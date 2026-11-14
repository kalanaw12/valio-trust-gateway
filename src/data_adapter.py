"""
Zero-Trust Data Adapter
=======================

Single source of truth for everything the Gateway knows about products:

* ``ProductCatalog``   – parses the 85 MB product JSON plus the reliability and
                         carbon CSVs into compact, typed ``Product`` records.
                         Missing values stay ``None``, never a guessed default.
* ``SemanticIndex``    – hybrid retrieval: multilingual sentence-embeddings in
                         FAISS, plus a lexical index and structured-claim
                         matching. "lactose-free milk" therefore hits products
                         that carry the ``FREE_FROM_LACTOSE`` claim even if the
                         title only says "laktoositon".
* ``ValioApiClient``   – async ``httpx`` client for the live availability and
                         price APIs. Batches at most 1000 ids, runs batches
                         concurrently, retries on 429/5xx, and validates every
                         response before anything downstream can use it.
* ``DataAdapter``      – the facade ``main.py`` uses.

"Zero-trust" in practice means:
  1. Never trust upstream payload shape: every API response is validated and
     normalized; unknown or unrequested product ids are dropped and logged.
  2. Never trust absence: a product missing from an API response is
     ``UNKNOWN``, not "available" or "free".
  3. Never invent data: missing CSV values stay ``None`` and are reported as such.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

import httpx
import numpy as np
import pandas as pd

try:  # ~3x faster parsing of the 85 MB file; optional
    import orjson as _fastjson
except ImportError:  # pragma: no cover
    _fastjson = None

try:
    import faiss  # type: ignore
except ImportError:  # pragma: no cover
    faiss = None

logger = logging.getLogger("gateway.data")

# =============================================================================
# Configuration
# =============================================================================

DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
CACHE_DIR = Path(os.getenv("CACHE_DIR", ".cache"))
PRODUCT_FILE = DATA_DIR / "valio_aimo_junction26_product_data.json"
RELIABILITY_FILE = DATA_DIR / "valio_aimo_junction26_delivery_reliability.csv"
CARBON_FILE = DATA_DIR / "valio_aimo_junction26_carbon_footprint.csv"

VALIO_BASE_URL = os.getenv("VALIO_BASE_URL", "https://junction26.valioaimo.fi")
VALIO_API_KEY = os.getenv("VALIO_API_KEY", "")
EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
)

MAX_IDS_PER_REQUEST = 1000  # hard limit from the live API contract

# GS1 AllergenTypeCode -> human label (codes observed in the dataset)
ALLERGEN_CODES: dict[str, str] = {
    "AC": "crustaceans", "AE": "eggs", "AF": "fish", "AM": "milk",
    "AN": "tree nuts", "AP": "peanuts", "AS": "sesame", "AU": "sulphites",
    "AW": "cereals containing gluten", "AX": "gluten", "AY": "soybeans",
    "BC": "celery", "BM": "mustard", "GB": "barley", "GK": "kamut",
    "GO": "oats", "GS": "spelt", "ML": "lactose", "NL": "lupin",
    "NR": "rye", "SA": "almonds", "SC": "cashews", "SH": "hazelnuts",
    "SM": "macadamia nuts", "SP": "pecans", "SR": "brazil nuts",
    "ST": "pistachios", "SW": "walnuts", "UM": "molluscs", "UW": "wheat",
    "X99": "other / undeclared allergen",
}

# Natural-language intent -> structured nutritionalClaim id (en / fi / sv).
# These make "lactose-free" a hard, verifiable fact instead of a fuzzy vector hit.
CLAIM_PATTERNS: dict[str, re.Pattern[str]] = {
    "FREE_FROM_LACTOSE": re.compile(r"lactose[\s-]*free|laktoositon|laktosfri|no lactose", re.I),
    "LOW_LACTOSE": re.compile(r"low[\s-]*lactose|vähälaktoos|hyla|laktosreducerad", re.I),
    "FREE_FROM_GLUTEN": re.compile(r"gluten[\s-]*free|gluteeniton|glutenfri", re.I),
    "VEGAN": re.compile(r"\bvegan\b|vegaani|vegansk", re.I),
    "VEGETARIAN": re.compile(r"vegetarian|kasvis|vegetarisk", re.I),
    "FREE_FROM_EGGS": re.compile(r"egg[\s-]*free|munaton|äggfri", re.I),
    "FREE_FROM_SOY": re.compile(r"soy[a]?[\s-]*free|soijaton|sojafri", re.I),
    "NO_ADDED_SUGARS": re.compile(r"no added sugar|sugar[\s-]*free|sokeroimaton|lisäämätön sokeri", re.I),
    "HIGH_PROTEIN": re.compile(r"high[\s-]*protein|proteiini", re.I),
    "LOW_FAT": re.compile(r"low[\s-]*fat|rasvaton|vähärasvai", re.I),
}

_TOKEN_RE = re.compile(r"[a-zåäö0-9]+", re.I)
_CONTENT_RE = re.compile(r"(\d+(?:[.,]\d+)?)\s*(kg|g|l|dl|cl|ml)\b", re.I)
_CONTENT_FACTORS = {"kg": ("KG", 1.0), "g": ("KG", 1e-3), "l": ("L", 1.0),
                    "dl": ("L", 0.1), "cl": ("L", 0.01), "ml": ("L", 1e-3)}


# =============================================================================
# Domain model
# =============================================================================

@dataclass(slots=True)
class Product:
    id: str
    name_en: Optional[str]
    name_fi: Optional[str]
    name_sv: Optional[str]
    description: Optional[str]
    brand: Optional[str]
    vendor: Optional[str]
    category: Optional[str]
    country_of_origin: Optional[str]
    sales_unit: Optional[str]
    base_unit: Optional[str]
    allowed_lot_size: Optional[float]
    sales_unit_in_base_units: Optional[float]
    base_unit_content: Optional[float]        # e.g. 1.0
    base_unit_content_uom: Optional[str]      # "L" or "KG"
    temperature_condition: Optional[int]
    vat_code: Optional[str]
    allergens_contains: frozenset[str] = frozenset()
    allergens_may_contain: frozenset[str] = frozenset()
    allergen_declared: bool = False           # False = no allergen data at all (unknown)
    free_from: frozenset[str] = frozenset()   # nonAllergen FREE_FROM codes
    claims: frozenset[str] = frozenset()      # nutritionalClaim ids
    curated_substitutes: tuple[str, ...] = ()  # Valio-curated substitution rules
    delivery_reliability: Optional[float] = None   # 0..1
    carbon_kg_co2e_per_kg: Optional[float] = None  # category-group average

    # ---- derived helpers -------------------------------------------------
    @property
    def display_name(self) -> str:
        return self.name_en or self.name_fi or self.name_sv or f"Product {self.id}"

    @property
    def content_per_sales_unit(self) -> Optional[float]:
        """Litres/kilograms in one *sales* unit (e.g. a case of 10 x 1 L = 10.0)."""
        if self.base_unit_content is None:
            return None
        multiplier = self.sales_unit_in_base_units or 1.0
        return round(self.base_unit_content * multiplier, 6)

    def allergen_conflicts(self, excluded: Iterable[str], strict: bool = True) -> list[dict]:
        """Return the excluded allergens this product contains (and traces if strict)."""
        out = []
        for code in excluded:
            if code in self.allergens_contains:
                out.append({"code": code, "label": ALLERGEN_CODES.get(code, code), "relation": "CONTAINS"})
            elif strict and code in self.allergens_may_contain:
                out.append({"code": code, "label": ALLERGEN_CODES.get(code, code), "relation": "MAY_CONTAIN"})
        return out

    def to_public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("allergens_contains", "allergens_may_contain", "free_from", "claims"):
            d[k] = sorted(d[k])
        d["curated_substitutes"] = list(self.curated_substitutes)
        d["display_name"] = self.display_name
        d["content_per_sales_unit"] = self.content_per_sales_unit
        d["allergen_labels"] = [ALLERGEN_CODES.get(c, c) for c in sorted(self.allergens_contains)]
        return d


# =============================================================================
# Parsing helpers (defensive: every field may be missing or malformed)
# =============================================================================

def _pick_lang(items: Optional[list], lang: str) -> Optional[str]:
    if not items:
        return None
    for it in items:
        if isinstance(it, dict) and it.get("language") == lang and it.get("value"):
            return str(it["value"]).strip()
    return None


def _safe_float(v: Any) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(f) or math.isinf(f) else f


def _parse_content(raw: dict, synkka: dict, name_en: Optional[str], name_fi: Optional[str]) -> tuple[Optional[float], Optional[str]]:
    """Content of one *base* unit: prefer structured unitConversions, fall back to the name."""
    for uc in synkka.get("unitConversions") or []:
        if uc.get("synkkaPackagingType") != "BASE_UNIT_OR_EACH":
            continue
        vol = uc.get("volume") or {}
        if vol.get("value"):
            factor = {"LTR": 1.0, "MLT": 1e-3, "DLT": 0.1, "CLT": 0.01}.get(vol.get("unit"))
            if factor:
                return float(vol["value"]) * factor, "L"
        net = uc.get("netWeight") or {}
        if net.get("value"):
            factor = {"KGM": 1.0, "GRM": 1e-3}.get(net.get("unit"))
            if factor:
                return float(net["value"]) * factor, "KG"
    for name in (name_en, name_fi):
        if name and (m := _CONTENT_RE.search(name)):
            uom, factor = _CONTENT_FACTORS[m.group(2).lower()]
            return float(m.group(1).replace(",", ".")) * factor, uom
    return None, None


def _parse_product(raw: dict) -> Optional[Product]:
    pid = raw.get("id")
    if not pid or raw.get("deleted"):
        return None
    s = raw.get("synkkaData") or {}
    names = s.get("names")
    name_en, name_fi, name_sv = (_pick_lang(names, l) for l in ("en", "fi", "sv"))
    desc = (_pick_lang(s.get("marketingTexts"), "en")
            or _pick_lang(s.get("keyIngredients"), "en")
            or _pick_lang(s.get("marketingTexts"), "fi"))

    contains, may_contain, free_from, claims = set(), set(), set(), set()
    allergen_declared = False
    for cl in s.get("classifications") or []:
        name, values = cl.get("name"), cl.get("values") or []
        if name == "allergen":
            allergen_declared = True
            for v in values:
                code, rel = v.get("id"), v.get("unit")
                if code and rel == "CONTAINS":
                    contains.add(code)
                elif code and rel == "MAY_CONTAIN":
                    may_contain.add(code)
        elif name == "nonAllergen":
            allergen_declared = True
            free_from.update(v["id"] for v in values if v.get("id") and v.get("unit") == "FREE_FROM")
        elif name == "nutritionalClaim":
            claims.update(v["id"] for v in values if v.get("id"))

    sales_unit = raw.get("salesUnit")
    su_size = None
    for u in raw.get("units") or []:
        if u.get("unitId") == sales_unit:
            su_size = _safe_float(u.get("sizeInBaseUnits"))
            break
    content, uom = _parse_content(raw, s, name_en, name_fi)

    subs = tuple(
        str(r["substituteProduct"]) for r in (raw.get("substitutions") or [])
        if isinstance(r, dict) and r.get("substituteProduct") and str(r["substituteProduct"]) != pid
    )

    tc = raw.get("temperatureCondition")
    return Product(
        id=str(pid), name_en=name_en, name_fi=name_fi, name_sv=name_sv,
        description=desc[:600] if desc else None,
        brand=s.get("brand"), vendor=raw.get("vendorName"), category=raw.get("category"),
        country_of_origin=raw.get("countryOfOrigin"),
        sales_unit=sales_unit, base_unit=raw.get("baseUnit"),
        allowed_lot_size=_safe_float(raw.get("allowedLotSize")),
        sales_unit_in_base_units=su_size,
        base_unit_content=content, base_unit_content_uom=uom,
        temperature_condition=int(tc) if isinstance(tc, (int, float)) else None,
        vat_code=s.get("vatCode"),
        allergens_contains=frozenset(contains), allergens_may_contain=frozenset(may_contain),
        allergen_declared=allergen_declared,
        free_from=frozenset(free_from), claims=frozenset(claims),
        curated_substitutes=subs,
    )


def _load_metric_csv(path: Path, value_col: str) -> dict[str, float]:
    """Load (productId, metric) CSV. Rows with missing/non-numeric values are skipped, not zeroed."""
    if not path.exists():
        logger.warning("Metric file %s missing — metric will be reported as null", path)
        return {}
    df = pd.read_csv(path, dtype={"productId": str})
    if value_col not in df.columns:
        # Tolerate header drift: take the first non-id column
        value_col = next(c for c in df.columns if c != "productId")
    df[value_col] = pd.to_numeric(df[value_col], errors="coerce")
    before = len(df)
    df = df.dropna(subset=["productId", value_col])
    df["productId"] = df["productId"].str.strip()
    if dropped := before - len(df):
        logger.info("%s: dropped %d rows with missing values", path.name, dropped)
    return dict(zip(df["productId"], df[value_col].astype(float)))


# =============================================================================
# Catalog
# =============================================================================

class ProductCatalog:
    def __init__(self) -> None:
        self._products: dict[str, Product] = {}
        self._by_category: dict[str, list[str]] = defaultdict(list)
        self.stats: dict[str, Any] = {}

    def load(self, product_file: Path = PRODUCT_FILE, reliability_file: Path = RELIABILITY_FILE,
             carbon_file: Path = CARBON_FILE) -> "ProductCatalog":
        t0 = time.perf_counter()
        raw_bytes = product_file.read_bytes()
        raw = _fastjson.loads(raw_bytes) if _fastjson else json.loads(raw_bytes)
        del raw_bytes
        if not isinstance(raw, list):
            raise ValueError(f"{product_file} must contain a JSON array of products")

        reliability = _load_metric_csv(reliability_file, "deliveryReliability")
        carbon = _load_metric_csv(carbon_file, "AVG kg CO2-eq/kg")

        skipped = 0
        for item in raw:
            try:
                p = _parse_product(item) if isinstance(item, dict) else None
            except Exception as exc:  # one bad record must not take the gateway down
                logger.debug("Skipping malformed product %r: %s", item.get("id") if isinstance(item, dict) else None, exc)
                p = None
            if p is None:
                skipped += 1
                continue
            r = reliability.get(p.id)
            p.delivery_reliability = min(max(r, 0.0), 1.0) if r is not None else None
            p.carbon_kg_co2e_per_kg = carbon.get(p.id)
            self._products[p.id] = p
            if p.category:
                self._by_category[p.category].append(p.id)
        del raw

        self.stats = {
            "products": len(self._products),
            "skipped": skipped,
            "with_reliability": sum(p.delivery_reliability is not None for p in self._products.values()),
            "with_carbon": sum(p.carbon_kg_co2e_per_kg is not None for p in self._products.values()),
            "with_allergen_data": sum(p.allergen_declared for p in self._products.values()),
            "load_seconds": round(time.perf_counter() - t0, 2),
        }
        logger.info("Catalog loaded: %s", self.stats)
        return self

    # ---- access ----------------------------------------------------------
    def get(self, product_id: str) -> Optional[Product]:
        return self._products.get(str(product_id))

    def require(self, product_id: str) -> Product:
        p = self.get(product_id)
        if p is None:
            raise KeyError(f"Unknown product id {product_id!r}")
        return p

    def __contains__(self, product_id: object) -> bool:
        return str(product_id) in self._products

    def __len__(self) -> int:
        return len(self._products)

    @property
    def products(self) -> list[Product]:
        return list(self._products.values())

    def in_category(self, category: str) -> list[Product]:
        return [self._products[i] for i in self._by_category.get(category, [])]

    def fingerprint(self) -> str:
        """Stable hash of the catalog contents used as the embedding-cache key."""
        h = hashlib.sha256()
        for pid in sorted(self._products):
            p = self._products[pid]
            h.update(f"{pid}|{p.name_en}|{p.name_fi}|{sorted(p.claims)}\n".encode())
        return h.hexdigest()[:16]


# =============================================================================
# Hybrid semantic index
# =============================================================================

@dataclass(slots=True)
class SearchHit:
    product: Product
    score: float
    semantic: float
    lexical: float
    matched_claims: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        p = self.product
        return {
            "productId": p.id,
            "name": p.display_name,
            "name_fi": p.name_fi,
            "brand": p.brand,
            "category": p.category,
            "salesUnit": p.sales_unit,
            "allowedLotSize": p.allowed_lot_size,
            "contentPerSalesUnit": p.content_per_sales_unit,
            "contentUom": p.base_unit_content_uom,
            "claims": sorted(p.claims),
            "allergens": sorted(p.allergens_contains),
            "deliveryReliability": p.delivery_reliability,
            "carbonKgCo2ePerKg": p.carbon_kg_co2e_per_kg,
            "score": round(self.score, 4),
            "explain": {
                "semantic": round(self.semantic, 4),
                "lexical": round(self.lexical, 4),
                "matchedClaims": self.matched_claims,
            },
        }


def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


def detect_claims(query: str) -> list[str]:
    """Natural-language query -> structured claim ids it implies."""
    return [claim for claim, pat in CLAIM_PATTERNS.items() if pat.search(query)]


class SemanticIndex:
    """
    Score = w_sem * cosine(query, product) + w_lex * normalized BM25-lite
            + claim_boost * (fraction of implied claims the product carries)

    FAISS (IndexFlatIP over L2-normalised vectors = exact cosine) handles recall;
    the lexical and claim signals handle precision on Finnish product names and
    on dietary facts that embeddings tend to blur ("milk" vs "lactose-free milk").
    """

    W_SEM, W_LEX, CLAIM_BOOST = 0.60, 0.30, 0.35
    CANDIDATE_POOL = 300

    def __init__(self, catalog: ProductCatalog, model_name: str = EMBEDDING_MODEL,
                 cache_dir: Path = CACHE_DIR) -> None:
        self.catalog = catalog
        self.model_name = model_name
        self.cache_dir = cache_dir
        self._ids: list[str] = []
        self._model = None
        self._faiss_index = None
        self._matrix: Optional[np.ndarray] = None  # numpy fallback if faiss is unavailable
        self._postings: dict[str, dict[int, int]] = defaultdict(dict)
        self._doc_len: np.ndarray = np.zeros(0)
        self._idf: dict[str, float] = {}
        self.semantic_enabled = False

    # ---- build -----------------------------------------------------------
    @staticmethod
    def _embed_text(p: Product) -> str:
        parts = [p.name_en, p.name_fi, p.brand]
        if p.claims:
            parts.append(" ".join(c.replace("_", " ").lower() for c in sorted(p.claims)))
        if p.description:
            parts.append(p.description[:300])
        return " | ".join(x for x in parts if x)

    @staticmethod
    def _lexical_text(p: Product) -> str:
        return " ".join(x for x in (p.name_en, p.name_fi, p.name_sv, p.brand) if x)

    def build(self) -> "SemanticIndex":
        products = self.catalog.products
        self._ids = [p.id for p in products]
        self._build_lexical(products)
        try:
            self._build_semantic(products)
        except Exception as exc:
            # Degrade, don't die: lexical + claim search still works.
            logger.warning("Semantic index unavailable (%s); running lexical-only search", exc)
            self.semantic_enabled = False
        return self

    def _build_lexical(self, products: Sequence[Product]) -> None:
        lengths = []
        df: dict[str, int] = defaultdict(int)
        for i, p in enumerate(products):
            toks = _tokens(self._lexical_text(p))
            lengths.append(len(toks) or 1)
            counts: dict[str, int] = defaultdict(int)
            for t in toks:
                counts[t] += 1
            for t, c in counts.items():
                self._postings[t][i] = c
                df[t] += 1
        n = len(products)
        self._doc_len = np.asarray(lengths, dtype=np.float32)
        self._idf = {t: math.log(1 + (n - d + 0.5) / (d + 0.5)) for t, d in df.items()}

    def _build_semantic(self, products: Sequence[Product]) -> None:
        from sentence_transformers import SentenceTransformer  # heavy import, deferred

        self._model = SentenceTransformer(self.model_name)
        slug = re.sub(r"[^a-z0-9]+", "-", self.model_name.lower())
        cache = self.cache_dir / f"emb_{slug}_{self.catalog.fingerprint()}.npy"
        if cache.exists():
            vectors = np.load(cache)
            logger.info("Loaded %d cached embeddings from %s", len(vectors), cache)
        else:
            t0 = time.perf_counter()
            logger.info("Embedding %d products with %s (first run only)...", len(products), self.model_name)
            vectors = self._model.encode(
                [self._embed_text(p) for p in products], batch_size=128,
                normalize_embeddings=True, show_progress_bar=True, convert_to_numpy=True,
            ).astype(np.float32)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            np.save(cache, vectors)
            logger.info("Embedded in %.1fs, cached to %s", time.perf_counter() - t0, cache)

        if len(vectors) != len(products):
            raise RuntimeError("Embedding cache out of sync with catalog")
        if faiss is not None:
            self._faiss_index = faiss.IndexFlatIP(vectors.shape[1])
            self._faiss_index.add(vectors)
        else:
            logger.warning("faiss not installed; using numpy brute-force cosine")
            self._matrix = vectors
        self.semantic_enabled = True

    # ---- query -----------------------------------------------------------
    def _semantic_candidates(self, query: str, k: int) -> dict[int, float]:
        if not self.semantic_enabled:
            return {}
        q = self._model.encode([query], normalize_embeddings=True, convert_to_numpy=True).astype(np.float32)
        if self._faiss_index is not None:
            scores, idx = self._faiss_index.search(q, k)
            return {int(i): float(s) for i, s in zip(idx[0], scores[0]) if i >= 0}
        sims = self._matrix @ q[0]
        top = np.argpartition(-sims, min(k, len(sims) - 1))[:k]
        return {int(i): float(sims[i]) for i in top}

    def _lexical_scores(self, query: str, k1: float = 1.2, b: float = 0.75) -> dict[int, float]:
        avg = float(self._doc_len.mean()) if len(self._doc_len) else 1.0
        scores: dict[int, float] = defaultdict(float)
        for t in set(_tokens(query)):
            idf = self._idf.get(t)
            if idf is None:
                continue
            for doc, tf in self._postings[t].items():
                dl = self._doc_len[doc]
                scores[doc] += idf * tf * (k1 + 1) / (tf + k1 * (1 - b + b * dl / avg))
        return scores

    def search(self, query: str, k: int = 10, *, exclude_allergens: Iterable[str] = (),
               strict_allergens: bool = True, require_claims: bool = False,
               category: Optional[str] = None, exclude_ids: Iterable[str] = ()) -> list[SearchHit]:
        """
        Hybrid search with hard filters applied *after* scoring:
          * exclude_allergens – drop products that conflict with the buyer profile
          * require_claims    – if the query implies claims (e.g. lactose-free),
                                drop products that do not carry them
        """
        query = (query or "").strip()
        if not query:
            return []
        implied = detect_claims(query)
        sem = self._semantic_candidates(query, self.CANDIDATE_POOL)
        lex = self._lexical_scores(query)
        lex_max = max(lex.values(), default=0.0) or 1.0

        pool = set(sem) | set(sorted(lex, key=lex.get, reverse=True)[: self.CANDIDATE_POOL])
        if implied:  # make sure claim-carrying products can always enter the pool
            for i in sorted(lex, key=lex.get, reverse=True)[: self.CANDIDATE_POOL * 3]:
                if any(c in self.catalog.require(self._ids[i]).claims for c in implied):
                    pool.add(i)

        excluded = set(exclude_allergens)
        skip_ids = set(exclude_ids)
        w_sem = self.W_SEM if self.semantic_enabled else 0.0
        w_lex = self.W_LEX if self.semantic_enabled else 1.0
        hits: list[SearchHit] = []
        for i in pool:
            p = self.catalog.require(self._ids[i])
            if p.id in skip_ids or (category and p.category != category):
                continue
            if excluded and p.allergen_conflicts(excluded, strict=strict_allergens):
                continue
            matched = [c for c in implied if c in p.claims]
            if require_claims and implied and len(matched) < len(implied):
                continue
            s, l = sem.get(i, 0.0), lex.get(i, 0.0) / lex_max
            claim_part = self.CLAIM_BOOST * (len(matched) / len(implied)) if implied else 0.0
            hits.append(SearchHit(p, float(w_sem * s + w_lex * l + claim_part), float(s), float(l), matched))

        # Deterministic ordering: score desc, then product id
        hits.sort(key=lambda h: (-h.score, h.product.id))
        return hits[:k]

    def similar_to(self, product_id: str, k: int = 5, **filters: Any) -> list[SearchHit]:
        """Nearest neighbours of an existing product (used by the substitution engine)."""
        p = self.catalog.require(product_id)
        query = " ".join(x for x in (p.name_en, p.name_fi) if x) or p.display_name
        exclude = set(filters.pop("exclude_ids", ())) | {product_id}
        return self.search(query, k=k, exclude_ids=exclude, **filters)


# =============================================================================
# Live API client
# =============================================================================

class UpstreamError(RuntimeError):
    """The live Valio Aimo API failed or returned something we refuse to trust."""


@dataclass(slots=True)
class AvailabilityRecord:
    product_id: str
    status: str                       # AVAILABLE | PARTIAL | OUT_OF_STOCK | BLOCKED | UNKNOWN
    sales_block: bool
    available_amount: float           # amount deliverable on/before requested date
    earliest_date: Optional[str]
    sales_unit: Optional[str]
    closing_time: Optional[str]
    logistic_model: Optional[str]
    raw: dict[str, Any]

    @property
    def is_stock_out(self) -> bool:
        return self.status in ("OUT_OF_STOCK", "BLOCKED", "UNKNOWN")


@dataclass(slots=True)
class PriceRecord:
    product_id: str
    status: str                       # PRICED | NO_PRICE | ERROR | UNKNOWN
    currency: Optional[str]
    unit_price: Optional[float]       # net, excl. VAT
    unit_price_with_tax: Optional[float]
    tax_rate: Optional[float]
    net_price_found: bool
    valid_from: Optional[str]
    valid_to: Optional[str]
    comparison_price: Optional[float]
    comparison_unit: Optional[str]
    raw: dict[str, Any]


def _chunks(seq: Sequence[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(seq), size):
        yield list(seq[i:i + size])


class ValioApiClient:
    RETRY_STATUSES = {429, 500, 502, 503, 504}

    def __init__(self, base_url: str = VALIO_BASE_URL, api_key: str = VALIO_API_KEY, *,
                 timeout: float = 20.0, max_retries: int = 3, max_concurrency: int = 4) -> None:
        if not api_key:
            logger.warning("VALIO_API_KEY is not set — live API calls will fail")
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"X-API-Key": api_key, "Accept": "application/json",
                     "User-Agent": "valio-agent-gateway/1.0"},
            timeout=httpx.Timeout(timeout, connect=5.0),
        )
        self._max_retries = max_retries
        self._sem = asyncio.Semaphore(max_concurrency)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "ValioApiClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ---- transport -------------------------------------------------------
    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        delay = 0.5
        for attempt in range(self._max_retries + 1):
            async with self._sem:
                try:
                    resp = await self._client.post(path, json=body)
                except httpx.TransportError as exc:
                    if attempt == self._max_retries:
                        raise UpstreamError(f"{path}: transport error: {exc}") from exc
                    resp = None
            if resp is not None:
                if resp.status_code < 400:
                    try:
                        data = resp.json()
                    except ValueError as exc:
                        raise UpstreamError(f"{path}: non-JSON response") from exc
                    if not isinstance(data, dict):
                        raise UpstreamError(f"{path}: expected JSON object")
                    return data
                if resp.status_code not in self.RETRY_STATUSES or attempt == self._max_retries:
                    raise UpstreamError(f"{path}: HTTP {resp.status_code}: {resp.text[:300]}")
                retry_after = _safe_float(resp.headers.get("Retry-After"))
                if retry_after:
                    delay = min(retry_after, 10.0)
            await asyncio.sleep(delay)
            delay *= 2
        raise UpstreamError(f"{path}: retries exhausted")  # pragma: no cover

    async def _batched(self, path: str, customer: str, requested_date: date | str,
                       product_ids: Sequence[str]) -> tuple[list[dict], list[dict]]:
        """Fan out in <=1000-id batches; return (product rows, batch envelopes)."""
        ids = list(dict.fromkeys(str(p) for p in product_ids))  # dedupe, keep order
        if not ids:
            return [], []
        req_date = requested_date.isoformat() if isinstance(requested_date, date) else str(requested_date)
        date.fromisoformat(req_date)  # validates YYYY-MM-DD, raises ValueError otherwise
        envelopes = await asyncio.gather(*(
            self._post(path, {"customer": customer, "requestedDate": req_date, "products": batch})
            for batch in _chunks(ids, MAX_IDS_PER_REQUEST)
        ))
        requested = set(ids)
        rows: list[dict] = []
        for env in envelopes:
            for row in env.get("products") or []:
                pid = str(row.get("productId")) if isinstance(row, dict) else None
                if pid not in requested:
                    logger.warning("%s returned unrequested product %r — discarded", path, pid)
                    continue
                rows.append(row)
        return rows, envelopes

    # ---- availability ----------------------------------------------------
    async def availability(self, customer: str, requested_date: date | str,
                           product_ids: Sequence[str]) -> dict[str, AvailabilityRecord]:
        rows, envs = await self._batched("/api/availability", customer, requested_date, product_ids)
        req = str(envs[0].get("requestedDate")) if envs else str(requested_date)
        out = {str(r["productId"]): self._normalize_availability(r, req) for r in rows}
        for pid in dict.fromkeys(map(str, product_ids)):  # absence is UNKNOWN, never AVAILABLE
            out.setdefault(pid, AvailabilityRecord(pid, "UNKNOWN", True, 0.0, None, None, None, None, {}))
        return out

    @staticmethod
    def _normalize_availability(row: dict, requested_date: str) -> AvailabilityRecord:
        pid = str(row["productId"])
        blocked = bool(row.get("salesBlock"))
        lines = [l for l in (row.get("scheduleLines") or []) if isinstance(l, dict)]
        usable = [l for l in lines if not l.get("salesBlock") and (_safe_float(l.get("availableAmount")) or 0) > 0]
        on_time = [l for l in usable if not l.get("availableDate") or str(l["availableDate"])[:10] <= requested_date[:10]]
        amount = sum(_safe_float(l.get("availableAmount")) or 0.0 for l in on_time)
        dates = sorted(str(l["availableDate"])[:10] for l in usable if l.get("availableDate"))
        if blocked:
            status = "BLOCKED"
        elif not lines or not usable:
            status = "OUT_OF_STOCK"
        elif amount <= 0:
            status = "PARTIAL"  # stock exists, but only after the requested date
        else:
            status = "AVAILABLE"
        return AvailabilityRecord(
            product_id=pid, status=status, sales_block=blocked, available_amount=round(amount, 6),
            earliest_date=dates[0] if dates else None,
            sales_unit=next((l.get("salesUnit") for l in lines if l.get("salesUnit")), None),
            closing_time=row.get("closingTime"), logistic_model=row.get("logisticModel"), raw=row,
        )

    # ---- price -----------------------------------------------------------
    async def price(self, customer: str, requested_date: date | str,
                    product_ids: Sequence[str]) -> dict[str, PriceRecord]:
        rows, _ = await self._batched("/api/price", customer, requested_date, product_ids)
        out = {str(r["productId"]): self._normalize_price(r) for r in rows}
        for pid in dict.fromkeys(map(str, product_ids)):
            out.setdefault(pid, PriceRecord(pid, "UNKNOWN", None, None, None, None, False, None, None, None, None, {}))
        return out

    @staticmethod
    def _normalize_price(row: dict) -> PriceRecord:
        pid = str(row["productId"])
        catalog = row.get("catalogPrice") if isinstance(row.get("catalogPrice"), dict) else None
        with_tax = row.get("priceWithTax") if isinstance(row.get("priceWithTax"), dict) else None
        tax = row.get("tax") if isinstance(row.get("tax"), dict) else None
        comp = row.get("comparisonPrice") if isinstance(row.get("comparisonPrice"), dict) else None
        net = _safe_float(catalog.get("value")) if catalog else None
        gross = (_safe_float(with_tax.get("value")) if with_tax else None) or (
            _safe_float(catalog.get("valueWithTax")) if catalog else None)
        if row.get("error"):
            status = "ERROR"
        elif net is None or net < 0:
            status, net = "NO_PRICE", None
        else:
            status = "PRICED"
        src = catalog or with_tax or {}
        return PriceRecord(
            product_id=pid, status=status,
            currency=src.get("currency") or None,
            unit_price=net, unit_price_with_tax=gross,
            tax_rate=_safe_float(tax.get("taxRate")) if tax else None,
            net_price_found=bool(row.get("netPriceFound")),
            valid_from=src.get("validFrom"), valid_to=src.get("validTo"),
            comparison_price=_safe_float(comp.get("value")) if comp else None,
            comparison_unit=row.get("comparisonUnit"), raw=row,
        )

    async def ping(self) -> bool:
        try:
            r = await self._client.get("/api/ping")
            return r.status_code < 400
        except httpx.HTTPError:
            return False


# =============================================================================
# Facade
# =============================================================================

class DataAdapter:
    """Owns the catalog, the search index and the live client for the app's lifetime."""

    def __init__(self, *, build_semantic: bool = True) -> None:
        self.catalog = ProductCatalog()
        self.index: Optional[SemanticIndex] = None
        self.api = ValioApiClient()
        self._build_semantic = build_semantic
        self.ready = False

    async def startup(self) -> None:
        # Heavy CPU/IO work happens off the event loop.
        await asyncio.to_thread(self.catalog.load)
        index = SemanticIndex(self.catalog)
        if self._build_semantic:
            await asyncio.to_thread(index.build)
        else:
            await asyncio.to_thread(index._build_lexical, self.catalog.products)
            index._ids = [p.id for p in self.catalog.products]
        self.index = index
        self.ready = True

    async def shutdown(self) -> None:
        await self.api.aclose()

    def search(self, query: str, k: int = 10, **filters: Any) -> list[SearchHit]:
        if self.index is None:
            raise RuntimeError("DataAdapter not started")
        return self.index.search(query, k=k, **filters)

    async def live_snapshot(self, customer: str, requested_date: date | str,
                            product_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        """Availability + price for each product, fetched concurrently."""
        avail, prices = await asyncio.gather(
            self.api.availability(customer, requested_date, product_ids),
            self.api.price(customer, requested_date, product_ids),
        )
        return {pid: {"availability": avail[pid], "price": prices[pid]} for pid in avail}

    def health(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "catalog": self.catalog.stats,
            "semantic_search": bool(self.index and self.index.semantic_enabled),
            "faiss": faiss is not None,
            "embedding_model": EMBEDDING_MODEL,
        }
