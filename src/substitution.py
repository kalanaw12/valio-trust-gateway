"""
Recipe-Compatible Substitution Engine
=====================================

When a product cannot be delivered, this engine proposes up to three
alternatives (BEST / BETTER / GOOD). Each comes with a scoring breakdown and a
plain-language explanation of why it is a good substitute.

Pipeline (each stage is deterministic, and every dropped candidate is recorded
with the reason it was dropped):

  1. Candidates   Valio-curated substitution rules first, then FAISS nearest
                  neighbours (policy: substitution.candidate_pool).
  2. Hard filters a) the substitute must not introduce an allergen the buyer
                     profile excludes;
                  b) recipe compatibility: dietary claims of the original
                     (lactose-free, gluten-free, vegan, ...) must be kept;
                  c) measurement basis must match (litres vs kilograms);
                  d) known delivery reliability >= substitution.min_reliability.
  3. Live check   one batched availability + price call; stocked-out candidates
                  are dropped.
  4. Scoring      weighted sum of price, reliability and carbon scores
                  (policy: substitution.weights). Each score is relative to the
                  best candidate, so it is stable and explainable. Missing data
                  gets a neutral-low score and is never treated as zero.
  5. Quantity     converts the requested quantity into the substitute's sales
                  units, by content and rounded up to its lot size (e.g.
                  1000 L = 100 cases of 10 x 1 L).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date
from decimal import ROUND_CEILING, Decimal
from typing import Any, Iterable, Optional

from .data_adapter import (ALLERGEN_CODES, AvailabilityRecord, DataAdapter, PriceRecord,
                           Product, UpstreamError)
from .guardrails import WEIGHT_SALES_UNITS, Policy, snap_to_lot  # noqa: F401 (re-exported)

logger = logging.getLogger("gateway.substitution")

# Claims that define recipe/dietary compatibility. If the original has one, the
# substitute must keep it. Marketing claims (HIGH_FIBRE, ...) are not enforced.
RECIPE_CRITICAL_CLAIMS = frozenset({
    "FREE_FROM_LACTOSE", "LOW_LACTOSE", "FREE_FROM_GLUTEN", "FREE_FROM_WHEAT",
    "VEGAN", "FREE_FROM_EGGS", "FREE_FROM_SOY",
})
# Claims checked softly: vendors declare them inconsistently, so a missing claim
# means "not declared", not "not compliant". It produces a warning, not a rejection.
SOFT_CLAIMS = frozenset({"VEGETARIAN"})
# FREE_FROM_LACTOSE implies LOW_LACTOSE, so a lactose-free substitute satisfies a low-lactose original.
CLAIM_IMPLIES = {"FREE_FROM_LACTOSE": {"LOW_LACTOSE"}, "VEGAN": {"VEGETARIAN", "FREE_FROM_EGGS", "FREE_FROM_LACTOSE"}}

UNKNOWN_SCORE = 0.4       # missing data ranks below average and is never treated as perfect
TIERS = ("BEST", "BETTER", "GOOD")


def _claim_label(c: str) -> str:
    return c.replace("FREE_FROM_", "").replace("_", " ").lower() + ("-free" if c.startswith("FREE_FROM_") else "")


def _effective_claims(p: Product) -> set[str]:
    claims = set(p.claims)
    for c in list(claims):
        claims |= CLAIM_IMPLIES.get(c, set())
    return claims


def round_up_to_lot(quantity: float, lot: Optional[float]) -> float:
    if not lot or lot <= 0:
        return float(quantity)
    q, l = Decimal(str(quantity)), Decimal(str(lot))
    return float((q / l).to_integral_value(rounding=ROUND_CEILING) * l)


# =============================================================================
# Result model
# =============================================================================

@dataclass(slots=True)
class SubstituteOption:
    product_id: str
    name: str
    tier: str
    rank: int
    score: float
    components: dict[str, float]
    curated: bool
    semantic_similarity: Optional[float]
    sales_unit: Optional[str]
    suggested_quantity: float
    unit_price: Optional[float]
    comparable_price: Optional[float]
    comparable_unit: Optional[str]
    estimated_line_value: Optional[float]
    availability_status: str
    available_amount: Optional[float]
    earliest_date: Optional[str]
    delivery_reliability: Optional[float]
    carbon_kg_co2e_per_kg: Optional[float]
    explanation: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "productId": self.product_id, "name": self.name, "tier": self.tier, "rank": self.rank,
            "score": self.score, "scoreBreakdown": self.components, "curated": self.curated,
            "semanticSimilarity": self.semantic_similarity, "salesUnit": self.sales_unit,
            "suggestedQuantity": self.suggested_quantity, "unitPrice": self.unit_price,
            "comparablePrice": self.comparable_price, "comparableUnit": self.comparable_unit,
            "estimatedLineValue": self.estimated_line_value,
            "availability": {"status": self.availability_status, "availableAmount": self.available_amount,
                             "earliestDate": self.earliest_date},
            "deliveryReliability": self.delivery_reliability,
            "carbonKgCo2ePerKg": self.carbon_kg_co2e_per_kg,
            "why": self.explanation, "warnings": self.warnings,
        }


@dataclass(slots=True)
class SubstitutionResult:
    original_product_id: str
    original_name: str
    trigger: str
    requested_quantity: float
    alternatives: list[SubstituteOption]
    rejected: list[dict[str, Any]]
    excluded_allergens: list[str]
    preserved_claims: list[str]
    degraded: bool = False          # True when live data was unavailable
    policy_hash: Optional[str] = None
    source: str = "NONE"            # OFFICIAL | FAISS_FALLBACK | NONE (which candidate pool produced the answer)

    def to_dict(self) -> dict[str, Any]:
        return {
            "originalProductId": self.original_product_id, "originalName": self.original_name,
            "trigger": self.trigger, "requestedQuantity": self.requested_quantity, "source": self.source,
            "alternatives": [a.to_dict() for a in self.alternatives],
            "rejectedCandidates": self.rejected,
            "constraints": {"excludedAllergens": self.excluded_allergens,
                            "preservedClaims": self.preserved_claims},
            "degraded": self.degraded, "policyHash": self.policy_hash,
        }


# =============================================================================
# Engine
# =============================================================================

class SubstitutionEngine:
    def __init__(self, adapter: DataAdapter, policy: Policy) -> None:
        self.adapter = adapter
        self.policy = policy

    # ---- trigger -------------------------------------------------------------
    @staticmethod
    def needs_substitution(avail: Optional[AvailabilityRecord], quantity: float, *,
                           product: Optional[Product] = None, blocked_allergens: Iterable[str] = (),
                           strict: bool = True) -> Optional[str]:
        """
        Return a trigger code if the line cannot be fulfilled as requested, else None.
        #5: a product containing a blocked allergen triggers substitution even if in stock.
        """
        if product is not None and blocked_allergens and product.allergen_conflicts(blocked_allergens, strict=strict):
            return "ALLERGEN_BLOCKED"
        if avail is None:
            return "UNKNOWN"
        if avail.sales_block:
            return "SALES_BLOCK"
        if not avail.raw.get("scheduleLines") and avail.status != "UNKNOWN":
            return "NO_SCHEDULE_LINES"
        if avail.status in ("OUT_OF_STOCK", "BLOCKED", "UNKNOWN"):
            return avail.status
        if avail.available_amount < quantity:
            return "INSUFFICIENT_QUANTITY"
        return None

    # ---- main entry point -----------------------------------------------------
    async def suggest(self, product_id: str, *, customer: str, requested_date: date | str,
                      quantity: float, buyer_profile: str = "default",
                      extra_excluded_allergens: Iterable[str] = (), trigger: str = "OUT_OF_STOCK",
                      original_price: Optional[PriceRecord] = None,
                      blocked_allergens: Iterable[str] = ()) -> SubstitutionResult:
        """
        #4: Valio's official `substitutions` are tried first. FAISS neighbours are
        only consulted if no official substitute survives the filters and live check.
        #5: `blocked_allergens` (per request) is merged with the buyer profile's exclusions.
        """
        catalog, index = self.adapter.catalog, self.adapter.index
        if index is None:
            raise RuntimeError("DataAdapter not started")
        original = catalog.require(product_id)
        excluded = self.policy.excluded_allergens(
            buyer_profile, set(extra_excluded_allergens) | set(blocked_allergens))
        strict = self.policy.allergen_mode == "strict"
        pool = int(self.policy.get("substitution.candidate_pool", 5))
        max_alts = int(self.policy.get("substitution.max_alternatives", 3))
        preserved = sorted(RECIPE_CRITICAL_CLAIMS & original.claims)
        rejected: list[dict[str, Any]] = []

        # ---- 1. official substitutions (Valio-curated) ------------------------------
        official = [(p, True, None) for sid in dict.fromkeys(original.curated_substitutes)
                    if (p := catalog.get(sid)) is not None]
        stocked, degraded, original_price = await self._screen(
            original, official, excluded, strict, preserved, customer, requested_date,
            original_price, rejected)
        source = "OFFICIAL" if stocked else "NONE"

        # ---- 2. FAISS fallback, only when no official substitute is viable --------------
        if not stocked:
            seen = {p.id for p, _, _ in official}
            fallback = []
            for hit in index.similar_to(product_id, k=pool, exclude_ids=seen):
                sim = round(hit.semantic, 4) if index.semantic_enabled else None
                fallback.append((hit.product, False, sim))
            stocked, degraded_fb, original_price = await self._screen(
                original, fallback, excluded, strict, preserved, customer, requested_date,
                original_price, rejected)
            degraded = degraded or degraded_fb
            if stocked:
                source = "FAISS_FALLBACK"

        # ---- 3. scoring ---------------------------------------------------------
        options = self._score(original, quantity, stocked, original_price, degraded)
        options.sort(key=lambda o: (-o.score, not o.curated, o.product_id))
        options = options[:max_alts]
        for rank, opt in enumerate(options, start=1):
            opt.rank, opt.tier = rank, TIERS[rank - 1] if rank <= len(TIERS) else "GOOD"
            opt.explanation.insert(0, self._headline(opt, original))

        return SubstitutionResult(
            original_product_id=product_id, original_name=original.display_name, trigger=trigger,
            requested_quantity=quantity, alternatives=options, rejected=rejected,
            excluded_allergens=excluded, preserved_claims=preserved, degraded=degraded,
            policy_hash=self.policy.hash, source=source,
        )

    async def _screen(self, original: Product, candidates: list[tuple[Product, bool, Optional[float]]],
                      excluded: list[str], strict: bool, preserved: list[str], customer: str,
                      requested_date: date | str, original_price: Optional[PriceRecord],
                      rejected: list[dict[str, Any]]):
        """Hard filters, then one batched live check. Appends every drop (with reason) to `rejected`."""
        min_rel = float(self.policy.get("substitution.min_reliability", 0.0))
        survivors = []
        for p, curated, sim in sorted(candidates, key=lambda c: c[0].id):
            reason = self._hard_filter(original, p, excluded, strict, preserved, min_rel)
            if reason:
                rejected.append({"productId": p.id, "name": p.display_name, "reason": reason,
                                 "pool": "official" if curated else "faiss"})
            else:
                survivors.append((p, curated, sim))

        degraded = False
        live: dict[str, dict[str, Any]] = {}
        ids = [p.id for p, _, _ in survivors] + ([original.id] if original_price is None else [])
        if ids:
            try:
                live = await self.adapter.live_snapshot(customer, requested_date, ids)
            except UpstreamError as exc:
                logger.warning("Live data unavailable for substitution of %s: %s", original.id, exc)
                degraded = True
        if original_price is None and original.id in live:
            original_price = live[original.id]["price"]

        stocked = []
        for p, curated, sim in survivors:
            snap = live.get(p.id) or {}
            avail, price = snap.get("availability"), snap.get("price")
            if not degraded and (avail is None or avail.is_stock_out):
                rejected.append({"productId": p.id, "name": p.display_name,
                                 "reason": f"Not deliverable on requested date ({avail.status if avail else 'UNKNOWN'})",
                                 "pool": "official" if curated else "faiss"})
                continue
            stocked.append((p, curated, sim, avail, price))
        return stocked, degraded, original_price

    # ---- filters ----------------------------------------------------------------
    @staticmethod
    def _hard_filter(original: Product, p: Product, excluded: list[str], strict: bool,
                     preserved: list[str], min_rel: float) -> Optional[str]:
        conflicts = p.allergen_conflicts(excluded, strict=strict)
        if conflicts:
            c = conflicts[0]
            return f"Introduces excluded allergen: {c['label']} ({c['code']}, {c['relation']})"
        if excluded and not p.allergen_declared:
            return "No allergen declaration; cannot prove it is safe for the buyer profile"
        missing = [c for c in preserved if c not in _effective_claims(p)]
        if missing:
            return "Breaks recipe compatibility: not " + ", ".join(_claim_label(c) for c in missing)
        if (original.base_unit_content_uom and p.base_unit_content_uom
                and original.base_unit_content_uom != p.base_unit_content_uom):
            return f"Different measurement basis ({p.base_unit_content_uom} vs {original.base_unit_content_uom})"
        if p.delivery_reliability is not None and p.delivery_reliability < min_rel:
            return f"Delivery reliability {p.delivery_reliability:.0%} below policy minimum {min_rel:.0%}"
        return None

    # ---- scoring ----------------------------------------------------------------
    def _score(self, original: Product, quantity: float, stocked: list, original_price: Optional[PriceRecord],
               degraded: bool) -> list[SubstituteOption]:
        w = self.policy.get("substitution.weights") or {"price": 0.4, "reliability": 0.35, "carbon": 0.25}
        uom = original.base_unit_content_uom

        # Comparable price = per litre/kg when content is known (fair across pack sizes)
        def comparable(p: Product, price: Optional[PriceRecord]) -> Optional[float]:
            if price is None or price.unit_price is None:
                return None
            c = p.content_per_sales_unit
            return price.unit_price / c if c else price.unit_price

        per_content = bool(uom) and all(p.content_per_sales_unit for p, *_ in stocked)
        prices = {p.id: comparable(p, pr) for p, _, _, _, pr in stocked}
        if not per_content:  # mixed knowledge: fall back to per-sales-unit comparison
            prices = {p.id: (pr.unit_price if pr else None) for p, _, _, _, pr in stocked}
        known_prices = [v for v in prices.values() if v is not None]
        best_price = min(known_prices) if known_prices else None
        known_co2 = [p.carbon_kg_co2e_per_kg for p, *_ in stocked if p.carbon_kg_co2e_per_kg is not None]
        best_co2 = min(known_co2) if known_co2 else None
        orig_cmp = comparable(original, original_price) if per_content else (
            original_price.unit_price if original_price else None)

        options = []
        for p, curated, sim, avail, price in stocked:
            cp = prices[p.id]
            s_price = UNKNOWN_SCORE if cp is None or not best_price else max(0.0, 1 - (cp - best_price) / best_price)
            s_rel = UNKNOWN_SCORE if p.delivery_reliability is None else p.delivery_reliability
            co2 = p.carbon_kg_co2e_per_kg
            s_co2 = UNKNOWN_SCORE if co2 is None or best_co2 is None else (
                1.0 if co2 <= best_co2 else max(0.0, 1 - (co2 - best_co2) / max(best_co2, 1e-9)))
            components = {"price": round(s_price, 4), "reliability": round(s_rel, 4), "carbon": round(s_co2, 4)}
            score = round(sum(float(w.get(k, 0)) * v for k, v in components.items()), 4)

            qty = self._equivalent_quantity(original, p, quantity)
            unit_price = price.unit_price if price else None
            why, warn = self._explain(original, p, curated, sim, cp, orig_cmp, per_content, avail, qty, co2, degraded)
            options.append(SubstituteOption(
                product_id=p.id, name=p.display_name, tier="", rank=0, score=score, components=components,
                curated=curated, semantic_similarity=sim, sales_unit=p.sales_unit, suggested_quantity=qty,
                unit_price=unit_price,
                comparable_price=round(cp, 4) if cp is not None else None,
                comparable_unit=f"EUR/{uom}" if per_content else f"EUR/{p.sales_unit}",
                estimated_line_value=round(unit_price * qty, 2) if unit_price is not None else None,
                availability_status=avail.status if avail else "UNKNOWN",
                available_amount=avail.available_amount if avail else None,
                earliest_date=avail.earliest_date if avail else None,
                delivery_reliability=p.delivery_reliability, carbon_kg_co2e_per_kg=co2,
                explanation=why, warnings=warn,
            ))
        return options

    @staticmethod
    def _equivalent_quantity(original: Product, sub: Product, quantity: float) -> float:
        """Same total litres/kg as the original request, rounded up to the substitute's lot size."""
        oc, sc = original.content_per_sales_unit, sub.content_per_sales_unit
        if oc and sc and original.base_unit_content_uom == sub.base_unit_content_uom:
            raw = quantity * oc / sc
        else:
            raw = quantity
        # Exact multiple of allowedLotSize; packs/cases are never split (see guardrails.snap_to_lot)
        return snap_to_lot(raw, sub.allowed_lot_size, sub.sales_unit)

    # ---- explanations -------------------------------------------------------------
    @staticmethod
    def _headline(opt: SubstituteOption, original: Product) -> str:
        top = max(sorted(opt.components), key=lambda k: opt.components[k])
        driver = {"price": "price", "reliability": "delivery reliability", "carbon": "carbon footprint"}[top]
        return (f"{opt.tier}: {opt.name} replaces {original.display_name}. "
                f"Score {opt.score:.2f}, strongest on {driver}.")

    @staticmethod
    def _explain(original: Product, p: Product, curated: bool, sim: Optional[float], cp: Optional[float],
                 orig_cmp: Optional[float], per_content: bool, avail: Optional[AvailabilityRecord],
                 qty: float, co2: Optional[float], degraded: bool) -> tuple[list[str], list[str]]:
        why: list[str] = []
        warn: list[str] = []
        if curated:
            why.append("Approved substitute in Valio Aimo's own substitution rules.")
        if sim is not None:
            why.append(f"Semantically close to the original (similarity {sim:.2f}).")
        kept = sorted(RECIPE_CRITICAL_CLAIMS & original.claims)
        if kept:
            why.append("Keeps recipe-critical properties: " + ", ".join(_claim_label(c) for c in kept) + ".")
        if p.category and p.category == original.category:
            why.append("Same product category.")
        for c in sorted(SOFT_CLAIMS & original.claims - _effective_claims(p)):
            warn.append(f"Original is labelled {_claim_label(c)}; this substitute does not declare it. Verify before use.")
        new_allergens = sorted(p.allergens_contains - original.allergens_contains)
        if new_allergens:
            warn.append("Contains allergens the original did not: "
                        + ", ".join(ALLERGEN_CODES.get(c, c) for c in new_allergens) + ".")
        else:
            why.append("Introduces no new allergens compared with the original.")

        unit = f"EUR/{original.base_unit_content_uom}" if per_content else "EUR/unit"
        if cp is not None and orig_cmp:
            delta = (cp - orig_cmp) / orig_cmp * 100
            why.append(f"Price {cp:.2f} {unit} ({delta:+.1f}% vs original).")
        elif cp is not None:
            why.append(f"Price {cp:.2f} {unit}.")
        else:
            warn.append("No verifiable live price.")

        if p.delivery_reliability is not None:
            why.append(f"Historical delivery reliability {p.delivery_reliability:.0%}.")
        else:
            warn.append("No delivery-reliability history.")
        if co2 is not None:
            line = f"Carbon {co2:g} kg CO2e/kg (product-group average)"
            if original.carbon_kg_co2e_per_kg:
                d = (co2 - original.carbon_kg_co2e_per_kg) / original.carbon_kg_co2e_per_kg * 100
                line += f", {d:+.0f}% vs original"
            why.append(line + ".")

        if degraded:
            warn.append("Live availability/price could not be confirmed; quote again before ordering.")
        elif avail is not None:
            if avail.available_amount >= qty:
                why.append(f"In stock: {avail.available_amount:g} {p.sales_unit} available, covers the "
                           f"suggested {qty:g} {p.sales_unit}.")
            else:
                warn.append(f"Only {avail.available_amount:g} of {qty:g} {p.sales_unit} available on the requested date.")
        if p.content_per_sales_unit and p.base_unit_content_uom:
            why.append(f"{qty:g} {p.sales_unit} x {p.content_per_sales_unit:g} {p.base_unit_content_uom} "
                       f"= {qty * p.content_per_sales_unit:g} {p.base_unit_content_uom}.")
        return why, warn
