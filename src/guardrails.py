"""
Deterministic Policy-as-Code Guardrails
=======================================

``evaluate_order()`` is a pure function of (order lines, context, catalog,
policy):

* no clock, no randomness and no I/O. The caller loads history, trust stats and
  trusted rules from SQLite and passes them in through ``OrderContext``, so the
  same input always gives the same decision and any decision can be replayed;
* checks run in a fixed order over lines sorted by product id;
* every decision carries ``policy_version`` / ``policy_hash`` and a plain-
  language ``explanation`` paragraph (#9).

Decision precedence:  REJECTED  >  PENDING_APPROVAL  >  AUTO_APPROVED
Severity per finding: REJECT    >  PENDING           >  INFO (explanatory only)

Decision matrix (what the judges see):

  AUTO_APPROVED     total <= agent's autonomous limit (trust level), no conflict with
                    the buyer's blocked allergens, no drift, and no other escalation;
                    OR every escalation is covered by a matching trusted rule, e.g. a
                    substitution a human already approved ("Approve & Remember").
  PENDING_APPROVAL  total > autonomous limit; OR a first-time substitution; OR
                    DRIFT_DETECTED (> drift.threshold_pct above the agent's history);
                    OR another safety escalation (price moved since quote, no net
                    price, stock unconfirmed, daily cap reached).
  REJECTED          a product conflicts with a blocked allergen (strict mode: also
                    "may contain"); OR the quote signature fails, the hard cap is
                    exceeded, the lot size is invalid, or the item is out of stock.

  Trusted rules can only turn PENDING into AUTO_APPROVED; they never soften a REJECTED.

Earned autonomy (Batch 1 features):
  #1 Trust escalation: a matching trusted rule may waive *listed* PENDING
     findings; REJECT findings are never waivable.
  #3 Trust levels: the autonomous spend limit comes from the agent's level.
  #6 Drift detection: an order or line far above the agent's own history is
     flagged DRIFT_DETECTED.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from .data_adapter import ALLERGEN_CODES, ProductCatalog
from .trust import canonical_json

POLICY_FILE = Path(os.getenv("POLICY_FILE", "policies.yaml"))
WEIGHT_SALES_UNITS = frozenset({"KG", "G", "L", "LTR"})


# =============================================================================
# Policy loading & validation
# =============================================================================

class PolicyError(ValueError):
    """policies.yaml is missing, malformed, or internally inconsistent."""


@dataclass(frozen=True)
class TrustProfile:
    agent_id: str
    level: int
    name: str
    score: int
    approvals: int
    rejections: int
    autonomous_limit: float
    next_level: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "level": self.level, "name": self.name, "score": self.score,
                "approvals": self.approvals, "rejections": self.rejections,
                "autonomous_limit": self.autonomous_limit, "next_level": self.next_level}


@dataclass(frozen=True)
class Policy:
    raw: dict[str, Any]
    version: str
    hash: str

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    # ---- agents ------------------------------------------------------------
    def agent(self, agent_id: str) -> dict[str, Any]:
        agents = self.raw.get("agents") or {}
        return agents.get(agent_id) or agents.get("default") or {"scopes": []}

    def has_scope(self, agent_id: str, scope: str) -> bool:
        return scope in (self.agent(agent_id).get("scopes") or [])

    def autonomous_limit(self, agent_id: str) -> float:
        """Static limit (no trust history): per-agent override, else the global default."""
        override = self.agent(agent_id).get("max_autonomous_spend")
        return float(override if override is not None else self.get("spend.max_autonomous_spend", 0))

    def trust_profile(self, agent_id: str, stats: Optional[dict[str, int]] = None) -> TrustProfile:
        """#3: level from score = approvals - penalty * rejections. A per-agent override is a floor."""
        stats = stats or {}
        approvals, rejections = int(stats.get("approvals", 0)), int(stats.get("rejections", 0))
        levels = sorted(self.get("trust_levels.levels") or [], key=lambda l: l["min_score"])
        override = self.agent(agent_id).get("max_autonomous_spend")
        hard_cap = float(self.get("spend.hard_cap_per_order"))
        if not levels:
            return TrustProfile(agent_id, 1, "Default", 0, approvals, rejections, self.autonomous_limit(agent_id))
        score = approvals - int(self.get("trust_levels.rejection_penalty", 2)) * rejections
        current = levels[0]
        for lvl in levels:
            if score >= lvl["min_score"]:
                current = lvl
        limit = float(current["max_autonomous_spend"])
        if override is not None:
            limit = max(limit, float(override))
        nxt = next((l for l in levels if l["min_score"] > score), None)
        return TrustProfile(
            agent_id=agent_id, level=int(current["level"]), name=str(current["name"]), score=score,
            approvals=approvals, rejections=rejections, autonomous_limit=min(limit, hard_cap),
            next_level=({"level": nxt["level"], "name": nxt["name"], "approvals_needed": nxt["min_score"] - score,
                         "max_autonomous_spend": nxt["max_autonomous_spend"]} if nxt else None),
        )

    # ---- buyer profiles ----------------------------------------------------
    def excluded_allergens(self, profile: str, extra: Iterable[str] = ()) -> list[str]:
        profiles = self.raw.get("buyer_profiles") or {}
        if profile not in profiles:
            raise PolicyError(f"Unknown buyer_profile {profile!r}; known: {sorted(profiles)}")
        extra_codes = {c.upper() for c in extra}
        unknown = extra_codes - set(ALLERGEN_CODES)
        if unknown:
            raise PolicyError(f"Unknown allergen codes {sorted(unknown)}; valid: {sorted(ALLERGEN_CODES)}")
        return sorted(set(profiles[profile].get("excluded_allergens") or []) | extra_codes)

    @property
    def allergen_mode(self) -> str:
        return str(self.get("allergens.safety", "strict"))

    @property
    def waivable_codes(self) -> frozenset[str]:
        return frozenset(self.get("trusted_rules.waivable_codes") or ())

    def summary(self) -> dict[str, Any]:
        return {"policy_version": self.version, "policy_hash": self.hash}


_REQUIRED_NUMBERS = (
    "spend.max_autonomous_spend", "spend.hard_cap_per_order",
    "spend.max_daily_autonomous_spend", "spend.max_line_value",
    "pricing.max_price_delta_pct", "pricing.reject_price_delta_pct",
    "quantity.max_units_per_line", "quotes.ttl_seconds",
)
# Findings a trusted rule may never waive, whatever policies.yaml says.
_NEVER_WAIVABLE = frozenset({"DAILY_LIMIT", "PRICE_DELTA", "PRICE_UNVERIFIED", "AVAILABILITY_UNKNOWN",
                             "ALLERGEN_DATA_MISSING", "CURRENCY_MISMATCH"})


def load_policies(path: Path | str = POLICY_FILE) -> Policy:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"Cannot load {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("policies.yaml must be a mapping")

    policy = Policy(raw=raw, version=str(raw.get("policy_version", "unversioned")),
                    hash=hashlib.sha256(canonical_json(raw)).hexdigest())

    # Fail closed: a typo in the policy must stop the gateway, not weaken it.
    for key in _REQUIRED_NUMBERS:
        v = policy.get(key)
        if not isinstance(v, (int, float)) or v < 0:
            raise PolicyError(f"{key} must be a non-negative number (got {v!r})")
    if policy.get("spend.max_autonomous_spend") > policy.get("spend.hard_cap_per_order"):
        raise PolicyError("spend.max_autonomous_spend cannot exceed spend.hard_cap_per_order")
    if policy.get("pricing.max_price_delta_pct") > policy.get("pricing.reject_price_delta_pct"):
        raise PolicyError("pricing.max_price_delta_pct cannot exceed pricing.reject_price_delta_pct")
    if policy.allergen_mode not in ("strict", "standard", "off"):
        raise PolicyError("allergens.safety must be strict | standard | off")
    if str(policy.get("allergens.unknown_allergen_data", "PENDING_APPROVAL")) not in (
            "AUTO_APPROVED", "PENDING_APPROVAL", "REJECTED"):
        raise PolicyError("allergens.unknown_allergen_data must be a decision status")
    weights = policy.get("substitution.weights") or {}
    if weights and not math.isclose(sum(weights.values()), 1.0, abs_tol=1e-6):
        raise PolicyError(f"substitution.weights must sum to 1.0 (got {sum(weights.values())})")
    for name, prof in (raw.get("buyer_profiles") or {}).items():
        unknown = set(prof.get("excluded_allergens") or []) - set(ALLERGEN_CODES)
        if unknown:
            raise PolicyError(f"buyer_profiles.{name}: unknown allergen codes {sorted(unknown)}")

    levels = policy.get("trust_levels.levels") or []
    seen_scores = set()
    for lvl in levels:
        if not {"level", "name", "min_score", "max_autonomous_spend"} <= set(lvl):
            raise PolicyError(f"trust_levels.levels entry missing fields: {lvl}")
        if lvl["max_autonomous_spend"] > policy.get("spend.hard_cap_per_order"):
            raise PolicyError(f"trust level {lvl['level']} limit exceeds spend.hard_cap_per_order")
        if lvl["min_score"] in seen_scores:
            raise PolicyError("trust_levels.levels min_score values must be unique")
        seen_scores.add(lvl["min_score"])
    if levels and min(l["min_score"] for l in levels) != 0:
        raise PolicyError("trust_levels.levels must include a level with min_score 0")
    bad_waivers = policy.waivable_codes & _NEVER_WAIVABLE
    if bad_waivers:
        raise PolicyError(f"trusted_rules.waivable_codes may not include {sorted(bad_waivers)}")
    if policy.get("drift.enabled") and not isinstance(policy.get("drift.threshold_pct"), (int, float)):
        raise PolicyError("drift.threshold_pct must be a number")
    if policy.get("negotiation.enabled"):
        for key in ("max_over_budget_pct", "quantity_uplift_pct", "discount_pct", "accept_min_qty"):
            v = policy.get(f"negotiation.{key}")
            if not isinstance(v, (int, float)) or v < 0:
                raise PolicyError(f"negotiation.{key} must be a non-negative number")
        if not 0 < policy.get("negotiation.discount_pct") < 100:
            raise PolicyError("negotiation.discount_pct must be between 0 and 100")
        cap = policy.get("negotiation.max_negotiated_over_limit_pct", 30)
        if not isinstance(cap, (int, float)) or not 0 <= cap <= 100:
            raise PolicyError("negotiation.max_negotiated_over_limit_pct must be between 0 and 100")
    return policy


# =============================================================================
# Decision model
# =============================================================================

class Status(str, Enum):
    AUTO_APPROVED = "AUTO_APPROVED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REJECTED = "REJECTED"


class Severity(str, Enum):
    INFO = "INFO"
    PENDING = "PENDING"
    REJECT = "REJECT"


_SEVERITY_RANK = {Severity.INFO: 0, Severity.PENDING: 1, Severity.REJECT: 2}
_STATUS_TO_SEVERITY = {"AUTO_APPROVED": Severity.INFO, "PENDING_APPROVAL": Severity.PENDING,
                       "REJECTED": Severity.REJECT}


@dataclass(slots=True)
class OrderLine:
    product_id: str
    quantity: float                          # in the product's sales unit
    quoted_unit_price: Optional[float]       # net price from the signed quote
    live_unit_price: Optional[float] = None  # net price re-fetched at order time
    currency: Optional[str] = "EUR"
    price_status: str = "PRICED"             # PriceRecord.status
    net_price_found: bool = True
    availability_status: str = "AVAILABLE"   # AvailabilityRecord.status
    available_amount: Optional[float] = None
    is_substitute: bool = False
    substitutes_for: Optional[str] = None

    @property
    def effective_unit_price(self) -> Optional[float]:
        return self.live_unit_price if self.live_unit_price is not None else self.quoted_unit_price

    @property
    def line_value(self) -> Optional[float]:
        p = self.effective_unit_price
        if p is None:
            return None
        # Money rounds half-up in Decimal (float round() gives 915.075 -> 915.07; the negotiator says 915.08)
        return float((Decimal(str(p)) * Decimal(str(self.quantity))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


@dataclass(slots=True)
class OrderContext:
    customer: str
    agent_id: str = "default"
    buyer_profile: str = "default"
    extra_excluded_allergens: tuple[str, ...] = ()   # a.k.a. blocked_allergens (#5)
    quote_signature_status: str = "OK"       # reason code from TrustSigner.open()
    daily_autonomous_spend: float = 0.0      # already placed without a human in the last 24 h
    currency: str = "EUR"
    trust: Optional[TrustProfile] = None     # #3 (None -> static policy limit)
    history: Optional[dict[str, Any]] = None  # #6 Database.order_history() (None -> no drift check)
    trusted_rules: tuple[dict[str, Any], ...] = ()  # #1 Database.active_rules()
    negotiated_total: Optional[float] = None  # a WON negotiation's total, accepted over the limit by policy


@dataclass(slots=True)
class Violation:
    code: str
    severity: Severity
    message: str
    product_id: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)
    because: Optional[str] = None            # short clause used in the explanation paragraph
    waived_by_rule: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity.value, "message": self.message,
                "productId": self.product_id, "data": self.data, "waivedByRule": self.waived_by_rule}


@dataclass(slots=True)
class Decision:
    status: Status
    violations: list[Violation]
    totals: dict[str, Any]
    policy_version: str
    policy_hash: str
    trusted_rule: Optional[dict[str, Any]] = None
    trust: Optional[TrustProfile] = None

    @property
    def reasons(self) -> list[str]:
        """Human-readable reasons that drove the status (INFO findings excluded)."""
        return [v.message for v in self.violations if v.severity is not Severity.INFO]

    @property
    def notes(self) -> list[str]:
        return [v.message for v in self.violations if v.severity is Severity.INFO]

    @property
    def drift(self) -> list[dict[str, Any]]:
        return [{**v.data, "productId": v.product_id} for v in self.violations if v.code == "DRIFT_DETECTED"]

    @property
    def explanation(self) -> str:
        """#9: one paragraph a purchasing manager can read without knowing the policy file."""
        return explain(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "explanation": self.explanation,
            "reasons": self.reasons or ["All policy checks passed"],
            "notes": self.notes,
            "violations": [v.to_dict() for v in self.violations],
            "totals": self.totals,
            "drift": self.drift,
            "trusted_rule": self.trusted_rule,
            "trust": self.trust.to_dict() if self.trust else None,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
        }


# =============================================================================
# Helpers
# =============================================================================

def is_multiple_of_lot(quantity: float, lot: Optional[float]) -> bool:
    """Exact decimal check, so 0.3 is a valid multiple of 0.1 (float % would say no)."""
    if not lot or lot <= 0:
        return True
    try:
        return Decimal(str(quantity)) % Decimal(str(lot)) == 0
    except InvalidOperation:
        return False


def snap_to_lot(quantity: float, lot: Optional[float], sales_unit: Optional[str] = None) -> float:
    """Round UP to the next valid order quantity. Packs/cases are never split, even if lot < 1."""
    lot = lot if lot and lot > 0 else 1.0
    if (sales_unit or "").upper() not in WEIGHT_SALES_UNITS:
        lot = max(lot, 1.0)
    q, l = Decimal(str(quantity)), Decimal(str(lot))
    return float((q / l).to_integral_value(rounding=ROUND_CEILING) * l)


def _eur(v: float) -> str:
    return f"€{v:,.2f}"


def _pct(observed: float, baseline: float) -> float:
    return (observed - baseline) / baseline * 100 if baseline else 0.0


# =============================================================================
# The evaluator
# =============================================================================

def evaluate_order(lines: list[OrderLine], ctx: OrderContext, catalog: ProductCatalog,
                   policy: Policy) -> Decision:
    out: list[Violation] = []

    def add(code: str, sev: Severity, msg: str, pid: Optional[str] = None, *,
            because: Optional[str] = None, **data: Any) -> None:
        out.append(Violation(code, sev, msg, pid, data, because))

    # ---- 0. Identity & integrity -------------------------------------------
    if not policy.has_scope(ctx.agent_id, "order"):
        add("AGENT_SCOPE", Severity.REJECT, f"Agent '{ctx.agent_id}' lacks the 'order' scope",
            because=f"agent '{ctx.agent_id}' is not allowed to place orders")
    if policy.get("quotes.require_valid_signature", True) and ctx.quote_signature_status != "OK":
        add(f"QUOTE_{ctx.quote_signature_status}", Severity.REJECT,
            f"Quote failed verification: {ctx.quote_signature_status}",
            because=f"the quote failed cryptographic verification ({ctx.quote_signature_status.lower().replace('_', ' ')})")
    if not lines:
        add("EMPTY_ORDER", Severity.REJECT, "Order contains no lines", because="the order contained no valid lines")

    try:
        excluded = policy.excluded_allergens(ctx.buyer_profile, ctx.extra_excluded_allergens)
    except PolicyError as exc:
        add("UNKNOWN_BUYER_PROFILE", Severity.REJECT, str(exc), because=str(exc))
        excluded = []
    mode = policy.allergen_mode
    max_delta = float(policy.get("pricing.max_price_delta_pct"))
    reject_delta = float(policy.get("pricing.reject_price_delta_pct"))
    max_line = float(policy.get("spend.max_line_value"))
    max_units = float(policy.get("quantity.max_units_per_line"))
    carbon_cap = policy.get("sustainability.max_carbon_kg_co2e_per_kg")
    carbon_flag = policy.get("sustainability.flag_carbon_above")

    drift_on = bool(policy.get("drift.enabled")) and ctx.history is not None
    drift_pct = float(policy.get("drift.threshold_pct", 15))
    min_hist = int(policy.get("drift.min_history_orders", 3))
    hist = ctx.history or {}

    seen: set[str] = set()
    total, unpriced = 0.0, 0

    # ---- 1. Per-line checks (fixed order, sorted lines) --------------------
    for line in sorted(lines, key=lambda l: l.product_id):
        pid = line.product_id
        if pid in seen:
            add("DUPLICATE_LINE", Severity.REJECT, f"Product {pid} appears more than once", pid,
                because=f"product {pid} appeared twice")
            continue
        seen.add(pid)

        product = catalog.get(pid)
        if product is None:
            add("UNKNOWN_PRODUCT", Severity.REJECT, f"Product {pid} does not exist in the catalog", pid,
                because=f"product {pid} does not exist")
            continue
        name = product.display_name

        # Quantity
        q = line.quantity
        if not isinstance(q, (int, float)) or not math.isfinite(q) or q <= 0:
            add("INVALID_QUANTITY", Severity.REJECT, f"{name}: quantity must be positive (got {q})", pid,
                because=f"the quantity for {name} was invalid")
            continue
        if policy.get("quantity.enforce_lot_size", True) and not is_multiple_of_lot(q, product.allowed_lot_size):
            add("LOT_SIZE", Severity.REJECT,
                f"{name}: quantity {q} is not a multiple of lot size {product.allowed_lot_size} {product.sales_unit}",
                pid, because=f"{q:g} {product.sales_unit} of {name} is not orderable (lot size {product.allowed_lot_size:g})",
                lot_size=product.allowed_lot_size,
                suggested_quantity=snap_to_lot(q, product.allowed_lot_size, product.sales_unit))
        if q > max_units:
            add("QUANTITY_UNUSUAL", Severity.PENDING,
                f"{name}: {q:g} {product.sales_unit} exceeds the {max_units:g}-unit sanity limit", pid,
                because=f"{q:g} {product.sales_unit} of {name} is unusually large")

        # Price integrity
        if line.price_status == "ERROR" and policy.get("pricing.reject_on_price_error", True):
            add("PRICE_ERROR", Severity.REJECT, f"{name}: pricing API reported an error", pid,
                because=f"Valio's pricing service returned an error for {name}")
        elif line.effective_unit_price is None:
            add("PRICE_UNVERIFIED", Severity.PENDING, f"{name}: no verifiable price; spend cannot be bounded", pid,
                because=f"no verifiable price exists for {name}")
        if line.effective_unit_price is not None and not line.net_price_found and policy.get("pricing.require_net_price", True):
            add("NO_NET_PRICE", Severity.PENDING, f"{name}: no customer net price, list/catalog price used", pid,
                because=f"{name} has no negotiated customer price")
        if line.currency and line.currency != ctx.currency:
            add("CURRENCY_MISMATCH", Severity.PENDING, f"{name}: priced in {line.currency}, expected {ctx.currency}", pid,
                because=f"{name} is priced in {line.currency}")
        if line.quoted_unit_price and line.live_unit_price is not None:
            delta = _pct(line.live_unit_price, line.quoted_unit_price)
            data = {"quoted": line.quoted_unit_price, "live": line.live_unit_price, "delta_pct": round(delta, 2)}
            clause = f"the price of {name} moved {delta:+.1f}% since the quote"
            if abs(delta) > reject_delta:
                add("PRICE_DELTA_EXTREME", Severity.REJECT,
                    f"{name}: price moved {delta:+.1f}% since quote (limit ±{reject_delta:g}%)", pid, because=clause, **data)
            elif abs(delta) > max_delta:
                add("PRICE_DELTA", Severity.PENDING,
                    f"{name}: price moved {delta:+.1f}% since quote (auto limit ±{max_delta:g}%)", pid, because=clause, **data)

        # Availability
        a = line.availability_status
        if a in ("BLOCKED", "OUT_OF_STOCK"):
            add(f"AVAILABILITY_{a}", Severity.REJECT,
                f"{name}: {a.replace('_', ' ').lower()} for the requested date; request a substitution", pid,
                because=f"{name} is {a.replace('_', ' ').lower()}")
        elif a == "UNKNOWN":
            add("AVAILABILITY_UNKNOWN", Severity.PENDING, f"{name}: availability could not be confirmed upstream", pid,
                because=f"stock for {name} could not be confirmed")
        elif line.available_amount is not None and line.available_amount < q:
            sev = Severity.INFO if policy.get("quantity.allow_partial_availability", False) else Severity.PENDING
            add("PARTIAL_AVAILABILITY", sev,
                f"{name}: only {line.available_amount:g} of {q:g} {product.sales_unit} available on the requested date",
                pid, because=f"only {line.available_amount:g} of {q:g} {product.sales_unit} of {name} are available",
                available=line.available_amount)

        # Allergens (#5: profile + blocked_allergens)
        if mode != "off" and excluded:
            if not product.allergen_declared:
                sev = _STATUS_TO_SEVERITY[str(policy.get("allergens.unknown_allergen_data", "PENDING_APPROVAL"))]
                add("ALLERGEN_DATA_MISSING", sev, f"{name}: no allergen declaration; cannot prove safety", pid,
                    because=f"{name} has no allergen declaration")
            for c in product.allergen_conflicts(excluded, strict=True):
                sev = Severity.REJECT if (c["relation"] == "CONTAINS" or mode == "strict") else Severity.PENDING
                verb = "contains" if c["relation"] == "CONTAINS" else "may contain traces of"
                add("ALLERGEN_CONFLICT", sev,
                    f"{name} {verb} {c['label']} ({c['code']}), excluded by profile '{ctx.buyer_profile}'",
                    pid, because=f"{name} {verb} {c['label']}",
                    allergen=c["code"], label=c["label"], relation=c["relation"])

        # Substitution
        if line.is_substitute:
            sev = Severity.PENDING if policy.get("substitution.substituted_lines_require_approval", True) else Severity.INFO
            add("SUBSTITUTED_LINE", sev,
                f"{name} substitutes {line.substitutes_for or 'an unavailable product'}; human confirmation required",
                pid, because=f"{name} is a substitute for {line.substitutes_for}", substitutes_for=line.substitutes_for)

        # Drift (#6): per-line quantity vs this agent's own history for the product
        if drift_on and hist.get("order_count", 0) >= min_hist:
            base_q = (hist.get("product_avg_qty") or {}).get(pid)
            if base_q and (hist.get("product_counts") or {}).get(pid, 0) >= min_hist:
                dev = _pct(q, base_q)
                if dev > drift_pct:
                    add("DRIFT_DETECTED", Severity.PENDING,
                        f"{name}: {q:g} {product.sales_unit} is {dev:.0f}% above this agent's usual {base_q:g} (threshold {drift_pct:g}%)",
                        pid, because=f"the quantity of {name} is {dev:.0f}% above the usual {base_q:g}",
                        metric="line_quantity", observed=q, baseline=round(base_q, 4), deviation_pct=round(dev, 2))

        # Sustainability
        co2 = product.carbon_kg_co2e_per_kg
        if co2 is not None:
            if carbon_cap is not None and co2 > float(carbon_cap):
                add("CARBON_CAP", Severity.REJECT, f"{name}: {co2:g} kg CO2e/kg exceeds cap {carbon_cap}", pid,
                    because=f"{name}'s footprint ({co2:g} kg CO2e/kg) exceeds the cap", carbon=co2)
            elif carbon_flag is not None and co2 > float(carbon_flag):
                add("CARBON_HIGH", Severity.INFO, f"{name}: high footprint, {co2:g} kg CO2e/kg (group avg)", pid)

        # Line value
        lv = line.line_value
        if lv is None:
            unpriced += 1
        else:
            total += lv
            if lv > max_line:
                add("LINE_VALUE", Severity.PENDING,
                    f"{name}: line value {_eur(lv)} exceeds {_eur(max_line)}", pid,
                    because=f"the {name} line ({_eur(lv)}) exceeds the {_eur(max_line)} line limit", line_value=lv)

    # ---- 2. Order-level spend (trust-level aware, #3) ------------------------
    total = round(total, 2)
    hard_cap = float(policy.get("spend.hard_cap_per_order"))
    trust = ctx.trust
    auto_cap = trust.autonomous_limit if trust else policy.autonomous_limit(ctx.agent_id)
    level_txt = f" (trust level {trust.level} '{trust.name}')" if trust else ""
    daily_cap = float(policy.get("spend.max_daily_autonomous_spend"))
    if total > hard_cap:
        add("HARD_CAP", Severity.REJECT, f"Order total {_eur(total)} exceeds hard cap {_eur(hard_cap)}",
            because=f"the total cost ({_eur(total)}) exceeded the hard cap ({_eur(hard_cap)})")
    else:
        # Won negotiation + negotiation.auto_approve_won: the spend limit accepts exactly the negotiated total,
        # capped at limit + max_negotiated_over_limit_pct. Every other check below still runs.
        neg_cap = auto_cap * (1 + float(policy.get("negotiation.max_negotiated_over_limit_pct", 30)) / 100)
        negotiated_ok = (ctx.negotiated_total is not None and bool(policy.get("negotiation.auto_approve_won"))
                         and total > auto_cap and total <= ctx.negotiated_total + 0.01 and total <= neg_cap)
        if negotiated_ok:
            add("NEGOTIATED_OVER_LIMIT", Severity.INFO,
                f"Negotiated total {_eur(total)} is above the {_eur(auto_cap)} autonomous limit; accepted by the "
                f"negotiation policy (cap {_eur(neg_cap)})",
                because=f"the negotiated total ({_eur(total)}) is {(total / auto_cap - 1) * 100:.0f}% above the "
                        f"agent's {_eur(auto_cap)} limit, which the negotiation policy allows",
                total=total, limit=auto_cap, cap=round(neg_cap, 2))
        elif total > auto_cap:
            add("SPEND_LIMIT", Severity.PENDING,
                f"Spend {_eur(total)} exceeds autonomous limit {_eur(auto_cap)} for agent '{ctx.agent_id}'{level_txt}",
                because=f"the total cost ({_eur(total)}) exceeded the agent's limit ({_eur(auto_cap)}){level_txt}",
                total=total, limit=auto_cap)
        # Checked independently of SPEND_LIMIT: the daily cap bounds how often trusted rules can fire.
        if ctx.daily_autonomous_spend + total > daily_cap:
            add("DAILY_LIMIT", Severity.PENDING,
                f"Daily autonomous spend would reach {_eur(ctx.daily_autonomous_spend + total)} (limit {_eur(daily_cap)})",
                because=f"today's autonomous spend would reach {_eur(ctx.daily_autonomous_spend + total)} "
                        f"(daily limit {_eur(daily_cap)})")

    # ---- 3. Order-level drift (#6) ------------------------------------------------
    if drift_on and hist.get("order_count", 0) >= min_hist and hist.get("avg_net_total"):
        base = float(hist["avg_net_total"])
        dev = _pct(total, base)
        if dev > drift_pct:
            add("DRIFT_DETECTED", Severity.PENDING,
                f"Order total {_eur(total)} is {dev:.0f}% above this agent's average {_eur(base)} "
                f"over {hist['order_count']} orders (threshold {drift_pct:g}%)",
                because=f"the order is {dev:.0f}% larger than this agent's usual {_eur(base)}",
                metric="order_total", observed=total, baseline=round(base, 2), deviation_pct=round(dev, 2))

    # ---- 4. Trust escalation (#1): a matching rule may waive listed PENDING findings
    applied_rule = _apply_trusted_rules(out, lines, total, ctx, policy)

    # ---- 5. Verdict -----------------------------------------------------------------
    worst = max((_SEVERITY_RANK[v.severity] for v in out), default=0)
    status = {0: Status.AUTO_APPROVED, 1: Status.PENDING_APPROVAL, 2: Status.REJECTED}[worst]
    totals = {
        "currency": ctx.currency,
        "net_total": total,
        "unpriced_lines": unpriced,
        "lines": len(lines),
        "autonomous_limit": auto_cap,
        "daily_autonomous_spend": round(ctx.daily_autonomous_spend, 2),
        "excluded_allergens": excluded,
    }
    return Decision(status, out, totals, policy.version, policy.hash, applied_rule, trust)


def _rule_covers(rule: dict[str, Any], lines: list[OrderLine], total: float,
                 pending_codes: set[str], waivable: frozenset[str], ctx: OrderContext) -> bool:
    if rule.get("agent_id") != ctx.agent_id or rule.get("customer") != ctx.customer:
        return False
    allowed_products = set(rule.get("product_ids") or [])
    max_q = rule.get("max_quantities") or {}
    if any(l.product_id not in allowed_products or l.quantity > float(max_q.get(l.product_id, 0)) for l in lines):
        return False
    # A substitute is only trusted for the exact original it replaced when the human approved it
    # ("Arla instead of Valio 464073" does not cover "Arla instead of anything else").
    pairs = rule.get("substitutions") or {}
    if any(l.is_substitute and pairs.get(l.product_id) != l.substitutes_for for l in lines):
        return False
    if total > float(rule.get("max_net_total", 0)):
        return False
    # The rule must cover every escalation reason, and each must still be waivable under today's policy.
    return pending_codes <= (set(rule.get("waived_codes") or []) & waivable)


def _apply_trusted_rules(out: list[Violation], lines: list[OrderLine], total: float,
                         ctx: OrderContext, policy: Policy) -> Optional[dict[str, Any]]:
    if not ctx.trusted_rules or not policy.get("trusted_rules.enabled", False) or not lines:
        return None
    if any(v.severity is Severity.REJECT for v in out):
        return None                                   # never soften a rejection
    pending = {v.code for v in out if v.severity is Severity.PENDING}
    if not pending:
        return None
    for rule in sorted(ctx.trusted_rules, key=lambda r: r.get("id", 0)):  # deterministic: oldest rule first
        if _rule_covers(rule, lines, total, pending, policy.waivable_codes, ctx):
            for v in out:
                if v.severity is Severity.PENDING:
                    v.severity = Severity.INFO
                    v.waived_by_rule = rule.get("id")
                    v.message += f" (waived by trusted rule #{rule.get('id')})"
            return {"id": rule.get("id"), "created_by": rule.get("created_by"),
                    "created_from_order": rule.get("created_from_order"), "expires_at": rule.get("expires_at"),
                    "waived_codes": sorted(pending)}
    return None


# =============================================================================
# Explainability (#9)
# =============================================================================

def _join(clauses: list[str]) -> str:
    clauses = list(dict.fromkeys(c for c in clauses if c))  # de-duplicate, keep order
    if not clauses:
        return ""
    return clauses[0] + "".join(f" AND {c}" for c in clauses[1:])


def _clauses(vs: list[Violation], severity: Severity) -> list[str]:
    """
    One clause per finding, except allergen conflicts, which are grouped per product:
    "X contains peanuts and may contain traces of tree nuts, almonds and cashews"
    instead of repeating the product name once per allergen.
    """
    out: list[str] = []
    allergens: dict[str, dict[str, Any]] = {}
    for v in vs:
        if v.severity is not severity:
            continue
        if v.code == "ALLERGEN_CONFLICT" and v.product_id:
            name = v.because.split(" contains ")[0].split(" may contain ")[0] if v.because else v.product_id
            g = allergens.setdefault(v.product_id, {"name": name, "contains": [], "may": []})
            if not g.get("_placed"):
                g["_placed"] = True
                out.append(f"\x00allergen:{v.product_id}")      # placeholder keeps original ordering
            (g["contains"] if v.data.get("relation") == "CONTAINS" else g["may"]).append(v.data.get("label", "allergens"))
        else:
            out.append(v.because or (v.message[0].lower() + v.message[1:]))

    def listing(items: list[str]) -> str:
        return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]

    for pid, g in allergens.items():
        parts = []
        if g["contains"]:
            parts.append(f"contains {listing(g['contains'])}")
        if g["may"]:
            parts.append(f"may contain traces of {listing(g['may'])}")
        out[out.index(f"\x00allergen:{pid}")] = f"{g['name']} {' and '.join(parts)}"
    return out


def explain(decision: Decision) -> str:
    vs = decision.violations
    clause = lambda v: v.because or (v.message[0].lower() + v.message[1:])
    total = decision.totals.get("net_total", 0.0)
    if decision.status is Status.REJECTED:
        hard = _clauses(vs, Severity.REJECT)
        soft = _clauses(vs, Severity.PENDING)
        text = f"Rejected because {_join(hard)}."
        if soft:
            text += f" It would also have needed human approval because {_join(soft)}."
        return text + " Rejections are final; the agent must submit a corrected order."
    if decision.status is Status.PENDING_APPROVAL:
        text = f"Sent for human approval because {_join(_clauses(vs, Severity.PENDING))}."
        if decision.trust and decision.trust.next_level:
            nl = decision.trust.next_level
            text += (f" Agent is at trust level {decision.trust.level} ('{decision.trust.name}'); "
                     f"{nl['approvals_needed']} more approval(s) unlock level {nl['level']} "
                     f"({_eur(nl['max_autonomous_spend'])} autonomous limit).")
        return text
    if decision.trusted_rule:
        r = decision.trusted_rule
        waived = [clause(v).replace(f" (waived by trusted rule #{r['id']})", "") for v in vs if v.waived_by_rule]
        return (f"Auto-approved ({_eur(total)}) under trusted rule #{r['id']}, created when {r['created_by']} "
                f"approved order {r['created_from_order']}. Waived: {_join(waived)}. "
                f"The rule expires {r['expires_at'][:10]}.")
    limit = decision.totals.get("autonomous_limit")
    lvl = f" for trust level {decision.trust.level} ('{decision.trust.name}')" if decision.trust else ""
    neg = next((v for v in vs if v.code == "NEGOTIATED_OVER_LIMIT"), None)
    if neg:
        return (f"Auto-approved under the negotiation policy: {neg.because}. All other checks passed "
                f"(daily cap, allergens, drift, price, stock).")
    return (f"Auto-approved: all policy checks passed. Total {_eur(total)} is within the "
            f"{_eur(limit)} autonomous limit{lvl}.")


# =============================================================================
# Trust escalation: learn a narrow rule from a human approval (#1)
# =============================================================================

def build_trusted_rule(order: dict[str, Any], reviewer: str, policy: Policy,
                       now: Optional[datetime] = None) -> Optional[dict[str, Any]]:
    """
    Returns a rule dict for Database.add_trusted_rule(), or None when the
    approval must not become a rule. That is the case when an escalation reason
    is not waivable (e.g. a price jump) or nothing was escalated at all.
    """
    if not (policy.get("trusted_rules.enabled") and policy.get("trusted_rules.auto_create_on_approval")):
        return None
    decision = order.get("decision") or {}
    violations = decision.get("violations") or []
    if any(v.get("severity") == "REJECT" for v in violations):
        return None
    codes = {v["code"] for v in violations if v.get("severity") == "PENDING"}
    if not codes or not codes <= policy.waivable_codes:
        return None
    qty_tol = 1 + float(policy.get("trusted_rules.quantity_tolerance_pct", 0)) / 100
    val_tol = 1 + float(policy.get("trusted_rules.value_tolerance_pct", 10)) / 100
    lines = order.get("lines") or []
    now = now or datetime.now(timezone.utc)
    ttl = timedelta(days=int(policy.get("trusted_rules.ttl_days", 30)))
    return {
        "agent_id": order["agent_id"],
        "customer": order["customer"],
        "product_ids": sorted({l["productId"] for l in lines}),
        "max_quantities": {l["productId"]: round(float(l["quantity"]) * qty_tol, 6) for l in lines},
        "max_net_total": round(float((decision.get("totals") or {}).get("net_total", 0)) * val_tol, 2),
        "waived_codes": sorted(codes),
        "substitutions": {l["productId"]: l["substitutesFor"] for l in lines if l.get("substitutesFor")},
        "created_from_order": order["order_id"],
        "created_by": reviewer,
        "expires_at": (now + ttl).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


# =============================================================================
# Negotiation hooks (pure): which orders qualify, and the negotiated order lines
# =============================================================================

def negotiation_candidate(decision: Decision, lines: list[OrderLine], policy: Policy) -> Optional[OrderLine]:
    """
    A single-line order that needs a human ONLY partly because it is over the agent's autonomous
    limit, by less than negotiation.max_over_budget_pct. Never for REJECTED orders.
    """
    if not policy.get("negotiation.enabled") or decision.status is not Status.PENDING_APPROVAL or len(lines) != 1:
        return None
    if any(v.severity is Severity.REJECT for v in decision.violations):
        return None
    if not any(v.code == "SPEND_LIMIT" and v.severity is Severity.PENDING for v in decision.violations):
        return None
    limit, total = float(decision.totals["autonomous_limit"]), float(decision.totals["net_total"])
    if not limit or total > limit * (1 + float(policy.get("negotiation.max_over_budget_pct", 20)) / 100):
        return None
    line = lines[0]
    return line if line.effective_unit_price else None


def apply_negotiation(line: OrderLine, offer: dict[str, Any]) -> OrderLine:
    """The won deal as an order line: more units at the negotiated unit price (quoted == live, no drift)."""
    from dataclasses import replace
    return replace(line, quantity=float(offer["new_qty"]), quoted_unit_price=float(offer["new_unit_price"]),
                   live_unit_price=float(offer["new_unit_price"]))


# =============================================================================
# Rolling spend ledger (kept for backward compatibility; SQLite replaces it)
# =============================================================================

class SpendLedger:
    """In-memory ledger of AUTO_APPROVED spend. Superseded by Database.autonomous_spend_since()."""

    WINDOW_SECONDS = 24 * 3600

    def __init__(self) -> None:
        self._events: dict[str, deque[tuple[float, float]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def record(self, customer: str, amount: float, ts: Optional[float] = None) -> None:
        with self._lock:
            self._events[customer].append((ts or time.time(), float(amount)))

    def spent_last_24h(self, customer: str, now: Optional[float] = None) -> float:
        now = now or time.time()
        with self._lock:
            q = self._events[customer]
            while q and q[0][0] < now - self.WINDOW_SECONDS:
                q.popleft()
            return round(sum(a for _, a in q), 2)
