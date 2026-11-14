"""
Autonomous Negotiation Engine (simulated counter-party)
=======================================================

When an order is slightly over the agent's budget, the gateway's agent tries a
classic bulk deal: buy MORE (+20% quantity) for a lower unit price (-10% on the
total). Valio Aimo's side is SIMULATED, because the challenge API has no
negotiation endpoint: it accepts when the new quantity exceeds 500 units.

Read the numbers carefully. +20% quantity at -10% costs 1.2 x 0.9 = 1.08x the
original order, so a won negotiation buys more for a lower UNIT price but spends
~8% MORE in total. "saved_amount" is the discount versus the list price of the
larger quantity, not money saved versus the original order. That's why the
gateway re-checks a negotiated order with the full guardrails and never lets
negotiation bypass a spend limit.

Pure functions only: no I/O, deterministic, easy to test and to replay.
"""

from __future__ import annotations

from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal
from typing import Any, Optional

COUNTERPARTY = "Valio Aimo (simulated counter-party)"


def _money(x: Decimal) -> float:
    return float(x.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _round_up_to_lot(qty: Decimal, lot: Optional[float]) -> Decimal:
    if not lot or lot <= 0:
        return qty.to_integral_value(rounding=ROUND_CEILING)
    step = Decimal(str(lot))
    return (qty / step).to_integral_value(rounding=ROUND_CEILING) * step


def negotiate_offer(requested_qty: float, unit_price: float, max_budget: float, *,
                    quantity_uplift_pct: float = 20, discount_pct: float = 10,
                    accept_min_qty: float = 500, lot_size: Optional[float] = None) -> dict[str, Any]:
    """
    Returns a negotiation record. status is one of:
      NOT_NEEDED        - the order fits the budget; nothing to negotiate
      NEGOTIATION_WON   - counter-offer accepted (new_qty > accept_min_qty)
      NEGOTIATION_LOST  - counter-offer rejected by the (simulated) counter-party
    """
    q, p, budget = Decimal(str(requested_qty)), Decimal(str(unit_price)), Decimal(str(max_budget))
    original_total = q * p
    base = {"counterparty": COUNTERPARTY, "simulated": True, "original_qty": float(q), "unit_price": float(p),
            "original_total": _money(original_total), "max_budget": _money(budget)}
    if original_total <= budget:
        return {**base, "status": "NOT_NEEDED", "reason": "Order fits the budget"}

    # Counter-offer: +20% quantity (whole lots), -10% on the new total
    new_qty = _round_up_to_lot(q * (1 + Decimal(str(quantity_uplift_pct)) / 100), lot_size)
    list_total = new_qty * p
    discount = Decimal(str(discount_pct)) / 100
    new_total = list_total * (1 - discount)
    offer = {**base, "proposed_qty": float(new_qty), "discount_pct": float(discount_pct),
             "list_total_for_new_qty": _money(list_total), "proposed_total": _money(new_total)}

    # Simulated counter-party decision
    if new_qty > Decimal(str(accept_min_qty)):
        return {**offer, "status": "NEGOTIATION_WON", "new_qty": float(new_qty), "new_total": _money(new_total),
                "new_total_price": _money(new_total),
                # 4 decimals so new_qty x new_unit_price reproduces new_total to the cent
                "new_unit_price": float((p * (1 - discount)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
                "saved_amount": _money(list_total - new_total),                 # vs list price of the bigger order
                "spend_change_vs_original": _money(new_total - original_total),  # usually positive (+8%)
                "reason": f"Bulk deal accepted: {float(new_qty):g} units exceeds the {accept_min_qty:g}-unit threshold"}
    return {**offer, "status": "NEGOTIATION_LOST",
            "reason": f"Counter-offer declined: {float(new_qty):g} units is not above the {accept_min_qty:g}-unit threshold"}


def simulate_valio_negotiation(product_id: str, requested_qty: float, unit_price: float, max_budget: float, *,
                               max_over_budget_pct: float = 20, quantity_uplift_pct: float = 20,
                               discount_pct: float = 10, accept_min_qty: float = 100,
                               lot_size: Optional[float] = None) -> dict[str, Any]:
    """
    Spec-shaped entry point:
        {"status": "ACCEPTED" | "REJECTED" | "NOT_NEEDED" | "NOT_ELIGIBLE",
         "new_qty", "new_total_price", "saved_amount", ...full record}

    Only orders over budget by LESS than max_over_budget_pct are negotiated (NOT_ELIGIBLE otherwise).
    saved_amount = list price of the new (bigger) quantity minus the discounted price, so it matches the
    spec example (1,200 units for 1,620 saves 180). Versus the ORIGINAL order the deal costs
    spend_change_vs_original more (+8% with the default terms), reported alongside so nobody is misled.
    """
    total = float(requested_qty) * float(unit_price)
    base = {"product_id": product_id, "counterparty": COUNTERPARTY, "simulated": True}
    if total <= max_budget:
        return {**base, "status": "NOT_NEEDED", "reason": "Order fits the budget"}
    if total > max_budget * (1 + max_over_budget_pct / 100):
        return {**base, "status": "NOT_ELIGIBLE",
                "reason": f"Order is more than {max_over_budget_pct:g}% over the budget; not negotiated"}
    rec = negotiate_offer(requested_qty, unit_price, max_budget, quantity_uplift_pct=quantity_uplift_pct,
                          discount_pct=discount_pct, accept_min_qty=accept_min_qty, lot_size=lot_size)
    status = {"NEGOTIATION_WON": "ACCEPTED", "NEGOTIATION_LOST": "REJECTED"}.get(rec["status"], rec["status"])
    return {**base, **rec, "status": status, "engine_status": rec["status"]}


def negotiate_proactive_offer(product_id: str, requested_qty: float, list_unit_price: float,
                              offer_discount_pct: float, quantity_available: float, *,
                              quantity_uplift_pct: float = 20, extra_discount_pct: float = 10,
                              lot_size: Optional[float] = None) -> dict[str, Any]:
    """
    The agent accepts a Valio proactive (surplus) offer and counter-proposes: "+20% volume for an
    extra 10% off the offer price". Simulated Valio rule: accept if the bigger volume still fits the
    surplus quantity on offer (clearing surplus is exactly what the offer is for).

    saved_amount = savings FROM THE NEGOTIATION ONLY (offer price -> negotiated price, on the new
    quantity). The offer's own discount is Valio's, not the negotiation's, and is reported separately.
    """
    q, lp = Decimal(str(requested_qty)), Decimal(str(list_unit_price))
    avail = Decimal(str(quantity_available))
    offer_unit = lp * (1 - Decimal(str(offer_discount_pct)) / 100)
    new_qty = _round_up_to_lot(q * (1 + Decimal(str(quantity_uplift_pct)) / 100), lot_size)
    neg_unit = offer_unit * (1 - Decimal(str(extra_discount_pct)) / 100)
    base = {"product_id": product_id, "counterparty": COUNTERPARTY, "simulated": True, "source": "proactive_offer",
            "original_qty": float(q), "list_unit_price": float(lp),
            "offer_discount_pct": float(offer_discount_pct), "offer_unit_price": float(offer_unit.quantize(Decimal("0.000001"))),
            "original_total": _money(q * offer_unit),                      # the offer accepted as-is
            "proposed_qty": float(new_qty), "discount_pct": float(extra_discount_pct),
            "quantity_available": float(avail)}
    if q <= 0:
        return {**base, "status": "NEGOTIATION_LOST", "reason": "Quantity must be positive"}
    if new_qty > avail:
        return {**base, "status": "NEGOTIATION_LOST",
                "reason": f"Counter-offer declined: {float(new_qty):g} units exceeds the {float(avail):g} on offer"}
    new_total = new_qty * neg_unit
    offer_total_new_qty = new_qty * offer_unit
    return {**base, "status": "NEGOTIATION_WON", "new_qty": float(new_qty),
            # 6 decimals: two stacked discounts (e.g. 1.75 x 0.85 x 0.9 = 1.33875) must not lose the cent
            "new_unit_price": float(neg_unit.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
            "new_total": _money(new_total), "new_total_price": _money(new_total),
            "list_total_for_new_qty": _money(new_qty * lp),
            "saved_amount": _money(offer_total_new_qty - new_total),              # the negotiation's own saving
            "offer_savings": _money(new_qty * lp - offer_total_new_qty),          # Valio's offer discount
            "total_saved_vs_list": _money(new_qty * lp - new_total),
            "spend_change_vs_original": _money(new_total - q * offer_unit),
            "reason": f"Bulk counter-offer accepted: {float(new_qty):g} of {float(avail):g} surplus units"}


def suggested_offer_quantity(quantity_available: float, quantity_uplift_pct: float = 20,
                             lot_size: Optional[float] = None) -> float:
    """Largest base quantity whose +uplift still fits the surplus on offer (so the counter-offer can be accepted)."""
    avail = Decimal(str(quantity_available))
    step = Decimal(str(lot_size)) if lot_size and lot_size > 0 else Decimal(1)
    q = (avail / (1 + Decimal(str(quantity_uplift_pct)) / 100) / step).to_integral_value(rounding="ROUND_FLOOR") * step
    while q > 0 and _round_up_to_lot(q * (1 + Decimal(str(quantity_uplift_pct)) / 100), float(step)) > avail:
        q -= step
    return float(max(q, step))
