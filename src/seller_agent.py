"""
Valio Aimo Seller Agent (simulated upstream surplus -> proactive B2B offer)
==========================================================================

We are the BUYER agent (a hotel); Valio Aimo is the SELLER. This module plays
Valio's side: it "detects" a surplus lot from an upstream supplier and pushes a
proactive offer to clear the warehouse.

Grounded in the challenge data:
  * product: a random PERISHABLE (milk, cheese, juice, yoghurt, cream, ...) from the
    real product catalogue (already loaded in memory, so the 85 MB JSON isn't re-read):
    chilled (temperatureCondition 1-6) food (reduced VAT class), not cleaners or chocolate;
  * supplier: the product's real `vendorName`;
  * price: the live base price from Valio Aimo's `/api/price` (with availability from
    `/api/availability`). Only products that are priced and in stock are offered;
    ones with a customer net price are preferred (they can be auto-approved).
Simulated: the surplus itself, its size (120-400 units) and the clearance discount (10-20%).

Set SELLER_AGENT_SEED for a reproducible demo.
"""

from __future__ import annotations

import logging
import os
import random
import re
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Optional

logger = logging.getLogger("gateway.seller")

PERISHABLE = re.compile(
    r"\b(milk|maito|cheese|juusto|juice|mehu|yogh?urt|jogurtti|cream|kerma|quark|rahka|kefir|piimä|"
    r"buttermilk|smoothie|skyr)\b", re.I)
# Non-food that happens to mention milk/juice ("milk system cleaner", "juice dispenser rinse", ...)
NON_FOOD = re.compile(r"clean|cleaner|detergent|rinse|descal|sanit|disinfect|pesu|puhdist|huuhtel|kalkin|"
                      r"dispenser|machine|system|foam|frother|jug|kann|pitcher|filter", re.I)
CANDIDATES_PER_RUN = 40          # one batched /api/price + /api/availability call
LOT_VALUE_EUR = (250, 700)
CHILLED = {1, 2, 3, 4, 5, 6}     # temperatureCondition codes of chilled goods (7 = frozen, 8 = ambient)       # surplus lot size by VALUE, so a hotel can realistically take it
_rng = random.Random(int(os.environ["SELLER_AGENT_SEED"])) if os.getenv("SELLER_AGENT_SEED") else random.Random()


class SellerAgentError(RuntimeError):
    """No suitable product could be offered (e.g. nothing priced / in stock right now)."""


def _perishables(catalog) -> list:
    cached = getattr(catalog, "_perishables_cache", None)
    if cached is None:
        # Food check from the data itself: Finnish food is in the reduced VAT class (vatCode MEDIUM, 13.5%);
        # cleaning chemicals etc. are STANDARD (25.5%). The keyword filter is only a second line of defence.
        # Perishable = CHILLED: temperatureCondition 1-6 (fresh milk, cheese, feta, yoghurt);
        # 7 = frozen (ice cream, IQF) and 8 = ambient (chocolate, canned fruit, milk powder) are excluded.
        cached = [p for p in catalog.products
                  if p.sales_unit and p.vat_code == "MEDIUM" and p.temperature_condition in CHILLED
                  and PERISHABLE.search(f"{p.name_en or ''} {p.name_fi or ''}")
                  and not NON_FOOD.search(f"{p.name_en or ''} {p.name_fi or ''}")]
        catalog._perishables_cache = cached
    return cached


async def generate_proactive_offer(adapter, customer: str, *, rng: Optional[random.Random] = None,
                                   min_discount: int = 10, max_discount: int = 20) -> dict[str, Any]:
    """
    Returns {product_id, name, base_price, discount_percent, offer_price, stock_status, ...}.
    base_price is the live net price Valio's /api/price returned for this customer, right now.
    """
    rng = rng or _rng
    pool = _perishables(adapter.catalog)
    if not pool:
        raise SellerAgentError("The catalogue has no perishable products")
    sample = rng.sample(pool, min(CANDIDATES_PER_RUN, len(pool)))
    delivery = (date.today() + timedelta(days=2)).isoformat()
    live = await adapter.live_snapshot(customer, delivery, [p.id for p in sample])   # /api/price + /api/availability

    priced = []
    for p in sample:
        snap = live.get(p.id) or {}
        price, avail = snap.get("price"), snap.get("availability")
        if price and price.status == "PRICED" and price.unit_price and avail and avail.status == "AVAILABLE":
            priced.append((p, price, avail))
    if not priced:
        raise SellerAgentError(f"None of {len(sample)} sampled perishables is priced and in stock right now")
    preferred = [x for x in priced if x[1].net_price_found] or priced   # net price = can be auto-approved
    p, price, avail = rng.choice(preferred)

    discount = rng.randint(min_discount, max_discount)
    base = Decimal(str(price.unit_price))
    offer_price = (base * (1 - Decimal(discount) / 100)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    lot = p.allowed_lot_size if (p.sales_unit or "").upper() in ("KG", "G", "L", "LTR") else max(p.allowed_lot_size or 1, 1)
    # Lot size by value (EUR 250-700 at base price), whole lots, at least 12 units so a +20% counter is meaningful
    target_value = Decimal(str(rng.uniform(*LOT_VALUE_EUR)))
    step = Decimal(str(lot))
    qty = float(max((target_value / base / step).to_integral_value() * step, Decimal(12) * step))
    supplier = p.vendor or "an upstream supplier"

    return {
        "product_id": p.id,
        "name": p.display_name,
        "base_price": float(base),                     # live, from Valio /api/price
        "discount_percent": discount,
        "offer_price": float(offer_price),
        "stock_status": "Surplus Stock",
        # extra context for the offer card / negotiation
        "currency": price.currency or "EUR",
        "net_price_found": price.net_price_found,
        "sales_unit": p.sales_unit,
        "quantity_available": qty,
        "supplier": supplier,
        "reason": f"Surplus lot from upstream supplier {supplier}",
        "valid_until": (date.today() + timedelta(days=2)).isoformat(),
        "priced_at": price.valid_from,
        "candidates_checked": len(sample),
        "simulated": ["surplus", "quantity", "discount"],
    }
