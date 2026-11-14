"""
Hotel inventory and standing orders.

The hotel's recurring stock (what it buys every week), the par levels that trigger a restock and the
weekly / monthly limits that a restock must never exceed. The product ids are real Valio Aimo catalog
products (checked against the live price + availability API).

Stock model (all real data, nothing invented):
    on_hand  = last stock count
             + deliveries received since that count   (PLACED orders whose delivery date has passed)
             - estimated usage since that count        (weekly_usage / 7 per day)
    incoming = PLACED orders not delivered yet
    awaiting = orders of the item still PENDING_APPROVAL
A manager can record a physical stock count at any time (POST /v1/inventory/count), which resets the
baseline. Until the first count, `initial_stock` below is the baseline.

check_inventory_levels() compares on_hand with the par level and returns what to order: enough to get back
to `target_level`, minus what is already incoming or awaiting approval, capped by the item's remaining
weekly / monthly unit limit and (when live prices are given) by the hotel's weekly / monthly budget.
Ordering itself goes through the gateway's normal pipeline (quote -> guardrails -> audit), see main.py.
"""
from __future__ import annotations

import json
import math
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

# ---------------------------------------------------------------------------------------------------------
# The hotel's standing order. Quantities are in each product's SALES units (the pack Valio sells, e.g. one
# 1 l carton = 1 ST). Limits apply to everything ordered for that product (restocks and manual orders).
# ---------------------------------------------------------------------------------------------------------
STANDING_ORDER: dict[str, Any] = {
    "hotel": "Hotel kitchen & breakfast buffet",
    "budget": {"weekly_eur": 6000.0, "monthly_eur": 24000.0},  # all purchasing for the customer
    "items": [
        {"product_id": "464201", "label": "Lactose-free semi-skimmed milk 1 l",
         "weekly_usage": 420, "par_level": 120, "target_level": 480,
         "weekly_limit": 500, "monthly_limit": 2000, "initial_stock": 90},
        {"product_id": "462616", "label": "Valio Edam 17 % cheese slices 1 kg",
         "weekly_usage": 25, "par_level": 8, "target_level": 30,
         "weekly_limit": 40, "monthly_limit": 150, "initial_stock": 20},
        {"product_id": "472560", "label": "Orange juice 1 l",
         "weekly_usage": 140, "par_level": 40, "target_level": 160,
         "weekly_limit": 200, "monthly_limit": 800, "initial_stock": 35},
        {"product_id": "476824", "label": "Lactose-free natural yoghurt 1 kg",
         "weekly_usage": 50, "par_level": 15, "target_level": 60,
         "weekly_limit": 80, "monthly_limit": 300, "initial_stock": 40},
    ],
}

# Statuses that count against limits / budgets (something was, or may be, bought)
_COMMITTED = ("PLACED", "PENDING_APPROVAL")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_counts (
    product_id  TEXT PRIMARY KEY,
    on_hand     REAL NOT NULL,
    counted_at  TEXT NOT NULL,          -- ISO-8601 UTC
    counted_by  TEXT NOT NULL
);
"""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def item(product_id: str) -> Optional[dict[str, Any]]:
    return next((i for i in STANDING_ORDER["items"] if i["product_id"] == product_id), None)


def ensure_schema(db: Any) -> None:
    """Create the stock-count table and the baseline count for items that have none yet."""
    with db.tx() as conn:
        conn.execute(_SCHEMA.strip().rstrip(";"))      # execute(), not executescript(): stays inside the tx
        now = _iso(_now())
        for it in STANDING_ORDER["items"]:
            conn.execute("INSERT OR IGNORE INTO inventory_counts (product_id, on_hand, counted_at, counted_by) "
                         "VALUES (?, ?, ?, ?)", (it["product_id"], float(it["initial_stock"]), now,
                                                 "initial stock (standing order)"))


def record_count(db: Any, product_id: str, on_hand: float, counted_by: str) -> dict[str, Any]:
    """A physical stock count: becomes the new baseline for the stock estimate."""
    if item(product_id) is None:
        raise KeyError(product_id)
    now = _iso(_now())
    with db.tx() as conn:
        conn.execute("INSERT INTO inventory_counts (product_id, on_hand, counted_at, counted_by) VALUES (?, ?, ?, ?) "
                     "ON CONFLICT(product_id) DO UPDATE SET on_hand = excluded.on_hand, "
                     "counted_at = excluded.counted_at, counted_by = excluded.counted_by",
                     (product_id, float(on_hand), now, counted_by))
    return {"product_id": product_id, "on_hand": float(on_hand), "counted_at": now, "counted_by": counted_by}


def _order_lines(db: Any, customer: str, product_ids: list[str]) -> list[dict[str, Any]]:
    marks = ",".join("?" * len(product_ids))
    rows = db.query(f"SELECT o.order_id, o.status, o.created_at, o.net_total, o.data, l.product_id, l.quantity "
                    f"FROM orders o JOIN order_lines l ON l.order_id = o.order_id "
                    f"WHERE o.customer = ? AND l.product_id IN ({marks})", (customer, *product_ids))
    for r in rows:
        try:
            r["delivery_date"] = (json.loads(r.pop("data")) or {}).get("requested_date")
        except (TypeError, ValueError):
            r["delivery_date"] = None
    return rows


def _spend_since(db: Any, customer: str, since: datetime) -> float:
    row = db.one("SELECT COALESCE(SUM(net_total), 0) AS s FROM orders WHERE customer = ? AND created_at >= ? "
                 f"AND status IN ({','.join('?' * len(_COMMITTED))})", (customer, _iso(since), *_COMMITTED))
    return round(float(row["s"] if row else 0), 2)


def check_inventory_levels(db: Any, catalog: Any, customer: str, *,
                           prices: Optional[dict[str, float]] = None,
                           now: Optional[datetime] = None) -> dict[str, Any]:
    """
    Current stock vs par levels for every standing-order item, and what to order without exceeding the
    weekly / monthly unit limits (and, when `prices` {product_id: EUR per sales unit} are given, the budget).
    """
    now = now or _now()
    today = now.date()
    week_start = datetime.combine(today - timedelta(days=today.weekday()), datetime.min.time(), timezone.utc)
    month_start = datetime.combine(today.replace(day=1), datetime.min.time(), timezone.utc)
    items = STANDING_ORDER["items"]
    ids = [i["product_id"] for i in items]
    counts = {r["product_id"]: r for r in db.query(
        f"SELECT * FROM inventory_counts WHERE product_id IN ({','.join('?' * len(ids))})", tuple(ids))}
    lines = _order_lines(db, customer, ids)

    out = []
    for it in items:
        pid = it["product_id"]
        p = catalog.get(pid)
        c = counts.get(pid) or {"on_hand": float(it["initial_stock"]), "counted_at": _iso(now), "counted_by": "initial stock"}
        counted_at = _parse(c["counted_at"])
        mine = [r for r in lines if r["product_id"] == pid]
        received = sum(r["quantity"] for r in mine if r["status"] == "PLACED" and r["created_at"] >= c["counted_at"]
                       and r["delivery_date"] and r["delivery_date"] <= today.isoformat())
        incoming = sum(r["quantity"] for r in mine if r["status"] == "PLACED"
                       and r["delivery_date"] and r["delivery_date"] > today.isoformat())
        awaiting = sum(r["quantity"] for r in mine if r["status"] == "PENDING_APPROVAL")
        days = max(0.0, (now - counted_at).total_seconds() / 86400)
        used = it["weekly_usage"] / 7 * days
        on_hand = max(0.0, c["on_hand"] + received - used)
        ordered_week = sum(r["quantity"] for r in mine if r["status"] in _COMMITTED and r["created_at"] >= _iso(week_start))
        ordered_month = sum(r["quantity"] for r in mine if r["status"] in _COMMITTED and r["created_at"] >= _iso(month_start))
        week_left = max(0.0, it["weekly_limit"] - ordered_week)
        month_left = max(0.0, it["monthly_limit"] - ordered_month)

        low = on_hand < it["par_level"]
        need = max(0.0, it["target_level"] - on_hand - incoming - awaiting) if low else 0.0
        suggested = math.floor(min(need, week_left, month_left))
        capped_by = [n for n, lim in (("weekly_limit", week_left), ("monthly_limit", month_left)) if need > lim]
        price = (prices or {}).get(pid)
        out.append({
            "product_id": pid, "label": it["label"],
            "name": p.display_name if p else it["label"], "sales_unit": p.sales_unit if p else "units",
            "on_hand": round(on_hand, 1), "par_level": it["par_level"], "target_level": it["target_level"],
            "weekly_usage": it["weekly_usage"], "days_of_cover": round(on_hand / (it["weekly_usage"] / 7), 1),
            "status": "LOW" if low else "OK",
            "incoming": round(incoming, 1), "awaiting_approval": round(awaiting, 1),
            "last_count": {"on_hand": c["on_hand"], "counted_at": c["counted_at"], "counted_by": c["counted_by"]},
            "limits": {"weekly_limit": it["weekly_limit"], "monthly_limit": it["monthly_limit"],
                       "ordered_this_week": round(ordered_week, 1), "ordered_this_month": round(ordered_month, 1),
                       "weekly_remaining": round(week_left, 1), "monthly_remaining": round(month_left, 1)},
            "need": round(need, 1), "suggested_qty": suggested, "capped_by": capped_by,
            "unit_price_eur": round(price, 2) if price else None,
            "estimated_cost_eur": round(suggested * price, 2) if price and suggested else (0.0 if price else None),
        })

    # Budget: the most urgent items (fewest days of cover) get the money first.
    budget = STANDING_ORDER["budget"]
    spent_week, spent_month = _spend_since(db, customer, week_start), _spend_since(db, customer, month_start)
    left = min(budget["weekly_eur"] - spent_week, budget["monthly_eur"] - spent_month)
    budget_checked = prices is not None
    if budget_checked:
        for row in sorted((r for r in out if r["suggested_qty"] > 0), key=lambda r: r["days_of_cover"]):
            price = row["unit_price_eur"]
            if not price:
                continue
            afford = max(0, math.floor(max(left, 0) / price))
            if afford < row["suggested_qty"]:
                row["suggested_qty"] = afford
                row["capped_by"].append("weekly_budget" if budget["weekly_eur"] - spent_week <= budget["monthly_eur"] - spent_month
                                        else "monthly_budget")
            row["estimated_cost_eur"] = round(row["suggested_qty"] * price, 2)
            left -= row["estimated_cost_eur"]

    low = [r for r in out if r["status"] == "LOW"]
    to_order = [r for r in out if r["suggested_qty"] > 0]
    return {
        "hotel": STANDING_ORDER["hotel"], "customer": customer, "generated_at": _iso(now),
        "status": "LOW_STOCK" if low else "HEALTHY", "low_count": len(low), "low_items": [r["label"] for r in low],
        "items": out, "needs_restock": [r["product_id"] for r in to_order],
        "estimated_restock_total_eur": round(sum(r["estimated_cost_eur"] or 0 for r in to_order), 2) if budget_checked else None,
        "budget": {"weekly_eur": budget["weekly_eur"], "monthly_eur": budget["monthly_eur"],
                   "spent_this_week": spent_week, "spent_this_month": spent_month,
                   "weekly_remaining": round(budget["weekly_eur"] - spent_week, 2),
                   "monthly_remaining": round(budget["monthly_eur"] - spent_month, 2),
                   "checked": budget_checked},
        "stock_model": "estimated: last stock count + delivered orders - expected usage since the count",
    }
