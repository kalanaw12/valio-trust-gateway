"""
Populate a running gateway with orders that exercise every dashboard state.

    python examples/seed_dashboard.py                    # http://127.0.0.1:8000
    python examples/seed_dashboard.py --url http://host:8000

Creates:
  * a large order         -> PENDING_APPROVAL (spend above the agent's autonomous limit)
  * a second large order  -> PENDING_APPROVAL
  * a small top-up        -> AUTO_APPROVED and placed
  * an allergen conflict  -> REJECTED by policy (milk_allergy profile ordering milk)
Works against both live and mock upstream.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import date, timedelta

import httpx

AGENT = {"X-Agent-Key": os.getenv("DEMO_AGENT_KEY", "dev-agent-key")}

SCENARIOS = [
    ("Big weekly milk order", "464073", 1000, "lactose_intolerant"),
    ("Banquet milk order", "464201", 600, "lactose_intolerant"),
    ("Small top-up", "464073", 4, "lactose_intolerant"),
    ("Allergen conflict", "464073", 10, "milk_allergy"),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    args = ap.parse_args()
    delivery = (date.today() + timedelta(days=3)).isoformat()

    with httpx.Client(base_url=args.url, timeout=60) as c:
        try:
            c.get("/health").raise_for_status()
        except httpx.HTTPError as exc:
            sys.exit(f"Gateway not reachable at {args.url}: {exc}")
        for label, pid, qty, profile in SCENARIOS:
            q = c.post("/v1/quote", headers=AGENT, json={
                "requested_date": delivery, "buyer_profile": profile,
                "lines": [{"product_id": pid, "quantity": qty}]})
            if q.status_code != 200:
                print(f"{label:24} quote failed: HTTP {q.status_code} {q.text[:200]}")
                continue
            o = c.post("/v1/orders", headers=AGENT, json={"quote_id": q.json()["quote_id"]})
            if o.status_code != 200:
                print(f"{label:24} order failed: HTTP {o.status_code} {o.text[:200]}")
                continue
            order = o.json()
            print(f"{label:24} {order['order_id']}  {order['status']:17} "
                  f"{order['decision']['totals']['net_total']:>9.2f} EUR  {'; '.join(order['decision']['reasons'])[:90]}")
    print(f"\nOpen {args.url}/dashboard  (approver key: dev-approver-key unless you changed it)")


if __name__ == "__main__":
    main()
