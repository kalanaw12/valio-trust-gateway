"""
Generate DEMO activity on a running gateway so every part of the dashboard has something to show.

    python examples/seed_demo.py                                   # http://127.0.0.1:8000
    python examples/seed_demo.py --url https://<your-modal-url>

Everything goes through the REAL API (live prices + stock -> signed quote -> guardrails -> audit), so the
numbers, charts, trust levels and the hash-chained audit trail stay consistent. It creates:
  * small orders within the agent's limit           -> AUTO-APPROVED and placed
  * large orders over the limit                      -> PENDING_APPROVAL (some left for you to decide)
  * an allergen conflict (milk_allergy profile)      -> REJECTED by policy (an "error prevented")
  * manager decisions: approve, Approve & Remember (trusted rule), reject
  * a repeat of the remembered order                 -> auto-approved by the TRUSTED RULE
Standing-order items (milk 464201, orange juice 472560) are left alone, so the Inventory card still shows
Low Stock and the Auto-restock button has something to do.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import date, timedelta

import httpx

AGENT = {"X-Agent-Key": os.getenv("DEMO_AGENT_KEY", "dev-agent-key")}

# (label, product_id, quantity in sales units, buyer profile)
AUTO = [
    ("Breakfast milk top-up", "464073", 24, "default"),
    ("Yoghurt for the buffet", "476824", 20, "default"),
    ("Yoghurt 5 kg for the kitchen", "476743", 6, "default"),
    ("Yoghurt cups 150 g", "464272", 10, "default"),
    ("Weekend milk top-up", "464073", 36, "default"),
]
LARGE = [
    ("Conference week milk", "464073", 600, "default"),        # -> approve & remember
    ("Banquet yoghurt", "476824", 400, "default"),             # -> approve
    ("Big Edam slices order", "476721", 240, "default"),       # -> reject
    ("Juice for the spa", "465262", 260, "default"),           # -> left pending
    ("Cheese platter Edam", "464204", 90, "default"),          # -> left pending
]
ALLERGEN = ("Milk for a guest with milk allergy", "464073", 10, "milk_allergy")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--user", default=os.getenv("DEMO_MANAGER_USER", "manager"))
    ap.add_argument("--password", default=os.getenv("DEMO_MANAGER_PASSWORD", "manager123"))
    args = ap.parse_args()
    delivery = (date.today() + timedelta(days=3))
    while delivery.weekday() >= 5:
        delivery += timedelta(days=1)

    with httpx.Client(base_url=args.url, timeout=90, follow_redirects=True) as c:
        try:
            c.get("/health").raise_for_status()
        except httpx.HTTPError as exc:
            sys.exit(f"Gateway not reachable at {args.url}: {exc}")
        tok = c.post("/v1/auth/login", json={"username": args.user, "password": args.password})
        if tok.status_code != 200:
            sys.exit(f"Manager login failed: HTTP {tok.status_code}")
        M = {"Authorization": f"Bearer {tok.json()['token']}"}

        def order(label: str, pid: str, qty: float, profile: str) -> dict | None:
            q = c.post("/v1/quote", headers=AGENT, json={"requested_date": delivery.isoformat(), "buyer_profile": profile,
                                                       "lines": [{"product_id": pid, "quantity": qty}]})
            if q.status_code != 200:
                print(f"  {label:36} quote failed: HTTP {q.status_code} {q.text[:160]}")
                return None
            o = c.post("/v1/orders", headers=AGENT, json={"quote_id": q.json()["quote_id"]})
            if o.status_code != 200:
                print(f"  {label:36} order failed: HTTP {o.status_code} {o.text[:160]}")
                return None
            d = o.json()
            neg = (d.get("negotiation") or {}).get("status")
            print(f"  {label:36} {d['order_id']}  {d['status']:17} {d['decision']['totals']['net_total']:>9.2f} EUR"
                  + (f"  [{neg}]" if neg else ""))
            time.sleep(0.4)
            return d

        def decide(o: dict | None, decision: str, comment: str, remember: bool = False) -> None:
            if not o or o["status"] != "PENDING_APPROVAL":
                return
            r = c.post(f"/v1/approvals/{o['order_id']}", headers=M,
                       json={"decision": decision, "comment": comment, "remember": remember})
            print(f"  -> {decision}{' & remember' if remember else ''} {o['order_id']}: HTTP {r.status_code} "
                  f"{(r.json().get('status') if r.status_code == 200 else r.text[:120])}")
            time.sleep(0.4)

        print("1) Small orders within the agent's limit")
        for s in AUTO:
            order(*s)
        print("2) Large orders over the limit")
        big = [order(*s) for s in LARGE]
        print("3) Allergen conflict")
        order(*ALLERGEN)
        print("4) Manager decisions")
        decide(big[0], "approve", "Conference week confirmed - remember this one", remember=True)
        decide(big[1], "approve", "Banquet on Saturday, approved")
        decide(big[2], "reject", "Too much cheese for this week, order half later")
        print("5) Repeat of the remembered order (should auto-approve via the trusted rule)")
        order("Conference week milk (repeat)", "464073", 600, "default")

        m = c.get("/v1/metrics", headers=M).json()
        print(f"\nDone. Total spend {m.get('total_spend')} EUR, pending approvals {m.get('pending_approvals')}, "
              f"trusted rules {m.get('active_trusted_rules')}.")
    print(f"Open {args.url}/dashboard")


if __name__ == "__main__":
    main()
