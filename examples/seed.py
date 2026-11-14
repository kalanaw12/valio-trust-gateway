"""
Seed a running gateway with a realistic week of agent activity for the demo.

    python examples/seed.py                      # http://localhost:8000
    python examples/seed.py --url http://host:8000 --delay 1.5

Every order goes through the real flow (signed quote -> order -> guardrails), so
the dashboard shows each one appear live over the WebSocket. Nothing is faked:
the server timestamps orders "now" and the live Valio API prices them.

Order of events (it matters):
  1. Cleaning-chemicals restock, 10 x 460052 (~€879)  -> PENDING_APPROVAL  (over the €750 agent limit)
     Placed FIRST so there is no history yet, so it can't also be flagged as drift.
     It is <20% over budget, so the agent tries to negotiate, but 12 units is too few: NEGOTIATION_LOST.
  1b. Bulk UHT milk, 480 x 464073 (~€787, ~5% over)  -> NEGOTIATION_WON, AUTO_APPROVED
     (576 units at -10%; policy negotiation.auto_approve_won; simulated counter-party)
  2-4. Routine milk, ~20 x 463335 Valio Eila 3% (~€28) -> AUTO_APPROVED x3 (builds the drift baseline)
  5. Milk spike, 80 x 463335 (+300% vs usual)         -> PENDING_APPROVAL  (DRIFT_DETECTED)
  6. Salted peanuts for a nut-free kitchen            -> REJECTED          (allergen: peanuts)

Product choice: with the placeholder customer `demo-customer`, only a handful of
products have a customer net price. Without one, an order needs a human whatever
its size. 463335 and 460052 do have one.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import date, timedelta

import requests

AGENT_HEADERS = {"X-Agent-Key": os.getenv("DEMO_AGENT_KEY", "dev-agent-key")}

MILK = "463335"          # Valio Eila 3% milk drink 1 l lactose free (net price available)
CLEANING = "460052"      # Suma Auto Oven Rinse D9.11 10 l (net price available, ~€88 each)
PEANUTS = "460428"       # Taffel salted peanuts 300 g (contains peanuts, AP)
UHT_MILK = "464073"      # Valio whole milk 1 l lactose free UHT (~€1.64): 480 units ~5% over the €750 limit

SCENARIOS = [
    # (day label, description, product, quantity, buyer profile, expected status)
    ("Mon", "Monthly cleaning-chemicals restock", CLEANING, 10, "default", "PENDING_APPROVAL"),
    ("Mon", "Bulk UHT milk, ~5% over budget -> agent negotiates", UHT_MILK, 480, "lactose_intolerant", "AUTO_APPROVED"),
    ("Tue", "Routine breakfast milk", MILK, 20, "lactose_intolerant", "AUTO_APPROVED"),
    ("Wed", "Routine breakfast milk", MILK, 22, "lactose_intolerant", "AUTO_APPROVED"),
    ("Thu", "Routine breakfast milk", MILK, 18, "lactose_intolerant", "AUTO_APPROVED"),
    ("Fri", "Milk order spikes +300% (agent drift?)", MILK, 80, "lactose_intolerant", "PENDING_APPROVAL"),
    ("Sat", "Bar snacks ordered for a nut-free kitchen", PEANUTS, 10, "nut_free_kitchen", "REJECTED"),
]

COLOR = {"AUTO_APPROVED": "\033[92m", "PENDING_APPROVAL": "\033[95m", "REJECTED": "\033[91m"}
RESET = "\033[0m"


def place(session: requests.Session, base: str, pid: str, qty: float, profile: str) -> dict:
    delivery = (date.today() + timedelta(days=2)).isoformat()
    q = session.post(f"{base}/v1/quote", headers=AGENT_HEADERS, timeout=60, json={
        "requested_date": delivery, "buyer_profile": profile,
        "lines": [{"product_id": pid, "quantity": qty}]})
    q.raise_for_status()
    o = session.post(f"{base}/v1/orders", headers=AGENT_HEADERS, timeout=60,
                     json={"quote_id": q.json()["quote_id"]})
    o.raise_for_status()
    return o.json()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between orders (lets the WebSocket show each)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    color = not args.no_color and sys.stdout.isatty()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if color and os.name == "nt":
        os.system("")  # enable ANSI colours in the Windows console
    paint = (lambda s: f"{COLOR.get(s, '')}{s}{RESET}") if color else (lambda s: s)

    session = requests.Session()
    try:
        health = session.get(f"{base}/health", timeout=10).json()
    except requests.RequestException as exc:
        print(f"Gateway not reachable at {base}: {exc}\nStart it first (seed_and_run.ps1 does this for you).")
        return 2
    print(f"Seeding {base}  (upstream={health.get('upstream')}, policy={health.get('policy_version')})\n")

    matches = 0
    for i, (day, label, pid, qty, profile, expected) in enumerate(SCENARIOS):
        try:
            order = place(session, base, pid, qty, profile)
        except requests.HTTPError as exc:
            body = exc.response.text[:200] if exc.response is not None else ""
            print(f"{day}  {label}\n     ✗ request failed: {exc} {body}")
            continue
        d = order["decision"]
        got = d["status"]                          # the guardrail verdict (AUTO_APPROVED / PENDING / REJECTED)
        ok = got == expected
        matches += ok
        print(f"{day}  {label}")
        print(f"     {order['order_id']}  €{d['totals']['net_total']:,.2f}  → {paint(got)}  {'✓' if ok else f'✗ expected {expected}'}")
        neg = order.get("negotiation")
        if neg:
            if neg["status"] == "NEGOTIATION_WON":
                print(f"     🤝 {neg['status']}: {neg['new_qty']:g} for €{neg['new_total']:,.2f}, saved €{neg['saved_amount']:,.2f} "
                      f"vs list ({'+' if neg['spend_change_vs_original'] >= 0 else ''}€{neg['spend_change_vs_original']:,.2f} vs original; simulated)")
            else:
                print(f"     ✗ {neg['status']}: {neg['reason']}")
        print(f"     {d['explanation']}")
        if i < len(SCENARIOS) - 1:
            time.sleep(args.delay)

    # A Valio surplus offer for the "Proactive Offers" widget: click it -> Accept Offer & Negotiate
    try:
        r = session.post(f"{base}/v1/offers/proactive", timeout=30,
                         headers={"X-Admin-Key": os.getenv("DEMO_ADMIN_KEY", "dev-admin-key")},
                         json={"product_id": UHT_MILK, "discount_pct": 15, "quantity_available": 200,
                               "valid_until": (date.today() + timedelta(days=3)).isoformat(),
                               "reason": "Surplus UHT stock at Vantaa DC"})
        r.raise_for_status()
        print(f"\n🛒 Valio pushed a proactive offer ({r.json()['offer_id']}): 200 ST UHT milk at -15%. "
              "Click it in the dashboard to accept & negotiate.")
    except requests.RequestException as exc:
        print(f"\n(could not push the demo offer: {exc})")

    print(f"\n✅ Seeded {len(SCENARIOS)} orders ({matches}/{len(SCENARIOS)} as expected).")
    print(f"   Open {base}/dashboard  (manager / manager123): 2 orders wait for approval, 1 was rejected.")
    if matches < len(SCENARIOS):
        print("   Some outcomes differ: earlier activity (history, trusted rules, daily cap) changes later\n"
              "   decisions by design. For a clean slate run:  .\\seed_and_run.ps1 -Fresh")
    return 0 if matches == len(SCENARIOS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
