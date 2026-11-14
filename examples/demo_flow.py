"""
Judges' demo: smart auto-approval and trust escalation, live on the dashboard
==============================================================================

Runs against a RUNNING gateway, so every step also streams into the dashboard.

  1. Small routine order (~€50)                 -> AUTO_APPROVED     (green)
  2. Huge order (~€1,500)                       -> PENDING_APPROVAL  (over the autonomous limit)
  3. First-time substitution (milk out of stock) -> PENDING_APPROVAL  (never approved before)
  4. Manager clicks "Approve & Remember"        -> PLACED + trusted rule
  5. The same substitution again                -> AUTO_APPROVED     (trusted rule)
  6. Order with a blocked allergen              -> REJECTED          (red)

Start the server in DEMO MODE (fresh state, deterministic stock-out), PowerShell:

    Remove-Item var\\demo.db*, var\\demo_audit.jsonl* -ErrorAction SilentlyContinue
    $env:GATEWAY_SEMANTIC="0"; $env:GATEWAY_UPSTREAM="mock"; $env:MOCK_OUT_OF_STOCK="464073"
    $env:DB_PATH="var/demo.db"; $env:AUDIT_FILE="var/demo_audit.jsonl"
    python -m uvicorn src.main:app --port 8000

then open http://127.0.0.1:8000/dashboard (manager / manager123) and run:

    python examples/demo_flow.py
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import date, timedelta

import httpx

AGENT = {"X-Agent-Key": os.getenv("DEMO_AGENT_KEY", "dev-agent-key")}
MANAGER = (os.getenv("DEMO_MANAGER_USER", "manager"), os.getenv("DEMO_MANAGER_PASSWORD", "manager123"))

ROUTINE_SKU = "464201"      # Valio semi skimmed milk 1 l lactose free UHT (in stock)
OUT_OF_STOCK_SKU = "464073"  # Valio whole milk 1 l lactose free UHT (out of stock in demo mode)

COLORS = {"AUTO_APPROVED": "\033[92m", "PLACED": "\033[92m", "PENDING_APPROVAL": "\033[95m",
          "REJECTED": "\033[91m", "REJECTED_BY_HUMAN": "\033[91m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
results: list[tuple[str, bool]] = []


def paint(status: str, use_color: bool) -> str:
    return f"{COLORS.get(status, '')}{BOLD}{status}{RESET}" if use_color else status


def outcome(order: dict) -> str:
    """Placed orders report the decision that placed them (auto vs human)."""
    return order["decision"]["status"] if order["status"] == "PLACED" else order["status"]


def report(step: str, order: dict, expected: str, color: bool) -> None:
    got = outcome(order)
    ok = got == expected
    results.append((step, ok))
    d = order["decision"]
    print(f"   order {order['order_id']}  net €{d['totals']['net_total']:,.2f}  "
          f"(agent limit €{d['totals']['autonomous_limit']:,.0f})")
    print(f"   → {paint(got, color)}   {'✓' if ok else f'✗ expected {expected}'}")
    print(f"   {DIM if color else ''}{d['explanation']}{RESET if color else ''}")


def quote(c: httpx.Client, pid: str, qty: float, *, blocked: list[str] | None = None) -> dict:
    r = c.post("/v1/quote", headers=AGENT, json={
        "requested_date": (date.today() + timedelta(days=2)).isoformat(),
        "buyer_profile": "lactose_intolerant", "extra_excluded_allergens": blocked or [],
        "lines": [{"product_id": pid, "quantity": qty}]})
    r.raise_for_status()
    return r.json()


def order(c: httpx.Client, q: dict, subs: list[dict] | None = None) -> dict:
    r = c.post("/v1/orders", headers=AGENT, json={"quote_id": q["quote_id"], "accept_substitutions": subs or []})
    r.raise_for_status()
    return r.json()


def qty_for_value(q_line: dict, target_eur: float) -> float:
    """Quantity (whole sales units) closest to a target value at the quoted unit price."""
    unit = q_line["price"]["unitPrice"] or 1.0
    return float(max(1, round(target_eur / unit)))


def substitution_order(c: httpx.Client, liters: float) -> tuple[dict, dict] | None:
    q = quote(c, OUT_OF_STOCK_SKU, liters)
    line = q["payload"]["lines"][0]
    alts = (line.get("substitution") or {}).get("alternatives") or []
    if not alts:
        return None
    best = alts[0]
    return order(c, q, [{"original_product_id": OUT_OF_STOCK_SKU, "substitute_product_id": best["productId"]}]), best


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    color = not args.no_color and sys.stdout.isatty()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if color and os.name == "nt":
        os.system("")  # enable ANSI colours in the Windows console

    with httpx.Client(base_url=args.url, timeout=60) as c:
        try:
            health = c.get("/health").json()
        except httpx.HTTPError as exc:
            print(f"Gateway not reachable at {args.url}: {exc}\nStart it first (see the top of this file).")
            return 2
        print(f"Gateway {args.url}  upstream={health['upstream']}  policy={health['policy_version']}\n")

        # 1 ------------------------------------------------------------------------------
        print(f"{BOLD if color else ''}Step 1 · Small routine order (~€50){RESET if color else ''}")
        probe = quote(c, ROUTINE_SKU, 1)["payload"]["lines"][0]
        small = order(c, quote(c, ROUTINE_SKU, qty_for_value(probe, 50)))
        report("small order", small, "AUTO_APPROVED", color)

        # 2 ------------------------------------------------------------------------------
        print(f"\n{BOLD if color else ''}Step 2 · Huge order (~€1,500){RESET if color else ''}")
        big = order(c, quote(c, ROUTINE_SKU, qty_for_value(probe, 1500)))
        report("huge order", big, "PENDING_APPROVAL", color)

        # 3 ------------------------------------------------------------------------------
        print(f"\n{BOLD if color else ''}Step 3 · {OUT_OF_STOCK_SKU} is out of stock → agent proposes a substitute{RESET if color else ''}")
        first = substitution_order(c, 100)
        if first is None:
            print(f"   {OUT_OF_STOCK_SKU} is in stock, so no substitution was needed.\n"
                  "   Start the server in demo mode (MOCK_OUT_OF_STOCK=464073, see top of file) for steps 3–5.")
            results.append(("substitution", False))
        else:
            sub_order, best = first
            print(f"   substitute offered: {best['productId']} {best['name']} × {best['suggestedQuantity']:g} {best['salesUnit']}")
            report("first-time substitution", sub_order, "PENDING_APPROVAL", color)

            # 4 --------------------------------------------------------------------------
            print(f"\n{BOLD if color else ''}Step 4 · Manager clicks “Approve & Remember”{RESET if color else ''}")
            login = c.post("/v1/auth/login", json={"username": MANAGER[0], "password": MANAGER[1]})
            if login.status_code != 200:
                print("   Manager login failed; set DEMO_MANAGER_PASSWORD.")
                results.append(("approve & remember", False))
            else:
                token = login.json()["token"]
                if sub_order["status"] != "PENDING_APPROVAL":
                    print("   (already trusted from a previous run; restart in demo mode with a fresh var/demo.db)")
                    results.append(("approve & remember", False))
                else:
                    d = c.post(f"/v1/approvals/{sub_order['order_id']}", headers={"Authorization": f"Bearer {token}"},
                               json={"decision": "approve", "remember": True,
                                     "comment": "Arla is fine for breakfast service; remember this swap."}).json()
                    rule = (d.get("approval") or {}).get("trusted_rule_id")
                    ok = d["status"] == "PLACED" and rule is not None
                    results.append(("approve & remember", ok))
                    print(f"   → {paint('PLACED', color)}  trusted rule #{rule} learned "
                          f"(agent now L{d['agent_trust']['level']} {d['agent_trust']['name']}, "
                          f"{d['agent_trust']['approvals']} approval(s))   {'✓' if ok else '✗'}")
                c.post("/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})

            # 5 --------------------------------------------------------------------------
            print(f"\n{BOLD if color else ''}Step 5 · Same substitution again{RESET if color else ''}")
            again = substitution_order(c, 100)
            if again:
                report("repeat substitution", again[0], "AUTO_APPROVED", color)

        # 6 ------------------------------------------------------------------------------
        print(f"\n{BOLD if color else ''}Step 6 · Kitchen blocks milk protein (AM), agent still orders milk{RESET if color else ''}")
        rejected = order(c, quote(c, ROUTINE_SKU, 10, blocked=["AM"]))
        report("blocked allergen", rejected, "REJECTED", color)

    passed = sum(ok for _, ok in results)
    print(f"\n{passed}/{len(results)} steps behaved as expected.")
    if passed < len(results):
        print("Tip: run against a fresh demo-mode server (see the top of this file); history, trust\n"
              "levels and trusted rules from earlier runs change later outcomes, by design.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
