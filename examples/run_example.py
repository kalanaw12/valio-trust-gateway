"""
End-to-end scenario: a hotel's purchasing agent needs 1000 L of lactose-free milk
================================================================================

  1. Agent discovers products with semantic search (lactose-intolerant profile).
  2. Agent quotes 1000 L of its standard SKU. The SKU is out of stock, so the
     gateway proposes BEST / BETTER / GOOD substitutes with reasons.
  3. Agent verifies the quote signature locally with only the public key.
  4. A tampered quote (price edited) is rejected.
  5. Agent orders the BEST substitute, which needs human approval
     (spend above 500 EUR plus a substituted line).
  6. A human approves it; the order is placed and the signed receipt is verified.
  7. A small top-up order is AUTO_APPROVED.
  8. Valio pushes a proactive surplus offer.
  9. The human-readable, hash-chained audit trail is exported.

Usage
-----
  In-process with mock upstream (no server, no API key needed):
      python examples/run_example.py
  Faster first run (skip downloading the embedding model):
      python examples/run_example.py --lexical
  Against a running server (start it with MOCK_OUT_OF_STOCK=464073 to see substitution):
      python examples/run_example.py --url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import math
import os
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STANDARD_SKU = "464073"        # Valio whole milk 1 l lactose free UHT: the hotel's usual product
TARGET_LITRES = 1000
AGENT = {"X-Agent-Key": os.getenv("DEMO_AGENT_KEY", "dev-agent-key")}
APPROVER = {"X-Approver-Key": os.getenv("DEMO_APPROVER_KEY", "dev-approver-key")}
ADMIN = {"X-Admin-Key": os.getenv("DEMO_ADMIN_KEY", "dev-admin-key")}


# ----------------------------------------------------------------------------- pretty output
def h(title: str) -> None:
    print(f"\n{'=' * 78}\n {title}\n{'=' * 78}")


def ok(resp, expected: int = 200) -> dict:
    if resp.status_code != expected:
        print(f"!! HTTP {resp.status_code}: {resp.text[:800]}")
        sys.exit(1)
    return resp.json()


# ----------------------------------------------------------------------------- agent-side crypto
def verify_locally(envelope: dict, jwks: dict) -> bool:
    """
    What a third-party agent does. It uses only `cryptography` and the published
    key, not the gateway's own code.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def b64d(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    key = next((k for k in jwks["keys"] if k["kid"] == envelope["kid"]), None)
    if key is None:
        return False
    canonical = json.dumps(envelope["payload"], sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(b64d(key["x"])).verify(b64d(envelope["signature"]), canonical)
        return True
    except InvalidSignature:
        return False


def packs_for(litres: float, product: dict) -> float:
    content = product.get("content_per_sales_unit")
    if not content:
        return litres
    lot = max(product.get("allowed_lot_size") or 1.0, 1.0)
    return math.ceil(litres / content / lot) * lot


# ----------------------------------------------------------------------------- scenario
def run(client) -> None:
    delivery = (date.today() + timedelta(days=2)).isoformat()

    h("0. Trust bootstrap: fetch the gateway's public key")
    jwks = ok(client.get("/v1/keys"))
    print(f"kid={jwks['keys'][0]['kid']}  alg={jwks['keys'][0]['alg']}  x={jwks['keys'][0]['x'][:24]}...")
    health = ok(client.get("/health"))
    print(f"upstream={health['upstream']}  semantic_search={health['semantic_search']}  "
          f"policy={health['policy_version']}  audit_chain_valid={health['audit']['valid']}")

    h("1. Semantic search: 'lactose-free milk' for a lactose-intolerant kitchen")
    res = ok(client.post("/v1/search", headers=AGENT, json={
        "query": "lactose-free milk", "k": 8, "buyer_profile": "lactose_intolerant", "require_claims": True}))
    for r in res["results"]:
        print(f"  {r['productId']}  {r['name'][:55]:55}  {r['salesUnit'] or '':4} "
              f"score={r['score']:.3f}  claims={','.join(c for c in r['claims'] if 'LACTOSE' in c)}")

    h(f"2. Quote {TARGET_LITRES} L of the standard SKU {STANDARD_SKU}")
    product = ok(client.get(f"/v1/products/{STANDARD_SKU}", headers=AGENT))
    qty = packs_for(TARGET_LITRES, product)
    print(f"{product['display_name']}: {product['content_per_sales_unit']} L per {product['sales_unit']} "
          f"-> {qty:g} {product['sales_unit']}")
    quote = ok(client.post("/v1/quote", headers=AGENT, json={
        "requested_date": delivery, "buyer_profile": "lactose_intolerant",
        "lines": [{"product_id": STANDARD_SKU, "quantity": qty}]}))
    qid, line = quote["quote_id"], quote["payload"]["lines"][0]
    print(f"quote_id={qid}  expires={quote['payload']['_meta']['expires_at']}")
    print(f"availability={line['availability']['status']}  fulfilmentIssue={line['fulfilmentIssue']}")
    sub = line["substitution"]
    if not sub or not sub["alternatives"]:
        print("No substitution needed or possible. Run with MOCK_OUT_OF_STOCK=464073 to see the engine.")
        return
    print(f"\nConstraints: excluded allergens={sub['constraints']['excludedAllergens']} "
          f"preserved claims={sub['constraints']['preservedClaims']}")
    for alt in sub["alternatives"]:
        print(f"\n  [{alt['tier']}] {alt['productId']} {alt['name']}")
        print(f"     score={alt['score']}  breakdown={alt['scoreBreakdown']}")
        print(f"     suggested {alt['suggestedQuantity']:g} {alt['salesUnit']}  "
              f"~{alt['estimatedLineValue']} EUR")
        for w in alt["why"][1:]:
            print(f"     + {w}")
        for w in alt["warnings"]:
            print(f"     ! {w}")
    for rj in sub["rejectedCandidates"]:
        print(f"  x {rj['productId']} {rj['name'][:45]}: {rj['reason']}")
    print(f"\nPolicy preview: {quote['payload']['policy_preview']['status']}")

    h("3. Agent verifies the quote signature locally (public key only)")
    print(f"signature valid: {verify_locally(quote, jwks)}")

    h("4. Attack: edit the BEST substitute's price in the signed quote, then submit it")
    best = sub["alternatives"][0]
    forged = copy.deepcopy(quote)
    forged["payload"]["lines"][0]["substitution"]["alternatives"][0]["unitPrice"] = 0.01
    print(f"local verification of forged quote: {verify_locally(forged, jwks)}")
    bad = ok(client.post("/v1/orders", headers=AGENT, json={
        "quote_id": qid, "quote": {k: forged[k] for k in ("payload", "signature", "kid", "alg", "digest")},
        "accept_substitutions": [{"original_product_id": STANDARD_SKU, "substitute_product_id": best["productId"]}]}))
    print(f"gateway decision: {bad['status']}")
    for r in bad["decision"]["reasons"]:
        print(f"  - {r}")

    h(f"5. Order the BEST substitute ({best['productId']}) with the genuine quote")
    order = ok(client.post("/v1/orders", headers={**AGENT, "Idempotency-Key": f"hotel-{qid}"}, json={
        "quote_id": qid,
        "accept_substitutions": [{"original_product_id": STANDARD_SKU, "substitute_product_id": best["productId"]}]}))
    oid = order["order_id"]
    print(f"order_id={oid}  status={order['status']}  net_total={order['decision']['totals']['net_total']} EUR")
    for r in order["decision"]["reasons"]:
        print(f"  - {r}")
    replay = client.post("/v1/orders", headers={**AGENT, "Idempotency-Key": f"hotel-{qid}"}, json={"quote_id": qid})
    print(f"retry with same Idempotency-Key -> same order: {replay.json().get('order_id') == oid}")

    h("6. Human approval (head chef / purchasing manager)")
    pending = ok(client.get("/v1/approvals", headers=APPROVER))
    print(f"pending approvals: {pending['count']}")
    approved = ok(client.post(f"/v1/approvals/{oid}", headers=APPROVER, json={
        "decision": "approve", "reviewer": "purchasing.manager@hotel.example",
        "comment": "Substitute OK for breakfast service; same lactose-free spec."}))
    print(f"status={approved['status']}  confirmation={approved['confirmation']}")
    print(f"receipt signature valid (agent-side): {verify_locally(approved['receipt'], jwks)}")

    h("6b. Order slightly over the agent's limit (~€850): the agent negotiates a bulk discount")
    # In-stock UHT milk (464073 is the scripted stock-out above): storable, so buying a bit more is sensible
    neg_pid = "464201"
    probe = ok(client.post("/v1/quote", headers=AGENT, json={
        "requested_date": delivery, "lines": [{"product_id": neg_pid, "quantity": 1}]}))["payload"]["lines"][0]
    unit = probe["price"]["unitPrice"]
    limit = ok(client.get("/v1/metrics", headers=APPROVER))["agents"][0]["autonomous_limit"]
    target = round(limit * 1.13, 2)                      # ~13% over the limit: inside the 20% negotiation band
    neg_qty = max(1, round(target / unit))
    print(f"agent limit {limit:.0f} EUR · ordering {neg_qty} x {unit} EUR = {neg_qty * unit:,.2f} EUR")
    neg_q = ok(client.post("/v1/quote", headers=AGENT, json={
        "requested_date": delivery, "buyer_profile": "lactose_intolerant",
        "lines": [{"product_id": neg_pid, "quantity": neg_qty}]}))
    neg = ok(client.post("/v1/orders", headers=AGENT, json={"quote_id": neg_q["quote_id"]}))
    n = neg.get("negotiation") or {}
    print(f"negotiation: {n.get('status')}  ({n.get('counterparty', 'n/a')})")
    if n.get("status") == "NEGOTIATION_WON":
        print(f"  counter-offer: {n['new_qty']:g} units at -{n['discount_pct']:g}% = {n['new_total']:,.2f} EUR "
              f"(list {n['list_total_for_new_qty']:,.2f}) -> saved {n['saved_amount']:,.2f} EUR vs list, "
              f"{n['spend_change_vs_original']:+,.2f} EUR vs the original order")
    print(f"status={neg['status']}  decision={neg['decision']['status']}")
    print(f"  {neg['decision']['explanation']}")
    savings = ok(client.get("/v1/metrics", headers=APPROVER))["negotiation"]
    print(f"Savings via negotiation card: {savings['saved_placed_eur']:,.2f} EUR placed "
          f"({savings['won']} won, {savings['lost']} lost)")

    h("7. Small top-up order: AUTO_APPROVED within policy")
    small_pid = next(r["productId"] for r in res["results"] if r["productId"] != STANDARD_SKU)
    small_q = ok(client.post("/v1/quote", headers=AGENT, json={
        "requested_date": delivery, "buyer_profile": "lactose_intolerant",
        "lines": [{"product_id": small_pid, "quantity": 2}]}))
    small = ok(client.post("/v1/orders", headers=AGENT, json={"quote_id": small_q["quote_id"]}))
    print(f"{small_pid}: status={small['status']}  net_total={small['decision']['totals']['net_total']} EUR")
    for r in small["decision"]["reasons"]:
        print(f"  - {r}")

    h("8. Valio pushes a proactive surplus offer")
    offer = ok(client.post("/v1/offers/proactive", headers=ADMIN, json={
        "product_id": best["productId"], "discount_pct": 15, "quantity_available": 200,
        "valid_until": (date.today() + timedelta(days=3)).isoformat(),
        "reason": "Surplus UHT stock at Vantaa DC"}))
    offers = ok(client.get("/v1/offers", headers=AGENT))
    print(f"offer {offer['offer_id']} visible to agent: {offers['count']} offer(s), "
          f"signature valid: {verify_locally(offer, jwks)}")

    h(f"9. Audit trail for {oid}")
    md = client.get(f"/v1/audit/{oid}", headers=APPROVER).text
    out_dir = ROOT / "examples" / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"audit_{oid}.md"
    path.write_text(md, encoding="utf-8")
    print("\n".join(md.splitlines()[:28]))
    print(f"... full trail written to {path.relative_to(ROOT)}")
    chain = ok(client.get("/v1/audit/verify"))
    print(f"\nchain valid={chain['chain']['valid']}  entries={chain['chain']['entries']}  "
          f"checkpoint signature valid={verify_locally(chain['checkpoint'], jwks)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="Run against a live gateway instead of in-process")
    ap.add_argument("--lexical", action="store_true", help="Skip the embedding model (faster first run)")
    args = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if args.url:
        import httpx
        with httpx.Client(base_url=args.url, timeout=120) as client:
            run(client)
        return

    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    os.environ.setdefault("GATEWAY_UPSTREAM", "mock")
    os.environ.setdefault("MOCK_OUT_OF_STOCK", STANDARD_SKU)
    os.environ.setdefault("AUDIT_FILE", str(ROOT / "examples" / "output" / "audit_log.jsonl"))
    import tempfile
    os.environ.setdefault("DB_PATH", os.path.join(tempfile.mkdtemp(prefix="valio-example-"), "gateway.db"))
    os.environ.setdefault("WEBHOOKS_ENABLED", "0")   # no HTTP server in-process to receive them
    if args.lexical:
        os.environ["GATEWAY_SEMANTIC"] = "0"
    (ROOT / "examples" / "output").mkdir(parents=True, exist_ok=True)

    from fastapi.testclient import TestClient
    from src.main import app

    print("Starting gateway in-process (loading 85 MB catalog)...")
    with TestClient(app) as client:  # runs the lifespan (catalog, index, keys)
        run(client)


if __name__ == "__main__":
    main()
