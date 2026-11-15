# Valio Aimo Agent Gateway

**A trusted way for autonomous purchasing agents to buy from Valio Aimo.**
Agents can search, compare and order, but only within rules Valio and the
customer control. Humans stay in the loop for exceptions, and every claim and
decision can be proven afterwards.

> Junction 2026 · Valio Aimo challenge · Backend only (FastAPI, Python 3.10+)

---

## Why this design

| An external agent needs... | The gateway gives it |
|---|---|
| To trust Valio's price and stock claims | **Ed25519-signed quotes.** Verifiable offline with the key from `GET /v1/keys`. |
| To find "lactose-free milk" when the title says *laktoositon* | **Hybrid semantic search.** Multilingual embeddings in FAISS, plus keyword scoring and *structured* dietary claims. |
| A useful answer when the product is out of stock | **Recipe-compatible substitution.** Allergen-safe, keeps dietary claims, Good / Better / Best, each with an explanation. |

| Valio and the customer need... | The gateway gives them |
|---|---|
| Agents that can't overspend or poison a guest | **Policy-as-code** (`policies.yaml`): deterministic `AUTO_APPROVED` / `PENDING_APPROVAL` / `REJECTED` decisions. |
| Humans approving exceptions, not every order | **Approval queue.** Policy rejections are final; only "pending" orders can be approved. |
| An answer to "why did the agent buy this?" | **Hash-chained audit log** with signed checkpoints and a Markdown export per order. |

---

## Architecture

```
                    ┌──────────────────────── Agent Gateway (FastAPI) ────────────────────────┐
  Hotel AI agent ──►│ /v1/search ─► SemanticIndex (FAISS + lexical + claims)                  │
   X-Agent-Key      │ /v1/quote  ─► ValioApiClient (batched ≤1000, retries, validation)       │──► junction26.valioaimo.fi
                    │              ─► SubstitutionEngine ─► TrustSigner.seal (Ed25519)        │    /api/availability
                    │ /v1/orders ─► verify signature ─► live re-price ─► Guardrails           │    /api/price
  Purchasing mgr ──►│ /v1/approvals/{id}           AUTO ─► place │ PENDING ─► human queue     │
   X-Approver-Key   │ /v1/audit/{id} ◄── AuditLog (append-only, SHA-256 chain, signed head)  │
  Valio ops ───────►│ /v1/offers/proactive ─► signed surplus offers ─► GET /v1/offers         │
   X-Admin-Key      └──────────────────────────────────────────────────────────────────────────┘
```

| Module | Responsibility |
|---|---|
| `src/data_adapter.py` | Loads the 85 MB catalog and both CSVs into typed records (missing values stay `null`). Hybrid search index. Async live-API client. |
| `src/trust.py` | Ed25519 key pair, canonical JSON, `sign_payload` / `verify_signature`, signed envelopes with expiry and nonce, JWKS. |
| `src/guardrails.py` | Loads and validates `policies.yaml` (fails closed). Pure-function `evaluate_order()`. 24 h spend ledger. |
| `src/substitution.py` | Candidates → hard filters → live check → weighted scoring → Good / Better / Best with reasons. |
| `src/audit.py` | Append-only JSONL hash chain, tamper detection, signed checkpoints, Markdown export. |
| `src/main.py` | FastAPI app, authentication and scopes, quote/order lifecycle, approvals, offers. |
| `src/mock_upstream.py` | Deterministic stand-in for the live API (same response shape, same parsers). |

---

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # add VALIO_API_KEY and VALIO_CUSTOMER_ID

# Run the full 1000 L lactose-free milk scenario in-process (mock upstream, no key needed)
python examples/run_example.py            # first run embeds 17.5k products (a few minutes), then cached
python examples/run_example.py --lexical  # instant: skip the embedding model

# Or run the server
uvicorn src.main:app --reload            # → http://127.0.0.1:8000/docs
```

**Upstream mode.** `GATEWAY_UPSTREAM=auto` (the default) calls the live API
when `VALIO_API_KEY` is set and otherwise uses the mock. Force one with
`GATEWAY_UPSTREAM=live|mock`. In mock mode, `MOCK_OUT_OF_STOCK=464073,...`
simulates stock-outs.

### Dashboard logins (demo)

Open `/dashboard` and sign in with one of the demo accounts:

| Role | Username | Password | Access |
|---|---|---|---|
| Manager | `manager` | `manager123` | read/write: approve, reject, restock, order |
| Auditor | `auditor` | `auditor123` | read-only |

These are default demo passwords for the hackathon. Change them before any real use.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VALIO_API_KEY` / `VALIO_BASE_URL` | – / `https://junction26.valioaimo.fi` | Live API |
| `VALIO_CUSTOMER_ID` | `demo-customer` | Default customer bound to agent keys |
| `GATEWAY_AGENT_KEYS` | `dev-agent-key:hotel-procurement-bot,dev-readonly-key:read-only-analyst` | `key:agent_id[:customer]`, comma-separated |
| `GATEWAY_APPROVER_KEY` / `GATEWAY_ADMIN_KEY` | `dev-approver-key` / `dev-admin-key` | Human approver / Valio ops |
| `GATEWAY_SIGNING_KEY_HEX` | *(ephemeral)* | 32-byte hex seed for a stable signing key |
| `GATEWAY_SEMANTIC` | `1` | `0` uses lexical + claims search only |
| `EMBEDDING_MODEL` | `paraphrase-multilingual-MiniLM-L12-v2` | Handles fi / sv / en |
| `POLICY_FILE` / `AUDIT_FILE` | `policies.yaml` / `audit_log.jsonl` | |

> **Change every `dev-*` key before running anywhere except your laptop.**

---

## API

| Method & path | Who | What |
|---|---|---|
| `GET /health` | anyone | Readiness, catalog stats, policy hash, audit-chain status |
| `GET /v1/keys` | anyone | Ed25519 public key (JWK + PEM) and how to verify |
| `GET /v1/policies` | anyone | The exact rules agents are held to, with version and hash |
| `POST /v1/verify` | anyone | Server-side check of any signed envelope (agents should also verify locally) |
| `POST /v1/search` | agent · `search` | Hybrid search with allergen-profile filtering |
| `GET /v1/products/{id}` | agent · `search` | Pack size, lot size, allergens, claims, reliability, carbon |
| `POST /v1/quote` | agent · `quote` | Live price and stock, substitutions, policy preview, **signed** |
| `POST /v1/orders` | agent · `order` | Verify quote → live re-price → guardrails → place or queue. Supports `Idempotency-Key`. |
| `GET /v1/orders/{id}` | agent (owner) | Order status, decision, links |
| `GET /v1/approvals` | approver | Queue of `PENDING_APPROVAL` orders |
| `POST /v1/approvals/{id}` | approver | `approve` / `reject` with reviewer and comment |
| `GET /v1/audit/{id}` | approver or owning agent | Human-readable Markdown audit trail |
| `GET /v1/audit/verify` | anyone | Chain integrity and signed checkpoint |
| `POST /v1/offers/proactive` | Valio admin | Push a signed surplus offer |
| `GET /v1/offers` | agent · `search` | Offers targeted at this agent or broadcast |

### Minimal flow

```bash
H='X-Agent-Key: dev-agent-key'
curl -s localhost:8000/v1/search -H "$H" -H 'content-type: application/json' \
  -d '{"query":"lactose-free milk","buyer_profile":"lactose_intolerant","require_claims":true}'

curl -s localhost:8000/v1/quote -H "$H" -H 'content-type: application/json' \
  -d '{"requested_date":"2026-11-16","buyer_profile":"lactose_intolerant",
       "lines":[{"product_id":"464073","quantity":1000}]}'          # → quote_id, payload, signature

curl -s localhost:8000/v1/orders -H "$H" -H 'content-type: application/json' \
  -d '{"quote_id":"qt_…","accept_substitutions":[{"original_product_id":"464073","substitute_product_id":"464201"}]}'

curl -s localhost:8000/v1/approvals/ord_… -H 'X-Approver-Key: dev-approver-key' \
  -H 'content-type: application/json' -d '{"decision":"approve","reviewer":"manager@hotel"}'

curl -s localhost:8000/v1/audit/ord_… -H 'X-Approver-Key: dev-approver-key'
```

---

## Trust protocol

1. The agent fetches `GET /v1/keys` once and pins the `kid`.
2. Every quote, order receipt, surplus offer and audit checkpoint is an envelope:
   `{payload, signature, kid, alg: "EdDSA", digest}`.
3. **Signed bytes** = `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` as UTF-8.
4. `payload._meta` holds `issued_at`, `expires_at` (quote TTL from policy) and a `nonce`. Because they sit
   inside the signature, an agent can't extend a quote's lifetime.
5. At order time the gateway re-verifies the quote. If the agent submits the envelope itself (`quote` field),
   tampering in transit is caught (`INVALID_SIGNATURE` → `REJECTED`). Each quote can be used for
   **one** order (anti-replay), and only by the agent it was issued to.
6. Substitutes are only accepted if they appear among the alternatives the gateway **signed** in that quote.

Verifying in about 10 lines with only `cryptography` is shown in `verify_locally()` in
`examples/run_example.py`.

---

## Guardrails (`policies.yaml`)

`evaluate_order()` is deterministic: no clock, no I/O, and lines are checked in a
fixed order. Every decision records `policy_version` and `policy_hash`, so it can
be replayed. A malformed policy file stops the gateway at startup (fail closed).

| Check | Outcome |
|---|---|
| Agent lacks `order` scope · quote signature invalid / expired · unknown product · bad lot size | **REJECTED** |
| Allergen conflict with buyer profile (`strict`: contains *or* may contain) | **REJECTED** |
| Out of stock / sales block · price change > 30 % · total > hard cap (25 000 EUR) | **REJECTED** |
| Total > autonomous limit (500 EUR, per-agent override) · 24 h spend > 2 000 EUR | **PENDING_APPROVAL** |
| Price change since quote > 10 % · no net price · partial or unknown availability | **PENDING_APPROVAL** |
| Substituted line · line value > 5 000 EUR · quantity > 10 000 | **PENDING_APPROVAL** |
| Carbon above flag threshold | note only |

Prices are **re-fetched live at order time**. The quote is the agent's
reference, never a blind authority.

**Allergen subtlety:** lactose intolerance is GS1 code **`ML`**, not `AM`
(milk protein). Lactose-free milk still contains `AM`. The `lactose_intolerant`
profile therefore excludes `ML` only, while `milk_allergy` excludes both.

---

## Substitution engine

1. **Candidates:** Valio's own `substitutions` rules first, then the top-*k*
   nearest products from search (`candidate_pool`).
2. **Hard filters** (each drop is reported with its reason):
   - adds an allergen the buyer excludes;
   - has no allergen declaration;
   - **loses a recipe-critical claim** (lactose-free, gluten-free, vegan, egg-free, ...);
   - is measured differently (litres vs kg);
   - has reliability below the policy minimum.
3. **Live check:** one batched availability and price call; stocked-out candidates are dropped.
4. **Score:** `0.40·price + 0.35·reliability + 0.25·carbon`.
   - Price is compared **per litre/kg**, so pack sizes are fair.
   - Price and carbon are scored relative to the best candidate.
   - Missing data scores 0.4, never "perfect".
5. **Quantity conversion:** 1000 L of 1 L bottles becomes 100 cases of 10 × 1 L,
   rounded up to whole packs and the lot size.
6. Each alternative carries `why[]` and `warnings[]`, for example
   *"Keeps recipe-critical properties: lactose-free"* or
   *"Original is labelled vegetarian; this substitute does not declare it"*.

---

## Audit trail

- `audit_log.jsonl` is append-only and fsync'd on every write. Each entry has
  `seq, timestamp, action, actor, refs, data, previous_hash, current_hash`.
- `current_hash = SHA-256(canonical_json(entry without current_hash) + previous_hash)`.
- `GET /v1/audit/verify` recomputes the chain and reports the **first** broken
  `seq`. It also returns a **signed checkpoint** of the head, so even a
  whole-file rewrite is detectable by anyone holding an earlier checkpoint.
- `GET /v1/audit/{order_id}` renders the order's story: its quote, the
  substitutions offered, the policy decision with reasons, the human approval
  and the placement. **Failed or forged attempts against the same quote are
  included too.**
- Secrets (`api_key`, `authorization`, `token`, ...) are redacted before hashing.

---

## The demo scenario (`examples/run_example.py`)

A hotel needs **1000 L of lactose-free milk**. The agent's standard SKU
(464073) is out of stock:

1. Search finds lactose-free products (filtered by the `FREE_FROM_LACTOSE` claim).
2. The quote returns **BEST / BETTER / GOOD** substitutes, all lactose-free and
   allergen-safe, each converted to 1000 L in its own pack size.
3. The agent verifies the signature locally. A **forged** quote with an edited
   price is **REJECTED**.
4. Ordering the BEST substitute (about 1 750 EUR) gives **PENDING_APPROVAL**,
   for two reasons: a substituted line, and spend over the agent's limit.
5. The purchasing manager approves it. The order is placed, and the agent
   verifies the **signed receipt**.
6. A 27 EUR top-up order is **AUTO_APPROVED**.
7. Valio pushes a signed 15 % surplus offer.
8. The Markdown audit trail is written to `examples/output/`.

---

## Data notes

- 17 546 products. Names are in en / fi / sv; allergens are GS1 codes marked `CONTAINS` / `MAY_CONTAIN`.
- Delivery reliability covers about **4.4 k** products and carbon about **11 k**.
  Missing values are surfaced as `null` and scored neutrally, never treated as 0 or as perfect.
- Carbon figures are **product-group averages** (kg CO₂e/kg), and the explanations say so.
- Pack content comes from GS1 `unitConversions`, falling back to parsing the
  name (e.g. "1 l", "5 dl").

## Known limitations and next steps

- **Order placement is simulated.** The provided OpenAPI has no order endpoint.
  `_place_order()` in `src/main.py` is the single place to connect ERP/EDI.
- Quotes, orders and offers are **in memory**. The audit log persists. Use
  Postgres or Redis for multiple instances, and set `GATEWAY_SIGNING_KEY_HEX`
  (ideally from a KMS/HSM) so every worker shares one key.
- Agent keys are static. In production, use OAuth2 client credentials or mTLS,
  with customer binding coming from the identity provider.
- Proactive offers are pulled by agents (`GET /v1/offers`). Webhook push with
  signed payloads is the natural extension.
- Keyword-only mode (`--lexical`) can rank e.g. lactose-free *chocolate* next to
  milk. Semantic mode fixes most of this.
