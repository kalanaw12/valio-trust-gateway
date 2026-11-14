# Pitch Deck: Valio Aimo Agent Trust Gateway

Five slides: copy the **slide text** onto each slide, and keep the **speaker notes** for yourself.
Replace `[Team Name]`. Every number below comes from the running system or the challenge data.

---

## Slide 1: Title

**AimoTrust Gateway**
*Let AI agents buy from Valio Aimo, without giving up control.*

[Team Name] · Junction 2026 · Valio Aimo Challenge

> **Speaker notes (15 s):** "Hotels and restaurants are starting to hand purchasing to AI agents.
> We built the layer that lets Valio Aimo say yes to those agents safely: every price is signed,
> every decision follows policy, and every exception reaches a human."

---

## Slide 2: The Problem

**AI agents are about to become Valio Aimo's customers. Can you trust them?**

- An agent can **overspend** in seconds, place **duplicate** orders, or chase a hallucinated price
- One wrong substitution can put an **allergen** on a guest's plate
- Agents act on **unverifiable claims**: "the price was €1.40" ("says who?")
- Today the choice is binary: **block agents** or **trust them blindly**
- When something goes wrong, nobody can answer **"why did the AI do that?"**

> **Speaker notes (30 s):** "A foodservice wholesaler has 17,546 products, allergen data in GS1 codes, and
> prices that differ per customer. Hand that to an autonomous agent with no guardrails and you get
> overspending, unsafe substitutions and no accountability. B2B AI needs three things: trust,
> guardrails, and human oversight. Otherwise it never leaves the pilot stage."

---

## Slide 3: The Solution

**A Trust Gateway between AI agents and Valio Aimo**

- 🔏 **Signed truth:** every quote, receipt and offer is **Ed25519-signed**. Agents verify it with a public key, and a tampered quote is rejected.
- ⚖️ **Policy-as-code guardrails:** every order gets a deterministic **Auto-approved / Needs a human / Rejected** decision, explained in plain language.
- 📈 **Earned autonomy:** a manager's **"Approve & Remember"** teaches a narrow, expiring trust rule. Trust levels unlock higher limits: **€500 → €1,000 → €2,000**.
- 🔎 **Drift detection:** an order **>15 %** above an agent's own history goes to a human.
- 🥛 **Recipe-safe substitutions:** Valio's official substitutes first, never introducing a blocked allergen, and the same dietary claims (e.g. lactose-free).
- ⛓️ **Tamper-evident audit trail:** a SHA-256 hash chain with signed checkpoints.

> **Speaker notes (45 s), live demo:**
> 1. Small milk order → **auto-approved** in milliseconds.
> 2. A +300 % spike → **DRIFT DETECTED**, sent to a human.
> 3. Peanuts for a nut-free kitchen → **rejected**, with the reason in plain English.
> 4. A manager clicks **Approve & Remember**, and the identical order next time is approved automatically.
> 5. Ask the Gemini auditor: *"Why was the last order rejected?"*

---

## Slide 4: The Technology

**Production patterns, built in 48 hours**

- **FastAPI** gateway on Valio Aimo's **live** availability and price APIs (batched ≤1,000 ids, zero-trust parsing)
- **SQLite** (WAL) for state and an append-only **JSONL hash chain** for the audit trail, safe across processes
- **WebSockets:** the manager dashboard updates live, with Chart.js metrics
- **Google Gemini:** an "Explainability Chat" answers *why* from the signed audit entries; it explains decisions but never makes them
- **Semantic search:** multilingual embeddings in FAISS, plus GS1 allergen and claim filters
- **Role-based access:** manager (read/write) and auditor (read-only); hashed passwords, HMAC-signed webhooks
- **Docker**, single container, deployable on Verda Cloud

> **Speaker notes (30 s):** "The decisions are deterministic code, not the LLM, so they can be replayed and audited.
> Gemini sits on top as the explainer, behind a prompt-injection guard and an automatic model fallback.
> Order placement is simulated because the challenge API has no order endpoint; that's one function
> to connect to Valio's ERP."

---

## Slide 5: The Impact for Valio Aimo

**Open the ecosystem to AI, on Valio Aimo's terms**

- ✅ **Say yes to AI customers safely:** agents get scoped, signed access, never the raw backend
- 🔐 **Valio keeps data ownership:** catalog, pricing and rules stay behind the gateway; Valio's signature is the source of truth
- 👩‍🍳 **Humans handle exceptions only:** routine orders flow automatically; managers see only what needs judgement
- 📜 **Every decision is provable:** signed, explained and hash-chained, so it can be shown to customers and auditors
- 💶 **New revenue channel:** Valio pushes signed **surplus offers** straight to agents (less waste, more sales)

**AimoTrust: autonomy you can audit.**

> **Speaker notes (30 s):** "For Valio Aimo this turns AI agents from a risk into a sales channel.
> Agents get faster at buying, managers keep control, and Valio owns the rules and the data.
> Thank you. Happy to show any part of the dashboard live."
