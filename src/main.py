"""
Valio Aimo Agent Gateway: FastAPI application
=============================================

Lifecycle of an autonomous purchase:

    search ──► quote (live price + stock, Ed25519-signed, substitutions) ──► order
                                                                              │
                     guardrails: AUTO_APPROVED ─► placed                      │
                                 PENDING_APPROVAL ─► human /v1/approvals ─────┤
                                 REJECTED ─► stop                             │
                                                                              ▼
                     every step ─► hash-chained audit log ─► /v1/audit/{id} (Markdown)

Run:  uvicorn src.main:app --reload
Docs: http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import secrets
import threading
import time
import json
import re
from collections import deque
from contextlib import asynccontextmanager
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import (Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile, WebSocket,
                     WebSocketDisconnect)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import inventory
from .audit import Action, AuditLog, summarize_entry
from .data_adapter import DataAdapter, UpstreamError
from .database import Database
from .guardrails import (WEIGHT_SALES_UNITS, OrderContext, OrderLine, Policy, PolicyError, Status,
                         apply_negotiation, build_trusted_rule, evaluate_order, load_policies,
                         negotiation_candidate)
from .negotiator import negotiate_proactive_offer, simulate_valio_negotiation, suggested_offer_quantity
from .mock_upstream import MockValioApi
from .substitution import SubstitutionEngine
from .trust import (WEBHOOK_SIGNATURE_HEADER, TrustSigner, WebhookDispatcher, iso, utcnow,
                    verify_webhook, verify_with_public_key, webhook_secret)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
logger = logging.getLogger("gateway")

# =============================================================================
# Identity configuration
# =============================================================================
# GATEWAY_AGENT_KEYS="key1:hotel-procurement-bot:CUST123,key2:read-only-analyst"
#   key -> (agent_id, customer). The customer is bound to the key: an agent can
#   never order on behalf of a different customer by editing a request body.
DEFAULT_CUSTOMER = os.getenv("VALIO_CUSTOMER_ID", "demo-customer")
APPROVER_KEY = os.getenv("GATEWAY_APPROVER_KEY", "dev-approver-key")
ADMIN_KEY = os.getenv("GATEWAY_ADMIN_KEY", "dev-admin-key")


def _parse_agent_keys(spec: str) -> dict[str, tuple[str, str]]:
    out = {}
    for item in filter(None, (s.strip() for s in spec.split(","))):
        parts = item.split(":")
        if len(parts) < 2:
            raise ValueError(f"Bad GATEWAY_AGENT_KEYS entry {item!r}")
        out[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else DEFAULT_CUSTOMER)
    return out


AGENT_KEYS = _parse_agent_keys(os.getenv(
    "GATEWAY_AGENT_KEYS",
    "dev-agent-key:hotel-procurement-bot,dev-readonly-key:read-only-analyst",
))


# =============================================================================
# Application state
# =============================================================================

class LiveHub:
    """Fan-out of server events to authenticated dashboard WebSockets."""

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    async def broadcast(self, event: str, data: dict[str, Any]) -> None:
        msg = json.dumps({"type": event, "ts": iso(utcnow()), "data": data}, default=str, ensure_ascii=False)
        for ws in list(self.clients):
            try:
                await ws.send_text(msg)
            except Exception:  # client vanished mid-send
                self.clients.discard(ws)

    def publish(self, event: str, data: dict[str, Any]) -> None:
        """Thread-safe, fire-and-forget. Callable from sync code (e.g. audit listeners)."""
        if self.loop is None or not self.clients:
            return
        self.loop.call_soon_threadsafe(lambda: self.loop.create_task(self.broadcast(event, data)))


def audit_view(e: dict[str, Any]) -> dict[str, Any]:
    """Compact, dashboard-friendly view of one audit entry (+ explanation when it is a decision)."""
    data = e.get("data") or {}
    decision = data.get("decision") if isinstance(data.get("decision"), dict) else {}
    return {
        "seq": e["seq"], "timestamp": e["timestamp"], "action": e["action"], "actor": e.get("actor"),
        "refs": e.get("refs", []), "summary": summarize_entry(e),
        "order_id": next((r for r in e.get("refs", []) if r.startswith("ord_")), None),
        "status": decision.get("status"), "explanation": decision.get("explanation"),
        "drift": bool(decision.get("drift")), "hash": e["current_hash"],
        "saved_amount": (data.get("negotiation") or {}).get("saved_amount") if e["action"] == "NEGOTIATION_WON" else None,
    }


class GatewayState:
    def __init__(self) -> None:
        self.policy: Policy = load_policies()
        self.signer = TrustSigner.from_env()
        self.audit = AuditLog(signer=self.signer)
        self.db = Database()
        self.hub = LiveHub()
        self.adapter = DataAdapter(build_semantic=os.getenv("GATEWAY_SEMANTIC", "1") != "0")
        self.engine: Optional[SubstitutionEngine] = None
        self.webhooks_received: deque[dict[str, Any]] = deque(maxlen=50)   # mock receiver inbox
        self.webhook_secret = webhook_secret()
        webhooks_on = bool(self.policy.get("webhooks.enabled")) and os.getenv("WEBHOOKS_ENABLED", "1") != "0"
        self.dispatcher: Optional[WebhookDispatcher] = WebhookDispatcher(
            self.signer, os.getenv("WEBHOOK_URL") or str(self.policy.get("webhooks.url")), self.webhook_secret,
            timeout=float(self.policy.get("webhooks.timeout_seconds", 5)),
            max_attempts=int(self.policy.get("webhooks.max_attempts", 3))) if webhooks_on else None
        self.upstream_mode = "live"
        self.audit.listeners.append(lambda e: self.hub.publish("audit", audit_view(e)))

    def seed_users(self) -> None:
        """Dashboard logins live in SQLite (hashed). Defaults are for local demos only."""
        for username, env, default, role in (("manager", "DASHBOARD_MANAGER_PASSWORD", "manager123", "manager"),
                                             ("auditor", "DASHBOARD_AUDITOR_PASSWORD", "auditor123", "auditor")):
            password = os.getenv(env) or default
            if self.db.ensure_user(username, password, role) and password == default:
                logger.warning("Created dashboard user '%s' with the DEFAULT password; set %s before deploying",
                               username, env)

    async def startup(self) -> None:
        self.hub.loop = asyncio.get_running_loop()
        self.seed_users()
        inventory.ensure_schema(self.db)      # stock-count table + baseline counts (no orders are created)
        await self.adapter.startup()
        mode = os.getenv("GATEWAY_UPSTREAM", "auto").lower()
        if mode == "mock" or (mode == "auto" and not os.getenv("VALIO_API_KEY")):
            await self.adapter.api.aclose()
            self.adapter.api = MockValioApi(self.adapter.catalog)  # type: ignore[assignment]
            self.upstream_mode = "mock"
            logger.warning("Upstream: MOCK (no VALIO_API_KEY or GATEWAY_UPSTREAM=mock)")
        self.engine = SubstitutionEngine(self.adapter, self.policy)
        self.audit.record(Action.SYSTEM, {
            "summary": "gateway started", "kid": self.signer.kid, "upstream": self.upstream_mode,
            **self.policy.summary(), "catalog": self.adapter.catalog.stats,
        })


state: GatewayState  # initialised in lifespan


@asynccontextmanager
async def lifespan(app: FastAPI):
    global state
    state = GatewayState()
    await state.startup()
    app.state.gateway = state
    yield
    await state.adapter.shutdown()
    state.db.close()


app = FastAPI(
    title="Valio Aimo Agent Gateway",
    version="1.0.0",
    description="Trusted interface for autonomous purchasing agents: signed quotes, "
                "policy-as-code guardrails, recipe-compatible substitutions and a hash-chained audit trail.",
    lifespan=lifespan,
)


# Resolved relative to this file so it works from any working directory (and in Docker)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


@app.exception_handler(UpstreamError)
async def _upstream_error(_: Request, exc: UpstreamError) -> JSONResponse:
    return JSONResponse(status_code=502, content={"error": "UPSTREAM_UNAVAILABLE", "detail": str(exc)})


@app.exception_handler(PolicyError)
async def _policy_error(_: Request, exc: PolicyError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": "POLICY_ERROR", "detail": str(exc)})


# =============================================================================
# Auth dependencies
# =============================================================================

class Agent(BaseModel):
    agent_id: str
    customer: str


def authenticate_agent(x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")) -> Agent:
    for key, (agent_id, customer) in AGENT_KEYS.items():
        if x_agent_key and secrets.compare_digest(x_agent_key, key):
            return Agent(agent_id=agent_id, customer=customer)
    raise HTTPException(401, detail={"error": "UNAUTHENTICATED", "detail": "Missing or invalid X-Agent-Key"})


def require_scope(scope: str):
    def dep(agent: Agent = Depends(authenticate_agent)) -> Agent:
        if not state.policy.has_scope(agent.agent_id, scope):
            raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": f"Agent lacks '{scope}' scope"})
        return agent
    return dep


class Viewer(BaseModel):
    username: str
    role: Literal["manager", "auditor"]
    via: Literal["session", "approver_key"] = "session"


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def require_viewer(authorization: Optional[str] = Header(None),
                   x_approver_key: Optional[str] = Header(None, alias="X-Approver-Key")) -> Viewer:
    """Dashboard users (manager/auditor via session token) or the service approver key (= manager)."""
    if x_approver_key and secrets.compare_digest(x_approver_key, APPROVER_KEY):
        return Viewer(username="approver-key", role="manager", via="approver_key")
    token = _bearer(authorization)
    if token and (session := state.db.get_session(token)):
        return Viewer(username=session["username"], role=session["role"])
    raise HTTPException(401, detail={"error": "UNAUTHENTICATED", "detail": "Log in or provide X-Approver-Key"})


def require_manager(viewer: Viewer = Depends(require_viewer)) -> Viewer:
    if viewer.role != "manager":
        raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": "Auditors have read-only access"})
    return viewer


def require_admin(x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")) -> None:
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(401, detail={"error": "UNAUTHENTICATED", "detail": "Valio admin key required"})


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


# =============================================================================
# Schemas
# =============================================================================

class SearchRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=200, examples=["lactose-free milk"])
    k: int = Field(10, ge=1, le=50)
    buyer_profile: str = "default"
    exclude_allergens: list[str] = []
    require_claims: bool = Field(False, description="Drop results lacking claims implied by the query")
    category: Optional[str] = None


class QuoteLineIn(BaseModel):
    product_id: str
    quantity: float = Field(1, gt=0, description="In the product's sales unit")


class QuoteRequest(BaseModel):
    requested_date: date
    lines: list[QuoteLineIn] = []
    products: list[str] = Field([], description="Shorthand: product ids, quantity 1 each")
    buyer_profile: str = "default"
    extra_excluded_allergens: list[str] = []

    @model_validator(mode="after")
    def _merge(self) -> "QuoteRequest":
        self.lines = self.lines + [QuoteLineIn(product_id=p) for p in self.products]
        self.products = []
        if not self.lines:
            raise ValueError("Provide `lines` or `products`")
        if len(self.lines) > 1000:
            raise ValueError("At most 1000 lines per quote")
        if len({l.product_id for l in self.lines}) != len(self.lines):
            raise ValueError("Duplicate product ids in quote")
        return self


class SignedEnvelope(BaseModel):
    payload: dict[str, Any]
    signature: str
    kid: Optional[str] = None
    alg: Optional[str] = None
    digest: Optional[str] = None


class AcceptSubstitution(BaseModel):
    original_product_id: str
    substitute_product_id: str
    quantity: Optional[float] = Field(None, gt=0, description="Defaults to the engine's suggested quantity")


class OrderRequest(BaseModel):
    quote_id: str
    quote: Optional[SignedEnvelope] = Field(
        None, description="Optional: the signed quote exactly as received. If present it is verified, "
                          "so tampering in transit is detected.")
    accept_substitutions: list[AcceptSubstitution] = []
    drop_product_ids: list[str] = []


class ApprovalRequest(BaseModel):
    decision: Literal["approve", "reject"]
    reviewer: Optional[str] = Field(None, min_length=2, max_length=120,
                                    description="Required with the approver key; ignored for logged-in users")
    comment: Optional[str] = Field(None, max_length=2000)
    remember: bool = Field(False, description="Approve & Remember: learn a narrow trusted rule (#1)")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class ProactiveOffer(BaseModel):
    product_id: str
    discount_pct: float = Field(..., gt=0, le=90)
    quantity_available: float = Field(..., gt=0)
    valid_until: date
    reason: str = Field("Surplus stock", max_length=300)
    target_agent_id: Optional[str] = Field(None, description="None = broadcast to all agents")


# =============================================================================
# Meta & trust endpoints
# =============================================================================

@app.get("/health", tags=["meta"])
async def health() -> dict[str, Any]:
    return {"status": "ok" if state.adapter.ready else "starting", "upstream": state.upstream_mode,
            **state.adapter.health(), **state.policy.summary(), "audit": state.audit.verify().to_dict()}


@app.get("/v1/keys", tags=["trust"])
async def public_keys() -> dict[str, Any]:
    """Ed25519 public key (JWK) that agents use to verify every quote, receipt and offer."""
    return state.signer.jwks()


@app.post("/v1/verify", tags=["trust"])
async def verify_envelope(env: SignedEnvelope) -> dict[str, Any]:
    """Convenience check. Agents SHOULD also verify locally with the key from /v1/keys."""
    ok, reason = state.signer.open(env.model_dump(), check_expiry=True)
    return {"valid": ok, "reason": reason, "kid": state.signer.kid}


@app.get("/v1/policies", tags=["trust"])
async def policies() -> dict[str, Any]:
    """The exact rules an agent is held to: transparent, versioned and hashed."""
    return {**state.policy.summary(), "rules": state.policy.raw}


# =============================================================================
# Search
# =============================================================================

@app.post("/v1/search", tags=["agent"])
async def search(req: SearchRequest, agent: Agent = Depends(require_scope("search"))) -> dict[str, Any]:
    excluded = state.policy.excluded_allergens(req.buyer_profile, req.exclude_allergens)
    strict = state.policy.allergen_mode == "strict"
    hits = await asyncio.to_thread(
        state.adapter.search, req.query, req.k, exclude_allergens=excluded,
        strict_allergens=strict, require_claims=req.require_claims, category=req.category)
    search_id = _new_id("srch")
    results = [h.to_dict() for h in hits]
    state.audit.record(Action.SEARCH, {
        "search_id": search_id, "query": req.query, "buyer_profile": req.buyer_profile,
        "excluded_allergens": excluded, "result_count": len(results),
        "results": [r["productId"] for r in results],
    }, actor=f"agent:{agent.agent_id}", refs=[search_id])
    return {"search_id": search_id, "query": req.query, "excluded_allergens": excluded,
            "semantic": state.adapter.health()["semantic_search"], "results": results}


@app.get("/v1/products/{product_id}", tags=["agent"])
async def product_detail(product_id: str, agent: Agent = Depends(require_scope("search"))) -> dict[str, Any]:
    """Static product facts (pack size, lot size, allergens, claims, reliability, carbon)."""
    p = state.adapter.catalog.get(product_id)
    if p is None:
        raise HTTPException(404, detail={"error": "UNKNOWN_PRODUCT", "productId": product_id})
    return p.to_public_dict()


# =============================================================================
# Quote
# =============================================================================

@app.post("/v1/quote", tags=["agent"])
async def quote(req: QuoteRequest, agent: Agent = Depends(require_scope("quote"))) -> dict[str, Any]:
    catalog, policy = state.adapter.catalog, state.policy
    unknown = [l.product_id for l in req.lines if l.product_id not in catalog]
    if unknown:
        raise HTTPException(404, detail={"error": "UNKNOWN_PRODUCTS", "products": unknown})
    excluded = policy.excluded_allergens(req.buyer_profile, req.extra_excluded_allergens)

    ids = [l.product_id for l in req.lines]
    snapshot = await state.adapter.live_snapshot(agent.customer, req.requested_date, ids)
    quote_id = _new_id("qt")

    async def build_line(line: QuoteLineIn) -> dict[str, Any]:
        p = catalog.require(line.product_id)
        avail = snapshot[p.id]["availability"]
        price = snapshot[p.id]["price"]
        trigger = SubstitutionEngine.needs_substitution(avail, line.quantity)
        substitution = None
        if trigger and policy.get("substitution.enabled", True):
            result = await state.engine.suggest(
                p.id, customer=agent.customer, requested_date=req.requested_date,
                quantity=line.quantity, buyer_profile=req.buyer_profile,
                extra_excluded_allergens=req.extra_excluded_allergens,
                trigger=trigger, original_price=price)
            substitution = result.to_dict()
            state.audit.record(Action.SUBSTITUTION, substitution, actor="gateway", refs=[quote_id])
        unit = price.unit_price
        return {
            "productId": p.id, "name": p.display_name, "quantity": line.quantity,
            "salesUnit": p.sales_unit, "contentPerSalesUnit": p.content_per_sales_unit,
            "contentUom": p.base_unit_content_uom, "allowedLotSize": p.allowed_lot_size,
            "price": {"status": price.status, "currency": price.currency, "unitPrice": unit,
                      "unitPriceWithTax": price.unit_price_with_tax, "taxRate": price.tax_rate,
                      "netPriceFound": price.net_price_found, "validFrom": price.valid_from,
                      "validTo": price.valid_to},
            "lineValue": round(unit * line.quantity, 2) if unit is not None else None,
            "availability": {"status": avail.status, "availableAmount": avail.available_amount,
                             "earliestDate": avail.earliest_date, "closingTime": avail.closing_time,
                             "salesBlock": avail.sales_block},
            "deliveryReliability": p.delivery_reliability,
            "carbonKgCo2ePerKg": p.carbon_kg_co2e_per_kg,
            "allergens": sorted(p.allergens_contains),
            "allergenConflicts": p.allergen_conflicts(excluded, strict=policy.allergen_mode == "strict"),
            "fulfilmentIssue": trigger,
            "substitution": substitution,
        }

    lines = await asyncio.gather(*(build_line(l) for l in req.lines))

    # Dry-run the guardrails so the agent knows the likely outcome before ordering
    preview = evaluate_order(
        [_order_line_from_quote(l) for l in lines],
        OrderContext(customer=agent.customer, agent_id=agent.agent_id, buyer_profile=req.buyer_profile,
                     extra_excluded_allergens=tuple(req.extra_excluded_allergens),
                     daily_autonomous_spend=state.db.autonomous_spend_since(agent.customer, utcnow() - timedelta(hours=24)),
                     trust=policy.trust_profile(agent.agent_id, state.db.agent_trust_stats(agent.agent_id)),
                     history=state.db.order_history(agent.agent_id, agent.customer,
                                                    lookback=int(policy.get("drift.lookback_orders", 20))),
                     trusted_rules=tuple(state.db.active_rules(agent.agent_id, agent.customer))),
        catalog, policy)

    payload = {
        "quote_id": quote_id, "customer": agent.customer, "agent_id": agent.agent_id,
        "requested_date": req.requested_date.isoformat(), "buyer_profile": req.buyer_profile,
        "extra_excluded_allergens": sorted(req.extra_excluded_allergens),
        "currency": "EUR", "upstream": state.upstream_mode,
        "lines": lines,
        "totals": {"net": round(sum(l["lineValue"] or 0 for l in lines), 2),
                   "unpriced_lines": sum(l["lineValue"] is None for l in lines),
                   "lines_needing_substitution": sum(bool(l["fulfilmentIssue"]) for l in lines)},
        "policy_preview": preview.to_dict(),
    }
    envelope = state.signer.seal(payload, ttl_seconds=int(policy.get("quotes.ttl_seconds", 900)), kind="quote")
    state.db.save_quote(quote_id, agent.agent_id, agent.customer, envelope, envelope["payload"]["_meta"]["expires_at"])
    state.audit.record(Action.QUOTE, {
        "quote_id": quote_id, "digest": envelope["digest"], "requested_date": payload["requested_date"],
        "lines": [{"productId": l["productId"], "quantity": l["quantity"], "unitPrice": l["price"]["unitPrice"],
                   "availability": l["availability"]["status"]} for l in lines],
        "totals": payload["totals"], "preview_status": preview.status.value,
    }, actor=f"agent:{agent.agent_id}", refs=[quote_id])
    return {"quote_id": quote_id, **envelope}


def _order_line_from_quote(l: dict[str, Any], *, quantity: Optional[float] = None,
                           live: Optional[dict[str, Any]] = None, substitutes_for: Optional[str] = None,
                           quoted_price: Optional[float] = None) -> OrderLine:
    """Quote line (+ optional live re-check at order time) -> guardrail OrderLine."""
    price = l.get("price") or {}
    avail = l.get("availability") or {}
    line = OrderLine(
        product_id=l["productId"], quantity=quantity if quantity is not None else l["quantity"],
        quoted_unit_price=quoted_price if quoted_price is not None else price.get("unitPrice"),
        currency=price.get("currency") or "EUR", price_status=price.get("status", "UNKNOWN"),
        net_price_found=bool(price.get("netPriceFound", False)),
        availability_status=avail.get("status", "UNKNOWN"), available_amount=avail.get("availableAmount"),
        is_substitute=substitutes_for is not None, substitutes_for=substitutes_for,
    )
    if live is not None:
        lp, la = live["price"], live["availability"]
        line.live_unit_price = lp.unit_price
        line.price_status, line.net_price_found = lp.status, lp.net_price_found
        line.currency = lp.currency or line.currency
        line.availability_status, line.available_amount = la.status, la.available_amount
    return line


# =============================================================================
# Orders
# =============================================================================

def _place_order(order: dict[str, Any], actor: str) -> None:
    """
    The provided OpenAPI exposes no order-creation endpoint, so placement is
    simulated: a confirmation is issued and signed, and the hook for a real
    ERP/EDI call is right here.
    """
    order["status"] = "PLACED"
    order["placed_at"] = iso(utcnow())
    order["confirmation"] = {"number": f"VA-{secrets.token_hex(4).upper()}", "placement": "SIMULATED"}
    order["receipt"] = state.signer.seal({
        "order_id": order["order_id"], "quote_id": order["quote_id"], "customer": order["customer"],
        "lines": [{"productId": l["productId"], "quantity": l["quantity"], "unitPrice": l["unitPrice"]}
                  for l in order["lines"]],
        "net_total": order["decision"]["totals"]["net_total"], "currency": "EUR",
        "confirmation": order["confirmation"], "placed_at": order["placed_at"],
    }, kind="order_receipt")
    state.audit.record(Action.ORDER_PLACED, {
        "order_id": order["order_id"], "confirmation": order["confirmation"],
        "receipt_digest": order["receipt"]["digest"],
    }, actor=actor, refs=[order["order_id"], order["quote_id"]])


@app.post("/v1/orders", tags=["agent"])
async def create_order(req: OrderRequest, agent: Agent = Depends(require_scope("order")),
                       idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key")) -> dict[str, Any]:
    db = state.db
    if idempotency_key and (prev := db.get_idempotent(agent.agent_id, idempotency_key)):
        return _public_order(_get_order(prev))

    # ---- 1. Resolve and verify the signed quote -------------------------------
    if req.quote:
        envelope = req.quote.model_dump()
    else:
        stored = db.get_quote(req.quote_id)
        envelope = stored["envelope"] if stored and stored["envelope"] else None
    if envelope is None:
        raise HTTPException(404, detail={"error": "QUOTE_NOT_FOUND", "quote_id": req.quote_id})
    sig_ok, sig_status = state.signer.open(envelope)
    qp = envelope.get("payload") or {}
    if sig_ok and qp.get("quote_id") != req.quote_id:
        sig_ok, sig_status = False, "QUOTE_ID_MISMATCH"
    if sig_ok and qp.get("agent_id") != agent.agent_id:
        raise HTTPException(403, detail={"error": "QUOTE_NOT_YOURS"})

    order_id = _new_id("ord")
    actor = f"agent:{agent.agent_id}"
    refs = [order_id, req.quote_id]

    # Anti-replay: atomic in SQLite. A forged envelope never consumes the genuine quote.
    if sig_ok and not db.consume_quote(req.quote_id, order_id):
        raise HTTPException(409, detail={"error": "QUOTE_ALREADY_USED", "quote_id": req.quote_id})

    # ---- 2. Build order lines (apply accepted substitutions) -------------------
    order_lines: list[OrderLine] = []
    view_lines: list[dict[str, Any]] = []
    subs = {s.original_product_id: s for s in req.accept_substitutions}
    quote_lines = {l["productId"]: l for l in qp.get("lines", [])} if sig_ok else {}
    for pid in subs:
        if sig_ok and pid not in quote_lines:
            raise HTTPException(422, detail={"error": "SUBSTITUTION_FOR_UNKNOWN_LINE", "productId": pid})

    plan: list[tuple[dict, str, float, Optional[str], Optional[float]]] = []  # (quote_line, pid, qty, subs_for, quoted_price)
    for pid, ql in quote_lines.items():
        if pid in req.drop_product_ids:
            continue
        if pid in subs:
            s = subs[pid]
            alts = {a["productId"]: a for a in ((ql.get("substitution") or {}).get("alternatives") or [])}
            alt = alts.get(s.substitute_product_id)
            if alt is None:  # only alternatives the gateway itself signed are acceptable
                raise HTTPException(422, detail={"error": "SUBSTITUTE_NOT_OFFERED", "productId": pid,
                                                 "offered": sorted(alts)})
            plan.append((ql, alt["productId"], s.quantity or alt["suggestedQuantity"], pid, alt["unitPrice"]))
        else:
            plan.append((ql, pid, ql["quantity"], None, None))

    # ---- 3. Live re-check: never trust a quote's price/stock blindly ------------
    live: dict[str, dict[str, Any]] = {}
    if plan:
        try:
            live = await state.adapter.live_snapshot(agent.customer, qp["requested_date"], [p[1] for p in plan])
        except UpstreamError as exc:
            logger.warning("Live re-check failed for %s: %s", order_id, exc)

    catalog = state.adapter.catalog
    for ql, pid, qty, subs_for, quoted_price in plan:
        if subs_for:
            p = catalog.require(pid)
            base = {"productId": pid, "quantity": qty,
                    "price": {"status": "PRICED" if quoted_price is not None else "UNKNOWN",
                              "unitPrice": quoted_price, "currency": "EUR", "netPriceFound": True},
                    "availability": {"status": "UNKNOWN"}}
        else:
            p, base = catalog.require(pid), ql
        ol = _order_line_from_quote(base, quantity=qty, live=live.get(pid), substitutes_for=subs_for,
                                    quoted_price=quoted_price)
        if pid not in live:  # upstream re-check failed: zero-trust → unknown
            ol.availability_status, ol.live_unit_price = "UNKNOWN", None
        order_lines.append(ol)
        view_lines.append({"productId": pid, "name": p.display_name, "quantity": qty, "salesUnit": p.sales_unit,
                           "quotedUnitPrice": ol.quoted_unit_price, "liveUnitPrice": ol.live_unit_price,
                           "unitPrice": ol.effective_unit_price, "lineValue": ol.line_value,
                           "availability": ol.availability_status, "substitutesFor": subs_for})

    # ---- 4. Guardrails ----------------------------------------------------------------
    # Everything the pure evaluator needs is loaded here: trust level (#3), history (#6), rules (#1)
    policy = state.policy
    ctx = OrderContext(
        customer=agent.customer, agent_id=agent.agent_id,
        buyer_profile=qp.get("buyer_profile", "default"),
        extra_excluded_allergens=tuple(qp.get("extra_excluded_allergens") or ()),
        quote_signature_status=sig_status,
        daily_autonomous_spend=db.autonomous_spend_since(agent.customer, utcnow() - timedelta(hours=24)),
        trust=policy.trust_profile(agent.agent_id, db.agent_trust_stats(agent.agent_id)),
        history=db.order_history(agent.agent_id, agent.customer,
                                 lookback=int(policy.get("drift.lookback_orders", 20))),
        trusted_rules=tuple(db.active_rules(agent.agent_id, agent.customer)),
    )
    decision = evaluate_order(order_lines, ctx, catalog, policy)

    # ---- 4b. Autonomous negotiation (simulated counter-party): slightly over budget -> try a bulk deal.
    # A won deal changes the order and goes through the guardrails AGAIN, so it can't bypass any limit.
    negotiation = None
    submitted_lines = [dict(l) for l in view_lines]          # what the agent actually asked for
    cand = negotiation_candidate(decision, order_lines, policy)
    if cand is not None:
        p = catalog.require(cand.product_id)
        lot = p.allowed_lot_size if (p.sales_unit or "").upper() in WEIGHT_SALES_UNITS else max(p.allowed_lot_size or 1, 1)
        negotiation = simulate_valio_negotiation(
            p.id, cand.quantity, cand.effective_unit_price, decision.totals["autonomous_limit"],
            max_over_budget_pct=float(policy.get("negotiation.max_over_budget_pct", 20)),
            quantity_uplift_pct=float(policy.get("negotiation.quantity_uplift_pct", 20)),
            discount_pct=float(policy.get("negotiation.discount_pct", 10)),
            accept_min_qty=float(policy.get("negotiation.accept_min_qty", 100)), lot_size=lot)
        # internal / audit status names stay NEGOTIATION_WON / NEGOTIATION_LOST
        negotiation["status"] = negotiation.get("engine_status", negotiation["status"])
        negotiation.update({"product": p.display_name, "sales_unit": p.sales_unit})
        if negotiation["status"] == "NEGOTIATION_WON":
            order_lines = [apply_negotiation(cand, negotiation)]          # override the quote: new qty + price
            nl = order_lines[0]
            view_lines = [{**view_lines[0], "quantity": nl.quantity, "quotedUnitPrice": nl.quoted_unit_price,
                           "liveUnitPrice": nl.live_unit_price, "unitPrice": nl.effective_unit_price,
                           "lineValue": nl.line_value, "negotiated": True}]
            # Full re-check of the new deal. With negotiation.auto_approve_won the spend limit accepts the
            # negotiated total (capped); daily cap, allergens, drift, price and stock still decide.
            ctx.negotiated_total = negotiation["new_total"]
            decision = evaluate_order(order_lines, ctx, catalog, policy)
        elif negotiation["status"] not in ("NEGOTIATION_LOST",):
            negotiation = None                                            # NOT_NEEDED / NOT_ELIGIBLE: nothing to log
    decision_doc = decision.to_dict()
    if negotiation and negotiation["status"] == "NEGOTIATION_WON":
        n = negotiation
        decision_doc["explanation"] = (
            f"🤝 The agent negotiated a bulk deal (simulated counter-party): {n['new_qty']:g} {n['sales_unit']} for "
            f"€{n['new_total']:,.2f} instead of {n['original_qty']:g} for €{n['original_total']:,.2f}, "
            f"{n['discount_pct']:g}% off list (€{n['saved_amount']:,.2f} saved vs list, "
            f"{'+' if n['spend_change_vs_original'] >= 0 else ''}€{n['spend_change_vs_original']:,.2f} vs the original order). "
            + decision_doc["explanation"])
    if negotiation:
        decision_doc["negotiation"] = negotiation
    order = {
        "order_id": order_id, "quote_id": req.quote_id, "agent_id": agent.agent_id,
        "customer": agent.customer, "requested_date": qp.get("requested_date"),
        "created_at": iso(utcnow()), "status": decision.status.value,
        "lines": view_lines, "decision": decision_doc,
        "quote_digest": envelope.get("digest"), "approval": None, "negotiation": negotiation,
    }
    state.audit.record(Action.ORDER_SUBMITTED, {
        "order_id": order_id, "quote_id": req.quote_id, "quote_signature": sig_status,
        "accepted_substitutions": [s.model_dump() for s in req.accept_substitutions],
        "dropped": req.drop_product_ids, "lines": submitted_lines,
    }, actor=actor, refs=refs)
    if negotiation:
        state.audit.record(Action.NEGOTIATION_WON if negotiation["status"] == "NEGOTIATION_WON" else Action.NEGOTIATION_LOST,
                           {"order_id": order_id, "negotiation": negotiation, "sales_unit": negotiation["sales_unit"],
                            "product": negotiation["product"]}, actor=f"agent:{agent.agent_id}", refs=refs)
    state.audit.record(Action.POLICY_DECISION, {"order_id": order_id, "decision": decision_doc},
                       actor="guardrails", refs=refs)
    for d in decision.drift:
        db.log_drift(order_id, agent.agent_id, agent.customer, d["metric"], d["observed"], d["baseline"],
                     d["deviation_pct"], d.get("productId") if d["metric"] == "line_quantity" else None)

    decided_by = None
    if decision.status is Status.AUTO_APPROVED:
        decided_by = "trusted_rule" if decision.trusted_rule else "auto"
        if decision.trusted_rule:
            db.touch_rule(decision.trusted_rule["id"])
        _place_order(order, actor="guardrails:auto")
    elif decision.status is Status.REJECTED:
        decided_by = "policy"
    db.save_order(order, decided_by=decided_by)
    if idempotency_key:
        db.put_idempotent(agent.agent_id, idempotency_key, order_id)

    if decision.status is Status.AUTO_APPROVED:
        _fire_webhook("order.auto_approved", order)
    state.hub.publish("order", _order_event(order))
    return _public_order(order)


def _order_event(order: dict[str, Any]) -> dict[str, Any]:
    d = order.get("decision") or {}
    return {"order_id": order["order_id"], "agent_id": order["agent_id"], "status": order["status"],
            "net_total": (d.get("totals") or {}).get("net_total"), "explanation": d.get("explanation"),
            "drift": bool(d.get("drift")), "trusted_rule": d.get("trusted_rule")}


def _fire_webhook(event: str, order: dict[str, Any]) -> None:
    """#2: signed webhook, delivered in the background so the API response is never delayed."""
    if state.dispatcher is None or event not in (state.policy.get("webhooks.events") or []):
        return
    payload = {"order_id": order["order_id"], "agent_id": order["agent_id"], "customer": order["customer"],
               "status": order["status"], "net_total": (order["decision"].get("totals") or {}).get("net_total"),
               "approval": order.get("approval"), "confirmation": order.get("confirmation"),
               "receipt_digest": (order.get("receipt") or {}).get("digest"),
               "explanation": order["decision"].get("explanation")}

    async def run() -> None:
        record = await state.dispatcher.deliver(event, payload, order_id=order["order_id"])
        state.db.log_webhook(record)
        state.audit.record(Action.WEBHOOK, {
            "event": event, "delivery_id": record["delivery_id"], "url": record["url"], "status": record["status"],
            "status_code": record.get("status_code"), "attempts": record["attempts"],
            "signature": record.get("signature"), "error": record.get("error"),
        }, actor="gateway:webhooks", refs=[order["order_id"]])

    # Thread-safe: also called from Gemini tool execution, which runs in a worker thread
    loop = state.hub.loop or asyncio.get_running_loop()
    try:
        in_loop = asyncio.get_running_loop() is loop
    except RuntimeError:
        in_loop = False
    if in_loop:
        loop.create_task(run())
    else:
        loop.call_soon_threadsafe(lambda: loop.create_task(run()))


def _public_order(order: dict[str, Any]) -> dict[str, Any]:
    out = dict(order)
    out["links"] = {"self": f"/v1/orders/{order['order_id']}", "audit": f"/v1/audit/{order['order_id']}"}
    if order["status"] == Status.PENDING_APPROVAL.value:
        out["links"]["approve"] = f"/v1/approvals/{order['order_id']}"
    return out


def _get_order(order_id: str) -> dict[str, Any]:
    order = state.db.get_order(order_id)
    if order is None:
        raise HTTPException(404, detail={"error": "ORDER_NOT_FOUND", "order_id": order_id})
    return order


@app.get("/v1/orders/{order_id}", tags=["agent"])
async def get_order(order_id: str, agent: Agent = Depends(authenticate_agent)) -> dict[str, Any]:
    order = _get_order(order_id)
    if order["agent_id"] != agent.agent_id:
        raise HTTPException(404, detail={"error": "ORDER_NOT_FOUND", "order_id": order_id})
    return _public_order(order)


# =============================================================================
# Human approvals
# =============================================================================

@app.get("/v1/approvals", tags=["human"])
async def pending_approvals(viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    pending = state.db.list_orders(status=Status.PENDING_APPROVAL.value, limit=500)
    trust_cache: dict[str, dict[str, Any]] = {}
    out = []
    for o in sorted(pending, key=lambda o: o["created_at"]):
        aid = o["agent_id"]
        if aid not in trust_cache:
            trust_cache[aid] = state.policy.trust_profile(aid, state.db.agent_trust_stats(aid)).to_dict()
        out.append({**_public_order(o), "agent_trust": trust_cache[aid],
                    "rememberable": build_trusted_rule(o, "preview", state.policy) is not None})
    return {"count": len(out), "orders": out}


@app.post("/v1/approvals/{order_id}", tags=["human"])
async def decide(order_id: str, req: ApprovalRequest, viewer: Viewer = Depends(require_manager)) -> dict[str, Any]:
    # A logged-in manager is always recorded as themselves; the service key must name a reviewer.
    reviewer = viewer.username if viewer.via == "session" else req.reviewer
    if not reviewer:
        raise HTTPException(422, detail={"error": "REVIEWER_REQUIRED"})
    if req.decision == "reject" and viewer.via == "session" and not (req.comment or "").strip():
        raise HTTPException(422, detail={"error": "COMMENT_REQUIRED", "detail": "Explain the rejection"})
    return _decide_order(order_id, req.decision, reviewer=reviewer, role=viewer.role,
                         comment=req.comment, remember=req.remember)


def _decide_order(order_id: str, decision: str, *, reviewer: str, role: str, comment: Optional[str],
                  remember: bool = False, ai: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """
    THE approval/rejection logic, shared by the dashboard buttons and the AI secretary's tools.
    `ai` (model, question, reason, confirmed_by_manager) marks an AI-secretary decision: same effects,
    but audited as APPROVED_BY_AI_SECRETARY / REJECTED_BY_AI_SECRETARY. Sync and thread-safe.
    """
    db, policy = state.db, state.policy
    order = _get_order(order_id)
    new_status = "APPROVING" if decision == "approve" else "REJECTED_BY_HUMAN"
    if not db.claim_pending(order_id, new_status):   # atomic: two managers (or manager + AI) can't both decide
        current = db.get_order(order_id)
        raise HTTPException(409, detail={"error": "NOT_PENDING", "status": current["status"] if current else None})

    agent_id = order["agent_id"]
    before = policy.trust_profile(agent_id, db.agent_trust_stats(agent_id))
    db.record_approval(order_id, agent_id, decision, reviewer, role if not ai else f"{role} via AI secretary", comment)
    order["status"] = new_status
    order["approval"] = {"decision": decision, "reviewer": reviewer, "role": role, "comment": comment,
                         "remember": remember, "decided_at": iso(utcnow()),
                         "via": "ai_secretary" if ai else "dashboard"}
    actor = f"human:{reviewer}" if not ai else f"ai_secretary:{ai.get('model')} (for {reviewer})"
    refs = [order_id, order["quote_id"]]
    if ai:
        state.audit.record(
            Action.APPROVED_BY_AI_SECRETARY if decision == "approve" else Action.REJECTED_BY_AI_SECRETARY, {
                "order_id": order_id, "reviewer": reviewer, "role": role, "model": ai.get("model"),
                "reason": ai.get("reason"), "manager_request": ai.get("question"),
                "confirmed_by_manager": bool(ai.get("confirmed_by_manager")),
                "overridden_reasons": order["decision"]["reasons"]}, actor=actor, refs=refs)
    else:
        state.audit.record(Action.APPROVAL if decision == "approve" else Action.REJECTION, {
            "order_id": order_id, "reviewer": reviewer, "role": role, "comment": comment,
            "remember": remember, "overridden_reasons": order["decision"]["reasons"],
        }, actor=actor, refs=refs)

    if decision == "approve":
        if remember:                                       # #1 trust escalation
            rule = build_trusted_rule(order, reviewer, policy)
            if rule:
                rule_id = db.add_trusted_rule(rule)
                order["approval"]["trusted_rule_id"] = rule_id
                state.audit.record(Action.TRUST_RULE, {"rule_id": rule_id, "event": "created", "by": reviewer,
                                                       **rule}, actor=actor, refs=refs)
            else:
                order["approval"]["trusted_rule_id"] = None
                order["approval"]["rule_note"] = ("Not remembered: at least one escalation reason "
                                                  "(e.g. price change, unverified stock) is never waivable")
        _place_order(order, actor=actor)
    db.save_order(order, decided_by="human")             # a manager authorized it (button or confirmed AI action)

    after = policy.trust_profile(agent_id, db.agent_trust_stats(agent_id))   # #3 trust levels
    if after.level != before.level:
        state.audit.record(Action.TRUST_LEVEL, {
            "agent_id": agent_id, "from_level": before.level, "to_level": after.level, "to_name": after.name,
            "autonomous_limit": after.autonomous_limit, "score": after.score}, actor="gateway:trust", refs=[order_id])
    _fire_webhook("order.approved" if decision == "approve" else "order.rejected", order)
    state.hub.publish("order", _order_event(order))
    return {**_public_order(order), "agent_trust": after.to_dict()}


# =============================================================================
# Dashboard auth (#13): manager = read/write approvals, auditor = read-only
# =============================================================================

@app.post("/v1/auth/login", tags=["human"])
async def login(req: LoginRequest) -> dict[str, Any]:
    role = await asyncio.to_thread(state.db.authenticate, req.username, req.password)  # PBKDF2 is CPU-bound
    if role is None:
        await asyncio.sleep(0.4)  # blunt brute force
        raise HTTPException(401, detail={"error": "INVALID_CREDENTIALS"})
    ttl = int(os.getenv("DASHBOARD_SESSION_HOURS", "12"))
    token = state.db.create_session(req.username, role, ttl_hours=ttl)
    state.audit.record(Action.SYSTEM, {"summary": f"dashboard login: {req.username} ({role})"}, actor=f"human:{req.username}")
    return {"token": token, "username": req.username, "role": role, "expires_in": ttl * 3600}


@app.post("/v1/auth/logout", tags=["human"], status_code=204)
async def logout(authorization: Optional[str] = Header(None)) -> Response:
    if token := _bearer(authorization):
        if sess := state.db.get_session(token):
            _forget_chat(sess["username"])
        state.db.delete_session(token)
    return Response(status_code=204)


@app.get("/v1/auth/me", tags=["human"])
async def me(viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    return viewer.model_dump()


# =============================================================================
# Live updates (#12)
# =============================================================================

@app.websocket("/ws")
async def live(websocket: WebSocket) -> None:
    """
    Protocol: client sends {"type":"auth","token":"..."} first (tokens never go in
    the URL, where proxies and access logs would record them). Server then pushes
    {"type": "audit"|"order"|"offer"|"webhook", "ts", "data"}. Client may send "ping".
    """
    await websocket.accept()
    try:
        first = json.loads(await asyncio.wait_for(websocket.receive_text(), timeout=10))
        session = state.db.get_session(str(first.get("token", ""))) if first.get("type") == "auth" else None
    except (asyncio.TimeoutError, ValueError, AttributeError, WebSocketDisconnect):
        session = None
    if not session:
        await websocket.close(code=4401)
        return
    state.hub.clients.add(websocket)
    try:
        await websocket.send_text(json.dumps({"type": "hello", "ts": iso(utcnow()),
                                              "data": {"username": session["username"], "role": session["role"],
                                                       "clients": len(state.hub.clients)}}))
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "ts": iso(utcnow()), "data": {}}))
    except WebSocketDisconnect:
        pass
    finally:
        state.hub.clients.discard(websocket)


# =============================================================================
# Metrics (#14)
# =============================================================================

@app.get("/v1/metrics", tags=["human"])
async def metrics(viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    db, p = state.db, state.policy
    agents: dict[str, dict[str, Any]] = {}
    for agent_id, customer in AGENT_KEYS.values():   # never expose the keys themselves
        a = agents.setdefault(agent_id, {"agent_id": agent_id, "customers": []})
        if customer not in a["customers"]:
            a["customers"].append(customer)
    for a in agents.values():
        stats = db.agent_trust_stats(a["agent_id"])
        a.update(p.trust_profile(a["agent_id"], stats).to_dict())
        a.update({"autonomous_orders": stats.get("autonomous_orders", 0),
                  "scopes": p.agent(a["agent_id"]).get("scopes") or [],
                  "levels": p.get("trust_levels.levels") or []})
    m = db.metrics()
    return {
        **m,
        "pending_approvals": len(db.list_orders(status=Status.PENDING_APPROVAL.value, limit=1000)),
        "agents": sorted(agents.values(), key=lambda a: a["agent_id"]),
        "recent_drift": db.drift_logs(10),
        "roi": {"error_prevention_estimate_eur": float(p.get("roi.error_prevention_estimate_eur", 50))},
        "policy": {**p.summary(), "max_autonomous_spend": p.get("spend.max_autonomous_spend"),
                   "hard_cap_per_order": p.get("spend.hard_cap_per_order"),
                   "max_daily_autonomous_spend": p.get("spend.max_daily_autonomous_spend"),
                   "drift_threshold_pct": p.get("drift.threshold_pct"), "allergen_safety": p.allergen_mode},
        "gateway": {"upstream": state.upstream_mode, "semantic_search": state.adapter.health()["semantic_search"],
                    "kid": state.signer.kid, "live_clients": len(state.hub.clients),
                    "webhooks": state.dispatcher.url if state.dispatcher else None},
        "viewer": viewer.model_dump(),
    }


# =============================================================================
# Proactive offer -> accept & negotiate (simulated counter-party)
# =============================================================================

class NegotiateRequest(BaseModel):
    # Unknown keys are rejected BY NAME ("extra_forbidden") instead of being silently ignored
    model_config = ConfigDict(extra="forbid")

    offer_id: str = Field(..., min_length=1)
    # Optional assertions from the client. They are CHECKED against the signed offer, never trusted:
    # a tampered base_price is refused instead of changing the maths.
    product_id: Optional[str] = None
    base_price: Optional[float] = Field(None, gt=0)
    quantity: Optional[float] = Field(None, gt=0, description="Base quantity before the +20% counter-offer; "
                                                               "default = the most that still fits the surplus")
    buyer_profile: str = "default"
    dry_run: bool = Field(False, description="Only compute terms + guardrail preview; create nothing")


def _negotiation_identity(x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
                          authorization: Optional[str] = Header(None),
                          x_approver_key: Optional[str] = Header(None, alias="X-Approver-Key")) -> dict[str, Any]:
    """The agent itself (X-Agent-Key) or a dashboard manager acting for the offer's agent."""
    if x_agent_key:
        agent = authenticate_agent(x_agent_key)
        if not state.policy.has_scope(agent.agent_id, "order"):
            raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": "Agent lacks 'order' scope"})
        return {"agent": agent, "actor": f"agent:{agent.agent_id}", "manager": None}
    viewer = require_viewer(authorization, x_approver_key)
    return {"agent": None, "actor": None, "manager": viewer}


def _ordering_agent(target: Optional[str]) -> Agent:
    """For a manager-initiated acceptance: the offer's target agent, else the first agent allowed to order."""
    for agent_id, customer in AGENT_KEYS.values():
        if (target and agent_id == target) or (not target and state.policy.has_scope(agent_id, "order")):
            return Agent(agent_id=agent_id, customer=customer)
    raise HTTPException(409, detail={"error": "NO_ORDERING_AGENT", "detail": "No agent may order this offer"})


def _order_context(agent: Agent, buyer_profile: str = "default", extra: tuple = ()) -> OrderContext:
    db, policy = state.db, state.policy
    return OrderContext(
        customer=agent.customer, agent_id=agent.agent_id, buyer_profile=buyer_profile,
        extra_excluded_allergens=extra, quote_signature_status="OK",
        daily_autonomous_spend=db.autonomous_spend_since(agent.customer, utcnow() - timedelta(hours=24)),
        trust=policy.trust_profile(agent.agent_id, db.agent_trust_stats(agent.agent_id)),
        history=db.order_history(agent.agent_id, agent.customer, lookback=int(policy.get("drift.lookback_orders", 20))),
        trusted_rules=tuple(db.active_rules(agent.agent_id, agent.customer)))


@app.post("/v1/agent/negotiate", tags=["agent"])
async def negotiate_offer_endpoint(req: NegotiateRequest, who: dict = Depends(_negotiation_identity)) -> dict[str, Any]:
    """
    Accept a Valio proactive offer and counter-propose "+20% volume for an extra 10%". A won deal becomes a
    real order that goes through the normal guardrails (auto-approved within limits, otherwise a human
    decides). dry_run=true returns the terms + the guardrail outcome without creating anything.
    """
    db, policy, catalog = state.db, state.policy, state.adapter.catalog
    row = db.get_offer(req.offer_id)
    if row is None:
        raise HTTPException(404, detail={"error": "OFFER_NOT_FOUND"})
    ok_sig, why = state.signer.open(row["envelope"], check_expiry=False)
    if not ok_sig:                                   # the offer must be one Valio (this gateway) actually signed
        hint = {
            "UNKNOWN_KEY": (f"This offer was signed with gateway key {row['envelope'].get('kid')}, but the gateway now "
                            f"signs with {state.signer.kid} (the key changed on a restart). Ask Valio to re-issue the offer."),
            "INVALID_SIGNATURE": "The stored offer was modified after Valio signed it; it can't be trusted.",
            "MALFORMED_ENVELOPE": "The stored offer is malformed.",
        }.get(why, why)
        raise HTTPException(409, detail={"error": "OFFER_SIGNATURE_INVALID", "reason": why, "detail": hint})
    offer = row["envelope"]["payload"]
    if row["status"] != "OPEN":
        raise HTTPException(409, detail={"error": "OFFER_NOT_OPEN", "status": row["status"]})
    if offer["valid_until"] < date.today().isoformat():
        raise HTTPException(410, detail={"error": "OFFER_EXPIRED", "valid_until": offer["valid_until"]})
    if who["manager"] is not None:
        if who["manager"].role != "manager" and not req.dry_run:
            raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": "Auditors have read-only access"})
        agent = _ordering_agent(offer.get("target_agent_id"))
        actor = f"agent:{agent.agent_id} (accepted by {who['manager'].username})"
    else:
        agent, actor = who["agent"], who["actor"]
        if offer.get("target_agent_id") not in (None, agent.agent_id):
            raise HTTPException(403, detail={"error": "OFFER_NOT_FOR_THIS_AGENT"})

    if req.product_id is not None and req.product_id != offer["productId"]:
        raise HTTPException(409, detail={"error": "OFFER_PRODUCT_MISMATCH",
                                          "detail": f"This offer is for {offer['productId']}, not {req.product_id}"})
    signed_base = offer.get("base_price")             # locked by the seller agent from Valio /api/price
    if req.base_price is not None and signed_base is not None and abs(req.base_price - signed_base) > 0.005:
        raise HTTPException(409, detail={"error": "BASE_PRICE_MISMATCH",
                                          "detail": f"The signed offer's base price is €{signed_base}, not €{req.base_price}"})
    p = catalog.require(offer["productId"])
    lot = p.allowed_lot_size if (p.sales_unit or "").upper() in WEIGHT_SALES_UNITS else max(p.allowed_lot_size or 1, 1)
    delivery = (date.today() + timedelta(days=2)).isoformat()
    live = (await state.adapter.live_snapshot(agent.customer, delivery, [p.id]))[p.id]
    price, avail = live["price"], live["availability"]
    list_price = signed_base if signed_base is not None else price.unit_price   # the offer locks its price
    if list_price is None:
        raise HTTPException(409, detail={"error": "NO_PRICE", "detail": "Valio returned no price for this product"})

    base_qty = req.quantity or suggested_offer_quantity(offer["quantity_available"],
                                                        float(policy.get("negotiation.quantity_uplift_pct", 20)), lot)
    terms = negotiate_proactive_offer(
        p.id, base_qty, list_price, offer["discount_pct"], offer["quantity_available"],
        quantity_uplift_pct=float(policy.get("negotiation.quantity_uplift_pct", 20)),
        extra_discount_pct=float(policy.get("negotiation.discount_pct", 10)), lot_size=lot)
    terms.update({"product": p.display_name, "sales_unit": p.sales_unit, "offer_id": req.offer_id,
                  "price_source": "signed offer (Valio /api/price at offer time)" if signed_base is not None
                                  else "live Valio /api/price"})

    def make_line() -> OrderLine:
        return OrderLine(p.id, terms["new_qty"], terms["new_unit_price"], terms["new_unit_price"],
                         currency=price.currency or "EUR", price_status=price.status, net_price_found=price.net_price_found,
                         availability_status=avail.status, available_amount=avail.available_amount)

    ctx = _order_context(agent, req.buyer_profile)
    if req.dry_run:
        preview = evaluate_order([make_line()], ctx, catalog, policy).to_dict() if terms["status"] == "NEGOTIATION_WON" else None
        return {"dry_run": True, "agent_id": agent.agent_id, "terms": terms, "preview": preview}

    order_id = _new_id("ord")
    refs = [order_id, req.offer_id]
    if terms["status"] != "NEGOTIATION_WON":
        state.audit.record(Action.NEGOTIATION_LOST, {"offer_id": req.offer_id, "negotiation": terms,
                                                     "sales_unit": p.sales_unit, "product": p.display_name},
                           actor=actor, refs=[req.offer_id])
        return {"ok": False, "status": "NEGOTIATION_LOST", "reason": terms["reason"], "terms": terms}
    if not db.accept_offer(req.offer_id, agent.agent_id, order_id):     # atomic: one acceptance per offer
        raise HTTPException(409, detail={"error": "OFFER_ALREADY_ACCEPTED"})

    line = make_line()
    decision = evaluate_order([line], ctx, catalog, policy)            # normal limits apply: no negotiation waiver
    decision_doc = decision.to_dict()
    decision_doc["explanation"] = (
        f"🤝 Accepted Valio's proactive offer (-{terms['offer_discount_pct']:g}%) and negotiated an extra "
        f"{terms['discount_pct']:g}% for {terms['new_qty']:g} {p.sales_unit} (simulated counter-party): "
        f"€{terms['new_total']:,.2f}, saving €{terms['saved_amount']:,.2f} through negotiation "
        f"(€{terms['total_saved_vs_list']:,.2f} vs list). " + decision_doc["explanation"])
    decision_doc["negotiation"] = terms
    view = [{"productId": p.id, "name": p.display_name, "quantity": line.quantity, "salesUnit": p.sales_unit,
             "quotedUnitPrice": line.quoted_unit_price, "liveUnitPrice": line.live_unit_price,
             "unitPrice": line.effective_unit_price, "lineValue": line.line_value,
             "availability": line.availability_status, "substitutesFor": None, "negotiated": True}]
    order = {"order_id": order_id, "quote_id": None, "offer_id": req.offer_id, "source": "proactive_offer",
             "agent_id": agent.agent_id, "customer": agent.customer, "requested_date": delivery,
             "created_at": iso(utcnow()), "status": decision.status.value, "lines": view, "decision": decision_doc,
             "quote_digest": None, "approval": None, "negotiation": terms}
    state.audit.record(Action.NEGOTIATION_WON, {"order_id": order_id, "offer_id": req.offer_id, "negotiation": terms,
                                                "sales_unit": p.sales_unit, "product": p.display_name},
                       actor=actor, refs=refs)
    state.audit.record(Action.POLICY_DECISION, {"order_id": order_id, "decision": decision_doc},
                       actor="guardrails", refs=refs)
    decided_by = None
    if decision.status is Status.AUTO_APPROVED:
        decided_by = "auto"
        _place_order(order, actor="guardrails:auto")
    elif decision.status is Status.REJECTED:
        decided_by = "policy"
    db.save_order(order, decided_by=decided_by)
    if decision.status is Status.AUTO_APPROVED:
        _fire_webhook("order.auto_approved", order)
    state.hub.publish("order", _order_event(order))
    state.hub.publish("offer", {**offer, "status": "ACCEPTED"})
    return {"ok": True, "status": "NEGOTIATION_WON", "saved_amount": terms["saved_amount"],
            "new_qty": terms["new_qty"], "new_total": terms["new_total"], "terms": terms,
            "order": _public_order(order),
            "message": f"Offer accepted and negotiated: {terms['new_qty']:g} {p.sales_unit} for €{terms['new_total']:,.2f}, "
                       f"saved €{terms['saved_amount']:,.2f}. Order {decision.status.value.replace('_', ' ').lower()}."}


# =============================================================================
# Last-minute event order: "big event tomorrow, buy 500 L of lactose-free milk"
# =============================================================================
# One core used by POST /v1/agent/event-order AND the chat tool order_for_last_minute_event.
# It resolves the product (search + unit fit + live price/stock), converts litres/kg into the
# product's sales units, then runs the REAL quote -> order pipeline, so signing, guardrails,
# negotiation, drift, audit and live updates all apply exactly as for any agent order.

class EventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_name: str = Field(..., min_length=2, max_length=120, examples=["lactose-free milk"])
    quantity: float = Field(..., gt=0, le=100000, description="How much, in `unit`")
    delivery_date: date = Field(..., description="YYYY-MM-DD, today or later")
    unit: Literal["L", "KG", "units"] = Field("units", description="L / KG are converted to sales units by pack size")
    product_id: Optional[str] = Field(None, max_length=40, description="Exact product id: skips the product search")
    buyer_profile: str = "default"
    dry_run: bool = Field(False, description="Resolve product + price + guardrail preview only")


_UNIT_UOM = {"L": "L", "KG": "KG", "units": None}
# Flavoured / derived variants that a plain "milk" request should not pick (kept if the request names them)
_VARIANT_WORDS = ("chocolate", "cocoa", "kaakao", "suklaa", "coffee", "kahvi", "vanilla", "strawberry", "banana",
                  "mango", "blueberry", "raspberry", "caramel", "powder", "jauhe", "drink snack", "play")


async def _available_alternatives(p: Any, delivery: str, agent: Agent, k: int = 3) -> list[dict[str, Any]]:
    """Similar products that ARE priced and in stock for that delivery date (real data only, never invented)."""
    try:
        hits = await asyncio.to_thread(state.adapter.index.similar_to, p.id, 12)
        if not hits:
            return []
        live = await state.adapter.live_snapshot(agent.customer, delivery, [h.product.id for h in hits])
    except Exception as exc:          # alternatives are a courtesy: never turn a clear "unavailable" into a 500
        logger.warning("alternatives for %s failed (%s)", p.id, type(exc).__name__)
        return []
    out = []
    for h in hits:
        snap = live.get(h.product.id) or {}
        price, avail = snap.get("price"), snap.get("availability")
        if price and price.unit_price and avail and avail.status == "AVAILABLE":
            q = h.product
            out.append({"product_id": q.id, "name": q.display_name, "sales_unit": q.sales_unit,
                        "price_eur_per_sales_unit": round(price.unit_price, 2), "availability": "AVAILABLE"})
        if len(out) >= k:
            break
    return out


async def _resolve_fixed_product(product_id: str, qty: float, unit: str, agent: Agent, delivery: str) -> dict[str, Any]:
    """place_order: the product is already chosen (from search_catalog). Price + stock it, convert L/KG to packs."""
    from .guardrails import snap_to_lot

    p = state.adapter.catalog.get(product_id)
    if p is None:
        raise HTTPException(404, detail={"error": "UNKNOWN_PRODUCT", "detail": f"No product with id {product_id!r}"})
    want = _UNIT_UOM[unit]
    if want and (p.base_unit_content_uom != want or not p.content_per_sales_unit):
        raise HTTPException(422, detail={"error": "UNIT_MISMATCH",
                                         "detail": f"{p.display_name} is not sold by {unit}; order it in packs "
                                                   f"({p.sales_unit}) instead"})
    snap = (await state.adapter.live_snapshot(agent.customer, delivery, [p.id])).get(p.id) or {}
    price, avail = snap.get("price"), snap.get("availability")
    weekday = date.fromisoformat(delivery).strftime("%A")
    if not (price and price.unit_price):
        raise HTTPException(409, detail={"error": "NO_PRICE", "detail": f"Valio has no price for {p.display_name} on {delivery}",
                                         "alternatives": await _available_alternatives(p, delivery, agent)})
    if not avail or avail.status != "AVAILABLE":
        if avail and avail.earliest_date and avail.earliest_date > delivery:
            raise HTTPException(409, detail={
                "error": "NO_DELIVERY_ON_DATE", "earliest_delivery": avail.earliest_date,
                "detail": f"Valio can't deliver {p.display_name} on {delivery} ({weekday}). Earliest delivery: "
                          f"{avail.earliest_date} ({date.fromisoformat(avail.earliest_date).strftime('%A')}).",
                "alternatives": await _available_alternatives(p, delivery, agent)})
        raise HTTPException(409, detail={"error": "NOT_AVAILABLE",
                                         "detail": f"{p.display_name} is {(avail.status if avail else 'unknown').replace('_', ' ').lower()} "
                                                   f"for {delivery} ({weekday})",
                                         "alternatives": await _available_alternatives(p, delivery, agent)})
    sales_qty = snap_to_lot(qty / p.content_per_sales_unit if want else qty, p.allowed_lot_size, p.sales_unit)
    covered = round(sales_qty * p.content_per_sales_unit, 3) if want else sales_qty
    return {"product": p, "price": price, "availability": avail, "sales_qty": sales_qty, "covered": covered,
            "alternatives": []}


async def _resolve_event_product(name: str, qty: float, unit: str, agent: Agent, delivery: str) -> dict[str, Any]:
    from .guardrails import snap_to_lot

    want = _UNIT_UOM[unit]
    hits = await asyncio.to_thread(state.adapter.search, name, 40, require_claims=True)
    if not hits:
        hits = await asyncio.to_thread(state.adapter.search, name, 40)
    q = name.lower()
    cands = []
    for h in hits:
        p = h.product
        pname = f"{p.name_en or ''} {p.name_fi or ''}".lower()
        if want and (p.base_unit_content_uom != want or not p.content_per_sales_unit):
            continue                                              # can't express "500 L" in this product
        if any(w in pname and w not in q for w in _VARIANT_WORDS):
            continue                                              # "milk" must not become milk chocolate
        cands.append(h)
    if not cands:
        raise HTTPException(404, detail={"error": "NO_MATCHING_PRODUCT",
                                         "detail": f"No product matching {name!r} sold by {unit} was found"})
    top = cands[:12]
    live = await state.adapter.live_snapshot(agent.customer, delivery, [h.product.id for h in top])
    scored = []
    for rank, h in enumerate(top):
        p = h.product
        snap = live.get(p.id) or {}
        price, avail = snap.get("price"), snap.get("availability")
        if not (price and price.unit_price and avail and avail.status == "AVAILABLE"):
            continue
        sales_qty = snap_to_lot(qty / p.content_per_sales_unit if want else qty, p.allowed_lot_size, p.sales_unit)
        enough = avail.available_amount >= sales_qty
        # in search order, preferring: enough stock, a customer net price (auto-approvable)
        scored.append(((not enough, not price.net_price_found, rank), p, price, avail, sales_qty))
    if not scored:
        # Typical cause: no delivery that day (e.g. Sunday). Valio reports stock arriving later: say when.
        later = sorted(a.earliest_date for a in (s.get("availability") for s in live.values())
                       if a and a.status == "PARTIAL" and a.earliest_date and a.earliest_date > delivery)
        weekday = date.fromisoformat(delivery).strftime("%A")
        if later:
            raise HTTPException(409, detail={
                "error": "NO_DELIVERY_ON_DATE", "earliest_delivery": later[0],
                "detail": f"Valio can't deliver {name} on {delivery} ({weekday}). Earliest delivery: "
                          f"{later[0]} ({date.fromisoformat(later[0]).strftime('%A')})."})
        raise HTTPException(409, detail={"error": "NOTHING_IN_STOCK",
                                         "detail": f"Found {len(top)} products matching {name!r}, but none is priced "
                                                   f"and in stock for {delivery} ({weekday})"})
    scored.sort(key=lambda x: x[0])
    _, p, price, avail, sales_qty = scored[0]
    covered = round(sales_qty * p.content_per_sales_unit, 3) if want else sales_qty
    return {"product": p, "price": price, "availability": avail, "sales_qty": sales_qty, "covered": covered,
            "alternatives": [{"productId": x[1].id, "name": x[1].display_name, "unitPrice": x[2].unit_price,
                              "salesUnit": x[1].sales_unit} for x in scored[1:4]]}


async def _event_order(agent: Agent, req: EventRequest, actor: str, *, source: str,
                       audit_action: str = Action.LAST_MINUTE_EVENT_ORDER) -> dict[str, Any]:
    if req.delivery_date < date.today():
        raise HTTPException(422, detail={"error": "DELIVERY_DATE_IN_PAST", "detail": f"{req.delivery_date} is in the past"})
    delivery = req.delivery_date.isoformat()
    r = (await _resolve_fixed_product(req.product_id, req.quantity, req.unit, agent, delivery) if req.product_id
         else await _resolve_event_product(req.product_name, req.quantity, req.unit, agent, delivery))
    p, price, sales_qty, covered = r["product"], r["price"], r["sales_qty"], r["covered"]
    unit_txt = "units" if req.unit == "units" else req.unit
    amount = f"{sales_qty:g} {p.sales_unit}" + (f" (= {covered:g} {unit_txt})" if req.unit != "units" else "")
    est_total = round(sales_qty * price.unit_price, 2)
    base = {"product_id": p.id, "product": p.display_name, "requested": f"{req.quantity:g} {unit_txt}",
            "sales_qty": sales_qty, "sales_unit": p.sales_unit, "covered": covered, "unit_price": price.unit_price,
            "estimated_total": est_total, "delivery_date": delivery, "alternatives": r["alternatives"]}

    if req.dry_run:
        line = OrderLine(p.id, sales_qty, price.unit_price, price.unit_price, currency=price.currency or "EUR",
                         price_status=price.status, net_price_found=price.net_price_found,
                         availability_status=r["availability"].status, available_amount=r["availability"].available_amount)
        preview = evaluate_order([line], _order_context(agent, req.buyer_profile), state.adapter.catalog, state.policy)
        return {"dry_run": True, **base, "preview": {"status": preview.status.value, "explanation": preview.explanation}}

    # The REAL pipeline: signed quote -> order (guardrails, negotiation, drift, audit, websockets)
    q = await quote(QuoteRequest(requested_date=req.delivery_date, buyer_profile=req.buyer_profile,
                                 lines=[QuoteLineIn(product_id=p.id, quantity=sales_qty)]), agent=agent)
    o = await create_order(OrderRequest(quote_id=q["quote_id"]), agent=agent, idempotency_key=None)
    status = o["status"]
    n = o.get("negotiation") or {}
    # Report what was ACTUALLY ordered: a won bulk negotiation changes the quantity (+20%)
    placed_qty = float(o["lines"][0]["quantity"]) if o["lines"] else sales_qty
    placed_cov = round(placed_qty * p.content_per_sales_unit, 3) if req.unit != "units" else placed_qty
    amount = f"{placed_qty:g} {p.sales_unit}" + (f" (= {placed_cov:g} {unit_txt})" if req.unit != "units" else "")
    verb = {"PLACED": "placed order", "PENDING_APPROVAL": "prepared order (awaiting your approval)",
            "REJECTED": "could not order"}.get(status, status.lower())
    msg = f"Found {p.display_name}, {verb} for {amount}"
    if status != "REJECTED":
        msg += f", total €{o['decision']['totals']['net_total']:,.2f}, delivery {delivery}."
    else:
        msg += f": {o['decision']['explanation']}"
    if n.get("status") == "NEGOTIATION_WON":
        msg += (f" You asked for {base['requested']}; the agent negotiated a bulk deal (+{placed_cov - covered:g} "
                f"{unit_txt} at {n['discount_pct']:g}% off), saving €{n['saved_amount']:,.2f} vs list.")
    state.audit.record(audit_action, {
        "order_id": o["order_id"], "product_id": p.id, "product": p.display_name, "requested": base["requested"],
        "sales_qty": o["lines"][0]["quantity"], "sales_unit": p.sales_unit, "covered": covered,
        "delivery_date": delivery, "status": status, "source": source, "search_query": req.product_name,
        "alternatives": r["alternatives"], "negotiation": n or None, "message": msg},
        actor=actor, refs=[o["order_id"], q["quote_id"]])
    state.hub.publish("order_placed", {"order_id": o["order_id"], "status": status, "message": msg,
                                       "product": p.display_name, "source": source})
    return {"ok": status != "REJECTED", "status": status, "message": msg, **base,
            "order_id": o["order_id"], "order": o, "negotiation": n or None}


@app.post("/v1/agent/event-order", tags=["agent"])
async def event_order(req: EventRequest, who: dict = Depends(_negotiation_identity)) -> dict[str, Any]:
    """Last-minute event: find the product, convert L/KG to sales units, quote, run the guardrails, order."""
    if who["manager"] is not None:
        if who["manager"].role != "manager" and not req.dry_run:
            raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": "Auditors have read-only access"})
        agent = _ordering_agent(None)
        actor = f"agent:{agent.agent_id} (for {who['manager'].username})"
    else:
        agent, actor = who["agent"], who["actor"]
    return await _event_order(agent, req, actor, source="api")


@app.get("/v1/dashboard/orders", tags=["human"])
async def dashboard_orders(limit: int = Query(8, ge=1, le=50), status: Optional[str] = None,
                           viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    """Newest orders for dashboard users (Focus Mode renders them as a list)."""
    if status and status not in {s.value for s in Status}:
        raise HTTPException(422, detail={"error": "UNKNOWN_STATUS", "detail": f"status must be one of {[s.value for s in Status]}"})
    orders = state.db.list_orders(status=status, limit=limit)
    return {"count": len(orders), "orders": [_public_order(o) for o in orders]}


@app.get("/v1/dashboard/orders/{order_id}", tags=["human"])
async def dashboard_order(order_id: str, viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    """Full order document for dashboard users (the spotlight renders it)."""
    order = _get_order(order_id)
    trust = state.policy.trust_profile(order["agent_id"], state.db.agent_trust_stats(order["agent_id"])).to_dict()
    return {**_public_order(order), "agent_trust": trust,
            "rememberable": order["status"] == Status.PENDING_APPROVAL.value
                            and build_trusted_rule(order, "preview", state.policy) is not None}


@app.get("/v1/trusted-rules", tags=["human"])
async def trusted_rules(include_inactive: bool = False, viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    return {"rules": state.db.list_rules(include_inactive)}


@app.delete("/v1/trusted-rules/{rule_id}", tags=["human"])
async def revoke_trusted_rule(rule_id: int, viewer: Viewer = Depends(require_manager)) -> dict[str, Any]:
    if not state.db.revoke_rule(rule_id, viewer.username):
        raise HTTPException(404, detail={"error": "RULE_NOT_FOUND_OR_INACTIVE"})
    state.audit.record(Action.TRUST_RULE, {"rule_id": rule_id, "event": "revoked", "by": viewer.username},
                       actor=f"human:{viewer.username}")
    return {"revoked": rule_id}


# =============================================================================
# Webhooks: mock receiver (#2). Stands in for the customer's ERP endpoint.
# =============================================================================

@app.post("/v1/webhooks/mock-receiver", tags=["valio"], include_in_schema=True)
async def mock_webhook_receiver(request: Request) -> Response:
    raw = await request.body()          # verify the RAW bytes, before any JSON parsing
    ok, reason = verify_webhook(raw, request.headers.get(WEBHOOK_SIGNATURE_HEADER), state.webhook_secret,
                                tolerance_seconds=int(state.policy.get("webhooks.signature_tolerance_seconds", 300)))
    ed_ok = False
    event = None
    if ok:
        try:
            env = json.loads(raw)
            ed_ok, _ = state.signer.open(env, check_expiry=False)
            event = env["payload"]["event"]
        except (ValueError, KeyError, TypeError):
            ok, reason = False, "MALFORMED_BODY"
    entry = {"received_at": iso(utcnow()), "delivery_id": request.headers.get("X-Valio-Delivery"),
             "event": event or request.headers.get("X-Valio-Event"), "hmac": reason, "ed25519_valid": ed_ok}
    state.webhooks_received.appendleft(entry)
    state.hub.publish("webhook", entry)
    return Response(status_code=204 if ok and ed_ok else 401)


@app.get("/v1/webhooks", tags=["human"])
async def webhook_log(viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    return {"deliveries": state.db.webhook_deliveries(30), "received": list(state.webhooks_received)}


# =============================================================================
# LLM Explainability Chat (Gemini): explains decisions, never makes them
# =============================================================================

class ChatRequest(BaseModel):
    # min_length=1 so a plain "hi" works; whitespace-only input is still refused
    question: str = Field(..., min_length=1, max_length=500)
    mode: Literal["text", "voice"] = Field("text", description="'voice' = short plain sentences for text-to-speech")
    allow_actions: bool = Field(True, description="False = never offer approve/reject tools (e.g. chart analytics)")

    @model_validator(mode="after")
    def _not_blank(self) -> "ChatRequest":
        self.question = self.question.strip()
        if not self.question:
            raise ValueError("question must not be empty")
        return self


# Purchasing-lifecycle entries carry the "why"; SYSTEM (logins, chat questions), searches and webhooks are noise
_CHAT_ACTIONS = {Action.QUOTE, Action.ORDER_SUBMITTED, Action.POLICY_DECISION, Action.APPROVAL, Action.REJECTION,
                 Action.APPROVED_BY_AI_SECRETARY, Action.REJECTED_BY_AI_SECRETARY,
                 Action.NEGOTIATION_WON, Action.NEGOTIATION_LOST, Action.LAST_MINUTE_EVENT_ORDER,
                 Action.ORDERED_BY_AI_SECRETARY, Action.QUICK_ORDER, Action.ORDER_PLACED, Action.TRUST_RULE,
                 Action.TRUST_LEVEL}
_CHAT_RECENT_ENTRIES = int(os.getenv("CHAT_CONTEXT_ENTRIES", "5"))
_CHAT_MAX_PENDING = int(os.getenv("CHAT_MAX_PENDING", "10"))
_VOICE_MAX_BYTES = int(os.getenv("VOICE_MAX_BYTES", str(8 * 1024 * 1024)))
_chat_calls: dict[str, deque] = {}


def _chat_entry(e: dict[str, Any]) -> dict[str, Any]:
    """Compact, explanation-relevant view of one audit entry (keeps prompts small and focused)."""
    d = e.get("data") or {}
    out = {"seq": e["seq"], "time": e["timestamp"], "action": e["action"], "actor": e.get("actor"),
           "order_id": next((r for r in e.get("refs", []) if r.startswith("ord_")), None),
           "summary": summarize_entry(e)}
    dec = d.get("decision") if isinstance(d.get("decision"), dict) else None
    if dec:
        out.update({
            "status": dec.get("status"), "explanation": dec.get("explanation"),
            "net_total_eur": (dec.get("totals") or {}).get("net_total"),
            "autonomous_limit_eur": (dec.get("totals") or {}).get("autonomous_limit"),
            "findings": [{"code": v["code"], "severity": v["severity"], "message": v["message"]}
                         for v in dec.get("violations") or []],
            "drift": dec.get("drift") or None, "trusted_rule": dec.get("trusted_rule"),
        })
    elif e["action"] in (Action.APPROVAL, Action.REJECTION):
        out.update({"reviewer": d.get("reviewer"), "comment": d.get("comment"), "remember": d.get("remember")})
    elif e["action"] in (Action.APPROVED_BY_AI_SECRETARY, Action.REJECTED_BY_AI_SECRETARY):
        out.update({"reviewer": d.get("reviewer"), "reason": d.get("reason"), "model": d.get("model"),
                    "confirmed_by_manager": d.get("confirmed_by_manager")})
    return out


def _dashboard_context() -> dict[str, Any]:
    """
    Snapshot of what the manager sees on the dashboard: metrics, pending approvals,
    agent trust levels and the most recent purchasing decisions.
    """
    db, policy = state.db, state.policy
    entries = [e for e in state.audit.entries()[-400:] if e.get("action") in _CHAT_ACTIONS]

    pending_docs = db.list_orders(status=Status.PENDING_APPROVAL.value, limit=200)
    pending = [{
        "order_id": o["order_id"], "agent_id": o["agent_id"], "submitted": o["created_at"],
        "delivery_date": o.get("requested_date"),
        "net_total_eur": o["decision"]["totals"]["net_total"],
        "why_it_needs_a_human": o["decision"].get("explanation"),
        "drift_detected": bool(o["decision"].get("drift")),
        "lines": [{"product": l["name"], "quantity": l["quantity"], "unit": l["salesUnit"],
                   "line_value_eur": l["lineValue"], "substitutes_for": l.get("substitutesFor")}
                  for l in o["lines"]],
    } for o in sorted(pending_docs, key=lambda o: o["created_at"])[:_CHAT_MAX_PENDING]]

    trust = []
    for agent_id in sorted({a for a, _ in AGENT_KEYS.values()}):
        stats = db.agent_trust_stats(agent_id)
        t = policy.trust_profile(agent_id, stats).to_dict()
        nxt = t.get("next_level")
        trust.append({
            **{k: t[k] for k in ("agent_id", "level", "name", "score", "approvals", "rejections")},
            "autonomous_limit_eur": t["autonomous_limit"],
            "scopes": policy.agent(agent_id).get("scopes") or [],
            "autonomous_orders_placed": stats.get("autonomous_orders", 0),
            "score_rule": "score = approvals - 2 x rejections",
            # Explicit names: "approvals_needed" alone was misread by the model as a total
            "next_level": {"level": nxt["level"], "name": nxt["name"],
                           "additional_approvals_needed": nxt["approvals_needed"],
                           "score_required": t["score"] + nxt["approvals_needed"],
                           "autonomous_limit_eur": nxt["max_autonomous_spend"]} if nxt else None,
        })

    m = db.metrics()
    by = {r["decided_by"]: r for r in m["placed_by_decider"]}
    count = lambda k: (by.get(k) or {}).get("n", 0)
    value = lambda k: (by.get(k) or {}).get("value", 0.0)
    st = m["orders_by_status"]
    metrics = {
        "total_spend_eur": m["total_spend"],
        "orders_auto_approved": count("auto") + count("trusted_rule"),
        "orders_auto_approved_via_trusted_rule": count("trusted_rule"),
        "orders_human_approved": count("human"),
        "orders_rejected_by_guardrails": st.get("REJECTED", 0),
        "orders_rejected_by_managers": st.get("REJECTED_BY_HUMAN", 0),
        "orders_pending_approval": st.get("PENDING_APPROVAL", 0),
        "autonomous_spend_eur": round(value("auto") + value("trusted_rule"), 2),
        "human_approved_spend_eur": round(value("human"), 2),
        "drift_events": m["drift_events"],
        "active_trusted_rules": m["active_trusted_rules"],
        "placed_spend_per_day_eur": [{"day": d["day"], "spend_eur": d["spend"], "orders": d["orders"]}
                                     for d in m["daily_spend"][-14:]],
        "negotiation": m["negotiation"],
        "audit_chain_valid": state.audit.verify().valid,
    }
    return {
        "as_of": iso(utcnow()),
        "today": date.today().isoformat(),
        "metrics": metrics,
        "pending_approvals": pending,
        "pending_approvals_not_listed": max(0, len(pending_docs) - len(pending)),
        "agent_trust_levels": trust,
        "recent_decisions": [_chat_entry(e) for e in entries[-_CHAT_RECENT_ENTRIES:]],
        "recent_orders": _recent_orders_brief(8),
        "policy": {"default_autonomous_limit_eur": policy.get("spend.max_autonomous_spend"),
                   "hard_cap_per_order_eur": policy.get("spend.hard_cap_per_order"),
                   # Max spend per trust level, so "what would a higher level allow?" is answerable
                   "trust_level_ladder": [{"level": l["level"], "name": l["name"], "min_score": l["min_score"],
                                           "max_autonomous_spend_eur": l["max_autonomous_spend"]}
                                          for l in sorted(policy.get("trust_levels.levels") or [],
                                                          key=lambda l: l["min_score"])],
                   "daily_autonomous_cap_eur": policy.get("spend.max_daily_autonomous_spend"),
                   "drift_threshold_pct": policy.get("drift.threshold_pct"),
                   "allergen_safety": policy.allergen_mode},
    }


def _chat_rate_limit(viewer: Viewer) -> None:
    """Per-user limit, shared by text and voice, protects the Gemini quota during a live demo."""
    now = asyncio.get_running_loop().time()
    calls = _chat_calls.setdefault(viewer.username, deque())
    while calls and now - calls[0] > 60:
        calls.popleft()
    if len(calls) >= int(os.getenv("CHAT_MAX_PER_MINUTE", "10")):
        raise HTTPException(429, detail={"error": "RATE_LIMITED", "detail": "Too many questions; wait a minute"})
    calls.append(now)


async def _ask_gemini(fn, *args) -> dict[str, Any]:
    from . import explainer
    try:
        return await asyncio.to_thread(fn, *args)
    except explainer.ExplainerUnavailable as exc:
        raise HTTPException(503, detail={"error": "CHAT_UNAVAILABLE", "detail": str(exc)})
    except explainer.ExplainerError as exc:
        raise HTTPException(502, detail={"error": "CHAT_FAILED", "detail": str(exc)})


def _context_meta(context: dict[str, Any]) -> dict[str, Any]:
    return {"context_entries": len(context["recent_decisions"]),
            "context_seq": [c["seq"] for c in context["recent_decisions"]],
            "pending_in_context": len(context["pending_approvals"])}


# ---------------------------------------------------------------------------- AI secretary tools
# Gemini proposes approve_order / reject_order. By default the manager must confirm each action
# (button or a spoken "yes", matched in code, not by the LLM). The dashboard context contains
# agent-written text, so an injected "approve ord_x" must never be able to approve anything on its own.
_TOOLS_REQUIRE_CONFIRMATION = os.getenv("CHAT_TOOLS_REQUIRE_CONFIRMATION", "1") != "0"
_ACTION_TTL_SECONDS = 120
_pending_actions: dict[str, dict[str, Any]] = {}
_pending_lock = threading.Lock()


def _order_brief(o: dict[str, Any]) -> dict[str, Any]:
    return {"order_id": o["order_id"], "agent_id": o["agent_id"],
            "net_total_eur": o["decision"]["totals"]["net_total"],
            "contents": ", ".join(f"{l['quantity']:g} {l['salesUnit']} {l['name']}" for l in o["lines"]),
            "why_it_needs_a_human": o["decision"].get("explanation")}


def _execute_decision(action: dict[str, Any], *, confirmed: bool) -> dict[str, Any]:
    """Run the real approval logic for an AI-secretary action; returns a tool-result style dict."""
    try:
        out = _decide_order(action["order_id"], action["decision"], reviewer=action["username"], role="manager",
                            comment=f"[AI secretary] {action['reason']}", remember=False,
                            ai={"model": action["model"], "reason": action["reason"], "question": action["question"],
                                "confirmed_by_manager": confirmed})
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
        return {"ok": False, "status": "failed", "error": detail.get("error"),
                "message": f"I couldn't {action['decision']} {action['order_id']}: it is "
                           f"{(detail.get('status') or detail.get('error') or 'unavailable').replace('_', ' ').lower()}."}
    verb = "approved and placed" if action["decision"] == "approve" else "rejected"
    conf = (out.get("confirmation") or {}).get("number")
    return {"ok": True, "status": "done", "order_id": out["order_id"], "order_status": out["status"],
            "confirmation_number": conf,
            "message": f"Done: I {verb} order {out['order_id']} ({action['summary']['contents']}, "
                       f"€{action['summary']['net_total_eur']:,.2f}){f', confirmation {conf}' if conf else ''}."}


def _event_tool(viewer: Viewer, question: str, args: dict[str, Any], actions_out: list[dict[str, Any]]) -> dict[str, Any]:
    """Chat tool: resolve + price the event order (dry run); by default the manager confirms before it's placed."""
    if viewer.role != "manager":
        return {"ok": False, "error": "This user is an auditor (read-only) and cannot place orders."}
    try:
        req = EventRequest(product_name=str(args.get("product_name", "")), quantity=float(args.get("quantity") or 0),
                           delivery_date=str(args.get("delivery_date", "")), unit=str(args.get("unit") or "units"),
                           dry_run=True)
    except Exception as exc:   # pydantic validation: tell the model exactly what is wrong
        return {"ok": False, "error": f"Invalid order request: {exc}"}
    return _propose_order(viewer, question, req, actions_out, kind="event_order",
                          reason_prefix="Last-minute event")


def _next_business_day(start: Optional[date] = None) -> date:
    d = (start or date.today()) + timedelta(days=1)
    while d.weekday() >= 5:            # Valio doesn't deliver at weekends
        d += timedelta(days=1)
    return d


_CATALOG_VARIANT_WORDS = _VARIANT_WORDS + ("ice cream", "jäätelö", "bar ", "candy", "makeis", "cookie", "keksi")


def _catalog_tool(viewer: Viewer, args: dict[str, Any], actions_out: list[dict[str, Any]]) -> dict[str, Any]:
    """search_catalog: hybrid search over product_data.json + live price/availability for the top 5."""
    query = str(args.get("query", "") or "").strip()[:120]
    if len(query) < 2:
        return {"ok": False, "error": "query must be at least 2 characters"}
    try:
        limit = max(1, min(10, int(args.get("limit") or 5)))
    except (TypeError, ValueError):
        limit = 5
    # The whole catalog: FAISS semantic search over all 17,546 embedded products + BM25 keywords
    # (keyword-only when the server runs with GATEWAY_SEMANTIC=0). "gluten-free ..." keeps only products
    # that carry the claim; if none do, fall back to plain relevance.
    hits = state.adapter.search(query, max(20, limit * 4), require_claims=True) or state.adapter.search(query, max(20, limit * 4))
    # "peanut butter" shouldn't surface peanut-butter ICE CREAM or chocolate bars, unless the query asks for them
    q = query.lower()
    plain = [h for h in hits if not any(w in f"{h.product.name_en or ''} {h.product.name_fi or ''}".lower() and w not in q
                                        for w in _CATALOG_VARIANT_WORDS)]
    hits = (plain if plain else hits)[:limit]
    delivery = _next_business_day().isoformat()
    live: dict[str, Any] = {}
    if hits:
        agent = _ordering_agent(None)
        try:   # worker thread -> run the async upstream call on the server loop
            live = asyncio.run_coroutine_threadsafe(
                state.adapter.live_snapshot(agent.customer, delivery, [h.product.id for h in hits]),
                state.hub.loop).result(30)
        except Exception as exc:       # upstream down: still answer from the catalog, without prices
            logger.warning("catalog search: live price/stock failed (%s)", type(exc).__name__)
    results = []
    for h in hits:
        p = h.product
        snap = live.get(p.id) or {}
        price, avail = snap.get("price"), snap.get("availability")
        content = p.content_per_sales_unit
        results.append({
            "product_id": p.id, "name": p.display_name, "brand": p.brand, "category": p.category,
            "pack": f"{p.sales_unit or 'unit'}" + (f" of {content:g} {p.base_unit_content_uom}" if content and p.base_unit_content_uom else ""),
            "sales_unit": p.sales_unit, "content_per_sales_unit": content, "content_uom": p.base_unit_content_uom,
            "price_eur_per_sales_unit": round(price.unit_price, 2) if price and price.unit_price else None,
            "availability": avail.status if avail else "UNKNOWN",
            "available_amount": avail.available_amount if avail else None,
            "earliest_delivery": avail.earliest_date if avail else None,
            "allergens": sorted(p.allergens_contains), "claims": sorted(p.claims)[:4],
        })
    search_id = _new_id("srch")
    state.audit.record(Action.SEARCH, {"search_id": search_id, "query": query, "source": "ai_secretary",
                                       "result_count": len(results), "results": [r["product_id"] for r in results]},
                       actor=f"human:{viewer.username} (via AI secretary)", refs=[search_id])
    with _memory_lock:
        _last_search[viewer.username] = {"t": time.monotonic(), "query": query, "availability_for": delivery,
                                         "results": results}
    actions_out.append({"type": "catalog", "query": query, "availability_for": delivery, "results": results})
    semantic = state.adapter.health().get("semantic_search")
    return {"ok": True, "query": query, "availability_checked_for": delivery, "count": len(results),
            "catalog_size": len(state.adapter.catalog),
            "search_mode": "semantic (FAISS) + keyword" if semantic else "keyword (semantic model off on this server)",
            "results": results, **({} if results else {"note": "Nothing matched: try a broader or different term."})}


def _place_order_tool(viewer: Viewer, question: str, args: dict[str, Any],
                      actions_out: list[dict[str, Any]]) -> dict[str, Any]:
    """place_order: exact product id from search_catalog -> dry run -> (manager confirms) -> real pipeline."""
    if viewer.role != "manager":
        return {"ok": False, "error": "This user is an auditor (read-only) and cannot place orders."}
    pid = str(args.get("product_id", "") or "").strip()
    p = state.adapter.catalog.get(pid)
    if p is None:
        return {"ok": False, "error": f"Unknown product_id {pid!r}. Call search_catalog and use an exact product_id from its results."}
    try:
        req = EventRequest(product_name=p.display_name[:120].ljust(2), product_id=pid,
                           quantity=float(args.get("quantity") or 0), unit=str(args.get("unit") or "units"),
                           delivery_date=str(args.get("delivery_date") or _next_business_day().isoformat()),
                           dry_run=True)
    except Exception as exc:   # pydantic validation: tell the model exactly what is wrong
        return {"ok": False, "error": f"Invalid order request: {exc}"}
    return _propose_order(viewer, question, req, actions_out, kind="chat_order", reason_prefix="Ordered via the AI secretary")


# kind -> audit action written when the order is actually placed
_ORDER_KINDS = {"event_order": Action.LAST_MINUTE_EVENT_ORDER, "chat_order": Action.ORDERED_BY_AI_SECRETARY}


def _propose_order(viewer: Viewer, question: str, req: EventRequest, actions_out: list[dict[str, Any]], *,
                   kind: str, reason_prefix: str) -> dict[str, Any]:
    """Shared by order_for_last_minute_event and place_order: dry run, then confirm (default) or place."""
    agent = _ordering_agent(None)
    loop = state.hub.loop
    try:   # we're in a worker thread (Gemini call); run the async core on the server loop
        preview = asyncio.run_coroutine_threadsafe(
            _event_order(agent, req, f"agent:{agent.agent_id} (for {viewer.username})", source="chat"), loop).result(60)
    except HTTPException as exc:
        d = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
        out = {"ok": False, "error": d.get("detail") or d.get("error"), "reason_code": d.get("error")}
        if exc.status_code in (404, 409):   # unavailable: give the model real choices, never a promise
            out.update({"unavailable": True,
                        **({"earliest_delivery": d["earliest_delivery"]} if d.get("earliest_delivery") else {}),
                        "available_alternatives": d.get("alternatives") or [],
                        "next_step": ("Tell the manager it's unavailable, mention the earliest delivery date and/or the "
                                      "available alternatives above (only these), and ask whether they'd like to contact "
                                      "Valio Aimo Sales Service or choose an available alternative.")})
        return out
    summary = {"order_id": preview["product_id"], "net_total_eur": preview["estimated_total"],
               "contents": f"{preview['sales_qty']:g} {preview['sales_unit']} {preview['product']}"
                           + (f" (= {preview['covered']:g} {req.unit})" if req.unit != "units" else ""),
               "why_it_needs_a_human": preview["preview"]["explanation"]}
    action = {"action_id": _new_id("act"), "kind": kind, "decision": "order", "order_id": preview["product_id"],
              "reason": f"{reason_prefix}, delivery {preview['delivery_date']}", "username": viewer.username,
              "question": question, "model": None, "summary": summary,
              "event": req.model_dump(mode="json") | {"dry_run": False}, "expires": time.monotonic() + _ACTION_TTL_SECONDS}
    result_for_model = {"product": preview["product"], "order": summary["contents"], "estimated_total_eur": preview["estimated_total"],
                        "delivery_date": preview["delivery_date"], "guardrail_preview": preview["preview"]["status"],
                        "guardrail_explanation": preview["preview"]["explanation"]}
    if _TOOLS_REQUIRE_CONFIRMATION:
        with _pending_lock:
            for k in [k for k, v in _pending_actions.items() if v["username"] == viewer.username]:
                _pending_actions.pop(k, None)
            _pending_actions[action["action_id"]] = action
        actions_out.append({"type": "pending", **{k: action[k] for k in ("action_id", "decision", "order_id", "reason", "summary")},
                            "kind": kind})
        return {"ok": True, "status": "awaiting_manager_confirmation", **result_for_model,
                "instruction": "Not ordered yet. Tell the manager which product you found, the amount in its packs, the "
                               "estimated total and the guardrail preview, and ask them to say 'yes' or tap Confirm. "
                               "If the total is slightly over the agent's limit, mention that the agent may negotiate a "
                               "bulk deal (+20% volume at 10% off) when placing it."}
    out = asyncio.run_coroutine_threadsafe(_event_order(agent, EventRequest(**action["event"]),
                                                        f"agent:{agent.agent_id} (for {viewer.username})", source="chat",
                                                        audit_action=_ORDER_KINDS[kind]),
                                           loop).result(90)
    actions_out.append({"type": "executed", "decision": "order", "order_id": out["order_id"], "ok": out["ok"], "message": out["message"]})
    return {"ok": out["ok"], "status": "done", "message": out["message"], "order_status": out["status"]}


def _inventory_for_model(report: dict[str, Any]) -> dict[str, Any]:
    """Compact inventory report for Gemini (and the chat's inventory card)."""
    return {
        "status": report["status"], "low_items": report["low_items"], "delivery_date": report.get("delivery_date"),
        "items": [{k: r.get(k) for k in ("product_id", "label", "sales_unit", "on_hand", "par_level", "target_level",
                                         "days_of_cover", "status", "incoming", "awaiting_approval", "suggested_qty",
                                         "capped_by", "unit_price_eur", "estimated_cost_eur", "availability")}
                  | {"weekly_limit": r["limits"]["weekly_limit"], "weekly_remaining": r["limits"]["weekly_remaining"],
                     "monthly_limit": r["limits"]["monthly_limit"], "monthly_remaining": r["limits"]["monthly_remaining"]}
                  for r in report["items"]],
        "estimated_restock_total_eur": report.get("estimated_restock_total_eur"),
        "budget": report["budget"], "stock_model": report["stock_model"],
    }


def _inventory_tool(viewer: Viewer, actions_out: list[dict[str, Any]]) -> dict[str, Any]:
    """check_inventory_levels: read-only. The dashboard shows the result as an inventory card."""
    report = asyncio.run_coroutine_threadsafe(_inventory_report(_ordering_agent(None)), state.hub.loop).result(45)
    compact = _inventory_for_model(report)
    actions_out.append({"type": "inventory", "report": compact, "can_restock": viewer.role == "manager"})
    hint = ("Summarise: which items are below par (stock vs par, days of cover), what you'd order (suggested_qty, "
            "estimated cost) and any cap (capped_by: weekly_limit / monthly_limit / weekly_budget / monthly_budget). "
            + ("If something should be ordered, propose it: ask whether to restock now (they can say yes, or tap "
               "'Restock now' on the card); on yes call restock_inventory." if viewer.role == "manager"
               else "This user is an auditor (read-only): don't offer to order."))
    return {"ok": True, **compact, "instruction": hint}


def _restock_tool(viewer: Viewer, question: str, actions_out: list[dict[str, Any]]) -> dict[str, Any]:
    """restock_inventory: plan the restock (dry run), then a pending action the manager confirms."""
    if viewer.role != "manager":
        return {"ok": False, "error": "This user is an auditor (read-only) and cannot order."}
    agent = _ordering_agent(None)
    actor = f"agent:{agent.agent_id} (for {viewer.username}, chat restock)"
    plan = asyncio.run_coroutine_threadsafe(_restock_inventory(agent, actor, source="chat", dry_run=True),
                                            state.hub.loop).result(60)
    planned = [x for x in plan["results"] if x["status"] == "PLANNED"]
    if not planned:
        return {"ok": True, "status": "nothing_to_order", "message": plan["message"]}
    if not _TOOLS_REQUIRE_CONFIRMATION:
        out = asyncio.run_coroutine_threadsafe(_restock_inventory(agent, actor, source="chat"), state.hub.loop).result(120)
        actions_out.append({"type": "executed", "decision": "order", "order_id": "inventory", "ok": out["ok"], "message": out["message"]})
        return {"ok": out["ok"], "status": "done", "message": out["message"]}
    summary = {"order_id": "standing order", "net_total_eur": plan["estimated_total_eur"],
               "contents": "; ".join(f"{x['quantity']:g} {x['sales_unit']} {x['label']}" for x in planned),
               "why_it_needs_a_human": "Restock of the hotel's standing-order items below par, within the weekly / "
                                       "monthly limits and budget. Each line still goes through the guardrails."}
    action = {"action_id": _new_id("act"), "kind": "inventory_restock", "decision": "order", "order_id": "standing order",
              "reason": f"Auto-restock, delivery {plan['delivery_date']}", "username": viewer.username,
              "question": question, "model": None, "summary": summary,
              "product_ids": [x["substituted"]["instead_of"] if x.get("substituted") else x["product_id"] for x in planned],
              "expires": time.monotonic() + _ACTION_TTL_SECONDS}
    with _pending_lock:
        for k in [k for k, v in _pending_actions.items() if v["username"] == viewer.username]:
            _pending_actions.pop(k, None)
        _pending_actions[action["action_id"]] = action
    actions_out.append({"type": "pending", **{k: action[k] for k in ("action_id", "decision", "order_id", "reason", "summary")},
                        "kind": "inventory_restock"})
    return {"ok": True, "status": "awaiting_manager_confirmation", "plan": planned,
            "estimated_total_eur": plan["estimated_total_eur"], "delivery_date": plan["delivery_date"],
            "instruction": "Not ordered yet. Tell the manager what will be restocked (items, packs, estimated total) and "
                           "ask them to say 'yes' or tap Confirm."}


def _make_tool_executor(viewer: Viewer, question: str, actions_out: list[dict[str, Any]]):
    """Executor handed to explainer: validates every tool call against the database before anything runs."""
    ordered: list[str] = []

    def execute(name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "focus_ui_element":
            return _focus_ui(args, actions_out)
        if name == "search_catalog":
            return _catalog_tool(viewer, args, actions_out)
        if name == "get_contact_info":
            return _contact_tool(args, actions_out, allowed=_contact_chosen(viewer.username, question))
        if name == "check_inventory_levels":
            return _inventory_tool(viewer, actions_out)
        if name == "restock_inventory":
            if ordered:
                return {"ok": False, "error": "Only one order per request."}
            ordered.append(name)
            return _restock_tool(viewer, question, actions_out)
        if name in ("place_order", "order_for_last_minute_event"):
            if ordered:          # one order per request: a confused model can't fan out into many orders
                return {"ok": False, "error": "Only one order per request. Tell the manager what you prepared; "
                                              "they can ask for another order afterwards."}
            ordered.append(name)
            return (_place_order_tool if name == "place_order" else _event_tool)(viewer, question, args, actions_out)
        decision = {"approve_order": "approve", "reject_order": "reject"}.get(name)
        if decision is None:
            return {"ok": False, "error": f"Unknown tool {name}"}
        if viewer.role != "manager":
            return {"ok": False, "error": "This user is an auditor (read-only) and cannot approve or reject."}
        order_id = str(args.get("order_id", "")).strip()
        reason = str(args.get("reason", "")).strip()[:300]
        order = state.db.get_order(order_id) if order_id else None
        if order is None:
            return {"ok": False, "error": f"No order with id {order_id!r}. Use an exact order_id from pending_approvals."}
        if order["status"] != Status.PENDING_APPROVAL.value:
            return {"ok": False, "error": f"Order {order_id} is {order['status']}; only PENDING_APPROVAL orders can be decided."}
        if decision == "reject" and len(reason) < 3:
            return {"ok": False, "error": "A rejection needs the manager's reason. Ask the manager why."}
        action = {"action_id": _new_id("act"), "decision": decision, "order_id": order_id,
                  "reason": reason or "approved on the manager's request", "username": viewer.username,
                  "question": question, "model": None, "summary": _order_brief(order),
                  "expires": time.monotonic() + _ACTION_TTL_SECONDS}
        if _TOOLS_REQUIRE_CONFIRMATION:
            with _pending_lock:
                # one open proposal per manager: a new one replaces the old
                for k in [k for k, v in _pending_actions.items() if v["username"] == viewer.username]:
                    _pending_actions.pop(k, None)
                _pending_actions[action["action_id"]] = action
            actions_out.append({"type": "pending", **{k: action[k] for k in ("action_id", "decision", "order_id",
                                                                            "reason", "summary")}})
            state.audit.record(Action.SYSTEM, {"summary": f"AI secretary proposed to {decision} {order_id}",
                                               "action_id": action["action_id"], "reason": reason,
                                               "manager_request": question}, actor=f"human:{viewer.username}",
                               refs=[order_id])
            return {"ok": True, "status": "awaiting_manager_confirmation", "order": action["summary"],
                    "instruction": "Not done yet. Tell the manager exactly what you will do and ask them to say "
                                   "'yes' or tap Confirm."}
        result = _execute_decision(action, confirmed=False)
        actions_out.append({"type": "executed", "decision": decision, "order_id": order_id, **result})
        return result
    return execute



def _recent_orders_brief(limit: int = 8) -> list[dict[str, Any]]:
    """Newest decided/pending orders, newest first: lets the AI find 'the last approval' etc."""
    out = []
    for o in state.db.list_orders(limit=limit):
        appr = o.get("approval") or {}
        out.append({"order_id": o["order_id"], "status": o["status"], "decided_by": o.get("decided_by"),
                    "submitted": o["created_at"], "agent_id": o["agent_id"],
                    "net_total_eur": o["decision"]["totals"]["net_total"],
                    "contents": ", ".join(f"{l['quantity']:g} {l['salesUnit']} {l['name']}" for l in o["lines"]),
                    "guardrail_explanation": o["decision"].get("explanation"),
                    "approved_or_rejected_by": appr.get("reviewer"), "via": appr.get("via")})
    return out


def _focus_ui(args: dict[str, Any], actions_out: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate a focus_ui_element call. The dashboard renders it; nothing changes server-side."""
    from .explainer import UI_ELEMENTS

    element = str(args.get("element_type", "")).strip()
    element_id = str(args.get("element_id", "") or "").strip()
    explanation = str(args.get("explanation", "") or "").strip()[:600]
    if element not in UI_ELEMENTS:
        return {"ok": False, "error": f"element_type must be one of {UI_ELEMENTS}"}
    if element_id and (element in ("pending_approvals", "recent_orders", "audit_trail")):
        order = state.db.get_order(element_id)
        if order is None:
            return {"ok": False, "error": f"No order with id {element_id!r}. Use an exact order_id from the dashboard "
                                          "state, or '' to show the whole list."}
        if element == "pending_approvals" and order["status"] != Status.PENDING_APPROVAL.value:
            element = "recent_orders"            # it was decided meanwhile: show it as a recent order instead
    elif element in ("spend_chart", "trust_levels", "order_decisions"):
        element_id = ""                          # whole-chart views have no item id
    # pending_approvals / recent_orders with no id = the whole list
    actions_out.append({"type": "ui_action", "element": element, "id": element_id, "text": explanation})
    return {"ok": True, "status": "shown", "element": element, "id": element_id}


# Safety net for Focus Mode: an unambiguous "show / explain the <chart|list>" request still brings it on
# screen if the model answered in text only. Lists need a "show" verb; "explain" only counts for charts.
_SHOW_VERB = re.compile(r"\b(show|see|display|open|view|bring up|pull up|visuali[sz]e|focus on|let me see|list)\b")
_EXPLAIN_VERB = re.compile(r"\b(explain|walk me through|break down|what does)\b")
_UI_INTENTS: list[tuple[str, bool, re.Pattern[str]]] = [          # (element, is_chart, pattern)
    ("spend_chart", True, re.compile(r"\bspend(ing)?\b|\bspent\b")),
    ("trust_levels", True, re.compile(r"\btrust\b")),
    ("order_decisions", True, re.compile(r"\border decisions?\b|\bdecisions? chart\b|\bdo(ugh)?nut\b|\bpie\b|\bapproval rate\b")),
    ("pending_approvals", False, re.compile(r"\bpending\b|\bneeds? (my )?approval\b|\bawaiting\b|\bwaiting for (my )?approval\b")),
    ("recent_orders", False, re.compile(r"\b(last|latest|recent)\b[\w\s]{0,12}\borders\b")),
    ("audit_trail", False, re.compile(r"\baudit\b")),
]


def _infer_ui_element(question: str) -> Optional[str]:
    q = question.lower()
    show, explain = bool(_SHOW_VERB.search(q)), bool(_EXPLAIN_VERB.search(q))
    hits = [el for el, chart, pat in _UI_INTENTS if pat.search(q) and (show or (explain and chart))]
    return hits[0] if len(hits) == 1 else None    # nothing / ambiguous: leave it to the model


# Short per-manager conversation memory: lets "order 10 of the 500g one" follow "what peanut butter do we
# have?". In-process only (single worker), expires after 30 min, cleared on logout.
_CHAT_MEMORY_TURNS = int(os.getenv("CHAT_MEMORY_TURNS", "6"))
_CHAT_MEMORY_TTL = 30 * 60
_chat_memory: dict[str, deque] = {}
_last_search: dict[str, dict[str, Any]] = {}
_memory_lock = threading.Lock()


def _remember_chat(username: str, question: str, answer: str) -> None:
    with _memory_lock:
        _chat_memory.setdefault(username, deque(maxlen=_CHAT_MEMORY_TURNS)).append((time.monotonic(), question, answer))


def _chat_history(username: str) -> list[dict[str, str]]:
    now = time.monotonic()
    with _memory_lock:
        turns = [t for t in _chat_memory.get(username, ()) if now - t[0] < _CHAT_MEMORY_TTL]
    return [m for _, q, a in turns for m in ({"role": "user", "text": q}, {"role": "model", "text": a})]


def _last_search_context(username: str) -> Optional[dict[str, Any]]:
    with _memory_lock:
        ls = _last_search.get(username)
    if not ls or time.monotonic() - ls["t"] > _CHAT_MEMORY_TTL:
        return None
    return {"query": ls["query"], "availability_for": ls["availability_for"],
            "results": [{k: r[k] for k in ("product_id", "name", "pack", "price_eur_per_sales_unit", "availability")}
                        for r in ls["results"]]}


def _forget_chat(username: str) -> None:
    with _memory_lock:
        _chat_memory.pop(username, None)
        _last_search.pop(username, None)


# ---------------------------------------------------------------------------- verified contacts
# contacts.yaml is the ONLY source of contact details. The model receives them through get_contact_info,
# the dashboard renders them from the tool result (not from model text), and _guard_contacts removes any
# e-mail address or phone number in an answer that isn't verified.
CONTACTS_FILE = Path(os.getenv("CONTACTS_FILE", "contacts.yaml"))
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<![\w-])(?:\+\d{1,3}[\s-]?|0)\d{1,3}(?:[\s-]?\d{2,4}){2,3}(?![\w-])")   # +358 / 0... formats
_CONTACT_ASK_RE = re.compile(r"\b(contact|phone|call|ring|e-?mail|reach|talk to|speak to|get in touch)\b", re.I)


def _load_contacts() -> dict[str, Any]:
    import yaml
    try:
        raw = yaml.safe_load(CONTACTS_FILE.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        logger.warning("%s not found: the assistant has no verified contact details", CONTACTS_FILE)
        return {"default": None, "departments": {}}
    deps = raw.get("departments") or {}
    for key, d in deps.items():
        if not d.get("name") or not (d.get("email") or d.get("phones")):
            raise RuntimeError(f"{CONTACTS_FILE}: department {key!r} needs a name and an email or phone")
    if raw.get("default") and raw["default"] not in deps:
        raise RuntimeError(f"{CONTACTS_FILE}: default {raw['default']!r} is not a department")
    return {"default": raw.get("default"), "departments": deps}


_CONTACTS = _load_contacts()


def _contact_card(key: str) -> dict[str, Any]:
    d = _CONTACTS["departments"][key]
    return {"department": d["name"], "email": d.get("email"),
            "phones": [{"language": ph.get("language"), "number": str(ph["number"])} for ph in d.get("phones") or []]}


def _contact_for(topic: str) -> dict[str, Any]:
    deps, default = _CONTACTS["departments"], _CONTACTS["default"]
    key = next((k for k, d in deps.items() if topic in (d.get("topics") or [])), None)
    if key:
        return {"verified": True, "topic": topic, **_contact_card(key)}
    out: dict[str, Any] = {"verified": False, "topic": topic,
                           "note": f"No verified contact details for '{topic.replace('_', ' ')}' requests are on file."}
    if default:
        out["general_contact"] = {"verified": True, **_contact_card(default)}
        out["note"] += f" {deps[default]['name']} is the general point of contact."
    return out


def _ensure_unavailable_question(answer: str, tool_actions: Optional[list[dict[str, Any]]]) -> str:
    """
    Unavailable requests must end with the choice 'alternative or contact Sales Service'. The prompt asks for
    it; this guarantees it when the model only stated the problem. Uses only real data from the tool result.
    """
    unav = next((a["result"] for a in tool_actions or []
                 if isinstance(a.get("result"), dict) and a["result"].get("unavailable")), None)
    if not unav or "?" in answer or "myyntipalvelu@" in answer:
        return answer
    choice = "choose an available alternative"
    if unav.get("earliest_delivery"):
        try:
            choice = f"choose {date.fromisoformat(str(unav['earliest_delivery'])[:10]).strftime('%A %d %B').replace(' 0', ' ')} instead"
        except ValueError:
            pass
    elif unav.get("available_alternatives"):
        choice = "choose an available alternative such as " + " or ".join(
            x["name"] for x in unav["available_alternatives"][:2])
    return f"{answer.rstrip()}\n\nWould you like to {choice}, or contact Valio Aimo Sales Service?"


_CONTACT_OFFER_RE = re.compile(r"\b(contact|sales service|get in touch|reach out)\b", re.I)
_CHOICE_RE = re.compile(r"^\W*(yes|yeah|yep|sure|ok(ay)?|please|kyllä|joo|ja|the (first|former)|sales service|them)\b", re.I)


def _contact_chosen(username: str, question: str) -> bool:
    """'Ask first', enforced: contact details only once the manager asked for them, or says yes to our offer."""
    if _CONTACT_ASK_RE.search(question):
        return True
    last = next((m["text"] for m in reversed(_chat_history(username)) if m["role"] == "model"), "")
    # a short "yes please" / "the sales service" right after we offered to put them in touch
    return bool(_CONTACT_OFFER_RE.search(last)) and len(question.split()) <= 6 and bool(_CHOICE_RE.search(question))


def _contact_tool(args: dict[str, Any], actions_out: list[dict[str, Any]], *, allowed: bool = True) -> dict[str, Any]:
    if not allowed:
        return {"ok": False, "error": "ASK_FIRST",
                "instruction": "The manager hasn't chosen to contact anyone yet. Don't give contact details: say what "
                               "isn't possible and ask whether they'd like to contact Valio Aimo Sales Service or choose "
                               "an available alternative (name the real alternatives you have)."}
    topic = str(args.get("topic") or "other").strip().lower()
    info = _contact_for(topic)
    card = info if info["verified"] else info.get("general_contact")
    if card and not any(a.get("type") == "contact" for a in actions_out):
        actions_out.append({"type": "contact", "topic": topic, "verified_for_topic": info["verified"],
                            "note": info.get("note"), **{k: card[k] for k in ("department", "email", "phones")}})
    return {"ok": True, **info}


def _verified_contact_strings() -> tuple[set[str], set[str]]:
    emails, phones = set(), set()
    for d in _CONTACTS["departments"].values():
        if d.get("email"):
            emails.add(d["email"].lower())
        phones |= {re.sub(r"\D", "", str(ph["number"])) for ph in d.get("phones") or []}
    return emails, phones


def _guard_contacts(answer: str, question: str, actions: list[dict[str, Any]]) -> str:
    """Remove unverified e-mails / phone numbers from a model answer; make sure verified ones are shown."""
    emails, phones = _verified_contact_strings()
    removed = False

    def scrub_email(m: re.Match) -> str:
        nonlocal removed
        if m.group(0).lower() in emails:
            return m.group(0)
        removed = True
        return "(see the verified contact details below)"

    def scrub_phone(m: re.Match) -> str:
        nonlocal removed
        if re.sub(r"\D", "", m.group(0)) in phones:
            return m.group(0)
        removed = True
        return "(see the verified contact details below)"

    answer = _PHONE_RE.sub(scrub_phone, _EMAIL_RE.sub(scrub_email, answer))
    if removed:
        logger.warning("removed unverified contact details from a chat answer")
    asked_any = bool(_CONTACT_ASK_RE.search(question))
    asked = asked_any and bool(re.search(
        r"\b(sales|service|someone|somebody|department|valio|support|a person|a human|them)\b", question, re.I))
    quoted = any(e in answer.lower() for e in emails) or any(
        re.sub(r"\D", "", m.group(0)) in phones for m in _PHONE_RE.finditer(answer))
    has_card = any(a.get("type") == "contact" for a in actions)
    if has_card and not (removed or asked_any or quoted):
        # Ask first: in the reply that says "unavailable - contact or alternative?" no details are shown yet
        actions[:] = [a for a in actions if a.get("type") != "contact"]
    elif (removed or asked or quoted) and not has_card:
        _contact_tool({"topic": "orders"}, actions)        # the verified card, from contacts.yaml
    return answer


def _ai_model_from_result(result: dict[str, Any], actions_out: list[dict[str, Any]]) -> None:
    """Stamp the model that proposed each pending action (known only after the call returns)."""
    with _pending_lock:
        for a in actions_out:
            if a.get("type") == "pending" and a["action_id"] in _pending_actions:
                _pending_actions[a["action_id"]]["model"] = result.get("model")


async def _answer(question: str, mode: str, viewer: Viewer, extra: Optional[dict[str, Any]] = None,
                  allow_actions: bool = True) -> dict[str, Any]:
    """Shared by text and voice: dashboard context -> Gemini (+ tools for managers) -> audit -> response."""
    from . import explainer

    context = _dashboard_context()
    # Tell the model plainly when it has no tools, or it may "offer" an approval that can't happen
    context["your_permissions"] = ("can_approve_and_reject" if viewer.role == "manager" and allow_actions
                                   else "explain_only_actions_disabled_here" if viewer.role == "manager" else "read_only")
    actions: list[dict[str, Any]] = []
    # Everyone may be SHOWN things; only managers get approve/reject. Analytics requests get no tools at all.
    tool_names = (["focus_ui_element", "search_catalog", "place_order", "approve_order", "reject_order",
                   "order_for_last_minute_event", "get_contact_info", "check_inventory_levels", "restock_inventory"]
                  if viewer.role == "manager" else ["focus_ui_element", "search_catalog", "get_contact_info",
                                                    "check_inventory_levels"])
    executor = _make_tool_executor(viewer, question, actions) if allow_actions else None
    if allow_actions:
        if ls := _last_search_context(viewer.username):
            context["last_catalog_search"] = ls
    history = _chat_history(viewer.username) if allow_actions else []
    result = await _ask_gemini(explainer.explain_decision_ex, question, context, mode, executor, tool_names, history)
    result["answer"] = _ensure_unavailable_question(_guard_contacts(result["answer"], question, actions),
                                                    result.get("actions"))
    if allow_actions:
        _remember_chat(viewer.username, question, result["answer"])
    _ai_model_from_result(result, actions)
    state.audit.record(Action.SYSTEM, {"summary": f"{mode} chat answered via {result['model']}",
                                       "question": question, "mode": mode, "model": result["model"],
                                       "tool_calls": [a.get("tool") for a in result.get("actions", [])],
                                       **(extra or {}), **_context_meta(context)}, actor=f"human:{viewer.username}")
    ui = next((a for a in actions if a.get("type") == "ui_action"), None)
    if ui is None and executor is not None and not any(a.get("type") == "pending" for a in actions):
        inferred = _infer_ui_element(question)
        if inferred:
            ui = {"type": "ui_action", "element": inferred, "id": "", "text": result["answer"], "inferred": True}
            actions.append(ui)
    out = {"answer": result["answer"], "model": result["model"], "mode": mode,
           "fallbacks_tried": result["attempts"], "actions": actions, **_context_meta(context)}
    if ui:   # Spatial UI: tell the dashboard what to spotlight and what to say
        out.update({"type": "ui_action", "element": ui["element"], "id": ui["id"], "text": ui["text"] or result["answer"]})
    else:
        out["type"] = "message"
    return out


@app.post("/v1/chat/explain", tags=["human"])
async def chat_explain(req: ChatRequest, viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    """Typed (or browser-transcribed) question -> answer; managers' requests may propose approve/reject actions."""
    _chat_rate_limit(viewer)
    return await _answer(req.question, req.mode, viewer, allow_actions=req.allow_actions)


class QuickActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["order", "approvals", "charts", "offers", "trust"]


@app.post("/v1/chat/quick-action", tags=["human"])
async def chat_quick_action(req: QuickActionRequest, viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    """
    Quick-action cards on the AI landing page: the assistant OPENS a short conversation, built from live
    data (no LLM call, so it's instant and exact). The opening line is stored in this manager's chat memory,
    so the next answer ("20 packs of milk", "yes") continues the same conversation with Gemini.
    Returns {answer, suggestions: [{label, say}], offer: {element, id} | null}: `offer` is what a plain
    "yes" opens.
    """
    is_mgr = viewer.role == "manager"
    offer, suggestions = None, []
    if req.action == "order":
        if is_mgr:
            answer = "Sure, I can help with that. What product and quantity would you like to order?"
            suggestions = [{"label": "20 packs of lactose-free milk", "say": "Order 20 packs of lactose-free milk"},
                           {"label": "Cheapest peanut butter", "say": "What's the cheapest peanut butter we have?"},
                           {"label": "Big event tomorrow", "say": "I have a big event tomorrow, buy 500 liters of lactose-free milk"}]
        else:
            answer = ("You're signed in as an auditor, so I can't place orders for you, but I can search the catalog. "
                      "What product are you looking for?")
    elif req.action == "approvals":
        pending = state.db.list_orders(status=Status.PENDING_APPROVAL.value, limit=500)
        n = len(pending)
        total = sum(o["decision"]["totals"]["net_total"] for o in pending)
        if n == 0:
            answer = "There are currently no orders pending approval. Everything your agents ordered was decided by the guardrails."
        else:
            oldest = min(pending, key=lambda o: o["created_at"])
            answer = (f"There {'is' if n == 1 else 'are'} currently {n} order{'' if n == 1 else 's'} pending approval"
                      f" (€{total:,.2f} in total). Would you like me to show {'it' if n == 1 else 'them'}?")
            offer = {"element": "pending_approvals", "id": oldest["order_id"] if n == 1 else ""}
            suggestions = [{"label": f"Yes, show {'it' if n == 1 else 'them'}", "say": "yes"},
                           {"label": "Why do they need approval?", "say": "Why do the pending orders need my approval?"}]
    elif req.action == "charts":
        answer = "Happy to. Which chart should I explain: daily spend, order decisions or agent trust levels?"
        suggestions = [{"label": "Daily spend", "say": "Explain the spend chart."},
                       {"label": "Order decisions", "say": "Explain the order decisions chart."},
                       {"label": "Trust levels", "say": "Explain the agent trust levels chart."}]
    elif req.action == "offers":
        open_offers = [o for o in _offer_rows() if o["status"] == "OPEN"]
        if not open_offers:
            answer = "Valio has no open offers right now. Their seller agent pushes a new surplus deal regularly; I'll show it here when it arrives."
        else:
            best = max(open_offers, key=lambda o: o.get("discount_pct") or 0)
            answer = (f"Valio has {len(open_offers)} open offer{'' if len(open_offers) == 1 else 's'} right now. The best is "
                      f"{best['name']} at {best.get('discount_pct', 0):g}% off. Would you like me to open it?")
            offer = {"element": "offer", "id": best["offer_id"]}
            suggestions = [{"label": "Yes, open it", "say": "yes"},
                           {"label": "Is it a good deal?", "say": f"Is the proactive offer for {best['name']} a good deal for us?"}]
    else:   # trust
        answer = "Sure. Should I explain every agent's trust level, or what it takes for the hotel bot to reach the next level?"
        suggestions = [{"label": "All agents", "say": "Explain the agent trust levels chart."},
                       {"label": "Next level", "say": "What does the hotel procurement bot need to reach the next trust level?"}]
    _remember_chat(viewer.username, f"[Quick action: {req.action}]", answer)
    return {"answer": answer, "suggestions": suggestions, "offer": offer}


@app.post("/v1/chat/voice", tags=["human"])
async def chat_voice(audio: UploadFile = File(..., description="Recorded question (webm/ogg/wav/mp3/mp4)"),
                     viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    """
    Spoken question (for browsers without the Web Speech API): Gemini transcribes the audio,
    then the transcript goes through exactly the same path as a typed voice question, tools included.
    """
    from . import explainer

    mime = (audio.content_type or "").split(";")[0].strip().lower()
    if mime not in explainer.AUDIO_MIME_TYPES:
        raise HTTPException(415, detail={"error": "UNSUPPORTED_AUDIO", "detail": f"content type {mime or 'missing'!r}",
                                         "supported": sorted(explainer.AUDIO_MIME_TYPES)})
    data = await audio.read(_VOICE_MAX_BYTES + 1)
    if len(data) > _VOICE_MAX_BYTES:
        raise HTTPException(413, detail={"error": "AUDIO_TOO_LARGE", "detail": f"max {_VOICE_MAX_BYTES // 1024 // 1024} MB"})
    if len(data) < 512:
        raise HTTPException(422, detail={"error": "AUDIO_EMPTY", "detail": "No audio was recorded"})

    _chat_rate_limit(viewer)
    stt = await _ask_gemini(explainer.transcribe_audio, data, mime)   # the recording itself is never stored
    transcript = stt["transcript"]
    if not transcript:
        return {"transcript": "", "answer": "Sorry, I couldn't make that out. Could you say it again?",
                "model": stt["model"], "mode": "voice", "fallbacks_tried": stt["attempts"], "actions": [],
                "context_entries": 0, "context_seq": [], "pending_in_context": 0}
    out = await _answer(transcript, "voice", viewer, extra={"transcribed_by": stt["model"], "audio_bytes": len(data)})
    return {"transcript": transcript, **out}


class ActionDecision(BaseModel):
    confirm: bool


class QuickOrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str = Field(..., min_length=1, max_length=40, examples=["473868"])
    quantity: float = Field(1, gt=0, le=100000, description="In the product's sales units (packs) unless `unit` says L/KG")
    unit: Literal["units", "L", "KG"] = "units"
    delivery_date: Optional[date] = Field(None, description="Default: next business day")


@app.post("/v1/agent/quick-order", tags=["agent"])
async def quick_order(req: QuickOrderRequest, who: dict = Depends(_negotiation_identity)) -> dict[str, Any]:
    """
    One click = one order: the "Order" button on a catalog result in the chat (or an agent with 'order' scope).
    No second confirmation, because the click IS the manager's explicit decision, but nothing is skipped
    either: live price + stock -> signed quote -> guardrails (limits, allergens, drift, trust) -> negotiation ->
    order -> audit -> websockets. The guardrails may still send it for approval or reject it; the response
    says which.
    """
    if who["manager"] is not None:
        if who["manager"].role != "manager":
            raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": "Auditors have read-only access"})
        agent = _ordering_agent(None)
        actor, username = f"agent:{agent.agent_id} (for {who['manager'].username}, quick order)", who["manager"].username
    else:
        agent, actor, username = who["agent"], who["actor"], None
    p = state.adapter.catalog.get(req.product_id)
    if p is None:
        raise HTTPException(404, detail={"error": "UNKNOWN_PRODUCT", "detail": f"No product with id {req.product_id!r}"})
    if username:
        _chat_rate_limit(who["manager"])
    delivery = req.delivery_date or _next_business_day()
    try:
        out = await _event_order(agent, EventRequest(product_name=p.display_name[:120].ljust(2), product_id=p.id,
                                                     quantity=req.quantity, unit=req.unit, delivery_date=delivery),
                                 actor, source="quick_order", audit_action=Action.QUICK_ORDER)
    except HTTPException as exc:      # unavailable: let the dashboard offer alternatives or the verified contact
        if exc.status_code == 409 and isinstance(exc.detail, dict):
            sales = _contact_for("orders")
            raise HTTPException(409, detail={**exc.detail, "unavailable": True,
                                             "contact": sales if sales["verified"] else sales.get("general_contact")})
        raise
    o = out["order"]
    line = o["lines"][0] if o.get("lines") else {}
    result = {"ok": out["ok"], "status": out["status"], "order_id": out["order_id"], "product_id": p.id,
              "product": p.display_name, "quantity": line.get("quantity", out["sales_qty"]), "sales_unit": p.sales_unit,
              "net_total_eur": o["decision"]["totals"]["net_total"], "delivery_date": out["delivery_date"],
              "confirmation_number": (o.get("confirmation") or {}).get("number"),
              "explanation": o["decision"].get("explanation"), "negotiation": out.get("negotiation"),
              "message": out["message"]}
    if username:   # the chat remembers it, so "what did I just order?" works
        _remember_chat(username, f"[Order button] {req.quantity:g} of {p.display_name} ({p.id})", out["message"])
    return result


# =============================================================================
# Hotel inventory & standing orders (src/inventory.py)
# =============================================================================
_restock_lock = asyncio.Lock()      # one restock at a time: a double click can't order twice


async def _inventory_report(agent: Agent, delivery: Optional[date] = None) -> dict[str, Any]:
    """Stock vs par levels, priced with LIVE Valio prices for the next delivery day (budget check included)."""
    delivery = delivery or _next_business_day()
    ids = [i["product_id"] for i in inventory.STANDING_ORDER["items"]]
    prices: dict[str, float] = {}
    avail: dict[str, str] = {}
    try:
        live = await state.adapter.live_snapshot(agent.customer, delivery.isoformat(), ids)
        for pid, snap in live.items():
            price, a = snap.get("price"), snap.get("availability")
            if price and price.unit_price:
                prices[pid] = float(price.unit_price)
            if a:
                avail[pid] = a.status
    except Exception as exc:          # still report stock levels; the budget check is then skipped
        logger.warning("inventory: live prices unavailable (%s)", type(exc).__name__)
    report = inventory.check_inventory_levels(state.db, state.adapter.catalog, agent.customer, prices=prices or None)
    for row in report["items"]:
        row["availability"] = avail.get(row["product_id"])
    report["delivery_date"] = delivery.isoformat()
    report["live_prices"] = bool(prices)
    return report


def _best_substitute(p: Any, alternatives: list[dict[str, Any]], qty: float) -> Optional[dict[str, Any]]:
    """Cheapest in-stock equivalent per litre / kg (same content unit), with the pack count converted."""
    if not (p and p.content_per_sales_unit and p.base_unit_content_uom):
        return None
    best = None
    for a in alternatives:
        q = state.adapter.catalog.get(a["product_id"])
        if not (q and q.content_per_sales_unit and q.base_unit_content_uom == p.base_unit_content_uom):
            continue
        per_base = a["price_eur_per_sales_unit"] / q.content_per_sales_unit
        if best is None or per_base < best["per_base"]:
            packs = math.ceil(qty * p.content_per_sales_unit / q.content_per_sales_unit)
            best = {"product_id": q.id, "name": q.display_name, "qty": packs, "per_base": per_base,
                    "unit_price_eur": a["price_eur_per_sales_unit"], "sales_unit": q.sales_unit}
    return best


async def _restock_inventory(agent: Agent, actor: str, *, source: str, product_ids: Optional[list[str]] = None,
                             dry_run: bool = False) -> dict[str, Any]:
    """
    Order what the inventory check says is needed. Every line goes through the normal pipeline
    (live price + stock -> signed quote -> guardrails -> negotiation -> audit -> websockets), so the
    guardrails may still hold a line for approval or reject it. If a standing-order product is out of stock
    or unpriced, the cheapest in-stock equivalent (per litre / kg) is used instead, and the result says so.
    """
    async with _restock_lock:
        report = await _inventory_report(agent)
        delivery = report["delivery_date"]
        rows = [r for r in report["items"] if r["suggested_qty"] > 0
                and (not product_ids or r["product_id"] in product_ids)]
        results: list[dict[str, Any]] = []
        for r in rows:
            p = state.adapter.catalog.get(r["product_id"])
            pid, qty, price, substituted = r["product_id"], float(r["suggested_qty"]), r["unit_price_eur"], None
            if r.get("availability") != "AVAILABLE" or not price:
                alts = await _available_alternatives(p, delivery, agent, k=5) if p else []
                sub = _best_substitute(p, alts, qty)
                if sub is None:
                    results.append({"product_id": pid, "label": r["label"], "quantity": qty, "status": "SKIPPED",
                                    "message": f"{r['label']} is {(r.get('availability') or 'not priced').replace('_', ' ').lower()} "
                                               f"for {delivery} and no equivalent product is in stock."})
                    continue
                substituted = {"instead_of": pid, "instead_of_label": r["label"]}
                pid, qty, price = sub["product_id"], float(sub["qty"]), sub["unit_price_eur"]
            name = (state.adapter.catalog.get(pid).display_name if state.adapter.catalog.get(pid) else r["label"])
            entry = {"product_id": pid, "label": r["label"], "product": name, "quantity": qty,
                     "sales_unit": r["sales_unit"], "estimated_total_eur": round(qty * price, 2) if price else None,
                     "substituted": substituted}
            if dry_run:
                results.append({**entry, "status": "PLANNED"})
                continue
            try:
                out = await _event_order(agent, EventRequest(product_name=name[:120].ljust(2), product_id=pid, quantity=qty,
                                                             unit="units", delivery_date=date.fromisoformat(delivery)),
                                         actor, source=source, audit_action=Action.INVENTORY_RESTOCK)
            except HTTPException as exc:
                d = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
                results.append({**entry, "status": "FAILED", "message": d.get("detail") or d.get("error")})
                continue
            o = out["order"]
            results.append({**entry, "status": out["status"], "order_id": out["order_id"],
                            "quantity": float(o["lines"][0]["quantity"]) if o.get("lines") else qty,
                            "net_total_eur": o["decision"]["totals"]["net_total"], "message": out["message"]})

        after = report if dry_run else await _inventory_report(agent)
        if not dry_run and results:
            state.hub.publish("inventory", {"status": after["status"], "low_count": after["low_count"]})
        by = {s: [x for x in results if x["status"] == s] for s in ("PLACED", "PENDING_APPROVAL", "REJECTED", "FAILED", "SKIPPED", "PLANNED")}
        if not rows:
            msg = ("Inventory is healthy: nothing needs restocking." if report["status"] == "HEALTHY" else
                   "Some items are low, but they are already on order / awaiting approval, or the weekly / monthly "
                   "limits or budget leave nothing to order.")
        elif dry_run:
            msg = f"Restock plan for delivery {delivery}: " + "; ".join(
                f"{x['quantity']:g} {x['sales_unit']} {x['label']}" + (f" (≈€{x['estimated_total_eur']:,.2f})" if x["estimated_total_eur"] else "")
                for x in by["PLANNED"]) + (f". Not orderable: {'; '.join(x['label'] for x in by['SKIPPED'])}." if by["SKIPPED"] else ".")
        else:
            parts = []
            if by["PLACED"]:
                parts.append(f"placed {len(by['PLACED'])} order(s) (€{sum(x['net_total_eur'] for x in by['PLACED']):,.2f})")
            if by["PENDING_APPROVAL"]:
                parts.append(f"{len(by['PENDING_APPROVAL'])} awaiting your approval")
            for s in ("REJECTED", "FAILED", "SKIPPED"):
                if by[s]:
                    parts.append(f"{len(by[s])} {s.lower()} ({', '.join(x['label'] for x in by[s])})")
            msg = f"Restock for delivery {delivery}: " + ", ".join(parts) + "."
        return {"ok": not dry_run and bool(by["PLACED"] or by["PENDING_APPROVAL"]) or (dry_run and bool(by["PLANNED"])),
                "dry_run": dry_run, "delivery_date": delivery, "message": msg, "results": results,
                "estimated_total_eur": round(sum(x.get("estimated_total_eur") or 0 for x in results), 2),
                "inventory": after}


def _manager_ordering_identity(who: dict[str, Any], what: str) -> tuple[Agent, str]:
    if who["manager"] is not None:
        if who["manager"].role != "manager":
            raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": "Auditors have read-only access"})
        agent = _ordering_agent(None)
        return agent, f"agent:{agent.agent_id} (for {who['manager'].username}, {what})"
    return who["agent"], who["actor"]


@app.get("/v1/inventory", tags=["human"])
async def inventory_status(viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    """The hotel's standing-order items: current stock, par levels, weekly/monthly limits, budget and what's needed."""
    return await _inventory_report(_ordering_agent(None))


class RestockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_ids: Optional[list[str]] = Field(None, description="Only these standing-order items (default: all low items)")
    dry_run: bool = Field(False, description="Plan only: what would be ordered and the estimated cost")


@app.post("/v1/inventory/restock", tags=["human"])
async def inventory_restock(req: Optional[RestockRequest] = None,
                            who: dict = Depends(_negotiation_identity)) -> dict[str, Any]:
    """
    Auto-restock: order the low standing-order items back up to their target level, within the weekly/monthly
    limits and budget, at live prices, through the guardrails. A manager (dashboard) or an agent with 'order' scope.
    """
    req = req or RestockRequest()
    agent, actor = _manager_ordering_identity(who, "auto-restock")
    unknown = [p for p in (req.product_ids or []) if inventory.item(p) is None]
    if unknown:
        raise HTTPException(404, detail={"error": "NOT_IN_STANDING_ORDER", "detail": f"Not standing-order items: {unknown}"})
    return await _restock_inventory(agent, actor, source="restock_button" if who["manager"] else "agent_api",
                                    product_ids=req.product_ids, dry_run=req.dry_run)


class StockCountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str = Field(..., max_length=40)
    on_hand: float = Field(..., ge=0, le=1_000_000, description="Counted stock, in the product's sales units")


@app.post("/v1/inventory/count", tags=["human"])
async def inventory_count(req: StockCountRequest, viewer: Viewer = Depends(require_manager)) -> dict[str, Any]:
    """Record a physical stock count: the new baseline for the stock estimate."""
    it = inventory.item(req.product_id)
    if it is None:
        raise HTTPException(404, detail={"error": "NOT_IN_STANDING_ORDER", "detail": f"{req.product_id} is not a standing-order item"})
    count = inventory.record_count(state.db, req.product_id, req.on_hand, f"human:{viewer.username}")
    p = state.adapter.catalog.get(req.product_id)
    state.audit.record(Action.INVENTORY_COUNT, {**count, "label": it["label"], "sales_unit": p.sales_unit if p else None},
                       actor=f"human:{viewer.username}")
    report = await _inventory_report(_ordering_agent(None))
    state.hub.publish("inventory", {"status": report["status"], "low_count": report["low_count"]})
    return {"ok": True, "count": count, "inventory": report}


@app.post("/v1/chat/actions/{action_id}", tags=["human"])
async def confirm_ai_action(action_id: str, req: ActionDecision,
                            viewer: Viewer = Depends(require_manager)) -> dict[str, Any]:
    """The manager confirms (or cancels) an approve/reject the AI secretary proposed."""
    with _pending_lock:
        action = _pending_actions.get(action_id)
        if action is None or action["username"] != viewer.username:
            raise HTTPException(404, detail={"error": "ACTION_NOT_FOUND", "detail": "No such proposal (or not yours)"})
        _pending_actions.pop(action_id, None)
    if time.monotonic() > action["expires"]:
        raise HTTPException(410, detail={"error": "ACTION_EXPIRED", "detail": "The proposal expired; ask again"})
    if not req.confirm:
        state.audit.record(Action.SYSTEM, {"summary": f"manager cancelled AI secretary proposal to {action['decision']} "
                                                      f"{action['order_id']}", "action_id": action_id},
                           actor=f"human:{viewer.username}", refs=[action["order_id"]])
        return {"ok": True, "status": "cancelled", "order_id": action["order_id"],
                "message": "Okay, I won't restock now." if action.get("kind") == "inventory_restock"
                           else "Okay, I won't place that order." if action.get("kind") in _ORDER_KINDS
                           else f"Okay, I won't {action['decision']} that order."}
    if action.get("kind") == "inventory_restock":
        agent = _ordering_agent(None)
        out = await _restock_inventory(agent, f"agent:{agent.agent_id} (for {viewer.username}, confirmed restock)",
                                       source="chat", product_ids=action.get("product_ids"))
        res = {"ok": out["ok"], "status": "done" if out["ok"] else "failed", "order_id": "standing order",
               "message": out["message"], "restock": out["results"]}
    elif action.get("kind") in _ORDER_KINDS:
        agent = _ordering_agent(None)
        try:
            out = await _event_order(agent, EventRequest(**action["event"]),
                                     f"agent:{agent.agent_id} (for {viewer.username}, confirmed)", source="chat",
                                     audit_action=_ORDER_KINDS[action["kind"]])
        except HTTPException as exc:   # e.g. stock or price changed since the proposal
            d = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
            res = {"ok": False, "status": "failed", "error": d.get("error"),
                   "message": f"I couldn't place that order: {d.get('detail') or d.get('error')}"}
        else:
            res = {"ok": out["ok"], "status": "done" if out["ok"] else "failed", "order_id": out["order_id"],
                   "order_status": out["status"], "message": out["message"]}
    else:
        res = await asyncio.to_thread(_execute_decision, action, confirmed=True)
    _remember_chat(viewer.username, "yes (confirmed)", res.get("message") or "")
    return res


# =============================================================================
# Audit
# =============================================================================

@app.get("/v1/audit/verify", tags=["trust"])
async def audit_verify() -> dict[str, Any]:
    """Chain integrity plus a signed checkpoint of the current head."""
    return {"chain": state.audit.verify().to_dict(), "checkpoint": state.audit.signed_checkpoint()}


# Both must be registered before /v1/audit/{order_id}, or "recent" is read as an order id.
@app.get("/v1/audit", tags=["human"])
@app.get("/v1/audit/recent", tags=["human"], include_in_schema=False)
async def audit_recent(limit: int = Query(50, ge=1, le=500),
                       viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    """Newest-first audit feed with one-line summaries and decision explanations (#9)."""
    entries = state.audit.entries()[-limit:]
    return {"chain": state.audit.verify().to_dict(), "entries": [audit_view(e) for e in reversed(entries)]}


# =============================================================================
# Dashboard (human managers)
# =============================================================================

@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    """Single-page manager dashboard. The page holds no secrets: it asks for the approver key."""
    return templates.TemplateResponse(request, "dashboard.html", {
        "policy_version": state.policy.version, "kid": state.signer.kid,
    })


@app.get("/v1/audit/{order_id}", tags=["trust"], response_class=PlainTextResponse)
async def audit_trail(order_id: str, x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
                      x_approver_key: Optional[str] = Header(None, alias="X-Approver-Key"),
                      authorization: Optional[str] = Header(None)) -> PlainTextResponse:
    order = _get_order(order_id)
    is_human = (bool(x_approver_key) and secrets.compare_digest(x_approver_key, APPROVER_KEY)) or bool(
        (token := _bearer(authorization)) and state.db.get_session(token))
    if not is_human:
        agent = authenticate_agent(x_agent_key)
        if agent.agent_id != order["agent_id"]:
            raise HTTPException(404, detail={"error": "ORDER_NOT_FOUND", "order_id": order_id})
    md = state.audit.export_markdown(order_id, title=f"Audit Trail: Order {order_id}")
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")


# =============================================================================
# Proactive offers (Valio Aimo -> agents)
# =============================================================================

@app.post("/v1/offers/proactive", tags=["valio"], dependencies=[Depends(require_admin)])
@app.post("/v1/proactive-offers", tags=["valio"], dependencies=[Depends(require_admin)], include_in_schema=False)
async def push_offer(offer: ProactiveOffer) -> dict[str, Any]:
    """
    Valio pushes a surplus offer (e.g. near-date stock). The offer is signed so
    an agent can trust the discount. Agents pull from GET /v1/offers; in
    production this would fan out over webhooks.
    """
    p = state.adapter.catalog.get(offer.product_id)
    if p is None:
        raise HTTPException(404, detail={"error": "UNKNOWN_PRODUCT", "productId": offer.product_id})
    envelope = _store_offer(p, offer.discount_pct, offer.quantity_available, offer.valid_until.isoformat(),
                            offer.reason, offer.target_agent_id)
    return {"offer_id": envelope["payload"]["offer_id"], **envelope}


def _store_offer(p, discount_pct: float, quantity_available: float, valid_until: str, reason: str,
                 target_agent_id: Optional[str], extra: Optional[dict[str, Any]] = None,
                 actor: str = "valio:ops") -> dict[str, Any]:
    """Sign, store, audit and broadcast an offer. Everything in the payload (incl. a base price) is signed."""
    offer_id = _new_id("ofr")
    payload = {
        "offer_id": offer_id, "productId": p.id, "name": p.display_name, "salesUnit": p.sales_unit,
        "discount_pct": discount_pct, "quantity_available": quantity_available,
        "valid_until": valid_until, "reason": reason, "target_agent_id": target_agent_id,
        "allergens": sorted(p.allergens_contains), "claims": sorted(p.claims),
        "deliveryReliability": p.delivery_reliability, "carbonKgCo2ePerKg": p.carbon_kg_co2e_per_kg,
        "how_to_accept": "POST /v1/agent/negotiate with this offer_id (accept + bulk counter-offer).",
        **(extra or {}),
    }
    envelope = state.signer.seal(payload, kind="proactive_offer")
    state.db.save_offer(offer_id, p.id, target_agent_id, envelope, valid_until)
    state.audit.record(Action.OFFER, {**payload, "digest": envelope["digest"]}, actor=actor, refs=[offer_id])
    state.hub.publish("offer", {**payload, "status": "OPEN", "created_at": iso(utcnow())})
    return envelope


# ---- Seller agent: data-driven surplus offers -------------------------------------------------
_SELLER_MIN_INTERVAL_S = float(os.getenv("SELLER_AGENT_MIN_INTERVAL_S", "60"))
_seller_last_run = {"at": 0.0}
_seller_lock = asyncio.Lock()


async def _run_seller_agent(actor: str) -> dict[str, Any]:
    """Valio's seller agent picks a real perishable, prices it live, and pushes a signed surplus offer."""
    from .seller_agent import SellerAgentError, generate_proactive_offer

    customer = next(iter(AGENT_KEYS.values()))[1] if AGENT_KEYS else DEFAULT_CUSTOMER
    try:
        gen = await generate_proactive_offer(state.adapter, customer)
    except SellerAgentError as exc:
        raise HTTPException(503, detail={"error": "NO_SURPLUS_TO_OFFER", "detail": str(exc)})
    p = state.adapter.catalog.require(gen["product_id"])
    envelope = _store_offer(p, gen["discount_percent"], gen["quantity_available"], gen["valid_until"], gen["reason"],
                            None, extra={k: gen[k] for k in ("base_price", "discount_percent", "offer_price", "stock_status",
                                                             "currency", "supplier", "priced_at", "simulated")},
                            actor="valio:seller_agent")
    state.audit.record(Action.SYSTEM, {
        "summary": "Valio Aimo Seller Agent detected upstream surplus and pushed a proactive B2B offer to the buyer.",
        "offer_id": envelope["payload"]["offer_id"], "product_id": gen["product_id"], "name": gen["name"],
        "base_price": gen["base_price"], "discount_percent": gen["discount_percent"], "offer_price": gen["offer_price"],
        "quantity_available": gen["quantity_available"], "supplier": gen["supplier"],
        "candidates_checked": gen["candidates_checked"], "triggered_by": actor}, actor="valio:seller_agent",
        refs=[envelope["payload"]["offer_id"]])
    _seller_last_run["at"] = asyncio.get_running_loop().time()
    return {**gen, "offer_id": envelope["payload"]["offer_id"], "envelope": envelope}


def _viewer_or_agent(x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
                     authorization: Optional[str] = Header(None),
                     x_approver_key: Optional[str] = Header(None, alias="X-Approver-Key")) -> str:
    if x_agent_key:
        return f"agent:{authenticate_agent(x_agent_key).agent_id}"
    return f"human:{require_viewer(authorization, x_approver_key).username}"


def _offer_rows(limit: int = 20) -> list[dict[str, Any]]:
    rows = state.db.query("SELECT * FROM offers ORDER BY created_at DESC LIMIT ?", (limit,))
    today = date.today().isoformat()
    return [{**json.loads(r["envelope"])["payload"],
             "status": r["status"] if (r["valid_until"] >= today or r["status"] != "OPEN") else "EXPIRED",
             "created_at": r["created_at"], "accepted_by": r["accepted_by"]} for r in rows]


@app.get("/v1/proactive-offers", tags=["agent"])
async def proactive_offers(who: str = Depends(_viewer_or_agent)) -> dict[str, Any]:
    """
    Current offers (open first, then history). If NO offer is open, Valio's seller agent generates one
    from live data first: at most once per SELLER_AGENT_MIN_INTERVAL_S, so polling can't flood the feed.
    """
    generated = None
    rows = _offer_rows()
    if not any(r["status"] == "OPEN" for r in rows):
        async with _seller_lock:
            rows = _offer_rows()
            fresh = asyncio.get_running_loop().time() - _seller_last_run["at"] >= _SELLER_MIN_INTERVAL_S
            if fresh and not any(r["status"] == "OPEN" for r in rows):
                try:
                    generated = (await _run_seller_agent(who))["offer_id"]
                except HTTPException as exc:          # no surplus right now: still return the history
                    logger.info("Seller agent produced no offer: %s", exc.detail)
                    _seller_last_run["at"] = asyncio.get_running_loop().time()
                rows = _offer_rows()
    rows.sort(key=lambda r: r["status"] != "OPEN")    # open first, stable within groups
    return {"offers": rows, "generated": generated}


@app.post("/v1/proactive-offers/generate", tags=["valio"])
async def generate_offer_now(x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
                             authorization: Optional[str] = Header(None),
                             x_approver_key: Optional[str] = Header(None, alias="X-Approver-Key")) -> dict[str, Any]:
    """Run Valio's seller agent now (Valio admin key, or a dashboard manager for demos)."""
    if x_admin_key and secrets.compare_digest(x_admin_key, ADMIN_KEY):
        actor = "valio:ops"
    else:
        viewer = require_viewer(authorization, x_approver_key)
        if viewer.role != "manager":
            raise HTTPException(403, detail={"error": "FORBIDDEN", "detail": "Auditors have read-only access"})
        actor = f"human:{viewer.username}"
    async with _seller_lock:
        out = await _run_seller_agent(actor)
    out.pop("envelope", None)
    return out


@app.get("/v1/offers", tags=["agent"])
async def list_offers(agent: Agent = Depends(require_scope("search"))) -> dict[str, Any]:
    rows = state.db.open_offers(agent.agent_id, date.today().isoformat())
    return {"count": len(rows), "offers": [r["envelope"] for r in rows]}


@app.get("/v1/dashboard/offers", tags=["human"])
async def dashboard_offers(limit: int = Query(20, ge=1, le=100),
                           viewer: Viewer = Depends(require_viewer)) -> dict[str, Any]:
    rows = state.db.query("SELECT * FROM offers ORDER BY created_at DESC LIMIT ?", (limit,))
    today = date.today().isoformat()
    return {"offers": [{**json.loads(r["envelope"])["payload"], "status": r["status"] if r["valid_until"] >= today
                        else "EXPIRED", "created_at": r["created_at"], "accepted_by": r["accepted_by"]} for r in rows]}


# =============================================================================
# Agent-side helper (exported for SDKs / examples)
# =============================================================================

def verify_quote_locally(envelope: dict[str, Any], jwks: dict[str, Any]) -> bool:
    """What an agent runs: verify a quote with nothing but the published public key."""
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == envelope.get("kid")), None)
    return bool(key) and verify_with_public_key(envelope["payload"], envelope["signature"], key["x"])
