"""
SQLite persistence
==================

Everything that used to live in memory moves here: quotes, orders (+ lines),
human approvals, trusted rules, drift logs, offers, webhook deliveries,
idempotency keys and dashboard users/sessions.

Design:
* stdlib ``sqlite3`` only; one shared connection guarded by an RLock. SQLite
  writes are microseconds at hackathon scale, and a single connection keeps
  ``:memory:`` databases (tests) and WAL file databases behaving the same.
* WAL journal + ``synchronous=NORMAL``: crash-safe and fast.
* JSON documents are stored as TEXT next to indexed scalar columns, so queries
  stay fast while the full order payload round-trips unchanged.
* ``PRAGMA user_version`` gives a minimal migration hook.

The audit log stays in its own append-only JSONL hash chain on purpose: that is
the tamper-evident record, while this database is the operational state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger("gateway.db")

DB_PATH = os.getenv("DB_PATH", "var/gateway.db")
SCHEMA_VERSION = 2   # v2: trusted_rules.substitutions (rule bound to exact substitute->original pairs)

SCHEMA = """
CREATE TABLE IF NOT EXISTS quotes (
    quote_id      TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    customer      TEXT NOT NULL,
    envelope      TEXT NOT NULL,             -- signed quote envelope (JSON)
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    consumed_by   TEXT                       -- order_id once used (anti-replay)
);

CREATE TABLE IF NOT EXISTS orders (
    order_id      TEXT PRIMARY KEY,
    quote_id      TEXT,
    agent_id      TEXT NOT NULL,
    customer      TEXT NOT NULL,
    status        TEXT NOT NULL,             -- PENDING_APPROVAL | PLACED | REJECTED | REJECTED_BY_HUMAN | ...
    decided_by    TEXT,                      -- 'auto' | 'trusted_rule' | 'human' | 'policy'
    net_total     REAL NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    data          TEXT NOT NULL              -- full order document (JSON)
);
CREATE INDEX IF NOT EXISTS ix_orders_status   ON orders(status);
CREATE INDEX IF NOT EXISTS ix_orders_agent    ON orders(agent_id, customer, created_at);

CREATE TABLE IF NOT EXISTS order_lines (
    order_id      TEXT NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
    product_id    TEXT NOT NULL,
    quantity      REAL NOT NULL,
    unit_price    REAL,
    line_value    REAL,
    substitutes_for TEXT,
    PRIMARY KEY (order_id, product_id)
);
CREATE INDEX IF NOT EXISTS ix_lines_product ON order_lines(product_id);

CREATE TABLE IF NOT EXISTS approvals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id      TEXT NOT NULL REFERENCES orders(order_id),
    agent_id      TEXT NOT NULL,
    decision      TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    reviewer      TEXT NOT NULL,
    role          TEXT,
    comment       TEXT,
    decided_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_approvals_agent ON approvals(agent_id);

CREATE TABLE IF NOT EXISTS trusted_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT NOT NULL,
    customer      TEXT NOT NULL,
    product_ids   TEXT NOT NULL,             -- JSON sorted list
    max_quantities TEXT NOT NULL,            -- JSON {product_id: max qty}
    max_net_total REAL NOT NULL,
    waived_codes  TEXT NOT NULL,             -- JSON sorted list of violation codes
    substitutions TEXT NOT NULL DEFAULT '{}', -- JSON {substitute_id: original_id} the human approved
    created_from_order TEXT,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    uses          INTEGER NOT NULL DEFAULT 0,
    last_used_at  TEXT,
    revoked_by    TEXT,
    revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS ix_rules_lookup ON trusted_rules(agent_id, customer, active, expires_at);

CREATE TABLE IF NOT EXISTS drift_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id      TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    customer      TEXT NOT NULL,
    metric        TEXT NOT NULL,             -- 'order_total' | 'line_quantity'
    product_id    TEXT,
    observed      REAL NOT NULL,
    baseline      REAL NOT NULL,
    deviation_pct REAL NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS offers (
    offer_id      TEXT PRIMARY KEY,
    product_id    TEXT NOT NULL,
    target_agent  TEXT,
    status        TEXT NOT NULL DEFAULT 'OPEN',  -- OPEN | ACCEPTED | EXPIRED | WITHDRAWN
    envelope      TEXT NOT NULL,
    valid_until   TEXT NOT NULL,
    accepted_by   TEXT,
    accepted_order_id TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id   TEXT NOT NULL UNIQUE,
    event         TEXT NOT NULL,
    order_id      TEXT,
    url           TEXT NOT NULL,
    status        TEXT NOT NULL,             -- DELIVERED | FAILED
    status_code   INTEGER,
    attempts      INTEGER NOT NULL,
    signature     TEXT NOT NULL,
    payload       TEXT NOT NULL,
    error         TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency (
    agent_id      TEXT NOT NULL,
    key           TEXT NOT NULL,
    order_id      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (agent_id, key)
);

CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    role          TEXT NOT NULL CHECK (role IN ('manager', 'auditor')),
    password_hash TEXT NOT NULL,             -- pbkdf2_sha256$iterations$salt$hash
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash    TEXT PRIMARY KEY,          -- sha256 of the bearer token; raw token never stored
    username      TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);
"""

PBKDF2_ITERATIONS = 240_000


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)


def hash_password(password: str, *, salt: Optional[str] = None, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    candidate = hash_password(password, salt=salt, iterations=int(iterations)).split("$")[3]
    return hmac.compare_digest(candidate, digest)


class Database:
    def __init__(self, path: str | Path = DB_PATH) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, timeout=15, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.executescript(SCHEMA)
            current = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if 0 < current < 2:   # v1 -> v2 migration for existing databases
                cols = {r[1] for r in self._conn.execute("PRAGMA table_info(trusted_rules)")}
                if "substitutions" not in cols:
                    self._conn.execute("ALTER TABLE trusted_rules ADD COLUMN substitutions TEXT NOT NULL DEFAULT '{}'")
                    logger.info("Migrated trusted_rules to schema v2 (substitution pairs)")
            if current < SCHEMA_VERSION:
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        logger.info("SQLite ready at %s (schema v%d)", self.path, SCHEMA_VERSION)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ primitives
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Atomic write transaction."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def query(self, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple | dict = ()) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------ quotes
    def save_quote(self, quote_id: str, agent_id: str, customer: str, envelope: dict, expires_at: Optional[str]) -> None:
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO quotes(quote_id, agent_id, customer, envelope, created_at, expires_at) "
                      "VALUES (?,?,?,?,?,?)", (quote_id, agent_id, customer, _dumps(envelope), iso(utc_now()), expires_at))

    def get_quote(self, quote_id: str) -> Optional[dict[str, Any]]:
        row = self.one("SELECT * FROM quotes WHERE quote_id = ?", (quote_id,))
        if row:
            row["envelope"] = json.loads(row["envelope"])
        return row

    def consume_quote(self, quote_id: str, order_id: str) -> bool:
        """Atomically mark a quote as used. False if it was already consumed (replay)."""
        with self.tx() as c:
            exists = c.execute("SELECT consumed_by FROM quotes WHERE quote_id = ?", (quote_id,)).fetchone()
            if exists is None:  # envelope submitted directly (stateless) -> register it as consumed
                c.execute("INSERT INTO quotes(quote_id, agent_id, customer, envelope, created_at, consumed_by) "
                          "VALUES (?, '', '', '{}', ?, ?)", (quote_id, iso(utc_now()), order_id))
                return True
            cur = c.execute("UPDATE quotes SET consumed_by = ? WHERE quote_id = ? AND consumed_by IS NULL",
                            (order_id, quote_id))
            return cur.rowcount == 1

    # ------------------------------------------------------------------ orders
    def save_order(self, order: dict[str, Any], *, decided_by: Optional[str] = None) -> None:
        now = iso(utc_now())
        net_total = float(((order.get("decision") or {}).get("totals") or {}).get("net_total") or 0)
        with self.tx() as c:
            c.execute(
                """INSERT INTO orders(order_id, quote_id, agent_id, customer, status, decided_by, net_total,
                                      created_at, updated_at, data)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(order_id) DO UPDATE SET status=excluded.status,
                       decided_by=COALESCE(excluded.decided_by, orders.decided_by),
                       net_total=excluded.net_total, updated_at=excluded.updated_at, data=excluded.data""",
                (order["order_id"], order.get("quote_id"), order["agent_id"], order["customer"], order["status"],
                 decided_by, net_total, order.get("created_at", now), now, _dumps(order)))
            c.execute("DELETE FROM order_lines WHERE order_id = ?", (order["order_id"],))
            c.executemany(
                "INSERT INTO order_lines(order_id, product_id, quantity, unit_price, line_value, substitutes_for) "
                "VALUES (?,?,?,?,?,?)",
                [(order["order_id"], l["productId"], float(l["quantity"]), l.get("unitPrice"), l.get("lineValue"),
                  l.get("substitutesFor")) for l in order.get("lines", [])])

    def get_order(self, order_id: str) -> Optional[dict[str, Any]]:
        row = self.one("SELECT data, decided_by FROM orders WHERE order_id = ?", (order_id,))
        if not row:
            return None
        doc = json.loads(row["data"])
        doc["decided_by"] = row["decided_by"]
        return doc

    def list_orders(self, *, status: Optional[str] = None, agent_id: Optional[str] = None,
                    limit: int = 50) -> list[dict[str, Any]]:
        sql, params = "SELECT data, decided_by FROM orders WHERE 1=1", []
        if status:
            sql += " AND status = ?"; params.append(status)
        if agent_id:
            sql += " AND agent_id = ?"; params.append(agent_id)
        sql += " ORDER BY created_at DESC, order_id DESC LIMIT ?"; params.append(limit)
        out = []
        for r in self.query(sql, tuple(params)):
            doc = json.loads(r["data"]); doc["decided_by"] = r["decided_by"]
            out.append(doc)
        return out

    def claim_pending(self, order_id: str, new_status: str) -> bool:
        """Compare-and-set PENDING_APPROVAL -> new_status, so two managers can't both decide."""
        with self.tx() as c:
            cur = c.execute("UPDATE orders SET status = ?, updated_at = ? WHERE order_id = ? AND status = 'PENDING_APPROVAL'",
                            (new_status, iso(utc_now()), order_id))
            return cur.rowcount == 1

    # ------------------------------------------------------------------ history (drift baseline)
    def order_history(self, agent_id: str, customer: str, *, lookback: int = 20,
                      exclude_order: Optional[str] = None) -> dict[str, Any]:
        """Baseline from previously PLACED orders: average total and average quantity per product."""
        orders = self.query(
            "SELECT order_id, net_total FROM orders WHERE agent_id = ? AND customer = ? AND status = 'PLACED' "
            "AND order_id != COALESCE(?, '') ORDER BY created_at DESC LIMIT ?",
            (agent_id, customer, exclude_order, lookback))
        ids = [o["order_id"] for o in orders]
        per_product: dict[str, list[float]] = {}
        if ids:
            marks = ",".join("?" * len(ids))
            for r in self.query(f"SELECT product_id, quantity FROM order_lines WHERE order_id IN ({marks})", tuple(ids)):
                per_product.setdefault(r["product_id"], []).append(r["quantity"])
        return {
            "order_count": len(orders),
            "avg_net_total": (sum(o["net_total"] for o in orders) / len(orders)) if orders else None,
            "product_avg_qty": {p: sum(q) / len(q) for p, q in per_product.items()},
            "product_counts": {p: len(q) for p, q in per_product.items()},
        }

    def log_drift(self, order_id: str, agent_id: str, customer: str, metric: str, observed: float,
                  baseline: float, deviation_pct: float, product_id: Optional[str] = None) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO drift_logs(order_id, agent_id, customer, metric, product_id, observed, baseline, "
                      "deviation_pct, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                      (order_id, agent_id, customer, metric, product_id, observed, baseline, deviation_pct, iso(utc_now())))

    def drift_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM drift_logs ORDER BY id DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------ spend
    def autonomous_spend_since(self, customer: str, since: datetime) -> float:
        """Spend placed WITHOUT a human (auto or trusted rule) since `since`. Feeds the daily cap."""
        row = self.one("SELECT COALESCE(SUM(net_total), 0) AS s FROM orders WHERE customer = ? AND status = 'PLACED' "
                       "AND decided_by IN ('auto', 'trusted_rule') AND created_at >= ?", (customer, iso(since)))
        return round(float(row["s"]), 2) if row else 0.0

    # ------------------------------------------------------------------ approvals & agent trust
    def record_approval(self, order_id: str, agent_id: str, decision: str, reviewer: str,
                        role: Optional[str], comment: Optional[str]) -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO approvals(order_id, agent_id, decision, reviewer, role, comment, decided_at) "
                            "VALUES (?,?,?,?,?,?,?)", (order_id, agent_id, decision, reviewer, role, comment, iso(utc_now())))
            return int(cur.lastrowid)

    def agent_trust_stats(self, agent_id: str) -> dict[str, int]:
        row = self.one(
            """SELECT
                 (SELECT COUNT(*) FROM approvals WHERE agent_id = :a AND decision = 'approve') AS approvals,
                 (SELECT COUNT(*) FROM approvals WHERE agent_id = :a AND decision = 'reject')  AS rejections,
                 (SELECT COUNT(*) FROM orders WHERE agent_id = :a AND status = 'PLACED'
                                               AND decided_by IN ('auto', 'trusted_rule'))  AS autonomous_orders""",
            {"a": agent_id})
        return {k: int(v or 0) for k, v in (row or {}).items()}

    # ------------------------------------------------------------------ trusted rules
    def add_trusted_rule(self, rule: dict[str, Any]) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO trusted_rules(agent_id, customer, product_ids, max_quantities, max_net_total, waived_codes, "
                "substitutions, created_from_order, created_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (rule["agent_id"], rule["customer"], _dumps(sorted(rule["product_ids"])), _dumps(rule["max_quantities"]),
                 rule["max_net_total"], _dumps(sorted(rule["waived_codes"])), _dumps(rule.get("substitutions") or {}),
                 rule.get("created_from_order"), rule["created_by"], iso(utc_now()), rule["expires_at"]))
            return int(cur.lastrowid)

    @staticmethod
    def _rule_row(r: dict[str, Any]) -> dict[str, Any]:
        r["product_ids"] = json.loads(r["product_ids"])
        r["max_quantities"] = json.loads(r["max_quantities"])
        r["waived_codes"] = json.loads(r["waived_codes"])
        r["substitutions"] = json.loads(r.get("substitutions") or "{}")
        r["active"] = bool(r["active"])
        return r

    def active_rules(self, agent_id: str, customer: str, now: Optional[datetime] = None) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM trusted_rules WHERE agent_id = ? AND customer = ? AND active = 1 "
                          "AND expires_at > ? ORDER BY id", (agent_id, customer, iso(now or utc_now())))
        return [self._rule_row(r) for r in rows]

    def list_rules(self, include_inactive: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM trusted_rules" + ("" if include_inactive else " WHERE active = 1") + " ORDER BY id DESC"
        return [self._rule_row(r) for r in self.query(sql)]

    def touch_rule(self, rule_id: int) -> None:
        with self.tx() as c:
            c.execute("UPDATE trusted_rules SET uses = uses + 1, last_used_at = ? WHERE id = ?", (iso(utc_now()), rule_id))

    def revoke_rule(self, rule_id: int, revoked_by: str) -> bool:
        with self.tx() as c:
            cur = c.execute("UPDATE trusted_rules SET active = 0, revoked_by = ?, revoked_at = ? WHERE id = ? AND active = 1",
                            (revoked_by, iso(utc_now()), rule_id))
            return cur.rowcount == 1

    # ------------------------------------------------------------------ offers
    def save_offer(self, offer_id: str, product_id: str, target_agent: Optional[str], envelope: dict,
                   valid_until: str) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO offers(offer_id, product_id, target_agent, envelope, valid_until, created_at) "
                      "VALUES (?,?,?,?,?,?)", (offer_id, product_id, target_agent, _dumps(envelope), valid_until, iso(utc_now())))

    def get_offer(self, offer_id: str) -> Optional[dict[str, Any]]:
        row = self.one("SELECT * FROM offers WHERE offer_id = ?", (offer_id,))
        if row:
            row["envelope"] = json.loads(row["envelope"])
        return row

    def open_offers(self, agent_id: str, today: str) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM offers WHERE status = 'OPEN' AND valid_until >= ? "
                          "AND (target_agent IS NULL OR target_agent = ?) ORDER BY created_at DESC", (today, agent_id))
        for r in rows:
            r["envelope"] = json.loads(r["envelope"])
        return rows

    def accept_offer(self, offer_id: str, agent_id: str, order_id: str) -> bool:
        with self.tx() as c:
            cur = c.execute("UPDATE offers SET status = 'ACCEPTED', accepted_by = ?, accepted_order_id = ? "
                            "WHERE offer_id = ? AND status = 'OPEN'", (agent_id, order_id, offer_id))
            return cur.rowcount == 1

    # ------------------------------------------------------------------ webhooks
    def log_webhook(self, record: dict[str, Any]) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO webhook_deliveries(delivery_id, event, order_id, url, status, status_code, attempts, "
                      "signature, payload, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                      (record["delivery_id"], record["event"], record.get("order_id"), record["url"], record["status"],
                       record.get("status_code"), record["attempts"], record["signature"], record["payload"],
                       record.get("error"), iso(utc_now())))

    def webhook_deliveries(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM webhook_deliveries ORDER BY id DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------ idempotency
    def get_idempotent(self, agent_id: str, key: str) -> Optional[str]:
        row = self.one("SELECT order_id FROM idempotency WHERE agent_id = ? AND key = ?", (agent_id, key))
        return row["order_id"] if row else None

    def put_idempotent(self, agent_id: str, key: str, order_id: str) -> None:
        with self.tx() as c:
            c.execute("INSERT OR IGNORE INTO idempotency(agent_id, key, order_id, created_at) VALUES (?,?,?,?)",
                      (agent_id, key, order_id, iso(utc_now())))

    # ------------------------------------------------------------------ users & sessions (dashboard auth)
    def upsert_user(self, username: str, password: str, role: str) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO users(username, role, password_hash, created_at) VALUES (?,?,?,?) "
                      "ON CONFLICT(username) DO UPDATE SET role=excluded.role, password_hash=excluded.password_hash",
                      (username, role, hash_password(password), iso(utc_now())))

    def ensure_user(self, username: str, password: str, role: str) -> bool:
        """Create the user only if missing (does not reset an existing password). True if created."""
        if self.one("SELECT 1 AS x FROM users WHERE username = ?", (username,)):
            return False
        self.upsert_user(username, password, role)
        return True

    def authenticate(self, username: str, password: str) -> Optional[str]:
        row = self.one("SELECT role, password_hash FROM users WHERE username = ?", (username,))
        if not row:
            check_password(password, hash_password("timing-equaliser"))  # constant-ish time for unknown users
            return None
        return row["role"] if check_password(password, row["password_hash"]) else None

    def create_session(self, username: str, role: str, ttl_hours: int = 12) -> str:
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            c.execute("DELETE FROM sessions WHERE expires_at <= ?", (iso(utc_now()),))
            c.execute("INSERT INTO sessions(token_hash, username, role, created_at, expires_at) VALUES (?,?,?,?,?)",
                      (hashlib.sha256(token.encode()).hexdigest(), username, role, iso(utc_now()),
                       iso(utc_now() + timedelta(hours=ttl_hours))))
        return token

    def get_session(self, token: str) -> Optional[dict[str, Any]]:
        return self.one("SELECT username, role, expires_at FROM sessions WHERE token_hash = ? AND expires_at > ?",
                        (hashlib.sha256(token.encode()).hexdigest(), iso(utc_now())))

    def delete_session(self, token: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))

    # ------------------------------------------------------------------ metrics (dashboard charts)
    def metrics(self) -> dict[str, Any]:
        by_decider = self.query(
            "SELECT COALESCE(decided_by, 'pending') AS decided_by, COUNT(*) AS n, ROUND(COALESCE(SUM(net_total),0), 2) AS value "
            "FROM orders WHERE status = 'PLACED' GROUP BY decided_by")
        by_status = self.query("SELECT status, COUNT(*) AS n FROM orders GROUP BY status")
        daily = self.query(
            "SELECT substr(created_at, 1, 10) AS day, ROUND(SUM(net_total), 2) AS spend, COUNT(*) AS orders "
            "FROM orders WHERE status = 'PLACED' GROUP BY day ORDER BY day DESC LIMIT 30")
        total = self.one("SELECT ROUND(COALESCE(SUM(net_total),0), 2) AS s FROM orders WHERE status = 'PLACED'")
        neg_rows = self.query(
            "SELECT order_id, status, created_at, json_extract(data, '$.negotiation') AS n FROM orders "
            "WHERE json_extract(data, '$.negotiation.status') IS NOT NULL ORDER BY created_at DESC")
        negs = [{**r, "n": json.loads(r["n"])} for r in neg_rows]
        won = [r for r in negs if r["n"]["status"] == "NEGOTIATION_WON"]
        return {
            "total_spend": total["s"] if total else 0.0,
            "placed_by_decider": by_decider,
            "orders_by_status": {r["status"]: r["n"] for r in by_status},
            "daily_spend": list(reversed(daily)),
            "drift_events": self.one("SELECT COUNT(*) AS n FROM drift_logs")["n"],
            # Orders where the guardrails caught a likely error: rejected by policy, or flagged for drift.
            # UNION counts each order once (a rejected order with drift is one prevented error, not two).
            "errors_prevented": {
                "rejected_by_policy": self.one("SELECT COUNT(*) AS n FROM orders WHERE status = 'REJECTED'")["n"],
                "drift_flagged": self.one("SELECT COUNT(DISTINCT order_id) AS n FROM drift_logs")["n"],
                "orders": self.one("SELECT COUNT(*) AS n FROM (SELECT order_id FROM orders WHERE status = 'REJECTED' "
                                   "UNION SELECT order_id FROM drift_logs)")["n"],
            },
            "active_trusted_rules": self.one("SELECT COUNT(*) AS n FROM trusted_rules WHERE active = 1")["n"],
            "webhooks": {r["status"]: r["n"] for r in self.query(
                "SELECT status, COUNT(*) AS n FROM webhook_deliveries GROUP BY status")},
            # Savings only count once the negotiated order is actually PLACED (a manager approved it)
            "negotiation": {
                "simulated": True,
                "won": len(won), "lost": len(negs) - len(won),
                # every NEGOTIATION_WON, except deals a manager later rejected (those savings never happened)
                "saved_total_eur": round(sum(r["n"]["saved_amount"] for r in won if r["status"] != "REJECTED_BY_HUMAN"), 2),
                "saved_placed_eur": round(sum(r["n"]["saved_amount"] for r in won if r["status"] == "PLACED"), 2),
                "saved_pending_eur": round(sum(r["n"]["saved_amount"] for r in won if r["status"] == "PENDING_APPROVAL"), 2),
                "extra_spend_vs_original_eur": round(sum(r["n"].get("spend_change_vs_original", 0) for r in won
                                                         if r["status"] == "PLACED"), 2),
                "recent": [{"order_id": r["order_id"], "order_status": r["status"], "at": r["created_at"],
                            **{k: r["n"].get(k) for k in ("status", "product", "sales_unit", "original_qty",
                                                          "original_total", "new_qty", "new_total", "saved_amount",
                                                          "spend_change_vs_original", "reason")}} for r in negs[:5]],
            },
        }
