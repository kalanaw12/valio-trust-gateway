"""
Hash-Chained Immutable Audit Trail
==================================

Append-only JSONL file where each entry commits to the one before it:

    current_hash = SHA-256( canonical_json(entry without current_hash) + previous_hash )

Changing, deleting or reordering any past line breaks every hash after it, and
``verify()`` reports the first broken sequence number. The chain head can be
signed with the Gateway's Ed25519 key (``signed_checkpoint``), which lets an
outside party pin the state of the log at a point in time. If someone rewrites
the whole file and recomputes all the hashes, it no longer matches a checkpoint
they hold.

Entries carry ``refs`` (order ids, quote ids, ...), so the full story of one
order can be pulled out and rendered as Markdown for a human reviewer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

from .trust import TrustSigner, canonical_json, iso, utcnow

logger = logging.getLogger("gateway.audit")

AUDIT_FILE = Path(os.getenv("AUDIT_FILE", "audit_log.jsonl"))
GENESIS_HASH = "0" * 64


class Action:
    SEARCH = "SEARCH"
    QUOTE = "QUOTE"
    SUBSTITUTION = "SUBSTITUTION"
    ORDER_SUBMITTED = "ORDER_SUBMITTED"
    POLICY_DECISION = "POLICY_DECISION"
    ORDER_PLACED = "ORDER_PLACED"
    APPROVAL = "APPROVAL"
    REJECTION = "REJECTION"
    APPROVED_BY_AI_SECRETARY = "APPROVED_BY_AI_SECRETARY"   # Gemini tool call, confirmed by a manager
    REJECTED_BY_AI_SECRETARY = "REJECTED_BY_AI_SECRETARY"
    NEGOTIATION_WON = "NEGOTIATION_WON"     # simulated counter-party accepted the agent's bulk counter-offer
    NEGOTIATION_LOST = "NEGOTIATION_LOST"
    LAST_MINUTE_EVENT_ORDER = "LAST_MINUTE_EVENT_ORDER"   # "big event tomorrow, buy 500 L of ..." (chat or API)
    ORDERED_BY_AI_SECRETARY = "ORDERED_BY_AI_SECRETARY"   # catalog search -> place_order from the chat, confirmed
    QUICK_ORDER = "QUICK_ORDER"             # one-click "Order" button on a catalog result (manager, dashboard)
    INVENTORY_RESTOCK = "INVENTORY_RESTOCK"  # standing-order restock of a low inventory item (button / chat / API)
    INVENTORY_COUNT = "INVENTORY_COUNT"      # a physical stock count recorded by a manager
    OFFER = "OFFER"
    TRUST_RULE = "TRUST_RULE"
    TRUST_LEVEL = "TRUST_LEVEL"
    WEBHOOK = "WEBHOOK"
    SYSTEM = "SYSTEM"


# Secrets that must never land in the log, whatever a caller passes in
_REDACT_KEYS = {"api_key", "apikey", "x-api-key", "authorization", "password", "secret", "token", "private_key"}


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if str(k).lower() in _REDACT_KEYS else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_redact(v) for v in obj]
    return obj


@contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    """
    Blocking exclusive lock across processes (Windows + POSIX), held on a SIDECAR
    file so the log itself can be renamed while locked (Windows refuses to rename
    a file that is open).
    """
    with open(lock_path, "a+b") as lf:
        if sys.platform == "win32":
            import msvcrt
            lf.seek(0)
            while True:   # LK_LOCK gives up after ~10 s; keep waiting rather than fail an audit write
                try:
                    msvcrt.locking(lf.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                yield
            finally:
                lf.seek(0)
                msvcrt.locking(lf.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def _read_last_entry(fh) -> tuple[str, Optional[dict[str, Any]]]:
    """
    Last complete JSONL line, read backwards (entries can be tens of KB).
    Returns ("empty", None) | ("ok", entry) | ("corrupt", None).
    """
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    block = 8192
    while size:
        start = max(0, size - block)
        fh.seek(start)
        chunk = fh.read(size - start)
        lines = [l for l in chunk.split(b"\n") if l.strip()]
        # The last line is known to be whole if we read from the file start, or if
        # at least one newline precedes it inside the chunk (>= 2 pieces).
        if lines and (start == 0 or len(lines) > 1):
            try:
                return "ok", json.loads(lines[-1])
            except ValueError:
                return "corrupt", None   # torn tail: verify() will report it
        if start == 0:
            break
        block *= 4
    return "empty", None


def compute_hash(entry_without_hash: dict[str, Any], previous_hash: str) -> str:
    return hashlib.sha256(canonical_json(entry_without_hash) + previous_hash.encode("ascii")).hexdigest()


@dataclass(slots=True)
class ChainStatus:
    valid: bool
    entries: int
    head_hash: str
    broken_at: Optional[int] = None
    reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "entries": self.entries, "head_hash": self.head_hash,
                "broken_at_seq": self.broken_at, "reason": self.reason}


class AuditLog:
    def __init__(self, path: Path | str = AUDIT_FILE, signer: Optional[TrustSigner] = None) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.signer = signer
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        status = self.verify()
        if not status.valid:
            # Keep serving, but loudly: appending continues from the last line so
            # new entries remain internally chained, and the break stays visible.
            logger.error("AUDIT CHAIN INTEGRITY FAILURE at seq %s: %s", status.broken_at, status.reason)
        self._integrity_at_boot = status
        # Called with each new entry after it is durably written (e.g. live WebSocket push)
        self.listeners: list[Callable[[dict[str, Any]], None]] = []
        last = self._last_entry()
        self._seq = (last["seq"] + 1) if last else 0
        self._head = last["current_hash"] if last else GENESIS_HASH

    # ---- write ------------------------------------------------------------
    def record(self, action: str, data: dict[str, Any], *, actor: str = "system",
               refs: Iterable[str] = ()) -> dict[str, Any]:
        """
        Append one entry. Safe across threads AND processes: under an exclusive OS
        file lock, the true chain head is re-read from disk, so several workers,
        an overlapping restart or a CLI tool can't fork the chain. fsync'd, so an
        acknowledged action survives a crash.
        """
        with self._lock, _exclusive_lock(self.lock_path):
            entry = self._append_locked(action, data, actor=actor, refs=refs)
        for listener in list(self.listeners):
            try:
                listener(entry)
            except Exception:  # a broken listener must never break the audit write path
                logger.exception("Audit listener failed")
        return entry

    def _append_locked(self, action: str, data: dict[str, Any], *, actor: str,
                       refs: Iterable[str]) -> dict[str, Any]:
        """Caller holds both locks. The chain head always comes from disk, never from memory."""
        payload = json.loads(canonical_json(_redact(data)))  # stored bytes == hashed bytes
        with self.path.open("a+b") as fh:
            kind, last = _read_last_entry(fh)
            if kind == "ok":
                self._seq, self._head = last["seq"] + 1, last["current_hash"]
            elif kind == "empty":          # fresh or just-reset log (possibly by another process)
                self._seq, self._head = 0, GENESIS_HASH
            # "corrupt": keep the cached head; verify() reports the torn line
            entry = {
                "seq": self._seq,
                "timestamp": iso(utcnow()),
                "action": action,
                "actor": actor,
                "refs": sorted({str(r) for r in refs if r}),
                "data": payload,
                "previous_hash": self._head,
            }
            entry["current_hash"] = compute_hash(entry, self._head)
            fh.write((json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
            self._seq += 1
            self._head = entry["current_hash"]
        return entry

    # ---- reset (archive, never delete) ------------------------------------------
    def archive_and_reset(self, reason: str, *, actor: str = "operator") -> dict[str, Any]:
        """
        Start a fresh chain WITHOUT destroying evidence:
          1. the current file is renamed to <name>.<UTC timestamp>.archived.jsonl;
          2. a new log starts at seq 0 whose first entry records the archive's
             file name, entry count, head hash and integrity status (incl. any
             break), Ed25519-signed when a signer is available.
        The old history therefore stays verifiable and the reset itself is on record.
        Safe while a server is running: writers re-read the head from disk.
        """
        if not reason or len(reason.strip()) < 3:
            raise ValueError("A reason is required to reset the audit log")
        with self._lock, _exclusive_lock(self.lock_path):
            old = self.verify()
            archive = None
            if self.path.exists() and self.path.stat().st_size > 0:
                stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
                archive = self.path.with_name(f"{self.path.stem}.{stamp}.archived{self.path.suffix}")
                n = 1
                while archive.exists():   # never overwrite an earlier archive (two resets in one second)
                    archive = self.path.with_name(f"{self.path.stem}.{stamp}-{n}.archived{self.path.suffix}")
                    n += 1
                os.rename(self.path, archive)   # rename, unlike replace, also refuses to clobber
            self.path.touch()
            summary = {
                "archived_file": archive.name if archive else None,
                "archived_entries": old.entries,
                "archived_head_hash": old.head_hash,
                "archived_chain_valid": old.valid,
                "archived_broken_at_seq": old.broken_at,
                "archived_break_reason": old.reason,
            }
            checkpoint = self.signer.seal(summary, kind="audit_archive") if self.signer else None
            entry = self._append_locked(Action.SYSTEM, {
                "summary": f"audit log reset by {actor}: {reason.strip()}",
                "reason": reason.strip(), **summary,
                "archive_checkpoint": {"signature": checkpoint["signature"], "kid": checkpoint["kid"],
                                       "digest": checkpoint["digest"]} if checkpoint else None,
            }, actor=actor, refs=[])
        logger.warning("Audit log reset by %s; previous chain archived to %s", actor, archive)
        for listener in list(self.listeners):
            try:
                listener(entry)
            except Exception:
                logger.exception("Audit listener failed")
        return {"archived_to": str(archive) if archive else None, "previous": old.to_dict(), "genesis": entry}

    # ---- read ----------------------------------------------------------------
    def _iter_raw(self) -> Iterable[tuple[int, str]]:
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if line.strip():
                    yield lineno, line

    def entries(self) -> list[dict[str, Any]]:
        out = []
        for lineno, line in self._iter_raw():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                logger.error("Unparseable audit line %d", lineno)
        return out

    def _last_entry(self) -> Optional[dict[str, Any]]:
        last = None
        for _, line in self._iter_raw():
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
        return last

    def related(self, ref: str) -> list[dict[str, Any]]:
        """
        Every entry about `ref`, plus entries about directly linked ids (one hop).
        Example: an order references its quote, so the quote's QUOTE and
        SUBSTITUTION entries are included in the order's trail.
        """
        all_entries = self.entries()
        direct = [e for e in all_entries if ref in e.get("refs", [])]
        linked = {r for e in direct for r in e.get("refs", [])}
        return [e for e in all_entries if linked & set(e.get("refs", []))] if linked else []

    @property
    def head_hash(self) -> str:
        return self._head

    # ---- integrity -------------------------------------------------------------
    def verify(self) -> ChainStatus:
        prev, count, expected_seq = GENESIS_HASH, 0, 0
        for lineno, line in self._iter_raw():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return ChainStatus(False, count, prev, expected_seq, f"line {lineno} is not valid JSON")
            seq = e.get("seq")
            if seq != expected_seq:
                return ChainStatus(False, count, prev, expected_seq, f"sequence gap: expected {expected_seq}, found {seq}")
            if e.get("previous_hash") != prev:
                return ChainStatus(False, count, prev, seq, "previous_hash does not match prior entry")
            claimed = e.pop("current_hash", None)
            if compute_hash(e, prev) != claimed:
                return ChainStatus(False, count, prev, seq, "entry content was modified (hash mismatch)")
            prev, count, expected_seq = claimed, count + 1, expected_seq + 1
        return ChainStatus(True, count, prev)

    def signed_checkpoint(self) -> dict[str, Any]:
        """Ed25519-signed statement: 'the log had N entries ending in head H at time T'."""
        status = self.verify()
        payload = {"log": str(self.path.name), "entries": status.entries, "head_hash": status.head_hash,
                   "chain_valid": status.valid}
        if self.signer is None:
            return {"payload": payload, "signature": None}
        return self.signer.seal(payload, kind="audit_checkpoint")

    # ---- export -------------------------------------------------------------------
    def export_markdown(self, ref: Optional[str] = None, *, title: Optional[str] = None) -> str:
        entries = self.related(ref) if ref else self.entries()
        status = self.verify()
        checkpoint = self.signed_checkpoint()
        title = title or (f"Audit Trail: {ref}" if ref else "Audit Trail: full log")

        md: list[str] = [f"# {title}", ""]
        md += [
            f"- **Generated:** {iso(utcnow())}",
            f"- **Entries in this trail:** {len(entries)} (of {status.entries} in the log)",
            f"- **Chain integrity:** {'✅ VERIFIED' if status.valid else '❌ BROKEN'}"
            + ("" if status.valid else f" at seq {status.broken_at}: {status.reason}"),
            f"- **Chain head:** `{status.head_hash}`",
        ]
        if checkpoint.get("signature"):
            md.append(f"- **Signed checkpoint:** key `{checkpoint['kid']}`, signature `{checkpoint['signature'][:32]}...`")
        md.append("")

        if not entries:
            md.append(f"_No audit entries found for `{ref}`._")
            return "\n".join(md) + "\n"

        outcome = _final_outcome(entries)
        if outcome:
            md += ["## Outcome", "", outcome, ""]

        md += ["## Timeline", "", "| # | Time (UTC) | Action | Actor | Summary |", "|---|---|---|---|---|"]
        for e in entries:
            md.append(f"| {e['seq']} | {e['timestamp']} | `{e['action']}` | {e.get('actor', '')} | "
                      f"{_summarize(e).replace('|', '/')} |")
        md.append("")

        md += ["## Entries", ""]
        for e in entries:
            md += [
                f"### #{e['seq']} · {e['action']} · {e['timestamp']}", "",
                f"- Actor: `{e.get('actor')}`",
                f"- Refs: {', '.join(f'`{r}`' for r in e.get('refs', [])) or 'none'}",
                f"- Previous hash: `{e['previous_hash'][:16]}...`",
                f"- Entry hash: `{e['current_hash'][:16]}...`",
            ]
            reasons = (e.get("data") or {}).get("decision", {}).get("reasons") if isinstance(
                (e.get("data") or {}).get("decision"), dict) else None
            if reasons:
                md += ["- Reasons:"] + [f"  - {r}" for r in reasons]
            md += ["", "<details><summary>Raw data</summary>", "", "```json",
                   json.dumps(e.get("data"), indent=2, ensure_ascii=False, default=str), "```", "", "</details>", ""]

        md += ["---", "",
               "_Verify independently: for each entry, remove `current_hash`, serialize with sorted keys and "
               "compact separators (UTF-8), append `previous_hash`, and SHA-256 the result._", ""]
        return "\n".join(md)


# =============================================================================
# Markdown helpers
# =============================================================================

def _summarize(e: dict[str, Any]) -> str:
    d = e.get("data") or {}
    a = e.get("action")
    if a == Action.SEARCH:
        return f"query '{d.get('query')}' → {d.get('result_count', len(d.get('results', [])))} results"
    if a == Action.QUOTE:
        return f"quote {d.get('quote_id', '')} for {len(d.get('lines', d.get('products', [])))} product(s)"
    if a == Action.SUBSTITUTION:
        alts = d.get("alternatives") or []
        return f"{d.get('originalProductId')} unavailable → {len(alts)} alternative(s)"
    if a == Action.POLICY_DECISION:
        dec = d.get("decision") or {}
        return f"{dec.get('status')} · net {dec.get('totals', {}).get('net_total')} {dec.get('totals', {}).get('currency', '')}"
    if a in (Action.APPROVAL, Action.REJECTION):
        return f"by {d.get('reviewer', e.get('actor'))}: {d.get('comment') or '(no comment)'}"
    if a in (Action.APPROVED_BY_AI_SECRETARY, Action.REJECTED_BY_AI_SECRETARY):
        verb = "approved" if a == Action.APPROVED_BY_AI_SECRETARY else "rejected"
        return (f"AI secretary ({d.get('model')}) {verb} {d.get('order_id')} for {d.get('reviewer')}"
                f"{' after confirmation' if d.get('confirmed_by_manager') else ''}: {d.get('reason') or ''}")
    if a == Action.TRUST_RULE:
        return (f"rule #{d.get('rule_id')} {d.get('event', 'created')} by {d.get('by', e.get('actor'))}: "
                f"{', '.join(d.get('waived_codes') or [])} for {', '.join(d.get('product_ids') or [])}")
    if a == Action.TRUST_LEVEL:
        return f"{d.get('agent_id')}: level {d.get('from_level')} → {d.get('to_level')} ({d.get('to_name')})"
    if a == Action.WEBHOOK:
        return f"{d.get('event')} → {d.get('status')} ({d.get('attempts')} attempt(s))"
    if a == Action.NEGOTIATION_WON and (d.get("negotiation") or {}).get("source") == "proactive_offer":
        n = d["negotiation"]
        return (f"Agent accepted proactive offer and negotiated a bulk discount. Saved €{n.get('saved_amount', 0):,.2f}. "
                f"({n.get('new_qty', 0):,.0f} {d.get('sales_unit') or 'units'} for €{n.get('new_total', 0):,.2f}; "
                f"simulated counter-party)")
    if a == Action.NEGOTIATION_WON:
        n = d.get("negotiation") or {}
        return (f"Agent negotiated bulk discount. Saved €{n.get('saved_amount', 0):,.2f}. "
                f"({n.get('new_qty', 0):,.0f} {d.get('sales_unit') or 'units'} for €{n.get('new_total', 0):,.2f}; "
                f"simulated counter-party)")
    if a == Action.NEGOTIATION_LOST:
        n = d.get("negotiation") or {}
        return f"Counter-offer for {n.get('proposed_qty', 0):,.0f} {d.get('sales_unit') or 'units'} declined: {n.get('reason', '')}"
    if a == Action.LAST_MINUTE_EVENT_ORDER:
        return f"🎉 Event order ({d.get('source')}): {d.get('message')}"
    if a == Action.ORDERED_BY_AI_SECRETARY:
        return f"🛒 AI secretary order: {d.get('message')}"
    if a == Action.QUICK_ORDER:
        return f"⚡ Quick order ({d.get('source')}): {d.get('message')}"
    if a == Action.INVENTORY_RESTOCK:
        return f"📦 Inventory restock ({d.get('source')}): {d.get('message')}"
    if a == Action.INVENTORY_COUNT:
        return f"📋 Stock count: {d.get('label')} = {d.get('on_hand'):g} {d.get('sales_unit') or 'units'}"
    if a == Action.ORDER_SUBMITTED:
        sig = d.get("quote_signature")
        flag = "" if sig == "OK" else f" ⚠ quote signature {sig}"
        return f"order {d.get('order_id')}: {len(d.get('lines') or [])} line(s) from {d.get('quote_id')}{flag}"
    if a == Action.ORDER_PLACED:
        return f"order {d.get('order_id')} placed"
    return d.get("summary") or ", ".join(f"{k}={v}" for k, v in list(d.items())[:3] if not isinstance(v, (dict, list)))


summarize_entry = _summarize  # public name for the dashboard feed


def _final_outcome(entries: list[dict[str, Any]]) -> Optional[str]:
    for e in reversed(entries):
        a, d = e["action"], e.get("data") or {}
        if a == Action.ORDER_PLACED:
            return f"**Order placed** at {e['timestamp']}."
        if a == Action.APPROVAL:
            return f"**Approved** by {d.get('reviewer', e.get('actor'))} at {e['timestamp']}."
        if a == Action.APPROVED_BY_AI_SECRETARY:
            return (f"**Approved by the AI secretary** ({d.get('model')}) for {d.get('reviewer')} at {e['timestamp']}"
                    f"{', confirmed by the manager' if d.get('confirmed_by_manager') else ''}.")
        if a == Action.REJECTED_BY_AI_SECRETARY:
            return (f"**Rejected by the AI secretary** ({d.get('model')}) for {d.get('reviewer')} at {e['timestamp']}"
                    f"{', confirmed by the manager' if d.get('confirmed_by_manager') else ''}.")
        if a == Action.REJECTION:
            return f"**Rejected** by {d.get('reviewer', e.get('actor'))} at {e['timestamp']}."
        if a == Action.POLICY_DECISION:
            dec = d.get("decision") or {}
            return f"**Policy decision: {dec.get('status')}**. " + "; ".join(dec.get("reasons") or [])
    return None


# =============================================================================
# Operator CLI:  python -m src.audit verify | reset --reason "..."
# =============================================================================
# Deliberately NOT an HTTP endpoint: wiping the live chain should need shell
# access to the server, not just a dashboard login.

def _cli(argv: Optional[list[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m src.audit", description="Audit log maintenance")
    ap.add_argument("command", choices=["verify", "reset"])
    ap.add_argument("--file", default=str(AUDIT_FILE), help=f"audit log path (default {AUDIT_FILE})")
    ap.add_argument("--reason", default="", help="why the log is being reset (recorded in the new chain)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args(argv)

    log = AuditLog(args.file)
    if args.command == "verify":
        status = log.verify()
        print(json.dumps(status.to_dict(), indent=2))
        return 0 if status.valid else 1

    if not args.reason:
        ap.error("reset requires --reason")
    status = log.verify()
    print(f"Current log: {status.entries} entries, chain {'VALID' if status.valid else f'BROKEN at #{status.broken_at}'}")
    if not args.yes and input("Archive it and start a fresh chain? [y/N] ").strip().lower() != "y":
        print("Aborted.")
        return 1
    try:
        from .trust import TrustSigner
        log.signer = TrustSigner.from_env()   # signs the archive checkpoint (stable if GATEWAY_SIGNING_KEY_HEX is set)
    except Exception:
        log.signer = None
    result = log.archive_and_reset(args.reason, actor=f"operator:{os.getenv('USERNAME') or os.getenv('USER') or 'cli'}")
    print(f"Archived to: {result['archived_to']}")
    print(f"New chain started: {json.dumps(log.verify().to_dict())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
