"""
Cryptographic Trust Protocol (Ed25519)
======================================

Every claim the Gateway makes about price and availability is signed, so an
autonomous purchasing agent can prove it later and spot any tampering:

    1. Agent fetches the public key once:      GET /v1/keys   (JWK, RFC 8037)
    2. Gateway returns signed quotes:          {"payload": {...}, "signature": "...", "kid": "..."}
    3. Agent verifies offline:                 Ed25519.verify(pub, canonical_json(payload), sig)
    4. Agent submits the quote to /v1/orders; the Gateway re-verifies its own
       signature, so a quote edited in transit (e.g. a changed price) is refused.

Canonicalization: JSON with sorted keys, no whitespace, UTF-8, NaN/Infinity
forbidden. That is the JCS subset (RFC 8785) that matters here, and an agent
in any language can reproduce it.

Key lifecycle: by default a fresh, ephemeral key pair is generated at boot.
That is the safest default for a demo, and every restart rotates the key. Set
GATEWAY_SIGNING_KEY_HEX (a 32-byte seed) to keep one key across restarts or
uvicorn workers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger("gateway.trust")

ALGORITHM = "EdDSA"
CURVE = "Ed25519"
# Envelope keys that are metadata about the signature, never part of the signed bytes
_SIGNATURE_FIELDS = frozenset({"signature", "kid", "alg"})


# =============================================================================
# Encoding helpers
# =============================================================================

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def canonical_json(payload: Any) -> bytes:
    """Deterministic byte serialization: the only bytes that are ever signed."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False, default=_json_default,
    ).encode("utf-8")


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if hasattr(obj, "isoformat"):  # date
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if hasattr(obj, "item") and callable(obj.item):  # numpy scalar -> Python scalar
        return obj.item()
    raise TypeError(f"Object of type {type(obj).__name__} is not canonically serializable")


def payload_digest(payload: Any) -> str:
    """SHA-256 of the canonical form. Used as a content id in audit entries."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# =============================================================================
# Signer
# =============================================================================

class TrustSigner:
    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._public_raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        # RFC 7638-style thumbprint: short, stable identifier of this key
        self.kid = "va-" + hashlib.sha256(self._public_raw).hexdigest()[:16]
        self.created_at = utcnow()

    @classmethod
    def from_env(cls) -> "TrustSigner":
        """
        Key source, in order:
          1. GATEWAY_SIGNING_KEY_HEX (64 hex chars): production / several workers sharing one key
          2. GATEWAY_SIGNING_KEY_FILE (default var/signing_key.hex): created once, then reused, so a
             restart or `--reload` no longer rotates the key (which invalidated every stored offer, quote
             and receipt with UNKNOWN_KEY)
          3. GATEWAY_SIGNING_KEY_EPHEMERAL=1: a fresh key per process (the old behaviour)
        """
        seed_hex = os.getenv("GATEWAY_SIGNING_KEY_HEX", "").strip()
        if seed_hex:
            seed = bytes.fromhex(seed_hex)
            if len(seed) != 32:
                raise ValueError("GATEWAY_SIGNING_KEY_HEX must be 64 hex chars (32 bytes)")
            signer = cls(Ed25519PrivateKey.from_private_bytes(seed))
            logger.info("Loaded signing key %s from GATEWAY_SIGNING_KEY_HEX", signer.kid)
            return signer
        if os.getenv("GATEWAY_SIGNING_KEY_EPHEMERAL", "0") == "1":
            signer = cls()
            logger.warning("Generated EPHEMERAL signing key %s: it changes on every restart", signer.kid)
            return signer

        from pathlib import Path
        path = Path(os.getenv("GATEWAY_SIGNING_KEY_FILE", "var/signing_key.hex"))
        if path.exists():
            seed = bytes.fromhex(path.read_text(encoding="ascii").strip())
            if len(seed) != 32:
                raise ValueError(f"{path} must contain 64 hex chars (32 bytes)")
            signer = cls(Ed25519PrivateKey.from_private_bytes(seed))
            logger.info("Loaded signing key %s from %s", signer.kid, path)
            return signer
        path.parent.mkdir(parents=True, exist_ok=True)
        seed = secrets.token_bytes(32)
        # O_EXCL: if two processes start at once, exactly one creates the key and the other loads it
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # owner-only (POSIX; ignored on Windows)
        except FileExistsError:
            import time
            time.sleep(0.2)                   # the other process is writing it: give it a moment, then load
            return cls.from_env()
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(seed.hex())
        signer = cls(Ed25519PrivateKey.from_private_bytes(seed))
        logger.warning("Created signing key %s at %s (kept across restarts; for production set "
                       "GATEWAY_SIGNING_KEY_HEX from a secret store instead)", signer.kid, path)
        return signer

    # ---- public key distribution ------------------------------------------
    @property
    def public_key_b64url(self) -> str:
        return b64url_encode(self._public_raw)

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def jwks(self) -> dict[str, Any]:
        """Response body for GET /v1/keys."""
        return {
            "keys": [{
                "kty": "OKP", "crv": CURVE, "alg": ALGORITHM, "use": "sig",
                "kid": self.kid, "x": self.public_key_b64url,
            }],
            "pem": self.public_key_pem(),
            "created_at": iso(self.created_at),
            "canonicalization": "JSON, sorted keys, separators (',',':'), UTF-8, no NaN",
            "verification": "Ed25519.verify(base64url_decode(x), base64url_decode(signature), canonical_json(payload))",
        }

    # ---- sign / verify ------------------------------------------------------
    def sign_payload(self, payload: dict) -> str:
        return b64url_encode(self._private_key.sign(canonical_json(payload)))

    def verify_signature(self, payload: dict, signature: str) -> bool:
        try:
            self._public_key.verify(b64url_decode(signature), canonical_json(payload))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    def seal(self, payload: dict, *, ttl_seconds: Optional[int] = None,
             kind: str = "quote") -> dict[str, Any]:
        """
        Wrap a payload in a signed envelope. Issuance metadata (`issued_at`,
        `expires_at`, `nonce`, `kid`) goes *inside* the payload so it is covered
        by the signature: an agent cannot extend a quote's lifetime.
        """
        now = utcnow()
        body = dict(payload)
        body["_meta"] = {
            "kind": kind,
            "issuer": "valio-aimo-agent-gateway",
            "kid": self.kid,
            "issued_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=ttl_seconds)) if ttl_seconds else None,
            "nonce": secrets.token_hex(12),
        }
        return {
            "payload": body,
            "signature": self.sign_payload(body),
            "kid": self.kid,
            "alg": ALGORITHM,
            "digest": payload_digest(body),
        }

    def open(self, envelope: dict[str, Any], *, check_expiry: bool = True) -> tuple[bool, str]:
        """
        Verify a sealed envelope. Returns (ok, reason). Reasons are stable
        machine-readable codes for guardrails and audit entries.
        """
        if not isinstance(envelope, dict) or "payload" not in envelope or "signature" not in envelope:
            return False, "MALFORMED_ENVELOPE"
        payload = envelope["payload"]
        if not isinstance(payload, dict):
            return False, "MALFORMED_ENVELOPE"
        meta = payload.get("_meta") or {}
        if envelope.get("kid") not in (None, self.kid) or meta.get("kid") != self.kid:
            return False, "UNKNOWN_KEY"  # signed by an older (rotated) key or someone else
        if not self.verify_signature(payload, str(envelope["signature"])):
            return False, "INVALID_SIGNATURE"
        if check_expiry and meta.get("expires_at"):
            try:
                expires = datetime.fromisoformat(meta["expires_at"].replace("Z", "+00:00"))
            except ValueError:
                return False, "MALFORMED_EXPIRY"
            if utcnow() > expires:
                return False, "EXPIRED"
        return True, "OK"


# =============================================================================
# Stateless verification, for agents / third parties holding only the public key
# =============================================================================

def verify_with_public_key(payload: dict, signature: str, public_key_b64url: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64url_decode(public_key_b64url))
        pub.verify(b64url_decode(signature), canonical_json(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# =============================================================================
# Module-level singleton + the functional API from the spec
# =============================================================================

_signer: Optional[TrustSigner] = None


def get_signer() -> TrustSigner:
    global _signer
    if _signer is None:
        _signer = TrustSigner.from_env()
    return _signer


def sign_payload(payload: dict) -> str:
    return get_signer().sign_payload(payload)


def verify_signature(payload: dict, signature: str) -> bool:
    return get_signer().verify_signature(payload, signature)


# =============================================================================
# Cryptographic webhooks (#2): HMAC-SHA256, Stripe-style timestamped signatures
# =============================================================================
#
#   X-Valio-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>
#
# * The timestamp is inside the MAC, so a captured webhook cannot be replayed
#   outside the tolerance window.
# * The receiver must verify the RAW body bytes before parsing JSON.
# * The body itself is an Ed25519-sealed envelope, so the approval stays provable
#   even after the webhook has been stored or forwarded (HMAC = transport
#   authenticity, Ed25519 = durable non-repudiation).

import asyncio as _asyncio
import hmac as _hmac
import time as _time

WEBHOOK_SIGNATURE_HEADER = "X-Valio-Signature"
_DEV_WEBHOOK_SECRET = "dev-webhook-secret-change-me"


def webhook_secret() -> str:
    secret = os.getenv("WEBHOOK_SECRET", "")
    if not secret:
        logger.warning("WEBHOOK_SECRET not set; using the development secret")
        return _DEV_WEBHOOK_SECRET
    return secret


def sign_webhook(body: bytes, secret: str, timestamp: Optional[int] = None) -> str:
    ts = int(timestamp if timestamp is not None else _time.time())
    mac = _hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def verify_webhook(body: bytes, header: Optional[str], secret: str, *, tolerance_seconds: int = 300,
                   now: Optional[int] = None) -> tuple[bool, str]:
    """Constant-time verification. Returns (ok, reason)."""
    if not header:
        return False, "MISSING_SIGNATURE"
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts, sig = int(parts["t"]), parts["v1"]
    except (ValueError, KeyError):
        return False, "MALFORMED_SIGNATURE"
    now = int(now if now is not None else _time.time())
    if abs(now - ts) > tolerance_seconds:
        return False, "TIMESTAMP_OUT_OF_TOLERANCE"
    expected = _hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return (True, "OK") if _hmac.compare_digest(expected, sig) else (False, "INVALID_SIGNATURE")


class WebhookDispatcher:
    """
    Delivers signed webhooks with retries. Returns a delivery record for the
    caller to persist (Database.log_webhook). Retries use the SAME body and
    delivery id but a fresh signature timestamp; receivers dedupe on
    X-Valio-Delivery.
    """

    def __init__(self, signer: TrustSigner, url: str, secret: str, *, timeout: float = 5.0,
                 max_attempts: int = 3) -> None:
        self.signer, self.url, self.secret = signer, url, secret
        self.timeout, self.max_attempts = timeout, max(1, max_attempts)

    def build(self, event: str, data: dict) -> tuple[str, bytes]:
        delivery_id = "whd_" + secrets.token_hex(8)
        envelope = self.signer.seal({"event": event, "delivery_id": delivery_id, "data": data}, kind="webhook")
        return delivery_id, canonical_json(envelope)

    async def deliver(self, event: str, data: dict, *, order_id: Optional[str] = None) -> dict[str, Any]:
        import httpx  # local import keeps trust.py importable without the HTTP stack

        delivery_id, body = self.build(event, data)
        record: dict[str, Any] = {"delivery_id": delivery_id, "event": event, "order_id": order_id, "url": self.url,
                                  "payload": body.decode("utf-8"), "attempts": 0, "status": "FAILED"}
        delay = 0.5
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(1, self.max_attempts + 1):
                signature = sign_webhook(body, self.secret)
                record.update(attempts=attempt, signature=signature)
                try:
                    resp = await client.post(self.url, content=body, headers={
                        "Content-Type": "application/json",
                        WEBHOOK_SIGNATURE_HEADER: signature,
                        "X-Valio-Event": event,
                        "X-Valio-Delivery": delivery_id,
                        "X-Valio-Key-Id": self.signer.kid,
                    })
                    record["status_code"] = resp.status_code
                    if resp.status_code < 300:
                        record.update(status="DELIVERED", error=None)
                        return record
                    record["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    if resp.status_code < 500 and resp.status_code != 429:
                        return record          # receiver rejected it; retrying won't help
                except httpx.HTTPError as exc:
                    record["error"] = f"{type(exc).__name__}: {exc}"
                if attempt < self.max_attempts:
                    await _asyncio.sleep(delay)
                    delay *= 2
        logger.warning("Webhook %s (%s) failed after %d attempts: %s", delivery_id, event,
                       record["attempts"], record.get("error"))
        return record
