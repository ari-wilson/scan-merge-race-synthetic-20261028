"""Offline GitHub OIDC identity verification; never grants authorization.

Caller must obtain JWKS from a trusted channel, issue a unique audience, enforce
one-use replay protection atomically, impose any stricter token age/lifetime
policy, and independently authorize any action.
No token or claims are persisted by this module.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class VerificationError(ValueError):
    """Untrusted input failed verification; messages never include input."""


@dataclass(frozen=True)
class ExpectedIdentity:
    audience: str
    repository_id: str
    event_name: str
    workflow_ref: str
    workflow_sha: str
    run_id: str
    run_attempt: str
    check_run_id: str


@dataclass(frozen=True)
class VerifiedIdentity:
    """Authenticated claims only; caller must atomically reject replay."""
    identity: ExpectedIdentity
    jti: str
    expires_at: int
    issued_at: int
    not_before: int


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate JSON key")
        result[key] = value
    return result


def _json(raw):
    try:
        result = json.loads(raw, object_pairs_hook=_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError):
        result = None
    if result is None:
        raise VerificationError("invalid JSON")
    if not isinstance(result, dict):
        raise VerificationError("expected JSON object")
    return result


def _decode(value, limit):
    if not isinstance(value, str) or not value or len(value) > limit:
        raise VerificationError("invalid encoding")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise VerificationError("invalid encoding")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise VerificationError("invalid encoding") from exc
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise VerificationError("noncanonical encoding")
    return decoded


def verify_token(token: str, jwks: bytes, expected: ExpectedIdentity) -> VerifiedIdentity:
    """Verify using trusted JWKS and system clock; caller must enforce replay."""
    now = int(time.time())
    if not isinstance(token, str) or len(token) > 32768 or not isinstance(jwks, bytes) or len(jwks) > 131072:
        raise VerificationError("input bounds")
    if not isinstance(expected, ExpectedIdentity):
        raise VerificationError("invalid verification policy")
    if any(not isinstance(v, str) or not v or len(v) > 2048 for v in vars(expected).values()):
        raise VerificationError("invalid verification policy")
    pieces = token.split(".")
    if len(pieces) != 3:
        raise VerificationError("invalid token")
    header = _json(_decode(pieces[0], 8192))
    claims = _json(_decode(pieces[1], 16384))
    signature = _decode(pieces[2], 2048)
    if set(header) - {"alg", "kid", "typ", "x5t"} or header.get("alg") != "RS256" or header.get("typ") not in (None, "JWT"):
        raise VerificationError("unsupported header")
    if "x5t" in header and len(_decode(header["x5t"], 64)) != 20:
        raise VerificationError("invalid certificate thumbprint")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > 256:
        raise VerificationError("invalid key id")
    keys = _json(jwks).get("keys")
    if not isinstance(keys, list) or len(keys) > 64 or any(not isinstance(k, dict) for k in keys):
        raise VerificationError("invalid keys")
    matches = [k for k in keys if k.get("kid") == kid]
    if len(matches) != 1:
        raise VerificationError("key selection failed")
    key = matches[0]
    if key.get("kty") != "RSA" or key.get("alg") not in (None, "RS256") or key.get("use") not in (None, "sig"):
        raise VerificationError("unsupported key")
    if "key_ops" in key and key["key_ops"] != ["verify"]:
        raise VerificationError("unsupported key operations")
    n_raw = _decode(key.get("n"), 2048)
    e_raw = _decode(key.get("e"), 16)
    if n_raw[0] == 0 or e_raw[0] == 0:
        raise VerificationError("noncanonical key")
    n, e = int.from_bytes(n_raw, "big"), int.from_bytes(e_raw, "big")
    if not 2048 <= n.bit_length() <= 8192 or e < 3 or e > 0xFFFFFFFF or e % 2 == 0:
        raise VerificationError("invalid RSA key")
    try:
        public = RSA.construct((n, e))
        pkcs1_15.new(public).verify(SHA256.new((pieces[0] + "." + pieces[1]).encode("ascii")), signature)
    except (ValueError, TypeError, IndexError) as exc:
        raise VerificationError("invalid signature") from exc
    if claims.get("iss") != "https://token.actions.githubusercontent.com" or claims.get("aud") != expected.audience:
        raise VerificationError("issuer or audience mismatch")
    for name in ("repository_id", "event_name", "workflow_ref", "workflow_sha", "run_id", "run_attempt", "check_run_id"):
        if claims.get(name) != getattr(expected, name):
            raise VerificationError("identity mismatch")
    for name in ("exp", "nbf", "iat"):
        if type(claims.get(name)) is not int:
            raise VerificationError("invalid time claim")
    if claims["exp"] <= now or claims["nbf"] > now or claims["iat"] > now or claims["exp"] <= claims["iat"]:
        raise VerificationError("token outside validity period")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti or len(jti) > 256:
        raise VerificationError("invalid token identifier")
    return VerifiedIdentity(expected, jti, claims["exp"], claims["iat"], claims["nbf"])
