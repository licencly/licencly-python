"""The signed license file format.

This is a standalone copy of the format logic, not an import from a shared
package: pulling in a licensing SDK should give you one dependency, not a tree.
Every Licencly SDK carries its own, and the conformance vectors in
``tests/data/vectors.json`` are what keep them in agreement.

Format: ``lcl1.<base64url(payload)>.<base64url(signature)>``

The signature covers the ASCII of ``lcl1.<payload>``: the bytes exactly as
transmitted. That removes any need for canonical JSON: two parsers that disagree
about key ordering would otherwise compute different digests and reject each
other's valid files.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: Format version, part of the signed bytes so a future format cannot be
#: relabelled as this one.
PREFIX = "lcl1"

#: License file schema version, distinct from the SDK's own version.
FORMAT_VERSION = 1

STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_REVOKED = "revoked"
STATUS_EXPIRED = "expired"


class LicenseFileError(Exception):
    """The license file could not be parsed or verified.

    ``reason`` is one of ``malformed``, ``unknown_version``, ``bad_signature``
    or ``unknown_key``.
    """

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(f"licencly: {message}")
        self.reason = reason


@dataclass(frozen=True)
class Claims:
    """Verified content of a license file.

    The names here are the ones the Go and .NET SDKs use, not the short keys the
    wire format uses. ``maintenance_expires_at`` says what it is; ``mnt`` needs
    the format spec open beside it, and a vendor moving between two of our SDKs
    should not have to relearn the same object.

    Frozen because these have been verified. A settable ``status`` would let a
    caller take a revoked license, assign "active" to it and act on the result.
    """

    version: int
    key_id: str
    license_uuid: str
    key: str
    product_uuid: str
    customer_ref: str
    status: str
    seats: int
    used: int
    fingerprint: str
    #: Seconds since the epoch.
    issued_at: int
    #: Seconds since the epoch; 0 for a perpetual license.
    expires_at: int
    #: Seconds since the epoch; 0 when maintenance never lapses.
    maintenance_expires_at: int
    #: Seconds since the epoch: when the client should check in again.
    revalidate_after: int
    grace_seconds: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "Claims":
        """Maps the short wire keys onto readable names."""
        return cls(
            version=int(payload.get("v", 0)),
            key_id=str(payload.get("kid", "")),
            license_uuid=str(payload.get("lic", "")),
            key=str(payload.get("key", "")),
            product_uuid=str(payload.get("prd", "")),
            customer_ref=str(payload.get("sub", "")),
            status=str(payload.get("st", "")),
            seats=int(payload.get("seats", 0)),
            used=int(payload.get("used", 0)),
            fingerprint=str(payload.get("fp", "")),
            issued_at=int(payload.get("iat", 0)),
            expires_at=int(payload.get("exp", 0)),
            maintenance_expires_at=int(payload.get("mnt", 0)),
            revalidate_after=int(payload.get("rev", 0)),
            grace_seconds=int(payload.get("grace", 0)),
            metadata=dict(payload.get("meta") or {}),
        )

    def needs_revalidation(self, now: datetime) -> bool:
        """True once past the check-in time: keep running, refresh in the background."""
        return self.revalidate_after != 0 and _unix(now) > self.revalidate_after

    def maintenance_active(self, now: datetime) -> bool:
        """Entitlement to releases published now.

        A perpetual license with lapsed maintenance keeps running but stops
        receiving updates.
        """
        return self.maintenance_expires_at == 0 or _unix(now) <= self.maintenance_expires_at


def public_key_from_raw(raw: bytes) -> Ed25519PublicKey:
    """Wraps a raw 32-byte Ed25519 public key."""
    if len(raw) != 32:
        raise LicenseFileError(f"public key is {len(raw)} bytes, want 32", "unknown_key")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_from_base64(encoded: str) -> Ed25519PublicKey:
    """Parses a base64 public key, as copied from the dashboard."""
    try:
        return public_key_from_raw(base64.b64decode(encoded, validate=True))
    except LicenseFileError:
        raise
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same problem
        raise LicenseFileError(f"public key is not valid base64: {exc}", "unknown_key") from exc


def decode(token: str) -> Claims:
    """Parses the payload WITHOUT verifying the signature.

    Its only legitimate use is reading ``kid`` to choose a public key. Every
    claim is attacker-controlled until :func:`verify` has succeeded.
    """
    _, claims, _ = _split(token)
    return claims


def verify(token: str, public_key: Ed25519PublicKey) -> Claims:
    """Checks the signature.

    Does not evaluate expiry, status or machine binding: that is
    :func:`licencly.decision.evaluate`, so a caller can tell "forged" apart from
    "expired".
    """
    signed, claims, signature = _split(token)

    try:
        public_key.verify(signature, signed)
    except InvalidSignature as exc:
        raise LicenseFileError("signature does not verify", "bad_signature") from exc
    return claims


def verify_with_keys(token: str, keys: Mapping[str, Ed25519PublicKey]) -> Claims:
    """Selects the public key by the file's key id.

    An unknown id is refused rather than retried against every key held: a
    client that tries them all accepts a file signed by a rotated-out key an
    attacker recovered.
    """
    unverified = decode(token)

    key = keys.get(unverified.key_id)
    if key is None:
        raise LicenseFileError(
            f'license was signed by key "{unverified.key_id}", which this build does not trust',
            "unknown_key",
        )
    return verify(token, key)


def _split(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise LicenseFileError("license file is malformed", "malformed")

    prefix, payload, signature = parts
    if prefix != PREFIX:
        raise LicenseFileError(f'unsupported license file version "{prefix}"', "unknown_version")

    try:
        decoded = json.loads(_b64url_decode(payload))
    except Exception as exc:  # noqa: BLE001
        raise LicenseFileError("license file is malformed", "malformed") from exc

    if not isinstance(decoded, dict):
        raise LicenseFileError("license file is malformed", "malformed")

    claims = Claims.from_payload(decoded)
    if claims.version != FORMAT_VERSION:
        raise LicenseFileError(f"unsupported license file version {claims.version}", "unknown_version")

    try:
        raw_signature = _b64url_decode(signature)
    except Exception as exc:  # noqa: BLE001
        raise LicenseFileError("license file is malformed", "malformed") from exc

    return f"{prefix}.{payload}".encode("ascii"), claims, raw_signature


def _b64url_decode(value: str) -> bytes:
    # The format uses unpadded base64url; Python's decoder insists on padding.
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _unix(moment: datetime) -> int:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())
