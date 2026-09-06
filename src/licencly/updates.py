"""Update checks and verified artifact downloads."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ApiError, NetworkError


class UpdateOutcome(str, Enum):
    """Mirrors the server's vocabulary exactly, so a vendor's logs match the API."""

    # Enum.__str__ would render "UpdateOutcome.UP_TO_DATE", which is precisely
    # what the line above promises it will not do. Formatting as the value keeps
    # a vendor's logs identical to the API and to the other three SDKs.
    __str__ = str.__str__

    AVAILABLE = "update_available"
    UP_TO_DATE = "up_to_date"
    #: NOT an error. A newer release exists and this license is not entitled to
    #: it; ``latest`` names what a renewal would unlock.
    MAINTENANCE_LAPSED = "maintenance_lapsed"
    #: An entitled release exists but needs an intermediate version first.
    UPGRADE_BLOCKED = "upgrade_blocked"
    NOT_ENTITLED = "not_entitled"


@dataclass(frozen=True)
class Release:
    uuid: str
    version: str
    channel: str = "stable"
    platform: str = ""
    arch: str = ""
    notes: str = ""
    min_upgrade_from: str = ""
    artifact_size: int = 0
    artifact_sha256: str = ""
    artifact_filename: str = ""
    signed: bool = False

    @classmethod
    def from_payload(cls, payload) -> "Release":
        return cls(
            uuid=str(payload.get("uuid", "")),
            version=str(payload.get("version", "")),
            channel=str(payload.get("channel", "stable")),
            platform=str(payload.get("platform", "")),
            arch=str(payload.get("arch", "")),
            notes=str(payload.get("notes", "")),
            min_upgrade_from=str(payload.get("min_upgrade_from", "")),
            artifact_size=int(payload.get("artifact_size", 0)),
            artifact_sha256=str(payload.get("artifact_sha256", "")),
            artifact_filename=str(payload.get("artifact_filename", "")),
            signed=bool(payload.get("signed", False)),
        )


@dataclass(frozen=True)
class UpdateResult:
    outcome: UpdateOutcome
    #: The release to install, when outcome is AVAILABLE.
    release: Optional[Release] = None
    #: What a renewal would unlock, when held back.
    latest: Optional[Release] = None
    download_url: str = ""

    @property
    def available(self) -> bool:
        """The single check for "should I offer an update"."""
        return self.outcome is UpdateOutcome.AVAILABLE

    @property
    def renewal_would_unlock(self) -> bool:
        """A newer release exists but this license cannot have it.

        A prompt, not a failure.
        """
        return self.outcome is UpdateOutcome.MAINTENANCE_LAPSED and self.latest is not None


class ArtifactError(Exception):
    """The downloaded artifact failed verification.

    ``reason`` is ``checksum``, ``signature`` or ``unsigned``.
    """

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(f"licencly: {message}")
        self.reason = reason


def download_artifact(
    *,
    base_url: str,
    product_uuid: str,
    license_key: str,
    release: Release,
    dest_dir: os.PathLike | str,
    artifact_key: Optional[Ed25519PublicKey] = None,
    user_agent: str,
    timeout: float = 1800.0,
) -> Path:
    """Downloads a release and verifies it before returning a path.

    ``artifact_key`` is YOUR Ed25519 public key, compiled into this application
    and not fetched from Licencly. Licencly stores and serves the signature but
    cannot produce one, so a compromise of Licencly cannot push code to your
    users. Passing ``None`` reduces the check to corruption detection.
    """
    url = (
        f"{base_url.rstrip('/')}/v1/products/{urllib.parse.quote(product_uuid)}"
        f"/releases/{urllib.parse.quote(release.uuid)}/download"
        f"?key={urllib.parse.quote(license_key)}"
    )

    request = urllib.request.Request(url, headers={"User-Agent": user_agent})

    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code, "download_failed", f"download failed ({exc.code})") from exc
    except Exception as exc:  # noqa: BLE001
        raise NetworkError(exc) from exc

    destination = Path(dest_dir)
    destination.mkdir(parents=True, exist_ok=True, mode=0o750)

    name = Path(release.artifact_filename or "artifact.bin").name
    final = destination / name

    # Download to a temporary name and rename only after verification, so a
    # half-written or unverified artifact is never left where something might
    # execute it.
    fd, tmp = tempfile.mkstemp(dir=str(destination), prefix=f".{name}.", suffix=".partial")
    try:
        digest = hashlib.sha256()
        with response, os.fdopen(fd, "wb") as handle:
            while chunk := response.read(1 << 20):
                digest.update(chunk)
                handle.write(chunk)

        actual = digest.hexdigest()
        if actual != release.artifact_sha256:
            raise ArtifactError(
                "downloaded artifact does not match its checksum: "
                f"got {actual}, expected {release.artifact_sha256}",
                "checksum",
            )

        if artifact_key is not None:
            encoded = response.headers.get("X-Artifact-Signature")
            if not encoded:
                raise ArtifactError("artifact carries no signature", "unsigned")

            import base64

            # Re-read from disk rather than trusting anything held in memory, so
            # what is verified is exactly what will be executed.
            with open(tmp, "rb") as handle:
                contents = handle.read()
            try:
                artifact_key.verify(base64.b64decode(encoded), contents)
            except (InvalidSignature, ValueError) as exc:
                raise ArtifactError(
                    "artifact signature does not verify against your artifact key", "signature"
                ) from exc

        os.replace(tmp, final)
        return final
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def parse_update_response(raw: Optional[dict]) -> UpdateResult:
    payload = raw or {}

    return UpdateResult(
        outcome=UpdateOutcome(payload.get("outcome", "up_to_date")),
        release=Release.from_payload(payload["release"]) if payload.get("release") else None,
        latest=Release.from_payload(payload["latest"]) if payload.get("latest") else None,
        download_url=str(payload.get("download_url", "")),
    )


def build_check_path(product_uuid: str, license_key: str, **query: str) -> str:
    params = {"key": license_key}
    params.update({k: v for k, v in query.items() if v})

    return (
        f"/v1/products/{urllib.parse.quote(product_uuid)}/updates/check"
        f"?{urllib.parse.urlencode(params)}"
    )


# Kept so a caller can round-trip a stored response without importing json.
def loads(raw: str) -> UpdateResult:
    return parse_update_response(json.loads(raw))
