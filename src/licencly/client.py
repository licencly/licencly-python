"""Verify Licencly licenses and check for entitled updates.

The design in one sentence: the signed license file is the answer, and the
network is an optimisation. :meth:`LicenclyClient.validate` reads the cache,
refreshes when due, and keeps working through an outage until the grace period
is spent, so Licencly being unreachable never stops software you have already
sold.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .cache import Cache, FileCache, MemoryCache, default_cache_path
from .decision import Decision, Outcome, evaluate
from .errors import ApiError, NetworkError
from .licensefile import Claims, LicenseFileError, public_key_from_base64, verify_with_keys
from .updates import Release

#: Sent in the user agent, so a vendor's traffic is identifiable in support.
VERSION = "1.0.0"

DEFAULT_BASE_URL = "https://licencly.com"
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 2

#: Bounds an artifact download, which is a different order of magnitude from an
#: API call. Artifacts are installers, routinely hundreds of megabytes, so
#: reusing the API timeout here would abort most downloads.
DEFAULT_DOWNLOAD_TIMEOUT = 1800.0

#: How far the clock may move backwards before it is treated as tampering
#: rather than an NTP correction or a timezone change.
CLOCK_SKEW_TOLERANCE = timedelta(hours=24)


def _fold_key(key: str) -> str:
    """Folds a license key the way the server does, for comparison only.

    Mirrors NormalizeKey server side: upper case, drop the grouping characters,
    and map the look-alikes Crockford base32 leaves out. No checksum here; this
    only ever compares two values, and rejecting a key is the server's job.
    """
    out = []
    for ch in key.strip().upper():
        if ch in "- \t_":
            continue
        if ch in "IL":
            out.append("1")
        elif ch == "O":
            out.append("0")
        else:
            out.append(ch)
    return "".join(out)


class LicenclyClient:
    def __init__(
        self,
        product_uuid: str,
        public_keys: Union[Mapping[str, str], Mapping[str, Ed25519PublicKey]],
        *,
        fingerprint: str = "",
        cache: Optional[Cache] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        download_timeout: float = DEFAULT_DOWNLOAD_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        hostname: str = "",
        platform: str = "",
        app_version: str = "",
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        """
        :param product_uuid: identifies your product; from the dashboard.
        :param public_keys: maps a signing key id to its public key, either as
            base64 strings or as key objects. Embed these at build time.
            fetching them at runtime would defeat the entire scheme. Include
            retired keys as well as the active one: a license signed before a
            rotation still verifies against the key it was signed with.
        :param fingerprint: identifies this machine. Empty disables machine
            binding, which makes the file usable anywhere it is copied.
        """
        if not product_uuid:
            raise ValueError("licencly: product_uuid is required")

        self.product_uuid = product_uuid
        self.keys: Dict[str, Ed25519PublicKey] = {
            kid: key if isinstance(key, Ed25519PublicKey) else public_key_from_base64(key)
            for kid, key in public_keys.items()
        }
        if not self.keys:
            raise ValueError(
                "licencly: at least one public key is required, or nothing can be verified"
            )

        self.fingerprint = fingerprint
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.download_timeout = download_timeout
        self.retries = retries
        self.hostname = hostname
        self.platform = platform
        self.app_version = app_version
        self._now = now or (lambda: datetime.now(timezone.utc))

        if cache is not None:
            self.cache: Cache = cache
        else:
            try:
                self.cache = FileCache(default_cache_path(product_uuid))
            except Exception:  # noqa: BLE001
                # Falling back to memory rather than failing: an unusual home
                # directory should degrade the offline story, not break startup.
                self.cache = MemoryCache()

    def validate(self, license_key: str) -> Decision:
        """Decides whether this machine may run.

        Refreshes from the server when the cached file is due, and falls back to
        the cache whenever the server cannot be reached, so a Licencly outage
        does not stop software that has already been sold. Never blocks on the
        network while a usable cached file exists.

        The cache is keyed on the product, so it can hold a license other than
        the one being validated. A cached file is only reused when its key claim
        matches the key asked about and its fingerprint matches this machine;
        otherwise the server is asked, because answering with a different
        customer's license would be worse than failing.

        :raises NetworkError: when there is no usable cached file and the server
            cannot be reached, which for a customer means a first run offline.
        """
        now = self._now()
        cached, highest_seen = self.cache.load()

        # A large jump backwards from the furthest time seen is not an NTP
        # correction. A speed bump rather than a fix: anyone who can set the
        # clock can also patch the binary.
        if highest_seen.timestamp() > 0 and now + CLOCK_SKEW_TOLERANCE < highest_seen:
            return Decision(
                outcome=Outcome.INVALID,
                from_cache=True,
                error=RuntimeError("licencly: system clock moved backwards by more than 24 hours"),
            )

        cache_answers_this_key = False

        if cached:
            try:
                claims = verify_with_keys(cached, self.keys)

                # An absent key claim cannot be compared, so it counts as a
                # match: every file the server issues carries one.
                cache_answers_this_key = (
                    not claims.key or _fold_key(claims.key) == _fold_key(license_key)
                )
                same_machine = (
                    not claims.fingerprint or not self.fingerprint or claims.fingerprint == self.fingerprint
                )

                if (
                    cache_answers_this_key
                    and same_machine
                    and not claims.needs_revalidation(now)
                ):
                    return evaluate(claims, None, now, self.fingerprint, True)
            except LicenseFileError:
                pass  # unverifiable, so refetch

        try:
            fetched = self._fetch(license_key)
        except (NetworkError, ApiError):
            if not cached or not cache_answers_this_key:
                raise
            return self._evaluate_token(cached, now, True)

        decision = self._evaluate_token(fetched, now, False)
        if decision.claims is not None:
            self.cache.save(fetched, max(now, highest_seen))
        return decision

    def deactivate(self, license_key: str) -> None:
        """Frees this machine's seat."""
        self._request(
            "POST",
            "/v1/licenses/deactivate",
            {
                "product": self.product_uuid,
                "key": license_key,
                "fingerprint": self.fingerprint,
            },
        )
        self.cache.clear()

    def clear_cache(self) -> None:
        """Removes the stored license. Exposed so support can say "run this"."""
        self.cache.clear()

    def check_for_update(
        self,
        license_key: str,
        *,
        current_version: str = "",
        channel: str = "",
        platform: str = "",
        arch: str = "",
    ):
        """Asks which release this license is entitled to.

        Never consumes a seat: a background updater polling weekly must not
        exhaust a customer's activations.
        """
        from .updates import build_check_path, parse_update_response

        path = build_check_path(
            self.product_uuid,
            license_key,
            version=current_version,
            channel=channel,
            platform=platform,
            arch=arch,
        )
        return parse_update_response(self._request("GET", path))

    def download_artifact(
        self,
        license_key: str,
        release: Release,
        dest_dir: os.PathLike | str,
        artifact_key: Optional[Ed25519PublicKey] = None,
    ) -> Path:
        """Downloads a release and verifies it before returning a path.

        ``artifact_key`` is YOUR Ed25519 public key, compiled into this
        application and not fetched from Licencly. Licencly stores and serves
        the signature but cannot produce one, so a compromise of Licencly
        cannot push code to your users. Omitting it reduces the check to
        corruption detection.
        """
        from .updates import download_artifact as _download

        return _download(
            base_url=self.base_url,
            product_uuid=self.product_uuid,
            license_key=license_key,
            release=release,
            dest_dir=dest_dir,
            artifact_key=artifact_key,
            user_agent=f"licencly-python/{VERSION}",
            timeout=self.download_timeout,
        )

    def _evaluate_token(self, token: str, now: datetime, from_cache: bool) -> Decision:
        claims: Optional[Claims] = None
        error: Optional[BaseException] = None
        try:
            claims = verify_with_keys(token, self.keys)
        except LicenseFileError as exc:
            error = exc
        return evaluate(claims, error, now, self.fingerprint, from_cache)

    def _fetch(self, license_key: str) -> str:
        body: Dict[str, str] = {"product": self.product_uuid, "key": license_key}
        if self.fingerprint:
            body.update(
                fingerprint=self.fingerprint,
                hostname=self.hostname,
                platform=self.platform,
                app_version=self.app_version,
            )

        response = self._request("POST", "/v1/licenses/validate", body)
        token = (response or {}).get("license", "")
        if not token:
            raise ApiError(200, "empty_response", "the server returned no license file")
        return str(token)

    def _request(
        self, method: str, path: str, body: Optional[Mapping[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        last_error: Optional[BaseException] = None

        for attempt in range(self.retries + 1):
            if attempt:
                # Exponential backoff. Validate is idempotent, so retrying is
                # safe.
                time.sleep(0.2 * (2 ** (attempt - 1)))

            request = urllib.request.Request(
                self.base_url + path,
                data=payload,
                method=method,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"licencly-python/{VERSION}",
                },
            )

            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                error = _parse_api_error(exc)
                # 4xx is a decision, not a hiccup: retrying an invalid key just
                # makes the same answer arrive three times.
                if exc.code < 500:
                    raise error from exc
                last_error = error
            except Exception as exc:  # noqa: BLE001 - URLError, socket timeouts, DNS
                last_error = NetworkError(exc)

        assert last_error is not None
        raise last_error


def _parse_api_error(exc: "urllib.error.HTTPError") -> ApiError:
    code, message = "unexpected_error", f"request failed ({exc.code})"

    try:
        envelope = json.loads(exc.read()).get("error", {})
        if envelope.get("code"):
            code = str(envelope["code"])
            message = str(envelope.get("message", message))
    except Exception:  # noqa: BLE001
        pass

    retry_after = exc.headers.get("Retry-After") if exc.headers else None
    return ApiError(
        exc.code,
        code,
        message,
        int(retry_after) if retry_after and retry_after.isdigit() else None,
    )
