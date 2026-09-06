"""Behaviour tests for the client: caching, the offline grace window, and the
error boundaries a caller has to act on."""

from __future__ import annotations

import base64
import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from licencly import (
    ApiError,
    LicenclyClient,
    MemoryCache,
    NetworkError,
    Outcome,
    UpdateOutcome,
    is_network_error,
)
from licencly.licensefile import FORMAT_VERSION, PREFIX

KID = "test-key-1"
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign(private_key: Ed25519PrivateKey, claims: dict) -> str:
    payload = b64url(json.dumps({**claims, "v": FORMAT_VERSION, "kid": KID}).encode())
    signed = f"{PREFIX}.{payload}"
    return f"{signed}.{b64url(private_key.sign(signed.encode('ascii')))}"


def active_claims(now: datetime) -> dict:
    seconds = int(now.timestamp())
    return {
        "lic": "license-uuid",
        # Every file the server issues names the license it is for, and the
        # client now checks it: a cache keyed on the product alone would
        # otherwise answer for whichever license was validated last.
        "key": "KEY",
        "prd": "product-uuid",
        "st": "active",
        "seats": 5,
        "used": 1,
        "fp": "machine-abc",
        "iat": seconds - 3600,
        "exp": 0,
        "mnt": 0,
        "rev": seconds + 7 * 24 * 3600,
        "grace": 7 * 24 * 3600,
    }


class Fixture:
    """A real HTTP server plus a client pointed at it."""

    def __init__(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_raw = self.private_key.public_key().public_bytes_raw()

        self.now = NOW
        self.calls = 0
        self.status = 0
        self.claims_fn = active_claims
        self.signing_key = self.private_key

        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                fixture.calls += 1
                if fixture.status:
                    body = json.dumps(
                        {"error": {"code": "seat_limit_reached", "message": "no free seats"}}
                    ).encode()
                    self.send_response(fixture.status)
                else:
                    token = sign(fixture.signing_key, fixture.claims_fn(fixture.now))
                    body = json.dumps({"license": token, "status": "active"}).encode()
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # keep the test output readable
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        self.cache = MemoryCache()
        self.client = LicenclyClient(
            product_uuid="product-uuid",
            public_keys={KID: base64.b64encode(self.public_raw).decode()},
            fingerprint="machine-abc",
            cache=self.cache,
            base_url=f"http://127.0.0.1:{self.server.server_port}",
            retries=0,
            now=lambda: self.now,
        )

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class ClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def test_fetches_once_then_serves_from_cache(self):
        decision = self.f.client.validate("KEY")
        self.assertIs(decision.outcome, Outcome.VALID)
        self.assertFalse(decision.from_cache)
        self.assertEqual(self.f.calls, 1)

        # Inside the revalidation window, so no network call at all. An app that
        # phones home on every launch is an app that fails to launch on a plane.
        decision = self.f.client.validate("KEY")
        self.assertIs(decision.outcome, Outcome.VALID)
        self.assertTrue(decision.from_cache)
        self.assertEqual(self.f.calls, 1, "a second validate hit the network")

    def test_server_down_inside_grace_keeps_working(self):
        self.f.client.validate("KEY")
        self.f.close()

        self.f.now = NOW + timedelta(days=8)

        decision = self.f.client.validate("KEY")
        self.assertIs(decision.outcome, Outcome.VALID, "an outage must not stop a paid license")
        self.assertTrue(decision.from_cache)
        self.assertTrue(decision.needs_revalidation)

    def test_past_grace_is_stale(self):
        self.f.client.validate("KEY")
        self.f.close()

        self.f.now = NOW + timedelta(days=20)
        self.assertIs(self.f.client.validate("KEY").outcome, Outcome.STALE)

    def test_revocation_takes_effect_on_refresh(self):
        self.assertIs(self.f.client.validate("KEY").outcome, Outcome.VALID)

        self.f.claims_fn = lambda now: {**active_claims(now), "st": "revoked"}
        self.f.now = NOW + timedelta(days=8)

        self.assertIs(self.f.client.validate("KEY").outcome, Outcome.NOT_ACTIVE)

    def test_unverifiable_response_is_not_cached(self):
        # A different key: the response is well-formed but untrusted.
        self.f.signing_key = Ed25519PrivateKey.generate()

        self.assertIs(self.f.client.validate("KEY").outcome, Outcome.INVALID)

        cached, _ = self.f.cache.load()
        self.assertEqual(cached, "", "an unverifiable file was written to the cache")

    def test_large_backward_clock_jump_is_rejected(self):
        self.f.client.validate("KEY")
        self.f.now = NOW - timedelta(days=90)

        self.assertIs(self.f.client.validate("KEY").outcome, Outcome.INVALID)

    def test_api_errors_stay_distinguishable(self):
        self.f.status = 409

        with self.assertRaises(ApiError) as caught:
            self.f.client.validate("KEY")

        self.assertTrue(
            caught.exception.seat_limit_reached,
            "a caller cannot tell the user to free a seat",
        )
        self.assertFalse(is_network_error(caught.exception))

    def test_network_failure_with_no_cache_is_retryable(self):
        self.f.close()

        with self.assertRaises(Exception) as caught:
            self.f.client.validate("KEY")

        self.assertTrue(
            is_network_error(caught.exception),
            f"got {caught.exception!r}, want a NetworkError",
        )

    def test_client_that_cannot_verify_is_refused(self):
        with self.assertRaises(ValueError):
            LicenclyClient(product_uuid="", public_keys={KID: "x"})
        with self.assertRaises(ValueError):
            LicenclyClient(product_uuid="p", public_keys={})


if __name__ == "__main__":
    unittest.main()


class PublicSurfaceTest(unittest.TestCase):
    """The whole advertised surface must actually be reachable on the client.

    This exists because `check_for_update` and `download_artifact` once shipped
    indented one level too far, which left them as dead nested functions inside
    a module-level helper. The package imported cleanly, the README documented
    both, and neither existed at runtime. Nothing caught it because nothing
    referenced them.
    """

    def test_documented_methods_are_bound_to_the_client(self):
        for name in ("validate", "deactivate", "clear_cache", "check_for_update", "download_artifact"):
            with self.subTest(method=name):
                self.assertTrue(
                    callable(getattr(LicenclyClient, name, None)),
                    f"LicenclyClient.{name} is missing or not callable",
                )

    def test_outcomes_format_as_their_wire_value(self):
        # A vendor logging an outcome must get the same spelling the API uses,
        # and the same one the other three SDKs print.
        self.assertEqual(f"{Outcome.VALID}", "valid")
        self.assertEqual(f"{Outcome.WRONG_MACHINE}", "wrong_machine")
        self.assertEqual(f"{UpdateOutcome.MAINTENANCE_LAPSED}", "maintenance_lapsed")


class CacheBelongsToTheLicenseTest(unittest.TestCase):
    """The cache is keyed on the product, so it holds the previous license.

    Validating a different key must not answer with the old one. A customer
    upgrading from a trial to a paid key, or replacing a revoked key, would
    otherwise keep being told about the license they just stopped using.
    """

    def setUp(self) -> None:
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def test_a_cached_file_for_another_license_is_not_reused(self) -> None:
        first = self.f.client.validate("KEY")
        self.assertIs(first.outcome, Outcome.VALID)
        self.assertEqual(self.f.calls, 1)

        # Same product, different key. The cached file is fresh, so the old
        # behaviour returned it without a single network call.
        second = self.f.client.validate("OTHER-KEY")
        self.assertEqual(self.f.calls, 2, "must go to the server for a different license")
        self.assertFalse(second.from_cache)

    def test_offline_with_a_cache_for_another_license_raises(self) -> None:
        self.f.client.validate("KEY")
        self.f.close()

        # Falling back to the cache would report the wrong customer, the wrong
        # expiry and the wrong seat count. Failing is the lesser evil.
        with self.assertRaises(NetworkError):
            self.f.client.validate("OTHER-KEY")
