"""Tests for the artifact download path.

This is what backs the claim that a compromise of Licencly cannot push code to
a vendor's users. Each test here checks a way that guarantee could be lost.
"""

from __future__ import annotations

import hashlib
import http.server
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from licencly import ArtifactError
from licencly.updates import Release, download_artifact


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class ArtifactServer:
    """Serves one body, optionally with a signature header."""

    def __init__(self, body: bytes, signature: str | None = None) -> None:
        self.body, self.signature = body, signature
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                if outer.signature:
                    self.send_header("X-Artifact-Signature", outer.signature)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):  # keep the suite quiet
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def release(body: bytes, *, digest: str | None = None, filename: str = "app.bin") -> Release:
    return Release(
        uuid="rel-1",
        version="4.0.0",
        channel="stable",
        platform="",
        arch="",
        notes="",
        min_upgrade_from="",
        artifact_size=len(body),
        artifact_sha256=digest if digest is not None else sha256_hex(body),
        artifact_filename=filename,
        signed=False,
    )


class DownloadArtifactTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())

    def fetch(self, server: ArtifactServer, rel: Release, key=None, dest: Path | None = None):
        return download_artifact(
            base_url=server.url,
            product_uuid="product-uuid",
            license_key="KEY",
            release=rel,
            dest_dir=dest or self.dir,
            artifact_key=key,
            user_agent="licencly-python/test",
        )

    def test_a_verified_artifact_is_written(self) -> None:
        body = b"this is a release artifact"
        server = ArtifactServer(body)
        self.addCleanup(server.close)

        path = self.fetch(server, release(body, filename="acme-cad-4.0.0.bin"))
        self.assertEqual(Path(path).read_bytes(), body)
        self.assertEqual(Path(path).name, "acme-cad-4.0.0.bin")

    def test_a_checksum_mismatch_leaves_nothing_behind(self) -> None:
        server = ArtifactServer(b"tampered bytes")
        self.addCleanup(server.close)

        with self.assertRaises(ArtifactError):
            self.fetch(server, release(b"tampered bytes", digest=sha256_hex(b"expected")))
        self.assertEqual(list(self.dir.iterdir()), [], "a refused artifact was left on disk")

    def test_a_foreign_signature_leaves_nothing_behind(self) -> None:
        """Bytes that pass the checksum but were not signed by the vendor."""
        body = b"substituted release"
        attacker = Ed25519PrivateKey.generate()
        vendor = Ed25519PrivateKey.generate().public_key()

        import base64

        server = ArtifactServer(body, base64.b64encode(attacker.sign(body)).decode())
        self.addCleanup(server.close)

        with self.assertRaises(ArtifactError):
            self.fetch(server, release(body), key=vendor)
        self.assertEqual(list(self.dir.iterdir()), [], "a refused artifact was left on disk")

    def test_an_unsigned_artifact_is_refused_when_a_key_was_given(self) -> None:
        """Not a silent downgrade to a checksum."""
        body = b"unsigned release"
        vendor = Ed25519PrivateKey.generate().public_key()

        server = ArtifactServer(body)
        self.addCleanup(server.close)

        with self.assertRaises(ArtifactError):
            self.fetch(server, release(body), key=vendor)
        self.assertEqual(list(self.dir.iterdir()), [], "a refused artifact was left on disk")

    def test_a_filename_cannot_escape_the_destination(self) -> None:
        """The filename comes from the server and must not place files elsewhere."""
        body = b"release"
        dest = self.dir / "downloads"

        for name in ("../escaped.bin", "../../escaped.bin", "/etc/escaped.bin", ""):
            server = ArtifactServer(body)
            try:
                path = Path(self.fetch(server, release(body, filename=name), dest=dest)).resolve()
                self.assertTrue(
                    str(path).startswith(str(dest.resolve()) + "/"),
                    f"filename {name!r} wrote to {path}, outside {dest}",
                )
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
