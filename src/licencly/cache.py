"""Persisting the last good license file between runs.

Without a cache, every launch needs the network and the offline guarantee is
worthless.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

_EPOCH = datetime.fromtimestamp(0, tz=timezone.utc)


class Cache(ABC):
    @abstractmethod
    def load(self) -> Tuple[str, datetime]:
        """Returns the cached file and the furthest-forward time seen."""

    @abstractmethod
    def save(self, file: str, highest_seen: datetime) -> None: ...

    @abstractmethod
    def clear(self) -> None: ...


class FileCache(Cache):
    """Stores the file in the user's data directory.

    Per-user and writable without privileges on purpose: an application that
    needs admin rights to cache a license will not have them when it matters.
    """

    def __init__(self, path: os.PathLike | str) -> None:
        self.path = Path(path)

    def load(self) -> Tuple[str, datetime]:
        try:
            envelope = json.loads(self.path.read_text("utf-8"))
        except Exception:  # noqa: BLE001
            # A missing cache is the normal first-run state. A corrupt one is
            # treated as absent rather than invalid: telling a user their
            # license is broken because a disk hiccup truncated a file we can
            # simply refetch would be wrong.
            return "", _EPOCH

        seen = datetime.fromtimestamp(int(envelope.get("highest_seen", 0)), tz=timezone.utc)
        return str(envelope.get("file", "")), seen

    def save(self, file: str, highest_seen: datetime) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        payload = json.dumps(
            {
                # Stored verbatim. Re-serialising risks changing the exact bytes
                # the signature covers.
                "file": file,
                "highest_seen": int(highest_seen.timestamp()),
            }
        )

        # Write and rename, so an interrupted save cannot leave a half-written
        # cache that reads as corrupt on next launch.
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".license-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


class MemoryCache(Cache):
    """Holds the file for the process lifetime only.

    Useful in tests and in short-lived jobs where writing to disk is unwelcome.
    """

    def __init__(self) -> None:
        self._file = ""
        self._seen = _EPOCH

    def load(self) -> Tuple[str, datetime]:
        return self._file, self._seen

    def save(self, file: str, highest_seen: datetime) -> None:
        self._file, self._seen = file, highest_seen

    def clear(self) -> None:
        self._file, self._seen = "", _EPOCH


def default_cache_path(product_slug: str) -> Path:
    """An OS-appropriate per-user location for the cached license."""
    name = f"{_sanitize(product_slug)}.license"

    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))

    return base / "licencly" / name


def _sanitize(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "-", value).strip("-")
    return cleaned or "license"
