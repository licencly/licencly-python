"""Errors a caller has to tell apart.

Collapsing these into one exception type is the most common way to make a
licensing integration unsupportable: "it doesn't work" means something different
for each.
"""

from __future__ import annotations

from typing import Optional

from .licensefile import LicenseFileError


class NetworkError(Exception):
    """Could not reach Licencly.

    Retryable, and inside the grace window it is not something the user should
    be shown.
    """

    def __init__(self, cause: BaseException) -> None:
        super().__init__(f"licencly: could not reach the server: {cause}")
        self.cause = cause


class ApiError(Exception):
    """A structured refusal from the server."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        retry_after_seconds: Optional[int] = None,
    ) -> None:
        super().__init__(f"licencly: {message} ({code})")
        self.status = status
        self.code = code
        self.retry_after_seconds = retry_after_seconds

    @property
    def not_found(self) -> bool:
        """Unknown product, unknown key, or a malformed one.

        The server deliberately does not distinguish them: that would let anyone
        probe which keys are real.
        """
        return self.status == 404

    @property
    def seat_limit_reached(self) -> bool:
        """In use on the maximum number of machines.

        Distinguished from :attr:`not_found` because the holder has proved they
        own a real key and needs to be told to free a seat.
        """
        return self.code == "seat_limit_reached"

    @property
    def rate_limited(self) -> bool:
        return self.status == 429


def is_network_error(err: BaseException) -> bool:
    return isinstance(err, NetworkError)


def is_tampering(err: BaseException) -> bool:
    """The license file failed verification.

    Never retry these: retrying obscures an attack and fixes nothing.
    """
    return isinstance(err, LicenseFileError)
