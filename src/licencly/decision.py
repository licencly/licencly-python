"""The result of evaluating a license."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .licensefile import STATUS_ACTIVE, STATUS_EXPIRED, Claims


class Outcome(str, Enum):
    """Fixed and shared by every Licencly SDK."""

    # Format as the wire value, not "Outcome.VALID", so logs match the API and
    # the other three SDKs. See the same note in updates.py.
    __str__ = str.__str__

    #: Verified and inside its window. Run.
    VALID = "valid"
    #: Signature or format failure. Tampering, not a network problem: refuse,
    #: and do not retry.
    INVALID = "invalid"
    #: Suspended, revoked, or expired by status.
    NOT_ACTIVE = "not_active"
    #: Past its expiry date.
    EXPIRED = "expired"
    #: Issued to a different machine.
    WRONG_MACHINE = "wrong_machine"
    #: The offline grace period is spent and the server could not be reached.
    STALE = "stale"


@dataclass(frozen=True)
class Decision:
    """What an application acts on."""

    outcome: Outcome
    #: Populated whenever the signature verified, even for an expired or revoked
    #: license, so an app can say *which* license expired.
    claims: Optional[Claims] = None
    #: True inside the grace window: keep running, refresh in the background.
    needs_revalidation: bool = False
    #: No network call was made, or one failed and the cached file was used.
    from_cache: bool = False
    #: Whether this license is entitled to releases published now.
    maintenance_active: bool = False
    error: Optional[BaseException] = None

    @property
    def ok(self) -> bool:
        """The single check an application should gate on."""
        return self.outcome is Outcome.VALID


def evaluate(
    claims: Optional[Claims],
    error: Optional[BaseException],
    now: datetime,
    fingerprint: str,
    from_cache: bool,
) -> Decision:
    """Maps a verification result onto an :class:`Outcome`.

    Kept in one place so the mapping cannot drift between the cached and
    freshly-fetched paths.
    """
    if claims is None or error is not None:
        return Decision(outcome=Outcome.INVALID, error=error, from_cache=from_cache)

    common = {
        "claims": claims,
        "needs_revalidation": claims.needs_revalidation(now),
        "from_cache": from_cache,
        "maintenance_active": claims.maintenance_active(now),
    }
    seconds = int(now.replace(tzinfo=now.tzinfo or timezone.utc).timestamp())

    # An expired status is an expiry, not a generic refusal. The server derives
    # the status when it signs, so a licence past its date arrives as "expired"
    # rather than "active" with a stale date. Checking the status first made
    # Outcome.EXPIRED unreachable in practice, and told a customer who needed to
    # renew that they had been suspended or revoked.
    if claims.status == STATUS_EXPIRED:
        return Decision(outcome=Outcome.EXPIRED, **common)
    if claims.status != STATUS_ACTIVE:
        return Decision(outcome=Outcome.NOT_ACTIVE, **common)
    if claims.expires_at != 0 and seconds > claims.expires_at:
        return Decision(outcome=Outcome.EXPIRED, **common)
    if claims.fingerprint and fingerprint and claims.fingerprint != fingerprint:
        return Decision(outcome=Outcome.WRONG_MACHINE, **common)
    if claims.revalidate_after != 0 and seconds > claims.revalidate_after + claims.grace_seconds:
        return Decision(outcome=Outcome.STALE, **common)
    return Decision(outcome=Outcome.VALID, **common)
