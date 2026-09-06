"""Verify Licencly licenses and check for entitled updates.

Example::

    from licencly import LicenclyClient, Outcome

    client = LicenclyClient(
        product_uuid="fec65576-…",
        public_keys={"9f2c1a44-…": "MWvD7YE6HjI/DQ0kYGJFNG4kXlx4hP6ck1Vr4j77fzk="},
        fingerprint=machine_id(),
    )

    decision = client.validate(user_entered_key)
    if decision.outcome is not Outcome.VALID:
        ...  # decision.outcome says why
"""

from .cache import Cache, FileCache, MemoryCache, default_cache_path
from .client import VERSION, LicenclyClient
from .decision import Decision, Outcome, evaluate
from .errors import ApiError, NetworkError, is_network_error, is_tampering
from .machineid import (
    NoMachineIdError,
    machine_id,
)
from .licensefile import (
    FORMAT_VERSION,
    PREFIX,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_REVOKED,
    STATUS_SUSPENDED,
    Claims,
    LicenseFileError,
    decode,
    public_key_from_base64,
    public_key_from_raw,
    verify,
    verify_with_keys,
)
# download_artifact is deliberately not re-exported. LicenclyClient.download_artifact
# does the same job without asking for the base url, product uuid and user agent
# the client already holds, and two ways to do one thing would both be frozen at 1.0.
from .updates import ArtifactError, Release, UpdateOutcome, UpdateResult

__all__ = [
    "machine_id",
    "NoMachineIdError",
    "VERSION",
    "ApiError",
    "ArtifactError",
    "Cache",
    "Claims",
    "Decision",
    "FORMAT_VERSION",
    "FileCache",
    "LicenclyClient",
    "LicenseFileError",
    "MemoryCache",
    "NetworkError",
    "Outcome",
    "PREFIX",
    "Release",
    "STATUS_ACTIVE",
    "STATUS_EXPIRED",
    "STATUS_REVOKED",
    "STATUS_SUSPENDED",
    "UpdateOutcome",
    "UpdateResult",
    "decode",
    "default_cache_path",
    "evaluate",
    "is_network_error",
    "is_tampering",
    "public_key_from_base64",
    "public_key_from_raw",
    "verify",
    "verify_with_keys",
]
