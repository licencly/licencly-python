# licencly

Verify [Licencly](https://licencly.com) licenses and check for entitled updates,
from Python.

```
pip install licencly
```

One runtime dependency (`cryptography`, for Ed25519, which Python has none of in the
standard library). HTTP uses stdlib `urllib`. Python 3.9+.

## The idea

The signed license file is the answer; the network is an optimisation. The
client reads its cache, refreshes when due, and keeps working through an outage
until the grace period is spent, so Licencly being unreachable never stops
software you have already sold.

## Quickstart

Copy the product UUID and public key from your dashboard and embed them at
build time. Fetching keys at runtime would defeat the whole scheme.

```python
from licencly import LicenclyClient, Outcome, is_network_error

client = LicenclyClient(
    product_uuid="fec65576-…",
    # Products → your product → Signing key.
    public_keys={"9f2c1a44-…": "MWvD7YE6HjI/DQ0kYGJFNG4kXlx4hP6ck1Vr4j77fzk="},
    fingerprint=machine_id(),  # yours; see below
)

decision = client.validate(user_entered_key)

if decision.outcome is Outcome.VALID:
    ...  # run
elif decision.outcome is Outcome.NOT_ACTIVE:
    show("This license has been suspended or revoked.")
elif decision.outcome is Outcome.EXPIRED:
    show("This license expired. Renew to continue.")
elif decision.outcome is Outcome.WRONG_MACHINE:
    show("This license is in use on another machine.")
elif decision.outcome is Outcome.STALE:
    show("Please connect to the internet to re-check your license.")
elif decision.outcome is Outcome.INVALID:
    show("This license file could not be verified.")
```

`validate` makes no network call at all while the cached file is still fresh.

## Offline

| When | Behaviour |
|---|---|
| Before `rev` | Cache only, no network |
| Between `rev` and `rev + grace` | Keeps working, refreshes in the background. `needs_revalidation` is true |
| After `rev + grace` | `Outcome.STALE` |

A network failure inside the grace window is **not** an error your users should
see. Check `is_network_error(err)` and stay quiet.

## Updates

```python
result = client.check_for_update(key, current_version="1.2.0", platform=sys.platform)

if result.available:
    path = client.download_artifact(key, result.release, "/tmp/updates", artifact_key)
elif result.renewal_would_unlock:
    # Not an error: a newer version exists and this license is not entitled to
    # it. result.latest names what renewing would unlock.
    show(f"Version {result.latest.version} is available with an active plan.")
```

Checking for updates never consumes a seat.

## Verifying downloads

`artifact_key` is **your own** Ed25519 public key, compiled into your
application, not fetched from Licencly. Licencly stores and serves the
signature but cannot produce one, so a compromise of Licencly cannot push code
to your users. `download_artifact` verifies the digest and that signature before
the file is moved into place; passing `None` reduces it to corruption detection.

## Packaged applications

If you ship with PyInstaller or similar, remember the public key is inside a
bundle a determined user can unpack and patch. That is true of every offline
licensing scheme, in every language. The signature stops casual sharing and
tampering with the *license*, not a reverse engineer with an afternoon.

## Machine fingerprints

The SDK does not compute one, because a good fingerprint is specific to what
you ship. It must stay stable across restarts, app updates and reboots, and
survive minor hardware change. VMs, containers and cloned disks all defeat naive
approaches. Budget more thought than it looks like it needs.

Omitting `fingerprint` disables machine binding, and a license file copied to
another machine will still verify.

## Clock tampering

Expiry is checked against a clock the user controls; rolling it back extends an
expired license offline. This is unavoidable for anything that must work without
a network.

The SDK records the furthest-forward time it has seen and rejects a jump
backwards of more than 24 hours. That is a speed bump, not a fix.

## Errors worth telling apart

| Check | Meaning |
|---|---|
| `is_network_error(err)` | Could not reach the server. Retryable, silent inside grace |
| `is_tampering(err)` | Signature or format failure. **Never retry** |
| `err.seat_limit_reached` | No free activations |
| `err.not_found` | Unknown product or key |
| `err.rate_limited` | Carries `retry_after_seconds` |

## Conformance

```
PYTHONPATH=src python -m unittest discover -s tests
```

Runs `tests/data/vectors.json`, the same suite every Licencly SDK runs. If this
SDK ever disagrees with the Go, TypeScript or .NET ones, that test fails first.
