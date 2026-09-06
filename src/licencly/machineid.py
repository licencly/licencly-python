"""A stable, hashed machine identifier for ``LicenclyClient(fingerprint=...)``."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

# Only machine_id and its error are public. machine_identity, stable_mac and
# is_virtual_name are how the fingerprint is derived, not something an
# application calls, and at 1.0 every name in __all__ becomes a promise that
# cannot be withdrawn without a major version. The Go SDK never exported them.
__all__ = ["NoMachineIdError", "machine_id"]


class NoMachineIdError(RuntimeError):
    """No stable identifier could be read.

    Rare, and it means machine binding is unavailable on that host rather than
    that anything is wrong: handle it by validating with an empty fingerprint.
    """

    def __init__(self) -> None:
        super().__init__("licencly: no stable machine identifier found")


#: Interfaces created by software rather than shipped with the machine. Their
#: addresses come and go with a container or a VPN, so a fingerprint built on
#: one is not stable.
VIRTUAL_PREFIXES = (
    "docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "vnic",
    "tun", "tap", "utun", "wg", "tailscale", "zt", "ham", "lo",
)

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def machine_id(salt: str) -> str:
    """A stable, hashed identifier for the machine this runs on.

    What it reads, in order:

    * Linux: ``/etc/machine-id``, then ``/var/lib/dbus/machine-id``
    * macOS: ``IOPlatformUUID``
    * Windows: ``HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid``
    * anywhere: the MAC address of the first physical network interface

    The operating system's own identifier is preferred over a MAC address
    deliberately. A MAC changes when someone plugs in a dock, modern systems
    randomise Wi-Fi MACs per network, and any machine with Docker or a VPN
    installed has several. The OS identifier survives all of that, survives a
    RAM or disk upgrade, and does not survive being copied to another machine,
    which is exactly the line a seat limit wants.

    The result is hashed with ``salt``, so no raw hardware identifier ever
    leaves the machine and the same computer produces a different id for every
    vendor. Pass your product UUID.

    :raises NoMachineIdError: when nothing stable could be read.
    """
    raw, source = machine_identity()
    # The source is mixed in so a MAC address and an OS identifier that happen
    # to be the same string could never collide.
    payload = f"{salt}\0{source}\0{raw}".encode()
    return hashlib.sha256(payload).hexdigest()[:32]


def machine_identity() -> Tuple[str, str]:
    """The rawest identifier available, and where it came from."""
    if sys.platform.startswith("linux"):
        # systemd writes the first; the second is the older D-Bus location and
        # is still the only one present on some minimal images.
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            value = _read_trimmed(path)
            if value:
                return value, "machine-id"
    elif sys.platform == "darwin":
        value = _darwin_platform_uuid()
        if value:
            return value, "ioplatformuuid"
    elif sys.platform == "win32":
        value = _windows_machine_guid()
        if value:
            return value, "machineguid"

    mac = stable_mac()
    if mac:
        return mac, "mac"
    raise NoMachineIdError()


def _read_trimmed(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def _darwin_platform_uuid() -> str:
    """The hardware UUID macOS assigns to the logic board."""
    out = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    for line in out.splitlines():
        if "IOPlatformUUID" not in line:
            continue
        # The line looks like:  "IOPlatformUUID" = "0A1B2C3D-…"
        at = line.find('= "')
        if at >= 0:
            value = line[at + 2 :].strip().strip('"')
            if value:
                return value
    return ""


def _windows_machine_guid() -> str:
    """The value Windows generates at install time.

    Shelling out to reg.exe rather than reading the registry keeps this package
    to a single dependency, which matters more than one process at startup.
    """
    out = _run(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].lower() == "machineguid":
            return fields[-1]
    return ""


def _run(args: List[str]) -> str:
    try:
        # Bounded so a wedged helper cannot hang an application's startup.
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=2, check=False
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def stable_mac() -> str:
    """The hardware address of the most plausible physical interface.

    Interfaces that are merely down are still considered: a laptop with the
    ethernet cable out must not get a different fingerprint from the same
    laptop plugged in.
    """
    candidates = []
    for name, mac in _interfaces():
        if is_virtual_name(name) or not _MAC_RE.match(mac) or mac == "00:00:00:00:00:00":
            continue
        # Bit 0x02 of the first octet marks a locally administered address:
        # randomised Wi-Fi, container bridges and most virtual adapters. Never
        # stable, so never a fingerprint.
        if int(mac[:2], 16) & 0x02:
            continue
        candidates.append((name, mac))

    if not candidates:
        return ""
    # Sorted by name so a machine with two cards answers the same way every
    # launch, whatever order the OS happened to enumerate them in.
    candidates.sort()
    return candidates[0][1]


def _interfaces() -> List[Tuple[str, str]]:
    """Interface name and MAC pairs, without adding a dependency.

    ``psutil`` would be the obvious way to do this and is deliberately not a
    dependency: the whole package asks for ``cryptography`` and nothing else.
    """
    out: List[Tuple[str, str]] = []
    sysfs = Path("/sys/class/net")
    if sysfs.is_dir():
        for entry in sorted(sysfs.iterdir()):
            address = entry / "address"
            try:
                out.append((entry.name, address.read_text().strip().lower()))
            except OSError:
                continue
        return out

    # macOS and Windows: parse the platform's own listing rather than guessing.
    if sys.platform == "darwin":
        text = _run(["ifconfig"])
        name = ""
        for line in text.splitlines():
            if line and not line[0].isspace():
                name = line.split(":", 1)[0]
            elif "ether " in line and name:
                out.append((name, line.split("ether ", 1)[1].strip().lower()))
    elif sys.platform == "win32":
        text = _run(["getmac", "/v", "/fo", "csv", "/nh"])
        for line in text.splitlines():
            parts = [p.strip('" ') for p in line.split('","')]
            if len(parts) >= 3:
                out.append((parts[0], parts[2].replace("-", ":").lower()))
    return out


def is_virtual_name(name: str) -> bool:
    lower = name.lower()
    return any(lower.startswith(prefix) for prefix in VIRTUAL_PREFIXES)
