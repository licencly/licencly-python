"""Tests for the machine fingerprint helper."""

from __future__ import annotations

import re
import unittest

from licencly import machine_id
# Not from the package: these are internals, and importing them here rather than
# from licencly keeps the test honest about what the public surface is.
from licencly.machineid import (
    NoMachineIdError,
    is_virtual_name,
    machine_identity,
    stable_mac,
)

HEX32 = re.compile(r"^[0-9a-f]{32}$")
MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class MachineIdTest(unittest.TestCase):
    def test_is_stable_and_opaque(self) -> None:
        try:
            first = machine_id("product-uuid")
        except NoMachineIdError:
            self.skipTest("no stable machine identifier on this host")

        self.assertEqual(machine_id("product-uuid"), first, "not stable across calls")
        self.assertRegex(first, HEX32)

        # The raw identifier must not be recoverable from what we send. A
        # vendor's dashboard should never hold a hardware serial.
        raw, _ = machine_identity()
        self.assertNotIn(raw.lower(), first)

    def test_differs_per_salt(self) -> None:
        """Two vendors must not be able to recognise the same machine.

        Otherwise Licencly becomes a cross-product tracking network by accident.
        """
        try:
            a = machine_id("product-a")
        except NoMachineIdError:
            self.skipTest("no stable machine identifier on this host")
        self.assertNotEqual(a, machine_id("product-b"))

    def test_virtual_interfaces_are_excluded(self) -> None:
        virtual = ["docker0", "veth1a2b", "br-abc123", "virbr0", "vmnet8", "tun0", "utun3", "tailscale0", "lo"]
        physical = ["eth0", "eno1", "enp3s0", "wlan0", "wlp2s0", "en0", "Ethernet"]
        for name in virtual:
            self.assertTrue(is_virtual_name(name), f"{name} should be virtual")
        for name in physical:
            self.assertFalse(is_virtual_name(name), f"{name} should be physical")

    def test_mac_candidate_is_universally_administered(self) -> None:
        mac = stable_mac()
        if not mac:
            self.skipTest("no physical interface on this host")
        self.assertRegex(mac, MAC)
        # Bit 0x02 marks a randomised or virtual address, never an identity.
        self.assertEqual(int(mac[:2], 16) & 0x02, 0)


if __name__ == "__main__":
    unittest.main()
