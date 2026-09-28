import unittest

from tests._loader import load_naming


class CanonicalInterfaceNameTests(unittest.TestCase):
    def setUp(self):
        self.naming = load_naming()

    def test_expands_cisco_abbreviations(self):
        cases = {
            "Gi1/0/1": "GigabitEthernet1/0/1",
            "Gig 1/0/1": "GigabitEthernet1/0/1",
            "Te1/1/1": "TenGigabitEthernet1/1/1",
            "Eth1/1": "Ethernet1/1",
            "Po10": "Port-channel10",
            "Lo0": "Loopback0",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(self.naming.canonical_interface_name(raw), expected)

    def test_leaves_full_and_non_cisco_names_unchanged(self):
        # These used to be rewritten (mgmt0 -> Management0, ae0 ->
        # Port-Channel0, ...). The renamed copies no longer matched the real
        # interfaces, which pruning then deleted along with their cables.
        for name in (
            "mgmt0",
            "ae0",
            "lo0",
            "lo0.0",
            "eth0",
            "port-channel1",
            "Port-channel1",
            "GigabitEthernet1/0/1",
            "TwentyFiveGigE1/0/1",
            "Management1",
            "Vlan10",
            "ge-0/0/0",
            "port1",
        ):
            with self.subTest(name=name):
                self.assertEqual(self.naming.canonical_interface_name(name), name)

    def test_legacy_mapping_reproduces_old_names(self):
        # Used to find interfaces stored by earlier versions so they can be
        # renamed rather than duplicated.
        self.assertEqual(self.naming.legacy_canonical_interface_name("mgmt0"), "Management0")
        self.assertEqual(self.naming.legacy_canonical_interface_name("ae0"), "Port-Channel0")
        self.assertEqual(
            self.naming.legacy_canonical_interface_name("port-channel1"), "Port-Channel1"
        )

    def test_interface_name_key_matches_abbreviated_and_full_names(self):
        key = self.naming.interface_name_key
        self.assertEqual(key("Gi1/0/1"), key("GigabitEthernet1/0/1"))
        self.assertEqual(key("Po1"), key("port-channel1"))


class DeviceIdTests(unittest.TestCase):
    def setUp(self):
        self.naming = load_naming()

    def test_strips_nxos_serial_suffix(self):
        self.assertEqual(self.naming.strip_device_id_serial("LEAF1(FDO21120ABC)"), "LEAF1")
        self.assertEqual(
            self.naming.strip_device_id_serial("leaf1.corp.local(FDO21120ABC)"), "leaf1.corp.local"
        )

    def test_leaves_plain_names_alone(self):
        self.assertEqual(self.naming.strip_device_id_serial("core-sw1.corp"), "core-sw1.corp")
        self.assertEqual(self.naming.strip_device_id_serial(""), "")

    def test_base_hostname(self):
        self.assertEqual(self.naming.base_hostname("Router1.EMEA.local"), "router1")
        self.assertEqual(self.naming.base_hostname(""), "")


if __name__ == "__main__":
    unittest.main()
