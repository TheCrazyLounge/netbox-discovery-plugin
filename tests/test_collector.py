import unittest

from tests._loader import load_collector as load_module


class ParseCdpNeighborsTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_module()

    def test_prefers_management_address_over_entry_address(self):
        output = """
Device ID: edge-switch-1
Entry address(es):
  IP address: 192.168.26.3
Platform: cisco C9200-48P,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): Gi1/0/24
Management address(es):
  IP address: 10.70.52.3
"""

        parsed = self.collector._parse_cdp_neighbors(output)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["remote_ip"], "10.70.52.3")
        self.assertNotIn("_management_ips", parsed[0])
        self.assertNotIn("_candidate_ips", parsed[0])

    def test_falls_back_to_entry_address_when_management_missing(self):
        output = """
Device ID: access-switch-1
Entry address(es):
  IP address: 10.20.30.40
Platform: cisco WS-C2960,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/2,  Port ID (outgoing port): Gi0/1
"""

        parsed = self.collector._parse_cdp_neighbors(output)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["remote_ip"], "10.20.30.40")

    def test_strips_nxos_serial_from_device_id(self):
        # NX-OS reports "LEAF1(FDO21120ABC)", which never matched the NetBox
        # device, so no cable was ever created to Nexus neighbors.
        output = """
Device ID:LEAF1(FDO21120ABC)
Interface: Ethernet1/1,  Port ID (outgoing port): Ethernet1/49
"""

        parsed = self.collector._parse_cdp_neighbors(output)

        self.assertEqual(parsed[0]["remote_hostname"], "LEAF1")


class FakeCollectorDevice:
    """NAPALM stand-in where every getter is unsupported unless overridden."""

    def __init__(self, lldp=None, cli_outputs=None, cli_exc=None):
        self._lldp = lldp or {}
        self._cli_outputs = cli_outputs or {}
        self._cli_exc = cli_exc

    def get_facts(self):
        return {"hostname": "sw1"}

    def get_interfaces(self):
        return {}

    def get_interfaces_ip(self):
        return {}

    def get_vlans(self):
        raise NotImplementedError

    def get_lldp_neighbors_detail(self):
        return self._lldp

    def cli(self, commands):
        if self._cli_exc:
            raise self._cli_exc
        return {command: self._cli_outputs.get(command, "") for command in commands}


class CollectDeviceDataTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_module()

    def test_stack_step_reports_failure_when_cli_fails(self):
        # _detect_cisco_stack used to swallow the CLI error and return [], so
        # a refused 'show switch' was reported as stack=ok.
        device = FakeCollectorDevice(cli_exc=RuntimeError("session dropped"))

        data = self.collector.collect_device_data(device, "ios", "lldp", lambda _m: None)

        self.assertEqual(data["step_status"]["stack"], "fail")

    def test_lldp_and_cdp_duplicates_merge_across_naming_styles(self):
        lldp = {
            "Gi1/0/1": [
                {"remote_system_name": "sw2.corp.local", "remote_port": "Gi1/0/48"},
            ]
        }
        cdp = """
Device ID: sw2
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/48
"""
        device = FakeCollectorDevice(
            lldp=lldp, cli_outputs={"show cdp neighbors detail": cdp}
        )

        data = self.collector.collect_device_data(device, "ios", "both", lambda _m: None)

        self.assertEqual(len(data["neighbors"]), 1)
        self.assertEqual(data["neighbors"][0]["source"], "lldp")


class ParseIosVrfRouteTargetsTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_module()

    def test_parses_import_and_export_rts(self):
        output = """\
VRF BLUE (VRF Id = 2); default RD 65000:100; default VPNID <not set>
  New CLI format, supports multiple address-families
  Flags: 0x180C
  Address family ipv4 unicast (Table ID = 0x2):
  Flags: 0x0
  Export VPN route-target communities
    RT:65000:100   RT:65000:200
  Import VPN route-target communities
    RT:65000:100   RT:65000:300
"""
        result = self.collector._parse_ios_vrf_route_targets(output)

        self.assertEqual(result["BLUE"]["export"], ["65000:100", "65000:200"])
        self.assertEqual(result["BLUE"]["import"], ["65000:100", "65000:300"])

    def test_skips_no_export_and_no_import_lines(self):
        output = """\
VRF MGMT (VRF Id = 1); default RD <not set>; default VPNID <not set>
  No Export VPN route-target communities
  No Import VPN route-target communities
"""
        result = self.collector._parse_ios_vrf_route_targets(output)

        self.assertEqual(result.get("MGMT", {}).get("export", []), [])
        self.assertEqual(result.get("MGMT", {}).get("import", []), [])

    def test_skips_default_and_global_vrf(self):
        output = """\
VRF default; default RD <not set>
  Export VPN route-target communities
    RT:65000:1
VRF global; default RD <not set>
  Export VPN route-target communities
    RT:65000:2
VRF PROD; default RD 65000:50
  Export VPN route-target communities
    RT:65000:50
"""
        result = self.collector._parse_ios_vrf_route_targets(output)

        self.assertNotIn("default", result)
        self.assertNotIn("global", result)
        self.assertIn("PROD", result)

    def test_handles_multiple_vrfs(self):
        output = """\
VRF RED; default RD 65000:10
  Export VPN route-target communities
    RT:65000:10
  Import VPN route-target communities
    RT:65000:10

VRF BLUE; default RD 65000:20
  Export VPN route-target communities
    RT:65000:20
  Import VPN route-target communities
    RT:65000:20   RT:65000:10
"""
        result = self.collector._parse_ios_vrf_route_targets(output)

        self.assertEqual(result["RED"]["export"], ["65000:10"])
        self.assertEqual(result["BLUE"]["import"], ["65000:20", "65000:10"])


class ParseNxosVrfRouteTargetsTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_module()

    def test_parses_import_and_export_rts(self):
        output = """\
VRF-Name: BLUE, VRF-ID: 3, State: Up, MPLS: Disabled
  RD: 65000:100
  RT import             : 65000:100  65000:200
  RT export             : 65000:100
"""
        result = self.collector._parse_nxos_vrf_route_targets(output)

        self.assertEqual(result["BLUE"]["import"], ["65000:100", "65000:200"])
        self.assertEqual(result["BLUE"]["export"], ["65000:100"])

    def test_handles_rt_both(self):
        output = """\
VRF-Name: SHARED, VRF-ID: 5, State: Up
  RD: 65000:999
  RT both               : 65000:999
"""
        result = self.collector._parse_nxos_vrf_route_targets(output)

        self.assertEqual(result["SHARED"]["import"], ["65000:999"])
        self.assertEqual(result["SHARED"]["export"], ["65000:999"])

    def test_skips_default_vrf(self):
        output = """\
VRF-Name: default, VRF-ID: 1, State: Up
  RT import             : 65000:1
VRF-Name: PROD, VRF-ID: 2, State: Up
  RT import             : 65000:10
  RT export             : 65000:10
"""
        result = self.collector._parse_nxos_vrf_route_targets(output)

        self.assertNotIn("default", result)
        self.assertIn("PROD", result)


if __name__ == "__main__":
    unittest.main()


class ParseInventoryOutputTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_module()

    def test_keeps_multiple_cisco_inventory_entries(self):
        output = """
NAME: "Chassis", DESCR: "Cisco C8500 Chassis"
PID: C8500L-8S4X    , VID: V01, SN: FLX263604LE

NAME: "module R0", DESCR: "Route Processor"
PID: C8500-RP       , VID: V01, SN: FOC12345678

NAME: "Power Supply Module 0", DESCR: "Cisco 650W AC Power Supply"
PID: PWR-650WAC-R   , VID: V01, SN: DCA12345678
"""

        parsed = self.collector._parse_inventory_output(output, "ios")

        self.assertEqual([item["name"] for item in parsed], [
            "Chassis",
            "module R0",
            "Power Supply Module 0",
        ])

    def test_keeps_entries_when_pid_or_serial_is_blank(self):
        output = """
NAME: "Power Supply Module 1", DESCR: "Cisco 650W AC Power Supply"
PID:                 , VID: V01, SN:

NAME: "Fan Tray", DESCR: "Fan Tray"
PID: FAN-TRAY-1      , VID: V01, SN:
"""

        parsed = self.collector._parse_inventory_output(output, "ios")

        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["name"], "Power Supply Module 1")
        self.assertEqual(parsed[0]["pid"], "")
        self.assertEqual(parsed[0]["serial"], "")
        self.assertEqual(parsed[1]["name"], "Fan Tray")
        self.assertEqual(parsed[1]["pid"], "FAN-TRAY-1")
        self.assertEqual(parsed[1]["serial"], "")


class NormalizeMacTableTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_module()

    def test_uppercases_mac_and_drops_blank_entries(self):
        entries = [
            {"mac": "aa:bb:cc:dd:ee:ff", "interface": "Gi0/1", "vlan": 10},
            {"mac": "", "interface": "Gi0/2", "vlan": 10},
            {"mac": "11:22:33:44:55:66", "interface": "", "vlan": 20},
        ]

        out = self.collector._normalize_mac_table(entries)

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(out[0]["vlan"], 10)
        self.assertEqual(out[0]["interface"], "Gi0/1")

    def test_dedupes_duplicate_entries(self):
        entries = [
            {"mac": "aa:bb:cc:dd:ee:ff", "interface": "Gi0/1", "vlan": 10},
            {"mac": "AA:BB:CC:DD:EE:FF", "interface": "gi0/1", "vlan": 10},
        ]

        out = self.collector._normalize_mac_table(entries)

        self.assertEqual(len(out), 1)

    def test_clamps_invalid_vlan_to_zero(self):
        entries = [
            {"mac": "aa:bb:cc:dd:ee:ff", "interface": "Gi0/1", "vlan": 9999},
            {"mac": "11:22:33:44:55:66", "interface": "Gi0/2", "vlan": "not-a-vlan"},
            {"mac": "77:88:99:aa:bb:cc", "interface": "Gi0/3", "vlan": None},
        ]

        out = self.collector._normalize_mac_table(entries)

        self.assertEqual(len(out), 3)
        self.assertEqual(out[0]["vlan"], 0)
        self.assertEqual(out[1]["vlan"], 0)
        self.assertEqual(out[2]["vlan"], 0)

    def test_preserves_static_and_active_flags(self):
        entries = [
            {"mac": "aa:bb:cc:dd:ee:ff", "interface": "Gi0/1", "vlan": 10,
             "static": True, "active": False},
        ]

        out = self.collector._normalize_mac_table(entries)

        self.assertTrue(out[0]["static"])
        self.assertFalse(out[0]["active"])
