import unittest

import netaddr

from tests._loader import load_scanner


class SingleHostTests(unittest.TestCase):
    def setUp(self):
        self.scanner = load_scanner()

    def test_host_routes_are_single_hosts(self):
        self.assertTrue(self.scanner._is_single_host(netaddr.IPNetwork("10.0.0.1/32")))
        self.assertTrue(self.scanner._is_single_host(netaddr.IPNetwork("2001:db8::1/128")))

    def test_ipv6_ranges_are_not_single_hosts(self):
        # prefixlen >= 32 used to be checked before the address family, so
        # every IPv6 range from /32 to /127 was treated as one address.
        for cidr in ("2001:db8::/64", "2001:db8::/120", "2001:db8::/32"):
            with self.subTest(cidr=cidr):
                self.assertFalse(self.scanner._is_single_host(netaddr.IPNetwork(cidr)))

    def test_ipv4_ranges_are_not_single_hosts(self):
        self.assertFalse(self.scanner._is_single_host(netaddr.IPNetwork("10.0.0.0/24")))


class ExpandTargetsTests(unittest.TestCase):
    def setUp(self):
        self.scanner = load_scanner()

    def test_expands_small_ipv6_range(self):
        ips = self.scanner._expand_targets(["2001:db8::/126"])
        self.assertGreater(len(ips), 1)
        self.assertTrue(all(ip.startswith("2001:db8::") for ip in ips))

    def test_skips_ranges_over_the_limit(self):
        # Expanding an IPv6 /64 would never finish and would exhaust memory.
        self.assertEqual(self.scanner._expand_targets(["2001:db8::/64"]), [])
        self.assertEqual(self.scanner._expand_targets(["10.0.0.0/8"]), [])

    def test_ipv4_24_expands_to_hosts(self):
        self.assertEqual(len(self.scanner._expand_targets(["192.0.2.0/24"])), 254)


if __name__ == "__main__":
    unittest.main()
