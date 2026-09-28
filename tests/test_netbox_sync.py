import sys
import types
import unittest
from unittest import mock

from tests._loader import FakeIntegrityError as tests_loader_integrity_error
from tests._loader import FakeMultipleObjectsReturned, make_django_db_stub
from tests._loader import load_netbox_sync as load_module


def _matches(obj, criteria):
    for key, expected in criteria.items():
        if key.endswith("__net_host"):
            attr = key[: -len("__net_host")]
            if str(getattr(obj, attr, "")).split("/")[0] != str(expected):
                return False
            continue
        if key.endswith("__iexact"):
            attr = key[:-8]
            actual = getattr(obj, attr, "")
            if str(actual).lower() != str(expected).lower():
                return False
            continue
        actual = getattr(obj, key, None)
        if actual != expected:
            return False
    return True


class FakeQuerySet(list):
    def first(self):
        return self[0] if self else None

    def exclude(self, **criteria):
        return FakeQuerySet([obj for obj in self if not _matches(obj, criteria)])

    def count(self):
        return len(self)

    def order_by(self, *fields):
        """Sort by the given attribute names, supporting a leading '-'."""
        result = FakeQuerySet(self)
        for field in reversed(fields):
            reverse = field.startswith("-")
            key = field.lstrip("-")
            result = FakeQuerySet(
                sorted(result, key=lambda obj: getattr(obj, key, None), reverse=reverse)
            )
        return result


class FakeM2MManager:
    def __init__(self):
        self._items = []

    def values_list(self, field, flat=False):
        return [getattr(item, field) for item in self._items]

    def add(self, item):
        self._items.append(item)

    def filter(self, **criteria):
        return FakeQuerySet([obj for obj in self._items if _matches(obj, criteria)])

    def all(self):
        return list(self._items)


class FakeVRF:
    objects = None

    def __init__(self, pk, name, rd=""):
        self.pk = pk
        self.name = name
        self.rd = rd
        self.save_calls = 0
        self.import_targets = FakeM2MManager()
        self.export_targets = FakeM2MManager()

    def save(self):
        self.save_calls += 1


class FakeVRFManager:
    def __init__(self, rows):
        self.rows = rows
        self.next_pk = max((row.pk for row in rows), default=0) + 1

    def filter(self, **criteria):
        return FakeQuerySet([row for row in self.rows if _matches(row, criteria)])

    def create(self, **kwargs):
        row = FakeVRF(pk=self.next_pk, name=kwargs["name"], rd=kwargs.get("rd", ""))
        self.next_pk += 1
        self.rows.append(row)
        return row


class FakeRouteTarget:
    objects = None

    def __init__(self, pk, name):
        self.pk = pk
        self.name = name


class FakeRouteTargetManager:
    model = types.SimpleNamespace(MultipleObjectsReturned=FakeMultipleObjectsReturned)

    def __init__(self):
        self.store = {}
        self.next_pk = 1

    def filter(self, **criteria):
        return FakeQuerySet([rt for rt in self.store.values() if _matches(rt, criteria)])

    def get_or_create(self, name, defaults=None):
        if name in self.store:
            return self.store[name], False
        rt = FakeRouteTarget(pk=self.next_pk, name=name)
        self.next_pk += 1
        self.store[name] = rt
        return rt, True


_FAKE_IFACE_CT = object()  # sentinel — acts as the Interface ContentType


class FakeContentTypeManager:
    def get_for_model(self, model):
        return _FAKE_IFACE_CT


class FakeContentType:
    objects = FakeContentTypeManager()


class FakeDevice:
    def __init__(self, pk=1, name="test-device"):
        self.pk = pk
        self.name = name


class SyncVrfsTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()

    def _run_sync(self, rows, vrfs_raw, device=None, iface_rows=None, ip_rows=None):
        manager = FakeVRFManager(rows)
        FakeVRF.objects = manager
        rt_manager = FakeRouteTargetManager()
        FakeRouteTarget.objects = rt_manager
        FakeInterface.objects = FakeInterfaceManager(iface_rows or [])
        FakeIPAddress.objects = FakeIPAddressManager(ip_rows or [])

        fake_dcim = types.ModuleType("dcim")
        fake_dcim_models = types.ModuleType("dcim.models")
        fake_dcim_models.Interface = FakeInterface
        fake_ipam = types.ModuleType("ipam")
        fake_ipam_models = types.ModuleType("ipam.models")
        fake_ipam_models.VRF = FakeVRF
        fake_ipam_models.RouteTarget = FakeRouteTarget
        fake_ipam_models.IPAddress = FakeIPAddress
        fake_ct = types.ModuleType("django.contrib.contenttypes")
        fake_ct_models = types.ModuleType("django.contrib.contenttypes.models")
        fake_ct_models.ContentType = FakeContentType
        messages = []

        with mock.patch.dict(sys.modules, {
            "dcim": fake_dcim,
            "dcim.models": fake_dcim_models,
            "ipam": fake_ipam,
            "ipam.models": fake_ipam_models,
            "django.contrib.contenttypes": fake_ct,
            "django.contrib.contenttypes.models": fake_ct_models,
            "django.db": make_django_db_stub(),
        }):
            self.netbox_sync._sync_vrfs(vrfs_raw, device, messages.append)

        return messages

    def test_skips_placeholder_rd_when_creating_new_vrf(self):
        rows = []

        self._run_sync(
            rows,
            {"blue": {"state": {"route_distinguisher": "0:0"}}},
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].name, "blue")
        self.assertEqual(rows[0].rd, "")

    def test_uses_first_duplicate_name_match_instead_of_raising(self):
        rows = [
            FakeVRF(pk=1, name="Corp", rd=""),
            FakeVRF(pk=2, name="corp", rd=""),
        ]

        messages = self._run_sync(
            rows,
            {"CORP": {"state": {"route_distinguisher": "65000:10"}}},
        )

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].rd, "65000:10")
        self.assertEqual(rows[0].save_calls, 1)
        self.assertTrue(any("Found 2 existing VRFs named 'CORP'" in msg for msg in messages))

    def test_skips_duplicate_rd_used_by_another_vrf(self):
        rows = [FakeVRF(pk=1, name="Shared", rd="65000:99")]

        messages = self._run_sync(
            rows,
            {"Blue": {"state": {"route_distinguisher": "65000:99"}}},
        )

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1].name, "Blue")
        self.assertEqual(rows[1].rd, "")
        self.assertTrue(any("Skipping RD '65000:99' for VRF 'Blue'" in msg for msg in messages))

    def test_creates_route_targets_and_links_to_new_vrf(self):
        rows = []

        messages = self._run_sync(
            rows,
            {
                "BLUE": {
                    "state": {"route_distinguisher": "65000:100"},
                    "route_targets": {
                        "import": ["65000:100", "65000:200"],
                        "export": ["65000:100"],
                    },
                }
            },
        )

        vrf = rows[0]
        self.assertEqual(vrf.name, "BLUE")
        self.assertEqual([rt.name for rt in vrf.import_targets.all()], ["65000:100", "65000:200"])
        self.assertEqual([rt.name for rt in vrf.export_targets.all()], ["65000:100"])
        self.assertTrue(any("route target" in msg for msg in messages))

    def test_links_route_targets_to_existing_vrf(self):
        existing = FakeVRF(pk=1, name="RED", rd="65000:10")
        rows = [existing]

        self._run_sync(
            rows,
            {
                "RED": {
                    "state": {"route_distinguisher": "65000:10"},
                    "route_targets": {
                        "import": ["65000:10"],
                        "export": ["65000:10"],
                    },
                }
            },
        )

        self.assertEqual([rt.name for rt in existing.import_targets.all()], ["65000:10"])
        self.assertEqual([rt.name for rt in existing.export_targets.all()], ["65000:10"])

    def test_does_not_duplicate_already_linked_route_target(self):
        existing = FakeVRF(pk=1, name="GREEN", rd="65000:50")
        rows = [existing]
        vrf_data = {
            "GREEN": {
                "state": {"route_distinguisher": "65000:50"},
                "route_targets": {"import": ["65000:50"], "export": []},
            }
        }

        self._run_sync(rows, vrf_data)
        self.assertEqual(len(existing.import_targets.all()), 1)

        self._run_sync(rows, vrf_data)
        self.assertEqual(len(existing.import_targets.all()), 1)

    def test_no_route_targets_when_key_absent(self):
        rows = []

        self._run_sync(
            rows,
            {"PLAIN": {"state": {"route_distinguisher": "65000:1"}}},
        )

        vrf = rows[0]
        self.assertEqual(vrf.import_targets.all(), [])
        self.assertEqual(vrf.export_targets.all(), [])

    def test_assigns_interface_to_vrf(self):
        device = FakeDevice()
        iface = FakeInterface(pk=10, name="Loopback0", device=device, vrf=None, vrf_id=None)
        rows = []

        messages = self._run_sync(
            rows,
            {
                "BLUE": {
                    "state": {"route_distinguisher": "65000:100"},
                    "interfaces": {"interface": {"Loopback0": {}}},
                }
            },
            device=device,
            iface_rows=[iface],
        )

        vrf = rows[0]
        self.assertIs(iface.vrf, vrf)
        self.assertEqual(iface.save_calls, 1)
        self.assertTrue(any("interface" in msg for msg in messages))

    def test_assigns_ip_to_vrf_via_interface(self):
        device = FakeDevice()
        iface = FakeInterface(pk=10, name="Loopback0", device=device, vrf=None, vrf_id=None)
        ip = FakeIPAddress(
            pk=20,
            address="10.0.0.1/32",
            assigned_object_type=_FAKE_IFACE_CT,
            assigned_object_id=10,
            vrf=None,
            vrf_id=None,
        )
        rows = []

        self._run_sync(
            rows,
            {
                "BLUE": {
                    "state": {"route_distinguisher": "65000:100"},
                    "interfaces": {"interface": {"Loopback0": {}}},
                }
            },
            device=device,
            iface_rows=[iface],
            ip_rows=[ip],
        )

        vrf = rows[0]
        self.assertIs(ip.vrf, vrf)
        self.assertEqual(ip.save_calls, 1)

    def test_does_not_overwrite_interface_already_in_different_vrf(self):
        device = FakeDevice()
        other_vrf = FakeVRF(pk=99, name="OTHER")
        iface = FakeInterface(pk=10, name="Loopback0", device=device, vrf=other_vrf, vrf_id=99)
        rows = []

        self._run_sync(
            rows,
            {
                "BLUE": {
                    "state": {"route_distinguisher": "65000:100"},
                    "interfaces": {"interface": {"Loopback0": {}}},
                }
            },
            device=device,
            iface_rows=[iface],
        )

        self.assertIs(iface.vrf, other_vrf)
        self.assertEqual(iface.save_calls, 0)

    def test_skips_interface_assignment_when_device_is_none(self):
        iface = FakeInterface(pk=10, name="Loopback0", device=None, vrf=None, vrf_id=None)
        rows = []

        self._run_sync(
            rows,
            {
                "BLUE": {
                    "state": {},
                    "interfaces": {"interface": {"Loopback0": {}}},
                }
            },
            device=None,
            iface_rows=[iface],
        )

        self.assertIsNone(iface.vrf)
        self.assertEqual(iface.save_calls, 0)


class JournalMessageTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()

    def test_interface_message_ignores_prune_only_runs(self):
        message = self.netbox_sync._build_interface_journal_message(
            {
                "created": 0,
                "updated": 0,
                "deleted": 0,
                "deleted_names": [],
                "delete_failed": 0,
                "prune_skipped": True,
            }
        )

        self.assertEqual(message, "")

    def test_interface_message_includes_real_changes(self):
        message = self.netbox_sync._build_interface_journal_message(
            {
                "created": 1,
                "updated": 2,
                "deleted": 1,
                "deleted_names": ["Gi1/0/24"],
                "delete_failed": 1,
            }
        )

        self.assertIn("created=1", message)
        self.assertIn("updated=2", message)
        self.assertIn("deleted=1 (Gi1/0/24)", message)
        self.assertIn("delete_failed=1", message)

    def test_ip_message_ignores_conflict_only_runs(self):
        message = self.netbox_sync._build_ip_journal_message(
            {
                "created": 0,
                "reassigned": 0,
                "conflicts": 3,
                "mgmt_created": 0,
            }
        )

        self.assertEqual(message, "")

    def test_ip_message_includes_conflicts_when_other_changes_exist(self):
        message = self.netbox_sync._build_ip_journal_message(
            {
                "created": 2,
                "reassigned": 1,
                "conflicts": 3,
                "mgmt_created": 0,
            }
        )

        self.assertIn("created=2", message)
        self.assertIn("reassigned=1", message)
        self.assertIn("conflicts=3", message)


class FakeTaggedVlanManager:
    """Stand-in for Interface.tagged_vlans (a NetBox-style M2M manager)."""

    def __init__(self):
        self._items = []

    def values_list(self, field, flat=False):
        return [getattr(item, field) for item in self._items]

    def set(self, items):
        self._items = list(items)

    def all(self):
        return list(self._items)


class FakeInterface:
    objects = None

    def __init__(self, pk, device=None, name="", enabled=True, type="1000base-t",
                 vrf=None, vrf_id=None, mode=None, untagged_vlan=None,
                 untagged_vlan_id=None):
        self.pk = pk
        self.device = device
        self.name = name
        self.enabled = enabled
        self.type = type
        self.vrf = vrf
        self.vrf_id = vrf_id
        self.mode = mode
        self.untagged_vlan = untagged_vlan
        self.untagged_vlan_id = untagged_vlan_id
        self.tagged_vlans = FakeTaggedVlanManager()
        self.description = ""
        self.mtu = None
        self.speed = None
        self.lag_id = None
        self.cable_id = None
        self.mac_address = None
        self.saved = False
        self.save_calls = 0

    def save(self):
        self.saved = True
        self.save_calls += 1
        if self.vrf is not None:
            self.vrf_id = self.vrf.pk
        if self.untagged_vlan is not None:
            self.untagged_vlan_id = self.untagged_vlan.pk


class FakeInterfaceManager:
    def __init__(self, rows):
        self.rows = rows
        self.next_pk = max((row.pk for row in rows), default=0) + 1

    def filter(self, **criteria):
        return FakeQuerySet([row for row in self.rows if _matches(row, criteria)])

    def values_list(self, *fields, flat=False):
        result = []
        for row in self.rows:
            if flat and len(fields) == 1:
                result.append(getattr(row, fields[0], None))
            else:
                result.append(tuple(getattr(row, f, None) for f in fields))
        return result

    def get_or_create(self, **kwargs):
        defaults = kwargs.pop("defaults", {})
        existing = self.filter(**kwargs).first()
        if existing:
            return existing, False
        row = FakeInterface(pk=self.next_pk, **kwargs, **defaults)
        self.next_pk += 1
        self.rows.append(row)
        return row, True


class FakeIPAddress:
    objects = None

    def __init__(
        self,
        pk,
        address="",
        assigned_object=None,
        status="active",
        assigned_object_type=None,
        assigned_object_id=None,
        vrf=None,
        vrf_id=None,
    ):
        self.pk = pk
        self.address = address
        self.assigned_object = assigned_object
        self.status = status
        self.assigned_object_type = assigned_object_type
        self.assigned_object_type_id = getattr(assigned_object_type, "id", None)
        self.assigned_object_id = (
            assigned_object_id if assigned_object_id is not None else getattr(assigned_object, "pk", None)
        )
        self.vrf = vrf
        self.vrf_id = vrf_id
        self.saved = False
        self.save_calls = 0

    def save(self):
        self.saved = True
        self.save_calls += 1
        if self.vrf is not None:
            self.vrf_id = self.vrf.pk


class FakeIPAddressManager:
    def __init__(self, rows):
        self.rows = rows
        self.next_pk = max((row.pk for row in rows), default=0) + 1

    def filter(self, **criteria):
        return FakeQuerySet([row for row in self.rows if _matches(row, criteria)])

    def get_or_create(self, address, defaults=None):
        defaults = defaults or {}
        existing = self.filter(address=address).first()
        if existing:
            return existing, False

        assigned_object = None
        assigned_object_id = defaults.get("assigned_object_id")
        if assigned_object_id is not None:
            assigned_object = next(
                (row for row in FakeInterface.objects.rows if row.pk == assigned_object_id),
                None,
            )
        row = FakeIPAddress(
            pk=self.next_pk,
            address=address,
            assigned_object=assigned_object,
            status=defaults.get("status", "active"),
            assigned_object_type=defaults.get("assigned_object_type"),
            assigned_object_id=assigned_object_id,
        )
        self.next_pk += 1
        self.rows.append(row)
        return row, True


class SyncIpsTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()

    def _run_sync_ips(self, interface_names, interfaces_ip, mgmt_ip, interfaces_raw=None):
        device = types.SimpleNamespace(pk=1, name="edge-01")
        iface_rows = [
            FakeInterface(pk=index, device=device, name=iface_name)
            for index, iface_name in enumerate(interface_names, start=1)
        ]
        ip_rows = []
        FakeInterface.objects = FakeInterfaceManager(iface_rows)
        FakeIPAddress.objects = FakeIPAddressManager(ip_rows)

        fake_dcim = types.ModuleType("dcim")
        fake_dcim_models = types.ModuleType("dcim.models")
        fake_dcim_models.Interface = FakeInterface

        fake_ipam = types.ModuleType("ipam")
        fake_ipam_models = types.ModuleType("ipam.models")
        fake_ipam_models.IPAddress = FakeIPAddress

        fake_django = types.ModuleType("django")
        fake_contrib = types.ModuleType("django.contrib")
        fake_contenttypes = types.ModuleType("django.contrib.contenttypes")
        fake_contenttypes_models = types.ModuleType("django.contrib.contenttypes.models")

        class FakeContentType:
            id = 42

        class FakeContentTypeManager:
            @staticmethod
            def get_for_model(_model):
                return FakeContentType()

        fake_contenttypes_models.ContentType = types.SimpleNamespace(objects=FakeContentTypeManager())

        with mock.patch.dict(
            sys.modules,
            {
                "dcim": fake_dcim,
                "dcim.models": fake_dcim_models,
                "ipam": fake_ipam,
                "ipam.models": fake_ipam_models,
                "django": fake_django,
                "django.contrib": fake_contrib,
                "django.contrib.contenttypes": fake_contenttypes,
                "django.contrib.contenttypes.models": fake_contenttypes_models,
                "django.db": make_django_db_stub(),
            },
        ):
            return self.netbox_sync._sync_ips(
                device,
                interfaces_ip,
                mgmt_ip=mgmt_ip,
                log_fn=lambda _msg: None,
                interfaces_raw=interfaces_raw,
            )

    def test_prefers_active_management_interface_ip_over_seed_ip(self):
        primary_ip, stats = self._run_sync_ips(
            ["Management1", "GigabitEthernet1/0/1"],
            {
                "GigabitEthernet1/0/1": {"ipv4": {"10.0.0.10": {"prefix_length": 24}}},
                "Management1": {"ipv4": {"192.0.2.10": {"prefix_length": 24}}},
            },
            mgmt_ip="10.0.0.10",
        )

        self.assertIsNotNone(primary_ip)
        self.assertEqual(primary_ip.address, "192.0.2.10/24")
        self.assertEqual(stats["created"], 2)
        self.assertEqual(stats["mgmt_created"], 0)

    def test_treats_catalyst_gigabitethernet0_0_as_management_interface(self):
        primary_ip, _stats = self._run_sync_ips(
            ["GigabitEthernet0/0", "GigabitEthernet1/0/1"],
            {
                "GigabitEthernet0/0": {"ipv4": {"192.0.2.10": {"prefix_length": 24}}},
                "GigabitEthernet1/0/1": {"ipv4": {"10.0.0.10": {"prefix_length": 24}}},
            },
            mgmt_ip="10.0.0.10",
        )

        self.assertIsNotNone(primary_ip)
        self.assertEqual(primary_ip.address, "192.0.2.10/24")

    def test_treats_nexus_mgmt0_as_management_interface(self):
        primary_ip, _stats = self._run_sync_ips(
            ["mgmt0", "Ethernet1/1"],
            {
                "mgmt0": {"ipv4": {"198.51.100.10": {"prefix_length": 24}}},
                "Ethernet1/1": {"ipv4": {"10.0.0.10": {"prefix_length": 24}}},
            },
            mgmt_ip="10.0.0.10",
        )

        self.assertIsNotNone(primary_ip)
        self.assertEqual(primary_ip.address, "198.51.100.10/24")

    def test_shutdown_gi0_0_not_used_as_primary(self):
        # Gi0/0 has an IP but is administratively shutdown — should not be primary.
        # mgmt_ip (seed) should become primary instead.
        primary_ip, _stats = self._run_sync_ips(
            ["GigabitEthernet0/0", "GigabitEthernet1/0/1"],
            {
                "GigabitEthernet0/0": {"ipv4": {"192.0.2.10": {"prefix_length": 24}}},
                "GigabitEthernet1/0/1": {"ipv4": {"10.0.0.10": {"prefix_length": 24}}},
            },
            mgmt_ip="10.0.0.10",
            interfaces_raw={
                "GigabitEthernet0/0": {"is_enabled": False, "is_up": False},
                "GigabitEthernet1/0/1": {"is_enabled": True, "is_up": True},
            },
        )

        self.assertIsNotNone(primary_ip)
        # mgmt_ip matches the 10.0.0.10/24 on GigabitEthernet1/0/1 — not the shutdown Gi0/0
        self.assertEqual(primary_ip.address, "10.0.0.10/24")

    def test_active_gi0_0_still_used_as_primary(self):
        # Gi0/0 is enabled — should still be selected as primary.
        primary_ip, _stats = self._run_sync_ips(
            ["GigabitEthernet0/0", "GigabitEthernet1/0/1"],
            {
                "GigabitEthernet0/0": {"ipv4": {"192.0.2.10": {"prefix_length": 24}}},
                "GigabitEthernet1/0/1": {"ipv4": {"10.0.0.10": {"prefix_length": 24}}},
            },
            mgmt_ip="10.0.0.10",
            interfaces_raw={
                "GigabitEthernet0/0": {"is_enabled": True, "is_up": True},
                "GigabitEthernet1/0/1": {"is_enabled": True, "is_up": True},
            },
        )

        self.assertIsNotNone(primary_ip)
        self.assertEqual(primary_ip.address, "192.0.2.10/24")


class PrimaryPreservationTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()

    def test_management_candidate_overrides_non_management_primary(self):
        device = types.SimpleNamespace(pk=1, name="edge-01")
        existing_iface = FakeInterface(pk=1, device=device, name="Loopback255")
        candidate_iface = FakeInterface(pk=2, device=device, name="GigabitEthernet0/0")
        existing_primary = FakeIPAddress(pk=1, address="192.168.1.1/32", assigned_object=existing_iface)
        candidate_primary = FakeIPAddress(pk=2, address="10.10.10.10/24", assigned_object=candidate_iface)

        self.assertFalse(
            self.netbox_sync._should_preserve_existing_primary(existing_primary, candidate_primary)
        )

    def test_preserves_existing_primary_when_candidate_is_not_management(self):
        device = types.SimpleNamespace(pk=1, name="edge-01")
        existing_iface = FakeInterface(pk=1, device=device, name="Loopback255")
        candidate_iface = FakeInterface(pk=2, device=device, name="Vlan10")
        existing_primary = FakeIPAddress(pk=1, address="192.168.1.1/32", assigned_object=existing_iface)
        candidate_primary = FakeIPAddress(pk=2, address="10.10.10.10/24", assigned_object=candidate_iface)

        self.assertTrue(
            self.netbox_sync._should_preserve_existing_primary(existing_primary, candidate_primary)
        )


# ---------------------------------------------------------------------------
# VLAN-to-interface binding tests
# ---------------------------------------------------------------------------


class FakeVLAN:
    objects = None

    def __init__(self, pk, vid, site, name=""):
        self.pk = pk
        self.vid = vid
        self.site = site
        self.name = name


class FakeVLANManager:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **criteria):
        site = criteria.get("site")
        vids = criteria.get("vid__in")
        results = []
        for row in self.rows:
            if site is not None and row.site is not site:
                continue
            if vids is not None and row.vid not in set(vids):
                continue
            results.append(row)
        return FakeQuerySet(results)


class SyncInterfaceVlansTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()

    def _run(self, vlans_raw, iface_rows, vlan_rows, device):
        FakeInterface.objects = FakeInterfaceManager(iface_rows)
        FakeVLAN.objects = FakeVLANManager(vlan_rows)

        fake_dcim = types.ModuleType("dcim")
        fake_dcim_models = types.ModuleType("dcim.models")
        fake_dcim_models.Interface = FakeInterface
        fake_ipam = types.ModuleType("ipam")
        fake_ipam_models = types.ModuleType("ipam.models")
        fake_ipam_models.VLAN = FakeVLAN
        messages = []

        with mock.patch.dict(sys.modules, {
            "dcim": fake_dcim,
            "dcim.models": fake_dcim_models,
            "ipam": fake_ipam,
            "ipam.models": fake_ipam_models,
        }):
            stats = self.netbox_sync._sync_interface_vlans(
                device, vlans_raw, messages.append,
            )
        return stats, messages

    def test_single_vlan_membership_sets_access_mode(self):
        site = types.SimpleNamespace(pk=1)
        device = types.SimpleNamespace(pk=1, name="sw1", site=site)
        iface = FakeInterface(pk=10, device=device, name="GigabitEthernet0/1")
        vlan = FakeVLAN(pk=100, vid=10, site=site, name="users")

        stats, _msgs = self._run(
            {"10": {"name": "users", "interfaces": ["GigabitEthernet0/1"]}},
            iface_rows=[iface],
            vlan_rows=[vlan],
            device=device,
        )

        self.assertEqual(iface.mode, "access")
        self.assertIs(iface.untagged_vlan, vlan)
        self.assertEqual(stats["access_set"], 1)
        self.assertEqual(stats["tagged_set"], 0)
        self.assertEqual(iface.save_calls, 1)

    def test_multiple_vlan_membership_sets_tagged_mode(self):
        site = types.SimpleNamespace(pk=1)
        device = types.SimpleNamespace(pk=1, name="sw1", site=site)
        iface = FakeInterface(pk=11, device=device, name="GigabitEthernet0/2")
        vlan10 = FakeVLAN(pk=100, vid=10, site=site)
        vlan20 = FakeVLAN(pk=101, vid=20, site=site)
        vlan30 = FakeVLAN(pk=102, vid=30, site=site)

        stats, _msgs = self._run(
            {
                "10": {"name": "v10", "interfaces": ["GigabitEthernet0/2"]},
                "20": {"name": "v20", "interfaces": ["GigabitEthernet0/2"]},
                "30": {"name": "v30", "interfaces": ["GigabitEthernet0/2"]},
            },
            iface_rows=[iface],
            vlan_rows=[vlan10, vlan20, vlan30],
            device=device,
        )

        self.assertEqual(iface.mode, "tagged")
        self.assertEqual(
            sorted(v.vid for v in iface.tagged_vlans.all()), [10, 20, 30]
        )
        self.assertEqual(stats["tagged_set"], 1)
        self.assertEqual(stats["access_set"], 0)

    def test_skips_virtual_and_lag_interfaces(self):
        site = types.SimpleNamespace(pk=1)
        device = types.SimpleNamespace(pk=1, name="sw1", site=site)
        svi = FakeInterface(pk=200, device=device, name="Vlan10", type="virtual")
        lag = FakeInterface(pk=201, device=device, name="Port-Channel1", type="lag")
        vlan = FakeVLAN(pk=100, vid=10, site=site)

        stats, _msgs = self._run(
            {
                "10": {"interfaces": ["Vlan10", "Port-Channel1"]},
            },
            iface_rows=[svi, lag],
            vlan_rows=[vlan],
            device=device,
        )

        self.assertEqual(stats["access_set"], 0)
        self.assertEqual(stats["tagged_set"], 0)
        self.assertEqual(svi.save_calls, 0)
        self.assertEqual(lag.save_calls, 0)

    def test_idempotent_when_already_correct(self):
        site = types.SimpleNamespace(pk=1)
        device = types.SimpleNamespace(pk=1, name="sw1", site=site)
        vlan = FakeVLAN(pk=100, vid=10, site=site)
        iface = FakeInterface(
            pk=10,
            device=device,
            name="GigabitEthernet0/1",
            mode="access",
            untagged_vlan=vlan,
            untagged_vlan_id=vlan.pk,
        )

        stats, _msgs = self._run(
            {"10": {"interfaces": ["GigabitEthernet0/1"]}},
            iface_rows=[iface],
            vlan_rows=[vlan],
            device=device,
        )

        self.assertEqual(iface.save_calls, 0)
        self.assertEqual(stats["access_set"], 0)

    def test_unknown_vlan_is_skipped(self):
        site = types.SimpleNamespace(pk=1)
        device = types.SimpleNamespace(pk=1, name="sw1", site=site)
        iface = FakeInterface(pk=10, device=device, name="GigabitEthernet0/1")

        stats, _msgs = self._run(
            {"999": {"interfaces": ["GigabitEthernet0/1"]}},
            iface_rows=[iface],
            vlan_rows=[],
            device=device,
        )

        self.assertEqual(stats["access_set"], 0)
        self.assertEqual(stats["tagged_set"], 0)
        self.assertEqual(stats["skipped_no_vlan"], 1)
        self.assertEqual(iface.save_calls, 0)


class GetOrCreateOneTests(unittest.TestCase):
    """
    Several NetBox models this plugin keys on permit duplicate rows:
    IPAddress.address (different VRFs; ENFORCE_GLOBAL_UNIQUE is off by
    default), VirtualChassis.name, and dcim.MACAddress. Plain get_or_create()
    raises MultipleObjectsReturned against those, and since sync_device() runs
    inside a single transaction that exception discarded the entire device.
    """

    def setUp(self):
        self.netbox_sync = load_module()

    @staticmethod
    def _manager(rows, get_or_create=None):
        class FakeModel:
            MultipleObjectsReturned = FakeMultipleObjectsReturned

        class FakeManager:
            model = FakeModel

            def __init__(self):
                self.created = []

            def filter(self, **criteria):
                return FakeQuerySet([r for r in rows if _matches(r, criteria)])

            def get_or_create(self, defaults=None, **lookup):
                if get_or_create is not None:
                    return get_or_create(defaults, lookup)
                obj = types.SimpleNamespace(pk=len(rows) + 1, **lookup)
                rows.append(obj)
                self.created.append(obj)
                return obj, True

        return FakeManager()

    def _call(self, manager, **kwargs):
        with mock.patch.dict(sys.modules, {"django.db": make_django_db_stub()}):
            return self.netbox_sync._get_or_create_one(manager, **kwargs)

    def test_returns_existing_row_without_creating(self):
        existing = types.SimpleNamespace(pk=7, address="10.0.0.1/24")
        manager = self._manager([existing])

        obj, created = self._call(manager, address="10.0.0.1/24")

        self.assertIs(obj, existing)
        self.assertFalse(created)
        self.assertEqual(manager.created, [])

    def test_creates_when_absent(self):
        manager = self._manager([])

        obj, created = self._call(manager, defaults={"status": "active"}, address="10.0.0.9/24")

        self.assertTrue(created)
        self.assertEqual(obj.address, "10.0.0.9/24")

    def test_picks_lowest_pk_when_duplicates_exist(self):
        # Two rows for the same address is legal in NetBox. Resolving to the
        # lowest pk keeps repeated runs converging on the same object rather
        # than flip-flopping between duplicates.
        high = types.SimpleNamespace(pk=99, address="10.0.0.1/24")
        low = types.SimpleNamespace(pk=3, address="10.0.0.1/24")
        manager = self._manager([high, low])

        obj, created = self._call(manager, address="10.0.0.1/24")

        self.assertIs(obj, low)
        self.assertFalse(created)

    def test_survives_multiple_objects_returned_from_get_or_create(self):
        # The duplicate appears between the existence check and the create —
        # exactly the concurrent-worker race. This used to abort the device.
        rows = []

        def racing_get_or_create(defaults, lookup):
            rows.append(types.SimpleNamespace(pk=5, **lookup))
            rows.append(types.SimpleNamespace(pk=6, **lookup))
            raise FakeMultipleObjectsReturned("two rows matched")

        manager = self._manager(rows, get_or_create=racing_get_or_create)

        obj, created = self._call(manager, address="10.0.0.1/24")

        self.assertEqual(obj.pk, 5)
        self.assertFalse(created)

    def test_survives_integrity_error_from_concurrent_insert(self):
        rows = []

        def losing_insert(defaults, lookup):
            rows.append(types.SimpleNamespace(pk=11, **lookup))
            raise tests_loader_integrity_error("duplicate key")

        manager = self._manager(rows, get_or_create=losing_insert)

        obj, created = self._call(manager, address="10.0.0.1/24")

        self.assertEqual(obj.pk, 11)
        self.assertFalse(created)


def _sync_fake_modules():
    """sys.modules entries for the dcim/ipam/contenttypes/django.db imports used by sync."""
    fake_dcim = types.ModuleType("dcim")
    fake_dcim_models = types.ModuleType("dcim.models")
    fake_dcim_models.Interface = FakeInterface
    fake_ipam = types.ModuleType("ipam")
    fake_ipam_models = types.ModuleType("ipam.models")
    fake_ipam_models.IPAddress = FakeIPAddress
    fake_contenttypes_models = types.ModuleType("django.contrib.contenttypes.models")

    class _ContentType:
        id = 42

    fake_contenttypes_models.ContentType = types.SimpleNamespace(
        objects=types.SimpleNamespace(get_for_model=lambda _model: _ContentType())
    )
    return {
        "dcim": fake_dcim,
        "dcim.models": fake_dcim_models,
        "ipam": fake_ipam,
        "ipam.models": fake_ipam_models,
        "django": types.ModuleType("django"),
        "django.contrib": types.ModuleType("django.contrib"),
        "django.contrib.contenttypes": types.ModuleType("django.contrib.contenttypes"),
        "django.contrib.contenttypes.models": fake_contenttypes_models,
        "django.db": make_django_db_stub(),
    }


class MapInterfaceTypeTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()

    def test_full_cisco_names_map_to_their_speed_class(self):
        # The patterns used to require a digit straight after "tengig",
        # "hundredgig", ..., so every full name fell through to "other".
        cases = {
            "TenGigabitEthernet1/1/1": "10gbase-x-sfpp",
            "TwentyFiveGigE1/0/1": "25gbase-x-sfp28",
            "FortyGigabitEthernet1/1/1": "40gbase-x-qsfpp",
            "HundredGigabitEthernet1/0/49": "100gbase-x-qsfp28",
            "GigabitEthernet1/0/1": "1000base-t",
            "Te1/1/1": "10gbase-x-sfpp",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.netbox_sync.map_interface_type(name), expected)

    def test_port_is_not_a_port_channel(self):
        # FortiGate "port1" matched ^(...|po)\d* and was typed as a LAG.
        self.assertNotEqual(self.netbox_sync.map_interface_type("port1"), "lag")
        self.assertEqual(self.netbox_sync.map_interface_type("Port-channel1"), "lag")
        self.assertEqual(self.netbox_sync.map_interface_type("Po1"), "lag")
        self.assertEqual(self.netbox_sync.map_interface_type("ae0"), "lag")

    def test_generic_names_use_reported_speed(self):
        self.assertEqual(self.netbox_sync.map_interface_type("Ethernet1/1", 25000), "25gbase-x-sfp28")
        self.assertEqual(self.netbox_sync.map_interface_type("port1", 1000.0), "1000base-t")
        self.assertEqual(self.netbox_sync.map_interface_type("Ethernet1/1"), "other")


class SelectStackMasterTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()

    def test_prefers_active_over_lower_numbered_standby(self):
        members = [
            {"position": 1, "role": "standby"},
            {"position": 2, "role": "active"},
            {"position": 3, "role": "member"},
        ]
        self.assertEqual(self.netbox_sync._select_stack_master(members)["position"], 2)

    def test_falls_back_to_standby_then_lowest_position(self):
        self.assertEqual(
            self.netbox_sync._select_stack_master(
                [{"position": 1, "role": "member"}, {"position": 2, "role": "standby"}]
            )["position"],
            2,
        )
        self.assertEqual(
            self.netbox_sync._select_stack_master(
                [{"position": 3, "role": "member"}, {"position": 2, "role": "member"}]
            )["position"],
            2,
        )


class FallbackPrimaryIpTests(unittest.TestCase):
    """The management IP was not on any collected interface."""

    def setUp(self):
        self.netbox_sync = load_module()
        self.device = types.SimpleNamespace(pk=1, name="edge-01")

    def _run(self, interface_names, ip_rows):
        FakeInterface.objects = FakeInterfaceManager([
            FakeInterface(pk=index, device=self.device, name=name)
            for index, name in enumerate(interface_names, start=1)
        ])
        FakeIPAddress.objects = FakeIPAddressManager(ip_rows)
        with mock.patch.dict(sys.modules, _sync_fake_modules()):
            return self.netbox_sync._sync_ips(
                self.device, {}, mgmt_ip="192.0.2.50", log_fn=lambda _msg: None
            )

    def test_does_not_claim_an_ip_assigned_to_another_device(self):
        other_device = types.SimpleNamespace(pk=2, name="other-01")
        other_iface = FakeInterface(pk=99, device=other_device, name="Vlan10")
        ip_rows = [FakeIPAddress(pk=1, address="192.0.2.50/24", assigned_object=other_iface)]

        primary_ip, stats = self._run(["mgmt0"], ip_rows)

        self.assertIsNone(primary_ip)
        self.assertEqual(stats["conflicts"], 1)

    def test_creates_host_address_on_management_interface(self):
        primary_ip, stats = self._run(["mgmt0", "Ethernet1/1"], [])

        self.assertIsNotNone(primary_ip)
        self.assertEqual(primary_ip.address, "192.0.2.50/32")
        self.assertEqual(primary_ip.assigned_object_id, 1)
        self.assertEqual(stats["mgmt_created"], 1)

    def test_leaves_primary_unset_without_a_management_interface(self):
        # An unassigned primary IP makes NetBox's device form refuse to save.
        primary_ip, stats = self._run(["Ethernet1/1"], [])

        self.assertIsNone(primary_ip)
        self.assertEqual(stats["mgmt_created"], 0)


class SyncInterfacesTests(unittest.TestCase):
    def setUp(self):
        self.netbox_sync = load_module()
        self.device = types.SimpleNamespace(pk=1, name="core-01")

    def _run(self, existing, payload, options=None):
        rows = []
        for index, (name, iface_type) in enumerate(existing, start=1):
            rows.append(FakeInterface(pk=index, device=self.device, name=name, type=iface_type))
        FakeInterface.objects = FakeInterfaceManager(rows)
        with mock.patch.dict(sys.modules, _sync_fake_modules()):
            stats = self.netbox_sync._sync_interfaces(
                self.device, payload, lambda _msg: None, options=options or {}
            )
        return rows, stats

    def test_new_interfaces_get_specific_types(self):
        rows, stats = self._run(
            [],
            {
                "TenGigabitEthernet1/1/1": {"speed": 10000},
                "Ethernet1/1": {"speed": 25000},
                "port1": {"speed": 1000},
            },
        )
        types_by_name = {row.name: row.type for row in rows}
        self.assertEqual(types_by_name["TenGigabitEthernet1/1/1"], "10gbase-x-sfpp")
        self.assertEqual(types_by_name["Ethernet1/1"], "25gbase-x-sfp28")
        self.assertEqual(types_by_name["port1"], "1000base-t")
        self.assertEqual(stats["created"], 3)

    def test_operator_set_type_is_preserved(self):
        rows, _ = self._run(
            [("GigabitEthernet1/0/1", "1000base-x-sfp")],
            {"GigabitEthernet1/0/1": {}},
        )
        self.assertEqual(rows[0].type, "1000base-x-sfp")

    def test_generic_other_type_is_upgraded(self):
        rows, _ = self._run(
            [("TenGigabitEthernet1/1/1", "other")],
            {"TenGigabitEthernet1/1/1": {}},
        )
        self.assertEqual(rows[0].type, "10gbase-x-sfpp")

    def test_existing_interface_matched_case_insensitively_and_renamed(self):
        rows, stats = self._run(
            [("Port-Channel1", "lag")],
            {"port-channel1": {}},
        )
        self.assertEqual(len(rows), 1, "must not create a second interface")
        self.assertEqual(rows[0].name, "port-channel1")
        self.assertEqual(stats["created"], 0)

    def test_legacy_canonical_name_is_renamed_not_duplicated(self):
        # Earlier versions stored NX-OS mgmt0 as "Management0".
        rows, stats = self._run(
            [("Management0", "1000base-t")],
            {"mgmt0": {}},
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].name, "mgmt0")
        self.assertEqual(stats["created"], 0)

    def test_nothing_is_pruned_by_default(self):
        rows, stats = self._run(
            [("GigabitEthernet1/0/1", "1000base-t"), ("GigabitEthernet1/0/2", "1000base-t")],
            {"GigabitEthernet1/0/1": {}},
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(stats["deleted"], 0)
        self.assertEqual(stats["stale_count"], 0)
