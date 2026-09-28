"""
NetBox synchronization logic.

All operations use get_or_create / update — nothing is ever deleted.
Matches existing devices by hostname first, then by primary IP.
"""

import logging
import logging.handlers
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from netbox_discovery.naming import (
    base_hostname as _base_hostname,
)
from netbox_discovery.naming import (
    canonical_interface_name as _canonical_interface_name,
)
from netbox_discovery.naming import (
    interface_name_key as _interface_name_key,
)
from netbox_discovery.naming import (
    legacy_canonical_interface_name as _legacy_canonical_interface_name,
)
from netbox_discovery.naming import (
    strip_device_id_serial as _strip_device_id_serial,
)
from netbox_discovery.sync.classify import classify_device

logger = logging.getLogger("netbox.plugins.netbox_discovery")

# ---------------------------------------------------------------------------
# Dedicated conflict logger — writes to /var/log/netbox/discovery_conflicts.log
# so IP assignment issues can be reviewed and corrected independently of the
# main NetBox log.
# ---------------------------------------------------------------------------

def _get_conflict_logger() -> logging.Logger:
    """Return (creating on first call) the dedicated IP-conflict file logger."""
    name = "netbox.plugins.netbox_discovery.conflicts"
    clog = logging.getLogger(name)
    if clog.handlers:
        return clog  # already configured

    clog.setLevel(logging.WARNING)
    clog.propagate = False  # don't bubble up into the main NetBox log

    from ..config import get_setting

    log_path = get_setting("conflict_log_path")
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,  # 5 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        clog.addHandler(handler)
    except OSError as exc:
        # If the log directory isn't writable, fall back to the main logger
        logger.warning("Cannot open conflict log %s: %s — conflicts will appear in main log only", log_path, exc)
        clog.addHandler(logging.NullHandler())

    return clog

# ---------------------------------------------------------------------------
# Interface type mapping
# ---------------------------------------------------------------------------

# Maps name-prefix/pattern → NetBox interface type slug. Patterns match both
# the full names get_interfaces() returns (TenGigabitEthernet1/1/1) and the
# abbreviations CDP uses (Te1/1/1); every alternative must be followed by a
# digit so e.g. FortiGate "port1" is not mistaken for a port-channel.
INTERFACE_TYPE_MAP = [
    (r"^(vlan|svi|bvi)\d*", "virtual"),
    (r"^loopback", "virtual"),
    (r"^tunnel", "virtual"),
    (r"^null", "virtual"),
    (r"^(port-channel|bundle-ether|ae|po)\d", "lag"),
    (r"^(hundredgigabitethernet|hundredgige|hu)\d", "100gbase-x-qsfp28"),
    (r"^(fortygigabitethernet|fortygige|fo)\d", "40gbase-x-qsfpp"),
    (r"^(twentyfivegigabitethernet|twentyfivegige|twe)\d", "25gbase-x-sfp28"),
    (r"^(tengigabitethernet|tengige|te|10gige)\d", "10gbase-x-sfpp"),
    (r"^(gigabitethernet|gi|ge)\d", "1000base-t"),
    (r"^(fastethernet|fa|fe)\d", "100base-tx"),
    (r"^(serial|se)\d", "other"),
    (r"^mgmt", "1000base-t"),
    (r"^management", "1000base-t"),
]

# Fallback for generically named ports (NX-OS/EOS "Ethernet1/1", FortiGate
# "port1"): NAPALM reports speed in Mbps.
_SPEED_TYPE_MAP = [
    (400000, "400gbase-x-qsfpdd"),
    (100000, "100gbase-x-qsfp28"),
    (40000, "40gbase-x-qsfpp"),
    (25000, "25gbase-x-sfp28"),
    (10000, "10gbase-x-sfpp"),
    (1000, "1000base-t"),
    (100, "100base-tx"),
]

# Types this plugin may overwrite on an existing interface. Anything else was
# either set by an operator or is already specific, and is left alone.
# "40gbase-x-qsfpplus" is an invalid slug earlier versions wrote.
_REPLACEABLE_INTERFACE_TYPES = {"other", "40gbase-x-qsfpplus"}


def map_interface_type(name: str, speed_mbps=None) -> str:
    """Map a NAPALM interface name (and optional speed) to a NetBox interface type slug."""
    n = (name or "").lower()
    for pattern, iface_type in INTERFACE_TYPE_MAP:
        if re.match(pattern, n):
            return iface_type
    try:
        speed = float(speed_mbps or 0)
    except (TypeError, ValueError):
        speed = 0
    for threshold, iface_type in _SPEED_TYPE_MAP:
        if speed == threshold:
            return iface_type
    return "other"


def _normalize_mac(value) -> Optional[str]:
    """Normalize a MAC for equality checks across str / EUI / MACAddress / None."""
    if value is None:
        return None
    s = "".join(ch for ch in str(value) if ch.isalnum()).upper()
    return s or None


def _mac_equal(a, b) -> bool:
    """Case- and separator-insensitive MAC equality."""
    return _normalize_mac(a) == _normalize_mac(b)


def _assign_interface_mac(iface, mac: str) -> bool:
    """
    Point an interface's primary MAC at a dcim.MACAddress object.

    NetBox 4.2 moved MAC addresses out of Interface into a first-class
    dcim.MACAddress model. Interface.mac_address is now a read-only
    cached_property derived from primary_mac_address, so the old
    `iface.mac_address = mac` assignment raises AttributeError. It used to be
    wrapped in a bare `except: pass`, which is why MAC sync silently stopped
    working rather than failing visibly.

    Returns True when the interface's primary MAC changed; the caller is
    responsible for saving the interface.
    """
    from dcim.models import MACAddress
    from django.contrib.contenttypes.models import ContentType

    if _mac_equal(iface.mac_address, mac):
        return False

    iface_ct = ContentType.objects.get_for_model(iface)
    # Scope to this interface: NetBox permits the same MAC on more than one
    # object, and the primary MAC must belong to the interface referencing it.
    mac_obj, _created = _get_or_create_one(
        MACAddress.objects,
        mac_address=mac,
        assigned_object_type=iface_ct,
        assigned_object_id=iface.pk,
    )
    iface.primary_mac_address = mac_obj
    # mac_address is a cached_property over primary_mac_address — drop any
    # value cached before this assignment so later reads are accurate.
    iface.__dict__.pop("mac_address", None)
    return True


def _is_management_interface_name(name: str) -> bool:
    """Return True when the interface name looks like a management port."""
    normalized = _canonical_interface_name(name).lower()
    return (
        normalized.startswith("mgmt")
        or normalized.startswith("management")
        or normalized == "gigabitethernet0/0"
    )


def _preferred_management_interface_ip(interfaces_ip: Dict, interfaces_raw: Dict = None) -> str:
    """Return the preferred IPv4 from a management interface when present."""
    for iface_name, addr_families in (interfaces_ip or {}).items():
        if not _is_management_interface_name(iface_name):
            continue
        if _is_interface_shutdown(iface_name, interfaces_raw):
            continue
        for ip_str in ((addr_families or {}).get("ipv4") or {}).keys():
            if ip_str:
                return ip_str
    return ""


def _is_interface_shutdown(iface_name: str, interfaces_raw: Dict) -> bool:
    """Return True when the interface is administratively shutdown (is_enabled=False)."""
    if not interfaces_raw:
        return False
    canonical = _canonical_interface_name(iface_name)
    for raw_name, raw_data in interfaces_raw.items():
        if _canonical_interface_name(raw_name) == canonical:
            return not (raw_data or {}).get("is_enabled", True)
    return False


# ---------------------------------------------------------------------------
# Slug helpers
# ---------------------------------------------------------------------------

def make_slug(text: str, max_length: int = 100) -> str:
    """Create a URL-safe slug from arbitrary text."""
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = slug.strip("-")
    return slug[:max_length]


# ---------------------------------------------------------------------------
# Main sync entry point
# ---------------------------------------------------------------------------

def sync_device(
    mgmt_ip: str,
    data: Dict[str, Any],
    holding_site_name: str = "Holding",
    log_fn: Optional[Callable[[str], None]] = None,
    options: Optional[Dict[str, Any]] = None,
) -> Tuple[str, bool]:
    """
    Synchronize discovered device data into NetBox.

    Args:
        mgmt_ip: The management IP used to connect to the device.
        data: Dict from collector.collect_device_data().
        holding_site_name: Name of the holding site (created if needed).
        log_fn: Log callback.
        options: Plugin config options (sync_platform, sync_fqdn, etc.).

    Returns:
        Tuple of (device_name, was_created).
    """
    # Import NetBox models here to avoid import errors outside NetBox context
    from dcim.models import (
        Device,
        DeviceType,
        Manufacturer,
    )
    from django.db import transaction

    if options is None:
        from ..config import get_discovery_options
        options = get_discovery_options()

    if log_fn is None:
        log_fn = lambda msg: logger.info(msg)

    facts = data.get("facts", {})
    interfaces_raw = data.get("interfaces", {})
    lag_members = data.get("lag_members", {})
    interfaces_ip = data.get("interfaces_ip", {})
    vlans_raw = data.get("vlans", {})
    stack_members = data.get("stack_members", [])

    raw_hostname = (facts.get("hostname") or "").strip()
    if _is_valid_hostname(raw_hostname):
        hostname = raw_hostname
    else:
        if raw_hostname:
            log_fn(f"  [WARN] Ignoring invalid hostname '{raw_hostname[:60]}' — using IP as identifier")
        hostname = mgmt_ip
    vendor = (facts.get("vendor") or "Unknown").strip()
    model = (facts.get("model") or "Unknown").strip()
    serial = (facts.get("serial_number") or "").strip()
    os_version = (facts.get("os_version") or "").strip()

    log_fn(f"  Syncing: {hostname} ({vendor} {model}, serial={serial or 'N/A'})")

    with transaction.atomic():
        # --- Site (Holding) ---
        site = _ensure_site(holding_site_name)

        # --- Manufacturer ---
        # Use filter().first() to tolerate duplicate rows (raises MultipleObjectsReturned
        # with get_or_create when the DB already has two matching entries).
        # Creation goes through _get_or_create_one so that two workers meeting
        # the same new vendor/model on a first run don't lose the whole device
        # to an IntegrityError inside this transaction.
        mfr = Manufacturer.objects.filter(name__iexact=vendor).first()
        if mfr is None:
            mfr, _ = _get_or_create_one(
                Manufacturer.objects,
                defaults={"slug": make_slug(vendor)},
                name=vendor,
            )
        if not mfr.slug:
            mfr.slug = make_slug(vendor)
            mfr.save()

        # --- DeviceType ---
        dtype = DeviceType.objects.filter(manufacturer=mfr, model__iexact=model).first()
        if dtype is None:
            dtype, _ = _get_or_create_one(
                DeviceType.objects,
                defaults={"slug": make_slug(f"{vendor}-{model}")},
                manufacturer=mfr,
                model=model,
            )
        if not dtype.slug:
            dtype.slug = make_slug(f"{vendor}-{model}")
            dtype.save()

        # --- DeviceRole (auto-classify by model / driver) ---
        driver = (data.get("driver") or "").strip()
        classification = classify_device(model=model, vendor=vendor, driver=driver)
        role = _ensure_role(classification["role"], color=classification["color"])
        log_fn(f"  Auto-classified role: {classification['role']} (model={model})")

        # --- Device: match by hostname, then by primary IP ---
        device, was_created = _get_or_create_device(
            hostname=hostname,
            mgmt_ip=mgmt_ip,
            site=site,
            device_type=dtype,
            role=role,
            serial=serial,
        )
        if was_created:
            _add_journal_entry(
                device,
                (
                    "Discovery created this device from collected facts: "
                    f"hostname={hostname}, vendor={vendor}, model={model}, serial={serial or 'N/A'}, "
                    f"mgmt_ip={mgmt_ip}."
                ),
            )

        if (
            not was_created
            and serial
            and device.serial
            and device.serial != serial
            and device.device_type_id != dtype.pk
        ):
            refreshed = _perform_hardware_refresh(
                old_device=device,
                hostname=hostname,
                new_device_type=dtype,
                role=role,
                serial=serial,
                log_fn=log_fn,
            )
            if refreshed is not None:
                device = refreshed
                was_created = True

        # Update mutable fields regardless of creation
        changed = False
        device_field_changes: List[str] = []
        if device.device_type != dtype:
            old_model = (
                device.device_type.model
                if getattr(device, "device_type", None) is not None
                else "unknown"
            )
            device.device_type = dtype
            changed = True
            device_field_changes.append(f"model '{old_model}' -> '{dtype.model}'")
        if serial and device.serial != serial:
            old_serial = device.serial or "N/A"
            device.serial = serial
            changed = True
            device_field_changes.append(f"serial '{old_serial}' -> '{serial}'")
        if os_version:
            try:
                cf = device.custom_field_data or {}
                if cf.get("os_version") != os_version:
                    old_os = cf.get("os_version") or "N/A"
                    cf["os_version"] = os_version
                    device.custom_field_data = cf
                    changed = True
                    device_field_changes.append(f"os_version '{old_os}' -> '{os_version}'")
            except Exception as exc:
                log_fn(f"  [WARN] Could not set os_version custom field: {exc}")
        # --- Hostname-to-site auto-assignment (only if still on holding site) ---
        if device.site_id == site.pk:
            matched_site = _match_site_by_hostname(hostname, exclude_site_name=holding_site_name)
            if matched_site:
                old_site_name = getattr(device.site, "name", holding_site_name)
                device.site = matched_site
                changed = True
                log_fn(f"  Auto-assigned site '{matched_site.name}' from hostname prefix.")
                device_field_changes.append(f"site '{old_site_name}' -> '{matched_site.name}'")

        # Update role if classification improved (e.g. model was unknown before)
        if device.role_id != role.pk:
            old_role = getattr(getattr(device, "role", None), "name", "unknown")
            device.role = role
            changed = True
            device_field_changes.append(f"role '{old_role}' -> '{role.name}'")

        if changed:
            device.save()
        if device_field_changes:
            _add_journal_entry(
                device,
                "Discovery updated device attributes: " + "; ".join(device_field_changes) + ".",
            )

        # --- Auto-assign tags based on classification ---
        _sync_device_tags(device, classification["tags"], log_fn)

        # --- Platform mapping (Tier 1.1) ---
        if options.get("sync_platform", True) and driver:
            _sync_platform(device, driver, mfr, log_fn)

        # --- FQDN custom field (Tier 1.3) ---
        if options.get("sync_fqdn", True):
            fqdn = (facts.get("fqdn") or "").strip()
            if fqdn:
                try:
                    # Savepoint: swallowing a DB error without one leaves the
                    # PostgreSQL transaction aborted for the rest of the device.
                    with transaction.atomic():
                        cf = device.custom_field_data or {}
                        if cf.get("fqdn") != fqdn:
                            cf["fqdn"] = fqdn
                            device.custom_field_data = cf
                            device.save()
                            log_fn(f"  Set FQDN custom field: {fqdn}")
                except Exception as exc:
                    log_fn(f"  [WARN] Could not set fqdn custom field: {exc}")

        # --- Interfaces ---
        interfaces_step_status = (data.get("step_status") or {}).get("interfaces")
        prune_stale = interfaces_step_status != "fail"
        # Interfaces reported only by get_interfaces_ip() or the LAG summary
        # are real; never let pruning treat them as stale.
        keep_names = set(interfaces_ip or {}) | set(lag_members or {})
        keep_names |= {_canonical_interface_name(n) for n in keep_names}
        interface_stats = _sync_interfaces(
            device,
            interfaces_raw,
            log_fn,
            prune_stale=prune_stale,
            options=options,
            keep_names=keep_names,
        )
        interface_journal_message = _build_interface_journal_message(interface_stats)
        if interface_journal_message:
            _add_journal_entry(device, interface_journal_message)
        _sync_lag_members(device, lag_members, log_fn)

        # --- IP Addresses ---
        primary_ip, ip_stats = _sync_ips(device, interfaces_ip, mgmt_ip, log_fn, interfaces_raw)
        ip_journal_message = _build_ip_journal_message(ip_stats)
        if ip_journal_message:
            _add_journal_entry(device, ip_journal_message)

        # --- Set primary IP ---
        existing_primary = device.primary_ip4
        ips_step_status = (data.get("step_status") or {}).get("interfaces_ip")
        can_verify_primary_presence = ips_step_status != "fail"
        existing_primary_present = (
            _is_existing_primary_present_on_device(device, interfaces_ip)
            if existing_primary and can_verify_primary_presence
            else True
        )
        if (
            primary_ip
            and existing_primary
            and existing_primary != primary_ip
            and existing_primary_present
            and _should_preserve_existing_primary(existing_primary, primary_ip)
        ):
            # Preserve user-selected/stable primary IP as long as it still
            # exists on this device. Allow a discovered management-interface
            # IP to replace an older non-management primary.
            log_fn(
                f"  Preserving existing primary IPv4 {existing_primary} on '{hostname}' "
                f"(candidate from discovery was {primary_ip})."
            )
            primary_ip = existing_primary

        if primary_ip and device.primary_ip4 != primary_ip:
            # Guard against the unique constraint on primary_ip4_id:
            # if another device already owns this IP as primary, skip rather than crash.
            conflict = Device.objects.filter(primary_ip4=primary_ip).exclude(pk=device.pk).first()
            if conflict:
                # Gather extra context: what interface is the IP currently assigned to?
                assigned_iface = primary_ip.assigned_object
                assigned_desc = (
                    f"{assigned_iface.device.name}/{assigned_iface.name}"
                    if assigned_iface and hasattr(assigned_iface, "device")
                    else str(assigned_iface) if assigned_iface else "unassigned"
                )

                # Auto-resolve: if the blocking device is a domain-variant of the
                # current device (same base hostname, different suffix), the conflict
                # is a stale duplicate.  Strip the primary-IP claim from the stale
                # device so this device can take it.
                if _base_hostname(conflict.name) == _base_hostname(hostname):
                    try:
                        conflict.primary_ip4 = None
                        conflict.save()
                        device.primary_ip4 = primary_ip
                        device.save()
                        _add_journal_entry(
                            conflict,
                            (
                                "Discovery cleared primary IPv4 during domain-variant conflict auto-resolution: "
                                f"{primary_ip} moved to '{hostname}'."
                            ),
                        )
                        _add_journal_entry(
                            device,
                            (
                                "Discovery auto-resolved primary IPv4 conflict by clearing "
                                f"domain-variant '{conflict.name}' and assigning {primary_ip}."
                            ),
                        )
                        log_fn(
                            f"  Auto-resolved primary IP conflict: cleared primary from "
                            f"domain-variant '{conflict.name}' (id={conflict.pk}), "
                            f"assigned {primary_ip} to '{hostname}'."
                        )
                    except Exception as exc:
                        log_fn(f"  [WARN] Could not auto-resolve IP conflict: {exc}")
                else:
                    warn_msg = (
                        f"  [WARN] Primary IP conflict — cannot assign {primary_ip} to '{hostname}' "
                        f"(mgmt={mgmt_ip}): already primary on '{conflict.name}' "
                        f"(id={conflict.pk}, site={conflict.site}). "
                        f"IP currently assigned to interface: {assigned_desc}."
                    )
                    log_fn(warn_msg)
                    _get_conflict_logger().warning(
                        "PRIMARY IP CONFLICT | wanted_device=%s (id=%s, mgmt=%s) | "
                        "blocking_device=%s (id=%s, site=%s) | "
                        "ip=%s (id=%s) | ip_assigned_to=%s",
                        hostname, device.pk, mgmt_ip,
                        conflict.name, conflict.pk, conflict.site,
                        primary_ip, primary_ip.pk, assigned_desc,
                    )
            else:
                device.primary_ip4 = primary_ip
                device.save()
                _add_journal_entry(
                    device,
                    f"Discovery set primary IPv4 to {primary_ip} (mgmt={mgmt_ip}).",
                )

        # --- VLANs ---
        # Use device.site (resolved real site) not the holding-site variable.
        _sync_vlans(vlans_raw, device.site, log_fn)

        # --- Bind VLANs to interfaces (access/trunk membership) ---
        if options.get("sync_interface_vlans", True) and vlans_raw:
            _sync_interface_vlans(device, vlans_raw, log_fn)

        # --- Prefixes from interface IPs (Tier 1.4) ---
        if options.get("create_prefixes", False):
            _sync_prefixes(interfaces_ip, device.site, log_fn)

        # --- VRFs (Tier 2.1) ---
        if options.get("collect_vrfs", False):
            vrfs_raw = data.get("vrfs", {})
            if vrfs_raw:
                _sync_vrfs(vrfs_raw, device, log_fn)

        # --- Inventory Items (Tier 2.2) ---
        if options.get("collect_inventory", False):
            inventory_items = data.get("inventory_items", [])
            if inventory_items:
                _sync_inventory_items(device, inventory_items, log_fn)

        # --- MAC address table (Tier 2.3) ---
        if options.get("collect_mac_address_table", False):
            mac_entries = data.get("mac_address_table", [])
            mac_step_status = (data.get("step_status") or {}).get("mac_address_table")
            if mac_step_status == "ok":
                _sync_mac_address_table(device, mac_entries, log_fn)

        # --- Virtual Chassis (Cisco StackWise) ---
        if len(stack_members) > 1:
            _sync_virtual_chassis(
                master_device=device,
                hostname=hostname,
                stack_members=stack_members,
                site=site,
                master_dtype=dtype,
                role=role,
                driver=driver,
                vendor=vendor,
                log_fn=log_fn,
            )

    action = "created" if was_created else "updated"
    log_fn(f"  Device '{hostname}' {action}.")
    return hostname, was_created


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _get_or_create_one(manager, defaults=None, **lookup):
    """
    get_or_create() that tolerates the row already being duplicated.

    Several NetBox models this module keys on do NOT enforce uniqueness on the
    field used for the lookup: IPAddress.address is legitimately duplicable
    (different VRFs, and ENFORCE_GLOBAL_UNIQUE defaults to off),
    VirtualChassis.name is not unique, and dcim.MACAddress has no constraint at
    all. Plain get_or_create() raises MultipleObjectsReturned when a second row
    exists, and because sync_device() wraps everything in one transaction that
    exception discarded the ENTIRE device — interfaces, IPs, VLANs and all —
    over a duplicate the plugin did not create and may not own.

    Duplicates can also appear mid-run: N crawl workers sync concurrently, so
    two threads can pass the existence check for the same object and both
    insert. The nested atomic() keeps such an IntegrityError from poisoning the
    outer transaction.

    Resolves to the lowest pk so repeated runs converge on the same row.
    """
    # Imported here, not at module scope: this module is deliberately free of
    # top-level Django imports so tests/ can load it without a NetBox install.
    from django.db import IntegrityError, transaction

    existing = manager.filter(**lookup).order_by("pk").first()
    if existing is not None:
        return existing, False

    try:
        with transaction.atomic():
            return manager.get_or_create(defaults=defaults or {}, **lookup)
    except manager.model.MultipleObjectsReturned:
        return manager.filter(**lookup).order_by("pk").first(), False
    except IntegrityError:
        # Lost a race with another worker; whatever it inserted is what we want.
        found = manager.filter(**lookup).order_by("pk").first()
        if found is None:
            raise
        return found, False


def _ensure_site(name: str):
    from dcim.models import Site

    site = Site.objects.filter(name__iexact=name).first()
    if site is None:
        site, created = _get_or_create_one(
            Site.objects,
            defaults={"slug": make_slug(name), "status": "active"},
            name=name,
        )
        if created:
            logger.info("Created holding site: %s", name)
    return site


def _ensure_role(name: str, color: str = "9e9e9e"):
    from dcim.models import DeviceRole

    role = DeviceRole.objects.filter(name__iexact=name).first()
    if role is None:
        role, created = _get_or_create_one(
            DeviceRole.objects,
            defaults={"slug": make_slug(name), "color": color},
            name=name,
        )
        if created:
            logger.info("Created device role: %s", name)
    return role


def _sync_device_tags(device, tag_slugs: List[str], log_fn: Callable):
    """
    Ensure the device has all auto-classified tags attached.
    Creates tags that don't exist yet. Never removes existing tags.
    """
    from extras.models import Tag

    if not tag_slugs:
        return

    existing_slugs = set(device.tags.values_list("slug", flat=True))
    added = []

    for slug in tag_slugs:
        if slug in existing_slugs:
            continue
        tag = Tag.objects.filter(slug=slug).first()
        if tag is None:
            # Create with a human-readable name (capitalize, replace hyphens)
            display_name = slug.replace("-", " ").title()
            tag, created = _get_or_create_one(
                Tag.objects,
                defaults={"name": display_name},
                slug=slug,
            )
        device.tags.add(tag)
        added.append(slug)

    if added:
        log_fn(f"  Auto-tagged: {', '.join(added)}")
        _add_journal_entry(
            device,
            f"Discovery auto-tagged device: {', '.join(added)}.",
        )


# Hostnames that are known-bad: CLI error artifacts, OS identifiers, generic labels.
_INVALID_HOSTNAME_EXACT = {
    "kernel", "localhost", "router", "switch", "firewall",
    "linux", "ubuntu", "debian", "centos", "redhat",
}
# Substrings/prefixes that indicate a Cisco CLI error was captured as a hostname.
_INVALID_HOSTNAME_FRAGMENTS = [
    "% invalid",
    "% incomplete",
    "% ambiguous",
    "invalid input",
    "incomplete command",
]


def _is_valid_hostname(hostname: str) -> bool:
    """
    Return False if *hostname* looks like a CLI error artifact or a non-network
    device identifier rather than a real network device hostname.
    """
    if not hostname:
        return False
    h = hostname.strip()
    # Reject the raw management IP as a hostname (fallback — we handle it upstream)
    if not h or h.startswith("^"):
        return False
    h_lower = h.lower()
    if h_lower in _INVALID_HOSTNAME_EXACT:
        return False
    for frag in _INVALID_HOSTNAME_FRAGMENTS:
        if frag in h_lower:
            return False
    return True


def _match_site_by_hostname(hostname: str, exclude_site_name: str = "Holding"):
    """
    Find the NetBox site whose name best matches as a prefix of the hostname.

    Strips domain suffix and normalises separators before comparing so that
    e.g. hostname 'GBLON10SWI01' matches site 'GBLON10'.  The longest matching
    prefix wins (most specific site).  Requires at least 4 characters to avoid
    spurious single-letter matches.

    Returns the matching Site object, or None.
    """
    from dcim.models import Site

    short = hostname.split(".")[0].upper()
    if len(short) < 4:
        return None

    def _norm(s: str) -> str:
        return re.sub(r"[-_\s]", "", s).upper()

    norm_short = _norm(short)
    best_site = None
    best_len = 0

    for site in Site.objects.exclude(name__iexact=exclude_site_name):
        norm_name = _norm(site.name)
        if len(norm_name) < 4:
            continue
        if norm_short.startswith(norm_name) and len(norm_name) > best_len:
            best_len = len(norm_name)
            best_site = site

    return best_site


def _get_or_create_device(
    hostname: str,
    mgmt_ip: str,
    site,
    device_type,
    role,
    serial: str,
) -> Tuple[Any, bool]:
    from dcim.models import Device
    from django.db.models import Q

    # 1. Try match by exact hostname
    device = Device.objects.filter(name=hostname).first()
    if device:
        return device, False

    # 2. Try match by the management IP, whatever prefix length it is stored
    #    with. This used to look up only "<ip>/32", but interface IPs are
    #    stored with their real mask (e.g. /24), so a renamed device was
    #    almost never matched and a duplicate was created instead.
    from ipam.models import IPAddress

    for ip_obj in IPAddress.objects.filter(address__net_host=mgmt_ip).order_by("pk"):
        iface = ip_obj.assigned_object
        if iface is not None and getattr(iface, "device", None):
            return iface.device, False

    # 3. Try match by base hostname (same short name, different domain suffix).
    #    e.g. "router1.emea.bcd.local" matches existing "router1.us.bcd.local"
    #    or bare "router1" to avoid creating duplicates under different domains.
    base = _base_hostname(hostname)
    if base:
        device = (
            Device.objects.filter(
                Q(name__iexact=base) | Q(name__istartswith=base + ".")
            )
            .exclude(name=hostname)
            .first()
        )
        if device:
            logger.info(
                "Domain-variant match: incoming '%s' matched existing device '%s' (id=%s)",
                hostname, device.name, device.pk,
            )
            return device, False

    # 4. Create new device. The same device can be reached through two of its
    #    IPs by two workers at once; whoever loses the insert race reuses the
    #    winner's row instead of failing the whole sync.
    device, created = _get_or_create_one(
        Device.objects,
        defaults={
            "site": site,
            "device_type": device_type,
            "role": role,
            "serial": serial,
            "status": "active",
        },
        name=hostname,
    )
    if created:
        logger.info("Created new device: %s", hostname)
    return device, created


def _device_decommission_status() -> str:
    try:
        from dcim.choices import DeviceStatusChoices

        for attr in ("STATUS_DECOMMISSIONING", "DECOMMISSIONING"):
            if hasattr(DeviceStatusChoices, attr):
                return getattr(DeviceStatusChoices, attr)
    except Exception:
        pass
    return "decommissioning"


def _next_available_device_name(base_name: str) -> str:
    from dcim.models import Device

    if not Device.objects.filter(name=base_name).exists():
        return base_name

    idx = 1
    while True:
        candidate = f"{base_name}-old-{idx}"
        if not Device.objects.filter(name=candidate).exists():
            return candidate
        idx += 1


def _perform_hardware_refresh(old_device, hostname: str, new_device_type, role, serial: str, log_fn: Callable):
    from dcim.models import Device, Interface
    from django.contrib.contenttypes.models import ContentType
    from ipam.models import IPAddress

    old_model = old_device.device_type.model if old_device.device_type_id else "Unknown"
    new_model = new_device_type.model
    old_serial = old_device.serial or "N/A"

    # Clear IP ownership from interfaces on the old device so the replacement can
    # safely claim the same addresses during sync (notably management/primary IP).
    iface_ids = list(
        Interface.objects.filter(device=old_device).values_list("pk", flat=True)
    )
    released_ip_count = 0
    if iface_ids:
        iface_ct = ContentType.objects.get_for_model(Interface)
        ips_to_release = IPAddress.objects.filter(
            assigned_object_type=iface_ct,
            assigned_object_id__in=iface_ids,
        )
        released_ip_count = ips_to_release.count()
        ips_to_release.update(assigned_object_type=None, assigned_object_id=None)

    if old_device.primary_ip4_id or getattr(old_device, "primary_ip6_id", None):
        old_device.primary_ip4 = None
        if hasattr(old_device, "primary_ip6"):
            old_device.primary_ip6 = None

    archive_name = _next_available_device_name(old_device.name)
    old_device_name = old_device.name
    old_device.status = _device_decommission_status()
    old_device.name = archive_name
    # Clear virtual chassis membership so the replacement can claim the same
    # vc_position — the DB unique constraint (virtual_chassis_id, vc_position)
    # would otherwise block the new device from joining the same stack slot.
    old_device.virtual_chassis = None
    old_device.vc_position = None
    old_device.vc_priority = None
    old_device.save()

    replacement = Device.objects.create(
        name=hostname,
        site=old_device.site,
        device_type=new_device_type,
        role=role,
        serial=serial,
        status="active",
        platform=old_device.platform,
        tenant=old_device.tenant,
        location=old_device.location,
        comments=old_device.comments,
        custom_field_data=old_device.custom_field_data or {},
    )
    replacement.tags.set(old_device.tags.all())

    refresh_note = (
        "Discovery detected hardware refresh (serial and model changed): "
        f"{old_model}/{old_serial} -> {new_model}/{serial}. "
        f"Decommissioned prior device '{archive_name}' and created replacement '{hostname}'."
    )
    _add_journal_entry(old_device, refresh_note)
    _add_journal_entry(replacement, refresh_note)
    log_fn(
        f"  [Refresh] {old_model}/{old_serial} replaced by {new_model}/{serial}. "
        f"Archived '{old_device_name}' as '{archive_name}' (status={old_device.status}, "
        f"released_ips={released_ip_count})."
    )
    return replacement


# Every interface this plugin creates carries this tag. Stale-interface pruning
# (opt-in) only ever touches tagged interfaces, so interfaces an operator or
# another tool created are never deleted.
DISCOVERY_TAG_SLUG = "discovered-by-nbdiscovery"
DISCOVERY_TAG_NAME = "Discovered by nbdiscovery"


def _tag_as_discovered(obj, log_fn: Optional[Callable] = None) -> None:
    """Attach the discovery tag to *obj*. Best-effort; never aborts the sync."""
    try:
        from django.db import transaction
        from extras.models import Tag
    except ImportError:
        return
    try:
        # Savepoint so a failure here cannot poison the device transaction.
        with transaction.atomic():
            tag, _ = _get_or_create_one(
                Tag.objects,
                defaults={"name": DISCOVERY_TAG_NAME},
                slug=DISCOVERY_TAG_SLUG,
            )
            obj.tags.add(tag)
    except Exception as exc:
        if log_fn:
            log_fn(f"  [WARN] Could not tag {obj} as discovered: {exc}")


def _get_or_create_interface(device, name: str, iface_type: str, log_fn: Callable, authoritative: bool = False):
    """
    Return (interface, created) for *name* on *device*.

    Matching is case-insensitive: NX-OS reports "port-channel1" while older
    plugin versions stored "Port-Channel1", and an exact-match lookup created
    a second interface next to the first.

    With authoritative=True (the name comes straight from get_interfaces()),
    an interface stored under the name the old canonicalization produced
    (mgmt0 → Management0, Junos ae0 → Port-Channel0) or under a different
    case is renamed to the device's own spelling, so it keeps its cables and
    IPs instead of being replaced.
    """
    from dcim.models import Interface

    iface = Interface.objects.filter(device=device, name__iexact=name).first()
    if iface is None and authoritative:
        legacy = _legacy_canonical_interface_name(name)
        if legacy and legacy.lower() != name.lower():
            iface = Interface.objects.filter(device=device, name__iexact=legacy).first()

    if iface is not None:
        if authoritative and iface.name != name:
            old_name = iface.name
            iface.name = name
            iface.save()
            log_fn(f"  [Interface] Renamed {device.name}/{old_name} -> {name} (device's own spelling).")
        return iface, False

    iface, created = _get_or_create_one(
        Interface.objects,
        defaults={"type": iface_type},
        device=device,
        name=name,
    )
    if created:
        _tag_as_discovered(iface, log_fn)
    return iface, created


def _is_misclassified_lag(iface, new_type: str) -> bool:
    """True when an earlier version typed a plain port (e.g. FortiGate port1) as a LAG."""
    from dcim.models import Interface

    if iface.type != "lag" or new_type == "lag":
        return False
    return Interface.objects.filter(device=iface.device, lag_id=iface.pk).first() is None


def _sync_interfaces(
    device,
    interfaces_raw: Dict,
    log_fn: Callable,
    prune_stale: bool = True,
    options: Optional[Dict] = None,
    keep_names=None,
):
    """
    Create/update the device's interfaces from get_interfaces() output.

    prune_stale is False when get_interfaces() failed. Pruning also requires
    the prune_stale_interfaces option, and keep_names lists interfaces
    reported elsewhere (interfaces_ip, LAG summaries) that are not stale.
    """
    from dcim.models import Interface
    from django.db import transaction

    if options is None:
        options = {}
    sync_speed = options.get("sync_interface_speed", True)
    prune_enabled = options.get("prune_stale_interfaces", False)

    created_count = 0
    updated_count = 0
    deleted_names: List[str] = []
    delete_failed = 0
    delete_skipped_cabled = 0
    prune_skipped = False
    normalized_raw = _normalize_interfaces_payload(interfaces_raw)
    desired_ifaces = set(normalized_raw.keys())

    for iface_name, iface_data in normalized_raw.items():
        iface_type = map_interface_type(iface_name, iface_data.get("speed"))
        iface, created = _get_or_create_interface(
            device, iface_name, iface_type, log_fn, authoritative=True
        )
        if created:
            created_count += 1

        enabled = iface_data.get("is_enabled", True)
        description = ((iface_data.get("description") or "")[:200]).strip()
        mtu = iface_data.get("mtu") or None
        mac = (iface_data.get("mac_address") or "").upper() or None

        changed_fields: List[str] = []

        # Only replace a type we set generically ourselves. The type used to
        # be rewritten on every run, reverting operator corrections such as
        # 1000base-x-sfp on an SFP GigabitEthernet port.
        if iface.type != iface_type and (
            iface.type in _REPLACEABLE_INTERFACE_TYPES
            or _is_misclassified_lag(iface, iface_type)
        ):
            iface.type = iface_type
            changed_fields.append("type")
        if iface.enabled != enabled:
            iface.enabled = enabled
            changed_fields.append("enabled")
        if (iface.description or "").strip() != description:
            iface.description = description
            changed_fields.append("description")
        if mtu and iface.mtu != mtu:
            iface.mtu = mtu
            changed_fields.append("mtu")
        if mac and _assign_interface_mac(iface, mac):
            changed_fields.append("primary_mac_address")

        # Interface speed sync (Tier 1.2) — NAPALM reports Mbps, NetBox stores kbps
        if sync_speed:
            speed_mbps = iface_data.get("speed", 0) or 0
            if speed_mbps > 0:
                speed_kbps = int(speed_mbps * 1000)
                if iface.speed != speed_kbps:
                    iface.speed = speed_kbps
                    changed_fields.append("speed")

        if changed_fields:
            iface.save()
            if not created:
                updated_count += 1
                log_fn(
                    f"  [Interface] Updated {device.name}/{iface_name}: "
                    f"{', '.join(changed_fields)}"
                )

    # Pruning is opt-in and limited to interfaces this plugin created. It also
    # requires a non-empty payload from a get_interfaces() call that did not
    # fail, so empty collector output can never cause mass deletion.
    stale_count = 0
    if desired_ifaces and prune_enabled and not prune_stale:
        prune_skipped = True
        log_fn(
            f"  [WARN] Interface pruning skipped for {device.name}: "
            "get_interfaces() failed for this device in the collector."
        )
    elif desired_ifaces and prune_enabled:
        keep_lower = {name.lower() for name in desired_ifaces}
        keep_lower.update(name.lower() for name in (keep_names or ()) if name)
        stale = [
            iface
            for iface in Interface.objects.filter(device=device, tags__slug=DISCOVERY_TAG_SLUG)
            if iface.name.lower() not in keep_lower
        ]
        stale_count = len(stale)
        if stale_count:
            log_fn(
                f"  [Interface] Reconciling {device.name}: discovered={len(desired_ifaces)}, "
                f"stale={stale_count}."
            )
        for stale_iface in stale:
            stale_name = stale_iface.name
            if getattr(stale_iface, "cable_id", None):
                # Never delete a cable: a stale interface that is still
                # cabled is left for an operator to review.
                delete_skipped_cabled += 1
                log_fn(
                    f"  [Interface] Kept stale interface {device.name}/{stale_name}: "
                    "it still has a cable attached."
                )
                continue
            try:
                # Savepoint: a failed delete must not abort the device's
                # enclosing transaction.
                with transaction.atomic():
                    _detach_interface_dependencies(stale_iface, log_fn)
                    stale_iface.delete()
                deleted_names.append(stale_name)
                log_fn(f"  [Interface] Deleted stale interface {device.name}/{stale_name}")
            except Exception as exc:
                delete_failed += 1
                log_fn(
                    f"  [WARN] Could not delete stale interface {device.name}/{stale_name}: "
                    f"{type(exc).__name__}: {exc}"
                )

    return {
        "created": created_count,
        "updated": updated_count,
        "deleted": len(deleted_names),
        "deleted_names": deleted_names,
        "delete_failed": delete_failed,
        "delete_skipped_cabled": delete_skipped_cabled,
        "prune_skipped": prune_skipped,
        "stale_count": stale_count,
    }


def _detach_interface_dependencies(iface, log_fn: Callable) -> None:
    """
    Remove references that commonly block stale interface deletion.

    Cables are deliberately not touched: callers skip cabled interfaces.
    """
    from dcim.models import Interface
    from django.contrib.contenttypes.models import ContentType
    from ipam.models import IPAddress

    # Remove any child LAG memberships if this interface is a parent LAG.
    if hasattr(Interface, "lag"):
        detached_members = Interface.objects.filter(device=iface.device, lag_id=iface.pk).update(lag=None)
        if detached_members:
            log_fn(
                f"  [Interface] Detached {detached_members} member interface(s) from stale LAG "
                f"{iface.device.name}/{iface.name}."
            )

    # If this stale interface is a LAG member, detach it from its parent.
    if getattr(iface, "lag_id", None):
        iface.lag = None
        iface.save(update_fields=["lag"])
        log_fn(f"  [Interface] Detached stale interface {iface.device.name}/{iface.name} from LAG.")

    # Detach parent/child interface relationships (subinterfaces).
    if hasattr(Interface, "parent"):
        detached_children = Interface.objects.filter(device=iface.device, parent_id=iface.pk).update(parent=None)
        if detached_children:
            log_fn(
                f"  [Interface] Detached {detached_children} child interface(s) from stale parent "
                f"{iface.device.name}/{iface.name}."
            )
        if getattr(iface, "parent_id", None):
            iface.parent = None
            iface.save(update_fields=["parent"])
            log_fn(f"  [Interface] Detached stale interface {iface.device.name}/{iface.name} from parent.")

    # Unassign any IPs from this interface before deletion.
    iface_ct = ContentType.objects.get_for_model(Interface)
    ips_qs = IPAddress.objects.filter(
        assigned_object_type=iface_ct,
        assigned_object_id=iface.pk,
    )
    ip_count = ips_qs.count()
    if ip_count:
        ips_qs.update(assigned_object_type=None, assigned_object_id=None)
        log_fn(f"  [Interface] Unassigned {ip_count} IP(s) from stale interface {iface.device.name}/{iface.name}.")


def _sync_lag_members(device, lag_members: Dict[str, List[str]], log_fn: Callable):
    from dcim.models import Interface

    if not lag_members:
        return

    lag_field_supported = hasattr(Interface, "lag")
    if not lag_field_supported:
        log_fn("  [WARN] Interface LAG relationships are not supported by this NetBox version.")
        return

    managed_lags = {}
    desired_members_by_lag_id: Dict[int, set] = {}
    unresolved_members: List[str] = []

    for lag_name, member_names in lag_members.items():
        lag_name = _canonical_interface_name(lag_name)
        lag_iface = _find_interface(device, lag_name)
        if lag_iface is None:
            lag_iface, _ = _get_or_create_interface(device, lag_name, "lag", log_fn)
        elif lag_iface.type != "lag":
            lag_iface.type = "lag"
            lag_iface.save()

        managed_lags[lag_iface.pk] = lag_iface
        desired_member_names = set()

        for member_name in member_names:
            member_name = _canonical_interface_name(member_name)
            member_iface = _find_interface(device, member_name)
            if member_iface is None:
                unresolved_members.append(member_name)
                log_fn(
                    f"  [WARN] LAG member '{member_name}' on {device.name} was not found in "
                    "discovered interfaces; skipping assignment to avoid duplicate interface creation."
                )
                continue
            desired_member_names.add(member_iface.name)

            current_lag = getattr(member_iface, "lag", None)
            if getattr(member_iface, "lag_id", None) != lag_iface.pk:
                old_lag_desc = current_lag.name if current_lag else "none"
                member_iface.lag = lag_iface
                member_iface.save()
                log_fn(
                    f"  [LAG] {device.name}/{member_iface.name} joined {lag_iface.name} "
                    f"(previous={old_lag_desc})."
                )
                _add_journal_entry(
                    member_iface,
                    (
                        f"Discovery updated LAG membership on {device.name}: interface "
                        f"{member_iface.name} moved from {old_lag_desc} to {lag_iface.name}."
                    ),
                )

        desired_members_by_lag_id[lag_iface.pk] = desired_member_names

    for iface in Interface.objects.filter(device=device).exclude(lag__isnull=True).select_related("lag"):
        current_lag_id = getattr(iface, "lag_id", None)
        if current_lag_id not in managed_lags:
            continue
        if iface.name in desired_members_by_lag_id.get(current_lag_id, set()):
            continue

        old_lag = iface.lag
        iface.lag = None
        iface.save()
        log_fn(f"  [LAG] {device.name}/{iface.name} removed from {old_lag.name}.")
        _add_journal_entry(
            iface,
            (
                f"Discovery removed interface {iface.name} from LAG {old_lag.name} "
                f"on {device.name} because it is no longer reported as a member."
            ),
        )

def _sync_ips(device, interfaces_ip: Dict, mgmt_ip: str, log_fn: Callable, interfaces_raw: Dict = None):
    from dcim.models import Interface
    from django.contrib.contenttypes.models import ContentType
    from ipam.models import IPAddress

    iface_ct = ContentType.objects.get_for_model(Interface)
    preferred_primary_ip = _preferred_management_interface_ip(interfaces_ip, interfaces_raw) or mgmt_ip
    primary_ip = None
    stats = {
        "created": 0,
        "reassigned": 0,
        "conflicts": 0,
        "mgmt_created": 0,
    }

    for iface_name, addr_families in interfaces_ip.items():
        iface_name = _canonical_interface_name(iface_name)
        # Resolve the interface object, creating a minimal one if missing.
        iface, _ = _get_or_create_interface(
            device, iface_name, map_interface_type(iface_name), log_fn
        )

        # addr_families is {'ipv4': {'10.0.0.1': {'prefix_length': 24}}, 'ipv6': {...}}
        for family, addrs in addr_families.items():
            for ip_str, ip_info in addrs.items():
                prefix_len = ip_info.get("prefix_length", 32)
                cidr = f"{ip_str}/{prefix_len}"

                ip_obj, created = _get_or_create_one(
                    IPAddress.objects,
                    defaults={
                        "assigned_object_type": iface_ct,
                        "assigned_object_id": iface.pk,
                        "status": "active",
                    },
                    address=cidr,
                )
                if created:
                    stats["created"] += 1

                # Only move an existing IP when it's unassigned or already belongs
                # to this device. Never steal an IP from another device.
                assigned_object = ip_obj.assigned_object
                assigned_device = getattr(assigned_object, "device", None)
                if (
                    assigned_object is not None
                    and assigned_device is not None
                    and assigned_device.pk != device.pk
                ):
                    assigned_desc = f"{assigned_device.name}/{assigned_object.name}"
                    warn_msg = (
                        f"  [WARN] IP conflict — leaving {cidr} on {assigned_desc}; "
                        f"not reassigning it to {device.name}/{iface.name}."
                    )
                    log_fn(warn_msg)
                    stats["conflicts"] += 1
                    _get_conflict_logger().warning(
                        "INTERFACE IP CONFLICT | wanted_device=%s (id=%s) | "
                        "blocking_device=%s (id=%s) | ip=%s (id=%s) | "
                        "wanted_interface=%s | blocking_interface=%s",
                        device.name,
                        device.pk,
                        assigned_device.name,
                        assigned_device.pk,
                        cidr,
                        ip_obj.pk,
                        iface.name,
                        assigned_object.name,
                    )
                    continue

                if (
                    ip_obj.assigned_object_type_id != iface_ct.id
                    or ip_obj.assigned_object_id != iface.pk
                ):
                    ip_obj.assigned_object_type = iface_ct
                    ip_obj.assigned_object_id = iface.pk
                    ip_obj.save()
                    stats["reassigned"] += 1

                # Track which IP is the management IP for setting as primary.
                # Skip interfaces that are administratively shutdown.
                if family == "ipv4" and ip_str == preferred_primary_ip:
                    if not _is_interface_shutdown(iface_name, interfaces_raw):
                        primary_ip = ip_obj

    if primary_ip is None and mgmt_ip:
        primary_ip = _fallback_primary_ip(device, mgmt_ip, iface_ct, stats, log_fn)

    return primary_ip, stats


def _fallback_primary_ip(device, mgmt_ip: str, iface_ct, stats: Dict[str, int], log_fn: Callable):
    """
    Resolve a primary IP for an address that was not on any collected
    interface (a NAT/VIP address, or get_interfaces_ip() failed).

    NetBox requires a device's primary IP to be assigned to one of that
    device's own interfaces; its device form refuses to save otherwise. This
    used to pick whatever row matched "<ip>/32" — including one assigned to
    a different device — or create an unassigned /32, and make it primary.
    Now the address is only used when it already sits on this device, or is
    free and can be attached to this device's management interface.
    """
    from dcim.models import Interface
    from ipam.models import IPAddress

    candidates = list(IPAddress.objects.filter(address__net_host=mgmt_ip).order_by("pk"))
    for candidate in candidates:
        owner = getattr(candidate.assigned_object, "device", None)
        if owner is not None and owner.pk == device.pk:
            return candidate

    assigned_elsewhere = [c for c in candidates if c.assigned_object is not None]
    if assigned_elsewhere:
        other = assigned_elsewhere[0].assigned_object
        owner_name = getattr(getattr(other, "device", None), "name", None) or str(other)
        log_fn(
            f"  [WARN] Management IP {mgmt_ip} is assigned to {owner_name}; "
            f"not using it as the primary IP of {device.name}."
        )
        stats["conflicts"] += 1
        return None

    mgmt_iface = next(
        (
            iface
            for iface in Interface.objects.filter(device=device)
            if _is_management_interface_name(iface.name)
        ),
        None,
    )
    if mgmt_iface is None:
        log_fn(
            f"  [WARN] {mgmt_ip} is not on any collected interface of {device.name} and the "
            "device has no management interface to hold it; primary IP left unchanged."
        )
        return None

    if candidates:
        ip_obj = candidates[0]
        ip_obj.assigned_object_type = iface_ct
        ip_obj.assigned_object_id = mgmt_iface.pk
        ip_obj.save()
        stats["reassigned"] += 1
        return ip_obj

    ip_obj, created = _get_or_create_one(
        IPAddress.objects,
        defaults={
            "status": "active",
            "assigned_object_type": iface_ct,
            "assigned_object_id": mgmt_iface.pk,
        },
        address=f"{mgmt_ip}/{128 if ':' in mgmt_ip else 32}",
    )
    if created:
        stats["mgmt_created"] += 1
    return ip_obj


def _should_preserve_existing_primary(existing_primary, candidate_primary) -> bool:
    """
    Preserve an existing primary IP unless discovery found a management
    interface IP and the current primary is not on a management port.
    """
    if existing_primary is None or candidate_primary is None:
        return False

    existing_iface = getattr(existing_primary, "assigned_object", None)
    candidate_iface = getattr(candidate_primary, "assigned_object", None)
    existing_iface_name = getattr(existing_iface, "name", "")
    candidate_iface_name = getattr(candidate_iface, "name", "")

    if (
        candidate_iface_name
        and _is_management_interface_name(candidate_iface_name)
        and not _is_management_interface_name(existing_iface_name)
    ):
        return False

    return True


def _is_existing_primary_present_on_device(device, interfaces_ip: Dict) -> bool:
    """
    Return True when device.primary_ip4 still exists on one of this device's
    currently collected interfaces.
    """
    primary = getattr(device, "primary_ip4", None)
    if primary is None:
        return False

    assigned_obj = getattr(primary, "assigned_object", None)
    assigned_dev = getattr(assigned_obj, "device", None)
    if assigned_obj is None or assigned_dev is None or assigned_dev.pk != device.pk:
        return False

    collected_cidrs = set()
    for _iface_name, addr_families in (interfaces_ip or {}).items():
        ipv4 = (addr_families or {}).get("ipv4", {})
        for ip_str, ip_info in (ipv4 or {}).items():
            try:
                prefix_len = (ip_info or {}).get("prefix_length", 32)
            except Exception:
                prefix_len = 32
            collected_cidrs.add(f"{ip_str}/{prefix_len}")

    return str(primary.address) in collected_cidrs


def _select_stack_master(stack_members: List[Dict]) -> Dict:
    """
    Return the stack member NetBox should treat as the VC master.

    Prefer the switch 'show switch' marks Active, then the Standby, then the
    lowest position. The old one-pass search took the first member that was
    *either* active or standby, which picked the standby whenever it had the
    lower position.
    """
    for role in ("active", "standby"):
        for member in stack_members:
            if member.get("role") == role:
                return member
    return min(stack_members, key=lambda m: m.get("position", 0))


def _free_vc_position(vc, position, keep_pk, log_fn: Callable) -> None:
    """
    Clear vc_position on whichever other device holds *position* in *vc*.

    After a stack switchover or renumbering the slot may still belong to a
    record from an earlier run. Saving another device there violates
    NetBox's unique (virtual_chassis, vc_position) constraint, and that
    IntegrityError failed the whole device on every run.
    """
    from dcim.models import Device

    occupant = (
        Device.objects.filter(virtual_chassis=vc, vc_position=position)
        .exclude(pk=keep_pk)
        .first()
    )
    if occupant is None:
        return
    occupant.vc_position = None
    occupant.save()
    log_fn(
        f"  [Stack] Freed position {position} in '{vc.name}' held by '{occupant.name}' "
        "(stack membership changed)."
    )


def _sync_virtual_chassis(
    master_device,
    hostname: str,
    stack_members: List,
    site,
    master_dtype,
    role,
    driver: str = "",
    vendor: str = "",
    log_fn: Callable = None,
):
    """
    Create / update a VirtualChassis for a Cisco StackWise stack.

    - One VirtualChassis named after the master device's hostname
    - The master device is assigned vc_position matching its 'active' role
    - Each additional stack member gets its own Device record (named
      '{base_hostname}-sw{position}') with its individual serial and model,
      and is assigned to the same VirtualChassis at its position
    """
    from dcim.models import Device, DeviceType, VirtualChassis

    active_entry = _select_stack_master(stack_members)
    master_pos = active_entry["position"]

    # Base name without domain (used for member device names)
    base = hostname.split(".")[0]

    # Create or get the VirtualChassis record
    vc, vc_created = _get_or_create_one(
        VirtualChassis.objects,
        defaults={"domain": hostname},
        name=hostname,
    )
    if vc_created:
        log_fn(f"  [Stack] Created VirtualChassis '{hostname}'")

    # After a stack switchover the master's new position may still be held
    # by the member record created for that switch on an earlier run. Saving
    # the master there would violate NetBox's unique (virtual_chassis,
    # vc_position) constraint and fail the whole device on every run, so move
    # the occupant out of the slot first. The member loop below gives it the
    # position it now reports.
    _free_vc_position(vc, master_pos, master_device.pk, log_fn)

    # Assign master device to VC
    master_changed = False
    if master_device.virtual_chassis_id != vc.pk:
        master_device.virtual_chassis = vc
        master_changed = True
    if master_device.vc_position != master_pos:
        master_device.vc_position = master_pos
        master_changed = True
    master_priority = active_entry.get("priority", 15)
    if master_device.vc_priority != master_priority:
        master_device.vc_priority = master_priority
        master_changed = True
    if master_changed:
        master_device.save()
        _add_journal_entry(
            master_device,
            (
                f"Discovery updated stack membership: virtual_chassis='{vc.name}', "
                f"position={master_device.vc_position}, priority={master_device.vc_priority}."
            ),
        )

    # Point VC master FK at this device
    if vc.master_id != master_device.pk:
        vc.master = master_device
        vc.save()

    log_fn(
        f"  [Stack] VirtualChassis '{hostname}': {len(stack_members)} member(s), "
        f"master at position {master_pos}"
    )

    # Sync non-master members
    for entry in stack_members:
        pos = entry["position"]
        if pos == master_pos:
            continue  # master already handled above

        member_serial = (entry.get("serial") or "").strip()
        member_model = (entry.get("model") or "").strip()
        member_name = f"{base}-sw{pos}"

        # Resolve DeviceType for this member (may differ from master if mixed-model stack)
        member_dtype = master_dtype
        if member_model and member_model.lower() != master_dtype.model.lower():
            found_dt = DeviceType.objects.filter(
                manufacturer=master_dtype.manufacturer,
                model__iexact=member_model,
            ).first()
            if found_dt:
                member_dtype = found_dt
            else:
                try:
                    member_dtype, _ = _get_or_create_one(
                        DeviceType.objects,
                        defaults={"slug": make_slug(f"{master_dtype.manufacturer.name}-{member_model}")},
                        manufacturer=master_dtype.manufacturer,
                        model=member_model,
                    )
                except Exception:
                    member_dtype = master_dtype  # fallback

        # Find existing member device: prefer by VC position, then by name
        mem_dev = (
            Device.objects.filter(virtual_chassis=vc, vc_position=pos).first()
            or Device.objects.filter(name=member_name).first()
        )

        # Classify member by its own model (may differ in mixed-model stacks)
        member_cls = classify_device(
            model=member_model or master_dtype.model,
            vendor=vendor,
            driver=driver,
        )
        member_role = _ensure_role(member_cls["role"], color=member_cls["color"])

        if mem_dev is None:
            mem_dev = Device.objects.create(
                name=member_name,
                site=master_device.site,
                device_type=member_dtype,
                role=member_role,
                serial=member_serial,
                status="active",
                virtual_chassis=vc,
                vc_position=pos,
                vc_priority=entry.get("priority", 1),
            )
            log_fn(
                f"  [Stack] Created member '{member_name}' "
                f"pos={pos} serial={member_serial or 'N/A'} model={member_model or 'N/A'}"
            )
            _add_journal_entry(
                mem_dev,
                (
                    "Discovery created stack member device: "
                    f"virtual_chassis='{vc.name}', position={pos}, serial={member_serial or 'N/A'}, "
                    f"model={member_model or member_dtype.model}."
                ),
            )
        else:
            changed = False
            member_changes: List[str] = []
            if mem_dev.virtual_chassis_id != vc.pk:
                mem_dev.virtual_chassis = vc
                changed = True
                member_changes.append(f"virtual_chassis -> '{vc.name}'")
            if mem_dev.vc_position != pos:
                _free_vc_position(vc, pos, mem_dev.pk, log_fn)
                mem_dev.vc_position = pos
                changed = True
                member_changes.append(f"position -> {pos}")
            if member_serial and mem_dev.serial != member_serial:
                mem_dev.serial = member_serial
                changed = True
                member_changes.append(f"serial -> '{member_serial}'")
            if mem_dev.device_type_id != member_dtype.pk:
                mem_dev.device_type = member_dtype
                changed = True
                member_changes.append(f"model -> '{member_dtype.model}'")
            if mem_dev.site_id != master_device.site_id:
                mem_dev.site = master_device.site
                changed = True
                member_changes.append(f"site -> '{master_device.site.name}'")
            if changed:
                mem_dev.save()
                log_fn(
                    f"  [Stack] Updated member '{mem_dev.name}' "
                    f"pos={pos} serial={member_serial or 'N/A'}"
                )
                _add_journal_entry(
                    mem_dev,
                    "Discovery updated stack member attributes: " + "; ".join(member_changes) + ".",
                )

        # Auto-tag member device
        _sync_device_tags(mem_dev, member_cls["tags"], log_fn)


def _sync_vlans(vlans_raw: Dict, site, log_fn: Callable):
    from ipam.models import VLAN

    for vid_str, vlan_data in vlans_raw.items():
        try:
            vid = int(vid_str)
        except (ValueError, TypeError):
            continue

        if not (1 <= vid <= 4094):
            continue

        vlan_name = vlan_data.get("name") or f"VLAN{vid}"
        matches = VLAN.objects.filter(vid=vid, site=site)
        vlan = matches.first()
        created = vlan is None
        if vlan is None:
            vlan = VLAN.objects.create(
                vid=vid,
                site=site,
                name=vlan_name,
                status="active",
            )
        elif matches.count() > 1:
            log_fn(
                f"  [WARN] Found {matches.count()} VLAN rows for VID {vid} at site {site}; "
                f"using VLAN id={vlan.pk}."
            )
        if not created and vlan.name != vlan_name and vlan.name == f"VLAN{vid}":
            # Update auto-generated names with the real name
            vlan.name = vlan_name
            vlan.save()


def _sync_interface_vlans(device, vlans_raw: Dict, log_fn: Callable) -> Dict[str, int]:
    """
    Bind VLANs to physical interfaces based on NAPALM get_vlans() output.

    NAPALM reports each VLAN's interface members as a flat list (no tagged/untagged
    distinction). Heuristic:
      - interface is in exactly one VLAN  -> mode='access', untagged_vlan=that VLAN
      - interface is in multiple VLANs    -> mode='tagged', tagged_vlans=union of those
        (untagged_vlan is left untouched: NAPALM doesn't report the native VLAN)
    Virtual interfaces (SVIs, loopbacks, port-channels, tunnels) are skipped: switchport
    mode does not apply to them.
    """
    from ipam.models import VLAN

    stats = {"access_set": 0, "tagged_set": 0, "skipped_no_vlan": 0}
    if not vlans_raw:
        return stats

    site = device.site

    iface_to_vids: Dict[str, set] = {}
    for vid_str, vlan_data in (vlans_raw or {}).items():
        try:
            vid = int(vid_str)
        except (ValueError, TypeError):
            continue
        if not (1 <= vid <= 4094):
            continue
        for raw_iface_name in (vlan_data or {}).get("interfaces", []) or []:
            canonical = _canonical_interface_name(raw_iface_name)
            if not canonical:
                continue
            iface_to_vids.setdefault(canonical, set()).add(vid)

    if not iface_to_vids:
        return stats

    vlan_by_vid: Dict[int, Any] = {}
    needed_vids = {vid for vids in iface_to_vids.values() for vid in vids}
    for vlan in VLAN.objects.filter(vid__in=needed_vids, site=site):
        vlan_by_vid.setdefault(vlan.vid, vlan)

    for iface_name, vids in iface_to_vids.items():
        iface = _find_interface(device, iface_name)
        if iface is None:
            continue
        if iface.type in ("virtual", "lag"):
            # SVIs/loopbacks/tunnels and LAG parents don't carry switchport mode here.
            # (LAG members get mode from their physical config; LAG parents are sync'd
            # separately via NAPALM's get_vlans on the bundle in some drivers — leave
            # them alone to avoid clobbering operator config.)
            continue

        resolved = [vlan_by_vid[v] for v in sorted(vids) if v in vlan_by_vid]
        if not resolved:
            stats["skipped_no_vlan"] += 1
            continue

        changed_fields: List[str] = []

        if len(resolved) == 1:
            target_vlan = resolved[0]
            if iface.mode != "access":
                iface.mode = "access"
                changed_fields.append("mode->access")
            if getattr(iface, "untagged_vlan_id", None) != target_vlan.pk:
                iface.untagged_vlan = target_vlan
                changed_fields.append(f"untagged_vlan->{target_vlan.vid}")
            if changed_fields:
                iface.save()
                stats["access_set"] += 1
                log_fn(
                    f"  [VLAN] {device.name}/{iface.name} access VLAN {target_vlan.vid} "
                    f"({', '.join(changed_fields)})."
                )
        else:
            if iface.mode != "tagged":
                iface.mode = "tagged"
                changed_fields.append("mode->tagged")
                iface.save()
            current_vids = set(iface.tagged_vlans.values_list("vid", flat=True))
            desired_vids = {v.vid for v in resolved}
            if current_vids != desired_vids:
                iface.tagged_vlans.set(resolved)
                changed_fields.append(f"tagged_vlans={sorted(desired_vids)}")
            if changed_fields:
                stats["tagged_set"] += 1
                log_fn(
                    f"  [VLAN] {device.name}/{iface.name} trunk "
                    f"({', '.join(changed_fields)})."
                )

    return stats


def _sync_mac_address_table(device, mac_entries: List[Dict], log_fn: Callable) -> Dict[str, int]:
    """
    Replace this device's stored MAC address table with the latest discovery snapshot.

    The table is transient (entries age out / move quickly), so we delete the previous
    snapshot for the device in a single transaction and insert the new entries. Each
    entry resolves an interface name to a NetBox Interface where possible, and a VLAN
    to a NetBox VLAN at the device's site where possible.
    """
    from django.db import transaction
    from ipam.models import VLAN

    from netbox_discovery.models import MacAddressTableEntry

    stats = {"inserted": 0, "removed": 0, "unresolved_interfaces": 0}
    site = device.site

    iface_cache: Dict[str, Any] = {}

    def _resolve_iface(name: str):
        key = name.lower()
        if key in iface_cache:
            return iface_cache[key]
        resolved = _find_interface(device, name)
        iface_cache[key] = resolved
        return resolved

    needed_vids = {e["vlan"] for e in mac_entries if e.get("vlan")}
    vlan_by_vid: Dict[int, Any] = {}
    if needed_vids:
        for vlan in VLAN.objects.filter(vid__in=needed_vids, site=site):
            vlan_by_vid.setdefault(vlan.vid, vlan)

    rows: List[MacAddressTableEntry] = []
    seen_keys: set = set()
    for entry in mac_entries:
        mac = entry.get("mac", "")
        iface_name = entry.get("interface", "")
        vlan_vid = entry.get("vlan") or None
        if not mac or not iface_name:
            continue

        # The unique constraint is on (device, mac, vlan_vid, interface_name).
        # NAPALM occasionally double-reports identical entries — dedupe before insert.
        key = (mac, vlan_vid, iface_name.lower())
        if key in seen_keys:
            continue
        seen_keys.add(key)

        iface = _resolve_iface(iface_name)
        if iface is None:
            stats["unresolved_interfaces"] += 1

        rows.append(
            MacAddressTableEntry(
                device=device,
                interface=iface,
                interface_name=iface_name,
                mac_address=mac,
                vlan=vlan_by_vid.get(vlan_vid) if vlan_vid else None,
                vlan_vid=vlan_vid,
                is_static=bool(entry.get("static", False)),
                is_active=bool(entry.get("active", True)),
            )
        )

    with transaction.atomic():
        existing_qs = MacAddressTableEntry.objects.filter(device=device)
        stats["removed"] = existing_qs.count()
        existing_qs.delete()
        if rows:
            MacAddressTableEntry.objects.bulk_create(rows, batch_size=500)
            stats["inserted"] = len(rows)

    if stats["inserted"] or stats["removed"]:
        log_fn(
            f"  [MAC] {device.name}: {stats['inserted']} entries stored "
            f"(replaced {stats['removed']}; "
            f"unresolved_interfaces={stats['unresolved_interfaces']})."
        )

    return stats


def _sync_platform(device, driver_name: str, manufacturer, log_fn: Callable):
    """Map NAPALM driver to a NetBox Platform and assign to device (Tier 1.1)."""
    from dcim.models import Platform

    platform = Platform.objects.filter(name__iexact=driver_name).first()
    if platform is None:
        defaults = {
            "slug": make_slug(driver_name),
            "manufacturer": manufacturer,
        }
        # NetBox 4.x removed Platform.napalm_driver. Keep backward compatibility
        # for environments that still expose the field.
        if any(f.name == "napalm_driver" for f in Platform._meta.get_fields()):
            defaults["napalm_driver"] = driver_name

        platform, created = _get_or_create_one(
            Platform.objects,
            defaults=defaults,
            name=driver_name,
        )
        if created:
            log_fn(f"  Created Platform '{driver_name}'")

    if device.platform_id != platform.pk:
        old_platform = getattr(device.platform, "name", "none") if device.platform_id else "none"
        device.platform = platform
        device.save()
        log_fn(f"  Set platform: {old_platform} -> {driver_name}")
        _add_journal_entry(
            device,
            f"Discovery set platform to '{driver_name}' (from NAPALM driver).",
        )


def _sync_prefixes(interfaces_ip: Dict, site, log_fn: Callable):
    """Create Prefix records from interface IP/prefix pairs (Tier 1.4)."""
    import netaddr
    from django.db import transaction
    from ipam.models import Prefix

    created_count = 0
    error_count = 0
    for _iface_name, addr_families in interfaces_ip.items():
        for family, addrs in addr_families.items():
            for ip_str, ip_info in addrs.items():
                prefix_len = ip_info.get("prefix_length", 32 if family == "ipv4" else 128)
                # Skip host routes and link-local
                if family == "ipv4" and prefix_len >= 32:
                    continue
                if family == "ipv6" and prefix_len >= 128:
                    continue
                try:
                    network = netaddr.IPNetwork(f"{ip_str}/{prefix_len}")
                    if network.ip.is_link_local() or network.ip.is_loopback():
                        continue
                    cidr = str(network.cidr)
                    defaults = {"status": "active"}
                    if site is not None:
                        # NetBox 4.2+ uses a generic scope field instead of Prefix.site.
                        if hasattr(Prefix, "scope"):
                            defaults["scope"] = site
                        elif hasattr(Prefix, "site"):
                            defaults["site"] = site
                    # Global table only, matching the VRF-less IPs sync creates.
                    # Plain get_or_create(prefix=...) raised
                    # MultipleObjectsReturned whenever the same prefix also
                    # existed in a VRF, which is routine. The savepoint keeps a
                    # DB error here from aborting the device's transaction.
                    with transaction.atomic():
                        _, created = _get_or_create_one(
                            Prefix.objects,
                            defaults=defaults,
                            prefix=cidr,
                            vrf=None,
                        )
                    if created:
                        created_count += 1
                except Exception as exc:
                    error_count += 1
                    log_fn(f"  [WARN] Failed to sync prefix {ip_str}/{prefix_len}: {exc}")
                    continue

    if created_count:
        log_fn(f"  [Prefix] Created {created_count} prefix(es)")
    if error_count:
        log_fn(f"  [WARN] Prefix sync had {error_count} error(s)")


def _sync_vrfs(vrfs_raw: Dict, device, log_fn: Callable):
    """Create VRF records from get_network_instances() data (Tier 2.1)."""
    from ipam.models import VRF, RouteTarget

    created_count = 0
    updated_count = 0
    warning_count = 0
    rt_created_count = 0
    rt_linked_count = 0
    iface_linked_count = 0
    ip_linked_count = 0

    for vrf_name, vrf_data in vrfs_raw.items():
        if not vrf_name or vrf_name.lower() in ("default", "global"):
            continue
        rd = ""
        state = vrf_data.get("state", {})
        if isinstance(state, dict):
            rd = state.get("route_distinguisher", "") or ""

        rd = str(rd).strip()
        rd_is_placeholder = rd.lower() in {"", "0:0", "0:0:0", "none", "n/a", "na"}

        matching_vrfs = VRF.objects.filter(name__iexact=vrf_name)
        matching_count = matching_vrfs.count()
        vrf = matching_vrfs.first()
        if matching_count > 1:
            warning_count += 1
            log_fn(
                f"  [WARN] Found {matching_count} existing VRFs named '{vrf_name}'; "
                f"using VRF id={vrf.pk}."
            )

        if vrf is None:
            create_kwargs = {"name": vrf_name}
            if rd and not rd_is_placeholder:
                conflicting_rd_vrf = VRF.objects.filter(rd=rd).first()
                if conflicting_rd_vrf is None:
                    create_kwargs["rd"] = rd
                else:
                    warning_count += 1
                    log_fn(
                        f"  [WARN] Skipping RD '{rd}' for VRF '{vrf_name}' because it is "
                        f"already used by VRF '{conflicting_rd_vrf.name}' (id={conflicting_rd_vrf.pk})."
                    )
            vrf = VRF.objects.create(**create_kwargs)
            created_count += 1
        else:
            if rd and not rd_is_placeholder and (vrf.rd or "").strip() != rd:
                conflicting_rd_vrf = VRF.objects.filter(rd=rd).exclude(pk=vrf.pk).first()
                if conflicting_rd_vrf is not None:
                    warning_count += 1
                    log_fn(
                        f"  [WARN] Leaving RD unchanged for VRF '{vrf_name}' because RD '{rd}' is "
                        f"already used by VRF '{conflicting_rd_vrf.name}' (id={conflicting_rd_vrf.pk})."
                    )
                elif not (vrf.rd or "").strip():
                    vrf.rd = rd
                    vrf.save()
                    updated_count += 1
                else:
                    warning_count += 1
                    log_fn(
                        f"  [WARN] Leaving existing RD '{vrf.rd}' on VRF '{vrf_name}' instead of "
                        f"overwriting it with '{rd}'."
                    )

        rt_data = vrf_data.get("route_targets", {})
        if rt_data:
            new_created, new_linked = _sync_vrf_route_targets(vrf, rt_data, RouteTarget, log_fn)
            rt_created_count += new_created
            rt_linked_count += new_linked

        iface_names = list(
            (vrf_data.get("interfaces") or {}).get("interface", {}).keys()
        )
        if iface_names and device is not None:
            new_ifaces, new_ips = _assign_vrf_interfaces(vrf, iface_names, device)
            iface_linked_count += new_ifaces
            ip_linked_count += new_ips

    if created_count:
        log_fn(f"  [VRF] Created {created_count} VRF(s)")
    if updated_count:
        log_fn(f"  [VRF] Updated {updated_count} VRF(s)")
    if rt_created_count:
        log_fn(f"  [VRF] Created {rt_created_count} route target(s)")
    if rt_linked_count:
        log_fn(f"  [VRF] Linked {rt_linked_count} route target association(s)")
    if iface_linked_count:
        log_fn(f"  [VRF] Assigned {iface_linked_count} interface(s) to VRF(s)")
    if ip_linked_count:
        log_fn(f"  [VRF] Assigned {ip_linked_count} IP address(es) to VRF(s)")
    if warning_count:
        log_fn(f"  [WARN] VRF sync had {warning_count} warning(s)")


def _sync_vrf_route_targets(vrf, rt_data: Dict, RouteTarget, log_fn: Callable):
    """
    Create RouteTarget objects and link them to a VRF's import/export M2M fields.
    RouteTarget is passed in to allow test injection.
    Returns (created_count, linked_count).
    """
    created_count = 0
    linked_count = 0

    for direction in ("import", "export"):
        rt_names = rt_data.get(direction, [])
        if not rt_names:
            continue
        m2m = getattr(vrf, f"{direction}_targets")
        existing_pks = set(m2m.values_list("pk", flat=True))
        for rt_name in rt_names:
            rt_name = rt_name.strip()
            if not rt_name:
                continue
            rt, created = _get_or_create_one(RouteTarget.objects, name=rt_name)
            if created:
                created_count += 1
            if rt.pk not in existing_pks:
                m2m.add(rt)
                linked_count += 1
                existing_pks.add(rt.pk)

    return created_count, linked_count


def _assign_vrf_interfaces(vrf, iface_names: List[str], device) -> tuple:
    """
    Set Interface.vrf and IPAddress.vrf for every interface listed in the
    NAPALM get_network_instances() data.  Only overwrites a None/blank vrf
    field — never reassigns an interface already in a different VRF.
    Returns (interfaces_assigned, ips_assigned).
    """
    from dcim.models import Interface
    from django.contrib.contenttypes.models import ContentType
    from ipam.models import IPAddress

    iface_ct = ContentType.objects.get_for_model(Interface)
    ifaces_assigned = 0
    ips_assigned = 0

    for iface_name in iface_names:
        iface = _find_interface(device, iface_name)
        if iface is None:
            continue

        if iface.vrf_id != vrf.pk:
            if iface.vrf_id is None:
                iface.vrf = vrf
                iface.save()
                ifaces_assigned += 1
            # If already in a different VRF, leave it alone — don't overwrite.

        for ip_obj in IPAddress.objects.filter(
            assigned_object_type=iface_ct,
            assigned_object_id=iface.pk,
        ):
            if ip_obj.vrf_id is None:
                ip_obj.vrf = vrf
                ip_obj.save()
                ips_assigned += 1

    return ifaces_assigned, ips_assigned


def _sync_inventory_items(device, items: List[Dict], log_fn: Callable):
    """Create/update InventoryItem records from show inventory data (Tier 2.2)."""
    from dcim.models import InventoryItem

    created_count = 0
    updated_count = 0
    for item in items:
        item_name = (item.get("name") or "").strip()
        if not item_name:
            continue
        pid = (item.get("pid") or "").strip()
        serial = (item.get("serial") or "").strip()
        description = (item.get("description") or "").strip()

        inv_item = InventoryItem.objects.filter(device=device, name=item_name).first()
        if inv_item is None:
            defaults = {}
            # 'discovered' field exists in NetBox 4.x InventoryItem
            if hasattr(InventoryItem, "discovered"):
                defaults["discovered"] = True
            if pid:
                defaults["part_id"] = pid
            if serial:
                defaults["serial"] = serial
            if description:
                defaults["description"] = description
            InventoryItem.objects.create(device=device, name=item_name, **defaults)
            created_count += 1
        else:
            changed = False
            if pid and inv_item.part_id != pid:
                inv_item.part_id = pid
                changed = True
            if serial and inv_item.serial != serial:
                inv_item.serial = serial
                changed = True
            if description and inv_item.description != description:
                inv_item.description = description
                changed = True
            if changed:
                inv_item.save()
                updated_count += 1

    if created_count or updated_count:
        log_fn(f"  [Inventory] created={created_count}, updated={updated_count}")
        _add_journal_entry(
            device,
            f"Discovery synchronized inventory items: created={created_count}, updated={updated_count}.",
        )


# ---------------------------------------------------------------------------
# Cable / connection sync (post-crawl)
# ---------------------------------------------------------------------------

# Map common CDP/LLDP abbreviated interface name prefixes to full names.
# Sorted longest-first so "twe" is tried before "te".
_IFACE_EXPANSIONS = [
    ("twe", "twentyfivegigabitethernet"),
    ("hundredgige", "hundredgigabitethernet"),
    ("hundredge", "hundredgigabitethernet"),
    ("fortygige", "fortygigabitethernet"),
    ("tengige", "tengigabitethernet"),
    ("gigabitethernet", "gigabitethernet"),   # already full — keep for identity
    ("fastethernet", "fastethernet"),
    ("hu", "hundredgigabitethernet"),
    ("fo", "fortygigabitethernet"),
    ("te", "tengigabitethernet"),
    ("gi", "gigabitethernet"),
    ("ge", "gigabitethernet"),
    ("fa", "fastethernet"),
    ("et", "ethernet"),
    ("po", "port-channel"),
    ("ae", "port-channel"),
    ("mg", "management"),
    ("ma", "management"),
    ("lo", "loopback"),
]


def _find_device_by_hostname(hostname: str):
    """Look up a NetBox Device by hostname, with domain-variant fallback."""
    from dcim.models import Device
    from django.db.models import Q

    if not hostname:
        return None
    device = Device.objects.filter(name=hostname).first()
    if device:
        return device
    base = _base_hostname(hostname)
    if base:
        device = Device.objects.filter(
            Q(name__iexact=base) | Q(name__istartswith=base + ".")
        ).first()
    return device


def _find_interface(device, name: str):
    """
    Look up a NetBox Interface on *device* by name.
    Tries exact match first, then expands common CDP/LLDP abbreviations.
    """
    from dcim.models import Interface

    if not name:
        return None

    canonical_name = _canonical_interface_name(name)
    iface = Interface.objects.filter(device=device, name__iexact=canonical_name).first()
    if iface:
        return iface

    lower = canonical_name.lower()
    for abbrev, full in _IFACE_EXPANSIONS:
        if lower.startswith(abbrev) and not lower.startswith(full):
            expanded = full + lower[len(abbrev):]
            iface = Interface.objects.filter(device=device, name__iexact=expanded).first()
            if iface:
                return iface

    # Final fallback: canonicalized prefix matching so abbreviated and fully
    # expanded names resolve to the same interface key.
    wanted_key = _interface_name_key(name)
    if wanted_key:
        for candidate_name, candidate_pk in Interface.objects.filter(device=device).values_list("name", "pk"):
            if _interface_name_key(candidate_name) == wanted_key:
                return Interface.objects.filter(pk=candidate_pk).first()
    return None


def _normalize_interfaces_payload(interfaces_raw: Dict) -> Dict:
    """
    Canonicalize interface names and merge duplicate entries that normalize to
    the same key (for example Eth1/3 and Ethernet1/3).
    """
    normalized: Dict[str, Dict] = {}
    for raw_name, iface_data in (interfaces_raw or {}).items():
        canonical_name = _canonical_interface_name(raw_name)
        if not canonical_name:
            continue
        existing = normalized.get(canonical_name)
        if existing is None:
            normalized[canonical_name] = dict(iface_data or {})
            continue
        incoming = iface_data or {}
        # Prefer the most informative non-empty value for each field.
        for key, value in incoming.items():
            if value not in (None, "", []):
                existing[key] = value
    return normalized


def _describe_termination(term) -> str:
    if term is None:
        return "unassigned"
    device = getattr(term, "device", None)
    if device is not None:
        return f"{device.name}/{term.name}"
    return str(term)


def _as_termination_list(value) -> List[Any]:
    if value is None:
        return []
    if hasattr(value, "all"):
        return list(value.all())
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _get_cable_endpoints(cable) -> Tuple[Optional[Any], Optional[Any]]:
    a_terms = _as_termination_list(getattr(cable, "a_terminations", None))
    b_terms = _as_termination_list(getattr(cable, "b_terminations", None))
    return (a_terms[0] if a_terms else None, b_terms[0] if b_terms else None)


def _set_cable_endpoints(cable, a_term, b_term) -> None:
    for attr, value in (("a_terminations", a_term), ("b_terminations", b_term)):
        current = getattr(cable, attr, None)
        if hasattr(current, "set"):
            current.set([value])
        else:
            setattr(cable, attr, [value])
    cable.full_clean()
    cable.save()


def _journal_kind_info():
    try:
        from extras.choices import JournalEntryKindChoices

        for attr in ("KIND_INFO", "TYPE_INFO", "INFO"):
            if hasattr(JournalEntryKindChoices, attr):
                return getattr(JournalEntryKindChoices, attr)
    except Exception:
        pass
    return "info"


def _build_interface_journal_message(interface_stats: Dict[str, Any]) -> str:
    """Return a journal message only when interface state actually changed."""
    if not (
        interface_stats.get("created")
        or interface_stats.get("updated")
        or interface_stats.get("deleted")
    ):
        return ""

    parts = []
    if interface_stats.get("created"):
        parts.append(f"created={interface_stats['created']}")
    if interface_stats.get("updated"):
        parts.append(f"updated={interface_stats['updated']}")
    if interface_stats.get("deleted"):
        deleted_names = interface_stats.get("deleted_names") or []
        parts.append(f"deleted={interface_stats['deleted']} ({', '.join(deleted_names)})")
    if interface_stats.get("delete_failed"):
        parts.append(f"delete_failed={interface_stats['delete_failed']}")

    return "Discovery synchronized interfaces: " + "; ".join(parts) + "."


def _build_ip_journal_message(ip_stats: Dict[str, int]) -> str:
    """Return a journal message only when IP ownership actually changed."""
    if not (
        ip_stats.get("created")
        or ip_stats.get("reassigned")
        or ip_stats.get("mgmt_created")
    ):
        return ""

    parts = [
        f"created={ip_stats.get('created', 0)}",
        f"reassigned={ip_stats.get('reassigned', 0)}",
        f"mgmt_created={ip_stats.get('mgmt_created', 0)}",
    ]
    if ip_stats.get("conflicts"):
        parts.append(f"conflicts={ip_stats['conflicts']}")

    return "Discovery synchronized IP assignments: " + ", ".join(parts) + "."


def _add_journal_entry(obj, message: str) -> bool:
    if obj is None or not message:
        return False

    try:
        from django.db import transaction
        from extras.models import JournalEntry
    except Exception:
        return False

    kwargs = {
        "assigned_object": obj,
        "kind": _journal_kind_info(),
        "comments": message,
    }
    # Each attempt runs in its own savepoint: journaling is best-effort, and
    # a swallowed DB error without one would leave the caller's transaction
    # aborted.
    try:
        with transaction.atomic():
            JournalEntry.objects.create(**kwargs)
        return True
    except TypeError:
        kwargs.pop("comments", None)
        kwargs["comment"] = message
        try:
            with transaction.atomic():
                JournalEntry.objects.create(**kwargs)
            return True
        except Exception:
            return False
    except Exception:
        return False


def _update_cable_connection(cable, fixed_term, new_other_term, log_fn: Callable) -> bool:
    a_term, b_term = _get_cable_endpoints(cable)
    if a_term is None or b_term is None:
        return False

    if a_term.pk == fixed_term.pk:
        old_other = b_term
        new_a, new_b = fixed_term, new_other_term
    elif b_term.pk == fixed_term.pk:
        old_other = a_term
        new_a, new_b = new_other_term, fixed_term
    else:
        return False

    if old_other.pk == new_other_term.pk:
        return False

    _set_cable_endpoints(cable, new_a, new_b)

    message = (
        "Discovery updated this connection based on the latest neighbor data: "
        f"{_describe_termination(fixed_term)} moved from {_describe_termination(old_other)} "
        f"to {_describe_termination(new_other_term)}."
    )
    _add_journal_entry(cable, message)
    _add_journal_entry(getattr(fixed_term, "device", None), message)
    _add_journal_entry(getattr(old_other, "device", None), message)
    _add_journal_entry(getattr(new_other_term, "device", None), message)
    log_fn(f"  [Cable] Updated {_describe_termination(fixed_term)}: {_describe_termination(old_other)} -> {_describe_termination(new_other_term)}")
    return True


def sync_cables(neighbor_records: List[Dict], log_fn: Optional[Callable] = None) -> int:
    """
    Create NetBox Cable objects from collected CDP/LLDP neighbor data.

    Should be called once after all devices have been synced (post-crawl),
    so both endpoints are guaranteed to exist in NetBox.

    Returns the count of new cables created.
    """
    from dcim.models import Cable
    from django.db import IntegrityError, transaction

    if log_fn is None:
        log_fn = lambda msg: logger.info(msg)

    created = 0
    # frozenset of (iface_pk_a, iface_pk_b) — deduplicates A→B / B→A within this run
    seen: set = set()
    processed_cables: set = set()

    # Every link is reported from both ends, and _find_interface's fallback
    # scans all of a device's interfaces, so memoize lookups for this pass.
    device_cache: Dict[str, Any] = {}
    iface_cache: Dict[Tuple[int, str], Any] = {}

    def find_device(hostname: str):
        key = hostname.lower()
        if key not in device_cache:
            device_cache[key] = _find_device_by_hostname(hostname)
        return device_cache[key]

    def find_iface(device, name: str):
        key = (device.pk, name.lower())
        if key not in iface_cache:
            iface_cache[key] = _find_interface(device, name)
        return iface_cache[key]

    for record in neighbor_records:
        local_hostname = record.get("hostname", "")
        local_device = find_device(local_hostname) if local_hostname else None
        if not local_device:
            continue

        for nbr in record.get("neighbors", []):
            local_iface_name = nbr.get("local_interface", "")
            # NX-OS appends the chassis serial to its CDP Device ID
            # ("LEAF1(FDO123)"), which never matches a NetBox device name.
            remote_hostname = _strip_device_id_serial(nbr.get("remote_hostname", ""))
            remote_iface_name = nbr.get("remote_interface", "")

            if not local_iface_name or not remote_hostname or not remote_iface_name:
                continue

            local_iface = find_iface(local_device, local_iface_name)
            if not local_iface:
                continue

            remote_device = find_device(remote_hostname)
            if not remote_device:
                continue

            remote_iface = find_iface(remote_device, remote_iface_name)
            if not remote_iface:
                continue

            desired_key = frozenset({local_iface.pk, remote_iface.pk})
            if desired_key in seen:
                continue
            seen.add(desired_key)

            if local_iface.cable_id and remote_iface.cable_id:
                if local_iface.cable_id == remote_iface.cable_id:
                    continue
                log_fn(
                    f"  [Cable] SKIP {_describe_termination(local_iface)} ↔ "
                    f"{_describe_termination(remote_iface)}: both interfaces already have different cables."
                )
                continue

            try:
                with transaction.atomic():
                    if local_iface.cable_id:
                        if local_iface.cable_id in processed_cables:
                            continue
                        if _update_cable_connection(local_iface.cable, local_iface, remote_iface, log_fn):
                            processed_cables.add(local_iface.cable_id)
                        continue

                    if remote_iface.cable_id:
                        if remote_iface.cable_id in processed_cables:
                            continue
                        if _update_cable_connection(remote_iface.cable, remote_iface, local_iface, log_fn):
                            processed_cables.add(remote_iface.cable_id)
                        continue

                    cable = Cable(
                        a_terminations=[local_iface],
                        b_terminations=[remote_iface],
                        status="connected",
                    )
                    cable.full_clean()
                    cable.save()
                    created += 1
                    processed_cables.add(cable.pk)
                    log_fn(
                        f"  [Cable] {local_device.name}/{local_iface.name}"
                        f" ↔ {remote_device.name}/{remote_iface.name}"
                    )
            except (IntegrityError, Exception) as exc:
                log_fn(
                    f"  [Cable] SKIP {local_device.name}/{local_iface.name}"
                    f" ↔ {remote_device.name}/{remote_iface.name}: {exc}"
                )
            finally:
                # The cached instances may now carry a stale cable_id; fetch
                # them afresh if another neighbor entry refers to them.
                iface_cache.pop((local_device.pk, local_iface_name.lower()), None)
                iface_cache.pop((remote_device.pk, remote_iface_name.lower()), None)

    return created
