# netbox_discovery/sync/netbox_sync.py

## Purpose

All NetBox write logic. Translates collected device data into NetBox ORM operations. Device records and cables are never deleted by discovery. Stale interfaces are deleted only when the opt-in `prune_stale_interfaces` setting is on, and only if the plugin created them (they carry the `discovered-by-nbdiscovery` tag) and have no cable.

Every get-or-create of a shared object (Manufacturer, DeviceType, DeviceRole, Site, Platform, Tag, RouteTarget, Device, Interface, IPAddress, Prefix) goes through `_get_or_create_one()`, which tolerates duplicate rows and concurrent inserts by other crawl workers. Best-effort steps that swallow exceptions run inside their own `transaction.atomic()` savepoint, so a swallowed DB error cannot abort the device's enclosing transaction.

---

## sync_device(mgmt_ip, data, holding_site_name, log_fn) → (hostname, was_created)

Main entry point. Called once per device from `jobs.py`'s `on_device` callback.

### Steps

1. **Hostname sanitization** — `_is_valid_hostname()` rejects CLI errors (`^`, `% Invalid input`), OS identifiers (`Kernel`, `localhost`), etc. Falls back to `mgmt_ip` as hostname.
2. **Manufacturer / DeviceType** — race-safe `_get_or_create_one` with slug generation.
3. **DeviceRole (auto-classified)** — `classify_device()` from `sync/classify.py` maps the model string + NAPALM driver to a specific role (Router, Switch, Firewall, Wireless AP, etc.) with a color. Falls back to driver-based inference, then `"Network Device"`.
4. **Device lookup** — `_get_or_create_device()`: exact hostname → management IP (any stored prefix length, via `address__net_host`) → domain-variant base hostname → create new.
5. **Update mutable fields** — device_type, serial, os_version custom field, role (re-classified on each sync).
6. **Hostname-to-site matching** — `_match_site_by_hostname()`: if device is on holding site, try to find a real site whose name is a prefix of the hostname (e.g. `GBLON10SWI01` → site `GBLON10`).
7. **Auto-tagging** — `_sync_device_tags()` applies classification-derived tags (vendor, device type, series) to the device. Tags are additive — never removed.
8. **Interfaces** — `_sync_interfaces()`: find or create each interface via `_get_or_create_interface()`, then update enabled/description/MTU/MAC/speed.
   - Lookup is case-insensitive. An interface stored under a different case, or under the name older versions produced (`mgmt0` → `Management0`, Junos `ae0` → `Port-Channel0`), is renamed to the device's own spelling instead of being duplicated.
   - Only Cisco-style abbreviations are expanded (`Gi1/0/1` → `GigabitEthernet1/0/1`, `Eth1/3` → `Ethernet1/3`). Full names and lowercase non-Cisco names (`mgmt0`, `ae0`, `lo0`) are kept as reported. See `netbox_discovery/naming.py`.
   - `type` is set on creation. Afterwards it only replaces `other` (or a LAG type wrongly given to a plain port), so operator corrections survive later runs.
   - Interfaces the plugin creates are tagged `discovered-by-nbdiscovery`.
   - Pruning (opt-in `prune_stale_interfaces`): deletes tagged interfaces the device no longer reports and that do not appear in `interfaces_ip` or the LAG summary. Cabled interfaces are kept and logged. It is skipped when collector `get_interfaces()` failed.
9. **IP Addresses** — `_sync_ips()`: `get_or_create` each IP, assign to interface. Returns management IP object. If the management IP is not on any collected interface, `_fallback_primary_ip()` uses it only when it is already on this device, or when it is unassigned and can be attached to this device's management interface. It never uses an IP assigned to another device, because NetBox's device form rejects a primary IP the device does not own.
10. **Primary IP** — set `device.primary_ip4`. If conflict detected:
   - Preserve existing `primary_ip4` if it still exists on the device (do not overwrite with newly discovered candidate IPs).
   - Only change `primary_ip4` when current primary is no longer present on collected interface IP data.
   - If blocker is a **domain-variant** (same base hostname): auto-resolve by clearing blocker's primary IP.
   - Otherwise: log WARNING to conflict file and skip.
11. **VLANs** — `_sync_vlans()`: `get_or_create` each VLAN scoped to holding site.
12. **VLAN-to-interface bindings** — `_sync_interface_vlans()`: heuristically sets `Interface.mode` and `Interface.untagged_vlan` / `Interface.tagged_vlans` from NAPALM `get_vlans()` membership lists. An interface in exactly one VLAN becomes `mode='access'` with that VLAN as `untagged_vlan`; an interface in multiple VLANs becomes `mode='tagged'` with the union as `tagged_vlans` (native VLAN is left untouched — NAPALM doesn't report it). Virtual / LAG-parent interfaces are skipped. Controlled by `sync_interface_vlans` (default on).
13. **VRFs** — `_sync_vrfs()`: creates VRFs from `get_network_instances()` when enabled. Placeholder route distinguishers like `0:0` are ignored, duplicate existing VRF names are tolerated by reusing the first match, and conflicting RDs are skipped with warnings instead of aborting the device sync.
14. **MAC address table** — `_sync_mac_address_table()`: when `collect_mac_address_table` is enabled and NAPALM `get_mac_address_table()` succeeded, replaces the device's previous `MacAddressTableEntry` rows with the new snapshot. Each entry resolves the reported interface via `_find_interface()` (preserving the raw name in `interface_name`) and the VLAN via `(vid, site)` lookup. Unresolved interfaces / unknown VLANs leave the FK null.
15. **Virtual Chassis** — `_sync_virtual_chassis()`: if `stack_members > 1`, create/update VC + member devices.
16. **Journal entries** — discovery writes journal entries for actual object changes (for example create, attribute updates, tags added, interface/IP changes, primary IP changes, stack membership/member updates). Informational no-op cases such as preserving an existing primary IP or skipping a prune are logged to the run output only, not persisted to the device journal.

---

## sync_cables(neighbor_records, log_fn) → int

Post-crawl pass. Creates `Cable` objects between matched interfaces. Called from `jobs.py` after all devices are synced.

### Logic

For each `{hostname, neighbors}` record:
1. Find local device via `_find_device_by_hostname()`
2. For each neighbor entry: find local interface (`_find_interface()`), remote device (after stripping an NX-OS `(serial)` suffix from the CDP Device ID), remote interface. Device and interface lookups are memoized for the pass.
3. Skip if either interface already has `cable_id`
4. Skip if this pair was already seen this run (bidirectional dedup via `frozenset`)
5. Create `Cable(a_terminations=[local_iface], b_terminations=[remote_iface], status="connected")`
6. Each creation is wrapped in `transaction.atomic()` — one failure doesn't abort the rest

---

## Key Helper Functions

### _is_valid_hostname(hostname)
Returns `False` for hostnames starting with `^`, containing `% invalid`/`invalid input`, or matching known non-network identifiers (`kernel`, `localhost`, etc.).

### _match_site_by_hostname(hostname, exclude_site_name)
Strips domain suffix, normalises separators, finds the **longest** site name that is a prefix of the hostname. Requires ≥4 chars. Returns `Site` or `None`.

Example: `GBLON10SWI01` → site `GBLON10`

### _find_device_by_hostname(hostname)
Exact name match → domain-variant match (same `_base_hostname()`).

### _find_interface(device, name)
Exact match first, then expands abbreviations from `_IFACE_EXPANSIONS` list (sorted longest-first to avoid prefix collisions: `"twe"` before `"te"`), then falls back to canonicalized abbreviation/full-name key matching.

LAG member sync intentionally skips unresolved member names instead of auto-creating placeholder interfaces, to avoid duplicate interface rows.

### _get_or_create_device(hostname, mgmt_ip, site, ...)
1. Exact hostname match
2. Management IP match on any prefix length (follow `IPAddress.assigned_object.device`)
3. Domain-variant match (`name__iexact=base` or `name__istartswith=base + "."`)
4. Create new (race-safe)

### map_interface_type(name, speed_mbps=None)
Name patterns match both full names and abbreviations. Every pattern requires a digit after the prefix, so FortiGate `port1` is not typed as a LAG. Generic names (`Ethernet1/1`, `port1`) fall back to the reported speed.

### _sync_virtual_chassis(master_device, hostname, stack_members, ...)
- Creates/gets `VirtualChassis` named after hostname
- Master = the member `show switch` reports as Active, then Standby, then the lowest position (`_select_stack_master`)
- Before a device takes a VC position, `_free_vc_position()` clears any other device still holding it (after a switchover), avoiding the `(virtual_chassis, vc_position)` unique-constraint failure
- For each non-master member: finds/creates a `Device` named `{base}-sw{position}`
- Member devices always use `master_device.site` (never the holding site)

---

## Conflict Log

IP conflicts that cannot be auto-resolved are written to `/var/log/netbox/discovery_conflicts.log` via `_get_conflict_logger()`. The logger uses `RotatingFileHandler` (5 MB × 5 files).

---

## How to Change

- **Add a new sync step**: Add it inside the `with transaction.atomic():` block in `sync_device()`. Everything is atomic per device.
- **Add a new field to sync**: Add it to the `changed = False` update block after `_get_or_create_device()`.
- **Add a new invalid hostname pattern**: Add to `_INVALID_HOSTNAME_EXACT` (set) or `_INVALID_HOSTNAME_FRAGMENTS` (substring list).
- **Add a new interface abbreviation**: Add to `_IFACE_EXPANSIONS` list — keep sorted longest-prefix-first.
- **Change cable sync behaviour**: Edit `sync_cables()` — the `frozenset` dedup and `cable_id` skip are the two idempotency guards.
- **Add a new device classification rule**: Add a tuple to `_RULES` in `sync/classify.py`. Pattern order matters — specific patterns before generic ones. Each rule is `(regex_pattern, role_name, [tag_slugs])`.
- **Add a new vendor for driver-based fallback**: Add to `DRIVER_ROLE_FALLBACK` and `DRIVER_VENDOR_TAG` dicts in `sync/classify.py`.
# netbox_sync.py

- Primary IPv4 selection now prefers an active IPv4 assigned to a management interface (`mgmt*`, `management*`, Nexus `mgmt0`, or Catalyst `GigabitEthernet0/0`) when one is present on the device.
- If no management-interface IPv4 is available, sync falls back to the discovered seed management IP. If that IP is not on any collected interface, a `/32` is created on the management interface only when the address is not already assigned elsewhere (see `_fallback_primary_ip`).
