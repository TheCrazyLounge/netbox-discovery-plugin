# netbox_discovery/discovery/collector.py

## Purpose

Collects all device data from an open NAPALM connection and returns it as a single dict. Called once per device during the BFS crawl.

---

## collect_device_data(device, driver_name, discovery_protocol, log_fn) → Dict

Returns a dict with keys:

| Key | Type | Source |
|-----|------|--------|
| `facts` | dict | `device.get_facts()` |
| `interfaces` | dict | `device.get_interfaces()` |
| `interfaces_ip` | dict | `device.get_interfaces_ip()` |
| `vlans` | dict | `device.get_vlans()` (skipped if unsupported) |
| `neighbors` | list | LLDP detail → LLDP basic → CDP CLI (in order) |
| `stack_members` | list | `_detect_cisco_stack()` (IOS only) |
| `raw_errors` | list | Any collection warnings/errors |
| `step_status` | dict | Per-step status map (`ok`/`fail`/`skip`) |

### Collection Steps

1. `get_facts()` — hostname, vendor, model, serial, os_version
2. `get_interfaces()` — name, enabled, description, MTU, MAC
3. `get_interfaces_ip()` — IPv4/IPv6 per interface (includes VLAN SVIs)
4. `get_vlans()` — VID + name (best-effort; skipped silently on unsupported drivers)
5. Neighbor collection — tries LLDP detail, then LLDP basic, then CDP CLI
6. Stack detection (IOS only) — runs `show switch` + `show inventory`

---

## Neighbor Data Structure

Each entry in `data["neighbors"]`:

```python
{
    "source": "lldp" | "cdp",
    "local_interface": str,   # e.g. "GigabitEthernet0/1"
    "remote_hostname": str,   # e.g. "ROUTER2" or FQDN
    "remote_interface": str,  # e.g. "GigabitEthernet0/2"
    "remote_ip": str,         # management IP of remote device
    "remote_description": str # platform string
}
```

### Neighbor Collection Priority

1. **LLDP detail** (`get_lldp_neighbors_detail()`) — richest data
2. **LLDP basic** (`get_lldp_neighbors()`) — fallback if detail fails
3. **CDP CLI** (`show cdp neighbors detail`) — Cisco only, parsed with `_parse_cdp_neighbors()`. The parser strips the `(serial)` suffix NX-OS appends to Device IDs, so the name matches the NetBox device.

LLDP and CDP entries for the same link are deduplicated on `(interface_name_key(local_interface), base_hostname(remote_hostname))` from `netbox_discovery/naming.py`. The key ignores abbreviation (`Gi1/0/1` vs `GigabitEthernet1/0/1`) and domain differences (`sw2` vs `sw2.corp.local`). LLDP entries win.

---

## Cisco Stack Detection (_detect_cisco_stack)

Only runs for the `ios` driver. Executes `show switch` and `show inventory` via `device.cli()`. CLI failures propagate, so the step is reported as `stack=fail`. They used to be swallowed and reported as `ok`.

Returns a list of stack members:
```python
{
    "position": int,   # switch number (1-based)
    "role": str,       # "Active", "Standby", "Member"
    "mac": str,
    "priority": int,
    "serial": str,     # from show inventory
    "model": str       # from show inventory
}
```

---

## How to Change

- **Add a new collection step**: Add a numbered step to `collect_device_data()`, catch exceptions, append to `raw_errors` on failure.
- **Add a new neighbor source**: Add it to the neighbor collection block. Follow the pattern: try, then merge with existing neighbors (deduplicated by normalized local interface + base remote hostname).
- **Support stack detection for NX-OS**: Add `"nxos_ssh"` to the driver check in `_detect_cisco_stack()` and parse `show module` or equivalent.
- **Parse additional CDP fields**: Update `_parse_cdp_neighbors()` to extract more fields from the CLI output.
