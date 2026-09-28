# netbox-discovery

A NetBox 4.x community plugin that discovers network devices from seed IPs and
CIDR ranges, walks CDP/LLDP neighbors, and syncs the results into NetBox.
It collects device facts, interfaces, L3 addressing, VLANs, stack members, and
optionally VRFs and inventory items.

---

## Features

- **Seed-based discovery**: Start from individual IPs or CIDR ranges
- **TCP host discovery**: Uses `nmap` when available and falls back to a pure-Python TCP probe
- **Recursive neighbor crawling**: Follows CDP and/or LLDP neighbors up to a configurable depth
- **NAPALM auto-detection**: Tries `ios → nxos_ssh → junos → fortios → eos`
- **Device sync**: Creates or updates manufacturers, device types, devices, interfaces, IPs, VLANs, and stack membership
- **Optional enrichment**: Can also sync platform, interface speed, FQDN, prefixes, VRFs, and inventory items
- **Duplicate-aware matching**: Matches by hostname, management IP, and base-hostname domain variants
- **Holding site workflow**: New devices land in a configurable holding site, then can be auto-assigned by hostname prefix
- **Optional stale interface cleanup**: With `prune_stale_interfaces` enabled, removes interfaces the plugin created that a device no longer reports (never cabled ones)
- **Conflict logging**: Writes IP assignment conflicts to a dedicated log file for follow-up
- **Duplicate device tools**: Includes a UI for reviewing, merging, and deleting domain-variant duplicates
- **Built-in scheduling**: Manual runs plus recurring runs via the background scheduler
- **NetBox UI + API**: CRUD views plus `POST /api/plugins/discovery/targets/{id}/run/`

---

## Requirements

- NetBox 4.0+
- Python 3.10+
- `nmap` binary recommended for faster host discovery

If `nmap` or `python-nmap` is unavailable, the plugin falls back to a threaded
TCP connect probe.

---

## Installation

### 1. Install the plugin

Clone to `/opt/netbox-discovery-plugin` on the NetBox server, then install as editable:

```bash
git clone git@github.com:YOUR-ORG/netbox-discovery.git /opt/netbox-discovery-plugin
sudo chown -R netbox:netbox /opt/netbox-discovery-plugin
sudo /opt/netbox/venv/bin/pip install -e /opt/netbox-discovery-plugin
```

To update to the latest version:
```bash
cd /opt/netbox-discovery-plugin
sudo git pull origin main
sudo systemctl restart netbox netbox-rq
```

### 2. Install system dependencies

```bash
# Ubuntu / Debian
sudo apt-get install nmap

# RHEL / CentOS
sudo yum install nmap
```

### 3. Generate an encryption key

Credentials are stored Fernet-encrypted. Generate a key once:

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

### 4. Update NetBox configuration

Add to your NetBox `configuration.py`:

```python
PLUGINS = ['netbox_discovery']

PLUGINS_CONFIG = {
    'netbox_discovery': {
        # Site name for newly discovered devices (created automatically)
        'holding_site_name': 'Holding',

        # SSH connection timeout in seconds
        'ssh_timeout': 10,

        # Fernet encryption key for stored credentials (required)
        'encryption_key': 'your-generated-key-here==',

        # Global credential fallbacks (used when per-target fields are blank)
        'default_username': '',
        'default_password': '',
        'default_enable_secret': '',

        # Default conflict log path
        'conflict_log_path': '/var/log/netbox/discovery_conflicts.log',

        # Tier 1 sync options (enabled by default)
        'sync_platform': True,
        'sync_interface_speed': True,
        'sync_fqdn': True,
        'create_prefixes': False,

        # Delete interfaces the plugin created that a device no longer
        # reports (cabled interfaces are always kept). Off by default.
        'prune_stale_interfaces': False,

        # Tier 2 collection options (disabled by default)
        'collect_vrfs': False,
        'collect_inventory': False,
    }
}
```

### 5. Run database migrations

```bash
cd /opt/netbox-discovery-plugin
sudo /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate netbox_discovery
```

### 6. Restart NetBox and workers

```bash
sudo systemctl restart netbox netbox-rq
```

---

## Usage

### Creating a Discovery Target

1. Navigate to **Plugins → Network Discovery → Discovery Targets**
2. Click **Add Target**
3. Fill in:
   - **Name**: A descriptive label
   - **Targets**: One IP address or CIDR range per line (e.g., `10.0.0.1`, `192.168.1.0/24`)
   - **Exclusions**: IPs or CIDRs to omit from scanning
   - **Credentials**: SSH username/password (or leave blank to use global defaults)
   - **NAPALM Driver**: `Auto-detect` tries Cisco IOS → NX-OS → JunOS → FortiOS → EOS
   - **Discovery Protocol**: LLDP, CDP, or Both
   - **Max Depth**: How many neighbor hops to follow (default: 3)
   - **SSH Timeout**: Per-device connection timeout
   - **Max Workers**: Number of devices crawled in parallel
   - **Auto-run Interval**: Minutes between automatic runs (0 = manual only)
4. Click **Save**

### Running Discovery

**Manually**: Open a Discovery Target and click **Run Now**.

**Automatically**: Set `scan_interval > 0` and `enabled = True` on the target.
The built-in scheduler checks every 5 minutes and enqueues jobs for due targets.

**Via API**: `POST /api/plugins/discovery/targets/{id}/run/`

### Viewing Results

- **Run History**: Plugins → Network Discovery → Run History
- Each run shows: hosts scanned, devices created/updated, error count, and full log output
- Discovered devices appear in **Devices** with site set to the holding site
- Interfaces, IPs, VLANs, stack members, and optional enrichment data are synchronized on each device

### Managing Duplicate Devices

Use **Plugins → Network Discovery → Duplicate Devices** to review devices that
share the same base hostname with different domain suffixes. From there you can:

- Merge a duplicate into the keeper device while preserving useful metadata, IPs, and connections
- Delete an unwanted duplicate directly from the plugin UI

---

## How Data is Synced to NetBox

| NAPALM data | NetBox object |
|-------------|---------------|
| `get_facts()` → hostname, vendor, model, serial, OS version | `dcim.Device`, `dcim.DeviceType`, `dcim.Manufacturer`, custom fields |
| `get_interfaces()` → name, enabled, description, MTU, speed | `dcim.Interface` |
| `get_interfaces_ip()` → IP/prefix per interface | `ipam.IPAddress` (assigned to interface) |
| `get_vlans()` → VID, name | `ipam.VLAN` (scoped to the device's resolved site) |
| Cisco stack data | `dcim.VirtualChassis` plus member `dcim.Device` records |
| Optional `get_network_instances()` data | `ipam.VRF` |
| Optional `show inventory` data | `dcim.InventoryItem` |
| Management IP (seed IP) | `dcim.Device.primary_ip4` |

### Matching logic

1. Check for existing `Device` with the same **hostname**
2. If not found, check for existing `IPAddress` with the management IP and follow its assignment
3. If not found, check for a device with the same base hostname and a different domain suffix
4. If not found, create a new device in the holding site
5. On match: update device attributes and synchronized data

### Sync behavior and safeguards

- Discovery updates existing devices instead of replacing them wholesale
- Primary IP conflicts are logged and domain-variant blockers can be auto-resolved
- Interface cleanup is opt-in (`prune_stale_interfaces`). It only touches interfaces the plugin created (tagged `discovered-by-nbdiscovery`), never deletes a cable, and is skipped when interface collection failed
- Interface names keep the device's own spelling (`mgmt0`, `ae0`, `port-channel1`); only Cisco abbreviations such as `Gi1/0/1` are expanded
- Target exclusions also apply to neighbors found through CDP/LLDP, not just to the initial scan
- Existing tags and user-managed data are preserved where possible
- Prefix creation, VRF collection, and inventory collection are opt-in

---

## Supported NAPALM Drivers

| Driver | Vendor / OS |
|--------|------------|
| `ios` | Cisco IOS / IOS-XE |
| `nxos_ssh` | Cisco NX-OS |
| `junos` | Juniper JunOS |
| `fortios` | Fortinet FortiOS |
| `eos` | Arista EOS |

Auto-detect tries them in the order above (Cisco-first).

---

## REST API

All endpoints are under `/api/plugins/discovery/`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/targets/` | List discovery targets |
| `POST` | `/targets/` | Create a target |
| `GET` | `/targets/{id}/` | Target detail |
| `PUT/PATCH` | `/targets/{id}/` | Update a target |
| `DELETE` | `/targets/{id}/` | Delete a target |
| `POST` | `/targets/{id}/run/` | Enqueue a discovery job |
| `GET` | `/runs/` | List discovery runs |
| `GET` | `/runs/{id}/` | Run detail with full log |

---

## Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `holding_site_name` | `"Holding"` | Site for newly discovered devices |
| `ssh_timeout` | `10` | Default SSH timeout (seconds) |
| `encryption_key` | `""` | Fernet key for credential encryption (**required**) |
| `default_username` | `""` | Fallback SSH username |
| `default_password` | `""` | Fallback SSH password |
| `default_enable_secret` | `""` | Fallback enable password |
| `conflict_log_path` | `"/var/log/netbox/discovery_conflicts.log"` | Default path used for the dedicated IP conflict log |
| `sync_platform` | `True` | Set the NetBox device platform from the selected NAPALM driver |
| `sync_interface_speed` | `True` | Sync interface speed from NAPALM data |
| `sync_fqdn` | `True` | Store device FQDN in a custom field when available |
| `create_prefixes` | `False` | Create Prefix records from discovered interface addressing |
| `prune_stale_interfaces` | `False` | Delete plugin-created interfaces a device no longer reports (cabled interfaces are kept) |
| `collect_vrfs` | `False` | Run `get_network_instances()` and sync VRFs |
| `collect_inventory` | `False` | Run inventory collection and sync inventory items |

---

## Troubleshooting

**Jobs not running?**
- Ensure `netbox-rq` worker is running: `systemctl status netbox-rq`
- Check NetBox system jobs in the admin panel

**Can't connect to devices?**
- Verify `nmap` is installed: `which nmap`
- Test manually: `napalm --user admin --password secret --vendor ios get_facts <ip>`
- Check SSH reachability from the NetBox server
- If a driver library is missing, the run log will mark it unavailable and skip future attempts in that process

**Wrong interfaces types?**
- Interface type is auto-detected from the interface name
- You can manually update types in NetBox after discovery

**Seeing many unreachable neighbor IPs?**
- Prefer CDP/LLDP management addresses where available
- Use target exclusions to prevent known non-manageable subnets from being scanned

**Need to investigate IP conflicts?**
- Review the main run log for warnings
- Check `/var/log/netbox/discovery_conflicts.log`

---

## License

Apache 2.0
