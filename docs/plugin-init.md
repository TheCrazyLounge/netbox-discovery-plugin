# netbox_discovery/__init__.py

## Purpose

Plugin entry point. Defines the `DiscoveryConfig` class (subclass of `PluginConfig`) that NetBox loads to register the plugin.

Also ensures the `os_version` custom field exists on the `Device` model after every migration run.

## Key Responsibilities

- Declares plugin metadata: name, version, base URL (`/plugins/discovery/`), minimum NetBox version
- Declares `default_config` keys consumed from `PLUGINS_CONFIG['netbox_discovery']`
- Hooks into the `post_migrate` signal to safely call `_ensure_os_version_custom_field()` (avoids `RuntimeWarning` from DB access during app initialisation)
- Imports `checks.py` in `ready()`, which registers system check `netbox_discovery.W001`. The check warns when `encryption_key` is missing or invalid, and the warning appears in `manage.py check` and at startup.

## Config Keys (default_config)

| Key | Default | Description |
|-----|---------|-------------|
| `holding_site_name` | `"Holding"` | Site for newly discovered devices |
| `ssh_timeout` | `10` | Default SSH timeout in seconds |
| `encryption_key` | `""` | Fernet key for credential encryption |
| `default_username` | `""` | Fallback SSH username |
| `default_password` | `""` | Fallback SSH password |
| `default_enable_secret` | `""` | Fallback enable/privilege password |
| `sync_platform` | `True` | Map NAPALM driver → NetBox `Platform` and assign to device |
| `sync_interface_speed` | `True` | Update `Interface.speed` from NAPALM speed reports |
| `sync_fqdn` | `True` | Set the `fqdn` device custom field |
| `sync_interface_vlans` | `True` | Bind discovered VLANs to interfaces (access/trunk mode + `untagged_vlan`/`tagged_vlans`) |
| `create_prefixes` | `False` | Create `ipam.Prefix` records from interface IPs (often manually curated) |
| `prune_stale_interfaces` | `False` | Delete interfaces the plugin created (tagged `discovered-by-nbdiscovery`) that the device no longer reports. Cabled interfaces are never deleted |
| `collect_vrfs` | `False` | Call `get_network_instances()` per device and sync VRFs / route targets |
| `collect_inventory` | `False` | Run `show inventory` and sync `InventoryItem` records |
| `collect_mac_address_table` | `False` | Call `get_mac_address_table()` per device and store entries in `MacAddressTableEntry` |

## os_version Custom Field

`_ensure_os_version_custom_field()` creates a `CustomField` named `os_version` of type `text` on the `Device` content type if it doesn't already exist. This is called once per `post_migrate` signal — not on every request.

## How to Change

- **Add a new config key**: Add it to `default_config`. Read it with `settings.PLUGINS_CONFIG.get('netbox_discovery', {}).get('your_key', default)`.
- **Change plugin version**: Update the `version` attribute.
- **Add another post-migrate action**: Call it from `_on_post_migrate()` (wrap in try/except so a failure doesn't break migrations).
