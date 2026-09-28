# netbox_discovery/models.py

## Purpose

Defines the database models for the plugin: `DiscoveryTarget`, `DiscoveryRun`, and `MacAddressTableEntry`.
Also provides Fernet-based encryption helpers for credential storage.

---

## Encryption Helpers

### `get_encryption_key_status()` / `encryption_available()`
Report whether `encryption_key` is `"ok"`, `"missing"` or `"invalid"`. `checks.py` turns a non-ok status into system-check warning `netbox_discovery.W001`, and the target form and API serializer use `encryption_available()` to reject a new secret with a validation error.

### `_get_fernet()`
Returns a `cryptography.fernet.Fernet` instance for a valid `encryption_key`, or `None`.

### `encrypt_value(raw)` / `decrypt_value(stored)`
`encrypt_value` raises `ImproperlyConfigured` when a non-empty secret is written without a valid key. It never stores plaintext silently.

`decrypt_value` returns legacy plaintext values (stored before a key existed) unchanged. It returns `""` and logs an error for a Fernet token (prefix `gAAAAA`) that cannot be decrypted because the key was removed or rotated. Previously the ciphertext itself was sent to devices as the password.

Always use these through the model property accessors — never read `_credential_password` directly.

### `validate_ip_lines(value, max_addresses=None)`
Returns error messages for invalid IP/CIDR lines, and for lines larger than `max_addresses`.

---

## DiscoveryTarget

Represents a discovery job configuration: what to scan, how to authenticate, and how often to run.

Inherits `JobsMixin` + `NetBoxModel`. `JobsMixin` is required for
`DiscoveryJob.enqueue(instance=target)` — NetBox rejects jobs bound to
models that do not declare the jobs feature.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | CharField(100, unique) | Human-readable label |
| `description` | CharField(500) | Optional description |
| `targets` | TextField | One IP/CIDR per line |
| `credential_username` | CharField(100) | Per-target SSH username |
| `_credential_password` | CharField(512) | Encrypted SSH password (use `.credential_password` property) |
| `_enable_secret` | CharField(512) | Encrypted enable secret (use `.enable_secret` property) |
| `napalm_driver` | CharField | `auto`, `ios`, `nxos_ssh`, `eos`, `junos`, `fortios` |
| `discovery_protocol` | CharField | `lldp`, `cdp`, or `both` |
| `max_depth` | PositiveIntegerField | Neighbor crawl recursion depth (default 3, max 10) |
| `ssh_timeout` | PositiveIntegerField | SSH connect timeout in seconds (default 10, 1–120) |
| `max_workers` | PositiveIntegerField | Parallel crawl threads (default 5, 1–50; each worker holds a DB connection) |
| `scan_interval` | PositiveIntegerField | Auto-run every N minutes (0 = disabled) |
| `enabled` | BooleanField | Whether scheduled runs are active |
| `last_run` | DateTimeField | Timestamp of last run (updated by job) |

### Properties

- `credential_password` — decrypted password via setter/getter
- `enable_secret` — decrypted enable secret via setter/getter
- `has_password` / `has_enable_secret` — template-safe booleans (checks stored value without decrypting)

### Methods

- `get_effective_username()` — per-target username or global fallback from `PLUGINS_CONFIG`
- `get_effective_password()` — per-target password or global fallback
- `get_effective_enable_secret()` — per-target secret or global fallback
- `get_target_list()` — parse `targets` field into `List[str]`, stripping blank lines
- `clean()` — validates `targets` (each line must be a valid IP/CIDR of at most 65,536 addresses, i.e. an IPv4 /16) and `exclusions`. It is on the model so the REST API enforces it as well as the form.

---

## DiscoveryRun

Read-only audit log for a single execution of a `DiscoveryTarget`. Created at job start, updated throughout, finalised at completion.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `target` | ForeignKey → DiscoveryTarget (CASCADE) | Parent target |
| `status` | CharField | `pending`, `running`, `completed`, `failed`, `partial` |
| `started_at` | DateTimeField | Job start timestamp |
| `completed_at` | DateTimeField | Job end timestamp |
| `hosts_scanned` | IntegerField | Count of live IPs found |
| `devices_created` | IntegerField | Count of new NetBox devices |
| `devices_updated` | IntegerField | Count of updated devices |
| `cables_created` | IntegerField | Count of cables created by the post-crawl cable sync |
| `errors` | IntegerField | Count of connection/sync errors |
| `log` | TextField | Full text log output (flushed per-line during run) |
| `device_results` | JSONField | List of `{ip, hostname, status, driver, error}` per device |

### Methods

- `append_log(message)` — append a line to the log field

---

## MacAddressTableEntry

Stores the L2 forwarding view collected from each device's MAC address table. The set of rows for a given device is replaced wholesale on each successful discovery run when `collect_mac_address_table` is enabled.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `device` | ForeignKey → dcim.Device (CASCADE) | Device that learned the MAC |
| `interface` | ForeignKey → dcim.Interface (SET_NULL) | Resolved local interface (nullable when unmatched) |
| `interface_name` | CharField(100) | Raw interface name as reported by the device |
| `mac_address` | CharField(17, indexed) | MAC address, normalised to upper case |
| `vlan` | ForeignKey → ipam.VLAN (SET_NULL) | Resolved VLAN at the device's site (nullable) |
| `vlan_vid` | PositiveSmallIntegerField (indexed) | VLAN ID as reported (kept even when no `ipam.VLAN` row exists) |
| `is_static` | BooleanField | Whether the device reports the entry as static |
| `is_active` | BooleanField | Whether the entry is currently active (default true) |
| `last_seen` | DateTimeField (auto_now) | Updated on every sync |

### Constraints

- `UniqueConstraint(device, mac_address, vlan_vid, interface_name)` — prevents duplicate inserts inside one snapshot.

---

## How to Change

- **Add a new field**: Add to the model, create a migration (`makemigrations`), add to `forms.py` and `api/serializers.py`.
- **Add a new credential field**: Follow the `_credential_password` pattern — store encrypted with `db_column` alias, expose via property.
- **Change run counters**: Add the counter field here and update `_finish_run()` in `jobs.py`.
