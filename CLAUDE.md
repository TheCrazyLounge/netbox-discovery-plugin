# CLAUDE.md — netbox-discovery-plugin

Project instructions and context for Claude Code.

## Project Overview

Full NetBox 4.x community plugin for automated network discovery.
Installed at `/home/ubuntu/netbox-discovery-plugin/` (dev) and `/opt/netbox-discovery-plugin` (production).
Plugin package: `netbox_discovery`. Base URL: `/plugins/discovery/`.

## Commit Convention

ALL commits MUST follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>[optional scope]: <description>

[optional body]
[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

Examples:
- `feat(sync): add hostname-to-site prefix matching`
- `fix(views): resolve ProtectedError on VC master deletion`
- `docs: add per-file documentation to docs/`
- `chore: update .gitignore`

## Architecture

```
Discovery pipeline:
  scanner.py       → find live hosts (nmap / TCP probe)
  driver_detect.py → auto-detect NAPALM driver (ios, nxos_ssh, eos, junos, fortios)
  collector.py     → collect facts, interfaces, IPs, VLANs, neighbors, stack members
  neighbor.py      → concurrent BFS crawl; calls collector + on_device_data callback per device

Sync pipeline (called per-device, then post-crawl for cables):
  sync/netbox_sync.py → sync_device() syncs one device; sync_cables() wires CDP/LLDP connections

Background jobs:
  jobs.py          → DiscoveryJob(JobRunner) + discovery_scheduler system_job (every 5 min)

UI / API:
  views.py         → Django class-based views
  urls.py          → URL patterns
  api/             → DRF viewsets + serializers
  templates/       → Jinja2/Django HTML templates
```

## Key Design Decisions

- **Never deletes devices or cables** — only race-safe `_get_or_create_one` and updates. The single exception is the opt-in `prune_stale_interfaces` setting, which deletes only uncabled interfaces the plugin itself created (tagged `discovered-by-nbdiscovery`)
- Credentials stored Fernet-encrypted in DB; per-target with global config fallback. Writing a secret without a valid `encryption_key` fails, and system check `netbox_discovery.W001` warns about a missing key
- Interface names keep the device's own spelling; only Cisco abbreviations are expanded (`netbox_discovery/naming.py`)
- Holding site (`"Holding"`) used for newly discovered devices; hostname-prefix matching auto-assigns real sites
- Domain-variant deduplication: `router1.emea.local` matches existing `router1.us.local` by base hostname
- Primary IP conflicts with domain-variant blockers are auto-resolved
- Garbage hostnames (CLI errors, `Kernel`, `localhost`) are rejected — management IP used as fallback
- StackWise stacks: master + members created as `VirtualChassis` + member `Device` records
- CDP/LLDP cables: created post-crawl (after all devices exist) via `sync_cables()`
- Driver detection: `ios → nxos_ssh → junos → fortios → eos` (EOS last — HTTP driver noisy)
- Per-driver wall-clock timeout via `ThreadPoolExecutor(max_workers=1)` + `shutdown(wait=False)`

## Production Server

- Plugin path: `/opt/netbox-discovery-plugin`
- NetBox venv: `/opt/netbox/venv/`
- Restart: `sudo systemctl restart netbox netbox-rq`
- Reinstall (editable): `sudo /opt/netbox/venv/bin/pip install -e /opt/netbox-discovery-plugin`
- Conflict log: `/var/log/netbox/discovery_conflicts.log`

## Adding a New Field to a Model

1. Add the field to `models.py`
2. Run `python manage.py makemigrations netbox_discovery` to generate a migration
3. Add the field to the form in `forms.py` (fieldsets + Meta.fields + Meta.widgets)
4. Add the field to the serializer in `api/serializers.py` if it should be API-visible
5. Add the field to the table in `tables.py` if it should appear in list views

## Adding a New URL / View

1. Write the view class in `views.py`
2. Add a URL pattern in `urls.py` with a `name=`
3. If it needs a nav link, add a `PluginMenuItem` in `navigation.py`
4. Create a template in `templates/netbox_discovery/`

## Running Migrations (Production)

```bash
cd /opt/netbox-discovery-plugin
sudo git pull origin main
sudo /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate netbox_discovery
sudo systemctl restart netbox netbox-rq
```

## Documentation

Each source file has a corresponding doc in `docs/`. Update the relevant doc when making significant changes to a file.
