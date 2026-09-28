# netbox_discovery/migrations/

## Purpose

Django database migration files. Applied in order to build and evolve the plugin's database schema.

---

## Migration History

| File | Changes |
|------|---------|
| `0001_initial.py` | Creates `DiscoveryTarget` and `DiscoveryRun` tables with all original fields |
| `0002_discoverytarget_max_workers.py` | Adds `max_workers` field to `DiscoveryTarget` (default 5) |
| `0003_discoveryrun_device_results.py` | Adds `device_results` JSONField to `DiscoveryRun` (default empty list) |
| `0004_discoverytarget_exclusions.py` | Adds `exclusions` to `DiscoveryTarget` |
| `0005_sync_model_metadata.py` | Syncs model metadata with NetBox base-model changes |
| `0006_macaddresstableentry.py` | Creates the `MacAddressTableEntry` table |
| `0007_target_bounds_run_cables_created.py` | Adds `DiscoveryRun.cables_created`; adds min/max validators to `max_depth`, `ssh_timeout`, `max_workers` (no schema change for those) |

---

## How to Create a New Migration

1. Make your field changes in `models.py`
2. Run (in the NetBox venv):
   ```bash
   python manage.py makemigrations netbox_discovery
   ```
3. Review the generated file — ensure it looks correct before committing
4. Apply on production:
   ```bash
   python manage.py migrate netbox_discovery
   sudo systemctl restart netbox netbox-rq
   ```

## Squashing Migrations

If the migration chain becomes very long, squash with:
```bash
python manage.py squashmigrations netbox_discovery 0001 0003
```

Review the squashed file carefully — remove any `RunPython` calls that are no longer needed.

## Rolling Back

To roll back to a specific migration:
```bash
python manage.py migrate netbox_discovery 0002
```

To roll all the way back (drops all plugin tables):
```bash
python manage.py migrate netbox_discovery zero
```
