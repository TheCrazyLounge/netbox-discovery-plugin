# netbox_discovery/views.py

## Purpose

All Django class-based views for the plugin UI. Covers Discovery Targets, Discovery Runs, and the Duplicate Devices tool.

---

## Duplicate Devices Views

### DuplicateDevicesView (GET /duplicate-devices/)

Lists all NetBox `Device` objects grouped by base hostname (the portion before the first `.`). Groups with more than one device are shown as potential duplicates.

**Context variables:**
- `duplicates` — list of `{base, devices}` dicts
- `duplicate_group_count` — number of groups

### MergeDevicesView (POST /duplicate-devices/merge/)

Merges two devices: keeps one (`keep_id`), copies data from the other (`delete_id`), then deletes the duplicate.

**Merge logic (in order):**
1. **Site**: if keeper is on the holding site and duplicate has a real site, transfer it
2. **Serial**: copy from duplicate if keeper has none
3. **os_version custom field**: copy from duplicate if keeper lacks it
4. **Virtual Chassis**: if duplicate is in a VC and keeper is not, the duplicate first gives up its slot, then the keeper takes its position and priority (and becomes master if the duplicate was). Doing it in the other order violated the unique `(virtual_chassis, vc_position)` constraint.
5. If duplicate was the VC master: re-fetch VC from DB, set `vc.master = keeper`
6. Detach duplicate from VC (null out fields) before deletion to avoid `ProtectedError`
7. **Primary/OOB IPs**: `primary_ip4`, `primary_ip6` and `oob_ip` (NetBox 4.1+) move to the keeper where it has none. These are one-to-one fields, so the duplicate releases them first.

The whole merge runs in one transaction. `ValueError`, `ProtectedError` and `IntegrityError` are reported as UI messages and roll back everything instead of returning a 500.

**Holding site name** is read from `PLUGINS_CONFIG['netbox_discovery']['holding_site']` (default: `"Holding"`).

### DeleteDuplicateDeviceView (POST /duplicate-devices/<pk>/delete/)

Deletes a single device without merging. Simple POST-only view.

---

## DiscoveryTarget Views

All extend NetBox generic views — most logic is in the framework.

| Class | Base | Purpose |
|-------|------|---------|
| `DiscoveryTargetListView` | `ObjectListView` | Paginated list with filter/search |
| `DiscoveryTargetView` | `ObjectView` | Detail page; adds `recent_runs_table` context |
| `DiscoveryTargetEditView` | `ObjectEditView` | Create/edit form |
| `DiscoveryTargetDeleteView` | `ObjectDeleteView` | Delete confirmation |
| `DiscoveryTargetBulkDeleteView` | `BulkDeleteView` | Bulk delete from list |

### DiscoveryTargetRunView (POST /targets/<pk>/run/)

Enqueues a `DiscoveryJob` for the target. Validates that the target is enabled and has credentials before enqueuing. Redirects to the target detail page with a flash message.

---

## DiscoveryRun Views

| Class | Base | Purpose |
|-------|------|---------|
| `DiscoveryRunListView` | `ObjectListView` | Paginated list ordered by `-started_at` |
| `DiscoveryRunView` | `ObjectView` | Detail page; splits `device_results` into created/updated/failed lists for collapsible panels |
| `DiscoveryRunDeleteView` | `ObjectDeleteView` | Delete confirmation |
| `DiscoveryRunBulkDeleteView` | `BulkDeleteView` | Bulk delete |

---

## How to Change

- **Add a new action to MergeDevicesView**: Add the logic before `keeper.save()` so it's batched into a single save call.
- **Add a new list view for a new model**: Subclass `generic.ObjectListView`, set `queryset`, `table`, `filterset`, `filterset_form`.
- **Add extra context to a detail view**: Override `get_extra_context(self, request, instance)` and return a dict.
