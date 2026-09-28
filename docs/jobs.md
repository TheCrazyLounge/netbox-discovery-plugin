# netbox_discovery/jobs.py

## Purpose

Background job orchestration. Contains the main `DiscoveryJob` class and the periodic `discovery_scheduler` system job.

---

## DiscoveryJob

Subclass of NetBox `JobRunner`. Executed by `netbox-rq` workers.

`enqueue_discovery(target)` binds the job with `instance=target` so it
appears on the target's Jobs tab. `DiscoveryTarget` must inherit
`JobsMixin` or `Job.full_clean()` rejects the enqueue.

### Execution Flow

```
run(data)
├── 1. Resolve DiscoveryTarget from data["target_id"]
├── 2. Reap any stale "running" runs (_reap_stale_runs)
├── 3. Create DiscoveryRun record (status=running)
├── 4. scan_targets() → live_ips
├── 5. crawl() [parallel BFS]
│   └── on_device(ip, device_data, driver_name)
│       ├── sync_device() → NetBox sync
│       ├── Append to device_results
│       └── Append {hostname, neighbors} to neighbor_records
├── 6. sync_cables(neighbor_records) → cables_created  [post-crawl]
├── 7. Log summary (hosts, created, updated, cables, errors)
└── finally: _finish_run() → saves DiscoveryRun
```

### Thread Safety

All shared state (`log_lines`, `counters`, `device_results`, `neighbor_records`) is protected by `log_lock` (a `threading.Lock`). The `log_fn` closure acquires the lock, appends the line, and flushes the run log to the DB via `queryset.update()`.

### Discovery Run Log File

Verbose per-device discovery output is written to a dedicated rotating file:

- `/var/log/netbox/discovery_runs.log` (20 MB x 10 files)

This logger does **not** propagate to the main `netbox.log`, so discovery crawl chatter is isolated. If the file cannot be opened, jobs fall back to the main plugin logger.

### Callbacks passed to crawl()

- `on_device(ip, device_data, driver_name)` — called on success; calls `sync_device()`, appends to `device_results` and `neighbor_records`
- `on_device_failed(ip, error)` — called on connection/timeout failure; appends a `status="failed"` entry to `device_results`

---

## _finish_run()

Updates `DiscoveryRun` with final counters, status, and log. Has a fallback `queryset.update()` if the full model save fails.

## _update_last_run()

Sets `target.last_run = now()` via `queryset.update()` (does not trigger signals).

## _reap_stale_runs()

Finds `DiscoveryRun` records stuck in `status="running"` for longer than `JOB_TIMEOUT` (1 hour) and marks them `failed`. Handles the case where a worker was `SIGKILL`ed and the `finally` block never ran.

---

## discovery_scheduler (system_job)

Runs every 5 minutes. Iterates all enabled targets with `scan_interval > 0` and enqueues `DiscoveryJob` for any that are overdue (`now - last_run >= scan_interval`).

Wrapped in `try/except ImportError` because `system_job` may not exist in all NetBox 4.x builds.

---

## How to Change

- **Add a new post-crawl step**: Add it after the `sync_cables()` call (Step 6). Update the summary log and `counters` dict.
- **Add a new counter**: Add it to the `counters` dict initialisation, increment it in `on_device`, and add a log line in the summary block. Also update `_finish_run()` if it should be persisted.
- **Change job timeout**: Update `JOB_TIMEOUT` at the top of the file. The crawl gets `JOB_TIMEOUT - FINALIZE_RESERVE` (300 s held back), so cable sync and `_finish_run()` still run before RQ kills the job. Without the reserve, a long run stayed stuck at `running`.
- The crawl receives the target's exclusions, so excluded addresses are never reached through CDP/LLDP neighbors either.
- `cables_created` is persisted on the `DiscoveryRun`.
- **Add a new callback to crawl()**: Add the parameter to the `crawl()` call and implement the corresponding kwarg in `neighbor.py`.
