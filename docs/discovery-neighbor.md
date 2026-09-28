# netbox_discovery/discovery/neighbor.py

## Purpose

Concurrent BFS (breadth-first search) crawler. Starting from seed IPs, connects to each device, collects data, then enqueues neighbor IPs for the next depth level. Devices at the same depth level are processed in parallel.

---

## crawl(seed_ips, username, password, ...) → Dict

Main entry point. Called by `jobs.py` after host scanning.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `seed_ips` | `Set[str]` | Live IPs from scanner |
| `username` / `password` | str | SSH credentials |
| `enable_secret` | str | Optional enable password |
| `timeout` | int | SSH timeout per connection |
| `preferred_driver` | str | `"auto"` or specific driver name |
| `max_depth` | int | Maximum neighbor hops (default 3) |
| `discovery_protocol` | str | `"lldp"`, `"cdp"`, or `"both"` |
| `on_device_data` | callable | `(ip, data_dict, driver_name)` — called on success |
| `on_device_failed` | callable | `(ip, error_msg)` — called on failure |
| `log_fn` | callable | Thread-safe log callback |
| `stop_flag` | callable | Returns `True` to abort early |
| `max_workers` | int | Parallel worker threads (default 5) |
| `overall_timeout` | int | Wall-clock ceiling for the whole crawl, in seconds |
| `exclusions` | list[str] | IPs/CIDRs never to connect to. Neighbors inside them are not queued |

### Returns

```python
{
    "connected": int,        # devices successfully connected and collected
    "failed": int,    # devices that failed to connect/collect
    "skipped": int,          # duplicates/stop-flag skips
    "neighbors_queued": int, # new neighbor IPs added to queue
}
```

---

## Concurrency Model

Uses a `queue.Queue` (work queue) and a `threading.Lock` (guards `visited` set and `queued` set).

- **`visited`** — IPs already dequeued and processed (prevents re-processing)
- **`queued`** — IPs already in the queue (prevents queue inflation from duplicate neighbor reports)
- Worker threads pull `(ip, depth)` items from the queue. When done, they extract neighbor IPs and enqueue any not already visited/queued — but only if `depth < max_depth`.
- Poison-pill shutdown: after the bounded `_join_with_deadline()` (all items processed, timeout, or cancellation), one `None` sentinel is enqueued per worker thread to unblock their `queue.get()` call.
- On timeout or cancellation an internal `abort` event is set. Workers check it before each item, so they skip the remaining queue instead of connecting to devices after `crawl()` has returned.
- Each worker closes its Django DB connection in a `finally` block so connections are returned to the pool.
- Per-device output is buffered and flushed atomically as a block. Every physical line is prefixed with device context (`[ip d=depth]`, then `[hostname]` once discovered), so multiline exceptions remain attributable to the correct device.
- Each device block ends with a compact `[SUMMARY]` line containing status, selected driver, step outcomes (`facts/interfaces/lag/ips/vlans/neighbors/stack`), warnings/errors, neighbors queued, and timing metrics (connect/collect/sync/total) for quick triage.

---

## Per-Device Processing (worker thread)

For each `(ip, depth)` item:
1. Call `detect_and_connect()` → open NAPALM device
2. Call `collect_device_data()` → all device data
3. Call `on_device_data(ip, data, driver_name)`
4. Extract neighbor IPs from `data["neighbors"]` via `_extract_neighbor_ips()`
5. Enqueue unseen, non-excluded neighbors at `depth + 1` (if `depth < max_depth`)
6. On any failure: call `on_device_failed(ip, error)`

---

## How to Change

- **Change parallelism**: The `max_workers` parameter is passed from `DiscoveryTarget.max_workers` (configurable per target in the UI).
- **Add a stop condition**: Pass a `stop_flag` callable that returns `True`. Workers check this before processing each item.
- **Add per-device post-processing**: Add logic inside the worker function after `on_device_data` is called.
- **Change neighbor IP extraction**: Update `_extract_neighbor_ips()` — currently reads `nbr["remote_ip"]` from the collector output.
