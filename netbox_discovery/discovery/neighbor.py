"""
BFS (breadth-first search) recursive neighbor crawler.

Starting from seed IPs, connects to each device, collects data,
then enqueues newly discovered neighbor IPs for further processing
up to max_depth levels deep.

Devices are processed in parallel using a thread pool (max_workers).

Each worker thread opens its own Django DB connection on first ORM use and
must close it on exit — Django has no connection pool by default, so every
worker is an additional PostgreSQL backend for the lifetime of the crawl.
Size max_workers with that in mind.
"""

import inspect
import logging
import queue as _queue_mod
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Callable, Dict, List, Optional, Set

import netaddr

from .collector import collect_device_data
from .driver_detect import detect_and_connect
from .scanner import _build_exclusion_set, _is_excluded

logger = logging.getLogger("netbox.plugins.netbox_discovery")


def _invoke_on_device_data(
    callback: Callable[..., None],
    ip: str,
    data: Dict[str, Any],
    driver_name: str,
    device_log: Callable[[str], None],
) -> None:
    """Invoke on_device_data callback while supporting legacy 3-arg signatures."""
    try:
        sig = inspect.signature(callback)
    except (TypeError, ValueError):
        # Built-ins/partials may not have an inspectable signature; try 4 args first.
        sig = None

    if sig is not None:
        positional = [
            p
            for p in sig.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        has_varargs = any(p.kind == p.VAR_POSITIONAL for p in sig.parameters.values())
        if not has_varargs and len(positional) <= 3:
            callback(ip, data, driver_name)
            return

    try:
        callback(ip, data, driver_name, device_log)
    except TypeError as exc:
        # Backward-compatibility fallback: older callbacks accept 3 args only.
        if "positional argument" in str(exc) and (
            "4 were given" in str(exc)
            or "required positional argument" in str(exc)
        ):
            callback(ip, data, driver_name)
            return
        raise


def crawl(
    seed_ips: Set[str],
    username: str,
    password: str,
    enable_secret: str = "",
    timeout: int = 10,
    preferred_driver: str = "auto",
    max_depth: int = 3,
    discovery_protocol: str = "both",
    on_device_data: Optional[Callable[[str, Dict[str, Any], str, Callable], None]] = None,
    on_device_failed: Optional[Callable[[str, str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    log_batch_fn: Optional[Callable[[List[str]], None]] = None,
    stop_flag: Optional[Callable[[], bool]] = None,
    max_workers: int = 5,
    options: Optional[Dict[str, Any]] = None,
    overall_timeout: int = 3600,
    exclusions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Concurrent BFS crawl starting from seed_ips, following LLDP/CDP neighbors.

    Args:
        seed_ips: Starting set of live IP addresses.
        username: SSH username.
        password: SSH password.
        enable_secret: Optional enable password.
        timeout: SSH timeout per connection.
        preferred_driver: 'auto' or specific NAPALM driver name.
        max_depth: Maximum neighbor recursion depth.
        on_device_data: Callback invoked with (ip, device_data_dict, driver_name,
                        device_log_fn) for each successfully collected device.
                        device_log_fn buffers messages for this device.
        on_device_failed: Optional callback invoked with (ip, error_message) for
                          each device that failed to connect or collect data.
        log_fn: Optional log/progress callback (must be thread-safe).
        log_batch_fn: Optional callback that flushes a list of log lines
                      atomically (keeps per-device output grouped).
        stop_flag: Optional callable that returns True to abort early.
        max_workers: Number of devices to process in parallel.
        overall_timeout: Hard wall-clock ceiling for the whole crawl, in
                         seconds. Guarantees crawl() returns rather than
                         blocking indefinitely on the work queue.
        exclusions: IPs/CIDRs that must never be connected to. The scanner
                    already drops them from the seeds; this stops the crawl
                    from reaching them again through CDP/LLDP neighbors.

    Returns:
        Summary dict with counts.
    """
    if log_fn is None:
        log_fn = lambda msg: logger.info(msg)
    if stop_flag is None:
        stop_flag = lambda: False
    if options is None:
        options = {}
    exclusion_networks = _build_exclusion_set(exclusions or [])

    # Set once crawl() stops waiting (timeout or cancellation). Workers check
    # it before each item: without it they kept draining the queue — SSHing
    # to devices and writing to NetBox — after the job had already reported
    # its result, because the poison pills sit behind the remaining work.
    abort = threading.Event()

    def should_stop() -> bool:
        return abort.is_set() or stop_flag()

    # Per-device data-collection wall-clock timeout.
    # The collector runs 5 base sequential NAPALM calls (get_facts, get_interfaces,
    # get_interfaces_ip, get_vlans, neighbors).  Each call may take up to
    # read_timeout seconds (max(timeout*3, 60) for most drivers).  On large
    # devices (e.g. 3850 stacks with 144 ports), show interfaces alone can
    # take 30-50s.  Allow enough room for all calls plus CDP CLI parsing.
    # Optional Tier 2 calls add to the budget.
    read_timeout = max(timeout * 3, 60)
    base_calls = 5
    optional_calls = sum(1 for k in ("collect_vrfs",) if options.get(k))
    # collect_inventory uses CLI (not a separate NAPALM getter) so it's faster
    if options.get("collect_inventory"):
        optional_calls += 1
    collect_timeout = read_timeout * (base_calls + optional_calls) + 30

    # Thread-safe work queue; each item is (ip, depth) or None (poison pill).
    work_queue: _queue_mod.Queue = _queue_mod.Queue()

    # Lock protects all shared mutable state.
    lock = threading.Lock()
    visited: Set[str] = set()
    queued: Set[str] = set(seed_ips)  # IPs ever enqueued — prevents duplicates
    summary = {
        "connected": 0,
        "failed": 0,
        "skipped": 0,
        "neighbors_queued": 0,
    }

    for ip in seed_ips:
        work_queue.put((ip, 0))

    # Use the configured worker count directly. Capping to len(seed_ips) meant
    # a single-seed crawl ran the entire multi-hundred-device topology on one
    # thread, because the cap was computed before any neighbors were
    # discovered. Surplus workers simply block harmlessly on Queue.get().
    actual_workers = max(1, max_workers)
    log_fn(
        f"Crawl starting: {len(seed_ips)} seed IP(s), max_depth={max_depth}, "
        f"workers={actual_workers}, collect_timeout={collect_timeout}s"
    )

    def _flush_device_log(lines: List[str]):
        """Flush buffered per-device log lines as one atomic block."""
        if not lines:
            return
        if log_batch_fn:
            log_batch_fn(lines)
        else:
            # Fallback: flush line-by-line (may interleave with other threads)
            for line in lines:
                log_fn(line)

    def worker():
        # Each thread needs its own Django DB connection released on exit.
        try:
            from django.db import connection as _db_conn
        except ImportError:
            _db_conn = None

        try:
            while True:
                item = work_queue.get()

                # Poison pill — time to exit.
                if item is None:
                    work_queue.task_done()
                    break

                ip, depth = item

                # Per-device log buffer: all messages for this device are
                # collected here and flushed as one contiguous block when
                # processing completes, preventing interleaved output from
                # concurrent worker threads.
                device_lines: List[str] = []
                discovered_hostname: Optional[str] = None
                device_started_at = time.monotonic()
                warning_count = 0
                error_count = 0
                queued_neighbors_count = 0
                selected_driver: Optional[str] = None
                connect_duration: Optional[float] = None
                collect_duration: Optional[float] = None
                sync_duration: Optional[float] = None
                device_status = "unknown"
                step_status_summary = (
                    "facts=n/a interfaces=n/a lag=n/a ips=n/a vlans=n/a neighbors=n/a stack=n/a"
                )

                def device_log(msg, _buf=device_lines):
                    """
                    Buffer log lines with device context.

                    Multi-line messages (for example Netmiko/NAPALM exceptions)
                    are split so every physical line is still attributable to
                    the same device in the aggregated run log.
                    """
                    nonlocal warning_count, error_count
                    text = str(msg) if msg is not None else ""
                    # Late binding of discovered_hostname/ip/depth is deliberate,
                    # not the bug B023 usually catches: device_log is redefined
                    # per loop iteration and only ever called within that same
                    # iteration, so reading the hostname at call time is what
                    # lets lines logged after detection carry the real name
                    # instead of the seed IP.
                    prefix = f"[{discovered_hostname}] " if discovered_hostname else f"[{ip} d={depth}] "  # noqa: B023
                    lines = text.splitlines() or [""]
                    for line in lines:
                        if "[WARN]" in line:
                            warning_count += 1
                        if any(token in line for token in ("[ERROR]", "[FAILED]", "[FATAL]")):
                            error_count += 1
                        _buf.append(f"{prefix}{line}")

                try:
                    if should_stop():
                        with lock:
                            summary["skipped"] += 1
                        continue

                    with lock:
                        if ip in visited:
                            summary["skipped"] += 1
                            continue
                        visited.add(ip)
                        n_visited = len(visited)

                    remaining = work_queue.qsize()
                    device_log("=" * 72)
                    device_log(
                        f"[START] Processing device at depth={depth} "
                        f"(queue~{remaining}, visited={n_visited})"
                    )

                    connect_started_at = time.monotonic()
                    device, driver_name = detect_and_connect(
                        ip=ip,
                        username=username,
                        password=password,
                        enable_secret=enable_secret,
                        timeout=timeout,
                        preferred_driver=preferred_driver,
                        log_fn=device_log,
                    )
                    connect_duration = time.monotonic() - connect_started_at

                    if device is None:
                        device_status = "connect_failed"
                        device_log(f"  [FAILED] {ip} — could not connect with any driver. Skipping.")
                        with lock:
                            summary["failed"] += 1
                        if on_device_failed:
                            on_device_failed(ip, "Could not connect with any driver")
                        continue

                    try:
                        selected_driver = driver_name
                        device_log(
                            f"  [OK] Connected via '{driver_name}'. "
                            f"Collecting data (timeout={collect_timeout}s)..."
                        )
                        # Hard wall-clock deadline so a hung NAPALM call can't
                        # stall this worker thread indefinitely.
                        executor = ThreadPoolExecutor(max_workers=1)
                        collect_started_at = time.monotonic()
                        future = executor.submit(
                            collect_device_data, device, driver_name, discovery_protocol, device_log, options
                        )
                        try:
                            data = future.result(timeout=collect_timeout)
                            collect_duration = time.monotonic() - collect_started_at
                        except FuturesTimeoutError:
                            collect_duration = time.monotonic() - collect_started_at
                            device_status = "collect_timed_out"
                            device_log(
                                f"  [ERROR] Data collection for {ip} timed out "
                                f"after {collect_timeout}s — skipping device"
                            )
                            logger.error("collect_device_data timed out for %s", ip)
                            with lock:
                                summary["failed"] += 1
                            if on_device_failed:
                                on_device_failed(ip, f"Data collection timed out after {collect_timeout}s")
                            continue
                        finally:
                            executor.shutdown(wait=False, cancel_futures=True)

                        facts = data.get("facts", {})
                        hostname = facts.get("hostname", ip)
                        discovered_hostname = hostname
                        step_status = data.get("step_status", {}) or {}
                        status_parts = [
                            f"facts={step_status.get('facts', 'n/a')}",
                            f"interfaces={step_status.get('interfaces', 'n/a')}",
                            f"lag={step_status.get('lag', 'n/a')}",
                            f"ips={step_status.get('interfaces_ip', 'n/a')}",
                            f"vlans={step_status.get('vlans', 'n/a')}",
                            f"neighbors={step_status.get('neighbors', 'n/a')}",
                            f"stack={step_status.get('stack', 'n/a')}",
                        ]
                        if "vrfs" in step_status:
                            status_parts.append(f"vrfs={step_status['vrfs']}")
                        if "inventory" in step_status:
                            status_parts.append(f"inventory={step_status['inventory']}")
                        step_status_summary = " ".join(status_parts)
                        device_log(
                            f"  Hostname: {hostname} | Vendor: {facts.get('vendor', '?')} "
                            f"| Model: {facts.get('model', '?')} | Serial: {facts.get('serial_number', '?')}"
                        )

                        if data.get("raw_errors"):
                            for err in data["raw_errors"]:
                                device_log(f"  [WARN] {err}")

                        # NetBox sync — pass buffered log so sync output stays grouped
                        if on_device_data:
                            sync_started_at = time.monotonic()
                            try:
                                _invoke_on_device_data(
                                    on_device_data, ip, data, driver_name, device_log
                                )
                                sync_duration = time.monotonic() - sync_started_at
                            except Exception as exc:
                                sync_duration = time.monotonic() - sync_started_at
                                device_status = "sync_failed"
                                device_log(f"  [ERROR] NetBox sync failed for {ip}: {exc} — continuing")
                                logger.exception("Sync error for %s", ip)

                        with lock:
                            summary["connected"] += 1

                        # Enqueue neighbors
                        if depth < max_depth:
                            new_ips = _extract_neighbor_ips(data.get("neighbors", []))
                            for neighbor_ip in new_ips:
                                if _is_excluded(neighbor_ip, exclusion_networks):
                                    device_log(f"  Neighbor {neighbor_ip} is excluded — not queuing")
                                    continue
                                enqueue = False
                                with lock:
                                    if neighbor_ip and neighbor_ip not in queued:
                                        queued.add(neighbor_ip)
                                        enqueue = True
                                    elif neighbor_ip in queued and neighbor_ip not in visited:
                                        device_log(
                                            f"  Neighbor {neighbor_ip} already queued — skipping duplicate"
                                        )
                                if enqueue:
                                    device_log(f"  Queuing neighbor: {neighbor_ip} (depth={depth + 1})")
                                    work_queue.put((neighbor_ip, depth + 1))
                                    with lock:
                                        summary["neighbors_queued"] += 1
                                    queued_neighbors_count += 1

                    except Exception as exc:
                        device_status = "collect_failed"
                        device_log(f"  [ERROR] Data collection failed for {ip}: {exc} — skipping device")
                        logger.exception("Collection error for %s", ip)
                        with lock:
                            summary["failed"] += 1
                        if on_device_failed:
                            on_device_failed(ip, str(exc))
                    finally:
                        if device_status == "unknown":
                            device_status = "completed_with_errors" if error_count > 0 else "completed"
                        try:
                            device.close()
                        except Exception:
                            pass

                except Exception as exc:
                    device_status = "worker_failed"
                    device_log(f"[ERROR] Unexpected error processing {ip}: {exc} — continuing")
                    logger.exception("Unexpected crawl error for %s", ip)
                    with lock:
                        summary["failed"] += 1
                finally:
                    total_duration = time.monotonic() - device_started_at
                    connect_s = f"{connect_duration:.1f}s" if connect_duration is not None else "n/a"
                    collect_s = f"{collect_duration:.1f}s" if collect_duration is not None else "n/a"
                    sync_s = f"{sync_duration:.1f}s" if sync_duration is not None else "n/a"
                    device_log(
                        "[SUMMARY] "
                        f"status={device_status} "
                        f"driver={selected_driver or 'n/a'} "
                        f"{step_status_summary} "
                        f"queued={queued_neighbors_count} "
                        f"warnings={warning_count} "
                        f"errors={error_count} "
                        f"connect={connect_s} "
                        f"collect={collect_s} "
                        f"sync={sync_s} "
                        f"total={total_duration:.1f}s"
                    )
                    device_log("[END] Device processing complete")
                    device_log("=" * 72)
                    # task_done() MUST run even if flushing fails. It used to
                    # sit after _flush_device_log(), which reaches the DB and a
                    # rotating file handler; one exception there skipped
                    # task_done() and left work_queue.join() blocked forever,
                    # wedging the rq worker until SIGKILL.
                    try:
                        _flush_device_log(device_lines)
                    except Exception:
                        logger.exception("Failed to flush device log for %s", ip)
                    finally:
                        work_queue.task_done()

        finally:
            # Release this thread's Django DB connection back to the pool.
            if _db_conn is not None:
                try:
                    _db_conn.close()
                except Exception:
                    pass

    # Start worker threads.
    threads = [
        threading.Thread(target=worker, daemon=True, name=f"discovery-worker-{i}")
        for i in range(actual_workers)
    ]
    for t in threads:
        t.start()

    # Block until every item (including dynamically enqueued neighbors) is
    # done, but never indefinitely — see _join_with_deadline.
    completed = _join_with_deadline(work_queue, overall_timeout, stop_flag)
    if not completed:
        abort.set()
        summary["timed_out"] = True
        log_fn(
            f"[WARN] Crawl did not drain its work queue within {overall_timeout}s "
            "(or was cancelled) — returning with partial results."
        )

    # Send poison pills so workers exit their blocking get() calls.
    for _ in range(actual_workers):
        work_queue.put(None)
    for t in threads:
        t.join(timeout=5)

    log_fn(
        f"Crawl complete. Connected: {summary['connected']}, "
        f"Failed: {summary['failed']}, Neighbors queued: {summary['neighbors_queued']}"
    )
    return summary


def _join_with_deadline(
    work_queue: "_queue_mod.Queue",
    timeout: float,
    stop_flag: Callable[[], bool],
) -> bool:
    """
    Bounded replacement for Queue.join().

    Queue.join() waits forever. A single missed task_done() — or a worker
    thread killed mid-item — therefore wedged the whole job until rq SIGKILLed
    the process, leaving the DiscoveryRun stuck at status="running".

    Returns True if the queue drained, False on timeout or cancellation.
    """
    deadline = time.monotonic() + timeout
    with work_queue.all_tasks_done:
        while work_queue.unfinished_tasks:
            if stop_flag():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            # Wake periodically so stop_flag() stays responsive.
            work_queue.all_tasks_done.wait(timeout=min(remaining, 2.0))
    return True


def _extract_neighbor_ips(neighbors: List[Dict]) -> List[str]:
    """Extract valid IP addresses from neighbor entries."""
    ips = []
    for n in neighbors:
        # `or ""` rather than a get() default: the key can be present with an
        # explicit None, which get() will happily return, and .strip() on it
        # raises AttributeError — aborting the crawl's expansion for the whole
        # device rather than skipping one bad neighbor entry.
        ip = (n.get("remote_ip") or "").strip()
        if ip and _is_valid_ip(ip) and not _is_link_local(ip):
            ips.append(ip)
    return ips


def _is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    # netaddr is imported at module scope: catching ImportError here used to
    # make every neighbor IP look invalid, silently halting BFS expansion.
    try:
        netaddr.IPAddress(ip)
        return True
    except (netaddr.AddrFormatError, ValueError, TypeError):
        return False


def _is_link_local(ip: str) -> bool:
    """Return True for link-local and loopback addresses (should not be crawled)."""
    try:
        addr = netaddr.IPAddress(ip)
        return addr.is_link_local() or addr.is_loopback()
    except (netaddr.AddrFormatError, ValueError, TypeError):
        return False
