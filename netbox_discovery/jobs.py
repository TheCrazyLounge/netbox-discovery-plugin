"""
Background jobs for network discovery.

DiscoveryJob: manually-triggered or scheduled job for a single DiscoveryTarget.
discovery_scheduler: system_job that fires every N minutes and enqueues
                     DiscoveryJob for any targets that are due.
"""

import logging
import logging.handlers
import os
import threading
import time

from django.utils import timezone
from netbox.jobs import JobRunner

from .config import get_discovery_options, get_setting

logger = logging.getLogger("netbox.plugins.netbox_discovery")


# 1 hour — large enough for any realistic crawl
JOB_TIMEOUT = 3600

# Part of JOB_TIMEOUT withheld from the crawl for post-crawl cable sync and
# for recording the run's result. Giving the crawl the whole budget meant RQ
# killed a long job before cable sync or _finish_run could run, leaving the
# DiscoveryRun stuck at "running".
FINALIZE_RESERVE = 300

# Minimum seconds between Job-status polls when checking for cancellation.
STOP_FLAG_POLL_INTERVAL = 5.0

# Minimum seconds between DiscoveryRun.log DB writes. The complete log always
# goes to the rotating run-log file; this column is a progress view.
LOG_FLUSH_INTERVAL = 3.0

# DiscoveryRun.log bounds. A large crawl can emit tens of thousands of lines,
# and this column was previously unbounded and rewritten in full per line.
LOG_HEAD_LINES = 2000
LOG_TAIL_LINES = 8000
MAX_LOG_CHARS = 2 * 1024 * 1024  # 2 MB


def _render_log(lines: list) -> str:
    """
    Render buffered log lines into a bounded string for DiscoveryRun.log.

    Keeps the head (target/config context) and the tail (where failures and
    the final summary appear), dropping the middle. Nothing is lost — the
    dedicated run-log file always receives every line.
    """
    total = len(lines)
    if total > LOG_HEAD_LINES + LOG_TAIL_LINES:
        omitted = total - LOG_HEAD_LINES - LOG_TAIL_LINES
        parts = (
            lines[:LOG_HEAD_LINES]
            + [f"... [{omitted} lines omitted — see the discovery run log file] ..."]
            + lines[-LOG_TAIL_LINES:]
        )
    else:
        parts = lines

    text = "\n".join(parts)
    if len(text) > MAX_LOG_CHARS:
        text = text[:MAX_LOG_CHARS] + "\n... [truncated]"
    return text


def _get_discovery_run_logger() -> logging.Logger:
    """
    Dedicated logger for verbose discovery run output.

    Writes to /var/log/netbox/discovery_runs.log so per-device crawl logs do
    not clutter the main netbox.log stream.
    """
    name = "netbox.plugins.netbox_discovery.runs"
    run_logger = logging.getLogger(name)
    if run_logger.handlers:
        return run_logger

    run_logger.setLevel(logging.INFO)
    run_logger.propagate = False

    log_path = get_setting("run_log_path")
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=20 * 1024 * 1024,  # 20 MB per file
            backupCount=10,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        run_logger.addHandler(handler)
    except OSError as exc:
        # Fall back to main plugin logger if dedicated file cannot be opened.
        logger.warning(
            "Cannot open discovery run log %s: %s — using main logger fallback",
            log_path,
            exc,
        )
        run_logger.addHandler(logging.NullHandler())
        run_logger.propagate = True

    return run_logger


def has_active_discovery(target) -> bool:
    """
    Return True if discovery for this target is already queued or running.

    Checks the NetBox Job queue as well as the DiscoveryRun table: the
    DiscoveryRun row is only created once the job *starts*, so a job sitting
    in the rq queue is invisible to a DiscoveryRun-only check. Without this,
    clicking "Run Now" repeatedly launched concurrent crawls that fought over
    the same devices.
    """
    from .models import DiscoveryRun

    if DiscoveryRun.objects.filter(target=target, status="running").exists():
        return True

    try:
        from core.choices import JobStatusChoices
        from core.models import Job
        from django.contrib.contenttypes.models import ContentType

        return Job.objects.filter(
            object_type=ContentType.objects.get_for_model(target),
            object_id=target.pk,
            status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES,
        ).exists()
    except Exception:
        # Never block a run because the Job introspection failed.
        logger.debug("Could not inspect the Job queue for target %s", target.pk, exc_info=True)
        return False


def enqueue_discovery(target):
    """Enqueue a DiscoveryJob bound to `target` so it shows on the target's Jobs tab."""
    return DiscoveryJob.enqueue(
        instance=target,
        data={"target_id": target.pk},
        name=f"Discovery: {target.name}",
    )


class DiscoveryJob(JobRunner):
    """
    NetBox background job that runs a full discovery cycle for one DiscoveryTarget.
    """

    class Meta:
        name = "Network Discovery"
        timeout = JOB_TIMEOUT

    def _make_stop_flag(self):
        """
        Build the callable crawl() polls to decide whether to abort.

        crawl() has always accepted a stop_flag and checked it per device, but
        nothing ever passed one — so a runaway crawl could only be stopped by
        killing the rq worker. Poll the Job row so deleting or terminating the
        job in the NetBox UI actually stops the crawl.
        """
        job_pk = getattr(self.job, "pk", None)
        if job_pk is None:
            return lambda: False

        state = {"checked": 0.0, "stop": False}

        def stop_flag():
            if state["stop"]:
                return True
            now = time.monotonic()
            if now - state["checked"] < STOP_FLAG_POLL_INTERVAL:
                return False
            state["checked"] = now
            try:
                from core.choices import JobStatusChoices
                from core.models import Job

                status = (
                    Job.objects.filter(pk=job_pk)
                    .values_list("status", flat=True)
                    .first()
                )
                # Job row deleted, or moved to a terminal state by an operator.
                if status is None or status in JobStatusChoices.TERMINAL_STATE_CHOICES:
                    state["stop"] = True
            except Exception:
                logger.debug("stop_flag poll failed", exc_info=True)
            return state["stop"]

        return stop_flag

    def run(self, data, commit=True):
        from .discovery.neighbor import crawl
        from .discovery.scanner import scan_targets
        from .models import DiscoveryRun, DiscoveryTarget
        from .sync.netbox_sync import sync_cables, sync_device

        target_id = data.get("target_id")
        if not target_id:
            self._safe_log("No target_id in job data")
            return

        try:
            target = DiscoveryTarget.objects.get(pk=target_id)
        except DiscoveryTarget.DoesNotExist:
            self._safe_log(f"DiscoveryTarget {target_id} not found")
            return

        # Clean up any runs that were left in 'running' state by a previously
        # killed worker process (SIGKILL bypasses our finally block).
        _reap_stale_runs(target)

        # Create run record
        run = DiscoveryRun.objects.create(
            target=target,
            status="running",
            started_at=timezone.now(),
        )

        holding_site = get_setting("holding_site_name")
        ssh_timeout = target.ssh_timeout or get_setting("ssh_timeout")

        # Built centrally so a new feature flag cannot be added to
        # default_settings without also being plumbed through to the collector.
        discovery_options = get_discovery_options()

        counters = {
            "hosts_scanned": 0,
            "devices_created": 0,
            "devices_updated": 0,
            "cables_created": 0,
            "errors": 0,
        }
        log_lines = []
        device_results = []  # [{ip, hostname, status, driver, error}]
        neighbor_records = []  # [{hostname, neighbors}] — for post-crawl cable sync
        log_lock = threading.Lock()  # guards log_lines, counters, device_results, neighbor_records
        final_status = "failed"
        run_logger = _get_discovery_run_logger()
        stop_flag = self._make_stop_flag()

        # DB flush pacing. Previously every single log line rebuilt the whole
        # log via "\n".join(log_lines) *inside* the lock and issued a full
        # TEXT-column UPDATE, so a run producing N lines did N joins and N
        # rewrites of a steadily growing value — O(n^2) in both CPU and WAL,
        # while every worker contended on log_lock. Flush on an interval
        # instead; the UI is a progress view, not a live tail.
        last_flush = [0.0]
        flush_lock = threading.Lock()

        def _flush_log_to_db(force=False):
            """Persist the accumulated log, at most once per LOG_FLUSH_INTERVAL."""
            now = time.monotonic()
            if not force and now - last_flush[0] < LOG_FLUSH_INTERVAL:
                return
            # Serialize writers, but never block a worker waiting to flush.
            if not flush_lock.acquire(blocking=force):
                return
            try:
                if not force and now - last_flush[0] < LOG_FLUSH_INTERVAL:
                    return
                with log_lock:
                    snapshot = _render_log(log_lines)
                last_flush[0] = time.monotonic()
                run.__class__.objects.filter(pk=run.pk).update(log=snapshot)
            except Exception:
                logger.exception("Failed to persist discovery run log")
            finally:
                flush_lock.release()

        def log_fn(msg):
            with log_lock:
                log_lines.append(msg)
            run_logger.info("[Discovery:%s] %s", target.name, msg)
            self._safe_log(msg)
            _flush_log_to_db()

        def log_batch(messages):
            """Flush multiple log lines atomically — keeps per-device output grouped."""
            if not messages:
                return
            block = "\n".join(messages)
            with log_lock:
                log_lines.extend(messages)
            run_logger.info("[Discovery:%s]\n%s", target.name, block)
            self._safe_log(block)
            _flush_log_to_db()

        try:
            log_fn(f"=== Discovery started: {target.name} ===")
            log_fn(f"Targets: {target.get_target_list()}")
            log_fn(f"Protocol: {target.discovery_protocol} | Max depth: {target.max_depth}")

            # Step 1: host scan
            live_ips = scan_targets(
                target.get_target_list(),
                exclusion_strings=target.get_exclusion_list(),
                log_fn=log_fn,
            )
            counters["hosts_scanned"] = len(live_ips)

            if not live_ips:
                log_fn("No live hosts found. Done.")
                final_status = "completed"
                return

            # Step 2: BFS crawl + NetBox sync
            def on_device(*callback_args, **_callback_kwargs):
                """Handle device data callback from crawl() across callback signature variants."""
                if len(callback_args) < 3:
                    raise ValueError(
                        "on_device callback expected at least 3 positional args "
                        f"(ip, device_data, driver_name); got {len(callback_args)}"
                    )

                ip, device_data, driver_name = callback_args[:3]
                device_log_fn = callback_args[3] if len(callback_args) > 3 else None
                _log = device_log_fn or log_fn
                try:
                    device_data["driver"] = driver_name
                    device_name, was_created = sync_device(
                        mgmt_ip=ip,
                        data=device_data,
                        holding_site_name=holding_site,
                        log_fn=_log,
                        options=discovery_options,
                    )
                    with log_lock:
                        status = "created" if was_created else "updated"
                        device_results.append({
                            "ip": ip,
                            "hostname": device_name,
                            "status": status,
                            "driver": driver_name,
                        })
                        neighbor_records.append({
                            "hostname": device_name,
                            "neighbors": device_data.get("neighbors", []),
                        })
                        if was_created:
                            counters["devices_created"] += 1
                        else:
                            counters["devices_updated"] += 1
                except Exception as exc:
                    _log(f"  [ERROR] Sync failed for {ip}: {exc}")
                    logger.exception("sync_device error for %s", ip)
                    with log_lock:
                        device_results.append({
                            "ip": ip,
                            "hostname": None,
                            "status": "failed",
                            "error": str(exc),
                        })
                        counters["errors"] += 1

            def on_device_failed(ip, error):
                with log_lock:
                    device_results.append({
                        "ip": ip,
                        "hostname": None,
                        "status": "failed",
                        "error": error,
                    })

            crawl_summary = crawl(
                seed_ips=live_ips,
                username=target.get_effective_username(),
                password=target.get_effective_password(),
                enable_secret=target.get_effective_enable_secret(),
                timeout=ssh_timeout,
                preferred_driver=target.napalm_driver,
                max_depth=target.max_depth,
                discovery_protocol=target.discovery_protocol,
                on_device_data=on_device,
                on_device_failed=on_device_failed,
                log_fn=log_fn,
                log_batch_fn=log_batch,
                stop_flag=stop_flag,
                max_workers=target.max_workers,
                options=discovery_options,
                overall_timeout=JOB_TIMEOUT - FINALIZE_RESERVE,
                exclusions=target.get_exclusion_list(),
            )
            counters["errors"] += crawl_summary.get("failed", 0)

            if stop_flag():
                log_fn("[ABORTED] Discovery cancelled — job is no longer active.")
                final_status = "failed"
                return

            # Step 3: cable sync — wire up CDP/LLDP connections post-crawl
            cables_created = 0
            if neighbor_records:
                log_fn("--- Cable sync (CDP/LLDP neighbors) ---")
                try:
                    cables_created = sync_cables(neighbor_records, log_fn=log_fn)
                except Exception as exc:
                    log_fn(f"  [Cable] sync_cables error: {exc}")
                    logger.exception("sync_cables error for target %s", target.name)
            counters["cables_created"] = cables_created

            final_status = "partial" if counters["errors"] > 0 else "completed"
            log_fn("=" * 60)
            log_fn(
                f"=== DISCOVERY COMPLETE: {target.name} ==="
            )
            log_fn(
                f"    Hosts scanned : {counters['hosts_scanned']}"
            )
            log_fn(
                f"    Devices created: {counters['devices_created']}"
            )
            log_fn(
                f"    Devices updated: {counters['devices_updated']}"
            )
            log_fn(
                f"    Cables created : {cables_created}"
            )
            log_fn(
                f"    Errors         : {counters['errors']}"
            )
            log_fn(
                f"    Status         : {final_status.upper()}"
            )
            log_fn("=" * 60)

        except Exception as exc:
            log_fn(f"[FATAL] Job crashed: {exc}")
            logger.exception("DiscoveryJob fatal error for target %s", target.name)
            counters["errors"] += 1
            final_status = "failed"

        finally:
            # Always update the run record regardless of success/failure/early return
            with log_lock:
                final_log = _render_log(log_lines)
            _finish_run(run, counters, final_status, final_log, device_results)
            _update_last_run(target)

    def _safe_log(self, msg: str):
        """
        Emit a line to the NetBox job log so it appears in the job detail UI.

        JobRunner instantiates `self.logger` for us. This previously called
        `self.log_info()` then `self.job.log()` — neither exists on JobRunner,
        so every line raised twice and was discarded, and the job UI showed
        nothing. Only genuinely unexpected failures are suppressed here, and
        they are reported once rather than silently.
        """
        try:
            self.logger.info(msg)
        except Exception:
            # Never let a logging failure abort an in-flight discovery run.
            logger.exception("Failed to write to the NetBox job log")


def _finish_run(run, counters: dict, status: str, log_text: str, device_results: list = None):
    """Update DiscoveryRun with final status. Never raises."""
    try:
        run.status = status
        run.completed_at = timezone.now()
        run.hosts_scanned = counters.get("hosts_scanned", 0)
        run.devices_created = counters.get("devices_created", 0)
        run.devices_updated = counters.get("devices_updated", 0)
        run.cables_created = counters.get("cables_created", 0)
        run.errors = counters.get("errors", 0)
        run.log = log_text
        if device_results is not None:
            run.device_results = device_results
        run.save()
    except Exception as exc:
        logger.error("Failed to save DiscoveryRun %s: %s", run.pk, exc)
        # Last-ditch attempt via queryset update (bypasses model signals)
        try:
            run.__class__.objects.filter(pk=run.pk).update(
                status=status,
                completed_at=timezone.now(),
                log=log_text[:10000],
            )
        except Exception:
            pass


def _update_last_run(target):
    """Update target.last_run. Never raises."""
    try:
        target.__class__.objects.filter(pk=target.pk).update(last_run=timezone.now())
    except Exception as exc:
        logger.error("Failed to update last_run for target %s: %s", target.pk, exc)


def _reap_stale_runs(target):
    """
    Mark any DiscoveryRun for this target that is still 'running' after more
    than JOB_TIMEOUT seconds as 'failed'.  This handles the case where a
    previous worker was killed (SIGKILL) before its finally block could run.
    """
    from datetime import timedelta

    from .models import DiscoveryRun

    cutoff = timezone.now() - timedelta(seconds=JOB_TIMEOUT)
    stale = DiscoveryRun.objects.filter(
        target=target, status="running", started_at__lt=cutoff
    )
    count = stale.update(
        status="failed",
        completed_at=timezone.now(),
        log="[Job killed by RQ worker timeout — no final log available]",
    )
    if count:
        logger.warning(
            "Reaped %d stale run(s) for target '%s'", count, target.name
        )


# ---------------------------------------------------------------------------
# Periodic scheduler (system_job)
# ---------------------------------------------------------------------------

try:
    from netbox.jobs import system_job

    @system_job(interval=5)
    class DiscoveryScheduler(JobRunner):
        """
        Runs every 5 minutes. Enqueues DiscoveryJob for any enabled targets
        whose scan_interval has elapsed since last_run.
        """

        class Meta:
            name = "Discovery Scheduler"

        def run(self, **kwargs):
            from .models import DiscoveryTarget

            now = timezone.now()
            for target in DiscoveryTarget.objects.filter(enabled=True, scan_interval__gt=0):
                if target.last_run is None:
                    due = True
                else:
                    elapsed_minutes = (now - target.last_run).total_seconds() / 60
                    due = elapsed_minutes >= target.scan_interval

                if not due:
                    continue

                # Don't enqueue a second job if one is already queued or running.
                if has_active_discovery(target):
                    logger.info(
                        "Skipping '%s' — a discovery run is already active",
                        target.name,
                    )
                    continue

                logger.info(
                    "Scheduling DiscoveryJob for '%s' (interval=%d min)",
                    target.name,
                    target.scan_interval,
                )
                enqueue_discovery(target)

except ImportError:
    logger.warning(
        "netbox.jobs.system_job not available — periodic scheduling disabled."
    )
