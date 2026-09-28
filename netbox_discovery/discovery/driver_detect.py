"""
NAPALM driver auto-detection.

Tries each driver in priority order (Cisco IOS/NX-OS first per preference).
Returns the first driver that successfully connects and calls get_facts().

Each attempt is capped at (timeout + 2) seconds using a background thread so
that drivers with their own internal timeouts (e.g. EOS/pyeapi uses the OS
default HTTP socket timeout of 60 s) cannot stall the crawl.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Callable, Optional, Tuple

logger = logging.getLogger("netbox.plugins.netbox_discovery")

# Detection order: Cisco-first per user preference, EOS last since
# pyeapi uses HTTP and produces noisy ConnectionRefusedError on non-Arista devices
DETECTION_ORDER = ["ios", "nxos_ssh", "junos", "fortios", "eos"]

# Hostnames that indicate the wrong driver parsed the device's CLI output.
# For example, the IOS driver connecting to NX-OS returns "Kernel" from the
# Linux kernel banner that NX-OS exposes before the NX-OS prompt.
#
# Deliberately NOT listed: "router" / "switch" / "firewall". Those are real
# factory-default hostnames (IOS ships as "Router" / "Switch"), and rejecting
# them made every driver "fail", so unconfigured devices could never be
# discovered. The sync layer already substitutes the management IP for them.
_GARBAGE_HOSTNAMES = {
    "kernel", "localhost", "linux", "ubuntu", "debian", "centos", "redhat",
}
# CLI error text that some drivers return as the hostname.
_GARBAGE_HOSTNAME_FRAGMENTS = ("% invalid", "% incomplete", "% ambiguous", "invalid input")
_UNAVAILABLE_DRIVERS = set()
_UNAVAILABLE_DRIVERS_LOCK = threading.Lock()


def _is_driver_available(driver_name: str) -> bool:
    with _UNAVAILABLE_DRIVERS_LOCK:
        return driver_name not in _UNAVAILABLE_DRIVERS


def _mark_driver_unavailable(driver_name: str, exc: Exception, log_fn: Callable) -> None:
    with _UNAVAILABLE_DRIVERS_LOCK:
        first_notice = driver_name not in _UNAVAILABLE_DRIVERS
        _UNAVAILABLE_DRIVERS.add(driver_name)

    if first_notice:
        log_fn(
            f"    Driver '{driver_name}' unavailable in this environment: {exc}. "
            "Skipping future attempts."
        )
        logger.warning("NAPALM driver '%s' unavailable: %s", driver_name, exc)


def _looks_like_ip(s: str) -> bool:
    """Return True if s looks like an IPv4 address (four dot-separated octets)."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_garbage_hostname(hostname) -> bool:
    """True when get_facts() returned output a wrong driver misparsed as a hostname."""
    reported = (hostname or "").strip().lower()
    return (
        reported in _GARBAGE_HOSTNAMES
        or reported.startswith("^")
        or _looks_like_ip(reported)
        or any(fragment in reported for fragment in _GARBAGE_HOSTNAME_FRAGMENTS)
    )


def _safe_close(device, driver_name: str = "") -> None:
    """
    Close a NAPALM session, never raising.

    Failing to close is not actionable by the caller — it is already on an
    error path — but it must not be invisible either, since a run that
    silently fails to close sessions will eventually exhaust the device's vty
    limit. Log at debug with the traceback.
    """
    if device is None:
        return
    try:
        device.close()
    except Exception:
        logger.debug(
            "Failed to close NAPALM session (driver=%s)", driver_name or "?", exc_info=True
        )


def _try_driver(
    driver_name: str,
    ip: str,
    username: str,
    password: str,
    enable_secret: str,
    timeout: int,
    log_fn: Callable,
) -> Optional[object]:
    """
    Attempt to connect using the named NAPALM driver.
    Returns the open driver instance on success, None on failure.
    """
    try:
        from napalm import get_network_driver

        driver_cls = get_network_driver(driver_name)

        # optional_args that improve compatibility in lab/production environments
        optional_args = {
            # Disable SSH agent and key-file lookup so password auth is used directly
            "allow_agent": False,
            "look_for_keys": False,
            # Don't load user SSH config (avoids ProxyCommand / IdentityFile issues)
            "ssh_config_file": None,
            # Disable strict host key checking (common in lab environments)
            "ssh_strict": False,
            # Accept legacy ciphers/key-exchange algorithms (needed for older IOS)
            "disabled_algorithms": {
                "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
            },
            # ---- Netmiko read_timeout -------------------------------------------
            # Netmiko's default read_timeout is 10 s, which is far too short for
            # devices that produce large output (e.g. 'show interfaces' on a
            # Catalyst 3850 stack with 144 ports, or 'show ip interface' on a
            # router with many SVIs).  The "Pattern not detected" errors in the
            # logs are Netmiko giving up before the device finishes sending.
            # Scale the read_timeout generously: 3× the SSH timeout (min 60 s)
            # for normal drivers, 5× (min 90 s) for NX-OS which is notoriously
            # slow.  The outer collect_timeout in neighbor.py already caps the
            # total wall-clock time per device so this cannot stall forever.
            "read_timeout": max(timeout * 5, 90) if driver_name == "nxos_ssh"
                            else max(timeout * 3, 60),
        }
        if enable_secret:
            optional_args["secret"] = enable_secret

        device = driver_cls(
            hostname=ip,
            username=username,
            password=password,
            # conn_timeout: how long to wait for the initial TCP/SSH handshake.
            # NX-OS gets extra headroom because SSH negotiation is slow on
            # Nexus 7000 / 9000 with many VDCs / VRFs.
            timeout=max(timeout * 3, 30) if driver_name == "nxos_ssh" else timeout,
            optional_args=optional_args,
        )
        # Once open() succeeds an SSH/HTTP session exists on the device, and
        # from here every exit path except success must close it. get_facts()
        # raising is the NORMAL case during auto-detection — it is how the
        # wrong driver announces itself ("Pattern not detected") — so this path
        # runs constantly, not just on error. Leaking here burned up to 4
        # sessions per device before the right driver was found; Cisco commonly
        # caps concurrent vty at 5, so a crawl could lock itself out of the
        # network it was surveying.
        try:
            device.open()
            facts = device.get_facts()

            # Validate the hostname returned by get_facts(). Some drivers (e.g. IOS)
            # successfully connect to NX-OS devices but misparse the CLI and return
            # garbage like "Kernel". Treat that as a detection failure so we fall
            # through to the correct driver (nxos_ssh).
            if _is_garbage_hostname(facts.get("hostname")):
                log_fn(
                    f"    Driver '{driver_name}' connected but returned garbage hostname "
                    f"'{facts.get('hostname')}' — skipping (likely wrong driver for this OS)"
                )
                _safe_close(device, driver_name)
                return None
        except Exception:
            _safe_close(device, driver_name)
            raise

        return device

    except (ImportError, ModuleNotFoundError) as exc:
        _mark_driver_unavailable(driver_name, exc, log_fn)
        return None

    except Exception as exc:
        # Log at INFO so errors appear in the run log, not just system logger
        log_fn(f"    Driver '{driver_name}' failed: {type(exc).__name__}: {exc}")
        return None


def _try_driver_timed(
    driver_name: str,
    ip: str,
    username: str,
    password: str,
    enable_secret: str,
    timeout: int,
    log_fn: Callable,
) -> Optional[object]:
    """
    Wrapper around _try_driver that enforces a hard wall-clock timeout.

    Some drivers (notably EOS/pyeapi) use HTTP connections whose internal
    timeout ignores the NAPALM `timeout` parameter and falls back to the OS
    default (typically 60 s).  Running the attempt in a thread and joining
    with a deadline prevents a single slow driver from stalling the entire
    discovery job.
    """
    # Wall-clock deadline must cover: TCP connect + SSH handshake + get_facts().
    # get_facts() sends 1-2 CLI commands, each of which may take up to
    # read_timeout seconds.  Add headroom for the connection phase.
    if driver_name == "nxos_ssh":
        deadline = max(timeout * 5, 90) + max(timeout * 3, 30) + 5
    else:
        deadline = max(timeout * 3, 60) + timeout + 5

    # Do NOT use 'with ThreadPoolExecutor(...) as executor:' here.
    # The context manager calls shutdown(wait=True) on __exit__, which blocks
    # until the background thread finishes — exactly the 60-second pyeapi hang
    # we are trying to avoid.  Instead, call shutdown(wait=False) so we
    # abandon any stuck thread and return immediately.
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(
        _try_driver,
        driver_name, ip, username, password, enable_secret, timeout, log_fn,
    )
    try:
        return future.result(timeout=deadline)
    except FuturesTimeoutError:
        log_fn(
            f"    Driver '{driver_name}' killed after {deadline}s "
            f"(internal timeout did not fire in time)"
        )
        # The abandoned attempt may still succeed and hand back an *open*
        # NAPALM session that nobody will ever read or close. Left alone
        # those sessions accumulate on the device — Cisco boxes commonly cap
        # concurrent vty sessions at 5, so repeated runs could lock us out.
        future.add_done_callback(_close_abandoned_device)
        return None
    finally:
        # cancel_futures=True drops queued (not yet started) futures.
        # The already-running thread cannot be cancelled — it will die on its
        # own when pyeapi's socket eventually times out.
        executor.shutdown(wait=False, cancel_futures=True)


def _close_abandoned_device(future):
    """Close a NAPALM session returned by an attempt we already gave up on."""
    try:
        device = future.result()
    except Exception:
        return  # attempt failed; nothing was opened
    if device is None:
        return
    _safe_close(device, "abandoned")
    logger.debug("Closed abandoned NAPALM session that completed after timeout")


def detect_and_connect(
    ip: str,
    username: str,
    password: str,
    enable_secret: str = "",
    timeout: int = 10,
    preferred_driver: str = "auto",
    log_fn: Callable = None,
) -> Tuple[Optional[object], Optional[str]]:
    """
    Attempt to connect to a device using NAPALM.

    Returns:
        Tuple of (open NAPALM driver instance, driver_name) or (None, None).
    """
    if log_fn is None:
        log_fn = lambda msg: logger.info(msg)

    if not username:
        log_fn(f"  [SKIP] No username configured for {ip} — check credentials")
        return None, None

    if preferred_driver and preferred_driver != "auto":
        drivers_to_try = [preferred_driver]
    else:
        drivers_to_try = [driver for driver in DETECTION_ORDER if _is_driver_available(driver)]

    if preferred_driver and preferred_driver != "auto" and not _is_driver_available(preferred_driver):
        log_fn(f"  [SKIP] Driver '{preferred_driver}' is unavailable in this environment")
        return None, None

    if not drivers_to_try:
        log_fn(f"  [FAILED] No usable NAPALM drivers are available for {ip}")
        return None, None

    log_fn(f"  Trying drivers {drivers_to_try} for {ip} (user={username})")

    for driver_name in drivers_to_try:
        device = _try_driver_timed(
            driver_name, ip, username, password, enable_secret, timeout, log_fn
        )
        if device is not None:
            log_fn(f"  [OK] Connected to {ip} via '{driver_name}'")
            return device, driver_name

    log_fn(f"  [FAILED] All drivers exhausted for {ip}")
    return None, None
