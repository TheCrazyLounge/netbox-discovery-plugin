"""
Host discovery using python-nmap (TCP connect, no root required) or
a pure-Python TCP probe fallback.
"""

import logging
import socket
import time
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from concurrent.futures import (
    TimeoutError as FuturesTimeoutError,
)
from typing import Callable, List, Set

import netaddr

logger = logging.getLogger("netbox.plugins.netbox_discovery")

# Ports to probe for host-up detection (TCP connect, no root needed)
PROBE_PORTS = [22, 23, 80, 443, 8080, 8443]

# Per-chunk wall-clock ceiling for nmap. python-nmap's scan() is a blocking
# subprocess call with no Python-side timeout: --host-timeout only bounds nmap
# internally, so a wedged nmap binary (DNS, ARP storm, zombie process) hung the
# entire job with no deadline above it.
NMAP_CHUNK_TIMEOUT = 300

# Overall ceiling for the pure-Python probe. 6 ports x 2s per host is ~12s
# worst case; across a large range that is hours if left unbounded.
TCP_PROBE_TIMEOUT = 900

# Largest CIDR range a single target line may expand to (an IPv4 /16).
# DiscoveryTarget.clean() enforces the same limit at input time.
MAX_RANGE_ADDRESSES = 65536


def _is_single_host(network: netaddr.IPNetwork) -> bool:
    """
    True for a /32 (IPv4) or /128 (IPv6).

    The old check tested `prefixlen >= 32` before looking at the address
    family, so every IPv6 range from /32 to /127 was treated as the single
    address it was written with.
    """
    return network.prefixlen == (32 if network.version == 4 else 128)


def _expand_targets(targets: List[str]) -> List[str]:
    """Expand a list of IPs and CIDR strings into individual IP strings."""
    ips = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        try:
            network = netaddr.IPNetwork(target)
            if _is_single_host(network):
                ips.append(str(network.ip))
            elif network.size > MAX_RANGE_ADDRESSES:
                # Expanding e.g. an IPv6 /64 would never finish (and would
                # exhaust memory first). Form/API validation rejects these;
                # this guards rows saved before that validation existed.
                logger.warning(
                    "Skipping target %s: %d addresses exceeds the %d-address limit",
                    target, network.size, MAX_RANGE_ADDRESSES,
                )
            else:
                for host in network.iter_hosts():
                    ips.append(str(host))
        except netaddr.AddrFormatError:
            logger.warning("Invalid target address: %s", target)
    return ips


def _nmap_tcp_scan(ips: List[str], log_fn: Callable) -> Set[str]:
    """
    Use nmap with TCP connect scan — works without root privileges.
    --unprivileged forces non-raw-socket methods.
    """
    try:
        import nmap

        nm = nmap.PortScanner()
        live = set()
        ports = ",".join(str(p) for p in PROBE_PORTS)

        chunk_size = 256
        for i in range(0, len(ips), chunk_size):
            chunk = ips[i : i + chunk_size]
            targets_str = " ".join(chunk)
            log_fn(f"  Scanning chunk {i // chunk_size + 1}: {len(chunk)} addresses")
            try:
                # --unprivileged = no raw sockets needed (works as non-root)
                # -sT = TCP connect scan
                # -T4 = aggressive timing
                # --open = only show open ports
                #
                # Run under a hard wall-clock deadline: nm.scan() itself cannot
                # be interrupted, so a hung nmap would otherwise block forever.
                executor = ThreadPoolExecutor(max_workers=1)
                try:
                    future = executor.submit(
                        nm.scan,
                        hosts=targets_str,
                        arguments=(
                            f"--unprivileged -sT -T4 -p {ports} --open --host-timeout 10s"
                        ),
                    )
                    future.result(timeout=NMAP_CHUNK_TIMEOUT)
                except FuturesTimeoutError:
                    log_fn(
                        f"  [WARN] nmap chunk exceeded {NMAP_CHUNK_TIMEOUT}s — "
                        "abandoning it and falling back to TCP probe"
                    )
                    live |= _tcp_probe(chunk, log_fn)
                    continue
                finally:
                    executor.shutdown(wait=False)

                for host in nm.all_hosts():
                    if nm[host].state() == "up":
                        live.add(host)
                    # Also check: host has at least one open port
                    elif "tcp" in nm[host]:
                        for port_info in nm[host]["tcp"].values():
                            if port_info.get("state") == "open":
                                live.add(host)
                                break
            except Exception as exc:
                log_fn(f"  nmap chunk error: {exc} — falling back to TCP probe for this chunk")
                live |= _tcp_probe(chunk, log_fn)

        return live

    except ImportError:
        logger.warning("python-nmap not installed; using TCP probe")
        return _tcp_probe(ips, log_fn)


def _tcp_probe_single(ip: str) -> bool:
    """Try TCP connect to any of the probe ports. Returns True if host is reachable."""
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=2):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return False


def _tcp_probe(ips: List[str], log_fn: Callable) -> Set[str]:
    """
    Pure-Python TCP connect probe using a thread pool for speed.

    Bounded by TCP_PROBE_TIMEOUT: any host not resolved by the deadline is
    treated as down rather than allowing an unbounded scan to consume the
    job's entire time budget.
    """
    live = set()
    log_fn(f"  TCP probe: checking {len(ips)} addresses (ports {PROBE_PORTS})")
    deadline = time.monotonic() + TCP_PROBE_TIMEOUT
    timed_out = 0

    executor = ThreadPoolExecutor(max_workers=50)
    try:
        future_to_ip = {executor.submit(_tcp_probe_single, ip): ip for ip in ips}
        try:
            for future in as_completed(
                future_to_ip, timeout=max(0.0, deadline - time.monotonic())
            ):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        live.add(ip)
                except Exception:
                    logger.debug("TCP probe failed for %s", ip, exc_info=True)
        except FuturesTimeoutError:
            timed_out = sum(1 for f in future_to_ip if not f.done())
            log_fn(
                f"  [WARN] TCP probe hit its {TCP_PROBE_TIMEOUT}s ceiling — "
                f"{timed_out} address(es) left unchecked and treated as down"
            )
    finally:
        # Don't block on in-flight connects; their sockets carry their own
        # 2s timeout and will retire on their own.
        executor.shutdown(wait=False, cancel_futures=True)

    return live


def _build_exclusion_set(exclusion_strings: List[str]) -> List[netaddr.IPNetwork]:
    """Parse exclusion strings into a list of IPNetwork objects for fast membership testing."""
    networks = []
    for entry in exclusion_strings:
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(netaddr.IPNetwork(entry))
        except netaddr.AddrFormatError:
            logger.warning("Invalid exclusion address: %s", entry)
    return networks


def _is_excluded(ip: str, exclusion_networks: List[netaddr.IPNetwork]) -> bool:
    """Return True if ip falls within any of the exclusion networks."""
    if not exclusion_networks:
        return False
    try:
        addr = netaddr.IPAddress(ip)
        return any(addr in net for net in exclusion_networks)
    except netaddr.AddrFormatError:
        return False


def scan_targets(
    target_strings: List[str],
    exclusion_strings: List[str] = None,
    log_fn: Callable = None,
) -> Set[str]:
    """
    Expand target IPs/CIDRs and scan to find live hosts.

    Individual IPs (/32) specified explicitly always bypass the scanner and
    go straight to the crawl — the user listed them intentionally and NAPALM
    will report a clean failure if they're unreachable.  CIDR ranges are
    scanned first so we don't attempt NAPALM on every address in a /24.

    Args:
        target_strings: List of IP strings or CIDR notations.
        exclusion_strings: Optional list of IPs/CIDRs to exclude from results.
        log_fn: Optional callable for progress messages.

    Returns:
        Set of live IP address strings.
    """
    if log_fn is None:
        log_fn = lambda msg: logger.info(msg)

    exclusion_networks = _build_exclusion_set(exclusion_strings or [])
    if exclusion_networks:
        log_fn(f"Exclusions active: {[str(n) for n in exclusion_networks]}")

    # Separate explicit single IPs from CIDR ranges
    single_ips: Set[str] = set()
    range_targets: List[str] = []

    for target in target_strings:
        target = target.strip()
        if not target:
            continue
        try:
            net = netaddr.IPNetwork(target)
            if _is_single_host(net):
                single_ips.add(str(net.ip))
            else:
                range_targets.append(target)
        except netaddr.AddrFormatError:
            logger.warning("Invalid target address: %s", target)

    # Apply exclusions to explicit single IPs
    excluded_singles = {ip for ip in single_ips if _is_excluded(ip, exclusion_networks)}
    if excluded_singles:
        log_fn(f"Excluding {len(excluded_singles)} individual IP(s): {sorted(excluded_singles)}")
        single_ips -= excluded_singles

    if single_ips:
        log_fn(
            f"{len(single_ips)} individual IP(s) will be tried directly "
            f"(no scan needed): {sorted(single_ips)}"
        )

    live: Set[str] = set(single_ips)

    if range_targets:
        range_ips = _expand_targets(range_targets)
        # Apply exclusions before scanning to avoid probing excluded hosts at all
        if exclusion_networks:
            before = len(range_ips)
            range_ips = [ip for ip in range_ips if not _is_excluded(ip, exclusion_networks)]
            excluded_count = before - len(range_ips)
            if excluded_count:
                log_fn(f"Excluded {excluded_count} IP(s) from CIDR ranges before scanning.")
        log_fn(f"Scanning {len(range_ips)} IPs from {len(range_targets)} CIDR range(s)...")
        if range_ips:
            log_fn(f"Starting host discovery (TCP connect on ports {PROBE_PORTS})...")
            found = _nmap_tcp_scan(range_ips, log_fn)
            if not found:
                log_fn("nmap returned 0 hosts — retrying with pure TCP probe...")
                found = _tcp_probe(range_ips, log_fn)
            live |= found

    log_fn(f"Host discovery complete. Live hosts: {len(live)}")
    return live
