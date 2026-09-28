# netbox_discovery/discovery/scanner.py

## Purpose

Host discovery: given a list of IP addresses and CIDR ranges, returns the set of live hosts that are worth trying NAPALM connections on.

---

## scan_targets(target_strings, log_fn) → Set[str]

Main entry point. Called by `jobs.py` before the crawl.

**Logic:**
1. Separate explicit single hosts from CIDR ranges using `_is_single_host()`, which treats IPv4 `/32` and IPv6 `/128` as single hosts. The old check treated every IPv6 range from `/32` to `/127` as one address.
2. Single IPs bypass the scanner entirely and are returned immediately — the user listed them intentionally; NAPALM will report a clean failure if unreachable.
3. CIDR ranges are expanded and scanned with nmap (`_nmap_tcp_scan`). If nmap returns 0 results, falls back to `_tcp_probe`. `_expand_targets()` skips (and logs) any range larger than `MAX_RANGE_ADDRESSES` (65,536, an IPv4 /16), which `DiscoveryTarget.clean()` also enforces at input time.
4. Returns the union of single IPs and scan results.

---

## _nmap_tcp_scan(ips, log_fn) → Set[str]

Uses `python-nmap` to run `--unprivileged -sT -T4 -p {PROBE_PORTS} --open` against the IPs in chunks of 256. Falls back to `_tcp_probe` on any chunk error.

**PROBE_PORTS:** `[22, 23, 80, 443, 8080, 8443]`

## _tcp_probe(ips, log_fn) → Set[str]

Pure-Python fallback. Tries `socket.create_connection` on each probe port for each IP using a `ThreadPoolExecutor(max_workers=50)`.

## _tcp_probe_single(ip) → bool

Tries each `PROBE_PORT` in sequence; returns `True` on first successful connect.

---

## How to Change

- **Add a probe port**: Add it to `PROBE_PORTS`.
- **Change chunk size**: Update `chunk_size = 256` in `_nmap_tcp_scan`.
- **Change nmap arguments**: Edit the `arguments=` string in `nm.scan(...)`. Note: `--unprivileged` is required to avoid needing root.
- **Change TCP probe concurrency**: Adjust `max_workers=50` in `_tcp_probe`.
