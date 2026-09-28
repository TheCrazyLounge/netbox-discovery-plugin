# netbox_discovery/discovery/driver_detect.py

## Purpose

NAPALM driver auto-detection. Tries each driver in priority order and returns the first one that successfully connects and calls `get_facts()`.

---

## detect_and_connect(ip, username, password, ...) → (device, driver_name)

Main entry point. Returns an open NAPALM driver instance and the driver name string, or `(None, None)` on total failure.

If `preferred_driver != "auto"`, only that driver is attempted. Otherwise, `DETECTION_ORDER` is used.

**DETECTION_ORDER:** `["ios", "nxos_ssh", "junos", "fortios", "eos"]`

EOS is last because the pyeapi HTTP driver produces noisy `ConnectionRefusedError` on non-Arista devices.

---

## _try_driver_timed(driver_name, ip, ...) → device | None

Wrapper that enforces a **hard wall-clock timeout** of `timeout + 2` seconds by running `_try_driver` in a background thread via `ThreadPoolExecutor(max_workers=1)`.

**Why not `with executor:`?**
Using the context manager calls `shutdown(wait=True)` on exit, which blocks until the thread finishes — exactly the 60-second pyeapi hang we're avoiding. Instead, `executor.shutdown(wait=False)` abandons any stuck thread immediately.

---

## _try_driver(driver_name, ip, ...) → device | None

Bare NAPALM connection attempt. Sets `optional_args` for:
- `allow_agent=False`, `look_for_keys=False` — force password auth
- `ssh_config_file=None` — ignore user SSH config
- `ssh_strict=False` — skip strict host key checking
- `disabled_algorithms` — accept legacy RSA ciphers for older IOS
- `secret` — enable password (if provided)
- `read_timeout` — Netmiko per-command read timeout: `max(timeout*3, 60)` for most drivers, `max(timeout*5, 90)` for NX-OS. Prevents "Pattern not detected" errors on devices with large command output (e.g. stacked switches with 100+ interfaces).

After `get_facts()`, `_is_garbage_hostname()` rejects hostnames that show the wrong driver parsed the output: `Kernel`/Linux identifiers, a `^` prefix, an IP-shaped string, or CLI error text such as `% Invalid input`. The session is closed and the next driver is tried. Factory-default names (`Router`, `Switch`, `firewall`) are deliberately accepted. Rejecting them made unconfigured devices impossible to discover, and the sync layer already replaces them with the management IP.

---

## How to Change

- **Add a new driver to auto-detection**: Add it to `DETECTION_ORDER` (position matters — earlier = tried first).
- **Change SSH options**: Edit `optional_args` in `_try_driver`.
- **Change the hard timeout headroom**: Adjust `deadline = timeout + 2`.
- **Add per-driver custom optional_args**: Add a `if driver_name == "eos": optional_args["..."] = ...` block in `_try_driver` before `driver_cls(...)` is called.
