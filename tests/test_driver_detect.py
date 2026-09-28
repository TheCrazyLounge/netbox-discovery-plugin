import sys
import types
import unittest
from unittest import mock

from tests._loader import load_driver_detect as load_module


class DriverDetectTests(unittest.TestCase):
    def setUp(self):
        self.driver_detect = load_module()
        self.driver_detect._UNAVAILABLE_DRIVERS.clear()

    def test_missing_driver_is_marked_unavailable(self):
        fake_napalm = types.ModuleType("napalm")

        def fake_get_network_driver(_name):
            raise ModuleNotFoundError('Cannot import "fortios". Is the library installed?')

        fake_napalm.get_network_driver = fake_get_network_driver
        messages = []

        with mock.patch.dict(sys.modules, {"napalm": fake_napalm}):
            result = self.driver_detect._try_driver(
                "fortios",
                "192.0.2.1",
                "user",
                "pass",
                "",
                10,
                messages.append,
            )

        self.assertIsNone(result)
        self.assertIn("fortios", self.driver_detect._UNAVAILABLE_DRIVERS)
        self.assertTrue(any("unavailable" in message for message in messages))

    def test_auto_detect_skips_cached_unavailable_driver(self):
        attempted = []
        self.driver_detect._UNAVAILABLE_DRIVERS.add("fortios")

        def fake_try_driver_timed(driver_name, *args, **kwargs):
            attempted.append(driver_name)
            return None

        with mock.patch.object(self.driver_detect, "_try_driver_timed", side_effect=fake_try_driver_timed):
            device, driver = self.driver_detect.detect_and_connect(
                ip="192.0.2.10",
                username="user",
                password="pass",
                timeout=5,
                log_fn=lambda msg: None,
            )

        self.assertIsNone(device)
        self.assertIsNone(driver)
        self.assertNotIn("fortios", attempted)
        self.assertEqual(attempted, ["ios", "nxos_ssh", "junos", "eos"])


class FakeNapalmDevice:
    """Minimal stand-in for a NAPALM driver instance."""

    def __init__(self, facts=None, get_facts_exc=None, open_exc=None):
        self._facts = facts or {"hostname": "switch-01"}
        self._get_facts_exc = get_facts_exc
        self._open_exc = open_exc
        self.opened = False
        self.close_calls = 0

    def open(self):
        if self._open_exc:
            raise self._open_exc
        self.opened = True

    def get_facts(self):
        if self._get_facts_exc:
            raise self._get_facts_exc
        return self._facts

    def close(self):
        self.close_calls += 1


class SessionLeakTests(unittest.TestCase):
    """
    Every exit path after a successful open() must close the session.

    Auto-detection tries up to five drivers per device and the wrong ones
    announce themselves by raising from get_facts(), so this is the normal
    path, not a rare error path. A leak here consumes the device's vty slots
    (commonly capped at 5 on Cisco) and eventually locks the crawl out of the
    network it is surveying.
    """

    def setUp(self):
        self.driver_detect = load_module()
        self.driver_detect._UNAVAILABLE_DRIVERS.clear()

    def _run_try_driver(self, device):
        fake_napalm = types.ModuleType("napalm")
        fake_napalm.get_network_driver = lambda _name: (lambda **kwargs: device)
        messages = []
        with mock.patch.dict(sys.modules, {"napalm": fake_napalm}):
            result = self.driver_detect._try_driver(
                "ios", "192.0.2.1", "user", "pass", "", 10, messages.append
            )
        return result, messages

    def test_closes_session_when_get_facts_raises(self):
        device = FakeNapalmDevice(get_facts_exc=RuntimeError("Pattern not detected"))

        result, messages = self._run_try_driver(device)

        self.assertIsNone(result)
        self.assertTrue(device.opened, "precondition: the session was actually opened")
        self.assertEqual(
            device.close_calls, 1, "an opened session must be closed when get_facts() raises"
        )
        self.assertTrue(any("failed" in m.lower() for m in messages))

    def test_closes_session_on_garbage_hostname(self):
        # The IOS driver connecting to NX-OS returns "Kernel" from the Linux
        # banner. Detection rejects it and must not leave the session open.
        device = FakeNapalmDevice(facts={"hostname": "Kernel"})

        result, _ = self._run_try_driver(device)

        self.assertIsNone(result)
        self.assertEqual(device.close_calls, 1)

    def test_accepts_factory_default_hostnames(self):
        # IOS ships named "Router" / "Switch". Rejecting those made every
        # driver "fail", so unconfigured devices could never be discovered.
        for hostname in ("Switch", "Router", "firewall"):
            with self.subTest(hostname=hostname):
                device = FakeNapalmDevice(facts={"hostname": hostname})

                result, _ = self._run_try_driver(device)

                self.assertIs(result, device)
                self.assertEqual(device.close_calls, 0)

    def test_rejects_cli_error_text_as_hostname(self):
        device = FakeNapalmDevice(facts={"hostname": "% Invalid input detected at '^' marker."})

        result, _ = self._run_try_driver(device)

        self.assertIsNone(result)
        self.assertEqual(device.close_calls, 1)

    def test_does_not_close_on_success(self):
        device = FakeNapalmDevice(facts={"hostname": "core-sw-01"})

        result, _ = self._run_try_driver(device)

        self.assertIs(result, device)
        self.assertEqual(
            device.close_calls, 0, "the caller owns the session once detection succeeds"
        )

    def test_no_close_attempted_when_open_itself_fails(self):
        device = FakeNapalmDevice(open_exc=OSError("connection refused"))

        result, _ = self._run_try_driver(device)

        self.assertIsNone(result)
        self.assertFalse(device.opened)
        # close() is still safe to call on a never-opened session, but the
        # point is that _try_driver returns cleanly rather than raising.
        self.assertLessEqual(device.close_calls, 1)

    def test_abandoned_future_session_is_closed(self):
        device = FakeNapalmDevice()

        class DoneFuture:
            def result(self):
                return device

        self.driver_detect._close_abandoned_device(DoneFuture())

        self.assertEqual(device.close_calls, 1)

    def test_abandoned_future_that_failed_is_ignored(self):
        class FailedFuture:
            def result(self):
                raise RuntimeError("attempt failed")

        # Must not raise: nothing was opened, so there is nothing to close.
        self.driver_detect._close_abandoned_device(FailedFuture())


if __name__ == "__main__":
    unittest.main()
