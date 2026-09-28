import threading
import time
import unittest

from tests._loader import load_neighbor


class FakeDevice:
    def close(self):
        pass


class CrawlTests(unittest.TestCase):
    def test_excluded_neighbors_are_never_connected_to(self):
        attempted = []
        lock = threading.Lock()

        def detect(ip, **kwargs):
            with lock:
                attempted.append(ip)
            return FakeDevice(), "ios"

        def collect(device, driver_name, protocol, log_fn, options):
            return {
                "facts": {"hostname": "seed"},
                "neighbors": [
                    {"remote_ip": "10.0.0.2"},
                    {"remote_ip": "10.0.0.5"},  # excluded
                    {"remote_ip": "10.9.9.9"},  # inside an excluded range
                ],
            }

        neighbor = load_neighbor(collect_device_data=collect, detect_and_connect=detect)
        neighbor.crawl(
            seed_ips={"10.0.0.1"},
            username="u",
            password="p",
            max_depth=1,
            max_workers=2,
            log_fn=lambda _msg: None,
            exclusions=["10.0.0.5", "10.9.0.0/16"],
            overall_timeout=10,
        )

        self.assertEqual(sorted(attempted), ["10.0.0.1", "10.0.0.2"])

    def test_workers_stop_after_the_crawl_times_out(self):
        # The poison pills sit behind any remaining work, so without an
        # explicit abort the workers kept connecting to devices after crawl()
        # had already returned and the job had reported its result.
        attempted = []
        lock = threading.Lock()

        def slow_detect(ip, **kwargs):
            with lock:
                attempted.append(ip)
            time.sleep(0.4)
            return None, None

        neighbor = load_neighbor(detect_and_connect=slow_detect)
        summary = neighbor.crawl(
            seed_ips={"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
            username="u",
            password="p",
            max_workers=1,
            log_fn=lambda _msg: None,
            overall_timeout=0.1,
        )
        # Give an unstopped worker time to start the next item.
        time.sleep(1.0)

        self.assertTrue(summary.get("timed_out"))
        self.assertEqual(len(attempted), 1)


if __name__ == "__main__":
    unittest.main()
