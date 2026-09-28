"""
Shared module loader for the no-Django test harness.

These tests deliberately run without NetBox, Django or a database so they
execute anywhere with just `pip install -e ".[dev]"`. Importing
`netbox_discovery.*` normally would pull in `netbox.models`, so instead each
module under test is loaded directly off disk under a private name, with any
package-level imports it performs stubbed out.

All three test modules previously carried their own near-identical copy of
this shim; it lives here now so the stubbing rules stay consistent.

Anything that genuinely needs the ORM belongs in the Django-based suite, not
here.
"""

import contextlib
import importlib.util
import pathlib
import sys
import types
from unittest import mock

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class FakeIntegrityError(Exception):
    """Stand-in for django.db.IntegrityError."""


class FakeMultipleObjectsReturned(Exception):
    """Stand-in for Model.MultipleObjectsReturned."""


def make_django_db_stub():
    """
    Build a stub `django.db` module.

    netbox_sync.py imports transaction/IntegrityError lazily inside functions
    precisely so this harness can run without Django installed, but the import
    still has to resolve. atomic() is a real context manager so `with
    transaction.atomic():` behaves; the savepoint calls are no-ops that record
    nothing, since these tests assert on behaviour rather than on transaction
    bookkeeping.
    """
    module = types.ModuleType("django.db")

    @contextlib.contextmanager
    def atomic(*args, **kwargs):
        yield

    module.IntegrityError = FakeIntegrityError
    module.transaction = types.SimpleNamespace(
        atomic=atomic,
        savepoint=lambda *a, **k: "savepoint",
        savepoint_rollback=lambda *a, **k: None,
        savepoint_commit=lambda *a, **k: None,
        set_rollback=lambda *a, **k: None,
    )
    module.connection = types.SimpleNamespace(close=lambda: None)
    module.connections = {}
    return module


def load_plugin_module(relative_path, name=None, fake_modules=None):
    """
    Load a single plugin module from disk, bypassing the package __init__.

    Args:
        relative_path: Path to the module relative to the repo root, e.g.
                       "netbox_discovery/discovery/collector.py".
        name: Name to register the loaded module under. Defaults to the file
              stem plus "_under_test" so it can never shadow the real package.
        fake_modules: Optional {import_name: module} injected into sys.modules
                      for the duration of the load, for modules that import
                      from their own package at import time.

    Returns:
        The executed module object.
    """
    path = REPO_ROOT / relative_path
    if not path.exists():
        raise FileNotFoundError(f"Module under test not found: {path}")

    if name is None:
        name = f"{path.stem}_under_test"

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not build an import spec for {path}")
    module = importlib.util.module_from_spec(spec)

    if fake_modules:
        with mock.patch.dict(sys.modules, fake_modules):
            spec.loader.exec_module(module)
    else:
        spec.loader.exec_module(module)
    return module


def make_package_stubs(*names):
    """
    Build empty stub modules for the given dotted import names.

    Convenience for the `fake_modules` argument above, e.g.
    make_package_stubs("netbox_discovery", "netbox_discovery.sync").
    """
    return {name: types.ModuleType(name) for name in names}


def load_naming():
    """Load naming.py (pure Python, no package imports)."""
    return load_plugin_module("netbox_discovery/naming.py", name="naming_under_test")


def _naming_stubs():
    """Package stubs exposing the real naming module as netbox_discovery.naming."""
    stubs = make_package_stubs("netbox_discovery")
    stubs["netbox_discovery.naming"] = load_naming()
    return stubs


def load_netbox_sync():
    """Load sync/netbox_sync.py with its package imports stubbed."""
    stubs = _naming_stubs()
    stubs.update(make_package_stubs(
        "netbox_discovery.sync",
        "netbox_discovery.sync.classify",
    ))
    stubs["netbox_discovery.sync.classify"].classify_device = lambda **kwargs: {}
    return load_plugin_module(
        "netbox_discovery/sync/netbox_sync.py",
        name="netbox_sync_under_test",
        fake_modules=stubs,
    )


def load_collector():
    """Load discovery/collector.py."""
    return load_plugin_module(
        "netbox_discovery/discovery/collector.py",
        name="collector_under_test",
        fake_modules=_naming_stubs(),
    )


def load_driver_detect():
    """Load discovery/driver_detect.py."""
    return load_plugin_module(
        "netbox_discovery/discovery/driver_detect.py", name="driver_detect_under_test"
    )


def load_scanner():
    """Load discovery/scanner.py."""
    return load_plugin_module(
        "netbox_discovery/discovery/scanner.py", name="scanner_under_test"
    )


def load_neighbor(collect_device_data=None, detect_and_connect=None):
    """
    Load discovery/neighbor.py with its sibling imports stubbed.

    neighbor.py uses package-relative imports, so it is registered under its
    real dotted name (giving it a __package__) and the siblings it imports
    are provided through sys.modules: the real scanner, plus stand-ins for
    the collector and driver detection supplied by the caller.
    """
    stubs = make_package_stubs(
        "netbox_discovery",
        "netbox_discovery.discovery",
        "netbox_discovery.discovery.collector",
        "netbox_discovery.discovery.driver_detect",
    )
    stubs["netbox_discovery.discovery.collector"].collect_device_data = (
        collect_device_data or (lambda *a, **k: {})
    )
    stubs["netbox_discovery.discovery.driver_detect"].detect_and_connect = (
        detect_and_connect or (lambda *a, **k: (None, None))
    )
    stubs["netbox_discovery.discovery.scanner"] = load_scanner()
    return load_plugin_module(
        "netbox_discovery/discovery/neighbor.py",
        name="netbox_discovery.discovery.neighbor",
        fake_modules=stubs,
    )
