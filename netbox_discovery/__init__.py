from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

from netbox.plugins import PluginConfig

try:
    # Single source of truth is pyproject.toml. Keeping a second literal here
    # meant the two could drift silently.
    __version__ = _dist_version("netbox-discovery")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0.dev0"


class DiscoveryConfig(PluginConfig):
    name = "netbox_discovery"
    verbose_name = "Network Discovery"
    description = "Discovers network devices via CDP/LLDP and NAPALM, syncing facts into NetBox"
    version = __version__
    author = "Billy Allen"
    author_email = "allenbilly1@gmail.com"
    base_url = "discovery"
    min_version = "4.0.0"
    # Bound the upper end so a NetBox major upgrade refuses to load the plugin
    # rather than failing at runtime deep inside a discovery job. Raise this
    # deliberately once tested against the next major.
    max_version = "4.99.99"

    # NOTE: NetBox reads `default_settings` / `required_settings`. These were
    # previously named `default_config` / `required_config`, which NetBox
    # ignores entirely — every value below was dead metadata and each call site
    # carried its own duplicate literal default. Do not rename these back.
    default_settings = {
        "holding_site_name": "Holding",
        "ssh_timeout": 10,
        "encryption_key": "",
        "default_username": "",
        "default_password": "",
        "default_enable_secret": "",
        "conflict_log_path": "/var/log/netbox/discovery_conflicts.log",
        "run_log_path": "/var/log/netbox/discovery_runs.log",
        # Tier 1 — always on by default
        "sync_platform": True,
        "sync_interface_speed": True,
        "sync_fqdn": True,
        "sync_interface_vlans": True,   # bind discovered VLANs to interfaces (access/trunk)
        "create_prefixes": False,       # opt-in (prefix management often manually curated)
        # Opt-in: delete interfaces this plugin created that a device no longer
        # reports. Cabled interfaces and interfaces created by anyone else are
        # never deleted.
        "prune_stale_interfaces": False,
        # Tier 2 — opt-in (new NAPALM calls, extra time per device)
        "collect_vrfs": False,
        "collect_inventory": False,
        "collect_mac_address_table": False,
    }

    # `encryption_key` is deliberately NOT listed here: making it a hard
    # requirement would refuse to start an already-running deployment. It is
    # enforced instead by a Django system check (checks.py) plus a hard failure
    # at the point credentials are actually written — see models.encrypt_value
    # and the form/serializer validation that reports it cleanly.
    required_settings = []

    def ready(self):
        super().ready()

        from django.db.models.signals import post_migrate

        # Importing the jobs module is what registers DiscoveryScheduler with
        # NetBox via @system_job — it is a side-effecting import, not dead code.
        # checks.py likewise registers its system checks on import.
        import netbox_discovery.checks  # noqa: F401
        import netbox_discovery.jobs  # noqa: F401

        # Custom-field creation is deferred to post_migrate so we never touch
        # the DB during app initialisation (which raises a RuntimeWarning and
        # breaks `manage.py migrate` on a fresh database).
        post_migrate.connect(_on_post_migrate, sender=self)


def _on_post_migrate(sender, **kwargs):
    """Called after migrations complete — safe to query the DB here."""
    try:
        _ensure_os_version_custom_field()
    except Exception:
        pass
    try:
        _ensure_fqdn_custom_field()
    except Exception:
        pass


def _ensure_os_version_custom_field():
    from django.contrib.contenttypes.models import ContentType
    from extras.models import CustomField

    # NetBox 4.x uses TYPE_TEXT; fall back gracefully if the choice moves.
    try:
        from extras.choices import CustomFieldTypeChoices
        cf_type = CustomFieldTypeChoices.TYPE_TEXT
    except (ImportError, AttributeError):
        cf_type = "text"

    from dcim.models import Device
    device_ct = ContentType.objects.get_for_model(Device)

    cf, _ = CustomField.objects.get_or_create(
        name="os_version",
        defaults={
            "label": "OS Version",
            "type": cf_type,
            "description": "Device OS version collected by network discovery",
        },
    )
    # Ensure Device is in the field's object_types (ManyToMany)
    if device_ct not in cf.object_types.all():
        cf.object_types.add(device_ct)


def _ensure_fqdn_custom_field():
    from django.contrib.contenttypes.models import ContentType
    from extras.models import CustomField

    try:
        from extras.choices import CustomFieldTypeChoices
        cf_type = CustomFieldTypeChoices.TYPE_TEXT
    except (ImportError, AttributeError):
        cf_type = "text"

    from dcim.models import Device
    device_ct = ContentType.objects.get_for_model(Device)

    cf, _ = CustomField.objects.get_or_create(
        name="fqdn",
        defaults={
            "label": "FQDN",
            "type": cf_type,
            "description": "Fully qualified domain name collected by network discovery",
        },
    )
    if device_ct not in cf.object_types.all():
        cf.object_types.add(device_ct)


config = DiscoveryConfig
