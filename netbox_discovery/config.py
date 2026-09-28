"""
Single accessor for plugin configuration.

NetBox merges ``DiscoveryConfig.default_settings`` into
``settings.PLUGINS_CONFIG['netbox_discovery']`` at startup, so call sites must
NOT carry their own literal defaults — that is how the two copies drifted while
the settings dict was misnamed ``default_config`` and silently ignored.

Read every plugin setting through :func:`get_setting`.
"""

from django.conf import settings as django_settings

PLUGIN_NAME = "netbox_discovery"

#: Sentinel distinguishing "caller passed no default" from "caller passed None".
_UNSET = object()


def get_plugin_config() -> dict:
    """Return this plugin's merged configuration dict."""
    return django_settings.PLUGINS_CONFIG.get(PLUGIN_NAME, {}) or {}


def get_setting(key: str, default=_UNSET):
    """
    Return a plugin setting.

    Values come from ``default_settings`` unless the user overrode them in
    ``PLUGINS_CONFIG``. A ``default`` is only needed for keys that are not
    declared in ``default_settings``; passing one for a declared key
    reintroduces the drift this module exists to prevent.
    """
    config = get_plugin_config()
    if key in config:
        return config[key]
    if default is _UNSET:
        raise KeyError(
            f"Plugin setting '{key}' is not defined. Add it to "
            f"DiscoveryConfig.default_settings in netbox_discovery/__init__.py."
        )
    return default


def get_discovery_options() -> dict:
    """
    Build the options dict handed to the collector and the sync layer.

    Every collector/sync feature flag must appear here — a key missing from
    this dict is silently unreachable no matter what the user configures.
    """
    return {
        "sync_platform": get_setting("sync_platform"),
        "sync_interface_speed": get_setting("sync_interface_speed"),
        "sync_fqdn": get_setting("sync_fqdn"),
        "sync_interface_vlans": get_setting("sync_interface_vlans"),
        "prune_stale_interfaces": get_setting("prune_stale_interfaces"),
        "create_prefixes": get_setting("create_prefixes"),
        "collect_vrfs": get_setting("collect_vrfs"),
        "collect_inventory": get_setting("collect_inventory"),
        "collect_mac_address_table": get_setting("collect_mac_address_table"),
    }
