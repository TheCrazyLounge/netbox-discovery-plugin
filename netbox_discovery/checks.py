"""
Django system checks for plugin configuration.

Registered by importing this module from DiscoveryConfig.ready(). Surfaces in
`manage.py check` and at every NetBox / rq worker start-up.
"""

from django.core.checks import Tags, Warning, register


@register(Tags.security)
def check_encryption_key(app_configs, **kwargs):
    """
    Warn when stored SSH credentials cannot be encrypted.

    A Warning rather than an Error: an Error would refuse to start an existing
    deployment. Writing a per-target credential without a valid key fails
    loudly instead (see models.encrypt_value).
    """
    from .models import ENCRYPTION_KEY_HELP, get_encryption_key_status

    status = get_encryption_key_status()
    if status == "ok":
        return []
    return [
        Warning(
            f"netbox_discovery encryption_key is {status}; per-target SSH passwords and "
            "enable secrets cannot be saved.",
            hint=ENCRYPTION_KEY_HELP,
            id="netbox_discovery.W001",
        )
    ]
