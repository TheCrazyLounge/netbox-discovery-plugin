from django import forms
from netbox.forms import NetBoxModelFilterSetForm, NetBoxModelForm
from utilities.forms.fields import TagFilterField
from utilities.forms.rendering import FieldSet

from .choices import (
    DiscoveryProtocolChoices,
    NapalmDriverChoices,
)
from .models import (
    ENCRYPTION_KEY_HELP,
    DiscoveryRun,
    DiscoveryTarget,
    MacAddressTableEntry,
    encryption_available,
)


class DiscoveryTargetForm(NetBoxModelForm):
    """Form for creating / editing a DiscoveryTarget."""

    # Password fields displayed as password inputs but never pre-populated
    credential_password = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        required=False,
        help_text=(
            "SSH password. Leave blank to keep existing value or use the global default."
        ),
    )
    enable_secret = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        required=False,
        help_text="Enable / privilege-level password (Cisco). Optional.",
    )

    fieldsets = (
        FieldSet("name", "description", "targets", "exclusions", name="Basic"),
        FieldSet(
            "credential_username",
            "credential_password",
            "enable_secret",
            name="Credentials",
        ),
        FieldSet(
            "napalm_driver",
            "discovery_protocol",
            "max_depth",
            "ssh_timeout",
            "max_workers",
            name="Discovery Settings",
        ),
        FieldSet("scan_interval", "enabled", name="Scheduling"),
        FieldSet("tags", name="Tags"),
    )

    class Meta:
        model = DiscoveryTarget
        fields = (
            "name",
            "description",
            "targets",
            "exclusions",
            "credential_username",
            "credential_password",
            "enable_secret",
            "napalm_driver",
            "discovery_protocol",
            "max_depth",
            "ssh_timeout",
            "max_workers",
            "scan_interval",
            "enabled",
            "tags",
        )
        widgets = {
            "targets": forms.Textarea(attrs={"rows": 6, "placeholder": "10.0.0.1\n192.168.1.0/24"}),
            "max_depth": forms.NumberInput(attrs={"min": 0, "max": 10}),
            "ssh_timeout": forms.NumberInput(attrs={"min": 1, "max": 120}),
            "max_workers": forms.NumberInput(attrs={"min": 1, "max": 50}),
            "scan_interval": forms.NumberInput(attrs={"min": 0}),
        }

    # targets/exclusions are validated by DiscoveryTarget.clean(), which
    # ModelForm runs too, so the UI and the REST API apply the same rules.

    def clean(self):
        cleaned = super().clean()
        # Report a missing key as a form error instead of letting
        # encrypt_value() raise ImproperlyConfigured (a 500) on save.
        if not encryption_available():
            for field in ("credential_password", "enable_secret"):
                if cleaned.get(field):
                    self.add_error(
                        field,
                        "Cannot store this secret: no valid encryption_key is configured "
                        "for the plugin. " + ENCRYPTION_KEY_HELP,
                    )
        return cleaned

    def save(self, commit=True):
        instance = super().save(commit=False)

        # Handle password fields: only update if a new value was entered
        new_password = self.cleaned_data.get("credential_password")
        if new_password:
            instance.credential_password = new_password
        elif not instance.pk:
            # New object with no password — store empty
            instance.credential_password = ""

        new_enable = self.cleaned_data.get("enable_secret")
        if new_enable:
            instance.enable_secret = new_enable
        elif not instance.pk:
            instance.enable_secret = ""

        if commit:
            instance.save()
            self.save_m2m()
        return instance


class DiscoveryTargetFilterForm(NetBoxModelFilterSetForm):
    """Filter form for the DiscoveryTarget list view."""

    model = DiscoveryTarget
    tag = TagFilterField(model)

    napalm_driver = forms.ChoiceField(
        choices=[("", "---------")] + NapalmDriverChoices.choices,
        required=False,
    )
    discovery_protocol = forms.ChoiceField(
        choices=[("", "---------")] + DiscoveryProtocolChoices.choices,
        required=False,
    )
    enabled = forms.NullBooleanField(required=False)


class DiscoveryRunFilterForm(NetBoxModelFilterSetForm):
    """Filter form for the DiscoveryRun list view."""

    model = DiscoveryRun
    tag = TagFilterField(model)


class MacAddressTableEntryFilterForm(NetBoxModelFilterSetForm):
    """Filter form for the MAC address table list view."""

    model = MacAddressTableEntry
    tag = TagFilterField(model)

    mac_address = forms.CharField(required=False, label="MAC contains")
    device = forms.CharField(required=False, label="Device contains")
    vlan_vid = forms.IntegerField(required=False, label="VLAN ID")
    is_static = forms.NullBooleanField(required=False, label="Static")
