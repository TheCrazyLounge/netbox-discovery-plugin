import logging

import netaddr
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel
from netbox.models.features import JobsMixin

from .choices import (
    DiscoveryProtocolChoices,
    DiscoveryRunStatusChoices,
    NapalmDriverChoices,
)
from .config import get_setting
from .discovery.scanner import MAX_RANGE_ADDRESSES

logger = logging.getLogger("netbox.plugins.netbox_discovery")

# Every Fernet token starts with this (base64 of version byte 0x80 plus the
# high bytes of the timestamp). It distinguishes a stored ciphertext from a
# legacy plaintext value written before an encryption key was configured.
FERNET_TOKEN_PREFIX = "gAAAAA"

ENCRYPTION_KEY_HELP = (
    "Set PLUGINS_CONFIG['netbox_discovery']['encryption_key'] to a key generated with "
    "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"`."
)


def get_encryption_key_status() -> str:
    """Return "ok", "missing" or "invalid" for the configured encryption_key."""
    key = get_setting("encryption_key")
    if not key:
        return "missing"
    try:
        from cryptography.fernet import Fernet

        Fernet(key.encode() if isinstance(key, str) else key)
    except (TypeError, ValueError):
        return "invalid"
    return "ok"


def _get_fernet():
    """Return a Fernet instance for the configured key, or None if unusable."""
    if get_encryption_key_status() != "ok":
        return None
    from cryptography.fernet import Fernet

    key = get_setting("encryption_key")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encryption_available() -> bool:
    """True when credentials can be encrypted before they are stored."""
    return _get_fernet() is not None


def encrypt_value(raw: str) -> str:
    """
    Encrypt a credential for storage.

    Raises ImproperlyConfigured when there is no usable key. This used to fall
    back to storing the plaintext silently whenever the key was missing or
    malformed, which nobody would notice until the database leaked.
    """
    if not raw:
        return raw
    f = _get_fernet()
    if f is None:
        raise ImproperlyConfigured(
            f"Refusing to store a credential unencrypted: the encryption key is "
            f"{get_encryption_key_status()}. {ENCRYPTION_KEY_HELP}"
        )
    return f.encrypt(raw.encode()).decode()


def decrypt_value(stored: str) -> str:
    """
    Decrypt a stored credential.

    Legacy plaintext values (stored before a key was configured) are
    returned unchanged. A value that is a Fernet token but cannot be
    decrypted — the key was removed or rotated — returns "" and logs an
    error. It used to be returned as-is, so the ciphertext was sent to
    devices as the SSH password.
    """
    if not stored:
        return stored
    is_token = stored.startswith(FERNET_TOKEN_PREFIX)
    f = _get_fernet()
    if f is None:
        if is_token:
            logger.error(
                "A stored credential is encrypted but no valid encryption_key is configured; "
                "treating it as unset."
            )
            return ""
        return stored
    try:
        from cryptography.fernet import InvalidToken

        return f.decrypt(stored.encode()).decode()
    except InvalidToken:
        if is_token:
            logger.error(
                "A stored credential could not be decrypted with the configured encryption_key "
                "(was the key changed?); treating it as unset."
            )
            return ""
        return stored


def validate_ip_lines(value: str, max_addresses=None) -> list:
    """
    Return error messages for the lines of *value* that are not a valid IP or
    CIDR, or that expand to more than *max_addresses* addresses.
    """
    errors = []
    for line in (value or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            network = netaddr.IPNetwork(line)
        except (netaddr.AddrFormatError, ValueError, TypeError):
            errors.append(f"'{line}' is not a valid IP address or CIDR range.")
            continue
        if max_addresses is not None and network.size > max_addresses:
            errors.append(
                f"'{line}' contains {network.size:,} addresses; the limit per line is "
                f"{max_addresses:,} (an IPv4 /16). Split it into smaller ranges."
            )
    return errors


class DiscoveryTarget(JobsMixin, NetBoxModel):
    """
    Defines a set of seed IPs / CIDRs to discover, along with credentials
    and scheduling configuration.

    JobsMixin is required so DiscoveryJob.enqueue(instance=target) can bind
    the NetBox Job row to this object. Without it, Job.full_clean() rejects
    the enqueue with "Jobs cannot be assigned to this object type".
    """

    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=500, blank=True)
    targets = models.TextField(
        help_text=(
            "One IP address or CIDR range per line. "
            "Example: 10.0.0.1 or 192.168.1.0/24"
        )
    )
    exclusions = models.TextField(
        blank=True,
        help_text=(
            "IPs or CIDR ranges to exclude from scanning, one per line. "
            "Example: 10.0.0.5 or 192.168.1.0/28"
        ),
    )

    # Credentials (optional — falls back to PLUGINS_CONFIG defaults)
    credential_username = models.CharField(
        max_length=100,
        blank=True,
        help_text="SSH username. Leave blank to use global default.",
    )
    _credential_password = models.CharField(
        max_length=512,
        blank=True,
        db_column="credential_password",
    )
    _enable_secret = models.CharField(
        max_length=512,
        blank=True,
        db_column="enable_secret",
    )

    # NAPALM settings
    napalm_driver = models.CharField(
        max_length=20,
        choices=NapalmDriverChoices.choices,
        default=NapalmDriverChoices.AUTO,
    )

    # Discovery settings
    discovery_protocol = models.CharField(
        max_length=10,
        choices=DiscoveryProtocolChoices.choices,
        default=DiscoveryProtocolChoices.BOTH,
    )
    # Bounds are enforced on the model, not just as HTML widget hints, so they
    # also apply to the REST API. Each crawl worker is a thread plus its own
    # PostgreSQL connection, so an unbounded max_workers could exhaust the
    # database's connection limit.
    max_depth = models.PositiveIntegerField(
        default=3,
        validators=[MaxValueValidator(10)],
        help_text="Maximum CDP/LLDP neighbor recursion depth.",
    )
    ssh_timeout = models.PositiveIntegerField(
        default=10,
        validators=[MinValueValidator(1), MaxValueValidator(120)],
        help_text="SSH connection timeout in seconds.",
    )
    max_workers = models.PositiveIntegerField(
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(50)],
        help_text="Number of devices to crawl in parallel. Increase for faster discovery on large networks.",
    )

    # Scheduling
    scan_interval = models.PositiveIntegerField(
        default=0,
        help_text="Auto-run interval in minutes. Set to 0 to disable scheduled runs.",
    )
    enabled = models.BooleanField(
        default=True,
        help_text="Enable or disable scheduled runs for this target.",
    )
    last_run = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Discovery Target"
        verbose_name_plural = "Discovery Targets"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_discovery:discoverytarget", args=[self.pk])

    def clean(self):
        """
        Validate the target and exclusion lists.

        Lives on the model rather than the form so the REST API, which runs
        full_clean() but never touches the form, is held to the same rules.
        """
        super().clean()
        errors = {}
        target_errors = validate_ip_lines(self.targets, max_addresses=MAX_RANGE_ADDRESSES)
        if target_errors:
            errors["targets"] = target_errors
        exclusion_errors = validate_ip_lines(self.exclusions)
        if exclusion_errors:
            errors["exclusions"] = exclusion_errors
        if errors:
            raise ValidationError(errors)

    def serialize_object(self, *args, **kwargs):
        """
        Serialize for the changelog with the credential columns removed.

        Every save of a NetBoxModel writes prechange/postchange JSON into
        core.ObjectChange, which is retained long-term and readable by anyone
        with changelog view permission.

        NetBox's own serialize_object() drops keys beginning with an
        underscore, which is very likely why these fields were named
        _credential_password / _enable_secret with explicit db_column
        overrides. That behaviour is an undocumented implementation detail
        though, and it is the only thing standing between a stored SSH
        password and the changelog. Strip them explicitly so the guarantee
        holds regardless of NetBox version.

        Both the attribute names and the db_column names are removed, since
        which one appears depends on the serializer NetBox uses. Signature is
        *args/**kwargs because the `exclude` parameter was added mid-4.x.
        """
        data = super().serialize_object(*args, **kwargs)
        if isinstance(data, dict):
            for key in (
                "_credential_password",
                "_enable_secret",
                "credential_password",
                "enable_secret",
            ):
                data.pop(key, None)
        return data

    # Password property accessors
    @property
    def credential_password(self):
        return decrypt_value(self._credential_password)

    @credential_password.setter
    def credential_password(self, raw):
        self._credential_password = encrypt_value(raw)

    @property
    def enable_secret(self):
        return decrypt_value(self._enable_secret)

    @enable_secret.setter
    def enable_secret(self, raw):
        self._enable_secret = encrypt_value(raw)

    @property
    def has_password(self):
        """Template-safe check for whether a per-target password is stored."""
        return bool(self._credential_password)

    @property
    def has_enable_secret(self):
        """Template-safe check for whether a per-target enable secret is stored."""
        return bool(self._enable_secret)

    def get_effective_username(self):
        """Return per-target username or fall back to global config."""
        if self.credential_username:
            return self.credential_username
        return get_setting("default_username")

    def get_effective_password(self):
        """Return per-target password or fall back to global config."""
        pw = self.credential_password
        if pw:
            return pw
        return get_setting("default_password")

    def get_effective_enable_secret(self):
        """Return per-target enable secret or fall back to global config."""
        sec = self.enable_secret
        if sec:
            return sec
        return get_setting("default_enable_secret")

    def get_target_list(self):
        """Return list of non-empty target strings."""
        return [t.strip() for t in self.targets.splitlines() if t.strip()]

    def get_exclusion_list(self):
        """Return list of non-empty exclusion strings."""
        return [e.strip() for e in self.exclusions.splitlines() if e.strip()]


class DiscoveryRun(NetBoxModel):
    """
    Records the outcome of a single discovery execution for a DiscoveryTarget.
    """

    target = models.ForeignKey(
        DiscoveryTarget,
        on_delete=models.CASCADE,
        related_name="runs",
    )
    status = models.CharField(
        max_length=20,
        choices=DiscoveryRunStatusChoices.choices,
        default=DiscoveryRunStatusChoices.PENDING,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Counters
    hosts_scanned = models.IntegerField(default=0)
    devices_created = models.IntegerField(default=0)
    devices_updated = models.IntegerField(default=0)
    cables_created = models.IntegerField(default=0)
    errors = models.IntegerField(default=0)

    # Full log output stored as text
    log = models.TextField(blank=True)

    # Structured per-device results: list of {ip, hostname, status, driver, error}
    device_results = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["-started_at"]
        verbose_name = "Discovery Run"
        verbose_name_plural = "Discovery Runs"

    def __str__(self):
        ts = self.started_at.strftime("%Y-%m-%d %H:%M") if self.started_at else "?"
        return f"{self.target.name} @ {ts}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_discovery:discoveryrun", args=[self.pk])

    def append_log(self, message: str):
        if self.log:
            self.log += f"\n{message}"
        else:
            self.log = message


class MacAddressTableEntry(NetBoxModel):
    """
    A single MAC address learned on a device interface.

    Populated from NAPALM get_mac_address_table(). The set of entries for
    a given device is replaced wholesale on each successful discovery run,
    so this table reflects the device's last reported view of L2 forwarding.
    """

    device = models.ForeignKey(
        "dcim.Device",
        on_delete=models.CASCADE,
        related_name="discovered_mac_entries",
    )
    interface = models.ForeignKey(
        "dcim.Interface",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="discovered_mac_entries",
    )
    interface_name = models.CharField(
        max_length=100,
        help_text="Raw interface name as reported by the device (preserved for unresolved entries).",
    )
    mac_address = models.CharField(max_length=17, db_index=True)
    vlan = models.ForeignKey(
        "ipam.VLAN",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    vlan_vid = models.PositiveSmallIntegerField(null=True, blank=True, db_index=True)
    is_static = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "vlan_vid", "mac_address"]
        verbose_name = "MAC Address Table Entry"
        verbose_name_plural = "MAC Address Table Entries"
        constraints = [
            models.UniqueConstraint(
                fields=["device", "mac_address", "vlan_vid", "interface_name"],
                name="discovery_mac_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["mac_address", "vlan_vid"]),
        ]

    def __str__(self):
        vid = f" vlan {self.vlan_vid}" if self.vlan_vid else ""
        return f"{self.mac_address}{vid} on {self.device}/{self.interface_name}"

    def get_absolute_url(self):
        # MAC table entries are transient and don't have their own detail page —
        # link through to the resolved interface (or the device) instead.
        if self.interface_id:
            return self.interface.get_absolute_url()
        return self.device.get_absolute_url()
