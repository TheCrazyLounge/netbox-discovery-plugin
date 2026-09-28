"""
Interface-name and hostname normalization shared by the collector and sync layers.

Pure Python with no Django or NetBox imports, so the discovery modules can use
it without pulling in the sync layer and the no-Django test harness can load it
directly.
"""

import re

# Cisco-style abbreviations → the full name IOS / IOS-XE / NX-OS itself uses.
# These only appear in abbreviated form in CDP/LLDP output and CLI summaries;
# get_interfaces() already returns full names.
_ABBREVIATIONS = {
    "eth": "Ethernet",
    "et": "Ethernet",
    "gi": "GigabitEthernet",
    "gig": "GigabitEthernet",
    "ge": "GigabitEthernet",
    "fa": "FastEthernet",
    "fe": "FastEthernet",
    "te": "TenGigabitEthernet",
    "ten": "TenGigabitEthernet",
    "fo": "FortyGigabitEthernet",
    "hu": "HundredGigabitEthernet",
    "twe": "TwentyFiveGigE",
    "po": "Port-channel",
    "lo": "Loopback",
    "vl": "Vlan",
}

# The mapping used before the fix above. It also rewrote full names and
# non-Cisco names (mgmt0 → Management0, Junos ae0 → Port-Channel0, lo0 →
# Loopback0, NX-OS port-channel1 → Port-Channel1), so NetBox holds
# interfaces under these names. Kept only so sync can find and rename them.
_LEGACY_PREFIXES = {
    "eth": "Ethernet",
    "et": "Ethernet",
    "gi": "GigabitEthernet",
    "ge": "GigabitEthernet",
    "gigabit": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "fa": "FastEthernet",
    "fe": "FastEthernet",
    "fasteth": "FastEthernet",
    "fastethernet": "FastEthernet",
    "te": "TenGigabitEthernet",
    "tengig": "TenGigabitEthernet",
    "tengige": "TenGigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "fo": "FortyGigabitEthernet",
    "fortygige": "FortyGigabitEthernet",
    "fortygigabitethernet": "FortyGigabitEthernet",
    "hu": "HundredGigabitEthernet",
    "hundredgige": "HundredGigabitEthernet",
    "hundredgigabitethernet": "HundredGigabitEthernet",
    "twe": "TwentyFiveGigE",
    "twentyfivege": "TwentyFiveGigE",
    "twentyfivegigabitethernet": "TwentyFiveGigE",
    "po": "Port-Channel",
    "port-channel": "Port-Channel",
    "ae": "Port-Channel",
    "lo": "Loopback",
    "loopback": "Loopback",
    "mg": "Management",
    "ma": "Management",
    "mgmt": "Management",
    "management": "Management",
    "vlan": "Vlan",
}

_PREFIX_RE = re.compile(r"^([A-Za-z-]+)(.*)$")


def canonical_interface_name(name) -> str:
    """
    Expand a Cisco-style abbreviation (Gi1/0/1, Te1/1/1, Po1, Eth1/1) to its
    full name. Anything else is returned unchanged.

    Only capitalized abbreviations are expanded. Cisco abbreviates as
    "Gi"/"Po"/"Lo", while Junos and Linux name interfaces in lowercase
    ("lo0", "ae0", "eth0"). Expanding those would rename real interfaces.
    """
    if not name:
        return ""
    raw = str(name).strip()
    if not raw:
        return ""

    match = _PREFIX_RE.match(raw)
    if not match or not raw[0].isupper():
        return raw

    prefix, suffix = match.group(1), match.group(2)
    full = _ABBREVIATIONS.get(prefix.lower())
    stripped_suffix = suffix.lstrip()
    if full is None or not stripped_suffix[:1].isdigit():
        return raw
    return f"{full}{stripped_suffix}"


def legacy_canonical_interface_name(name) -> str:
    """Return the name the pre-fix canonicalization produced for *name*."""
    if not name:
        return ""
    raw = str(name).strip()
    match = _PREFIX_RE.match(raw)
    if not match:
        return raw
    full = _LEGACY_PREFIXES.get(match.group(1).lower())
    return f"{full}{match.group(2)}" if full else raw


def interface_name_key(name) -> str:
    """Case- and whitespace-insensitive key for loose interface-name matching."""
    if not name:
        return ""
    return canonical_interface_name(name).lower().replace(" ", "")


_CDP_SERIAL_SUFFIX_RE = re.compile(r"\([^)]*\)\s*$")


def strip_device_id_serial(device_id) -> str:
    """
    Remove the "(serial)" suffix NX-OS appends to CDP Device IDs,
    e.g. "N9K-LEAF1(FDO21120ABC)" → "N9K-LEAF1".
    """
    if not device_id:
        return ""
    return _CDP_SERIAL_SUFFIX_RE.sub("", str(device_id)).strip()


def base_hostname(name) -> str:
    """Return the label before the first '.' (the short hostname), lowercased."""
    return str(name).split(".")[0].lower() if name else ""
