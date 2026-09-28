import logging
from collections import defaultdict

from dcim.models import Device
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import ProtectedError
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from netbox.views import generic
from utilities.views import ObjectPermissionRequiredMixin

from .config import get_setting
from .filtersets import (
    DiscoveryRunFilterSet,
    DiscoveryTargetFilterSet,
    MacAddressTableEntryFilterSet,
)
from .forms import (
    DiscoveryRunFilterForm,
    DiscoveryTargetFilterForm,
    DiscoveryTargetForm,
    MacAddressTableEntryFilterForm,
)
from .models import DiscoveryRun, DiscoveryTarget, MacAddressTableEntry
from .sync.netbox_sync import (
    _add_journal_entry,
    _assign_interface_mac,
    _describe_termination,
    _get_cable_endpoints,
    _set_cable_endpoints,
)
from .tables import (
    DiscoveryRunTable,
    DiscoveryTargetTable,
    MacAddressTableEntryTable,
)

logger = logging.getLogger("netbox.plugins.netbox_discovery")


# ---------------------------------------------------------------------------
# Duplicate Devices views
# ---------------------------------------------------------------------------


def _base_name(device_name: str) -> str:
    """Return the short hostname (before first '.'), lowercased."""
    return device_name.split(".")[0].lower() if device_name else ""


class DuplicateDevicesView(LoginRequiredMixin, ObjectPermissionRequiredMixin, View):
    """
    Lists NetBox devices that share the same base hostname but have different
    full names (e.g. router1.emea.bcd.local vs router1.us.bcd.local).

    Uses NetBox's ObjectPermissionRequiredMixin rather than Django's
    PermissionRequiredMixin. NetBox permissions are two-layer: the model-level
    has_perm check plus a queryset.restrict() call that applies the
    ObjectPermission constraints. Django's mixin only does the first, so a user
    whose dcim.view_device grant is scoped to one site could previously see —
    and on the sibling views, delete — every device in the installation.
    """

    queryset = Device.objects.all()
    template_name = "netbox_discovery/duplicate_devices.html"

    def get_required_permission(self):
        return "dcim.view_device"

    def get(self, request):
        # self.queryset — not Device.objects — because has_permission() has
        # replaced it with the restricted version. Querying the manager
        # directly would compute the restriction and then discard it.
        # Step 1: fetch only (pk, name) — minimal memory footprint.
        # Avoids loading full Device objects for every device in NetBox.
        name_data = self.queryset.values_list("pk", "name").order_by("name")
        groups: dict = defaultdict(list)
        for pk, name in name_data:
            key = _base_name(name)
            if key:
                groups[key].append(pk)

        # Step 2: identify groups that have more than one device
        dup_groups = {base: pks for base, pks in groups.items() if len(pks) > 1}

        # Step 3: fetch full objects only for the duplicate devices
        all_dup_pks = [pk for pks in dup_groups.values() for pk in pks]
        device_map = {
            d.pk: d
            for d in self.queryset.filter(pk__in=all_dup_pks).select_related(
                "site", "device_type__manufacturer", "role"
            )
        }

        duplicates = [
            {"base": base, "devices": [device_map[pk] for pk in pks if pk in device_map]}
            for base, pks in sorted(dup_groups.items())
        ]

        paginator = Paginator(duplicates, 25)
        page_number = request.GET.get("page", 1)
        page_obj = paginator.get_page(page_number)

        return render(request, self.template_name, {
            "duplicates": page_obj,
            "duplicate_group_count": len(duplicates),
            "page_obj": page_obj,
            "paginator": paginator,
        })


class MergeDevicesView(LoginRequiredMixin, ObjectPermissionRequiredMixin, View):
    """
    POST: keep one device, copy missing data from the duplicate, then delete it.
    """

    queryset = Device.objects.all()
    # ObjectPermissionRequiredMixin restricts the queryset using the single
    # permission returned by get_required_permission(); anything else the view
    # needs goes here. The previous `permission_required` tuple silently did
    # nothing useful, because the delete half was never enforced against
    # object-level constraints.
    additional_permissions = ("dcim.delete_device",)

    def get_required_permission(self):
        return "dcim.change_device"

    def post(self, request):
        keep_id = request.POST.get("keep_id")
        delete_id = request.POST.get("delete_id")

        if not keep_id or not delete_id or keep_id == delete_id:
            messages.error(request, "Invalid merge request — select two different devices.")
            return redirect("plugins:netbox_discovery:duplicate_devices")

        # Two different actions, so two differently restricted querysets: the
        # keeper is modified, the duplicate is destroyed. A user permitted to
        # change devices at one site must not be able to delete one at another
        # just because it appears in the same duplicate group.
        keeper = get_object_or_404(self.queryset, pk=keep_id)
        duplicate = get_object_or_404(
            Device.objects.restrict(request.user, "delete"), pk=delete_id
        )

        holding_site_name = get_setting("holding_site_name")

        try:
            with transaction.atomic():
                _merge_device_metadata(keeper, duplicate, holding_site_name)
                _merge_device_interfaces(keeper, duplicate)
                _rehome_duplicate_virtual_chassis(keeper, duplicate)
                _adopt_duplicate_primary_ip(keeper, duplicate)

                dup_name = duplicate.name
                duplicate.delete()

                # Inside the transaction: if the journal write fails the merge
                # must not be reported as successful. Previously this ran after
                # the atomic block, so a failure here left the devices merged
                # but unrecorded.
                _add_journal_entry(
                    keeper,
                    f"Discovery duplicate merge: absorbed device '{dup_name}' and "
                    "preserved its interface/IP/connection state where possible.",
                )
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect("plugins:netbox_discovery:duplicate_devices")
        except ProtectedError as exc:
            # A referencing object blocks the delete. Report it instead of
            # returning a 500 — the previous handler only caught ValueError.
            logger.warning("Merge blocked by protected references: %s", exc)
            messages.error(
                request,
                f"Cannot delete '{duplicate.name}': other objects still reference it. "
                "Remove those references and try again.",
            )
            return redirect("plugins:netbox_discovery:duplicate_devices")
        except IntegrityError as exc:
            # The transaction has rolled back, so nothing was changed.
            logger.warning("Merge of %s into %s hit a constraint: %s", duplicate.pk, keeper.pk, exc)
            messages.error(
                request,
                f"Could not merge '{duplicate.name}' into '{keeper.name}': {exc}. "
                "No changes were made.",
            )
            return redirect("plugins:netbox_discovery:duplicate_devices")

        messages.success(
            request,
            f"Merged '{dup_name}' into '{keeper.name}' and deleted the duplicate.",
        )
        return redirect("plugins:netbox_discovery:duplicate_devices")


class DeleteDuplicateDeviceView(LoginRequiredMixin, ObjectPermissionRequiredMixin, View):
    """POST: delete a single device identified as a duplicate."""

    queryset = Device.objects.all()

    def get_required_permission(self):
        return "dcim.delete_device"

    def post(self, request, pk):
        device = get_object_or_404(self.queryset, pk=pk)
        name = device.name
        try:
            device.delete()
        except ProtectedError as exc:
            logger.warning("Delete blocked by protected references: %s", exc)
            messages.error(
                request,
                f"Cannot delete '{name}': other objects still reference it.",
            )
            return redirect("plugins:netbox_discovery:duplicate_devices")

        messages.success(request, f"Device '{name}' deleted.")
        return redirect("plugins:netbox_discovery:duplicate_devices")


def _merge_device_metadata(keeper, duplicate, holding_site_name: str) -> None:
    changed = False

    keeper_on_holding = not keeper.site or keeper.site.name == holding_site_name
    dup_has_real_site = duplicate.site and duplicate.site.name != holding_site_name
    if keeper_on_holding and dup_has_real_site:
        keeper.site = duplicate.site
        changed = True

    if not keeper.serial and duplicate.serial:
        keeper.serial = duplicate.serial
        changed = True

    dup_cf = duplicate.custom_field_data or {}
    keep_cf = dict(keeper.custom_field_data or {})
    if not keep_cf.get("os_version") and dup_cf.get("os_version"):
        keep_cf["os_version"] = dup_cf["os_version"]
        keeper.custom_field_data = keep_cf
        changed = True

    dup_vc = duplicate.virtual_chassis
    if dup_vc and not keeper.virtual_chassis:
        position, priority = duplicate.vc_position, duplicate.vc_priority
        # Release the slot first: (virtual_chassis, vc_position) is unique,
        # and saving the keeper into a position the duplicate still held
        # raised IntegrityError and turned the merge into a 500.
        duplicate.virtual_chassis = None
        duplicate.vc_position = None
        duplicate.vc_priority = None
        duplicate.save()
        keeper.virtual_chassis = dup_vc
        keeper.vc_position = position
        keeper.vc_priority = priority
        if dup_vc.master_id == duplicate.pk:
            dup_vc.master = keeper
            dup_vc.save()
        changed = True

    if changed:
        keeper.save()


def _merge_device_interfaces(keeper, duplicate) -> None:
    from dcim.models import Interface

    iface_ct = ContentType.objects.get_for_model(Interface)
    keeper_interfaces = {
        iface.name.lower(): iface
        for iface in Interface.objects.filter(device=keeper).select_related("lag", "device")
    }
    duplicate_interfaces = list(
        Interface.objects.filter(device=duplicate).select_related("lag", "device")
    )
    interface_map = {}

    for dup_iface in duplicate_interfaces:
        keeper_iface = keeper_interfaces.get(dup_iface.name.lower())
        if keeper_iface is None:
            dup_iface.device = keeper
            dup_iface.save()
            keeper_iface = dup_iface
            keeper_interfaces[keeper_iface.name.lower()] = keeper_iface
            interface_map[dup_iface.pk] = keeper_iface
            continue

        if dup_iface.cable_id and keeper_iface.cable_id and dup_iface.cable_id != keeper_iface.cable_id:
            dup_a, dup_b = _get_cable_endpoints(dup_iface.cable)
            keep_a, keep_b = _get_cable_endpoints(keeper_iface.cable)
            dup_other = dup_b if dup_a and dup_a.pk == dup_iface.pk else dup_a
            keep_other = keep_b if keep_a and keep_a.pk == keeper_iface.pk else keep_a
            if getattr(dup_other, "pk", None) != getattr(keep_other, "pk", None):
                raise ValueError(
                    f"Cannot merge '{duplicate.name}' into '{keeper.name}' automatically: "
                    f"interface '{dup_iface.name}' is connected to both "
                    f"{_describe_termination(dup_other)} and {_describe_termination(keep_other)}. "
                    "Please resolve the connection conflict first."
                )

        _merge_interface_attributes(keeper_iface, dup_iface)
        _move_interface_ips(dup_iface, keeper_iface, iface_ct)
        _move_interface_cable(dup_iface, keeper_iface)
        interface_map[dup_iface.pk] = keeper_iface

    for old_iface_id, new_iface in interface_map.items():
        old_iface = next((iface for iface in duplicate_interfaces if iface.pk == old_iface_id), None)
        old_lag = getattr(old_iface, "lag", None)
        if old_lag is None:
            continue
        mapped_lag = interface_map.get(old_lag.pk)
        if mapped_lag and getattr(new_iface, "lag_id", None) != mapped_lag.pk:
            new_iface.lag = mapped_lag
            new_iface.save()

def _merge_interface_attributes(target_iface, source_iface) -> None:
    changed = False

    if not getattr(target_iface, "description", "") and getattr(source_iface, "description", ""):
        target_iface.description = source_iface.description
        changed = True
    if not getattr(target_iface, "mtu", None) and getattr(source_iface, "mtu", None):
        target_iface.mtu = source_iface.mtu
        changed = True
    # NetBox 4.2+: mac_address is a read-only property over primary_mac_address.
    # Assigning to it raises AttributeError, which aborted the whole merge.
    source_mac = getattr(source_iface, "mac_address", None)
    if not getattr(target_iface, "mac_address", None) and source_mac:
        if _assign_interface_mac(target_iface, str(source_mac)):
            changed = True
    if not getattr(target_iface, "enabled", True) and getattr(source_iface, "enabled", True):
        target_iface.enabled = source_iface.enabled
        changed = True
    if changed:
        target_iface.save()


def _move_interface_ips(source_iface, target_iface, iface_ct) -> None:
    from ipam.models import IPAddress

    for ip_obj in IPAddress.objects.filter(
        assigned_object_type=iface_ct,
        assigned_object_id=source_iface.pk,
    ):
        ip_obj.assigned_object_type = iface_ct
        ip_obj.assigned_object_id = target_iface.pk
        ip_obj.save()


def _move_interface_cable(source_iface, target_iface) -> None:
    cable = getattr(source_iface, "cable", None)
    if cable is None or getattr(target_iface, "cable_id", None) == getattr(source_iface, "cable_id", None):
        return
    if getattr(target_iface, "cable_id", None):
        return

    a_term, b_term = _get_cable_endpoints(cable)
    if a_term is None or b_term is None:
        return

    if a_term.pk == source_iface.pk:
        _set_cable_endpoints(cable, target_iface, b_term)
        moved_peer = b_term
    elif b_term.pk == source_iface.pk:
        _set_cable_endpoints(cable, a_term, target_iface)
        moved_peer = a_term
    else:
        return

    _add_journal_entry(
        cable,
        (
            "Discovery duplicate merge preserved a connection by moving one cable endpoint "
            f"from {_describe_termination(source_iface)} to {_describe_termination(target_iface)} "
            f"while keeping {_describe_termination(moved_peer)} connected."
        ),
    )


def _rehome_duplicate_virtual_chassis(keeper, duplicate) -> None:
    from dcim.models import Device

    dup_vc_fresh = (
        duplicate.virtual_chassis.__class__.objects.filter(pk=duplicate.virtual_chassis_id).first()
        if duplicate.virtual_chassis_id
        else None
    )
    if not dup_vc_fresh:
        return

    if dup_vc_fresh.master_id == duplicate.pk:
        new_master = (
            keeper
            if keeper.virtual_chassis_id == dup_vc_fresh.pk
            else Device.objects.filter(virtual_chassis=dup_vc_fresh)
            .exclude(pk=duplicate.pk)
            .first()
        )
        dup_vc_fresh.master = new_master
        dup_vc_fresh.save()

    duplicate.virtual_chassis = None
    duplicate.vc_position = None
    duplicate.vc_priority = None
    duplicate.save()


def _adopt_duplicate_primary_ip(keeper, duplicate) -> None:
    """
    Move the duplicate's primary/OOB IPs to the keeper where it has none.

    These are one-to-one fields, so the duplicate has to give up an IP before
    the keeper can take it. Assigning it to the keeper first raised
    IntegrityError and turned the merge into a 500.
    """
    adopted = {}
    for field in ("primary_ip4", "primary_ip6", "oob_ip"):
        if not hasattr(duplicate, f"{field}_id"):
            continue  # oob_ip only exists on NetBox 4.1+
        ip = getattr(duplicate, field, None)
        if ip is not None and getattr(keeper, f"{field}_id") is None:
            adopted[field] = ip

    if not adopted:
        return
    for field in adopted:
        setattr(duplicate, field, None)
    duplicate.save()
    for field, ip in adopted.items():
        setattr(keeper, field, ip)
    keeper.save()


# ---------------------------------------------------------------------------
# DiscoveryTarget views
# ---------------------------------------------------------------------------


class DiscoveryTargetBulkDeleteView(generic.BulkDeleteView):
    queryset = DiscoveryTarget.objects.all()
    filterset = DiscoveryTargetFilterSet
    table = DiscoveryTargetTable
    default_return_url = "plugins:netbox_discovery:discoverytarget_list"


class DiscoveryTargetListView(generic.ObjectListView):
    queryset = DiscoveryTarget.objects.all()
    table = DiscoveryTargetTable
    filterset = DiscoveryTargetFilterSet
    filterset_form = DiscoveryTargetFilterForm
    template_name = "netbox_discovery/discoverytarget_list.html"
    bulk_delete_url = "plugins:netbox_discovery:discoverytarget_bulk_delete"


class DiscoveryTargetView(generic.ObjectView):
    queryset = DiscoveryTarget.objects.prefetch_related("runs")
    template_name = "netbox_discovery/discoverytarget.html"

    def get_extra_context(self, request, instance):
        recent_runs = list(instance.runs.order_by("-started_at")[:10])
        run_table = DiscoveryRunTable(recent_runs)
        return {
            "recent_runs_table": run_table,
        }


class DiscoveryTargetEditView(generic.ObjectEditView):
    queryset = DiscoveryTarget.objects.all()
    form = DiscoveryTargetForm
    template_name = "netbox_discovery/discoverytarget_edit.html"


class DiscoveryTargetDeleteView(generic.ObjectDeleteView):
    queryset = DiscoveryTarget.objects.all()
    default_return_url = "plugins:netbox_discovery:discoverytarget_list"


# ---------------------------------------------------------------------------
# Run Now action view
# ---------------------------------------------------------------------------


class DiscoveryTargetRunView(LoginRequiredMixin, ObjectPermissionRequiredMixin, View):
    """
    POST-only view that enqueues a DiscoveryJob for the given target and
    redirects back to the target detail page.

    Requires change permission on the target: this triggers an SSH crawl of
    the network using stored credentials, so it must not be reachable by any
    user who merely has view access.
    """

    queryset = DiscoveryTarget.objects.all()

    def get_required_permission(self):
        return "netbox_discovery.change_discoverytarget"

    def post(self, request, pk):
        target = get_object_or_404(self.queryset, pk=pk)

        if not target.enabled:
            messages.warning(
                request,
                f"Target '{target.name}' is disabled. Enable it before running.",
            )
            return redirect(target.get_absolute_url())

        if not target.get_effective_username() or not target.get_effective_password():
            messages.error(
                request,
                f"Target '{target.name}' has no credentials configured. "
                "Please set a username/password or configure global defaults in PLUGINS_CONFIG.",
            )
            return redirect(target.get_absolute_url())

        from .jobs import enqueue_discovery, has_active_discovery

        if has_active_discovery(target):
            messages.warning(
                request,
                f"Discovery is already queued or running for '{target.name}'. "
                "Wait for it to finish before starting another.",
            )
            return redirect(target.get_absolute_url())

        try:
            enqueue_discovery(target)
            messages.success(
                request,
                f"Discovery job enqueued for '{target.name}'. "
                "Check Run History for progress.",
            )
        except Exception as exc:
            logger.exception("Failed to enqueue DiscoveryJob for target %s", target.pk)
            messages.error(request, f"Failed to enqueue job: {exc}")

        return redirect(target.get_absolute_url())

    def get(self, request, pk):
        # GET: redirect to the target page with a confirmation prompt via the
        # template. self.queryset is the permission-restricted queryset, so a
        # user cannot probe for targets they may not see.
        target = get_object_or_404(self.queryset, pk=pk)
        return redirect(target.get_absolute_url())


# ---------------------------------------------------------------------------
# DiscoveryRun views
# ---------------------------------------------------------------------------


class DiscoveryRunDeleteView(generic.ObjectDeleteView):
    queryset = DiscoveryRun.objects.all()
    default_return_url = "plugins:netbox_discovery:discoveryrun_list"


class DiscoveryRunBulkDeleteView(generic.BulkDeleteView):
    queryset = DiscoveryRun.objects.select_related("target")
    filterset = DiscoveryRunFilterSet
    table = DiscoveryRunTable
    default_return_url = "plugins:netbox_discovery:discoveryrun_list"


class DiscoveryRunListView(generic.ObjectListView):
    queryset = DiscoveryRun.objects.select_related("target").order_by("-started_at")
    table = DiscoveryRunTable
    filterset = DiscoveryRunFilterSet
    filterset_form = DiscoveryRunFilterForm
    template_name = "netbox_discovery/discoveryrun_list.html"
    bulk_delete_url = "plugins:netbox_discovery:discoveryrun_bulk_delete"


class DiscoveryRunView(generic.ObjectView):
    queryset = DiscoveryRun.objects.select_related("target")
    template_name = "netbox_discovery/discoveryrun.html"

    def get_extra_context(self, request, instance):
        log_lines = instance.log.splitlines() if instance.log else []
        results = instance.device_results or []
        return {
            "log_lines": log_lines,
            "results_created": [r for r in results if r.get("status") == "created"],
            "results_updated": [r for r in results if r.get("status") == "updated"],
            "results_failed": [r for r in results if r.get("status") == "failed"],
        }


# ---------------------------------------------------------------------------
# MAC address table views
# ---------------------------------------------------------------------------


class MacAddressTableEntryListView(generic.ObjectListView):
    queryset = (
        MacAddressTableEntry.objects.select_related("device", "interface", "vlan")
        .order_by("device__name", "vlan_vid", "mac_address")
    )
    table = MacAddressTableEntryTable
    filterset = MacAddressTableEntryFilterSet
    filterset_form = MacAddressTableEntryFilterForm
    template_name = "netbox_discovery/macaddresstableentry_list.html"
    actions = {}
