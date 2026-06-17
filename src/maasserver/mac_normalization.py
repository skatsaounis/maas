#  Copyright 2026 Canonical Ltd.  This software is licensed under the
#  GNU Affero General Public License version 3 (see the file LICENSE).

"""Detect MAC addresses that bypass uniqueness because of inconsistent format.

Historically MAAS did not always normalize the MAC addresses of interfaces
before storing them. As a result the same physical MAC could be stored more
than once using a different case (e.g. ``AA:BB:CC:DD:EE:FF`` and
``aa:bb:cc:dd:ee:ff``) and MAAS would treat them as distinct addresses.

Normalization is now applied on every write path, but pre-existing rows cannot
be fixed automatically without a database migration. This module detects such
rows so administrators can be warned to fix them manually.
"""

from collections import defaultdict
from typing import NamedTuple

from maascommon.fields import normalise_macaddress
from maasserver.enum import INTERFACE_TYPE
from maasserver.models import Notification
from maasserver.models.interface import Interface

DUPLICATE_MAC_NOTIFICATION_IDENT = "duplicate_mac_addresses"
DUPLICATE_MAC_DOC_URL = (
    "https://canonical.com/maas/docs/latest/how-to-guides/"
    "resolve-duplicate-mac-addresses"
)


class _InterfaceRow(NamedTuple):
    """A lightweight projection of the interface fields used for detection.

    Avoids materializing full ``Interface``/``NodeConfig``/``Node`` model
    instances, which is significant when scanning every physical interface in
    a large deployment.
    """

    id: int
    name: str
    mac_address: str
    node_config_id: int
    node_id: int
    hostname: str
    system_id: str


def _interfaces_bypassing_uniqueness(interfaces):
    """Return the interfaces that share a MAC in a forbidden, differently
    formatted way.

    MAAS forbids two physical interfaces from sharing a MAC address unless they
    belong to different ``node_config`` of the *same* node (historical
    configurations legitimately repeat the MAC). A pair is therefore forbidden
    when the interfaces are on the same ``node_config`` (enforced by a database
    constraint) or on different nodes (enforced in application code).

    Such forbidden pairs can only exist when the stored values differ in format
    (e.g. ``AA:BB:CC:DD:EE:FF`` and ``aa:bb:cc:dd:ee:ff``), because identical
    values are rejected on write. The returned interfaces are sorted by id.
    """
    flagged = set()
    for index, first in enumerate(interfaces):
        for second in interfaces[index + 1 :]:
            if first.mac_address == second.mac_address:
                # Identical stored values can't bypass any uniqueness check.
                continue
            same_node_config = first.node_config_id == second.node_config_id
            different_node = first.node_id != second.node_id
            if same_node_config or different_node:
                flagged.update((first, second))
    return sorted(flagged, key=lambda interface: interface.id)


def _duplicate_mac_interfaces():
    """Return problematic physical interfaces grouped by normalized MAC.

    Non-physical interfaces such as bonds, bridges and VLANs are excluded
    because they legitimately reuse the MAC address of one of their children.

    For each normalized MAC, only the interfaces that bypass MAC uniqueness
    (see ``_interfaces_bypassing_uniqueness``) are returned. MACs that are used
    consistently, or that only repeat across different ``node_config`` of the
    same node, are omitted.
    """
    interfaces_by_normalized = defaultdict(list)
    rows = (
        Interface.objects.filter(type=INTERFACE_TYPE.PHYSICAL)
        .exclude(mac_address__isnull=True)
        .values_list(
            "id",
            "name",
            "mac_address",
            "node_config_id",
            "node_config__node_id",
            "node_config__node__hostname",
            "node_config__node__system_id",
        )
        .iterator()
    )
    for (
        interface_id,
        name,
        mac_address,
        node_config_id,
        node_id,
        hostname,
        system_id,
    ) in rows:
        if not mac_address:
            continue
        try:
            normalized = normalise_macaddress(mac_address)
        except (ValueError, AttributeError):
            # A malformed value that can't be normalized can't collide with a
            # normalized one either, so it's not relevant to this check.
            continue
        interfaces_by_normalized[normalized].append(
            _InterfaceRow(
                id=interface_id,
                name=name,
                mac_address=mac_address,
                node_config_id=node_config_id,
                node_id=node_id,
                hostname=hostname,
                system_id=system_id,
            )
        )

    duplicates = {}
    for normalized, interfaces in interfaces_by_normalized.items():
        flagged = _interfaces_bypassing_uniqueness(interfaces)
        if flagged:
            duplicates[normalized] = flagged
    return duplicates


def find_duplicate_mac_addresses():
    """Return the normalized MACs that bypass the physical uniqueness check."""
    return sorted(_duplicate_mac_interfaces())


def print_duplicate_mac_report():
    """Print the physical interfaces whose MAC addresses bypass uniqueness.

    Intended to be run from a region controller shell. For each affected MAC
    address it lists the colliding interfaces and the machine they belong to,
    including the value stored in the database, so the duplicates can be
    identified and removed.
    """
    duplicates = _duplicate_mac_interfaces()
    if not duplicates:
        print("No duplicate MAC addresses found.")
        return

    for normalized in sorted(duplicates):
        print(normalized)
        for interface in duplicates[normalized]:
            print(
                f"    {interface.hostname} ({interface.system_id}) "
                f"interface id={interface.id} name={interface.name} "
                f"stored={interface.mac_address}"
            )


def sync_duplicate_mac_address_notification():
    """Create or clear the duplicate MAC address notification for admins."""
    duplicates = find_duplicate_mac_addresses()

    existing = Notification.objects.filter(
        ident=DUPLICATE_MAC_NOTIFICATION_IDENT
    )

    if not duplicates:
        existing.delete()
        return

    message = (
        "%d MAC address(es) are stored in more than one format and are "
        "treated as distinct interfaces by MAAS. Please review the affected "
        "interfaces and update them so each physical MAC address is used "
        "only once."
        "<br><a class='p-link--external' href='%s'>"
        "How to resolve duplicate MAC addresses...</a>"
    ) % (len(duplicates), DUPLICATE_MAC_DOC_URL)

    if existing.exists():
        existing.update(message=message)
    else:
        Notification.objects.create_warning_for_admins(
            message,
            ident=DUPLICATE_MAC_NOTIFICATION_IDENT,
            dismissable=False,
        )
