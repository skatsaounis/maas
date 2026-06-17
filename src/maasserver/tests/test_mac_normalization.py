#  Copyright 2026 Canonical Ltd.  This software is licensed under the
#  GNU Affero General Public License version 3 (see the file LICENSE).

import contextlib
import io

from django.db import connection

from maasserver.enum import INTERFACE_TYPE
from maasserver.mac_normalization import (
    DUPLICATE_MAC_DOC_URL,
    DUPLICATE_MAC_NOTIFICATION_IDENT,
    find_duplicate_mac_addresses,
    print_duplicate_mac_report,
    sync_duplicate_mac_address_notification,
)
from maasserver.models import Notification
from maasserver.models.nodeconfig import NODE_CONFIG_TYPE
from maasserver.testing.factory import factory
from maasserver.testing.testcase import MAASServerTestCase


def _set_raw_mac(interface, mac_address):
    """Store a MAC verbatim, bypassing model normalization on save.

    Uses raw SQL because ``MACAddressField`` normalizes values on every ORM
    write path (including ``QuerySet.update()``), which would otherwise
    prevent the inconsistently formatted duplicates these tests rely on.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE maasserver_interface SET mac_address = %s WHERE id = %s",
            [mac_address, interface.id],
        )


class TestFindDuplicateMacAddresses(MAASServerTestCase):
    def test_returns_empty_when_no_duplicates(self):
        factory.make_Interface(
            INTERFACE_TYPE.PHYSICAL, mac_address="aa:bb:cc:dd:ee:ff"
        )
        self.assertEqual([], find_duplicate_mac_addresses())

    def test_detects_macs_stored_in_different_format(self):
        node = factory.make_Node()
        if1 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node)
        if2 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node)
        _set_raw_mac(if1, "aa:bb:cc:dd:ee:ff")
        _set_raw_mac(if2, "AA:BB:CC:DD:EE:FF")

        self.assertEqual(["aa:bb:cc:dd:ee:ff"], find_duplicate_mac_addresses())

    def test_detects_same_mac_on_different_nodes(self):
        # MAAS forbids the same physical MAC on different nodes, so a pair
        # stored in different formats across nodes bypasses that check and must
        # be reported.
        node1 = factory.make_Node()
        node2 = factory.make_Node()
        if1 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node1)
        if2 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node2)
        _set_raw_mac(if1, "aa:bb:cc:dd:ee:ff")
        _set_raw_mac(if2, "AA:BB:CC:DD:EE:FF")

        self.assertEqual(["aa:bb:cc:dd:ee:ff"], find_duplicate_mac_addresses())

    def test_ignores_same_mac_across_node_configs_of_same_node(self):
        # The same physical MAC may legitimately appear on different
        # node_configs of the same node, so it must not be reported even when
        # the stored values differ in case.
        node = factory.make_Node()
        other_config = factory.make_NodeConfig(
            node=node, name=NODE_CONFIG_TYPE.DEPLOYMENT
        )
        if1 = factory.make_Interface(
            INTERFACE_TYPE.PHYSICAL, node_config=node.current_config
        )
        if2 = factory.make_Interface(
            INTERFACE_TYPE.PHYSICAL, node_config=other_config
        )
        _set_raw_mac(if1, "aa:bb:cc:dd:ee:ff")
        _set_raw_mac(if2, "AA:BB:CC:DD:EE:FF")

        self.assertEqual([], find_duplicate_mac_addresses())

    def test_ignores_bond_sharing_child_mac_address(self):
        # Bonds legitimately reuse a child interface's MAC address; this is a
        # valid use case and must not be reported even when the stored values
        # differ in case.
        node = factory.make_Node()
        parent = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node)
        bond = factory.make_Interface(
            INTERFACE_TYPE.BOND, node=node, parents=[parent]
        )
        _set_raw_mac(parent, "aa:bb:cc:dd:ee:ff")
        _set_raw_mac(bond, "AA:BB:CC:DD:EE:FF")

        self.assertEqual([], find_duplicate_mac_addresses())


class TestPrintDuplicateMacReport(MAASServerTestCase):
    def _run_report(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_duplicate_mac_report()
        return out.getvalue()

    def test_reports_no_duplicates(self):
        factory.make_Interface(
            INTERFACE_TYPE.PHYSICAL, mac_address="aa:bb:cc:dd:ee:ff"
        )
        self.assertIn("No duplicate MAC addresses found.", self._run_report())

    def test_reports_affected_interfaces(self):
        node = factory.make_Node(hostname="webserver-01")
        if1 = factory.make_Interface(
            INTERFACE_TYPE.PHYSICAL, node=node, name="eth1"
        )
        if2 = factory.make_Interface(
            INTERFACE_TYPE.PHYSICAL, node=node, name="eth2"
        )
        _set_raw_mac(if1, "AA:BB:CC:DD:EE:FF")
        _set_raw_mac(if2, "aa:bb:cc:dd:ee:ff")

        output = self._run_report()

        self.assertIn(node.system_id, output)
        self.assertIn("aa:bb:cc:dd:ee:ff", output)
        self.assertIn(f"id={if1.id}", output)
        self.assertIn("stored=AA:BB:CC:DD:EE:FF", output)
        self.assertIn(f"id={if2.id}", output)

    def test_reports_interfaces_across_different_nodes(self):
        node1 = factory.make_Node(hostname="server-a")
        node2 = factory.make_Node(hostname="server-b")
        if1 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node1)
        if2 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node2)
        _set_raw_mac(if1, "aa:bb:cc:dd:ee:ff")
        _set_raw_mac(if2, "AA:BB:CC:DD:EE:FF")

        output = self._run_report()

        self.assertIn(node1.system_id, output)
        self.assertIn(node2.system_id, output)
        self.assertIn("stored=aa:bb:cc:dd:ee:ff", output)
        self.assertIn("stored=AA:BB:CC:DD:EE:FF", output)


class TestSyncDuplicateMacAddressNotification(MAASServerTestCase):
    def test_creates_notification_when_duplicates_exist(self):
        node = factory.make_Node()
        if1 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node)
        if2 = factory.make_Interface(INTERFACE_TYPE.PHYSICAL, node=node)
        _set_raw_mac(if1, "aa:bb:cc:dd:ee:ff")
        _set_raw_mac(if2, "AA:BB:CC:DD:EE:FF")

        sync_duplicate_mac_address_notification()

        notification = Notification.objects.get(
            ident=DUPLICATE_MAC_NOTIFICATION_IDENT
        )
        self.assertEqual("warning", notification.category)
        self.assertTrue(notification.admins)
        self.assertFalse(notification.dismissable)
        self.assertIn(DUPLICATE_MAC_DOC_URL, notification.message)

    def test_clears_notification_when_no_duplicates(self):
        Notification.objects.create_warning_for_admins(
            "stale",
            ident=DUPLICATE_MAC_NOTIFICATION_IDENT,
            dismissable=False,
        )

        sync_duplicate_mac_address_notification()

        self.assertFalse(
            Notification.objects.filter(
                ident=DUPLICATE_MAC_NOTIFICATION_IDENT
            ).exists()
        )
