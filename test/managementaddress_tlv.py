#!/usr/bin/env python3

import unittest
from lldp.tlv import TLV, ManagementAddressTLV
from ipaddress import ip_address


class ManagementAddressTLVTests(unittest.TestCase):
    def setUp(self):
        self.v4_address = ip_address("192.0.2.17")
        self.v6_address = ip_address("2001:db::4")
        self.ifnum = 5

        # OIDs are represented as ASN.1 encoded byte strings (ISO/IEC 8824-1 or ITU-T X.680).
        # We will only check if the TLV's OID length field corresponds to the given OID byte string.
        self.oid = b"\x2b\x06\x01\x04\x01\x82\x37\x15\x14"  # 1.3.6.1.4.1.311.21.20

        self.tlv4 = ManagementAddressTLV(address=self.v4_address, interface_number=self.ifnum, oid=self.oid)
        self.tlv6 = ManagementAddressTLV(address=self.v6_address, interface_number=self.ifnum, oid=self.oid)

        self.assertIsInstance(self.tlv4.__len__(), int)
        self.assertIsInstance(self.tlv4.__bytes__(), bytes)
        self.assertIsInstance(self.tlv6.__len__(), int)
        self.assertIsInstance(self.tlv6.__bytes__(), bytes)

    def test_type(self):
        self.assertEqual(self.tlv4.type, TLV.Type.MANAGEMENT_ADDRESS)
        self.assertEqual(self.tlv6.type, TLV.Type.MANAGEMENT_ADDRESS)

    def test_length_v4(self):
        self.assertEqual(len(self.tlv4), 12 + len(self.oid) if self.oid is not None else 0)

    def test_length_v6(self):
        self.assertEqual(len(self.tlv6), 24 + len(self.oid) if self.oid is not None else 0)

    def test_value(self):
        self.assertEqual(self.tlv4.value, self.v4_address)
        self.assertEqual(self.tlv6.value, self.v6_address)

    def test_oid(self):
        self.assertEqual(self.tlv4.oid, self.oid)

    def test_none_oid(self):
        tlv = ManagementAddressTLV(address=self.v4_address, interface_number=self.ifnum)
        self.assertEqual(tlv.oid, None)

    def test_dump_v4(self):
        address_bytes = self.v4_address.packed
        overall_len = (12 + len(self.oid)).to_bytes(1, 'big')

        self.assertEqual(bytes(self.tlv4),
                         b"\x10" + overall_len +
                         b"\x05\x01" + address_bytes +
                         b"\x01" + self.ifnum.to_bytes(4, 'big') +
                         (len(self.oid).to_bytes(1, 'big') if self.oid is not None else b"\x00") +
                         (self.oid if self.oid is not None else b""))

    def test_dump_v6(self):
        address_bytes = self.v6_address.packed
        overall_len = (24 + len(self.oid)).to_bytes(1, 'big')

        self.assertEqual(bytes(self.tlv6),
                         b"\x10" + overall_len +
                         b"\x11\x02" + address_bytes +
                         b"\x01" + self.ifnum.to_bytes(4, 'big') +
                         (len(self.oid).to_bytes(1, 'big') if self.oid is not None else b"\x00") +
                         (self.oid if self.oid is not None else b""))

    def test_dump_zero_oid(self):
        tlv = ManagementAddressTLV(address="192.0.2.42", interface_number=1, oid=None,
                                   ifsubtype=ManagementAddressTLV.IFNumberingSubtype.SYSTEM_PORT)
        self.assertEqual(bytes(tlv), b"\x10\x0C\x05\x01\xC0\x00\x02*\x03\x00\x00\x00\x01\x00")

    def test_load_v4(self):
        tlv = ManagementAddressTLV.from_bytes(b"\x10\x0D\x05\x01\xC0\x00\x02*\x02\x00\x00\x00\x01\x01\x0A")
        self.assertEqual(tlv.type, TLV.Type.MANAGEMENT_ADDRESS)
        self.assertEqual(tlv.subtype, ManagementAddressTLV.IFNumberingSubtype.IF_INDEX)
        self.assertEqual(tlv.value, ip_address("192.0.2.42"))
        self.assertEqual(tlv.oid, b"\x0A")

    def test_load_v6(self):
        tlv = ManagementAddressTLV.from_bytes(
            b"\x10\x19\x11\x02 \x01\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B\x02\x00\x00\x00\x01\x01\x0A"
        )
        self.assertEqual(tlv.type, TLV.Type.MANAGEMENT_ADDRESS)
        self.assertEqual(tlv.subtype, ManagementAddressTLV.IFNumberingSubtype.IF_INDEX)
        self.assertEqual(tlv.value, ip_address("2001:db::42"))
        self.assertEqual(tlv.oid, b"\x0A")

    def test_load_zero_oid(self):
        tlv = ManagementAddressTLV.from_bytes(b"\x10\x0C\x05\x01\xC0\x00\x02*\x03\x00\x00\x00\x01\x00")
        self.assertEqual(tlv.oid, None)
