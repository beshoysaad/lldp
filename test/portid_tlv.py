#!/usr/bin/env python3

import unittest
from ipaddress import ip_address
from lldp.tlv import PortIdTLV


class PortIdTLVTests(unittest.TestCase):
    def setUp(self):
        self.subtype = PortIdTLV.Subtype.LOCAL
        self.value = "Bla bla bla, Mr.Freeman."
        self.tlv = PortIdTLV(subtype=self.subtype, id=self.value)

        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertIsInstance(self.tlv.__len__(), int)

    def test_portid_type(self):
        self.assertEqual(self.tlv.type, 2)

    def test_portid_length(self):
        self.assertEqual(len(self.tlv), len(self.value) + 1)

    def test_portid_value(self):
        self.assertEqual(self.tlv.value, self.value)

    def test_portid_subtype(self):
        self.assertEqual(self.tlv.subtype, self.subtype)

    def test_portid_generic_subtypes(self):
        for mytype in [PortIdTLV.Subtype.INTERFACE_ALIAS,
                       PortIdTLV.Subtype.PORT_COMPONENT,
                       PortIdTLV.Subtype.INTERFACE_NAME,
                       PortIdTLV.Subtype.CIRCUIT_ID,
                       PortIdTLV.Subtype.LOCAL]:
            self.tlv = PortIdTLV(subtype=mytype, id=self.value)
            self.assertEqual(self.tlv.value, self.value)
            self.assertEqual(self.tlv.subtype, mytype)

    def test_portid_generic_subtypes_dump(self):
        for mytype in [PortIdTLV.Subtype.INTERFACE_ALIAS,
                       PortIdTLV.Subtype.PORT_COMPONENT,
                       PortIdTLV.Subtype.INTERFACE_NAME,
                       PortIdTLV.Subtype.CIRCUIT_ID,
                       PortIdTLV.Subtype.LOCAL]:
            self.tlv = PortIdTLV(subtype=mytype, id=self.value)
            self.assertEqual(bytes(self.tlv), b"\x04" + (len(self.value) + 1).to_bytes(1, 'big')
                             + mytype.value.to_bytes(1, 'big') + bytes(self.value, 'utf8'))

    def test_portid_address_subtype_ipv4_dump(self):
        self.tlv = PortIdTLV(subtype=PortIdTLV.Subtype.NETWORK_ADDRESS, id=ip_address("192.0.2.100"))
        self.assertEqual(bytes(self.tlv), b"\x04\x06\x04\x01\xC0\x00\x02\x64")

    def test_portid_address_subtype_ipv6_dump(self):
        self.tlv = PortIdTLV(subtype=PortIdTLV.Subtype.NETWORK_ADDRESS, id=ip_address("20db::1"))
        self.assertEqual(bytes(self.tlv),
                         b"\x04\x12\x04\x02\x20\xDB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")

    def test_load(self):
        tlv = PortIdTLV.from_bytes(b"\x04\x0C\x07Abracadabra")
        self.assertEqual(len(tlv), 12)
        self.assertEqual(tlv.subtype, PortIdTLV.Subtype.LOCAL)
        self.assertEqual(tlv.value, "Abracadabra")

    def test_load_ipv4(self):
        tlv = PortIdTLV.from_bytes(b"\x04\x06\x04\x01\xC0\x02\x00\x01")
        self.assertEqual(len(tlv), 6)
        self.assertEqual(tlv.subtype, PortIdTLV.Subtype.NETWORK_ADDRESS)
        self.assertEqual(tlv.value, ip_address("192.2.0.1"))

    def test_load_invalid_ipv4(self):
        with self.assertRaises(ValueError):
            PortIdTLV.from_bytes(b"\x04\x07\x04\x01\xC0\x02\x00\x01\x99")

    def test_load_ipv6(self):
        tlv = PortIdTLV.from_bytes(b"\x04\x12\x04\x02\x20\x01\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x78")
        self.assertEqual(len(tlv), 18)
        self.assertEqual(tlv.subtype, PortIdTLV.Subtype.NETWORK_ADDRESS)
        self.assertEqual(tlv.value, ip_address("2001:db::78"))

    def test_load_invalid_ipv6(self):
        with self.assertRaises(ValueError):
            PortIdTLV.from_bytes(b"\x04\x06\x04\x02\xC0\x02\x00\x01")
