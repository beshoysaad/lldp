#!/usr/bin/env python3

import unittest
from lldp.tlv import TLV, OrganizationallySpecificTLV


class OrganizationallySpecificTLVTests(unittest.TestCase):
    def setUp(self):
        self.oui = b"\xAA\xBB\xCC"
        self.subtype = b"\x05"
        self.data = "HURZ!"
        self.tlv = OrganizationallySpecificTLV(oui=self.oui, subtype=self.subtype, value=self.data)

        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertIsInstance(self.tlv.__len__(), int)

    def test_organizationallyspecific_type(self):
        self.assertEqual(self.tlv.type, TLV.Type.ORGANIZATIONALLY_SPECIFIC)

    def test_organizationallyspecific_length(self):
        self.assertEqual(len(self.tlv), len(self.data) + 4)

    def test_organizationallyspecific_value(self):
        self.assertEqual(self.tlv.value, bytes(self.data, "utf8"))

    def test_organizationallyspecific_subtype(self):
        self.assertEqual(self.tlv.subtype, self.subtype)

    def test_organizationallyspecific_dump(self):
        data_bytes = bytes(self.data, 'utf8')
        len_bytes = (len(data_bytes) + 4).to_bytes(1, "big")

        self.assertEqual(bytes(self.tlv), b"\xFE" + len_bytes + self.oui + self.subtype + data_bytes)

    def test_organizationallyspecific_load(self):
        tlv = OrganizationallySpecificTLV.from_bytes(b"\xFE\x1D\xAA\xBB\xCC\x1A0118 999 88199 9119 725 3")
        self.assertEqual(len(tlv), 29)
        self.assertEqual(tlv.value, b"0118 999 88199 9119 725 3")
        self.assertEqual(tlv.oui, b"\xAA\xBB\xCC")
        self.assertEqual(tlv.subtype, b"\x1A")
