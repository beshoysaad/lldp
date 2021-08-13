#!/usr/bin/env python3

import unittest
from lldp.tlv import TLV, SystemNameTLV


class SystemNameTLVTests(unittest.TestCase):
    def setUp(self):
        self.tlv = SystemNameTLV("Unittest")
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertIsInstance(self.tlv.__len__(), int)

    def test_systemname_type(self):
        self.assertEqual(self.tlv.type, TLV.Type.SYSTEM_NAME)

    def test_systemname_length(self):
        self.assertEqual(len(self.tlv), 8)

    def test_systemname_value(self):
        self.assertEqual(self.tlv.value, "Unittest")

    def test_systemname_subtype(self):
        # SystemName TLVs don't have a subtype
        self.assertEqual(self.tlv.subtype, None)

    def test_systemname_dump(self):
        self.assertEqual(bytes(self.tlv), b"\x0A\x08Unittest")

    def test_systemname_load(self):
        tlv = SystemNameTLV.from_bytes(b"\x0A\x14AnotherUnittestAgain")
        self.assertEqual(len(tlv), 20)
        self.assertEqual(tlv.value, "AnotherUnittestAgain")
