#!/usr/bin/env python3

import unittest
from lldp.tlv import TLV, SystemDescriptionTLV


class SystemDescriptionTLVTests(unittest.TestCase):
    def setUp(self):
        self.tlv = SystemDescriptionTLV("Unittest")
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertIsInstance(self.tlv.__len__(), int)

    def test_systemdescription_type(self):
        self.assertEqual(self.tlv.type, TLV.Type.SYSTEM_DESCRIPTION)

    def test_systemdescription_length(self):
        self.assertIsInstance(self.tlv.__len__(), int)
        self.assertEqual(len(self.tlv), 8)

    def test_systemdescription_value(self):
        self.assertEqual(self.tlv.value, "Unittest")

    def test_systemdescription_subtype(self):
        # SystemDescription TLVs don't have a subtype
        self.assertEqual(self.tlv.subtype, None)

    def test_systemdescription_dump(self):
        self.assertEqual(bytes(self.tlv), b"\x0C\x08Unittest")

    def test_systemdescription_load(self):
        tlv = SystemDescriptionTLV.from_bytes(b"\x0C\x12YetAnotherUnittest")
        self.assertEqual(len(tlv), 18)
        self.assertEqual(tlv.value, "YetAnotherUnittest")
