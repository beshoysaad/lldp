#!/usr/bin/env python3

import unittest
from lldp.tlv import TLV, PortDescriptionTLV


class PortDescriptionTLVTests(unittest.TestCase):
    def setUp(self):
        self.tlv = PortDescriptionTLV("Unittest")
        
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertIsInstance(self.tlv.__len__(), int)

    def test_portdescription_type(self):
        self.assertEqual(self.tlv.type, TLV.Type.PORT_DESCRIPTION)

    def test_portdescription_length(self):
        self.assertEqual(len(self.tlv), 8)

    def test_portdescription_value(self):
        self.assertEqual(self.tlv.value, "Unittest")

    def test_portdescription_subtype(self):
        # PortDescription TLVs don't have a subtype
        self.assertEqual(self.tlv.subtype, None)

    def test_portdescription_dump(self):
        self.assertEqual(bytes(self.tlv), b"\x08\x08Unittest")

    def test_portdescription_load(self):
        tlv = PortDescriptionTLV.from_bytes(b"\x08\x0FAnotherUnittest")
        self.assertEqual(len(tlv), 15)
        self.assertEqual(tlv.value, "AnotherUnittest")
