#!/usr/bin/env python3

import unittest
from lldp.tlv import EndOfLLDPDUTLV, TLV


class EndOfLLDPDUTLVTests(unittest.TestCase):
    def setUp(self):
        self.tlv = EndOfLLDPDUTLV()

    def test_eolldpdu_type(self):
        self.assertEqual(self.tlv.type, 0)

    def test_eolldpdu_length(self):
        self.assertIsInstance(self.tlv.__len__(), int)
        self.assertEqual(len(self.tlv), 0)

    def test_eolldpdu_value(self):
        # EoLLDPDU TLVs don't have a value
        self.assertEqual(self.tlv.value, None)

    def test_eolldpdu_dump(self):
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertEqual(bytes(self.tlv), b"\x00\x00")

    def test_eolldpdu_load(self):
        tlv = EndOfLLDPDUTLV.from_bytes(b"\x00\x00")
        self.assertTrue(hasattr(tlv, "type"))
        self.assertEqual(tlv.type, TLV.Type.END_OF_LLDPDU)
