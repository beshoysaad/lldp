import random
import unittest
from lldp.tlv import TTLTLV, TLV


class TTLTLVTests(unittest.TestCase):
    def setUp(self):
        random.seed()
        self.ttl = random.randrange(65535)
        self.tlv = TTLTLV(self.ttl)
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertIsInstance(self.tlv.__len__(), int)

    def test_type(self):
        self.assertEqual(self.tlv.type, 3)

    def test_length(self):
        self.assertIsInstance(self.tlv.__len__(), int)
        self.assertEqual(len(self.tlv), 2)

    def test_value(self):
        self.assertEqual(self.tlv.value, self.ttl)

    def test_subtype(self):
        # TTL TLVs don't have a subtype
        self.assertEqual(self.tlv.subtype, None)

    def test_invalid_ttl(self):
        with self.assertRaises(ValueError):
            self.tlv = TTLTLV(65539)

    def test_dump(self):
        self.assertEqual(bytes(self.tlv), b"\x06\x02" + self.ttl.to_bytes(2, 'big'))

    def test_load(self):
        tlv = TTLTLV.from_bytes(b"\x06\x02\x00\x78")
        self.assertTrue(hasattr(tlv, 'value'))
        self.assertEqual(tlv.value, 120)

    def test_load_invalid_length(self):
        with self.assertRaises(ValueError):
            self.tlv.from_bytes(b"\x06\x03\x00\x78\x00")

    def test_load_incorrect_length(self):
        with self.assertRaises(ValueError):
            self.tlv.from_bytes(b"\x06\x01\x00\x78")
