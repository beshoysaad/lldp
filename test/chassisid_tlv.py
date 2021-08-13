from ipaddress import ip_address
from lldp.tlv import TLV, ChassisIdTLV
import unittest


class ChassisIdTLVTests(unittest.TestCase):
    def setUp(self):
        self.subtype = ChassisIdTLV.Subtype.LOCAL
        self.value = "Terok Nor"
        self.tlv = ChassisIdTLV(subtype=self.subtype, id=self.value)

    def test_chassisid_type(self):
        self.assertEqual(self.tlv.type, TLV.Type.CHASSIS_ID)

    def test_chassisid_length(self):
        self.assertIsInstance(self.tlv.__len__(), int)
        self.assertEqual(len(self.tlv), len(self.value) + 1)

    def test_chassisid_value(self):
        self.assertEqual(self.tlv.value, self.value)

    def test_chassisid_subtype(self):
        self.assertEqual(self.tlv.subtype, self.subtype)

    def test_chassisid_generic_subtypes(self):
        for mytype in [ChassisIdTLV.Subtype.CHASSIS_COMPONENT,
                       ChassisIdTLV.Subtype.INTERFACE_ALIAS,
                       ChassisIdTLV.Subtype.PORT_COMPONENT,
                       ChassisIdTLV.Subtype.INTERFACE_NAME,
                       ChassisIdTLV.Subtype.LOCAL]:
            self.tlv = ChassisIdTLV(subtype=mytype, id=self.value)
            self.assertEqual(self.tlv.subtype, mytype)
            self.assertEqual(self.tlv.value, self.value)

    def test_chassisid_mac_subtype_dump(self):
        tlv = ChassisIdTLV(subtype=ChassisIdTLV.Subtype.MAC_ADDRESS, id=b"\x00\x22\x12\xAA\xBB\xCC")
        self.assertIsInstance(tlv.__bytes__(), bytes)
        self.assertEqual(bytes(tlv), b"\x02\x07\x04\x00\x22\x12\xAA\xBB\xCC")

    def test_chassisid_mac_subtype_load(self):
        tlv = ChassisIdTLV.from_bytes(b"\x02\x07\x04\x00\x22\x12\xAA\xBB\xCC")
        self.assertTrue(hasattr(tlv, "subtype"))
        self.assertEqual(tlv.subtype, ChassisIdTLV.Subtype.MAC_ADDRESS)
        self.assertTrue(hasattr(tlv, "value"))
        self.assertEqual(tlv.value, b"\x00\x22\x12\xAA\xBB\xCC")

    def test_chassisid_mac_subtype_invalid_address(self):
        with self.assertRaises(ValueError):
            ChassisIdTLV(subtype=ChassisIdTLV.Subtype.MAC_ADDRESS, id=b"\xAA\xBB\xCC\xDD\xEE")
            ChassisIdTLV(subtype=ChassisIdTLV.Subtype.MAC_ADDRESS, id=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00")

    def test_chassisid_address_subtype_ipv4_dump(self):
        self.tlv = ChassisIdTLV(subtype=ChassisIdTLV.Subtype.NETWORK_ADDRESS, id=ip_address("192.0.2.100"))
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertEqual(bytes(self.tlv), b"\x02\x06\x05\x01\xc0\x00\x02\x64")

    def test_chassisid_address_subtype_ipv6_dump(self):
        self.tlv = ChassisIdTLV(subtype=ChassisIdTLV.Subtype.NETWORK_ADDRESS,
                                id=ip_address("20db::1"))
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertEqual(bytes(self.tlv),
                         b"\x02\x12\x05\x02\x20\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")

    def test_chassisid_load_generic(self):
        tlv = ChassisIdTLV.from_bytes(b"\x02\x09\x07Unittest")
        self.assertTrue(hasattr(tlv, "subtype"))
        self.assertEqual(tlv.subtype, ChassisIdTLV.Subtype.LOCAL)
        self.assertTrue(hasattr(tlv, "value"))
        self.assertEqual(tlv.value, "Unittest")

    def test_chassisid_load_generic_unicode(self):
        tlv = ChassisIdTLV.from_bytes(b"\x02\x0d\x07\xe5\x8d\x95\xe5\x85\x83\xe6\xb5\x8b\xe8\xaf\x95")
        self.assertTrue(hasattr(tlv, "subtype"))
        self.assertEqual(tlv.subtype, ChassisIdTLV.Subtype.LOCAL)
        self.assertTrue(hasattr(tlv, "value"))
        self.assertEqual(tlv.value, "单元测试")

    def test_chassisid_load_mac(self):
        tlv = ChassisIdTLV.from_bytes(b"\x02\x07\x04\xc8\xbc\xc8\x94\x92\xca")
        self.assertTrue(hasattr(tlv, "value"))
        self.assertEqual(tlv.value, b"\xc8\xbc\xc8\x94\x92\xca")

    def test_chassisid_load_ipv4(self):
        tlv = ChassisIdTLV.from_bytes(b"\x02\x06\x05\x01\xc0\x00\x02\x0e")
        self.assertTrue(hasattr(tlv, "value"))
        self.assertEqual(tlv.value, ip_address("192.0.2.14"))

    def test_chassisid_load_ipv6(self):
        tlv = ChassisIdTLV.from_bytes(
            b"\x02\x12\x05\x02\x20\x01\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x12")
        self.assertTrue(hasattr(tlv, "value"))
        self.assertEqual(tlv.value, ip_address("2001:db::ff:12"))

    def test_chassisid_load_invalid_generic(self):
        with self.assertRaises(ValueError):
            ChassisIdTLV.from_bytes(b"\x02\x0a\x07\x55\x6e\x69\x74\x74\x65\x73\x74")

    def test_chassisid_load_invalid_mac(self):
        with self.assertRaises(ValueError):
            ChassisIdTLV.from_bytes(b"\x02\x08\x04\xc8\xbc\xc8\x94\x92\xca\x11")

    def test_chassisid_load_invalid_ipv4(self):
        with self.assertRaises(ValueError):
            ChassisIdTLV.from_bytes(b"\x02\x04\x05\xc0\x00\x02")

    def test_chassisid_load_invalid_ipv6(self):
        with self.assertRaises(ValueError):
            ChassisIdTLV.from_bytes(b"\x02\x10\x05\x20\x01\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00")
