#!/usr/bin/env python3

import unittest
from lldp.tlv import TLV, SystemCapabilitiesTLV


class SystemCapabilitiesTLVTests(unittest.TestCase):
    def setUp(self):
        caps = SystemCapabilitiesTLV.Capability
        self.tlv = SystemCapabilitiesTLV(
            supported=caps.WLAN_AP | caps.BRIDGE | caps.ROUTER | caps.DOCSIS_DEVICE,
            enabled=caps.BRIDGE | caps.ROUTER | caps.DOCSIS_DEVICE
        )
        self.assertIsInstance(self.tlv.__bytes__(), bytes)
        self.assertIsInstance(self.tlv.__len__(), int)

    def test_type(self):
        self.assertEqual(self.tlv.type, TLV.Type.SYSTEM_CAPABILITIES)

    def test_length(self):
        self.assertIsInstance(self.tlv.__len__(), int)
        self.assertEqual(len(self.tlv), 4)

    def test_value(self):
        self.assertEqual(self.tlv.value, 0x005c0054)

    def test_subtype(self):
        # SystemCapability TLVs don't have a subtype
        self.assertEqual(self.tlv.subtype, None)

    def test_dump(self):
        self.assertEqual(bytes(self.tlv), b"\x0e\x04\x00\x5C\x00\x54")

    def test_load(self):
        tlv = SystemCapabilitiesTLV.from_bytes(b"\x0e\x04\x00\x14\x00\x04")

        self.assertEqual(tlv.type, TLV.Type.SYSTEM_CAPABILITIES)
        self.assertEqual(len(tlv), 4)

        self.assertEqual((tlv.value & 0xFFFF0000) >> 16, 20,
                         "Expected only BRIDGE and ROUTER capabilities to be supported.")
        self.assertEqual(tlv.value & 0xFFFF, 4, "Expected only BRIDGE capability to be enabled.")

    def test_supports(self):
        caps = SystemCapabilitiesTLV.Capability
        self.assertTrue(self.tlv.supports(caps.WLAN_AP | caps.BRIDGE | caps.ROUTER | caps.DOCSIS_DEVICE))

        for cap in (caps.WLAN_AP, caps.BRIDGE, caps.ROUTER, caps.DOCSIS_DEVICE):
            self.assertTrue(self.tlv.supports(cap))

        for cap in (caps.OTHER, caps.REPEATER, caps.TELEPHONE, caps.STATION_ONLY,
                    caps.C_VLAN_COMPONENT, caps.S_VLAN_COMPONENT, caps.TWO_PORT_MAC_RELAY):

            self.assertFalse(self.tlv.supports(cap))

        # Reserved bits should not be used
        self.assertFalse(self.tlv.supports(0xF800))

    def test_enabled(self):
        caps = SystemCapabilitiesTLV.Capability
        self.assertTrue(self.tlv.enabled(caps.BRIDGE | caps.ROUTER | caps.DOCSIS_DEVICE))

        for cap in (caps.BRIDGE, caps.ROUTER, caps.DOCSIS_DEVICE):
            self.assertTrue(self.tlv.enabled(cap))

        for cap in (caps.OTHER, caps.REPEATER, caps.WLAN_AP, caps.TELEPHONE, caps.STATION_ONLY,
                    caps.C_VLAN_COMPONENT, caps.S_VLAN_COMPONENT, caps.TWO_PORT_MAC_RELAY):

            self.assertFalse(self.tlv.enabled(cap))

        # Reserved bits should not be used
        self.assertFalse(self.tlv.enabled(0xF800))

    def test_capability_mismatch(self):
        caps = SystemCapabilitiesTLV.Capability
        with self.assertRaises(ValueError):
            SystemCapabilitiesTLV(supported=caps.STATION_ONLY, enabled=caps.WLAN_AP)

    def test_load_capability_mismatch(self):
        with self.assertRaises(ValueError):
            SystemCapabilitiesTLV.from_bytes(b"\x0e\x04\x00\x00\x00\x14")
