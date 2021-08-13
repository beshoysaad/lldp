import unittest
from lldp import LLDPDU
from lldp.tlv import *


def fails_on_keyerror(f):
    def wrapper(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except KeyError as e:
            self.fail("Raised Exception {}".format(e))
    return wrapper


class LLDPDUTests(unittest.TestCase):
    def setUp(self):
        self.lldpdu = LLDPDU()

    @fails_on_keyerror
    def test_append_tlv_length(self):
        self.lldpdu.append(ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL))
        self.assertEqual(len(self.lldpdu), 1)
        self.lldpdu.append(PortIdTLV(id="port(1)", subtype=PortIdTLV.Subtype.LOCAL))
        self.assertEqual(len(self.lldpdu), 2)
        self.lldpdu.append(TTLTLV(120))
        self.assertEqual(len(self.lldpdu), 3)
        self.lldpdu.append(EndOfLLDPDUTLV())
        self.assertEqual(len(self.lldpdu), 4)

    @fails_on_keyerror
    def test_append_tlv_order(self):
        self.lldpdu.append(ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL))
        self.lldpdu.append(PortIdTLV(id="port(1)", subtype=PortIdTLV.Subtype.LOCAL))
        self.lldpdu.append(TTLTLV(120))
        self.lldpdu.append(EndOfLLDPDUTLV())

        for idx, expected_type in zip(range(4), [1, 2, 3, 0]):
            self.assertEqual(self.lldpdu[idx].type, expected_type,
                             "TLVs should be returned in the order they have been added to an LLDPDU.")

    @fails_on_keyerror
    def test_append_duplicate_required_tlv(self):
        with self.assertRaises(ValueError):
            self.lldpdu.append(ChassisIdTLV(id="Voyager", subtype=ChassisIdTLV.Subtype.LOCAL))
            self.lldpdu.append(ChassisIdTLV(id="Intrepid", subtype=ChassisIdTLV.Subtype.LOCAL))
            self.lldpdu.append(PortIdTLV(id="port(1)", subtype=PortIdTLV.Subtype.LOCAL))
            self.lldpdu.append(PortIdTLV(id="port(1)", subtype=PortIdTLV.Subtype.LOCAL))
            self.lldpdu.append(TTLTLV(120))
            self.lldpdu.append(TTLTLV(100))

    @fails_on_keyerror
    def test_append_duplicate_optional_tlv(self):
        self.lldpdu.append(ChassisIdTLV(id="Voyager", subtype=ChassisIdTLV.Subtype.LOCAL))
        self.lldpdu.append(PortIdTLV(id="port(1)", subtype=PortIdTLV.Subtype.LOCAL))
        self.lldpdu.append(TTLTLV(120))
        self.lldpdu.append(ManagementAddressTLV(address="192.2.0.1", interface_number=1))
        self.lldpdu.append(ManagementAddressTLV(address="2001:db::c0a8:1", interface_number=1))
        self.lldpdu.append(EndOfLLDPDUTLV())
        self.assertEqual(len(self.lldpdu), 6)

    @fails_on_keyerror
    def test_valid_lldpdu_is_valid(self):
        self.lldpdu.append(ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL))
        self.lldpdu.append(PortIdTLV(id="port(4)", subtype=PortIdTLV.Subtype.LOCAL))
        self.lldpdu.append(TTLTLV(90))
        self.lldpdu.append(EndOfLLDPDUTLV())

    @fails_on_keyerror
    def test_invalid_lldpdu_is_invalid(self):
        for tlv in [
            EndOfLLDPDUTLV(),
            TTLTLV(100),
            PortIdTLV(PortIdTLV.Subtype.LOCAL, "42"),
            SystemNameTLV("HAL9000"),
            OrganizationallySpecificTLV(b"\x00\x08\x15", b"\x00", 42),
        ]:
            with self.assertRaises(ValueError):
                LLDPDU(tlv)

    def test_lldpdu_too_big(self):
        description = SystemDescriptionTLV("I am putting myself to the fullest possible use, which is all I think that "
                                           "any conscious entity can ever hope to do.")
        lldpdu = LLDPDU(
            ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL),
            PortIdTLV(id="port(12)", subtype=PortIdTLV.Subtype.LOCAL),
            TTLTLV(120))

        with self.assertRaises(ValueError, msg="LLDPU must fit inside one Ethernet frame."):
            for i in range(20):
                lldpdu.append(description)

    def test_lldpdu_complete(self):
        lldpdu = LLDPDU(
            ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL),
            PortIdTLV(id="port(12)", subtype=PortIdTLV.Subtype.LOCAL),
            TTLTLV(120),
            EndOfLLDPDUTLV())
        self.assertTrue(lldpdu.complete())

    def test_lldpdu_incomplete(self):
        lldpdu = LLDPDU(
            ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL),
            PortIdTLV(id="port(12)", subtype=PortIdTLV.Subtype.LOCAL))
        self.assertFalse(lldpdu.complete())

    def test_lldpdu_too_many_ends(self):
        with self.assertRaises(ValueError, msg="End of LLDPDU TLV may only be added at most once."):
            lldpdu = LLDPDU(
                ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL),
                PortIdTLV(id="port(12)", subtype=PortIdTLV.Subtype.LOCAL),
                TTLTLV(120),
                EndOfLLDPDUTLV(),
                EndOfLLDPDUTLV())

    @fails_on_keyerror
    def test_dump(self):
        self.lldpdu.append(ChassisIdTLV(id="unittest", subtype=ChassisIdTLV.Subtype.LOCAL))
        self.lldpdu.append(PortIdTLV(id="port(12)", subtype=PortIdTLV.Subtype.LOCAL))
        self.lldpdu.append(TTLTLV(400))
        self.lldpdu.append(EndOfLLDPDUTLV())
        self.assertEqual(bytes(self.lldpdu),
                         b"\x02\x09\x07unittest" +
                         b"\x04\x09\x07port(12)" +
                         b"\x06\x02\x01\x90" +
                         b"\x00\x00")

    def test_load(self):
        du_bytes = (b"\x02\x08\x07Voyager" +
                    b"\x04\x06\x0710743" +
                    b"\x06\x02\x00\xff" +
                    b"\x08\x0bEngineering" +
                    b"\x00\x00")
        du = LLDPDU.from_bytes(du_bytes)

        self.assertTrue(hasattr(du, "__len__"))
        self.assertIsInstance(du.__len__(), int)
        self.assertEqual(len(du), 5)
