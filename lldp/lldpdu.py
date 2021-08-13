from lldp.tlv import EndOfLLDPDUTLV, ChassisIdTLV, PortIdTLV, TTLTLV, PortDescriptionTLV, SystemNameTLV, SystemDescriptionTLV, SystemCapabilitiesTLV, ManagementAddressTLV, OrganizationallySpecificTLV
from lldp.tlv import TLV


class LLDPDU:
    """LLDP Data Unit

    The LLDP Data Unit contains an ordered sequence of TLVs, three mandatory TLVs followed by zero or more optional TLVs
    plus an End Of LLDPDU TLV.

    Optional TLVs may be inserted in any order.

    An LLDPDU has to fit inside one Ethernet frame and cannot be split.

    LLDPDU Format:

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+-+
        |                 |                 |                 |                                 |
        | Chassis ID TLV  |   Port ID TLV   |     TTL TLV     |         (Optional TLVs)         |
        |                 |                 |                 |                                 |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+-+
    """

    def __init__(self, *tlvs):
        self.length = 0
        self.__tlvs = []
        """List of included TLVs"""

        if len(tlvs) > 0:
            for tlv in tlvs:
                self.append(tlv)

    def __len__(self) -> int:
        """Get the number of TLVs in the LLDPDU"""
        return len(self.__tlvs)

    def __bytes__(self) -> bytes:
        """Get the byte representation of the LLDPDU"""
        res = b""
        for tlv in self.__tlvs:
            res += bytes(tlv)
        return res

    def __getitem__(self, item: int) -> TLV:
        """Get the TLV at position `item`"""
        return self.__tlvs[item]

    def __repr__(self):
        """Return a representation of the LLDPDU"""
        return "{}({})".format(self.__class__.__name__, repr(self.__tlvs))

    def __str__(self):
        """Return a printable representation of the LLDPDU"""
        return repr(self)

    def append(self, tlv: TLV):
        """Append `tlv` to the LLDPDU

        This method adds the given tlv to the LLDPDU.

        If adding the TLV makes the LLDPDU invalid (e.g. by adding a TLV after an EndOfLLDPDU TLV) it should raise a
        `ValueError`. Conditions for specific TLVs are detailed in each TLV's class description.
        """

        if len(tlv.__bytes__()) + self.length > 1500:
            raise ValueError

        if any(isinstance(x, EndOfLLDPDUTLV) for x in self.__tlvs):
            raise ValueError
        else:
            if tlv.type == TLV.Type.CHASSIS_ID:
                if any(isinstance(x, ChassisIdTLV) for x in self.__tlvs):
                    raise ValueError
            elif tlv.type == TLV.Type.PORT_ID:
                if any(isinstance(x, PortIdTLV) for x in self.__tlvs) or not any(isinstance(x, ChassisIdTLV) for x in self.__tlvs):
                    raise ValueError
            elif tlv.type == TLV.Type.TTL:
                if any(isinstance(x, TTLTLV) for x in self.__tlvs) or not any(isinstance(x, ChassisIdTLV) for x in self.__tlvs) or not any(isinstance(x, PortIdTLV) for x in self.__tlvs):
                    raise ValueError
            else:
                if not any(isinstance(x, ChassisIdTLV) for x in self.__tlvs) or not any(
                        isinstance(x, PortIdTLV) for x in self.__tlvs) or not any(
                        isinstance(x, TTLTLV) for x in self.__tlvs):
                    raise ValueError

        self.__tlvs.append(tlv)
        self.length += len(tlv.__bytes__())

    def complete(self):
        """Check if LLDPDU is complete.

        An LLDPDU is complete when it includes at least the mandatory TLVs (Chassis ID, Port ID, TTL).
        """
        if any(isinstance(x, ChassisIdTLV) for x in self.__tlvs) and any(
                isinstance(x, PortIdTLV) for x in self.__tlvs) and any(isinstance(x, TTLTLV) for x in self.__tlvs):
            return True
        else:
            return False

    @staticmethod
    def from_bytes(data: bytes):
        """Create an LLDPDU instance from raw bytes.

        Args:
            data (bytes or bytearray): The packed LLDPDU

        Raises a value error if the provided TLV is of unknown type. Apart from that validity checks are left to the
        subclass.
        """
        cur_idx = 0

        lldpdu = LLDPDU()

        while cur_idx < (len(data) + 1):
            tlv_type = (data[cur_idx] >> 1) & 0x7F
            tlv_len = ((data[cur_idx] & 1) << 8) | data[cur_idx + 1]

            if (cur_idx + tlv_len + 2) > len(data):
                raise ValueError
            if tlv_type == TLV.Type.END_OF_LLDPDU:
                end_tlv = EndOfLLDPDUTLV()
                lldpdu.append(end_tlv)
                cur_idx += tlv_len + 2
                break
            elif tlv_type == TLV.Type.CHASSIS_ID:
                chassis_tlv = ChassisIdTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(chassis_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.PORT_ID:
                port_tlv = PortIdTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(port_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.TTL:
                ttlive_tlv = TTLTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(ttlive_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.PORT_DESCRIPTION:
                port_desc_tlv = PortDescriptionTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(port_desc_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.SYSTEM_NAME:
                name_tlv = SystemNameTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(name_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.SYSTEM_DESCRIPTION:
                desc_tlv = SystemDescriptionTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(desc_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.SYSTEM_CAPABILITIES:
                cap_tlv = SystemCapabilitiesTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(cap_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.MANAGEMENT_ADDRESS:
                man_tlv = ManagementAddressTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(man_tlv)
                cur_idx += tlv_len + 2
            elif tlv_type == TLV.Type.ORGANIZATIONALLY_SPECIFIC:
                org_tlv = OrganizationallySpecificTLV.from_bytes(data[cur_idx:cur_idx + tlv_len + 2])
                lldpdu.append(org_tlv)
                cur_idx += tlv_len + 2
            else:
                raise ValueError
        return lldpdu
