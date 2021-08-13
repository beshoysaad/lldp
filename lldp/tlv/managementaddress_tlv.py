from lldp.tlv import TLV
from ipaddress import ip_address, IPv4Address, IPv6Address
from enum import IntEnum
import struct


class ManagementAddressTLV(TLV):
    """Management Address TLV

    The Management Address TLV identifies an address associated with the local LLDP agent that may be used to reach
    higher layer entities to assist discovery by network management, e.g. a web interface for device configuration.

    It is an optional TLV and as such may be included in an LLDPDU zero or more times between
    the TTL TLV and the End of LLDPDU TLV.

    Attributes:
        type    (TLV.Type): The type of the TLV
        subtype (IFNumberingSubtype): The interface numbering subtype
        value   (ip_address): The management address
        oid     (bytes): The object identifier of the device sending the TLV

    TLV Format:

         0               1               2               3               4
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+~
        |             |                 |  Management   |  Management   |   Management    |
        |     0x1     |      Length     |    Address    |    Address    |     Address     |
        |             |                 | String Length |    Subtype    | (m=1-31 octets) |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+~

         4+m             5+m              9+m           10+m
       ~+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+.....+-+-+-+-+-+-+-+
        |   Interface   |   Interface   |  OID String   |        Object identifier        |
        |   Numbering   |    Number     |    Length     |         (0-128 octets)          |
        |    Subtype    |   (4 octets)  |   (1 octet)   |                                 |
       ~+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+.....+-+-+-+-+-+-+-+

    Management Address Subtype and Management Address String Length:

        In practice there are many different network protocols, each with their own address format and length.

        To identify the type of network protocol and length of the network address the TLV includes a management address
        subtype and string length. Address lengths are given in bytes.

        For this implementation we only consider IPv4 and IPv6.

        | Protocol | Subtype |
        | -------- | ------- |
        |   IPv4   |       1 |
        |   IPv6   |       2 |

        Example:
            134.96.86.110 is an IPv4 address, so it has a subtype of 1 and it has a length of 4 bytes.

        The full list of registered protocol families is available at:
            https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml


    Interface Number and Subtype:

        The interface numbering subtype indicates the numbering method used to define the interface number.

        From the view of the LLDP agent the interface number is not treated differently depending on the numbering
        subtype. It is just a number.

        The LLDP standard specifies three valid subtypes:

        | Subtype |    Description     |
        | ------- | ------------------ |
        |       1 |      Unknown       |
        |       2 |  Interface Index   |
        |       3 | System Port Number |

    OID / OID Length:

        An OID (Object IDentifier) is a globally unambiguous name for any type of object / thing.
        It can be used to e.g. identify the kind of hardware component associated with the management address.

        This implementation will not make use of the OID, but it nevertheless has to be handled properly if included in
        a TLV. It does not have to be interpreted.

        Example:
            >>> tlv = ManagementAddressTLV(ip_address("192.0.2.1"), 4, ifsubtype=IFNumberingSubtype.IF_INDEX,
            >>>                            oid=b"\x00\x08\x15")
            >>> tlv.oid
            b'\x00\x08\x15'
    """

    class IFNumberingSubtype(IntEnum):
        UNKNOWN = 1
        IF_INDEX = 2
        SYSTEM_PORT = 3

        def __repr__(self):
            return repr(self.value)

    def __init__(self, address, interface_number: int = 0, ifsubtype: IFNumberingSubtype = IFNumberingSubtype.UNKNOWN,
                 oid: TLV.ByteType = None):
        """ Constructor

        Args:
            address (ip_address): IP Address to be parsed
            interface_number (int): The interface number
            ifsubtype (IFNumberingSubtype): The interface numbering subtype
            oid (bytes): The OID. See above
        """
        address = ip_address(address)
        self.type = TLV.Type.MANAGEMENT_ADDRESS
        self.subtype = ifsubtype
        self.value = address
        self.oid = oid
        addr_subtype = 0
        if isinstance(address, IPv4Address):
            addr_subtype = 1
        elif isinstance(address, IPv6Address):
            addr_subtype = 2
        assert addr_subtype != 0
        self.bytes = bytearray(struct.pack("!BB", int((address.max_prefixlen / 8) + 1), addr_subtype))
        self.bytes += bytearray(address.packed)
        self.bytes += bytearray(struct.pack("!BI", ifsubtype, interface_number))
        if oid is not None:
            self.bytes += bytearray(len(oid).to_bytes(1, 'big'))
            self.bytes += bytearray(oid)
        else:
            self.bytes += bytearray((0).to_bytes(1, 'big'))
        self.ifnum = interface_number

    def __bytes__(self):
        """Return the byte representation of the TLV.

        This method must return bytes. Returning a bytearray will raise a TypeError.
        See `TLV.__bytes__()` for more information.
        """
        return super().__bytes__()

    def __len__(self):
        """Return the length of the TLV value.

        This method must return an int. Returning anything else will raise a TypeError.
        See `TLV.__len__()` for more information.
        """
        return super().__len__()

    def __repr__(self):
        """Return a printable representation of the TLV object.

        See `TLV.__repr__()` for more information.
        """
        return f"ManagementAddressTLV({self.value}, {self.ifnum}, {self.subtype}, {self.oid})"

    @staticmethod
    def from_bytes(data: TLV.ByteType):
        """Create a TLV instance from raw bytes.

        Args:
            data (bytes or bytearray): The packed TLV

        Raises a `ValueError` if the provided TLV contains errors (e.g. has the wrong type).
        """
        if len(data) < 2:
            raise ValueError

        tlv_type = (data[0] >> 1) & 0x7F

        if not tlv_type == TLV.Type.MANAGEMENT_ADDRESS:
            raise ValueError

        length = ((data[0] & 1) << 8) | data[1]

        if not len(data) == length + 2:
            raise ValueError

        addr_len = data[2] - 1
        oid_len = data[9 + addr_len]

        if oid_len == 0:
            tlv = ManagementAddressTLV(ip_address(data[4:4 + addr_len]),
                                       (struct.unpack_from("!I", data, 5 + addr_len))[0],
                                       ManagementAddressTLV.IFNumberingSubtype(data[4 + addr_len]),
                                       None)
        else:
            tlv = ManagementAddressTLV(ip_address(data[4:4 + addr_len]),
                                       (struct.unpack_from("!I", data, 5 + addr_len))[0],
                                       ManagementAddressTLV.IFNumberingSubtype(data[4 + addr_len]),
                                       data[10 + addr_len: 10 + addr_len + oid_len])
        return tlv
