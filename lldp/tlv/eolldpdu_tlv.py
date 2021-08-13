from lldp.tlv import TLV


class EndOfLLDPDUTLV(TLV):
    """End of LLDP Data Unit TLV

    The End of LLDPDU TLV is an optional TLV marking the end of an LLDP data unit (LLDPDU).
    It MUST be the last TLV in an LLDPDU and can only be included once.

    Attributes:
        type    (TLV.Type): The type of the TLV
        value   (NoneType): This TLV does not have a value. Always None

    TLV Format:

         0                   1
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             |                 |
        |      0      |       0x0       |
        |             |                 |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    def __init__(self):
        """Constructor"""
        self.type = TLV.Type.END_OF_LLDPDU
        self.value = None
        self.bytes = bytearray([0x0, 0x0])

    def __bytes__(self):
        """Return the byte representation of the TLV.

        This method must return bytes. Returning a bytearray will raise a TypeError.
        See `TLV.__bytes__()` for more information.
        """
        return b'\x00\x00'

    def __len__(self):
        """Return the length of the TLV value.

        This method must return an int. Returning anything else will raise a TypeError.
        See `TLV.__len__()` for more information.
        """
        return 0

    def __repr__(self):
        """Return a printable representation of the TLV object.

        See `TLV.__repr__()` for more information.
        """
        return "EndOfLLDPDUTLV()"

    @staticmethod
    def from_bytes(data: TLV.ByteType):
        """Create a TLV instance from raw bytes.

        Args:
            data (bytes or bytearray): The packed TLV

        Raises a `ValueError` if the provided TLV contains errors (e.g. has the wrong type).
        """
        if bytes(data) == b'\x00\x00':
            return EndOfLLDPDUTLV()

        raise ValueError()
