from lldp.tlv import TLV


class PortDescriptionTLV(TLV):
    """Port Description TLV

    The Port Description TLV allows network management to advertise the device's port description.

    It is an optional TLV and as such may be included in an LLDPDU zero or more times between
    the TTL TLV and the End of LLDPDU TLV.

    Attributes:
        type (TLV.Type): The type of the TLV
        description (str): The port description

    TLV Format:

         0                   1                   2
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+
        |             |                 |                           |
        |      4      |      Length     |     Port Description      |
        |             |                 |                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+

                                                0 - 255 byte
    """

    def __init__(self, description: str):
        self.type = TLV.Type.PORT_DESCRIPTION
        self.value = description
        self.bytes = bytearray(description, 'utf-8')

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
        return f"PortDescriptionTLV({self.value})"

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

        if not tlv_type == TLV.Type.PORT_DESCRIPTION:
            raise ValueError

        length = ((data[0] & 1) << 8) | data[1]

        if not len(data) == length + 2:
            raise ValueError

        tlv = PortDescriptionTLV(data[2:len(data)].decode('utf-8'))
        return tlv


class SystemDescriptionTLV(TLV):
    """System Description TLV

    The System Description TLV allows network management to advertise the system’s description.

    It is an optional TLV and as such may be included in an LLDPDU zero or more times between
    the TTL TLV and the End of LLDPDU TLV.

    Attributes:
        type (TLV.Type): The type of the TLV
        description (str): The system description

    TLV Format:

         0                   1                   2
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+
        |             |                 |                           |
        |      6      |      Length     |     System Description    |
        |             |                 |                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+

                                                0 - 255 byte
    """

    def __init__(self, description: str):
        self.type = TLV.Type.SYSTEM_DESCRIPTION
        self.value = description
        self.bytes = bytearray(description, 'utf-8')

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
        return f"SystemDescriptionTLV({self.value})"

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

        if not tlv_type == TLV.Type.SYSTEM_DESCRIPTION:
            raise ValueError

        length = ((data[0] & 1) << 8) | data[1]

        if not len(data) == length + 2:
            raise ValueError

        tlv = SystemDescriptionTLV(data[2:len(data)].decode('utf-8'))
        return tlv


class SystemNameTLV(TLV):
    """System Name TLV

    The System Name TLV allows network management to advertise the system’s assigned name.

    It is an optional TLV and as such may be included in an LLDPDU zero or more times between
    the TTL TLV and the End of LLDPDU TLV.

    Attributes:
        type (TLV.Type): The type of the TLV
        name (str): The system name

    TLV Format:

         0                   1                   2
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+
        |             |                 |                           |
        |      5      |      Length     |     System Description    |
        |             |                 |                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+

                                                        0 - 255 byte
    """

    def __init__(self, name: str):
        self.type = TLV.Type.SYSTEM_NAME
        self.value = name
        self.bytes = bytearray(name, 'utf-8')

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
        return f"SystemNameTLV({self.value})"

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

        if not tlv_type == TLV.Type.SYSTEM_NAME:
            raise ValueError

        length = ((data[0] & 1) << 8) | data[1]

        if not len(data) == length + 2:
            raise ValueError

        tlv = SystemNameTLV(data[2:len(data)].decode('utf-8'))
        return tlv
