from enum import IntEnum
from typing import TypeVar, Tuple
import struct


class TLV(object):
    """TLV Base class

    This is the basic abstract TLV class. It provides some functionality common to all (or at least most) of the TLVs
    defined by IEEE802.AB.

    No instances of this class should ever be created. It is simply an ancestor for TLVs to inherit from.

    You have to implement at least `TLV.get_length()` and parts of `TLV.get_type()`.

    Hint: Implementing the other methods in this class (or even adding some methods) can save you a lot of work in the
          other TLVs. It might be worth checking out the formats of the other TLVs and implement a lowest common
          denominator here. It is not required however.

    Attributes:
        type (TLV.Type)
        subtype (int)
        value (depends on type and subtype)
    """

    ByteType = TypeVar("ByteType", bytes, bytearray)
    """Either bytes or bytearray

    Both types can be cast to each other by using the builtin bytes() or bytearray() functions.

    bytes and bytearray are very similar (see https://docs.python.org/3/library/stdtypes.html#bytes-methods)
    However, bytearrays are mutable while bytes are not.
    """

    class Type(IntEnum):
        END_OF_LLDPDU = 0
        CHASSIS_ID = 1
        PORT_ID = 2
        TTL = 3
        PORT_DESCRIPTION = 4
        SYSTEM_NAME = 5
        SYSTEM_DESCRIPTION = 6
        SYSTEM_CAPABILITIES = 7
        MANAGEMENT_ADDRESS = 8
        ORGANIZATIONALLY_SPECIFIC = 127

        def __repr__(self):
            return repr(self.value)

    type = None
    subtype = None
    value = None
    bytes = None

    @staticmethod
    def get_type(data: ByteType) -> Type:
        """Get the type of a packed TLV.

        Extracts the relevant bytes from `data` and returns a corresponding `TLV.Type`.

        Params:
            data (bytes or bytearray): The packed TLV
        """

        # Extract the type value from `data`
        typevalue = (data[0] >> 1) & 0x7F

        # Return the proper type enum or raise an error
        try:
            return TLV.Type(typevalue)
        except ValueError:
            raise ValueError(f"No such TLV Type: {typevalue}")

    @staticmethod
    def get_length(data: ByteType) -> int:
        """Get the length of a packed TLV.

        Extracts the relevant bytes from `data` and returns them.

        Params:
            data (bytes or bytearray): The packed TLV
        """
        return ((data[0] & 1) << 8) | data[1]

    @staticmethod
    def from_bytes(data: ByteType) -> 'TLV':
        """Create a TLV instance from raw bytes.

        Args:
            data (bytes or bytearray): The packed TLV

        Reads the TLV Type of `data` and calls the from_bytes() method of the corresponding TLV subclass.

        Raises a value error if the provided TLV is of unknown type. Apart from that validity checks are left to the
        subclass.
        """
        # lazy imports to avoid circular import dependencies
        from lldp.tlv import EndOfLLDPDUTLV, ChassisIdTLV, PortIdTLV, TTLTLV, PortDescriptionTLV, SystemNameTLV,\
            SystemDescriptionTLV, SystemCapabilitiesTLV, ManagementAddressTLV, OrganizationallySpecificTLV

        tlv_type = TLV.get_type(data)

        return {
            TLV.Type.END_OF_LLDPDU:             EndOfLLDPDUTLV,
            TLV.Type.CHASSIS_ID:                ChassisIdTLV,
            TLV.Type.PORT_ID:                   PortIdTLV,
            TLV.Type.TTL:                       TTLTLV,
            TLV.Type.PORT_DESCRIPTION:          PortDescriptionTLV,
            TLV.Type.SYSTEM_NAME:               SystemNameTLV,
            TLV.Type.SYSTEM_DESCRIPTION:        SystemDescriptionTLV,
            TLV.Type.SYSTEM_CAPABILITIES:       SystemCapabilitiesTLV,
            TLV.Type.MANAGEMENT_ADDRESS:        ManagementAddressTLV,
            TLV.Type.ORGANIZATIONALLY_SPECIFIC: OrganizationallySpecificTLV
        }[tlv_type].from_bytes(data)

    def __init__(self, type: Type, value_bytes: ByteType, subtype: int = None):
        """Constructor

        Args:
            type (TLV.Type): TLV Type
            value_bytes (bytes or bytearray): data to fill the value field
            subtype (int, optional): If the respective TLV has a subtype, it should be stored here.
                Otherwise, this should be set to None
        """
        self.type = None
        self.subtype = None
        self.value = None
        self.bytes = None

    def __bytes__(self) -> bytes:
        """Return the byte representation of the TLV.

        Consider the following TLV:

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             |                 |                               |
        |     0x3     |       0x2       |            0x003c             |
        |             |                 |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        When called on this TLV, this method should return b'\x06\x02\x00\x3c'.

        Note:
            This method must return bytes. Returning a bytearray will raise a TypeError.
        """
        tlv_bytes_hdr = struct.pack("!BB", (self.type << 1) | (self.__len__() >> 8) & 1, self.__len__() & 0xFF)
        tlv_bytes = bytes(bytearray(tlv_bytes_hdr) + bytearray(self.bytes))
        return tlv_bytes

    def __len__(self) -> int:
        """Return the length of the TLV value.

        Returns the length of the TLV value in bytes, i.e. the value encoded in the length field of the TLV.

        When called on the TLV above, the __len__ method should return the 0x2 from the length field.

        Note:
            This method must return an int. Returning anything else will raise a TypeError.
        """
        return len(self.bytes)

    def __repr__(self) -> str:
        """
        Using inheritance can save you a lot of work when implementing the __bytes__ and __len__ methods in the subclasses.

        The __repr__() method is called by the builtin repr() to create a useful string representation.

        See https://docs.python.org/3/reference/datamodel.html#object.__repr__
        and https://docs.python.org/3/library/functions.html#repr

        For the TLV subclasses, these representation should have the following form:
            SubclassName(repr(arg1), repr(arg2), repr(kwarg1))

        Note how keyword arguments do not have their keyword attached. In fact, they can be used just like positional
        arguments if they are passed in the correct order. We do however expect them to be displayed even if they are the
        default value (usually None).

        Example:
            >>> tlv = ChassisIdTLV(ChassisIdTLV.Subtype.NETWORK_ADDRESS, "::1")
            >>> repr(tlv)
            "ChassisIdTLV(5, '::1')"

        To use inheritance for implementing this, take a look at the builtin __class__ and __name__ methods.
        """
        return "NotImplemented"
