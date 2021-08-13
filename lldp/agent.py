import binascii
import socket, select
import time
import ctypes
import struct
import fcntl
from .lldpdu import LLDPDU
from .tlv import *


class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]


class StdoutLogger:
    def __init__(self):
        pass

    def log(self, msg):
        print(msg)


class LLDPAgent:
    """LLDP Agent

    The LLDP agent is the top-level component. It provides two functions.

    It announces its presence on the network by sending LLDP frames in regular intervals.
    At the same time it listens for LLDP frames from other network devices.

    If a frame is received and it is valid its contents will be logged for the administrator.
    """

    def __init__(self, mac_address: bytes, interface_name: str = "", interval=1.0, sock=None, logger=None):
        """LLDP Agent Constructor

        Sets up the network socket and LLDP agent state.

        Parameters:
            mac_address (bytes): The local MAC address
            interface_name (str): Name of the local interface
            interval (float): Announce interval in seconds
            sock: A previously opened socket. Used for testing
            logger: A logger instance. Used for testing
            
        """
        if sock is None:
            # Open a socket suitable for transmitting LLDP frames.
            ETH_P_ALL = socket.ntohs(0x0003)
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_ALL)
            self.socket.bind((interface_name, 0))
            IFF_PROMISC = 0x100
            SIOCGIFFLAGS = 0x8913
            SIOCSIFFLAGS = 0x8914
            ifr = ifreq()
            ifr.ifr_ifrn = interface_name.encode('utf-8')
            fcntl.ioctl(self.socket.fileno(), SIOCGIFFLAGS, ifr)  # G for Get
            ifr.ifr_flags |= IFF_PROMISC
            fcntl.ioctl(self.socket.fileno(), SIOCSIFFLAGS, ifr)  # S for Set

        else:
            self.socket = sock

        self.interface_name = interface_name
        self.mac_address = mac_address
        self.announce_interval = interval  # in seconds
        self.logger = StdoutLogger() if logger is None else logger

    def run(self, run_once: bool = False):
        """Agent Loop

        This is the main loop of the LLDP agent. It takes care of sending as well as receiving LLDP frames.

        The loop continuously checks the socket for new data. If data (in the form of an Ethernet frame)
        has been received, it will check if the frame is a valid LLDP frame and, if so, log its contents for the
        administrator. All other frames will be ignored.

        Valid LLDP frames have an ethertype of 0x88CC, are directed to one of the LLDP multicast addresses
        (01:80:c2:00:00:00, 01:80:c2:00:00:03 and 01:80:c2:00:00:0e) and have not been sent by the local agent.

        After processing received frames, the agent announces itself by calling `LLDPAgent.announce()` if a sufficient
        amount of time has passed.

        Parameters:
            run_once (bool): Stop the main loop after the first pass
        """
        received = False
        t_previous = time.time()
        try:
            while not run_once or not received:
                r, _, _ = select.select([self.socket], [], [], self.announce_interval)
                if len(r) > 0:
                    # Frames have been received by the network card

                    # Get the next frame
                    data = r[0].recv(4096)

                    # Check format and extract LLDPDU (raw bytes)
                    dest_addr = struct.unpack_from("6s", data, 0)

                    # print(binascii.hexlify(dest_addr[0]))

                    if dest_addr[0] != bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]) and dest_addr[0] != bytes(
                            [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]) and dest_addr[0] != bytes(
                            [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]):
                        print("Error: invalid destination address!")
                        continue

                    src_addr = struct.unpack_from("6s", data, 6)

                    # print(binascii.hexlify(src_addr[0]))

                    if src_addr[0] == self.mac_address:
                        print("Error: message origin is self!")
                        continue

                    eth_type = struct.unpack_from("!H", data, 12)

                    # print(hex(eth_type[0]))

                    if eth_type[0] != 0x88CC:
                        print("Error: wrong ethertype!")
                        continue

                    # Instantiate LLDPDU object from raw bytes
                    lldpdu = LLDPDU.from_bytes(data[14:len(data)])

                    # Log contents
                    self.logger.log(str(lldpdu))
                    received = True

                # Announce if the time is right
                t_now = time.time()
                if t_now - t_previous > self.announce_interval:
                    self.announce()
                    t_previous = t_now

        except KeyboardInterrupt:
            pass
        finally:
            # Clean up
            self.socket.close()

    def announce(self):
        """Announce the agent

        Send an LLDP frame using the socket.

        Sends an LLDP frame with an LLDPDU containing:
            * the agent's MAC address as its chassis id
            * the agent's interface name as port id
            * a TTL of 60 seconds
        """

        # Construct LLDPDU
        chassis_tlv = ChassisIdTLV(ChassisIdTLV.Subtype.MAC_ADDRESS, self.mac_address)
        port_tlv = PortIdTLV(PortIdTLV.Subtype.INTERFACE_NAME, self.interface_name)
        ttlive_tlv = TTLTLV(60)
        # end_tlv = EndOfLLDPDUTLV()
        lldpdu = LLDPDU(chassis_tlv, port_tlv, ttlive_tlv)

        # Construct Ethernet Frame
        dst_addr = bytearray([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e])

        payload = lldpdu.__bytes__()

        ethertype = 0x88CC

        eth_header = struct.pack('!6s6sH', dst_addr, self.mac_address, ethertype)

        # checksum = binascii.crc32(bytearray(eth_header) + bytearray(payload))

        # print(binascii.hexlify(bytearray(eth_header) + bytearray(payload)))

        # print(binascii.hexlify(checksum.to_bytes(4, byteorder='big')))

        frame = bytearray(eth_header) + bytearray(payload)  # + checksum.to_bytes(4, byteorder='big')

        # print(binascii.hexlify(frame))

        # Send frame
        self.socket.send(frame)
