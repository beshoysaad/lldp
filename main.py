#!/usr/bin/env python3.6

import argparse
import errno
import fcntl
from lldp.agent import *
import socket
import struct


def get_hardware_address(ifname):
    """Get the MAC address of the named interface

    Raises an OSError if no interface witht the given name is found.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15].encode("ascii")))
    s.close()
    return info[18:24]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple LLDP agent.")
    parser.add_argument("interface_name", help="The name of the network interface to send/receive LLDP frames on.",
                        nargs="?", type=str, default="eth0")
    args = parser.parse_args()

    try:
        mac_address = get_hardware_address(args.interface_name)
    except OSError as e:
        if e.errno == errno.ENODEV:
            print("No interface named '{}'.".format(args.interface_name))
            print("Exiting.")
            exit(1)

    agent = LLDPAgent(mac_address, interface_name=args.interface_name)
    agent.run()
