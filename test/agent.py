import unittest
from lldp import LLDPAgent
import time
import multiprocessing
import socket
import binascii


class MockSocket:
    def __init__(self, tx=b""):
        self.rx = b""
        self.tx = tx

    def send(self, data):
        self.rx += data

    def recv(self, bufsize):
        idx = min(bufsize, len(self.tx))
        res = self.tx[:idx]
        self.tx = self.tx[idx:]
        return res

    # TODO implement different/additional socket methods?


class MockLogger:
    def __init__(self):
        self.full_log = ""

    def log(self, msg):
        self.full_log += msg


class LLDPAgentTests(unittest.TestCase):
    def setUp(self):
        pass

    def test_announce(self):
        s = MockSocket()
        a = LLDPAgent(b"\x66\x6F\x6F\x62\x61\x72", interface_name="lo", sock=s)
        a.announce()
        self.assertEqual(s.rx, b'\x01\x80\xc2\x00\x00\x0e' +
                               b'\x66\x6F\x6F\x62\x61\x72' +
                               b'\x88\xcc' +
                               b'\x02\x07\x04foobar' +
                               b'\x04\x03\x05lo' +
                               b'\x06\x02\x00\x3c'
                         )

    def test_announce2(self):
        s = MockSocket()
        a = LLDPAgent(b"\x28\x5E\x5F\x5E\x27\x29", interface_name="enp4s0", sock=s)
        a.announce()
        self.assertEqual(s.rx, b"\x01\x80\xc2\x00\x00\x0e" +
                               b"\x28\x5E\x5F\x5E\x27\x29" +
                               b"\x88\xcc" +
                               b"\x02\x07\x04(^_^')" +
                               b"\x04\x07\x05enp4s0" +
                               b"\x06\x02\x00\x3c"
                         )

    def test_socket_bind(self):
        try:
            a = LLDPAgent(b"\xAA\xBB\xCC\xDD\xEE\xFF", interface_name="lo")
        except Exception as e:
            self.fail("Raised exception {}".format(e))
        self.assertEqual(a.socket.family, socket.AF_PACKET)
        self.assertEqual(a.socket.proto, 768)

    def test_run(self):
        interface = "lo"
        logger = MockLogger()

        def deferred_send():
            time.sleep(2)
            sending_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sending_socket.bind((interface, 0))

            full_msg = '0180c200000effeeddccbbaa88cc020704ffeeddccbbaa040703ffeeddccbbaa060200780000'

            sending_socket.send(binascii.unhexlify(full_msg))

            sending_socket.close()

        peer = multiprocessing.Process(target=deferred_send, daemon=True)
        peer.start()

        try:
            agent = LLDPAgent(b"\xAA\xBB\xCC\xDD\xEE\xFF", interface_name=interface, logger=logger)
        except Exception as e:
            self.fail("Raised exception {}".format(e))

        try:
            agent.run(run_once=True)
        except Exception as e:
            self.fail("Raised exception {}".format(e))

        self.assertEqual(logger.full_log.replace(" ", ""), "LLDPDU([ChassisIdTLV(4,b'\\xff\\xee\\xdd\\xcc\\xbb\\xaa'),"
                                                           "PortIdTLV(3,b'\\xff\\xee\\xdd\\xcc\\xbb\\xaa'),"
                                                           "TTLTLV(120),"
                                                           "EndOfLLDPDUTLV()])")
