import socket
import threading
import unittest

from sshagent_py.listener import handle_connection, receive_packet


class ReceivePacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reader, self.writer = socket.socketpair()

    def tearDown(self) -> None:
        self.reader.close()
        self.writer.close()

    def test_reads_a_fragmented_packet(self) -> None:
        packet = b"\x00\x00\x00\x01\x0b"
        self.writer.sendall(packet[:2])
        self.writer.sendall(packet[2:])

        self.assertEqual(receive_packet(self.reader), packet)

    def test_reads_coalesced_packets_one_at_a_time(self) -> None:
        packet = b"\x00\x00\x00\x01\x0b"
        self.writer.sendall(packet + packet)

        self.assertEqual(receive_packet(self.reader), packet)
        self.assertEqual(receive_packet(self.reader), packet)

    def test_returns_none_for_a_truncated_packet(self) -> None:
        self.writer.sendall(b"\x00\x00\x00\x05\x0b")
        self.writer.shutdown(socket.SHUT_WR)

        self.assertIsNone(receive_packet(self.reader))

    def test_handler_responds_to_a_fragmented_request(self) -> None:
        thread = threading.Thread(target=handle_connection, args=(self.reader,))
        thread.start()

        request = b"\x00\x00\x00\x01\x0b"
        self.writer.sendall(request[:2])
        self.writer.sendall(request[2:])

        self.assertEqual(
            receive_packet(self.writer),
            b"\x00\x00\x00\x05\x0c\x00\x00\x00\x00",
        )
        self.writer.shutdown(socket.SHUT_WR)
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
