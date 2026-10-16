"""Offline checks: preserve TLS handshake bytes and reject local targets."""

import socket
import ssl
import threading
import unittest
from unittest.mock import patch

import uu_connection_proxy as proxy


class ProxyTests(unittest.TestCase):
    def test_clienthello_record_split_preserves_handshake(self):
        context = ssl.create_default_context()
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = context.wrap_bio(
            incoming, outgoing, server_side=False,
            server_hostname="api.nrd.nie.163.com",
        )
        with self.assertRaises(ssl.SSLWantReadError):
            client.do_handshake()
        hello = outgoing.read()
        original_size = int.from_bytes(hello[3:5], "big")
        original = hello[:5 + original_size]
        source, adapter_in = socket.socketpair()
        adapter_out, target = socket.socketpair()
        try:
            target.settimeout(2)
            source.sendall(original)
            proxy.forward_initial(adapter_in, adapter_out, "api.nrd.nie.163.com")
            actual = proxy.recv_exact(target, len(original) + 5)
            self.assertEqual(actual[:3], original[:3])
            self.assertEqual(int.from_bytes(actual[3:5], "big"), 1)
            self.assertEqual(actual[6:9], original[:3])
            self.assertEqual(int.from_bytes(actual[9:11], "big"), original_size - 1)
            self.assertEqual(actual[5:6] + actual[11:], original[5:])
            self.assertIn(b"api.nrd.nie.163.com", actual[5:6] + actual[11:])
        finally:
            for connection in (source, adapter_in, adapter_out, target):
                connection.close()

    def test_socks5_rejects_loopback_without_upstream(self):
        server = proxy.Server(("127.0.0.1", 0), proxy.Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with socket.socket() as client:
                client.settimeout(2)
                client.connect(server.server_address)
                with patch.object(proxy.socket, "create_connection") as upstream:
                    client.sendall(b"\x05\x01\x00")
                    self.assertEqual(proxy.recv_exact(client, 2), b"\x05\x00")
                    client.sendall(
                        b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                        + (443).to_bytes(2, "big")
                    )
                    self.assertEqual(proxy.recv_exact(client, 10)[:2], b"\x05\x02")
                    upstream.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_http_connect_rejects_unrelated_domain(self):
        server = proxy.Server(("127.0.0.1", 0), proxy.Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with socket.socket() as client:
                client.settimeout(2)
                client.connect(server.server_address)
                with patch.object(proxy.socket, "create_connection") as upstream:
                    client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
                    self.assertTrue(client.recv(4096).startswith(b"HTTP/1.1 403"))
                    upstream.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
