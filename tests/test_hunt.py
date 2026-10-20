"""hunt testleri. İnternete çıkmaz: yalnızca bu bilgisayarda kendi açtığı kapıyı tarar.

Çalıştırma: python -m unittest
"""

import socket
import unittest

from lycan import hunt


class CheckAllowed(unittest.TestCase):
    def test_own_network_is_allowed(self):
        for ip in ["127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.20", "::1"]:
            hunt.check_allowed(ip)  # hata fırlatmamalı

    def test_internet_is_refused(self):
        for ip in ["8.8.8.8", "1.1.1.1", "104.16.0.1", "2606:4700::1111"]:
            with self.assertRaises(hunt.NotAllowed):
                hunt.check_allowed(ip)

    def test_not_a_single_machine_is_refused(self):
        for ip in ["0.0.0.0", "224.0.0.1"]:
            with self.assertRaises(hunt.NotAllowed):
                hunt.check_allowed(ip)


class ParsePorts(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(hunt.parse_ports("80, 22,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_bad_input(self):
        for text in ["", "0", "70000", "90-80", "abc", "1-5000"]:
            with self.assertRaises(ValueError):
                hunt.parse_ports(text)


class Hunt(unittest.TestCase):
    def test_finds_a_port_we_opened(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))  # 0 = işletim sistemi boş bir kapı seçsin
        server.listen()
        port = server.getsockname()[1]
        try:
            found = hunt.hunt("127.0.0.1", [port], timeout=1)
        finally:
            server.close()
        self.assertEqual([f["port"] for f in found], [port])

    def test_refuses_public_address(self):
        with self.assertRaises(hunt.NotAllowed):
            hunt.hunt("8.8.8.8", [53])


if __name__ == "__main__":
    unittest.main()
