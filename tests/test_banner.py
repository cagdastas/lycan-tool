"""banner testleri. İnternete çıkmaz: bu bilgisayarda kendi açtığı sahte sunuculara bağlanır.

Çalıştırma: python -m unittest
"""

import socket
import threading
import unittest

from lycan import banner, hunt


class Describe(unittest.TestCase):
    def test_known_programs(self):
        cases = [
            ("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n", "OpenSSH", "9.2p1"),
            ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian)\r\n\r\n", "Apache", "2.4.62"),
            ("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n", "nginx", "1.24.0"),
            ("220 (vsFTPd 3.0.3)\r\n", "vsftpd", "3.0.3"),
            ("J\x00\x00\x00\n5.5.5-10.11.6-MariaDB-0+deb12u1\x00", "MariaDB", "10.11.6"),
            ("J\x00\x00\x00\n8.0.39-0ubuntu0.24.04.2\x00", "MySQL", "8.0.39"),
        ]
        for text, product, version in cases:
            info = banner.describe(text)
            self.assertEqual((info["product"], info["version"]), (product, version), text)

    def test_unknown_program_is_not_guessed(self):
        info = banner.describe("+OK Dovecot ready.\r\n")
        self.assertIsNone(info["product"])
        self.assertEqual(info["raw"], "+OK Dovecot ready.")

    def test_web_shows_server_line(self):
        info = banner.describe("HTTP/1.1 200 OK\r\nServer: Caddy\r\n\r\n")
        self.assertEqual(info["raw"], "Caddy")

    def test_terminal_escape_codes_are_removed(self):
        # Kötü niyetli bir sunucu terminalin rengini/başlığını değiştirmeye çalışırsa
        info = banner.describe("\x1b[31mEVIL\x1b]0;hacked\x07 banner\r\n")
        self.assertNotIn("\x1b", info["raw"])
        self.assertNotIn("\x07", info["raw"])


def fake_server(reply, talks_first):
    """Bir kez bağlantı kabul eden sahte sunucu. Kapı numarasını döner."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()

    def run():
        conn, _ = server.accept()
        with conn:
            if not talks_first:
                conn.recv(1024)  # web sunucusu gibi: önce soruyu bekle
            conn.sendall(reply)
        server.close()

    threading.Thread(target=run, daemon=True).start()
    return server.getsockname()[1]


class Grab(unittest.TestCase):
    def test_program_that_talks_first(self):
        port = fake_server(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", talks_first=True)
        info = banner.grab("127.0.0.1", port, timeout=1)
        self.assertEqual((info["product"], info["version"]), ("OpenSSH", "9.6p1"))

    def test_program_that_waits_for_a_question(self):
        port = fake_server(b"HTTP/1.0 200 OK\r\nServer: nginx/1.26.2\r\n\r\n", talks_first=False)
        info = banner.grab("127.0.0.1", port, timeout=0.5)
        self.assertEqual((info["product"], info["version"]), ("nginx", "1.26.2"))

    def test_closed_port_gives_none(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # kapı artık kapalı
        self.assertIsNone(banner.grab("127.0.0.1", port, timeout=0.5))

    def test_refuses_public_address(self):
        with self.assertRaises(hunt.NotAllowed):
            banner.grab("8.8.8.8", 22)
        with self.assertRaises(hunt.NotAllowed):
            banner.grab_all("1.1.1.1", [22, 80])


if __name__ == "__main__":
    unittest.main()
