"""checks testleri. İnternete çıkmaz: bu bilgisayarda gerçek programlar gibi konuşan sahte sunuculara bağlanır.

Çalıştırma: python -m unittest
"""

import socket
import struct
import threading
import unittest

from lycan import checks, hunt, report, watch
from tests.test_report_watch import sample


def fake_server(greeting=b"", replies=()):
    """Bir bağlantı kabul eder: önce selam verir, sonra gelen her mesaja sıradaki cevabı yollar."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()

    def run():
        conn, _ = server.accept()
        with conn:
            conn.settimeout(2)
            if greeting:
                conn.sendall(greeting)
            for reply in replies:
                try:
                    if not conn.recv(4096):
                        break
                    conn.sendall(reply)
                except OSError:
                    break
        server.close()

    threading.Thread(target=run, daemon=True).start()
    return server.getsockname()[1]


def mongo_reply(ok):
    """MongoDB cevabının en küçük hâli: başlık + bayrak + {"ok": <sayı>} belgesi."""
    doc = b"\x01ok\x00" + struct.pack("<d", ok)
    doc = struct.pack("<i", len(doc) + 5) + doc + b"\x00"
    body = struct.pack("<I", 0) + b"\x00" + doc
    return struct.pack("<iiii", 16 + len(body), 7, 1, 2013) + body


class Checks(unittest.TestCase):
    def check(self, func, **server):
        return func("127.0.0.1", fake_server(**server))

    def test_redis(self):
        self.assertEqual(self.check(checks.redis, replies=[b"+PONG\r\n"])["id"], "redis-no-auth")
        self.assertIsNone(self.check(checks.redis, replies=[b"-NOAUTH Authentication required.\r\n"]))
        self.assertIsNone(self.check(checks.redis, replies=[b"-DENIED Redis is running in protected mode\r\n"]))

    def test_elasticsearch(self):
        open_es = b'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"cluster_name":"lab"}'
        locked = b'HTTP/1.1 401 Unauthorized\r\n\r\n{"error":"missing authentication"}'
        self.assertEqual(self.check(checks.elasticsearch, replies=[open_es])["id"], "elasticsearch-no-auth")
        self.assertIsNone(self.check(checks.elasticsearch, replies=[locked]))

    def test_mongodb(self):
        self.assertEqual(self.check(checks.mongodb, replies=[mongo_reply(1.0)])["id"], "mongodb-no-auth")
        self.assertIsNone(self.check(checks.mongodb, replies=[mongo_reply(0.0)]))  # code 13: Unauthorized

    def test_ftp(self):
        anonymous = [b"331 Please specify the password.\r\n", b"230 Login successful.\r\n", b"221 Goodbye.\r\n"]
        refused = [b"331 Please specify the password.\r\n", b"530 Login incorrect.\r\n", b"221 Goodbye.\r\n"]
        greeting = b"220 (vsFTPd 3.0.3)\r\n"
        self.assertEqual(self.check(checks.ftp, greeting=greeting, replies=anonymous)["id"], "ftp-anonymous")
        self.assertIsNone(self.check(checks.ftp, greeting=greeting, replies=refused))

    def test_bson_is_valid(self):
        doc = checks._bson([("listDatabases", 1), ("nameOnly", True), ("$db", "admin")])
        self.assertEqual(struct.unpack("<i", doc[:4])[0], len(doc))  # ilk 4 bayt = belgenin boyu
        self.assertEqual(doc[-1:], b"\x00")

    def test_run_only_checks_known_services(self):
        port = fake_server(replies=[b"+PONG\r\n"])
        found = checks.run("127.0.0.1", [{"port": port, "service": "redis"}, {"port": 1, "service": "ssh"}])
        self.assertEqual(list(found), [port])
        self.assertEqual(found[port][0]["severity"], "HIGH")

    def test_closed_port_is_no_finding(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(checks.run("127.0.0.1", [{"port": port, "service": "redis"}]), {port: []})

    def test_refuses_public_address(self):
        with self.assertRaises(hunt.NotAllowed):
            checks.run("8.8.8.8", [{"port": 6379, "service": "redis"}])


def with_redis_finding(result):
    result["checks"] = True
    result["open"].append({"port": 6379, "service": "redis", "note": "", "banner": None, "cves": None,
                           "cve_error": None, "findings": [checks.finding("redis-no-auth", "HIGH",
                                                                          "Redis answers without a password.", "Set requirepass.")]})
    return result


class ReportAndWatch(unittest.TestCase):
    def test_report_lists_problem_first(self):
        page = report.render(with_redis_finding(sample()))
        self.assertIn("<h2>Configuration problems</h2>", page)
        self.assertLess(page.index("Port 6379: Redis answers"), page.index("Port 22 runs OpenSSH"))

    def test_watch_sees_new_problem(self):
        old = sample()
        old["open"].append({"port": 6379, "service": "redis", "note": "", "banner": None,
                            "cves": None, "cve_error": None, "findings": []})
        kinds = [c["kind"] for c in watch.compare(old, with_redis_finding(sample()))]
        self.assertEqual(kinds, ["new_finding"])


if __name__ == "__main__":
    unittest.main()
