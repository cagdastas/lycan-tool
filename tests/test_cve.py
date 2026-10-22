"""cve testleri. İnternete çıkmaz: NVD yerine sahte cevap kullanılır.

Çalıştırma: python -m unittest
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lycan import banner, cve

# NVD cevabının küçültülmüş bir örneği (gerçek cevapla aynı yapı)
FAKE_NVD = {
    "totalResults": 2,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2024-6387",
            "descriptions": [{"lang": "en", "value": "A signal handler race condition in sshd."}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
        }},
        {"cve": {
            "id": "CVE-2008-3844",
            "descriptions": [{"lang": "en", "value": "Old packages may have been modified."}],
            "metrics": {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.3}}]},
        }},
    ],
}


class CpeNames(unittest.TestCase):
    def test_openssh_splits_update(self):
        self.assertEqual(
            cve.cpe_names("OpenSSH", "9.2p1"),
            ["cpe:2.3:a:openbsd:openssh:9.2:p1:*:*:*:*:*:*"],
        )

    def test_plain_version_and_two_names(self):
        self.assertEqual(
            cve.cpe_names("nginx", "1.24.0"),
            ["cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"],
        )

    def test_unknown_or_strange_input_gives_nothing(self):
        self.assertEqual(cve.cpe_names("Caddy", "2.7"), [])
        self.assertEqual(cve.cpe_names("OpenSSH", "9.2p1:*:evil"), [])  # CPE'ye fazladan alan eklenemez
        self.assertEqual(cve.cpe_names("OpenSSH", None), [])


class Parse(unittest.TestCase):
    def test_reads_id_score_severity(self):
        found = cve.parse(FAKE_NVD)
        self.assertEqual(found[0]["id"], "CVE-2024-6387")
        self.assertEqual((found[0]["score"], found[0]["severity"]), (8.1, "HIGH"))
        self.assertEqual((found[1]["score"], found[1]["severity"]), (9.3, "CRITICAL"))  # eski CVSS 2


class Lookup(unittest.TestCase):
    def setUp(self):
        # Gerçek ~/.lycan dosyasına dokunma: geçici klasör kullan
        self.folder = tempfile.TemporaryDirectory()
        self.patches = [
            mock.patch.object(cve, "CACHE_FILE", Path(self.folder.name) / "cache.json"),
            mock.patch.object(cve, "_memory", {}),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.folder.cleanup()

    def test_sorted_by_score_and_cached(self):
        with mock.patch.object(cve, "fetch", return_value=FAKE_NVD) as fetch:
            found = cve.lookup("OpenSSH", "9.2p1")
            self.assertEqual([c["id"] for c in found], ["CVE-2008-3844", "CVE-2024-6387"])
            self.assertEqual(fetch.call_count, 1)

            cve._memory.clear()  # yeni bir çalıştırma gibi: yalnızca dosyadaki önbellek kalsın
            cve.lookup("OpenSSH", "9.2p1")
            self.assertEqual(fetch.call_count, 1)  # ikinci kez NVD'ye sorulmadı

    def test_unknown_product_never_asks_nvd(self):
        with mock.patch.object(cve, "fetch") as fetch:
            self.assertIsNone(cve.lookup("Caddy", "2.7"))
            fetch.assert_not_called()

    def test_same_cve_under_two_names_counted_once(self):
        with mock.patch.object(cve, "fetch", return_value=FAKE_NVD) as fetch:
            found = cve.lookup("nginx", "1.24.0")
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(len(found), 2)


class Distro(unittest.TestCase):
    def test_backport_hint(self):
        self.assertEqual(banner.describe("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n")["distro"], "Debian")
        self.assertEqual(banner.describe("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")["distro"], "Ubuntu")
        self.assertIsNone(banner.describe("SSH-2.0-OpenSSH_9.8\r\n")["distro"])


if __name__ == "__main__":
    unittest.main()
