"""results, report ve watch testleri. İnternete çıkmaz; gerçek tarama yerine örnek sonuç kullanılır.

Çalıştırma: python -m unittest
"""

import copy
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from lycan import cli, report, results, watch


def sample():
    """Kaydedilmiş bir taramanın örneği (gerçek sonuçla aynı yapı)."""
    return {
        "lycan": "0.1.0", "format": 1, "target": "kali.local", "ip": "192.168.56.101",
        "time": "2026-10-24T10:00:00+00:00", "ports_checked": 20,
        "banners": True, "cve_lookup": True,
        "open": [
            {"port": 22, "service": "ssh", "note": "Remote login.",
             "banner": {"product": "OpenSSH", "version": "9.2p1", "raw": "SSH-2.0-OpenSSH_9.2p1 Debian", "distro": "Debian"},
             "cves": [{"id": "CVE-2023-38408", "score": 9.8, "severity": "CRITICAL", "summary": "ssh-agent flaw."}],
             "cve_error": None},
            {"port": 80, "service": "http", "note": "Web server without encryption.",
             "banner": {"product": None, "version": None, "raw": "<script>alert(1)</script>", "distro": None},
             "cves": None, "cve_error": None},
        ],
    }


class Collect(unittest.TestCase):
    def test_puts_banner_and_cves_together(self):
        found = [{"port": 22, "service": "ssh", "note": "x"}]
        info = {"product": "OpenSSH", "version": "9.2p1", "raw": "", "distro": None}
        with mock.patch.object(results.hunt, "hunt", return_value=found), \
             mock.patch.object(results.banner, "grab_all", return_value={22: info}), \
             mock.patch.object(results.cve, "lookup", return_value=[]) as lookup:
            result = results.collect("t", "127.0.0.1", [22], find_cves=True, progress=lambda _: None)
        self.assertTrue(result["banners"])  # --cve, --banner'ı da açar
        self.assertEqual(result["open"][0]["banner"], info)
        self.assertEqual(result["open"][0]["cves"], [])
        lookup.assert_called_once_with("OpenSSH", "9.2p1")

    def test_nvd_failure_is_kept_not_raised(self):
        found = [{"port": 22, "service": "ssh", "note": "x"}]
        info = {"product": "OpenSSH", "version": "9.2p1", "raw": "", "distro": None}
        with mock.patch.object(results.hunt, "hunt", return_value=found), \
             mock.patch.object(results.banner, "grab_all", return_value={22: info}), \
             mock.patch.object(results.cve, "lookup", side_effect=results.cve.NvdError("down")):
            result = results.collect("t", "127.0.0.1", [22], find_cves=True, progress=lambda _: None)
        self.assertEqual(result["open"][0]["cve_error"], "down")


class SaveLoad(unittest.TestCase):
    def test_round_trip_and_bad_files(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "hunt.json"
            results.save(sample(), path)
            self.assertEqual(results.load(path), sample())

            (Path(folder) / "other.json").write_text('{"hello": 1}', encoding="utf-8")
            for bad in ["missing.json", "other.json"]:
                with self.assertRaises(ValueError):
                    results.load(Path(folder) / bad)


class Report(unittest.TestCase):
    def test_remote_text_cannot_become_html(self):
        page = report.render(sample())
        self.assertNotIn("<script>alert(1)</script>", page)  # XSS olmaz
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_has_cve_link_todo_and_no_outside_files(self):
        page = report.render(sample())
        self.assertIn('href="https://nvd.nist.gov/vuln/detail/CVE-2023-38408"', page)
        self.assertIn("Port 22 runs OpenSSH 9.2p1 with 1 critical", page)
        self.assertNotIn("<script", page)
        self.assertNotIn(" src=", page)

    def test_strange_cve_id_is_not_a_link(self):
        result = sample()
        result["open"][0]["cves"][0]["id"] = 'x" onclick="alert(1)'
        page = report.render(result)
        self.assertNotIn('onclick="alert', page)


class Compare(unittest.TestCase):
    def test_same_hunt_has_no_changes(self):
        self.assertEqual(watch.compare(sample(), sample()), [])

    def test_finds_every_kind_of_change(self):
        old, new = sample(), sample()
        del new["open"][1]  # 80 kapandı
        new["open"].append({"port": 3389, "service": "rdp", "note": "", "banner": None,
                            "cves": None, "cve_error": None})  # 3389 açıldı
        new["open"][0]["banner"]["version"] = "9.6p1"  # sürüm değişti
        new["open"][0]["cves"].append({"id": "CVE-2026-1", "score": 5, "severity": "MEDIUM", "summary": ""})
        kinds = {(c["kind"], c["port"]) for c in watch.compare(old, new)}
        self.assertEqual(kinds, {("opened", 3389), ("closed", 80), ("version", 22), ("new_cve", 22)})

    def test_versions_compared_only_when_both_read(self):
        old, new = sample(), copy.deepcopy(sample())
        new["banners"] = False
        for p in new["open"]:
            p["banner"] = None
        self.assertEqual([c for c in watch.compare(old, new) if c["kind"] == "version"], [])


class WatchCommand(unittest.TestCase):
    def run_watch(self, baseline, result, *extra):
        args = cli.build_parser().parse_args(["watch", "127.0.0.1", "--baseline", str(baseline), *extra])
        output = io.StringIO()
        with mock.patch.object(cli.results, "collect", return_value=result), redirect_stdout(output):
            try:
                args.func(args)
                code = 0
            except SystemExit as stop:
                code = stop.code
        return code, output.getvalue()

    def test_first_run_saves_then_reports_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            baseline = Path(folder) / "base.json"
            code, text = self.run_watch(baseline, sample())
            self.assertEqual(code, 0)
            self.assertTrue(baseline.exists())
            self.assertIn("now the baseline", text)

            changed = sample()
            changed["open"].append({"port": 3389, "service": "rdp", "note": "", "banner": None,
                                    "cves": None, "cve_error": None})
            code, text = self.run_watch(baseline, changed)
            self.assertEqual(code, 1)  # değişiklik var
            self.assertIn("Port 3389 (rdp) is now OPEN", text)

            code, _ = self.run_watch(baseline, changed, "--update")
            self.assertEqual(code, 1)
            code, text = self.run_watch(baseline, changed)
            self.assertEqual(code, 0)  # kabul edildi, artık fark yok
            self.assertIn("No changes", text)


if __name__ == "__main__":
    unittest.main()
