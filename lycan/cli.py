"""Komut satırı: "lycan <komut>" yazınca buradan başlar.

argparse, Python'la birlikte gelen bir kütüphane. Kullanıcının yazdığı
kelimeleri (argümanları) okur ve hangi komutun istendiğini bize söyler.
"""

import argparse
import sys
import webbrowser
from pathlib import Path

from lycan import __version__
from lycan import hunt
from lycan import report
from lycan import results
from lycan import scan
from lycan import watch


def cmd_version(args):
    # Çağdaş'ın yazdığı ilk Lycan satırı (14 Ekim 2026)
    print (f"lycan {__version__}")


def cmd_scan(args):
    ports = scan.listening_ports()
    exposed = 0

    print(f"{'PROTO':<6}{'ADDRESS':<28}{'PORT':>6}  {'REACH':<10}PROCESS (PID)")
    for p in ports:
        if scan.is_exposed(p["address"]):
            reach = "network"
            exposed += 1
        else:
            reach = "local"
        print(f"{p['proto']:<6}{p['address']:<28}{p['port']:>6}  {reach:<10}{p['process']} ({p['pid']})")

    print()
    print(f"{len(ports)} ports listening, {exposed} reachable from the network.")


def prepare(args):
    """Hedefi ve kapıları okur, yasal kilidi kontrol eder. Sorun varsa çıkar."""
    try:
        ports = hunt.parse_ports(args.ports) if args.ports else sorted(hunt.COMMON_PORTS)
        ip = hunt.resolve(args.target)
        hunt.check_allowed(ip)
    except (ValueError, hunt.NotAllowed) as error:
        fail(error)
    return ip, ports


def fail(error):
    print(f"lycan: {error}", file=sys.stderr)
    sys.exit(2)


def run(args, ip, ports):
    """Taramayı yapar ve sonucu döner (hunt ve watch ortak kullanır)."""
    print(f"Hunting {args.target} ({ip}) on {len(ports)} ports...")
    return results.collect(
        args.target, ip, ports, timeout=args.timeout,
        read_banners=args.banner, find_cves=args.cve, run_checks=args.checks,
    )


def cmd_hunt(args):
    ip, ports = prepare(args)
    result = run(args, ip, ports)
    print_result(result)
    if args.save:
        try:
            results.save(result, args.save)
        except OSError as error:
            fail(f"Cannot save to {args.save}: {error.strerror}.")
        print(f"Saved to {args.save}. Make a report with: lycan report {args.save}")


def print_result(result):
    found = result["open"]
    if not found:
        print("No open ports found.")
        return

    print()
    if not result["banners"]:
        print(f"{'PORT':>6}  {'SERVICE':<12}NOTE")
        for f in found:
            print(f"{f['port']:>6}  {f['service']:<12}{f['note']}")
    else:
        print(f"{'PORT':>6}  {'SERVICE':<12}{'VERSION':<30}NOTE")
        for f in found:
            version = results.version_text(f["banner"])[:28]
            print(f"{f['port']:>6}  {f['service']:<12}{version:<30}{f['note']}")
    if result.get("checks"):
        print_findings(result)
    if result["cve_lookup"]:
        print_cves(found)
    print()
    print(f"{len(found)} open of {result['ports_checked']} checked.")


def print_findings(result):
    """Yapılandırma kontrollerinin sonucunu yazar."""
    print()
    pairs = results.all_findings(result)
    checked = sum(p.get("findings") is not None for p in result["open"])
    if not pairs:
        print(f"Configuration checks: {checked} service(s) checked, no problems found.")
        return
    print(f"Configuration checks: {len(pairs)} problem(s) found.")
    for port, f in pairs:
        print(f"  {f['severity']:<7}port {port}: {f['title']}")
        print(f"          Fix: {f['fix']}")


def print_cves(found):
    """Her tanınan sürüm için NVD'deki olası açıkları yazar (en yüksek puanlı 5 tanesi)."""
    for f in found:
        info = f["banner"]
        if not info or not info["product"]:
            continue
        name = results.version_text(info)
        cves = f["cves"]
        print()
        if f["cve_error"]:
            print(f"{f['port']:>6}  {name}: lookup failed. {f['cve_error']}")
            continue
        if cves is None:
            print(f"{f['port']:>6}  {name}: not in Lycan's product list yet, skipped.")
            continue
        if not cves:
            print(f"{f['port']:>6}  {name}: no known CVEs in NVD.")
            continue

        c = results.counts(cves)
        print(f"{f['port']:>6}  {name}: {len(cves)} possible CVEs ({c['CRITICAL']} critical, {c['HIGH']} high)")
        if info["distro"]:
            print(f"        {info['distro']} build: fixes are often added without changing the version.")
            print("        Check the installed package version with your package manager before acting.")
        for cv in cves[:5]:
            print(f"        {cv['id']:<16}{cv['score']:>4.1f} {cv['severity']:<9}{cv['summary'][:70]}")
        if len(cves) > 5:
            print(f"        +{len(cves) - 5} more: https://nvd.nist.gov/vuln/search")


def cmd_report(args):
    try:
        result = results.load(args.file)
    except ValueError as error:
        fail(error)
    out = Path(args.out) if args.out else Path(args.file).with_suffix(".html")
    try:
        out.write_text(report.render(result), encoding="utf-8")
    except OSError as error:
        fail(f"Cannot write {out}: {error.strerror}.")
    print(f"Report written to {out}")
    if args.open:
        webbrowser.open(out.resolve().as_uri())


def cmd_watch(args):
    ip, ports = prepare(args)
    path = Path(args.baseline) if args.baseline else watch.baseline_path(ip)
    try:
        old = results.load(path) if path.exists() else None
    except ValueError as error:
        fail(error)

    new = run(args, ip, ports)
    print_result(new)
    print()

    if old is None:
        save_baseline(new, path)
        print(f"First watch: this hunt is now the baseline ({path}).")
        print("Run the same command later to see what changed.")
        return

    changes = watch.compare(old, new)
    if not changes:
        print(f"No changes since the baseline ({old['time']}).")
        return

    print(f"{len(changes)} change(s) since the baseline ({old['time']}):")
    for change in changes:
        print(f"  ! {change['text']}")
    if args.update:
        save_baseline(new, path)
        print("Baseline updated: these changes are now the normal state.")
    else:
        print("If these changes are expected, run again with --update to accept them.")
    sys.exit(1)  # betikler ve zamanlanmış görevler "değişiklik var" diye anlasın


def save_baseline(result, path):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        results.save(result, path)
    except OSError as error:
        fail(f"Cannot save the baseline to {path}: {error.strerror}.")


def add_hunt_options(cmd):
    """hunt ve watch aynı tarama seçeneklerini kullanır."""
    cmd.add_argument("target", help="IP address or name, e.g. 192.168.1.20")
    cmd.add_argument("--ports", help="e.g. 22,80,8000-8100 (default: 20 common ports)")
    cmd.add_argument("--timeout", type=float, default=0.5, help="seconds per port (default 0.5)")
    cmd.add_argument(
        "--banner", action="store_true",
        help="also read each open port's greeting to show program and version",
    )
    cmd.add_argument(
        "--cve", action="store_true",
        help="also look up known vulnerabilities for each version on NVD (needs internet; implies --banner)",
    )
    cmd.add_argument(
        "--checks", action="store_true",
        help="also check if Redis, Elasticsearch, MongoDB or FTP let anyone in "
        "(one harmless request each; FTP tries the public 'anonymous' login once)",
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="lycan",
        description="Open-source threat hunter. Use only on systems you own.",
    )
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    version = commands.add_parser("version", help="Print the installed version.")
    version.set_defaults(func=cmd_version)

    scan_cmd = commands.add_parser("scan", help="List ports listening on this machine.")
    scan_cmd.set_defaults(func=cmd_scan)

    hunt_cmd = commands.add_parser(
        "hunt",
        help="Check which ports are open on a machine in your own network.",
        description="Only private network addresses are allowed (127.x, 10.x, "
        "172.16-31.x, 192.168.x). Hunt only machines you own or may test.",
    )
    add_hunt_options(hunt_cmd)
    hunt_cmd.add_argument("--save", metavar="FILE", help="also save the result as JSON, e.g. hunt.json")
    hunt_cmd.set_defaults(func=cmd_hunt)

    report_cmd = commands.add_parser(
        "report",
        help="Turn a saved hunt (JSON) into an HTML report.",
        description="Example: lycan hunt 192.168.1.20 --cve --save hunt.json, then lycan report hunt.json",
    )
    report_cmd.add_argument("file", help="JSON file saved with lycan hunt --save")
    report_cmd.add_argument("--out", metavar="FILE", help="HTML file to write (default: same name, .html)")
    report_cmd.add_argument("--open", action="store_true", help="open the report in your browser")
    report_cmd.set_defaults(func=cmd_report)

    watch_cmd = commands.add_parser(
        "watch",
        help="Hunt again and show what changed since the baseline.",
        description="The first run saves a baseline. Later runs compare with it and exit with code 1 "
        "if something changed. Same address rules as hunt.",
    )
    add_hunt_options(watch_cmd)
    watch_cmd.add_argument("--baseline", metavar="FILE",
                           help="baseline file (default: ~/.lycan/baselines/<address>.json)")
    watch_cmd.add_argument("--update", action="store_true", help="accept the changes as the new baseline")
    watch_cmd.set_defaults(func=cmd_watch)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Komut yazılmadıysa (sadece "lycan") yardım metnini göster
    if not hasattr(args, "func"):
        parser.print_help()
        return

    args.func(args)
