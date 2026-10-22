"""Komut satırı: "lycan <komut>" yazınca buradan başlar.

argparse, Python'la birlikte gelen bir kütüphane. Kullanıcının yazdığı
kelimeleri (argümanları) okur ve hangi komutun istendiğini bize söyler.
"""

import argparse

import sys

from lycan import __version__
from lycan import banner
from lycan import hunt
from lycan import scan


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


def cmd_hunt(args):
    try:
        ports = hunt.parse_ports(args.ports) if args.ports else sorted(hunt.COMMON_PORTS)
        ip = hunt.resolve(args.target)
        hunt.check_allowed(ip)
    except (ValueError, hunt.NotAllowed) as error:
        print(f"lycan: {error}", file=sys.stderr)
        sys.exit(2)

    print(f"Hunting {args.target} ({ip}) on {len(ports)} ports...")
    found = hunt.hunt(ip, ports, timeout=args.timeout)

    if not found:
        print("No open ports found.")
        return

    if not args.banner:
        print()
        print(f"{'PORT':>6}  {'SERVICE':<12}NOTE")
        for f in found:
            print(f"{f['port']:>6}  {f['service']:<12}{f['note']}")
    else:
        print("Reading banners...")
        banners = banner.grab_all(ip, [f["port"] for f in found])
        print()
        print(f"{'PORT':>6}  {'SERVICE':<12}{'VERSION':<30}NOTE")
        for f in found:
            print(f"{f['port']:>6}  {f['service']:<12}{version_text(banners[f['port']]):<30}{f['note']}")
    print()
    print(f"{len(found)} open of {len(ports)} checked.")


def version_text(info):
    """Tabloda gösterilecek sürüm: tanınırsa "OpenSSH 9.2p1", tanınmazsa ham satır."""
    if info is None:
        return "-"  # program hiç konuşmadı
    if info["product"]:
        return f"{info['product']} {info['version']}"
    return info["raw"][:28] or "-"


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
    hunt_cmd.add_argument("target", help="IP address or name, e.g. 192.168.1.20")
    hunt_cmd.add_argument("--ports", help="e.g. 22,80,8000-8100 (default: 20 common ports)")
    hunt_cmd.add_argument("--timeout", type=float, default=0.5, help="seconds per port (default 0.5)")
    hunt_cmd.add_argument(
        "--banner", action="store_true",
        help="also read each open port's greeting to show program and version",
    )
    hunt_cmd.set_defaults(func=cmd_hunt)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Komut yazılmadıysa (sadece "lycan") yardım metnini göster
    if not hasattr(args, "func"):
        parser.print_help()
        return

    args.func(args)
