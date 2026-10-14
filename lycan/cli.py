"""Komut satırı: "lycan <komut>" yazınca buradan başlar.

argparse, Python'la birlikte gelen bir kütüphane. Kullanıcının yazdığı
kelimeleri (argümanları) okur ve hangi komutun istendiğini bize söyler.
"""

import argparse

from lycan import __version__


def cmd_version(args):
    # GÖREV: Burayı sen yazacaksın.
    # Ekrana "lycan 0.0.1" yazdır. Sürüm numarasını elle yazma,
    # yukarıda içe aktardığımız __version__ değişkenini kullan.
    print (f"lycan {__version__}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="lycan",
        description="Open-source threat hunter. Use only on systems you own.",
    )
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    version = commands.add_parser("version", help="Print the installed version.")
    version.set_defaults(func=cmd_version)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Komut yazılmadıysa (sadece "lycan") yardım metnini göster
    if not hasattr(args, "func"):
        parser.print_help()
        return

    args.func(args)
