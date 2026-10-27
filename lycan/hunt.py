"""lycan hunt: kendi ağındaki bir makinenin açık kapılarını dışarıdan kontrol eder.

scan "evin içinden" bakar (işletim sistemine sorar). hunt ise sokaktan bakar:
her kapıyı tek tek çalar, açılanı not eder. Buna "TCP connect taraması" denir.

Yasal sınır: yalnızca özel ağ adresleri (127.x, 10.x, 172.16-31.x, 192.168.x)
taranır. İnternetteki adresler reddedilir. İzinsiz tarama suç olabilir.
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

# En sık rastlanan kapılar ve neden önemli oldukları
COMMON_PORTS = {
    21: ("ftp", "File transfer, often sends passwords in plain text."),
    22: ("ssh", "Remote login. Fine if passwords are strong or keys are used."),
    23: ("telnet", "Remote login with no encryption. Should be closed."),
    25: ("smtp", "Mail server."),
    53: ("dns", "Name server."),
    80: ("http", "Web server without encryption."),
    110: ("pop3", "Mail download, often unencrypted."),
    135: ("msrpc", "Windows remote services. Keep it off untrusted networks."),
    139: ("netbios", "Old Windows file sharing."),
    143: ("imap", "Mail access, often unencrypted."),
    443: ("https", "Encrypted web server."),
    445: ("smb", "Windows file sharing. WannaCry spread through this port."),
    3306: ("mysql", "Database. Should not be reachable from other machines."),
    3389: ("rdp", "Windows remote desktop. A common attack target."),
    5432: ("postgresql", "Database. Should not be reachable from other machines."),
    5900: ("vnc", "Remote desktop, often weakly protected."),
    6379: ("redis", "Database, often runs with no password."),
    8080: ("http-alt", "Alternative web server, often a test or admin panel."),
    8443: ("https-alt", "Alternative encrypted web server."),
    27017: ("mongodb", "Database, often runs with no password."),
}

# Varsayılan listede olmayan ama adını bildiğimiz kapılar (--ports ile taranınca tanınır)
MORE_PORTS = {
    9200: ("elasticsearch", "Search database, often runs with no login."),
}

MAX_PORTS = 1024  # bir seferde en fazla bu kadar kapı (ağı boğmamak için)


class NotAllowed(Exception):
    """Hedef taranmasına izin verilmeyen bir adres."""


def resolve(target):
    """Adı (ör. kali.local) IP adresine çevirir."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise NotAllowed(f"Cannot find '{target}'. Check the name or use an IP address.")


def check_allowed(ip):
    """Yalnızca kendi ağımızdaki adreslere izin verir, değilse NotAllowed fırlatır."""
    addr = ipaddress.ip_address(ip)
    if addr.is_unspecified or addr.is_multicast:
        raise NotAllowed(f"{ip} is not a single machine.")
    if not (addr.is_private or addr.is_loopback):
        raise NotAllowed(
            f"{ip} is a public internet address. Lycan only hunts on your own "
            "network (127.x, 10.x, 172.16-31.x, 192.168.x). Scanning systems you "
            "don't own without permission can be a crime."
        )


def parse_ports(text):
    """"22,80,8000-8010" gibi bir yazıyı port listesine çevirir."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                raise ValueError(f"Range '{part}' goes backwards.")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("No ports given.")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"At most {MAX_PORTS} ports per hunt.")
    return sorted(ports)


def is_open(ip, port, timeout):
    """Kapıyı çalar: bağlantı kurulursa açık demektir."""
    with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def hunt(ip, ports, timeout=0.5):
    """Açık kapıları bulur. Aynı anda en fazla 50 kapı çalınır."""
    check_allowed(ip)
    with ThreadPoolExecutor(max_workers=50) as pool:
        results = pool.map(lambda p: (p, is_open(ip, p, timeout)), ports)
        open_ports = [p for p, is_up in results if is_up]

    found = []
    for port in open_ports:
        service, note = COMMON_PORTS.get(port) or MORE_PORTS.get(port, ("?", ""))
        found.append({"port": port, "service": service, "note": note})
    return found
