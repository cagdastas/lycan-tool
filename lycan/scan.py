"""lycan scan: bu bilgisayarda dinleyen (bağlantı bekleyen) portları bulur.

Her dinleyen port bir "kapı"dır. Saldırganın ilk işi açık kapıları bulmaktır,
biz de önce kendi kapılarımızı görüyoruz.
"""

import socket

import psutil


def is_exposed(address):
    """Kapı sokağa mı açılıyor? Ağdan erişilebilirse True, yalnızca bu bilgisayarsa False."""
    # 127.0.0.1 (IPv4) ve ::1 (IPv6) "bu bilgisayarın kendisi" demek: iç kapı
    if address == "127.0.0.1" or address == "::1":
        return False
    # Geri kalan her adres (0.0.0.0 dahil) ağdaki diğer makinelerden çalınabilir
    return True


def process_name(pid):
    """PID numarasından program adını bulur (ör. 4 → System)."""
    if not pid:
        return "?"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        # Program bu arada kapanmış olabilir ya da adını görmeye iznimiz yoktur
        return "?"


def listening_ports():
    """Dinleyen her port için bir sözlük döndürür, port numarasına göre sıralı."""
    found = {}
    for conn in psutil.net_connections(kind="inet"):
        is_tcp = conn.type == socket.SOCK_STREAM

        # TCP'de "dinliyor" durumu açıkça yazar. UDP'de durum yoktur;
        # karşı tarafı (raddr) olmayan UDP soketi bağlantı bekliyor demektir.
        if is_tcp and conn.status != psutil.CONN_LISTEN:
            continue
        if not is_tcp and conn.raddr:
            continue

        proto = "TCP" if is_tcp else "UDP"
        key = (proto, conn.laddr.ip, conn.laddr.port)
        found[key] = {
            "proto": proto,
            "address": conn.laddr.ip,
            "port": conn.laddr.port,
            "pid": conn.pid,
            "process": process_name(conn.pid),
        }

    return sorted(found.values(), key=lambda p: (p["port"], p["proto"]))
