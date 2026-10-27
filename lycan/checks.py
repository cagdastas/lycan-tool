"""lycan hunt --checks: açık kapıdaki programın kapısı kilitli mi, kontrol eder.

Bir veritabanının ağa açık olması kötüdür; ŞİFRESİZ açık olması çok daha kötüdür.
Bu bölüm her programa tek, zararsız bir soru sorar ve cevaba bakar:
    Redis          "PING"            -> "+PONG" ise şifre sormadan cevap verdi
    Elasticsearch  "GET /"           -> küme bilgisi geldiyse kimlik sormadı
    MongoDB        "listDatabases"   -> liste geldiyse kimlik sormadı
    FTP            "anonymous" girişi -> 230 ise herkes girebiliyor

Hiçbir veri okunmaz, değiştirilmez, şifre tahmin edilmez. FTP'deki "anonymous"
girişi tek bir denemedir ve FTP'nin herkese açık giriş için ayırdığı addır.
Yasal kilit hunt ile aynı: yalnızca özel ağ adresleri.
"""

import socket
import struct

from lycan.hunt import check_allowed

TIMEOUT = 2.0


def _talk(ip, port, messages, read_first=False):
    """Bağlanır, mesajları sırayla gönderir, her birinin cevabını döner (en fazla 4 KB)."""
    replies = []
    with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
        if read_first:
            replies.append(sock.recv(4096))  # FTP gibi önce kendisi konuşanlar
        for message in messages:
            sock.sendall(message)
            replies.append(sock.recv(4096))
    return replies


def redis(ip, port):
    reply = _talk(ip, port, [b"PING\r\n"])[0]
    if reply.startswith(b"+PONG"):
        return finding("redis-no-auth", "HIGH", "Redis answers without a password.",
                       "Set 'requirepass' in redis.conf (or use ACL users) and bind Redis to 127.0.0.1.")
    return None  # -NOAUTH (şifre istiyor) ya da -DENIED (korumalı mod): iyi


def elasticsearch(ip, port):
    reply = _talk(ip, port, [f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()])[0]
    if reply.startswith(b"HTTP/") and b" 200 " in reply.split(b"\r\n", 1)[0] and b"cluster_name" in reply:
        return finding("elasticsearch-no-auth", "HIGH", "Elasticsearch answers without a login.",
                       "Turn on security (xpack.security.enabled: true), set passwords and do not expose port 9200.")
    return None


def _bson(fields):
    """Çok küçük bir BSON yazıcı (MongoDB'nin ikili JSON'u). Yalnızca sayı, yazı ve evet/hayır."""
    body = b""
    for name, value in fields:
        key = name.encode() + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + key + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += b"\x10" + key + struct.pack("<i", value)
        else:
            text = value.encode() + b"\x00"
            body += b"\x02" + key + struct.pack("<i", len(text)) + text
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _mongo_ok(reply):
    """Cevaptaki "ok" alanını bulur: 1.0 başarılı demek. Bulamazsa None."""
    mark = reply.find(b"\x01ok\x00")  # 0x01 = ondalık sayı, adı "ok"
    if mark == -1 or len(reply) < mark + 12:
        return None
    return struct.unpack("<d", reply[mark + 4:mark + 12])[0]


def mongodb(ip, port):
    command = _bson([("listDatabases", 1), ("nameOnly", True), ("$db", "admin")])
    payload = struct.pack("<I", 0) + b"\x00" + command  # bayraklar + "gövde" bölümü
    header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2013)  # 2013 = OP_MSG
    reply = _talk(ip, port, [header + payload])[0]
    if _mongo_ok(reply) == 1.0:
        return finding("mongodb-no-auth", "HIGH", "MongoDB lists its databases without a login.",
                       "Turn on authorization (security.authorization: enabled), create users, bind to 127.0.0.1.")
    return None


def ftp(ip, port):
    replies = _talk(ip, port, [b"USER anonymous\r\n", b"PASS anonymous@\r\n", b"QUIT\r\n"], read_first=True)
    if replies[0].startswith(b"220") and replies[2].startswith(b"230"):
        return finding("ftp-anonymous", "MEDIUM", "FTP lets anyone log in as 'anonymous'.",
                       "Turn off anonymous login (vsftpd: anonymous_enable=NO) unless you share public files on purpose.")
    return None


def finding(check_id, severity, title, fix):
    return {"id": check_id, "severity": severity, "title": title, "fix": fix}


# Hangi hizmete hangi kontrol (hunt'taki hizmet adına göre)
CHECKS = {"redis": redis, "elasticsearch": elasticsearch, "mongodb": mongodb, "ftp": ftp}


def run(ip, open_ports):
    """Açık kapılara uygun kontrolleri yapar. Döner: {kapı: bulgu listesi}; kontrolü olmayan kapı yok."""
    check_allowed(ip)
    results = {}
    for p in open_ports:
        check = CHECKS.get(p["service"])
        if not check:
            continue
        try:
            found = check(ip, p["port"])
        except OSError:  # kapandı, cevap vermedi, bağlantı koptu: bulgu yok
            found = None
        results[p["port"]] = [found] if found else []
    return results
