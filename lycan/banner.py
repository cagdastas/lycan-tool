"""lycan hunt --banner: açık kapının arkasındaki programın adını ve sürümünü okur.

Birçok program bağlantı kurulunca kendini tanıtır. Bu ilk söze "banner" denir:
    SSH  -> "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
    FTP  -> "220 (vsFTPd 3.0.3)"
Web sunucusu ise önce soru bekler; ona tek bir "HEAD /" isteği gönderip
cevaptaki "Server:" satırını okuruz.

Her açık kapıya tek bağlantı açılır, saldırı yapılmaz. Yasal kilit hunt ile aynı.
"""

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

from lycan.hunt import check_allowed

MAX_BYTES = 1024  # karşı taraf ne gönderirse göndersin en fazla bu kadar okunur
WEB_PORTS = {80, 8000, 8008, 8080, 8888}  # beklemeden hemen soru sorulan kapılar
TLS_PORTS = {443, 8443}  # şifreli kapılar: önce TLS el sıkışması gerekir

# Ürün adı ve sürümü bulan kalıplar (regex). Sıra önemli: ilk eşleşen kazanır.
PATTERNS = [
    ("OpenSSH", r"OpenSSH_([\w.]+)"),
    ("Apache", r"Apache/([\d.]+)"),
    ("nginx", r"nginx/([\d.]+)"),
    ("Microsoft-IIS", r"Microsoft-IIS/([\d.]+)"),
    ("lighttpd", r"lighttpd/([\d.]+)"),
    ("vsftpd", r"vsFTPd ([\d.]+)"),
    ("ProFTPD", r"ProFTPD ([\d.]+\w*)"),
    ("Exim", r"Exim ([\d.]+)"),
    ("MariaDB", r"([\d.]+)-MariaDB"),  # MySQL'den önce: MariaDB de MySQL gibi selamlar
    ("MySQL", r"^.{4}\n(\d+\.\d+\.\d+)"),  # MySQL ikili (binary) selam: 4 bayt başlık, sonra 10, sonra sürüm
]


def clean(text):
    """Ekrana basmadan önce görünmeyen karakterleri atar.

    Yazı başka bir makineden geliyor. İçinde terminale renk ya da komut
    veren kaçış kodları (ESC) olabilir. Yalnızca düz harf ve işaretler kalır.
    """
    return "".join(ch for ch in text if " " <= ch <= "~").strip()


def first_line(text):
    """Gösterilecek kısa satır: web için "Server:" değeri, diğerleri için ilk dolu satır."""
    server = re.search(r"^Server:[ \t]*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if server:
        return clean(server.group(1))[:60]
    for line in text.splitlines():
        line = clean(line)
        if len(line) >= 3:
            return line[:60]
    return ""


# Dağıtım işaretleri. Bu dağıtımlar açığı kapatır ama sürüm numarasını değiştirmez
# ("backport"). O zaman sürüme bakarak bulunan CVE'ler yalnızca "olası" olur.
DISTROS = [
    ("Debian", r"Debian|deb\d+u\d+"),
    ("Ubuntu", r"Ubuntu"),
    ("Raspbian", r"Raspbian"),
    ("Red Hat", r"Red Hat|CentOS|Rocky|AlmaLinux|\.el\d+"),
    ("Fedora", r"Fedora"),
    ("FreeBSD", r"FreeBSD"),
]


def distro(text):
    """Banner'da bir Linux/BSD dağıtımının adı geçiyorsa onu döner."""
    for name, pattern in DISTROS:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    return None


def describe(text):
    """Banner yazısından ürün, sürüm ve dağıtımı çıkarır. Tanımazsa tahmin yapmaz."""
    info = {"product": None, "version": None, "raw": first_line(text), "distro": distro(text)}
    for product, pattern in PATTERNS:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            info["product"], info["version"] = product, match.group(1)
            break
    return info


def _tls(sock):
    """Bağlantıyı şifreli hale getirir.

    Sertifikayı doğrulamıyoruz: kendi makinelerimizde sertifika çoğu zaman
    kendinden imzalıdır ve biz yalnızca sürüm okuyoruz, gizli veri göndermiyoruz.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock)


def _recv(sock):
    """Gelen yazıyı okur. Süre dolarsa boş döner."""
    try:
        return sock.recv(MAX_BYTES)
    except socket.timeout:
        return b""


def grab(ip, port, timeout=2.0):
    """Kapıya bağlanır, programın ilk sözünü okur. Hiçbir şey gelmezse None döner."""
    check_allowed(ip)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if port in TLS_PORTS:
                sock = _tls(sock)
            data = b""
            if port not in WEB_PORTS and port not in TLS_PORTS:
                data = _recv(sock)  # SSH, FTP gibi programlar önce kendileri konuşur
            if not data:
                # Sessiz kaldı: belki bir web sunucusu. Tek bir kısa soru soruyoruz.
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                data = _recv(sock)
    except OSError:  # kapı kapandı, reddetti ya da TLS tutmadı
        return None
    if not data:
        return None
    # Bayt -> yazı. latin-1 her baytı bir harfe çevirir, asla hata vermez.
    return describe(data.decode("latin-1"))


def grab_all(ip, ports, timeout=2.0):
    """Birden çok kapının banner'ını okur. Aynı anda en fazla 10 bağlantı."""
    check_allowed(ip)
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = pool.map(lambda p: (p, grab(ip, p, timeout)), ports)
        return dict(results)
