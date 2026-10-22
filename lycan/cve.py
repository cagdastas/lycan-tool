"""lycan hunt --cve: bulunan program sürümünün bilinen açıklarını (CVE) NVD'den sorar.

NVD (National Vulnerability Database), ABD'nin resmî açık veritabanıdır.
Her ürünün bir "CPE" adı vardır, ör. OpenSSH 9.2p1:
    cpe:2.3:a:openbsd:openssh:9.2:p1:*:*:*:*:*:*
NVD'ye bu adı verince o sürümü etkileyen CVE'leri döner.

Gizlilik: NVD'ye yalnızca ürün adı ve sürüm gider. Taranan makinenin adresi gitmez.
Sonuçlar ~/.lycan/cve-cache.json dosyasında 1 gün saklanır; aynı soru tekrar sorulmaz.

Dürüstlük: NVD yalnızca sürüm numarasına bakar. Debian, Ubuntu gibi dağıtımlar
açığı kapatır ama sürüm numarasını değiştirmez. Bu yüzden sonuçlar "olası" açıktır.
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from lycan import __version__

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = Path.home() / ".lycan" / "cve-cache.json"
CACHE_SECONDS = 24 * 60 * 60  # 1 gün

# banner.py'deki ürün adı -> NVD'deki "üretici:ürün" adları.
# Bazı ürünler NVD'de yıllar içinde iki farklı adla kaydedilmiş, ikisine de sorulur.
CPE_NAMES = {
    "OpenSSH": ["openbsd:openssh"],
    "Apache": ["apache:http_server"],
    "nginx": ["f5:nginx", "nginx:nginx"],
    "Microsoft-IIS": ["microsoft:internet_information_services"],
    "lighttpd": ["lighttpd:lighttpd"],
    "vsftpd": ["vsftpd_project:vsftpd", "beasts:vsftpd"],
    "ProFTPD": ["proftpd:proftpd"],
    "Exim": ["exim:exim"],
    "MariaDB": ["mariadb:mariadb"],
    "MySQL": ["oracle:mysql"],
}

_last_request = 0.0  # son NVD isteğinin zamanı (hız sınırı için)
_memory = {}  # bu çalıştırmada zaten sorulanlar


class NvdError(Exception):
    """NVD'ye ulaşılamadı ya da cevap okunamadı."""


def cpe_names(product, version):
    """Ürün ve sürümden NVD'ye sorulacak CPE adlarını üretir. Bilinmeyen ürün: boş liste.

    "9.2p1" gibi sürümler iki parçaya ayrılır: sürüm "9.2", güncelleme "p1".
    """
    match = re.fullmatch(r"(\d+(?:\.\d+)*)([a-z]\w*)?", version or "")
    if product not in CPE_NAMES or not match:
        return []
    number, update = match.group(1), match.group(2) or "*"
    return [f"cpe:2.3:a:{name}:{number}:{update}:*:*:*:*:*:*" for name in CPE_NAMES[product]]


def _severity(cve):
    """CVSS puanı ve önem derecesi. En yeni ölçüt (4.0 > 3.1 > 3.0 > 2) kullanılır."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        # NVD'nin kendi puanı ("Primary") varsa onu seç
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or "?"
        return float(data.get("baseScore", 0)), severity.upper()
    return 0.0, "?"


def parse(response):
    """NVD cevabından kısa bir liste çıkarır: kimlik, puan, önem, tek satır özet."""
    found = []
    for item in response.get("vulnerabilities", []):
        cve = item["cve"]
        score, severity = _severity(cve)
        summary = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        found.append({
            "id": cve["id"],
            "score": score,
            "severity": severity,
            "summary": " ".join(summary.split())[:200],
        })
    return found


def _wait_for_turn(has_key):
    """NVD hız sınırı: anahtarsız 30 saniyede 5 istek, anahtarla 50. Araya boşluk koyarız."""
    global _last_request
    gap = 0.7 if has_key else 6.5
    wait = _last_request + gap - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last_request = time.monotonic()


def fetch(cpe):
    """NVD'ye tek bir CPE adı için sorar ve ham JSON cevabını döner."""
    key = os.environ.get("NVD_API_KEY")  # isteğe bağlı; ekrana asla basılmaz
    # noRejected: geri çekilmiş (hatalı açılmış) CVE'leri getirme
    url = f"{API}?cpeName={urllib.parse.quote(cpe, safe=':*')}&noRejected"
    headers = {"User-Agent": f"lycan/{__version__}"}
    if key:
        headers["apiKey"] = key

    _wait_for_turn(bool(key))
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as reply:
            return json.load(reply)
    except urllib.error.HTTPError as error:
        raise NvdError(f"NVD answered {error.code}. Try again in a minute.")
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise NvdError(f"Cannot reach NVD ({error}). Check your internet connection.")
    except json.JSONDecodeError:
        raise NvdError("NVD sent an answer that is not JSON.")


def _load_cache():
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}  # dosya yok ya da bozuk: boş başla


def _save_cache(cache):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass  # önbellek yazılamazsa tarama yine de çalışır


def lookup(product, version):
    """Ürün sürümünün olası CVE'lerini döner, en yüksek puanlı önce.

    Bilinmeyen ürün için None döner (NVD'ye hiç sorulmaz).
    """
    names = cpe_names(product, version)
    if not names:
        return None

    cache = _load_cache()
    now = time.time()
    found = {}
    for cpe in names:
        if cpe in _memory:
            cves = _memory[cpe]
        elif cpe in cache and now - cache[cpe]["time"] < CACHE_SECONDS:
            cves = cache[cpe]["cves"]
        else:
            cves = parse(fetch(cpe))
            cache[cpe] = {"time": now, "cves": cves}
            _save_cache(cache)
        _memory[cpe] = cves
        for cve in cves:
            found[cve["id"]] = cve  # iki adda da çıkan CVE bir kez sayılır

    return sorted(found.values(), key=lambda c: (c["score"], c["id"]), reverse=True)
