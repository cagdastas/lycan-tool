"""Bir hunt taramasının sonucunu tek bir sözlükte toplar.

Ekrana yazmak, JSON dosyasına kaydetmek, HTML rapor yapmak ve iki taramayı
karşılaştırmak (watch) hep bu sözlükten yapılır. Böylece tarama bir kez yapılır,
sonucu birçok yerde kullanılır.
"""

import json
from datetime import datetime, timezone

from lycan import __version__, banner, checks, cve, hunt

FORMAT = 1  # dosya biçiminin sürümü; yapı değişirse artar

# Kendi başına risk taşıyan kapılar (ağa açık olmaları tek başına sorun)
RISKY_PORTS = {21, 23, 135, 139, 445, 3306, 3389, 5432, 5900, 6379, 27017}


def collect(target, ip, ports, timeout=0.5, read_banners=False, find_cves=False, run_checks=False,
            progress=print):
    """Taramayı yapar ve sonucu sözlük olarak döner. progress: ara mesajları yazan fonksiyon."""
    if find_cves:
        read_banners = True  # CVE aramak için önce sürümü okumak gerekir

    found = hunt.hunt(ip, ports, timeout=timeout)  # yasal kilit (check_allowed) burada da çalışır

    banners = {}
    if read_banners and found:
        progress("Reading banners...")
        banners = banner.grab_all(ip, [f["port"] for f in found])

    known = [f for f in found if banners.get(f["port"]) and banners[f["port"]]["product"]]
    if find_cves and known:
        progress("Looking up known vulnerabilities on NVD.")
        progress('Only the product and version are sent (e.g. "OpenSSH 9.2p1"), never the address.')

    findings = {}
    if run_checks and found:
        progress("Checking configuration (one harmless question per service)...")
        findings = checks.run(ip, found)

    for f in found:
        f["findings"] = findings.get(f["port"])  # None: bu kapı için kontrol yok ya da istenmedi
        info = banners.get(f["port"])
        f["banner"] = info
        f["cves"] = None  # None: hiç sorulmadı ya da ürün Lycan'ın listesinde yok
        f["cve_error"] = None
        if find_cves and info and info["product"]:
            try:
                f["cves"] = cve.lookup(info["product"], info["version"])
            except cve.NvdError as error:
                f["cve_error"] = str(error)

    return {
        "lycan": __version__,
        "format": FORMAT,
        "target": target,
        "ip": ip,
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ports_checked": len(ports),
        "banners": read_banners,
        "cve_lookup": find_cves,
        "checks": run_checks,
        "open": found,
    }


def version_text(info):
    """Gösterilecek sürüm: tanınırsa "OpenSSH 9.2p1", tanınmazsa ham satır, hiç konuşmadıysa "-"."""
    if not info:
        return "-"
    if info["product"]:
        return f"{info['product']} {info['version']}"
    return info["raw"] or "-"


def counts(cves):
    """Önem derecesine göre sayılar: {"CRITICAL": 3, "HIGH": 10, ...}."""
    result = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for c in cves or []:
        if c["severity"] in result:
            result[c["severity"]] += 1
    return result


def all_findings(result):
    """Tüm yapılandırma bulguları, kapı numarasıyla: [(kapı, bulgu), ...], yüksek risk önce."""
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    pairs = [(p["port"], f) for p in result["open"] for f in p.get("findings") or []]
    return sorted(pairs, key=lambda pair: order.get(pair[1]["severity"], 3))


def save(result, path):
    """Sonucu okunabilir JSON olarak kaydeder."""
    with open(path, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)


def load(path):
    """Kaydedilmiş sonucu okur. Lycan dosyası değilse anlaşılır bir hata verir."""
    try:
        with open(path, encoding="utf-8") as file:
            result = json.load(file)
    except OSError as error:
        raise ValueError(f"Cannot open {path}: {error.strerror}.")
    except json.JSONDecodeError:
        raise ValueError(f"{path} is not a JSON file.")
    if not isinstance(result, dict) or result.get("format") != FORMAT or not isinstance(result.get("open"), list):
        raise ValueError(f"{path} is not a Lycan hunt result (save one with: lycan hunt <target> --save {path}).")
    return result
