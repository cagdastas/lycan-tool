"""lycan watch: bugünkü taramayı daha önce kaydedilmiş "temel" (baseline) taramayla karşılaştırır.

Fikir basit: makinenin normal hâlini bir kez kaydet. Sonra her taramada farkı göster.
"Dün kapalıydı, bugün 3389 açık" bir anomalidir: ya biri bir program kurdu,
ya da bir saldırgan arka kapı açtı. Güvenlik ekipleri (SOC) bunu her gün yapar.
"""

import re
from pathlib import Path

from lycan.results import version_text

BASELINE_DIR = Path.home() / ".lycan" / "baselines"


def baseline_path(ip):
    """Hedef için varsayılan temel dosyası: ~/.lycan/baselines/192.168.1.20.json"""
    safe = re.sub(r"[^0-9A-Za-z.]", "_", ip)  # IPv6'daki ":" dosya adında sorun çıkarır
    return BASELINE_DIR / f"{safe}.json"


def compare(old, new):
    """İki tarama arasındaki farkları liste olarak döner. Fark yoksa boş liste."""
    changes = []
    before = {p["port"]: p for p in old["open"]}
    after = {p["port"]: p for p in new["open"]}

    for port in sorted(after.keys() - before.keys()):
        changes.append({"kind": "opened", "port": port,
                        "text": f"Port {port} ({after[port]['service']}) is now OPEN. It was closed before."})
    for port in sorted(before.keys() - after.keys()):
        changes.append({"kind": "closed", "port": port,
                        "text": f"Port {port} ({before[port]['service']}) is now closed."})

    for port in sorted(before.keys() & after.keys()):
        a, b = before[port], after[port]
        # Sürüm yalnızca iki taramada da okunduysa karşılaştırılır
        if old.get("banners") and new.get("banners"):
            was, now = version_text(a.get("banner")), version_text(b.get("banner"))
            if was != now:
                changes.append({"kind": "version", "port": port,
                                "text": f"Port {port} changed: {was} -> {now}"})
        if a.get("findings") is not None and b.get("findings") is not None:
            for f in b["findings"]:
                if f["id"] not in {x["id"] for x in a["findings"]}:
                    changes.append({"kind": "new_finding", "port": port,
                                    "text": f"Port {port}: new problem: {f['title']}"})
        if a.get("cves") is not None and b.get("cves") is not None:
            fresh = sorted({c["id"] for c in b["cves"]} - {c["id"] for c in a["cves"]})
            if fresh:
                shown = ", ".join(fresh[:5]) + (f" (+{len(fresh) - 5} more)" if len(fresh) > 5 else "")
                changes.append({"kind": "new_cve", "port": port,
                                "text": f"Port {port}: {len(fresh)} new possible CVEs: {shown}"})
    return changes
