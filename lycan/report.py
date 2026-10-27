"""lycan report: kaydedilmiş bir taramadan tek dosyalık HTML rapor üretir.

Rapor tarayıcıda açılır, internet gerekmez (dış dosya, yazı tipi, script yok).

Güvenlik: banner yazıları taranan makineden gelir. İçinde "<script>" gibi
HTML olabilir. Bu yüzden rapora giren HER değer html.escape ile kaçırılır;
tarayıcı onu kod olarak değil, düz yazı olarak gösterir (XSS koruması).
"""

import html
import re

from lycan.results import RISKY_PORTS, all_findings, counts, version_text

CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")  # bağlantıya yalnızca gerçek CVE kimliği girer
SEVERITY_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}

STYLE = """
:root { --bg:#03070f; --panel:#0a1322; --line:#1b2a42; --text:#dce8f7; --dim:#8ea3bf;
        --ice:#9fd4ff; --amber:#f0b44c; --ember:#e2553a; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 system-ui, "Segoe UI", sans-serif; }
main { max-width:980px; margin:0 auto; padding:40px 16px 64px; }
h1 { font-size:1.9rem; margin:0 0 4px; letter-spacing:.02em; }
h2 { font-size:1.15rem; margin:36px 0 12px; color:var(--ice); text-transform:uppercase; letter-spacing:.08em; }
.meta { color:var(--dim); margin:0; }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:12px; margin-top:24px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
.card b { display:block; font-size:2rem; line-height:1.1; }
.card span { color:var(--dim); font-size:.9rem; }
.card.alert b { color:var(--ember); } .card.warn b { color:var(--amber); }
ol.todo { padding-left:22px; } ol.todo li { margin:6px 0; }
.wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:12px; }
th, td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--dim); font-weight:600; font-size:.85rem; text-transform:uppercase; letter-spacing:.05em; }
tr:last-child td { border-bottom:0; }
code { font-family:Consolas, "Cascadia Mono", monospace; font-size:.92em; }
.tag { display:inline-block; padding:1px 8px; border-radius:999px; font-size:.78rem; font-weight:700; }
.crit { background:#5c1a10; color:#ffb4a5; } .high { background:#4a2410; color:#ffc59a; }
.med { background:#3d3210; color:#ffe08a; } .low { background:#123049; color:var(--ice); }
.note { color:var(--dim); font-size:.9rem; }
a { color:var(--ice); }
footer { margin-top:40px; color:var(--dim); font-size:.85rem; border-top:1px solid var(--line); padding-top:16px; }
"""


def e(value):
    """Kısaltma: her değeri HTML'e girmeden önce kaçır."""
    return html.escape(str(value), quote=True)


def _todo(result):
    """"Önce bunları yap" listesi: kritik/yüksek CVE'li sürümler önce, sonra riskli kapılar."""
    items = [f"Port {port}: {f['title']} {f['fix']}" for port, f in all_findings(result)]
    by_risk = sorted(
        (p for p in result["open"] if p.get("cves")),
        key=lambda p: (counts(p["cves"])["CRITICAL"], counts(p["cves"])["HIGH"]),
        reverse=True,
    )
    for p in by_risk:
        c = counts(p["cves"])
        if c["CRITICAL"] or c["HIGH"]:
            text = (f"Port {p['port']} runs {version_text(p['banner'])} with {c['CRITICAL']} critical and "
                    f"{c['HIGH']} high possible CVEs. Update it, then hunt again.")
            if p["banner"].get("distro"):
                text += f" ({p['banner']['distro']} may already have fixed some: check the package version.)"
            items.append(text)
    for p in result["open"]:
        if p["port"] in RISKY_PORTS:
            items.append(f"Port {p['port']} ({p['service']}) is open: {p['note']} "
                         "Close it or allow it only from machines that need it.")
    return items


def render(result):
    """Sonuç sözlüğünden tam bir HTML sayfası (yazı) üretir."""
    open_ports = result["open"]
    total = {"CRITICAL": 0, "HIGH": 0}
    for p in open_ports:
        c = counts(p.get("cves"))
        total["CRITICAL"] += c["CRITICAL"]
        total["HIGH"] += c["HIGH"]
    risky = sum(p["port"] in RISKY_PORTS for p in open_ports)

    out = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        # Rapor hiçbir dış kaynak yüklemez, script çalıştırmaz
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>Lycan report: {e(result['target'])}</title>",
        f"<style>{STYLE}</style></head><body><main>",
        f"<h1>Lycan report: {e(result['target'])}</h1>",
        f"<p class=\"meta\">{e(result['ip'])} · {e(result['time'])} · {e(result['ports_checked'])} ports checked</p>",
        '<div class="cards">',
        f'<div class="card"><b>{len(open_ports)}</b><span>open ports</span></div>',
        f'<div class="card{" warn" if risky else ""}"><b>{risky}</b><span>risky ports open</span></div>',
    ]
    if result.get("checks"):
        problems = len(all_findings(result))
        out.append(f'<div class="card{" alert" if problems else ""}"><b>{problems}</b><span>configuration problems</span></div>')
    if result.get("cve_lookup"):
        out += [
            f'<div class="card{" alert" if total["CRITICAL"] else ""}"><b>{total["CRITICAL"]}</b><span>critical possible CVEs</span></div>',
            f'<div class="card{" warn" if total["HIGH"] else ""}"><b>{total["HIGH"]}</b><span>high possible CVEs</span></div>',
        ]
    out.append("</div>")

    todo = _todo(result)
    out.append("<h2>Do these first</h2>")
    if todo:
        out.append('<ol class="todo">' + "".join(f"<li>{e(t)}</li>" for t in todo) + "</ol>")
    else:
        out.append('<p class="note">Nothing urgent found in this hunt.</p>')

    pairs = all_findings(result)
    if pairs:
        out.append("<h2>Configuration problems</h2>")
        out.append('<div class="wrap"><table><tr><th>Port</th><th>Risk</th><th>Problem</th><th>Fix</th></tr>')
        for port, f in pairs:
            css = SEVERITY_CLASS.get(f["severity"], "low")
            out.append(f'<tr><td><code>{e(port)}</code></td><td><span class="tag {css}">{e(f["severity"])}</span></td>'
                       f'<td>{e(f["title"])}</td><td class="note">{e(f["fix"])}</td></tr>')
        out.append("</table></div>")

    out.append("<h2>Open ports</h2>")
    if not open_ports:
        out.append('<p class="note">No open ports found.</p>')
    else:
        out.append('<div class="wrap"><table><tr><th>Port</th><th>Service</th><th>Version</th><th>CVEs</th><th>Note</th></tr>')
        for p in open_ports:
            out.append(
                f"<tr><td><code>{e(p['port'])}</code></td><td>{e(p['service'])}</td>"
                f"<td><code>{e(version_text(p.get('banner')))}</code></td><td>{_cve_cell(p, result)}</td>"
                f"<td class=\"note\">{e(p['note'])}</td></tr>"
            )
        out.append("</table></div>")

    for p in open_ports:
        if p.get("cves"):
            out.append(f"<h2>Port {e(p['port'])}: {e(version_text(p['banner']))}</h2>")
            if p["banner"].get("distro"):
                out.append(f'<p class="note">{e(p["banner"]["distro"])} build: fixes are often added without '
                           "changing the version. Check the installed package version before acting.</p>")
            out.append('<div class="wrap"><table><tr><th>CVE</th><th>Score</th><th>Summary</th></tr>')
            for c in p["cves"][:15]:
                out.append(f"<tr><td>{_cve_link(c['id'])}</td><td>{_tag(c)}</td><td>{e(c['summary'])}</td></tr>")
            out.append("</table></div>")
            if len(p["cves"]) > 15:
                out.append(f'<p class="note">+{len(p["cves"]) - 15} more in the JSON file.</p>')

    out += [
        "<footer>CVEs are <b>possible</b> matches: NVD only looks at the version number. "
        "Hunt only machines you own or may test. "
        f"Made with Lycan {e(result['lycan'])} · https://lycansoc.com</footer>",
        "</main></body></html>",
    ]
    return "\n".join(out)


def _cve_cell(p, result):
    if not result.get("cve_lookup") or not (p.get("banner") or {}).get("product"):
        return "-"
    if p.get("cve_error"):
        return '<span class="note">lookup failed</span>'
    if p.get("cves") is None:
        return '<span class="note">product not in list</span>'
    c = counts(p["cves"])
    if not p["cves"]:
        return "none known"
    return f"{len(p['cves'])} ({c['CRITICAL']} critical, {c['HIGH']} high)"


def _cve_link(cve_id):
    if CVE_ID.fullmatch(cve_id):
        return f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}">{cve_id}</a>'
    return e(cve_id)  # beklenmeyen biçim: bağlantı yok, yalnızca kaçırılmış yazı


def _tag(c):
    css = SEVERITY_CLASS.get(c["severity"], "low")
    return f'<span class="tag {css}">{e(c["score"])} {e(c["severity"])}</span>'
