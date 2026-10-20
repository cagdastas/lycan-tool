# Lycan — araç (Python CLI)

Tanıtım sitesi ayrı projede: `../Lycan` (lycansoc.com). Sitedeki Docs sayfası yalnızca burada gerçekten çalışan komutları anlatmalı.
Kullanıcıyla Türkçe konuş; her adımı kısa ve sade anlat.

## Kurallar
- Yalnızca kendi sistemlerimiz test edilir (kullanıcının bilgisayarı, Kali VM). Başkasını hedefleyen örnek yok.
- Bağımlılıkları az tut; her yeni paketi neden eklediğimizi açıkla.
- Commit e-postası GitHub noreply adresi; kişisel e-posta adresi hiçbir yere yazılmaz.
- Sahte iddia / uydurma çıktı yok.

## Durum (2026-10-20) — sürüm 0.1.0
- ✅ Aşama 0: iskelet, venv (`.venv/`), `lycan version`.
- ✅ Aşama 1: `lycan scan` (psutil ile dinleyen portlar, network/local).
- ✅ Aşama 2 (basit): `lycan hunt <hedef>` TCP connect taraması. Yasal kilit: yalnızca özel ağ adresleri
  (`hunt.check_allowed`), tek makine, en fazla 1024 port, 50 eşzamanlı. Bu kilidi gevşetme; testler (`tests/`) korur.
- GitHub: `cagtas0/lycan-tool` (public). Kurulum: `pip install git+https://github.com/cagtas0/lycan-tool.git`.
- Site (lycansoc.com) pasif kalır; port taraması asla siteden yapılmaz. Sitede yalnızca CLI'yı anlatan bölüm olur.

## Yol haritası
0 iskelet + `lycan version` · 1 `lycan scan` (yerel açık portlar) · 2 `lycan hunt` (ağ tarama, Kali'ye karşı)
3 CVE eşleştirme · 4 `lycan report` · 5 `lycan watch` (baseline/anomali) · 6 test, CI, yayın
