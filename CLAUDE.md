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
- 🔶 Aşama 3 (2026-10-23): 3a+3b+3c kodu tamam, henüz push yok, sürüm hâlâ 0.1.0.
  `--banner` (`lycan/banner.py`): açık kapının ilk sözünü okur (web kapılarına tek `HEAD /`, 443/8443 TLS),
  regex ile ürün+sürüm ve dağıtım (Debian/Ubuntu…) çıkarır; uzaktan gelen yazı ekrana basılmadan temizlenir.
  `--cve` (`lycan/cve.py`): NVD API 2.0'a `cpeName` ile sorar (`virtualMatchString` sürüm aralıklarını
  tutmuyor, 0 döndü; `cpeName` + `*` güncelleme alanı çalışıyor). Ürün→CPE tablosu `CPE_NAMES`
  (nginx ve vsftpd iki adla). Anahtarsız 6,5 sn aralık, `NVD_API_KEY` isteğe bağlı. Önbellek
  `~/.lycan/cve-cache.json`, 1 gün. Sonuç "olası" diye yazılır; dağıtım varsa backport uyarısı.
- 🔶 Aşama 4+5 (2026-10-24, commit yok/sorulacak): `lycan/results.py` taramayı tek sözlükte toplar
  (`collect`, `save`/`load`, biçim `format: 1`); `hunt --save x.json`. `lycan report x.json [--out] [--open]`
  (`lycan/report.py`): tek dosya HTML, CSP `default-src 'none'`, her değer `html.escape`, CVE bağlantısı
  yalnızca `CVE-\d{4}-\d+` kimliğe. `lycan watch <hedef>` (`lycan/watch.py`): ilk çalıştırma temeli
  `~/.lycan/baselines/<ip>.json`'a yazar; sonra açılan/kapanan kapı, sürüm değişimi, yeni CVE; fark varsa
  çıkış kodu 1, `--update` kabul eder.
  Sırada: Kali VM'de gerçek deneme, sonra 0.2.0 + push (kullanıcıya sor). Eksikler: UDP, yapılandırma
  kontrolleri (Redis/Mongo kimliksiz erişim; FTP anonim giriş yalnızca açık seçenekle).
- GitHub: `cagdastas/lycan-tool` (public). Kurulum: `pip install git+https://github.com/cagdastas/lycan-tool.git`.
- Site (lycansoc.com) pasif kalır; port taraması asla siteden yapılmaz. Sitede yalnızca CLI'yı anlatan bölüm olur.

## Yol haritası
0 iskelet + `lycan version` · 1 `lycan scan` (yerel açık portlar) · 2 `lycan hunt` (ağ tarama, Kali'ye karşı)
3 CVE eşleştirme · 4 `lycan report` · 5 `lycan watch` (baseline/anomali) · 6 test, CI, yayın
