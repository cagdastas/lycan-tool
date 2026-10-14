# Lycan — araç (Python CLI)

Tanıtım sitesi ayrı projede: `../Lycan` (lycansoc.com). Sitedeki Docs sayfası yalnızca burada gerçekten çalışan komutları anlatmalı.
Kullanıcı Türkçe konuşur ve öğreniyor: "birlikte yazalım" modu. Her adımda kısaca açıkla, küçük parçaları kullanıcı yazsın, sen kontrol et.

## Kurallar
- Yalnızca kendi sistemlerimiz test edilir (kullanıcının bilgisayarı, Kali VM). Başkasını hedefleyen örnek yok.
- Bağımlılıkları az tut; her yeni paketi neden eklediğimizi açıkla.
- Commit e-postası GitHub noreply adresi; kullanıcının Gmail adresini hiçbir yere yazma.
- Sahte iddia / uydurma çıktı yok.

## Yol haritası
0 iskelet + `lycan version` · 1 `lycan scan` (yerel açık portlar) · 2 `lycan hunt` (ağ tarama, Kali'ye karşı)
3 CVE eşleştirme · 4 `lycan report` · 5 `lycan watch` (baseline/anomali) · 6 test, CI, yayın
