# KUpon Merkezi — A-Z MASTER PROMPT

Rol: Kıdemli web uygulaması mühendisi, AppSec mühendisi, PWA mühendisi ve DevOps mühendisi.

Amaç: `Sokmarket/Kupon` reposu için gerçek, production-ready, demo olmayan; gereksiz dosyaları temizlenmiş; GitHub Pages üzerinde kurulabilir PWA frontend ve ayrı HTTPS analytics backend oluşturmaktır.

Kurallar:
1. Önce mevcut repository ve dosya ağacını analiz et; çalışan kodu gereksiz yere silme.
2. Demo/placeholder hedef kullanma. Gerçek repository ve gerçek deployment değerleri dışında örnek endpoint çalıştırma.
3. Frontend tek ana HTML5 giriş noktası kullansın; responsive, erişilebilir ve mobil öncelikli olsun.
4. PWA için manifest, 192/512 ikon, relative start_url/scope ve root service worker üret. GitHub Pages proje yolu dikkate alınmalıdır.
5. Açılış splash ekranı, ikon, tema renkleri ve install metadata sağla.
6. Tıklama analitiği yalnızca açık kullanıcı rızasından sonra çalışsın.
7. Tıklama kaydında event, target, page, campaign/ref, timestamp ve gerekli teknik başlıkları işle.
8. Ham IP ve ham User-Agent veritabanında saklanmasın; HMAC/SHA-256 ile geri döndürülemez hash kullan.
9. Global CORS kullanma. Production origin allowlist uygula.
10. `/api/report` kimlik doğrulamalı olsun; bearer/admin token secret olarak environment/CI secret üzerinden gelsin.
11. Rate limiting, request-size sınırı, JSON doğrulama ve güvenli hata mesajları uygula.
12. MaxMind veya başka GeoIP kaynağı kullanılıyorsa credential kaynak koda yazılmasın. Country, region, city, timezone, ASN, organization, network ve doğruluk yarıçapını yalnızca sağlayıcı gerçekten döndürüyorsa raporla.
13. Konum verisini kesin fiziksel adres veya kişi kimliği gibi sunma.
14. SQLite'ı local/dev için kullan; production'da gerekiyorsa güvenilir managed DB'ye geçiş noktası açık olsun.
15. GitHub Pages frontend ile backend'i aynı process sanma; statik frontend yalnızca HTTPS analytics API'ye event gönderir.
16. Service worker analytics POST isteklerini cache'leme.
17. GitHub Actions ile syntax, JSON, smoke test ve güvenlik kontrolleri çalıştır.
18. `.env`, token, key, pem, database, log, backup ve runtime dosyalarını Git'e alma.
19. Gereksiz `FIX-*`, `FINAL-*`, timestamp backup ve test çıktılarının production repository'de kalmasına izin verme.
20. Son aşamada repository'yi A-Z denetle; broken links, wrong paths, port mismatch, missing icons, missing manifest, missing service worker, endpoint mismatch, CORS, auth, secret leakage ve deployment path sorunlarını düzelt.
21. Her değişiklikten sonra gerçek dosyalar üzerinden test et; varsayım yapma.
22. Son çıktıda dosya ağacını, deployment URL'sini, analytics API URL'sini, rapor endpoint'ini, test sonuçlarını ve kalan tekil manuel secret/deployment adımını açıkça belirt.

Başarı ölçütü: `Sokmarket/Kupon` içinde temiz, anlaşılır, kurulabilir PWA + consent-based click analytics + authenticated report API; gizli veri sızıntısı yok; frontend/backend endpointleri uyumlu; GitHub Pages pathleri doğru; CI yeşil.
