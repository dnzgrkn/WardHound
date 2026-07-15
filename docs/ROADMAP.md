# WardHound — Yoğun Build Roadmap

Hazırlanma: 9 Temmuz 2026 | Tempo: 20+ saat/hafta, ama ilerleme takvim haftasına değil aşama tamamlanmasına göre — "Aşama N" başlıkları sabit bir hafta demek değil, sıralı bir iş birimi demek. Hedef: Company X'teki erişim penceresi kapanmadan önce gerçek NAC/PAM/AD trafiğine karşı test edilebilecek bir MVP çıkarmak.

## Neden sıralamayı değiştiriyoruz

`12_Month_Career_Roadmap.md`'de WardHound Phase 3'te (Ocak–Mart 2027), CCNA ve Network Automation Platform'dan sonra planlanmıştı. Bunu öne çekmenin tek gerçek gerekçesi var ama güçlü bir gerekçe: şu an elinde canlı bir Zero Trust altyapısı (PacketFence, JumpServer, AD Tiering) var ve Company X ile olan görev süresi sona erince bu erişim kayboluyor. Bir correlation/AI platformunu gerçek event'lere karşı test edebilmek, sentetik veriyle test etmekten kıyaslanamayacak kadar değerli — bu iddiayı portföyde kanıtlanabilir kılan şey de bu. Riski açık söyleyeyim: CCNA'yı erteliyorsun ve bu roadmap'i job-search takvimini birkaç ay kaydırabilir. Kabul edilebilir bir trade-off, çünkü zaman-kısıtlı fırsat (Company X erişimi) geri gelmeyecek, sertifika her zaman alınabilir.

**Gizlilik kuralı devam ediyor:** Company X'teki gerçek hostname/IP/kullanıcı adı/şirket-özel veri asla public repo'ya girmeyecek. Gerçek event'lerle sadece lokal/private test yapılacak; public repo'ya giden her şey (örnek loglar, case study, demo) proje gizlilik kuralına göre anonimleştirilecek — "orta ölçekli bir kurumsal ortam" gibi genellenmiş ifadeler, gerçek RADIUS secret/SNMP community/kullanıcı adı yok.

## Kritik yol riski

Eğer Company X ile olan süreçte kalan zaman azalırsa, Aşama 1–2 (iskelet + gerçek collector'lar) mutlaka önce bitmeli — geri kalan her şey sentetik veriyle de geliştirilebilir, ama collector'ların gerçek PacketFence/JumpServer/AD event'lerine karşı doğrulanması sadece şimdi mümkün. Erişim penceresi kısalırsa Aşama 1 ve 2'yi birleştirip sıkıştır.

---

## Aşama 1 — İskelet ve Sözleşmeler ✅ tamamlandı

Docker Compose ile FastAPI + PostgreSQL + Redis + Celery worker iskeleti. Pydantic v2 ile `RawEvent` ve `NormalizedEvent` şemalarını tasarla — bu proje boyunca her katmanın konuştuğu ortak sözleşme bu olacak, en başta doğru kurulmalı. Collector interface'ini (abstract base class) tanımla: her collector `raw bytes/dict → RawEvent` üretir. ADR-001 yaz: neden bu stack, neden rule-based correlation (ML değil) ile başlıyoruz. CI: ruff + mypy + pytest + GitHub Actions. Çıktı: `docker-compose up` ile ayakta duran, sahte bir event'i uçtan uca DB'ye yazan boş bir pipeline.

## Aşama 2 — Gerçek Collector'lar (en yüksek öncelik) ✅ tamamlandı

PacketFence syslog collector (UDP/TCP listener, RFC5424 parse), JumpServer collector (REST API polling — session start/end, privileged command, abnormal session), AD collector (Windows Event Forwarding veya WinRM üzerinden Security log okuma — 4625 failed auth, 4740 lockout, 4728 group membership change). Her biri normalization layer'dan geçip `NormalizedEvent` olarak Postgres'e yazılıyor. Bu aşama Company X ortamına karşı gerçek doğrulama yapılacak aşama — mümkünse burayı geciktirme.

## Aşama 3 — Correlation + Policy + Risk Engine ✅ tamamlandı

Zaman-pencereli correlation kuralları (örn. aynı entity'de N dakika içinde AD auth fail + PacketFence quarantine + JumpServer yeni session = tek incident). Policy engine: Tier 0 kaynağa PAW olmayan cihazdan erişim, VLAN quarantine bypass denemesi gibi ihlaller. Risk engine: başlangıçta deterministik, ağırlıklı skor (ML'e sonra geçilir — "never over-engineer" prensibi). Bu üç motor birbirinden bağımsız, ayrı test edilebilir modüller olmalı.

## Aşama 4 — AI Analysis Engine ✅ tamamlandı

Anthropic Claude + Instructor ile structured output: `RootCauseAnalysis` Pydantic modeli (`probable_cause`, `confidence`, `evidence: list[Evidence]`, `recommended_actions: list[Action]`, `side_effects: str`). Correlated incident'i context olarak ver, NAC/PAM/AD domain'ine özel few-shot örnekler ekle. Serbest metin çıktı yok — her şey typed. Bu katman projenin asıl farkı, en çok zaman ayrılması gereken yer.

## Aşama 5 — Response Engine (simüle) ✅ tamamlandı

Action modelleri: Quarantine Device, Disable User, Block IP, Close Session, Require MFA, Notify Administrator, Create Incident, Require Manual Approval. Hepsi başta simüle — audit log'a yazılır, gerçek sisteme dokunmaz. Human-in-the-loop approval workflow zorunlu, özellikle privileged action'lar için (bu, career roadmap'inde AI güvenilirliği için vurgulanan nokta — "otonom remediation yok" mesajı hem doğru hem satılabilir).

## Aşama 6 — Dashboard ✅ tamamlandı

React + TypeScript + Tailwind + shadcn/ui. Incident listesi, incident detail (AI açıklaması + confidence + kanıt + önerilen aksiyon), approve/reject UI, WebSocket ile realtime güncelleme. Bu aşama demo edilebilirlik için kritik — interview'da ekranı açıp gösterebileceğin katman.

## Aşama 7 — Observability + Test Sertliği ✅ tamamlandı

Prometheus metrikleri, Grafana dashboard, OpenTelemetry tracing. Correlation/policy/risk engine'lerde pytest coverage. mypy + ruff temiz. Structured logging, secrets yönetimi (`.env` + Docker secrets, asla commit edilmez). Kısa bir threat model notu (bu platformun kendisi de bir security tool, kendi saldırı yüzeyini düşünmen bekleniyor).

## Aşama 8 — Dokümantasyon ve Portföy Cilası ✅ tamamlandı

README (mermaid mimari diyagramı, kurulum, demo GIF), ADR'ları topla, anonimleştirilmiş case study ("gerçek kurumsal Zero Trust altyapısına karşı test edildi" — client ismi yok), tek komutla `docker-compose up` demo, v2 roadmap notu (ML tabanlı anomaly detection, multi-tenant, SOAR entegrasyonları — şimdi yapma, sadece yaz).

## Aşama 9 — Kalıcı Veri Katmanı (v2'nin ilk maddesi) ✅ tamamlandı

In-memory store'lar (`InMemoryEventStore`, `InMemoryIncidentStore`, `InMemoryApprovalStore`) SQLAlchemy async modelleri, Alembic migration'ları ve Postgres-backed repository'lerle değiştirildi — restart sonrası incident, event, analiz ve approval geçmişi korunuyor, uçtan uca doğrulandı (`docker compose restart api` sonrası incident hâlâ erişilebilir). İlk implementasyonda `EventStore`/`IncidentStore`/`ApprovalStore` Protocol'leri senkron kalmıştı ve Postgres'e gerçek async I/O yaptırmak için her çağrıda yeni thread + yeni event loop açan bir shim kullanılmıştı — bu, event loop'u bloke edip API'yi eşzamanlı yük altında fiilen sıralı hale getiriyordu. Ayrı bir düzeltmeyle (`fix/async-store-protocols`) Protocol'ler native async yapıldı, shim tamamen kaldırıldı, ve eşzamanlı isteklerin gerçekten iç içe geçtiğini kanıtlayan bir regresyon testi eklendi. Detaylar: `docs/adr/0009-persistent-data-layer.md` ve amendment bölümü.

## Aşama 10 — Auth0 Kimlik Federasyonu (v2'nin ikinci maddesi) ✅ tamamlandı

Statik API key hâlâ salt-okunur/demo yollarında (`POST /events`, incident okuma, action-history okuma, analiz, WebSocket) çalışıyor — `docker compose up` + Load demo hesap açmadan işlemeye devam ediyor. Ama response action talep etme (`request:actions`) ve onaylama/reddetme (`approve:actions`) artık gerçek Auth0 Bearer token + izin gerektiriyor; `decided_by` artık client'ın gönderdiği bir alan değil, doğrulanmış token'ın `sub` claim'inden geliyor. Dashboard Auth0'a Single Page Application olarak kayıtlı (Regular Web Application değil — bir React SPA client secret'ı güvenle saklayamaz). Detaylar: `docs/adr/0010-auth0-identity-federation.md`.

## Aşama 11 — İlk Gerçek SOAR Entegrasyonu: PacketFence Quarantine (v2'nin üçüncü maddesi) ✅ tamamlandı

Sekiz response action'dan yalnızca `QUARANTINE_DEVICE`, PacketFence'e karşı gerçek bir HTTP çağrısı yapabiliyor — diğer yedi handler hâlâ tamamen simüle. Gerçek yürütme dört bağımsız sinyal gerektiriyor: `PACKETFENCE_BASE_URL`, `PACKETFENCE_API_TOKEN`, `PACKETFENCE_ISOLATION_SECURITY_EVENT_ID`, ve `PACKETFENCE_REAL_EXECUTION=true` — herhangi biri eksikse handler bugüne kadarki simülasyon davranışına geri düşüyor, yani `docker compose up` + Load demo sıfır konfigürasyonla değişmeden çalışmaya devam ediyor.

İlk implementasyonda ciddi bir doğruluk hatası vardı: `isolate_node`, PacketFence'in `POST /api/v1/nodes/bulk_deregister` endpoint'ini çağırıyordu — bu, cihazın kaydını tamamen siliyor (node'u "unregistered" durumuna getirip yeniden captive portal kaydına zorluyor), "isolated" durumuna geçirmiyor. Gerçek isolation, PacketFence'in security-event mekanizmasıyla tetikleniyor. Ayrı bir düzeltmeyle (`fix/packetfence-isolation-endpoint`) doğru endpoint'e (`PUT /api/v1/node/{mac}/apply_security_event`) geçildi, üçüncü bir zorunlu konfigürasyon sinyali (`PACKETFENCE_ISOLATION_SECURITY_EVENT_ID`) eklendi, ve gate'in dört sinyalin hiçbirini atlamadığını kanıtlayan parametrize testler yazıldı. Bu hata PacketFence'in gerçek controller kaynak kodu okunarak (`lib/pf/UnifiedApi/Controller/Nodes.pm`) tespit edildi — agent'ın kendi test suite'i bunu yakalamamıştı, çünkü testler yanlış endpoint'i doğru varsayarak mock'lanmıştı. Detaylar: `docs/adr/0011-real-packetfence-integration.md` ve amendment bölümü.

## Aşama 12 — İkinci Gerçek SOAR Entegrasyonu: Active Directory Disable User ✅ tamamlandı

`DisableUserHandler` artık self-hosted Active Directory'ye karşı gerçek bir LDAP mutasyonu yapabiliyor — `ldap3` üzerinden LDAPS ile bağlanıp `userAccountControl`'e `ACCOUNTDISABLE` bitini yazıyor. Bu aşama Stage 11'den kasıtlı olarak daha yüksek riskli kabul edildi: PacketFence quarantine sadece bir cihazın ağ erişimini kısıtlarken, AD hesabı devre dışı bırakmak email/SSO/VPN/PAM dahil o kimliğin güvendiği her şeyi etkileyebiliyor. Beş bağımsız sinyal gerekiyor (`AD_LDAP_URL`, `AD_BIND_DN`, `AD_BIND_PASSWORD`, `AD_USER_SEARCH_BASE_DN`, `AD_REAL_EXECUTION=true`) — herhangi biri eksikse simülasyona düşüyor.

`ldap3` senkron bir kütüphane olduğu için (asyncpg gibi native async sürücüsü yok), tüm LDAP işlemi (bind→search→modify→confirm→unbind) tek bir `asyncio.to_thread` çağrısında yürütülüyor — bu, Stage 9'daki hatanın (zaten async olan bir sürücüyü gereksiz thread+nested-loop shim'i arkasına saklamak) tekrarı değil, gerçekten senkron bir kütüphaneyi event loop'tan doğru şekilde ayırma. Stage 11'in `bulk_deregister` dersi burada da uygulandı: `modify()` çağrısı başarı dönse bile, client `userAccountControl`'ü tekrar okuyup `ACCOUNTDISABLE` bitinin gerçekten set edildiğini doğrulamadan başarı raporlamıyor — bunu kanıtlayan bir regresyon testi var (modify sahte başarı döndüğünde durum değişmemişse hata fırlatılıyor). Detaylar: `docs/adr/0012-real-active-directory-disable.md`.

## v2 / Sonraki adımlar

- **ML tabanlı anomaly detection:** Yeterli etiketli veri ve değerlendirme zemini oluştuğunda deterministik kuralları bilinmeyen davranış örüntüleriyle tamamlamak için planlandı.
- **Multi-tenant izolasyon:** Veri, sorgu, telemetry ve yetkilendirme sınırlarını tenant bazında ayırarak birden çok kurumu güvenle desteklemek için gerekli.
- **Kalan SOAR entegrasyonları:** Yalnızca require manual approval hâlâ simülasyon. Gerçek entegrasyonlar hedef sistemin riskine uygun safety gate ile tek tek eklendi; altyapı mutasyonu yapan eylemler insan onayı ve sonuç doğrulaması gerektirirken, düşük riskli webhook eylemleri kendi teslim veya oluşturma sözleşmelerini doğrular.

---

## Claude Code + Codex'i Nasıl Kullanıyoruz

Aşama 1'de git worktree ile ikisini gerçek zamanlı paralel çalıştırdık — çalıştı ama koordinasyon maliyeti yüksekti (iki agent bağımsız olarak aynı `pyproject.toml`'u yazdı, merge conflict çıktı; iki ayrı worktree'yi, iki branch'i takip etmek gerekti). Aşama 2'den itibaren daha basit bir modele geçiyoruz:

- **Sıralı çalışma, tek branch.** Worktree yok, paralel branch yok. Bir seferde tek agent kod yazıyor, aynı klasörde (`C:\dev\NetAiPortfolio\WardHound`).
- **Agent seçimi kotaya göre:** Claude Code'un limiti dolarsa Codex'e geç (ya da tersi), kaldığı yerden devam ettir. İki agent'ın aynı anda çalışması gerekmiyor, sadece ikisinin de hazır olması yetiyor.
- **Çapraz review hâlâ geçerli:** Bir agent bir task'ı bitirince, commit'lemeden önce diğer agent'a "bu diff'i review et" diye verebilirsin — worktree izolasyonu olmadan da bu işler, çünkü review sırasında ikinci agent sadece okuyor, aynı anda yazmıyor.
- **Worktree/paralel model tamamen çöp değil** — task'lar birbirinden gerçekten bağımsız hale geldiğinde (örn. dashboard'u frontend'de bir agent, observability'yi backend'de başka agent aynı anda yazarken) tekrar gündeme gelebilir. Şimdilik, collector'lar birbirine yakın/tekrarlayan iş olduğu için sıralı daha az sürtünmeli.

Sources (Aşama 1'deki paralel deneme için araştırılmıştı, ileride worktree'ye dönülürse hâlâ geçerli):
- [Run parallel sessions with worktrees - Claude Code Docs](https://code.claude.com/docs/en/worktrees)
- [Git Worktrees for AI Coding Agents: Full Guide | Nimbalyst](https://nimbalyst.com/blog/git-worktrees-for-ai-coding-agents-complete-guide/)
- [Codex vs Claude Code (2026): A Real Head-to-Head | Nimbalyst](https://nimbalyst.com/blog/codex-vs-claude-code-workflow-harness/)
- [Git Worktrees + Claude Code: The 2026 Playbook - Developers Digest](https://www.developersdigest.tech/blog/git-worktrees-claude-code-parallel-agents-guide)
