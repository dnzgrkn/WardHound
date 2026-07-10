# WardHound — Yoğun Build Roadmap

Hazırlanma: 9 Temmuz 2026 | Tempo: 20+ saat/hafta, ama ilerleme takvim haftasına değil aşama tamamlanmasına göre — "Aşama N" başlıkları sabit bir hafta demek değil, sıralı bir iş birimi demek. Hedef: internship'i bitmeden önce gerçek NAC/PAM/AD trafiğine karşı test edebilecek bir MVP çıkarmak.

## Neden sıralamayı değiştiriyoruz

`12_Month_Career_Roadmap.md`'de WardHound Phase 3'te (Ocak–Mart 2027), CCNA ve Network Automation Platform'dan sonra planlanmıştı. Bunu öne çekmenin tek gerçek gerekçesi var ama güçlü bir gerekçe: şu an elinde canlı bir Zero Trust altyapısı (PacketFence, JumpServer, AD Tiering) var ve internship bitince bu erişim kayboluyor. Bir correlation/AI platformunu gerçek event'lere karşı test edebilmek, sentetik veriyle test etmekten kıyaslanamayacak kadar değerli — bu iddiayı portföyde kanıtlanabilir kılan şey de bu. Riski açık söyleyeyim: CCNA'yı erteliyorsun ve bu roadmap'i job-search takvimini birkaç ay kaydırabilir. Kabul edilebilir bir trade-off, çünkü zaman-kısıtlı fırsat (internship erişimi) geri gelmeyecek, sertifika her zaman alınabilir.

**Gizlilik kuralı devam ediyor:** İnternship'teki gerçek hostname/IP/kullanıcı adı/şirket-özel veri asla public repo'ya girmeyecek. Gerçek event'lerle sadece lokal/private test yapılacak; public repo'ya giden her şey (örnek loglar, case study, demo) [internal confidentiality reference removed] kuralına göre anonimleştirilecek — "orta ölçekli bir kurumsal ortam" gibi genellenmiş ifadeler, gerçek RADIUS secret/SNMP community/kullanıcı adı yok.

## Kritik yol riski

Eğer internship'te kalan süre azalırsa, Aşama 1–2 (iskelet + gerçek collector'lar) mutlaka önce bitmeli — geri kalan her şey sentetik veriyle de geliştirilebilir, ama collector'ların gerçek PacketFence/JumpServer/AD event'lerine karşı doğrulanması sadece şimdi mümkün. Erişim penceresi kısalırsa Aşama 1 ve 2'yi birleştirip sıkıştır.

---

## Aşama 1 — İskelet ve Sözleşmeler ✅ tamamlandı

Docker Compose ile FastAPI + PostgreSQL + Redis + Celery worker iskeleti. Pydantic v2 ile `RawEvent` ve `NormalizedEvent` şemalarını tasarla — bu proje boyunca her katmanın konuştuğu ortak sözleşme bu olacak, en başta doğru kurulmalı. Collector interface'ini (abstract base class) tanımla: her collector `raw bytes/dict → RawEvent` üretir. ADR-001 yaz: neden bu stack, neden rule-based correlation (ML değil) ile başlıyoruz. CI: ruff + mypy + pytest + GitHub Actions. Çıktı: `docker-compose up` ile ayakta duran, sahte bir event'i uçtan uca DB'ye yazan boş bir pipeline.

## Aşama 2 — Gerçek Collector'lar (en yüksek öncelik)

PacketFence syslog collector (UDP/TCP listener, RFC5424 parse), JumpServer collector (REST API polling — session start/end, privileged command, abnormal session), AD collector (Windows Event Forwarding veya WinRM üzerinden Security log okuma — 4625 failed auth, 4740 lockout, 4728 group membership change). Her biri normalization layer'dan geçip `NormalizedEvent` olarak Postgres'e yazılıyor. Bu aşama internship ortamına karşı gerçek doğrulama yapılacak aşama — mümkünse burayı geciktirme.

## Aşama 3 — Correlation + Policy + Risk Engine

Zaman-pencereli correlation kuralları (örn. aynı entity'de N dakika içinde AD auth fail + PacketFence quarantine + JumpServer yeni session = tek incident). Policy engine: Tier 0 kaynağa PAW olmayan cihazdan erişim, VLAN quarantine bypass denemesi gibi ihlaller. Risk engine: başlangıçta deterministik, ağırlıklı skor (ML'e sonra geçilir — "never over-engineer" prensibi). Bu üç motor birbirinden bağımsız, ayrı test edilebilir modüller olmalı.

## Aşama 4 — AI Analysis Engine

Anthropic Claude + Instructor ile structured output: `RootCauseAnalysis` Pydantic modeli (`probable_cause`, `confidence`, `evidence: list[Evidence]`, `recommended_actions: list[Action]`, `side_effects: str`). Correlated incident'i context olarak ver, NAC/PAM/AD domain'ine özel few-shot örnekler ekle. Serbest metin çıktı yok — her şey typed. Bu katman projenin asıl farkı, en çok zaman ayrılması gereken yer.

## Aşama 5 — Response Engine (simüle)

Action modelleri: Quarantine Device, Disable User, Block IP, Close Session, Require MFA, Notify Administrator, Create Incident, Require Manual Approval. Hepsi başta simüle — audit log'a yazılır, gerçek sisteme dokunmaz. Human-in-the-loop approval workflow zorunlu, özellikle privileged action'lar için (bu, career roadmap'inde AI güvenilirliği için vurgulanan nokta — "otonom remediation yok" mesajı hem doğru hem satılabilir).

## Aşama 6 — Dashboard

React + TypeScript + Tailwind + shadcn/ui. Incident listesi, incident detail (AI açıklaması + confidence + kanıt + önerilen aksiyon), approve/reject UI, WebSocket ile realtime güncelleme. Bu aşama demo edilebilirlik için kritik — interview'da ekranı açıp gösterebileceğin katman.

## Aşama 7 — Observability + Test Sertliği

Prometheus metrikleri, Grafana dashboard, OpenTelemetry tracing. Correlation/policy/risk engine'lerde pytest coverage. mypy + ruff temiz. Structured logging, secrets yönetimi (`.env` + Docker secrets, asla commit edilmez). Kısa bir threat model notu (bu platformun kendisi de bir security tool, kendi saldırı yüzeyini düşünmen bekleniyor).

## Aşama 8 — Dokümantasyon ve Portföy Cilası

README (mermaid mimari diyagramı, kurulum, demo GIF), ADR'ları topla, anonimleştirilmiş case study ("gerçek kurumsal Zero Trust altyapısına karşı test edildi" — client ismi yok), tek komutla `docker-compose up` demo, v2 roadmap notu (ML tabanlı anomaly detection, multi-tenant, SOAR entegrasyonları — şimdi yapma, sadece yaz).

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
