# WardHound — 8 Haftalık Yoğun Build Roadmap

Hazırlanma: 9 Temmuz 2026 | Tempo: 20+ saat/hafta | Hedef: internship'i bitmeden önce gerçek NAC/PAM/AD trafiğine karşı test edebilecek bir MVP çıkarmak.

## Neden sıralamayı değiştiriyoruz

`12_Month_Career_Roadmap.md`'de WardHound Phase 3'te (Ocak–Mart 2027), CCNA ve Network Automation Platform'dan sonra planlanmıştı. Bunu öne çekmenin tek gerçek gerekçesi var ama güçlü bir gerekçe: şu an elinde canlı bir Zero Trust altyapısı (PacketFence, JumpServer, AD Tiering) var ve internship bitince bu erişim kayboluyor. Bir correlation/AI platformunu gerçek event'lere karşı test edebilmek, sentetik veriyle test etmekten kıyaslanamayacak kadar değerli — bu iddiayı portföyde kanıtlanabilir kılan şey de bu. Riski açık söyleyeyim: CCNA'yı erteliyorsun ve bu roadmap'i job-search takvimini birkaç ay kaydırabilir. Kabul edilebilir bir trade-off, çünkü zaman-kısıtlı fırsat (internship erişimi) geri gelmeyecek, sertifika her zaman alınabilir.

**Gizlilik kuralı devam ediyor:** İnternship'teki gerçek hostname/IP/kullanıcı adı/şirket-özel veri asla public repo'ya girmeyecek. Gerçek event'lerle sadece lokal/private test yapılacak; public repo'ya giden her şey (örnek loglar, case study, demo) [internal confidentiality reference removed] kuralına göre anonimleştirilecek — "orta ölçekli bir kurumsal ortam" gibi genellenmiş ifadeler, gerçek RADIUS secret/SNMP community/kullanıcı adı yok.

## Kritik yol riski

Eğer internship'te kalan süre 8 haftadan azsa, Hafta 1–2 (iskelet + gerçek collector'lar) mutlaka önce bitmeli — geri kalan her şey sentetik veriyle de geliştirilebilir, ama collector'ların gerçek PacketFence/JumpServer/AD event'lerine karşı doğrulanması sadece şimdi mümkün. Erişim penceresi kısalırsa Hafta 1 ve 2'yi birleştirip sıkıştır.

---

## Hafta 1 — İskelet ve Sözleşmeler

Docker Compose ile FastAPI + PostgreSQL + Redis + Celery worker iskeleti. Pydantic v2 ile `RawEvent` ve `NormalizedEvent` şemalarını tasarla — bu proje boyunca her katmanın konuştuğu ortak sözleşme bu olacak, en başta doğru kurulmalı. Collector interface'ini (abstract base class) tanımla: her collector `raw bytes/dict → RawEvent` üretir. ADR-001 yaz: neden bu stack, neden rule-based correlation (ML değil) ile başlıyoruz. CI: ruff + mypy + pytest + GitHub Actions. Çıktı: `docker-compose up` ile ayakta duran, sahte bir event'i uçtan uca DB'ye yazan boş bir pipeline.

## Hafta 2 — Gerçek Collector'lar (en yüksek öncelik)

PacketFence syslog collector (UDP/TCP listener, RFC5424 parse), JumpServer collector (REST API polling — session start/end, privileged command, abnormal session), AD collector (Windows Event Forwarding veya WinRM üzerinden Security log okuma — 4625 failed auth, 4740 lockout, 4728 group membership change). Her biri normalization layer'dan geçip `NormalizedEvent` olarak Postgres'e yazılıyor. Bu hafta internship ortamına karşı gerçek doğrulama yapılacak hafta — mümkünse burayı geciktirme.

## Hafta 3 — Correlation + Policy + Risk Engine

Zaman-pencereli correlation kuralları (örn. aynı entity'de N dakika içinde AD auth fail + PacketFence quarantine + JumpServer yeni session = tek incident). Policy engine: Tier 0 kaynağa PAW olmayan cihazdan erişim, VLAN quarantine bypass denemesi gibi ihlaller. Risk engine: başlangıçta deterministik, ağırlıklı skor (ML'e sonra geçilir — "never over-engineer" prensibi). Bu üç motor birbirinden bağımsız, ayrı test edilebilir modüller olmalı.

## Hafta 4 — AI Analysis Engine

Anthropic Claude + Instructor ile structured output: `RootCauseAnalysis` Pydantic modeli (`probable_cause`, `confidence`, `evidence: list[Evidence]`, `recommended_actions: list[Action]`, `side_effects: str`). Correlated incident'i context olarak ver, NAC/PAM/AD domain'ine özel few-shot örnekler ekle. Serbest metin çıktı yok — her şey typed. Bu katman projenin asıl farkı, en çok zaman ayrılması gereken yer.

## Hafta 5 — Response Engine (simüle)

Action modelleri: Quarantine Device, Disable User, Block IP, Close Session, Require MFA, Notify Administrator, Create Incident, Require Manual Approval. Hepsi başta simüle — audit log'a yazılır, gerçek sisteme dokunmaz. Human-in-the-loop approval workflow zorunlu, özellikle privileged action'lar için (bu, career roadmap'inde AI güvenilirliği için vurgulanan nokta — "otonom remediation yok" mesajı hem doğru hem satılabilir).

## Hafta 6 — Dashboard

React + TypeScript + Tailwind + shadcn/ui. Incident listesi, incident detail (AI açıklaması + confidence + kanıt + önerilen aksiyon), approve/reject UI, WebSocket ile realtime güncelleme. Bu hafta demo edilebilirlik için kritik — interview'da ekranı açıp gösterebileceğin katman.

## Hafta 7 — Observability + Test Sertliği

Prometheus metrikleri, Grafana dashboard, OpenTelemetry tracing. Correlation/policy/risk engine'lerde pytest coverage. mypy + ruff temiz. Structured logging, secrets yönetimi (`.env` + Docker secrets, asla commit edilmez). Kısa bir threat model notu (bu platformun kendisi de bir security tool, kendi saldırı yüzeyini düşünmen bekleniyor).

## Hafta 8 — Dokümantasyon ve Portföy Cilası

README (mermaid mimari diyagramı, kurulum, demo GIF), ADR'ları topla, anonimleştirilmiş case study ("gerçek kurumsal Zero Trust altyapısına karşı test edildi" — client ismi yok), tek komutla `docker-compose up` demo, v2 roadmap notu (ML tabanlı anomaly detection, multi-tenant, SOAR entegrasyonları — şimdi yapma, sadece yaz).

---

## Claude Code + Codex'i Paralel Kullanma

İkisini aynı repo'da aynı anda çalıştırmanın standart yolu **git worktree**: her worktree kendi branch'i, kendi dosya kopyası, ama aynı `.git` geçmişini paylaşıyor — böylece iki agent aynı anda aynı dosyaya çakışmadan dokunmuyor.

Pratik kurulum:
- Repo kökünde hem `CLAUDE.md` (Claude Code otomatik okur) hem `AGENTS.md` (Codex her session başında okur) tut. İkisi farklı dosyalar ama içerik büyük ölçüde aynı olabilir — birini diğerine sembolik link atman bile mümkün.
- Görevi modül sınırlarına göre böl, dosya sınırlarına göre değil: örn. "Codex, collector'ları yaz" + "Claude Code, correlation engine + testleri yaz" aynı anda, farklı worktree'lerde, farklı branch'lerde. İkisi de aynı `NormalizedEvent` şemasına yazdığı sürece çakışmazlar.
- `git worktree add ../wardhound-collectors feat/collectors` gibi ayrı klasörler aç, her birinde ayrı terminal/ayrı agent session'ı çalıştır. Her worktree'nin kendi `node_modules`/`.venv`/pytest cache'i olur, branch değiştirmek gibi state kirlenmesi yaşanmaz.

Rol ayrımı için önerim (bu projenin doğasına göre):
- **Claude Code** → mimari kararlar, planlama, correlation/risk/AI analysis engine gibi "doğru tasarım" gerektiren, iyi spesifikasyona rağmen judgment call'ların çok olduğu katmanlar. Zaten bu CLAUDE.md dosyasındaki tüm bağlamı (staj deneyimin, mühendislik prensiplerin) elinde tutuyor.
- **Codex** → net spesifikasyonu olan, izole, tekrarlayan implementasyon işleri: bir collector yaz, bir Pydantic modeli genişlet, test coverage artır, belirli bir endpoint'i CRUD'la. Paralel worktree'de arka planda çalıştırıp sonucu sonra review edersin.
- **Çapraz review**: bir agent'ın yazdığı kritik kodu (özellikle response engine — gerçek aksiyon tetikleyebilecek katman) diğerine review ettir. İki farklı modelin kör noktaları farklı, bu ucuz bir ikinci göz.
- Merge noktası `main` — her worktree kendi branch'inde bitirir, sen (ya da bir agent plan-review modunda) PR gibi gözden geçirip merge eder. Aynı anda 3-4'ten fazla paralel session açmak koordinasyon maliyetini review süresinden daha pahalı hale getiriyor, bu projede 2 (Claude Code + Codex) yeterli.

Sources:
- [Run parallel sessions with worktrees - Claude Code Docs](https://code.claude.com/docs/en/worktrees)
- [Git Worktrees for AI Coding Agents: Full Guide | Nimbalyst](https://nimbalyst.com/blog/git-worktrees-for-ai-coding-agents-complete-guide/)
- [Codex vs Claude Code (2026): A Real Head-to-Head | Nimbalyst](https://nimbalyst.com/blog/codex-vs-claude-code-workflow-harness/)
- [Git Worktrees + Claude Code: The 2026 Playbook - Developers Digest](https://www.developersdigest.tech/blog/git-worktrees-claude-code-parallel-agents-guide)
