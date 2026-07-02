# ARCHITECTURE.md — WAF Enterprise Tier

> Documento di riferimento per il tier **enterprise** (a pagamento, licenza
> source-available BSL 1.1 / Elastic 2.0). Da rileggere all'inizio di ogni sessione.
> Presuppone la conoscenza del core (`ARCHITECTURE.md`) e del confine (`BOUNDARY.md`).
>
> **Regola-guida ereditata da `BOUNDARY.md`.** Il core è il **datapath di sicurezza**
> (single-node, ispezionabile). L'enterprise vende **scala, governance e operabilità
> di team** — MAI capacità di detection baseline. *"Capire e ispezionare un protocollo"
> è core; "gestirlo a scala / con governance" è enterprise.*

---

## 1. Obiettivi e non-obiettivi

### Obiettivi
- **Scala multi-nodo**: stato condiviso (rate-limit + IP-reputation) cluster-wide,
  coerente e non sfruttabile (no over-allow / no TOCTOU).
- **Governance & compliance**: RBAC, SSO, audit firmato, report SOC2/PCI-DSS.
- **Operabilità di team**: control plane (dashboard, drill-down, alerting), retention
  a lungo termine di metriche/telemetria.
- **Threat intelligence**: feed reputazione/firme premium + regole CRS curate.
- **Integrazione enterprise**: connettori SIEM, marketplace/signing dei plugin WASM,
  gestione certificati a scala (ACME, rotation, mTLS con PKI gestita).

### Non-obiettivi (vincoli di confine, NON negoziabili)
- **Nessuna detection baseline** vive qui: SQLi/XSS/PT/RCE/LFI-RFI/SSRF/header-inj/
  smuggling/SSI/XXE, GraphQL e gRPC inspection, scoring, fast-path, normalizzazione →
  restano **OPEN** (`BOUNDARY.md` §1.3, §3.1). Spostarli sarebbe un "gutted core".
- **Nessun fork del core**: si **dipende** dai crate pubblicati su crates.io e si
  **implementano i trait** (`BOUNDARY.md` §4, §5).
- **Nessuna modifica retroattiva del confine** già rilasciato (`BOUNDARY.md` §5):
  l'unico spostamento consentito è `ENTERPRISE → OPEN`.

---

## 2. Principio architetturale: estensione, non fork

L'enterprise è un **insieme di crate separati** (path/repo distinto, ciascuno con la
propria licenza BSL — `BOUNDARY.md` §6.4) che **dipendono** dal core come libreria e si
agganciano ai **tre seam stabili** (ABI congelata, SemVer — `BOUNDARY.md` §5):

```rust
// crate enterprise, dipende dal core PUBBLICATO come libreria:
let proxy = Proxy::builder(&config)
    .state_store(Arc::new(RedisStore::connect(&url)?))  // §3 — StateStore distribuito
    .cert_source(Arc::new(AcmeCertSource::new(..)))      // §5 — TlsCertSource a scala
    .modules(premium_modules)                            // §4 — WafModule premium
    .build()
    .await?;
```

Ogni seam ha un **default OPEN**: un builder senza override è identico a `Proxy::bind`.
L'enterprise **sostituisce** l'implementazione, non riscrive il datapath. Vincolo
permanente: ogni nuova capability cluster-wide è un **nuovo metodo di trait con default
impl** (additivo, non-breaking — `BOUNDARY.md` §4), mai un trait parallelo che bypassa
la pipeline.

### Mappa crate (proposta)

| Crate enterprise | Seam / area | Dipende da |
|---|---|---|
| `waf-state-redis`     | `StateStore` distribuito (§3) | `waf-core::state` |
| `waf-tls-managed`     | `TlsCertSource` ACME/mTLS (§5) | `waf-proxy::tls` |
| `waf-modules-premium` | `WafModule` firme premium (§4) | `waf-core` (contratto moduli) |
| `waf-threatintel`     | feed reputazione/firme (§4, §6) | `waf-core`, `waf-state-redis` |
| `waf-crs-curated`     | contenuto CRS curato (§6) | parser `crs` OPEN (`waf-core`) |
| `waf-controlplane`    | dashboard/API/alerting (§7) | telemetria OPEN + store |
| `waf-governance`      | RBAC/SSO/audit firmato (§8) | `waf-controlplane` |
| `waf-siem`            | connettori SIEM (§9) | logging/metriche OPEN |
| `waf-marketplace`     | signing/distribuzione WASM (§4) | runtime `waf-wasm` OPEN |

---

## 3. Stato distribuito multi-nodo (`StateStore` Redis) — `BOUNDARY.md` §2.1

> **STATO: §3 INTERAMENTE IMPLEMENTATO (2026-06-30).** Rate-limit distribuito (`waf-state-redis`,
> provato a 2 nodi sul wire) **+** IP-reputation cluster-wide (`waf-threatintel` + `waf-state-redis`).
> Il **feed §6** che *popola* la reputazione in Redis (capability di scrittura, deliberatamente
> separata) è ora anch'esso IMPLEMENTATO (2026-07-02) — vedi §6.

Il seam OPEN `StateStore` (`waf-core::state`) ha **una sola operazione atomica**:

```rust
pub trait StateStore: Send + Sync {
    fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired;
}
```

### Invariante cardine: atomicità refill-then-consume
Il contratto **non** è get/update: il refill-then-consume dev'essere **indivisibile**
fra nodi, altrimenti due nodi leggono lo stesso livello del bucket ed entrambi
consentono → **over-allow cluster-wide / TOCTOU**. L'in-memory OPEN lo garantisce sotto
un lock; **Redis lo garantisce con uno script server-side** (Lua / `EVALSHA`) che
esegue refill + consume + writeback in **una sola** round-trip atomica.

- **Token bucket distribuito**: chiave = `ctx.client_ip` (derivato dal resolver
  trusted-proxy del core), valore = `{tokens, last_refill_ts}`. Il **clock è di Redis**
  (`TIME`), così il refill non dipende dallo skew dei nodi WAF. Il **cap memoria** è il
  TTL di Redis (chiavi idle scadono) → fuori dall'ABI, come per l'in-memory.
- **Degradazione (fail-open vs fail-closed)**: Redis irraggiungibile è uno scenario
  operativo critico. `RedisStore` espone una policy `[state.redis].on_backend_error`:
  - `local_fallback` (default consigliato) → ripiega sul token bucket **in-memory
    locale** del nodo (rate-limit per-nodo, non cluster-wide) + `warn!` + metrica
    `waf_state_backend_errors_total`. Coerente con la filosofia *additive-control* del
    core: un guasto dell'infrastruttura di stato non deve azzerare il throttling.
  - `fail_closed` → `Reject{503}` (per deployment dove l'esattezza cluster-wide è
    requisito di compliance).
- **Non azzerabile al reload** (eredita §9 del core): i bucket vivono in Redis, oltre il
  process-lifetime del nodo → un reload/restart di un nodo non resetta il throttle.

### IP-reputation cluster-wide (capability ENTERPRISE-ONLY — NON sul trait core)

> **Correzione di design (2026-06-30).** Una stesura precedente proponeva un metodo
> `reputation()` **defaulted sul `StateStore` core**. È sbagliato e va respinto: il datapath
> OPEN consuma `try_acquire` (rate-limit) e **non chiama mai** `reputation()`. Un metodo che
> il core non invoca **non appartiene alla ABI core** — sarebbe contaminazione del confine
> mascherata da "additivo", a costo di una `core 0.3` e di un metodo congelato per sempre, a
> **beneficio zero**: poiché l'enterprise costruisce comunque lo store e lo inietta nel modulo
> via `.add_module()`, il modulo ha già in mano il tipo enterprise → il metodo sul trait core
> non aggiunge alcuna capacità. Resta la regola "ENTERPRISE → OPEN è l'unico movimento".

**IMPLEMENTATO (`waf-threatintel` + `waf-state-redis`).** La reputation vive **interamente
nell'enterprise**, usando solo i seam core già esistenti (`.add_module()` + `.state_store()`) —
**nessuna modifica al core**:

```rust
// crate enterprise (es. waf-state-redis): trait + dato, NON in waf-core
pub trait ReputationStore: Send + Sync {
    fn reputation(&self, ip: IpAddr) -> Reputation;   // IpAddr, non &str (chiave canonica in UN punto)
}
pub enum Reputation { Unknown, Suspicious, Malicious }
```

- **Un solo `RedisStore`, due capability**: `RedisStore` implementa **sia** `StateStore`
  (`try_acquire`) **sia** `ReputationStore` (`reputation`), condividendo lo **stesso pool**
  (keyspace separato dai bucket, popolato dal feed §6). `Arc<RedisStore>` coercia a entrambi i
  trait. Lookup read-only → **niente atomicità/Lua** (non è refill-then-consume).
- **Chiave canonica in UN punto**: `IpAddr::to_string()` è già la forma canonica RFC 5952
  (IPv6 compresso, no brackets/zone-id). Un solo helper `rep_key(ip)` serve sia il lookup sia
  il popolamento → niente mismatch fra forme dell'IP.
- **fail → `Unknown`** (fail-to-no-opinion): Redis giù ⇒ `reputation()` ritorna `Unknown`, la
  pipeline **ispeziona comunque**. Un feed giù non deve né bloccare né sbloccare. È l'analogo
  del `local_fallback` dello store, per una capability additiva per natura.
- **Consumo**: un `WafModule` premium (`waf-threatintel`) in `Phase::Connection` legge
  `ctx.client_ip` → `reputation(ip)` → `Decision::Scores` con **severità** (Malicious/Suspicious
  → severity, `Unknown` → `Allow`); la pipeline mappa severity→points (§4: nessun punteggio
  hardcoded). Contribuisce allo **stesso anomaly score** cumulativo del core, nessuna logica di
  decisione nuova.
- **Anti doppio-conteggio** (nota di design per §6): se in futuro il feed alimenta anche moduli
  di firma premium, lo **stesso IP non deve contribuire due volte** allo score cumulativo →
  namespace di `rule_id` dedicato + dedup. Non un problema per l'MVP (solo modulo reputation),
  ma vincolo da rispettare quando §6 cresce.
- **Popolamento**: in produzione = **feed §6** (`ReputationWriter::apply_snapshot`, IMPLEMENTATO —
  vedi §6). Il crate NON espone un `set_reputation` di prodotto (il feed possiede le scritture); i
  test seminano `rep:<ip>` grezzo via `redis-cli` sul formato chiave documentato.

---

## 4. Moduli di detection premium (`WafModule`) — `BOUNDARY.md` §2.4

> **Confine rigido**: qui vivono SOLO firme **premium curate** e moduli che consumano
> stato/intelligence enterprise — MAI riportare nel core capacità baseline.

- **Firme premium** (`waf-modules-premium`): regole ad alta-cura (es. abuse GraphQL/gRPC
  depth/complexity, evasion families aggiornate, bot/scanner avanzati) impacchettate come
  `WafModule` aggiuntivi, iniettati via `.modules(premium_modules)` **dopo** i built-in.
  Stesso contratto `inspect -> Decision`, stesso scoring §7 del core, filtro per
  `paranoia_level`: **nessun punteggio hardcoded**, ogni regola dichiara solo una severità.
- **Schema-enforcement GraphQL/gRPC** (`BOUNDARY.md` §3.1): validare la query/messaggio
  contro lo **schema reale** dell'app (`.graphql` / `.proto`) è **gestione schema =
  governance** → enterprise. Si aggancia come modulo strutturale (`structural() = true`)
  che gira anche sul fast-path-skip, esattamente come i cap strutturali OPEN.
- **IP-reputation module** (consuma §3): `Phase::Connection`, legge `StateStore::reputation`.

### Marketplace / signing dei plugin WASM (`BOUNDARY.md` §1.7, §2.4)
Il **runtime** Proxy-Wasm (`waf-wasm`, `wasmi`) è **OPEN**. L'enterprise aggiunge:
- **Signing**: verifica firma del `.wasm` prima del load (catena di fiducia gestita).
- **Marketplace**: distribuzione/versioning/aggiornamento dei plugin firmati.
- Si integra senza toccare il runtime: un `verified_plugin_loader` valida la firma e poi
  delega al loader OPEN esistente.

---

## 5. Gestione certificati a scala (`TlsCertSource`) — `BOUNDARY.md` §3.2

Il core spedisce **solo** `FileCertSource` (PEM, cert-da-file) dietro il seam
`waf-proxy::tls::TlsCertSource`. L'enterprise fornisce implementazioni **dello stesso
trait** (zero fork).

**IMPLEMENTATO (`waf-tls-managed`, core 0.2).** Il trait ha guadagnato due metodi
**additivi defaulted** (`BOUNDARY.md` §5): `resolver() -> Option<Arc<dyn ResolvesServerCert>>`
e `client_verifier() -> Option<Arc<dyn ClientCertVerifier>>` (entrambi default `None` → la
strada OPEN single-cert via `load()` resta invariata). `build_server_config` ramifica:
resolver `Some` ⇒ `with_cert_resolver` (e non chiama `load()`); verifier `Some` ⇒
`with_client_cert_verifier`.

- **ACME (TLS-ALPN-01, HITLESS)** via `resolver()`: `ManagedTlsCertSource` espone il
  `ResolvesServerCert` di `rustls-acme`; issuance + **renewal in background** ruotano il cert
  vivo **senza ricostruire l'acceptor**. Il core aggiunge `acme-tls/1` all'ALPN quando un
  resolver è presente, così la challenge negozia sulla stessa `:443`. **DNS-01** = secondo
  livello (wildcard / CA che non raggiunge `:443`), provider-impl follow-on.
- **mTLS con PKI gestita** via `client_verifier()`: `WebPkiClientVerifier` da un bundle CA
  configurato (`[tls.mtls].ca_path`). Roots caricate al boot (rotation = restart).
- **Cert multi-nodo centralizzati**: distribuzione coerente del materiale TLS sul cluster
  (store condiviso / control plane) — follow-on.

Config: `[tls.acme]` / `[tls.mtls]` ri-parsate dal binario enterprise (il `Config` OPEN le
ignora). Vincoli ereditati dal core (§9 "Terminazione TLS"): `[tls].enabled`/`alpn` restano
da config (la **sorgente governa solo la provenienza** del cert); **no silent downgrade**
(fail-closed); un errore di handshake per-connessione resta non-fatale.

> **Rotation vs immutabilità acceptor (RISOLTO).** L'acceptor del core resta immutabile
> post-bind, ma la rotation NON lo viola: il `resolver()` è un `ResolvesServerCert` consultato
> **per-handshake**, quindi il cert ruota dentro la sorgente senza toccare l'acceptor né
> passare da config-reload. Il contratto "solo-TLS quando abilitato" resta invariato.

---

## 6. Threat intelligence e contenuto curato — `BOUNDARY.md` §2.4

- **Feed reputazione** (`waf-threatintel`) — **IMPLEMENTATO (2026-07-02)**: il *writer* che popola il
  keyspace `rep:<ip>` letto dal modulo reputation (§3). Simmetrico al read: seam di scrittura
  `ReputationWriter::apply_snapshot` su `RedisStore` (stessa `rep_key` + encoding valore in UN punto —
  read e write non possono divergere), sorgenti dietro il trait `ReputationFeed` (v1: `FileFeed` +
  `HttpListFeed`, lista IP-per-riga, **verdetto per-sorgente**; API di subscription commerciali =
  follow-on dietro lo stesso trait), driver `start_reputation_feed` in background.
  - **Single-writer** (`DistributedLock`, chiave `feed_lock:` sullo stesso pool): solo UN nodo per
    ciclo fa fetch+scrive → N nodi non ripetono lo stesso fetch (subscription potenzialmente metered).
    Lock per-ciclo, niente heartbeat; leader morto → il ciclo dopo un altro nodo subentra.
  - **Snapshot TTL-based** (niente swap atomico): ogni `rep:<ip>` scritto con `entry_ttl` (default 3×
    refresh). Un IP de-listato invecchia da solo; un feed giù fa scadere tutto → `Unknown`
    (fail-to-no-opinion, coerente col read). **Solo IP esatti** in v1 (il read è `GET rep:<ip>`; i CIDR
    sono skippati con warn, follow-on).
  - Config `[enterprise.reputation.feed]` (default off; richiede `redis_url`). Un nodo può essere un
    **feed-writer puro** (popola per gli altri) anche senza il modulo reputation locale.
  - Il rinnovo/hot-update è intrinseco al loop (ri-fetch periodico), NON serve un SIGHUP.
- **Regole CRS/ModSecurity curate** (`waf-crs-curated`) — **IMPLEMENTATO (2026-07-02)**: il
  **parser/engine `seclang`** è OPEN (`BOUNDARY.md` §1.7, B2); qui vive **solo il contenuto curato**
  (file `SecRule` premium mantenuti e tarati). **Conta nello stesso anomaly score cumulativo** → con
  CRS-curated attivo il tuning di soglia è dell'operatore (doppio-conteggio coi nativi accettato,
  paletto #4 di B2).
  - **Contenuto premium-ADDITIVO, non baseline**: firme CVE/app/evasion ad alta-cura. **27 regole v1**:
    (a) categorie generiche (SSRF cloud-metadata, PHP wrapper LFI, webshell, `.git`/`.env` exposure, metodi
    HTTP pericolosi, deserialization marker, recon UA); (b) **pack CVE nominali** da CISA KEV (`rules/cve.conf`,
    id 9100000+): Joomla JCE, Mirasvit/Magento object-injection, UniFi/Cisco-SD-WAN/FortiWeb/TeamCity/PAN-OS
    traversal, Next.js middleware bypass, SharePoint ToolShell, PHP-CGI arg-injection, MOVEit, GoAnywhere,
    Kentico, PaperCut, Oracle EBS, Log4Shell/Spring4Shell. **Non** reimplementa SQLi/XSS/PT/RCE/LFI-RFI
    baseline (restano OPEN nei moduli nativi). Solo costrutti del **subset v1** del motore (`@rx`/`@pm`;
    `@detectSQLi`/`@detectXSS` restano fuori → SQLi/XSS ai nativi). CVE FP-prone (Serv-U deflate, `/_layouts/`
    generico) **scartati esplicitamente** con nota nel `.conf`.
  - **Packaging = embed + `.add_module()`**: il crate embedda i `.conf` (`include_str!`) ed espone
    `curated_source()` + `EXPECTED_LOADED`; il binario enterprise costruisce `CrsModule::from_source`
    e lo inietta gated da `[enterprise.crs_curated]` (default off, no Redis). Il canale OPEN
    `[modules.crs].files` resta per le regole DELL'operatore. Caveat: come i moduli premium, **non
    sopravvive a SIGHUP** (finché il core non espone `module_factory`).
  - **Gate di compatibilità** (il valore ingegneristico del tier): il test del crate carica il
    contenuto attraverso il motore OPEN e asserisce `loaded_count() == EXPECTED_LOADED` **esatto** +
    `skipped()` **vuoto** + un bite-test per-regola → il contenuto è *garantito-compatibile* col
    subset spedito, niente perdita silenziosa (la lezione del bug setvar B2).

---

## 7. Control plane — `BOUNDARY.md` §2.2

Servizio separato dal datapath (mai sulla porta dati). Consuma la **telemetria baseline
OPEN** (logging JSON strutturato + metriche Prometheus, esposte dal core) e la persiste a
lungo termine.

- **Dashboard web**: stato cluster, volumi per decisione (`allowed|blocked|rate_limited|
  bad_request|upstream_error|internal_error`), latenze (dagli histogram Prometheus del
  core, quantili lato scrape).
- **Drill-down richieste bloccate**: ricostruzione del verdetto dai
  `score_contributions` (module/rule_id/severity/points) loggati dal core.
- **Rule management**: editing/versioning regole + push validato ai nodi (riusa l'hot
  reload SIGHUP; il control plane è "il bottone", la logica validate-then-swap resta OPEN).
- **Alerting**: soglie su metriche/eventi.
- **Retention a lungo termine** di metriche/telemetria (i contatori OPEN sono
  exporter-neutral → il control plane è un secondo sink, non una riscrittura).

> **Vincolo cardinalità** ereditato dal core: MAI label da input utente su
> `requests_total`. Breakdown per-regola/IP/path = metriche separate con cap, materializzate
> nello store del control plane, non labels sul path caldo.

---

## 8. Governance e compliance — `BOUNDARY.md` §2.3

- **RBAC**: ruoli/permessi sul control plane (read-only / operatore / admin).
- **SSO**: SAML / OIDC.
- **Audit log firmati**: ogni azione operatore (edit regole, cambio soglie, reload,
  override fail-mode) → record firmato (catena verificabile) per SOC2 / PCI-DSS.
- **Report di compliance automatici** + retention a lungo termine.

L'audit enterprise è **distinto** dal decision-log OPEN: il core logga i **verdetti** (per
richiesta); l'enterprise logga le **azioni umane/amministrative** sul control plane.

---

## 9. Integrazione e supporto — `BOUNDARY.md` §2.5

- **Connettori SIEM**: export degli eventi (decision-log OPEN + audit enterprise) verso
  Splunk/Elastic/QRadar/… Si appoggia al logging strutturato OPEN come sorgente.
- **SLA support** e **guided hardening** (servizio).

---

## 10. Confine e stabilità (riassunto operativo)

| Capability | OPEN (core) | ENTERPRISE (questo doc) |
|---|---|---|
| Rate-limit / state | in-memory token bucket | `StateStore` Redis cluster-wide + IP-reputation |
| TLS | termination base cert-da-file | ACME / rotation / multi-nodo / mTLS PKI |
| WASM | runtime Proxy-Wasm | marketplace / signing |
| CRS/ModSecurity | parser/engine `seclang` | regole curate premium |
| Detection (SQLi…XXE, GraphQL/gRPC) | **tutta** | firme premium + schema-enforcement |
| Telemetria | baseline Prom/OTLP | dashboard + retention + drill-down |
| Governance | — | RBAC / SSO / audit firmato / report |

### Regole di stabilità (normative, da `BOUNDARY.md` §5)
1. Una feature `OPEN` **non** può diventare `ENTERPRISE` dopo un rilascio. Solo
   `ENTERPRISE → OPEN` è permesso.
2. I tre trait (`WafModule`, `StateStore`, `TlsCertSource`) sono **public ABI** congelata
   (SemVer). Nuove capability cluster-wide = **nuovo metodo con default impl** (additivo).
3. `Config` è `#[non_exhaustive]`: nuove sezioni enterprise (`[state.redis]`,
   `[controlplane]`, `[governance]`, …) sono **additive non-breaking** lato core.
4. Ogni crate enterprise vive in path/repo separato con **LICENSE BSL** propria
   (`BOUNDARY.md` §6.4): il confine è fisico, non solo documentale.
5. Ogni nuova feature è etichettata in `BOUNDARY.md` **prima del merge**.

---

## 11. Convenzioni di sviluppo (delta rispetto al core)

- L'enterprise **dipende dalle versioni pubblicate** del core (no path-dep verso un fork).
- I test enterprise NON ri-testano la detection baseline (è del core/`waf-corpus`); testano
  **scala, atomicità, governance**: es. property-test sull'atomicità di `try_acquire` Redis
  (no over-allow sotto concorrenza), bite-test sul fail-mode dello store, test di rotation
  TLS senza downgrade.
- **Aggiornare `BOUNDARY.md`** ad ogni nuova feature (label inequivocabile) e questo file
  quando cambia un seam o un'implementazione a scala.
- Disciplina **bite-test** ereditata (§13 core): una guardia mai vista fallire è speranza,
  non garanzia — vale in primis per l'atomicità distribuita.
