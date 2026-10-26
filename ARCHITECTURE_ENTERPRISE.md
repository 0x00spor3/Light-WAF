# ARCHITECTURE.md — WAF Enterprise Tier

> Documento di riferimento per il tier **enterprise** (Apache-2.0). Da rileggere all'inizio di ogni sessione.
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

- **Firme premium** (`waf-modules-premium`): regole ad alta-cura impacchettate come `WafModule`
  aggiuntivi, iniettati via `.add_module()` **dopo** i built-in. Stesso contratto `inspect -> Decision`,
  stesso scoring del core: **nessun punteggio hardcoded**, ogni regola dichiara solo una severità.
  - **Client-integrity / bot detection** (`bot.rs`) — **IMPLEMENTATO (2026-07-03)**: heuristiche
    **native cross-header** che una regex non esprime — deliberatamente **fuori** dal modulo `scanner`
    OPEN (che fa UA-tool-matching = baseline) e da `waf-crs-curated` (contenuto firma). v1 = **browser
    impersonation (S1)**: una UA che dichiara un browser **moderno** (Chromium/Firefox major a 3 cifre;
    Safari escluso — Sec-Fetch storicamente incoerente) **senza NESSUN header `sec-fetch-*`** → un bot
    che si spaccia per browser (`curl`/`requests` non manda Fetch-Metadata; un client non-browser non
    dichiara un browser → non scatta). `Phase::Headers`, `structural()=true`, `Decision::Scores` additive
    (`bot-browser-impersonation`, `Critical` tarabile). Config `[enterprise.bot_detection]` (default off,
    niente file/Redis, costruzione infallibile). FP-source = browser vecchi/edge o proxy che strippano
    header → governata dalla severità. Namespace `rule_id` `bot-*` (registry strutturale).
  - **Follow-on** dichiarati: **scanner comportamentale** (contatori per-IP nello store §3), **TLS/JA
    fingerprint** (ClientHello), segnali corroboranti (`sec-ch-ua`/`accept-language`), header-order/casing.
- **Schema-enforcement GraphQL** (`waf-modules-premium`) — **IMPLEMENTATO (2026-07-03)**: valida
  ogni operazione GraphQL contro lo **schema reale** dell'app (`.graphql` SDL) — è **gestione schema =
  governance** → enterprise. Modulo strutturale (`Phase::Body`, `structural() = true`) che gira anche
  sul fast-path-skip, come i cap strutturali OPEN.
  - **Validatore = `apollo-compiler`** (l'engine dell'Apollo Router): zero-gap — un validatore
    hand-rolled sarebbe falsa sicurezza per un security control. **DoS-parser bounded**: i cap
    strutturali OPEN di Fase 11 (depth/size/batch → `Reject{400}`) girano PRIMA, quindi il validatore
    vede solo operazioni già limitate.
  - **Estrazione = specchio del modulo GraphQL OPEN**: `application/graphql` raw-body by Content-Type
    (any path), JSON `query`-leaf + batch `<i>.query` e GET `?query=` **solo sui `paths` configurati**;
    riusa `waf_normalizer::graphql::unwrap_query_envelope` così non diverge mai dall'OPEN.
  - **Contributo = `Decision::Scores` additive** (mai `Reject` secco): due `rule_id` con severità
    distinte — `schema-graphql-parse-error` (body non-GraphQL, più bassa) vs `schema-graphql-unknown-field`
    (query valida ma fuori-schema, `Critical`). Dedup per-kind (un batch di N violazioni = un segnale).
    L'introspection **non** è flaggata qui (è compito del modulo OPEN). Namespace `rule_id` `schema-*`
    riservato + enforced strutturalmente (registry `rules`), disgiunto dagli id OPEN (anti-doppio-conteggio).
  - **Confine FP**: l'unica vera fonte-FP è lo **schema-drift** (app aggiornata prima della copia SDL del
    WAF) — governato dalla severità configurabile, non dall'allentare la validazione (un client conforme
    non manda mai query fuori-schema; il backend reale le rifiuta comunque).
  - **Config** `[enterprise.schema_enforcement]` (default off; `schema_path` obbligatorio se enabled →
    **boot-fatal** se manca/è invalido = fail-closed sulla config, mai sul traffico). Nessun Redis.
  - ⚠️ **No hot-reload in v1** (G5): lo schema è immutabile in-memory → **drift → restart** (come gli
    altri moduli premium, non sopravvive a SIGHUP). Il fix è il **follow-on core-0.3 `module_factory`**
    (i moduli iniettati sopravvivono E si re-init sul reload → hot-reload keep-old-on-invalid gratis per
    reputation + CRS-curated + schema insieme). La `load_schema(path)` è già una fn pura re-entrant pronta
    per quel factory.
- **Schema-enforcement gRPC** (`waf-modules-premium`, stesso crate) — **IMPLEMENTATO (2026-07-03)**: valida
  ogni messaggio gRPC **unary** contro il **descrittore reale** dell'app (`FileDescriptorSet` `.bin` da
  `protoc`/`buf`). Il `:path` (`/pkg.Service/Method`) seleziona l'input message-type; il messaggio viene
  decodificato via **`prost-reflect`** (`DynamicMessage`). Modulo strutturale (`Phase::Body`, `structural()`),
  riconosciuto via `Content-Type: application/grpc*` (niente lista `paths` — in gRPC il path È il metodo).
  - **Tre segnali** `Decision::Scores` additive sotto `schema-grpc-*`: `unknown-method` (`:path` non nel
    descrittore) → `Critical`; `decode-error` (byte che non decodificano) → `Warning`; `unknown-field` (campo
    top-level fuori descrittore) → **opt-in `flag_unknown_fields`, default off**. Dedup per-kind del batch di frame.
  - **Differenze dal GraphQL** (a verbale): (1) `GrpcExtract` OPEN non espone i byte grezzi → il modulo **de-frama
    da sé** (`[flag:1][len:4][msg]`, mirror del framing OPEN) e **salta i frame compressi** (opachi → mai
    decode-error FP); (2) protobuf **tollera by-design i campi sconosciuti** (forward-compat) → unknown-field è
    opt-in per non generare FP quando un client usa un `.proto` più nuovo della copia del WAF. Rilevamento
    unknown-field = tag-walk manuale, **scope v1 = top-level** (nested = follow-on).
  - **Config** `[enterprise.grpc_schema_enforcement]` (default off; `descriptor_path` obbligatorio se enabled →
    **boot-fatal** su descrittore mancante/invalido). `load_descriptors(path)` puro reload-ready (come GraphQL, G5).
  - **Solo unary** in v1 (streaming, grpc-web, validazione risposte, input `.proto`-via-protox = follow-on).
- **API positive-security OpenAPI** (`waf-modules-premium`, `api_schema.rs`) — **IMPLEMENTATO (2026-07-15)**: valida
  ogni richiesta REST/JSON sotto un prefisso guardato contro la **spec OpenAPI reale** dell'app (file JSON; v1
  JSON-only) — è **gestione del contratto = positive security**, non baseline detection. `Phase::Body`,
  `structural()`, `Decision::Scores` additivo, zero core. Namespace `rule_id` `schema-api-*` (registry strutturale).
  - **Estrazione mirror-OPEN**: routing/gating su `ctx.normalized.path` (decoded + traversal-resolved →
    **evasion-resistant**), query/header da `normalized` (lowercased), body JSON da `ctx.body` grezzo.
  - **Router path** (statico > templato `/users/{id}`, most-specific-first) → `unknown-route`/`method-not-allowed`
    (Critical, `unknown_route_severity`); operazione nota → validazione param (path/query/header con coercion
    stringa→scalar) + `requestBody` via **`jsonschema`** (crate maturo, no hand-roll) → `unknown-param`/
    `missing-required`/`type-violation`/`unknown-property`/`content-type`/`body-parse-error` (Warning,
    `violation_severity`); dedup per-kind.
  - **Confine**: injection value-level (SQLi/XSS nel *valore* di un param) resta OPEN §6; i cap DoS/body strutturali
    OPEN girano PRIMA. **Librerie** (A0): `oas3` (parse 3.0+3.1), `jsonschema` `default-features=false` (NO
    retriever HTTP — un WAF non fa fetch di schemi remoti); **normalizzazione 3.0→JSON-Schema al load** (il
    `nullable` 3.0 sarebbe un falso positivo). `from_config`/`CompiledSpec::compile` **boot-fatal** su spec
    mancante/invalida/non-compilabile; precompilazione per-operazione. Config `[enterprise.api_schema]` (default off).
  - **Monitor-first naturale** (additivo → non blocca da solo sotto soglia; evita il muro-FP del positive-model
    ModSecurity). Follow-on: BOLA/BFLA comportamentale, sensitive-data lato risposta, YAML pure-Rust, spec via §7.
- **IP-reputation module** (consuma §3): `Phase::Connection`, legge `StateStore::reputation`.

### Marketplace / signing dei plugin WASM (`BOUNDARY.md` §1.7, §2.4)
Il **runtime** Proxy-Wasm (`waf-wasm`, `wasmi`) è **OPEN** e carica già `.wasm` **non firmati** da
`[modules.wasm]` (skip-on-error). L'enterprise (`waf-marketplace`) aggiunge il **gate di fiducia** — **IMPLEMENTATO
(2026-07-03)**:
- **Signing**: `verify_signature` valida una **firma staccata minisign (ed25519)** del `.wasm` contro le
  `trusted_keys` configurate; `load_verified_plugin` verifica e SOLO se la firma è valida delega a
  `WasmModule::from_bytes` (API OPEN, **zero core**) — stesso buffer verificato e caricato (no TOCTOU).
- **Postura fail-closed (divergenza voluta dall'OPEN)**: un plugin firmato che **non** verifica (firma
  assente/invalida/chiave-non-fidata) è **boot-fatal**, mai skip. Motivo: nel path OPEN l'assenza degrada la
  copertura; qui una firma che non verifica è **indistinguibile da una manomissione** → si rifiuta.
- **Config** `[enterprise.wasm]` (default off): `trusted_keys` + `plugins[{wasm_path, sig_path, config?}]` +
  limiti runtime section-global. **`exclusive = true`** = rifiuta al boot una config con `[modules.wasm]` OPEN
  popolato (enforcement del lockdown: senza il flag, un `.wasm` non firmato nel blocco OPEN bypasserebbe il gate —
  limite v1 dichiarato).
- **Marketplace** completo (distribuzione/versioning/aggiornamento, PKI/cert-chain + revoca, cosign/OCI) = **follow-on**.

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

> **v1 IMPLEMENTATA (2026-07-05)** — crate `waf-controlplane` (BSL). **Osservabilità read-only**:
> ingestione + retention + drill-down + API-dashboard. Rule-management (write-path → push SIGHUP)
> **deferito dopo §8** (RBAC/audit). Servizio **axum** + **Postgres**; **DECOUPLED da `waf-core`**
> (DTO propri sul contratto JSON del decision-log → non linka il datapath). Auth v1 = bearer token
> statico (RBAC/SSO = §8). Runbook `scripts/controlplane/`. Bite-test e2e con un nodo WAF reale.
>
> **v2 ALERTING IMPLEMENTATA (2026-07-05)** — regole in config (`[[controlplane.alerts]]`) valutate
> da un **evaluator** in background: quando il conteggio (per-gruppo `client_ip`/`rule_id`) di
> `decision_events` negati in finestra supera la soglia (fuori cooldown) → riga `alerts` + **webhook**
> generico (POST JSON) + `GET /api/alerts`. Modello fired-record + cooldown DB-based. Zero-datapath
> (legge solo lo store del control plane). e2e col webhook-receiver provato. Migrazione `0003_alerts`.
>
> **DASHBOARD WEB IMPLEMENTATA (2026-07-06)** — SPA **React + Vite + TypeScript** (+ **Recharts**) in
> `crates/waf-controlplane/ui/`, consumatrice dell'API read (same-origin, **no CORS**). Viste
> **Overview** (card volumi + bar-chart, area-chart eventi-nel-tempo con range-selector, latenza
> p50/95/99 per-nodo, stato cluster) · **Events** (filtri → tabella → **drill-down** `/events/:id` col
> breakdown per-modulo) · **Alerts** (alert scattati + regole). Endpoint di supporto: `GET
> /api/decisions/series` (bucket whitelist {60,300,3600} + window cappata 7g, aggregazione in SQL) e
> `GET /api/version` (drift-check UI↔API). **Due modi di serving**: `[controlplane].ui_dir` = override
> dev (`ServeDir`); **single-binary** di produzione via `rust-embed` dietro feature **`embed-ui`**
> (`ui/dist` embeddato nel binario; un `cargo build` normale NON richiede il frontend). Asset UI
> **pubblici**, solo `/api` dietro il bearer. Auth = token in `sessionStorage` (trade-off XSS
> dichiarato → §8/SSO migra a cookie HttpOnly). Supply-chain: lockfile committato + `npm audit` in CI
> + deps dirette minime (no UI-kit). Zero-datapath (la UI è solo un altro consumatore dell'API).
> **E2E Playwright (2026-07-07)**: suite committata (`ui/tests/e2e/`) che guida la SPA in browser reale
> contro il **backend reale** (2 binari embed-ui token/session + Postgres); copre auth 2-modi, RBAC, ogni
> vista + flussi (publish rule, compliance generate/verify, audit verify). `npm run e2e`, runbook §M. CI=follow-on.
>
> **WRITE-PATH (RULE-MANAGEMENT v3) IMPLEMENTATO (2026-07-07)** — l'ultimo pezzo di §7, sbloccato da §8.
> Il control plane versiona **UN file SecRule `.conf` gestito** e lo **pusha** ai nodi, che ricaricano a
> caldo. **Zero-core** (verificato): il WAF carica il file via `[modules.crs].files` e su **SIGHUP**
> `reload_from` lo ricarica con **validate-then-swap** (regole invalide → tiene last-good). **Backend**
> (migr `0004_rules`): `rule_versions` immutabile + `rule_current` singleton (rollback = re-point) +
> `node_rule_status` (convergenza). API: **manage** (`ManageRules` operator+ + audit `rule.publish`/
> `rule.rollback`) `POST/GET /api/rules/versions`·`GET /versions/{id}`·`POST /rollback`; **agent**
> (`ReadObservability`) `GET /api/rules/current`·`POST /api/rules/status`·`GET /api/rules/nodes`.
> L'estrattore `MaybePrincipal` fa servire le stesse route a governance-ON (RBAC) e OFF (bearer statico =
> `api-token`). **Agente per-nodo** = NUOVO crate `waf-node-agent` (binario, linka `waf-detection` OPEN
> **solo per pre-validare**, NON sul datapath): polla `current` → **pre-valida** (parser seclang) → valido:
> **write-atomico** (temp+rename) + `reload_command` (SIGHUP, configurabile → portabile) + report `applied`;
> invalido: report `rejected`, **WAF intatto**. **Due livelli fail-safe** (agente pre-valida + WAF
> validate-then-swap). **UI**: vista **Rules** (Publish editor · Versions con badge current/rollback ·
> Node-convergence), nav role-gated operator+. Provato e2e (Proxy REALE: publish → agente valida+scrive →
> `reload_from` in-process = SIGHUP → richiesta 200→**403** + convergenza; reject-path: v2 invalido → WAF
> intatto) + smoke browser. Runbook §I. **Follow-on**: dry-run server-side, canary/staged rollout, diff
> versioni, ruleset multipli nominali, firma ruleset, WebSocket convergenza live, reload su Windows.

Servizio separato dal datapath (mai sulla porta dati). Consuma la **telemetria baseline
OPEN** (logging JSON strutturato + metriche Prometheus, esposte dal core) e la persiste a
lungo termine.

**Postura di isolamento / prestazioni (il control plane NON tassa il datapath).** È fuori dal
percorso della richiesta per costruzione: il binario `waf` non dipende nemmeno da `waf-controlplane`.
Due flussi, entrambi a costo ~zero sul path caldo:
- **Metriche = PULL**: uno scraper fa `GET /metrics` sul listener **dedicato/loopback** del WAF
  (default 15s). `render()` legge solo contatori atomici (`relaxed`, nessun lock condiviso con
  `handle()`). Lo scrape gira su un task di background, non ruba tempo al serving.
- **Decision-log = PUSH fuori processo**: il WAF scrive i log JSON come già faceva; un **log shipper
  esterno** li inoltra a `POST /ingest/events`. Il WAF non conosce il control plane. La correlazione
  `→ request`+`request blocked` e il parsing NDJSON avvengono NEL control plane.
- **Unica modifica lato-WAF (core 0.4)**: `score_contributions` serializzato nel decision-log **solo
  su richiesta negata** (Block/Reject) → il traffico benigno paga **zero**.
Contrasto: il `StateStore` Redis (§3) è on-datapath (per-richiesta); il control plane è puramente
osservazionale a valle. Verifica empirica nel runbook §D (bench con/senza scrape).

**Architettura v1 (fasi):** Phase-0 arricchimento OPEN core 0.4 (`score_contributions` nel
decision-log). Phase-1 store Postgres (`decision_events`+`metric_rollups`+`latency_buckets`).
Phase-2 ingestione (scraper `/metrics` → rollups; `POST /ingest/events` NDJSON → parse+correlazione
→ `decision_events`). Phase-3 API read (`/api/cluster/status`·`/decisions/volume`·`/latency`
[p50/95/99]·`/events` ricerca·`/events/{request_id}` drill-down; bearer middleware). Phase-4 bite-test
e2e (nodo WAF reale → drill-down) + runbook. **v2 = alerting** (config-rules + evaluator + webhook +
`GET /api/alerts`, migr `0003_alerts`; **FATTA**). **UI = dashboard web FATTA** (SPA React/Vite +
serving `ui_dir`/`embed-ui`). **Write-path rule-management (v3) = FATTO** (crate `waf-node-agent`,
migr `0004_rules`, vista Rules; vedi callout sopra). **Follow-on**: alerting metric/latency-based +
stato firing/resolved, connettori Slack/email nativi, OpenAPI, dry-run server-side + canary rollout per
il write-path, integrazione Prometheus/Grafana esterni.

### 7.1 Due flussi di dati (le metriche NON sono l'unica sorgente)

Il control plane ha **due input separati**, con due modelli e due store — NON deriva solo dalle metriche:

| Flusso | Modello | Sorgente | Alimenta |
|---|---|---|---|
| **Metriche** | **PULL** — scraper `GET /metrics` | endpoint Prometheus del core (B1) | dashboard aggregate: volumi/decisione, latenze (`metric_rollups`, `latency_buckets`) |
| **Decision-log** | **PUSH** — `POST /ingest/events` | il file/stdout JSON del WAF, via **log shipper esterno** | **drill-down per-richiesta** (`decision_events`) |

- Il **drill-down NON viene da `/metrics`**: le metriche sono aggregate e, per il **vincolo di cardinalità**
  (mai `path`/`ip`/`request_id` come label), non portano dettaglio per-richiesta. Il dettaglio viene dal
  **decision-log JSON**.
- Il control plane **non legge il file di log**: lo legge un **log shipper** (Vector / Fluent-bit / lo script
  di riferimento `forward_logs.sh`) che fa `tail -F` e inoltra ogni riga NDJSON a `POST /ingest/events`. Il WAF
  resta ignaro (out-of-process, zero-datapath). `ingest.rs` correla `→ request` + `request blocked` per
  `request_id` e scrive `decision_events`.

```text
WAF ──scrive──> node.jsonl ──tail-F──> [log shipper] ──POST /ingest/events?node=X──┐
WAF ──espone──> /metrics ─────────────────────────────GET (scraper, 15s)──────────┤──> control plane ──> Postgres
```

### 7.2 Un solo control plane su WAF multi-nodo

Funziona perché **entrambi i flussi sono per-nodo** e ogni dato porta l'identità del nodo (colonna `node`):

- **Metriche**: la config elenca **tutti i nodi** — `[[controlplane.nodes]]` con il loro `metrics_url`; lo
  scraper cicla su ognuno e salva rollup taggati `node`. **Reset-aware totals**: `waf_requests_total` e i
  bucket di latenza sono **counter Prometheus** (cumulativi dall'avvio del processo, si **azzerano al
  restart** del WAF). Lo scraper mantiene quindi un totale persistente reset-aware in `metric_totals`/
  `latency_totals` (delta dall'ultimo valore, o il valore grezzo quando rileva un reset), così i volumi
  dell'Overview **continuano a salire attraverso i restart** invece di crollare all'ultimo snapshot. Lo
  stato vive in Postgres → sopravvive sia al restart del WAF (rilevamento reset) sia del control plane
  (lo stato viene riletto). `GET /api/decisions/volume` **somma i cumulativi tra i nodi** per decisione;
  `GET /api/cluster/status` li elenca (last-seen da `metric_totals`); `GET /api/latency` è per-nodo
  (percentili **lifetime**). I raw `metric_rollups`/`latency_buckets` restano come storico grezzo.
- **Decision-log**: ogni nodo ha il suo shipper che fa `POST /ingest/events?node=<nome>` → `decision_events.node`
  distingue la provenienza (l'identità la mette il **shipper**, mai il core → zero-core). Ricerca/drill-down
  coprono tutto il cluster.

```text
edge-1 ─/metrics─┐        edge-1 ─shipper─┐
edge-2 ─/metrics─┼─> [1 control plane] <─┼─ edge-2 ─shipper   →  1 Postgres (colonna `node` ovunque)
edge-3 ─/metrics─┘        edge-3 ─shipper─┘
```

**Nota deployment**: il listener `/metrics` del core è **loopback di default** (info-leak se pubblico). Perché
un control plane su un altro host lo scrapi, il nodo deve esporlo su un'**interfaccia privata/di management**
raggiungibile dal control plane (rete privata / tunnel), mai su Internet. È una scelta di rete, non un limite
architetturale. Uno **shipper per nodo** (o uno centrale che legge i log di tutti) fornisce il flusso push.

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

### 7.3 API attack-surface inventory (discovery §4-B pt3) — **IMPLEMENTATO (2026-07-15)**

Il control plane costruisce un **inventario della superficie d'attacco API** dagli enforcement decision
già persistiti (`inventory.rs`, `GET /api/inventory` + `/api/inventory/drift`, vista UI "API Inventory").
**Realtà dei dati (decisiva):** `decision_events` contiene **solo richieste denied** (blocked/rejected — il
traffico benigno scade dal buffer di correlazione, mai memorizzato) → è la **superficie d'attacco vista**, NON
un inventario all-traffic. Aggregazione **on-demand** su `decision_events` (niente tabella/aggregatore
dedicati): `GROUP BY (method, path)` con hit/first/last, poi in Rust **templating** (segmenti numerici/UUID/
hex-lunghi → `{}`, così `/users/5` e `/users/6` collassano) e **classificazione** vs la spec OpenAPI
configurata (`[controlplane.api_inventory].spec_path`, opzionale, non-fatale):

- **`documented`** = path+metodo dichiarati (endpoint noto che ha comunque attirato blocchi — violazioni di
  contratto o injection contro API note),
- **`shadow`** = path/metodo NON dichiarati (endpoint non documentato colpito — il segnale forte di discovery),
- **`unclassified`** = nessuna spec configurata.

**Confine (`BOUNDARY.md` §2.2)**: read-only, off-datapath, **core-free** — il control plane NON dipende da
`waf-core` (consuma il contratto JSON OPEN), quindi il matcher path→route è una **reimplementazione standalone
(solo `serde_json`)** del `Router` del datapath (§4-B A2), non un import di `waf-modules-premium`. **Zombie**
(dichiarato-ma-inutilizzato) e discovery all-traffic = **follow-on** (servirebbe un ingest di tutto il traffico,
non solo denied). Learning-mode "genera bozza OpenAPI dal traffico" = follow-on.

---

## 8. Governance e compliance — `BOUNDARY.md` §2.3

> **v1 IMPLEMENTATA (2026-07-06)** — crate `waf-governance` (BSL), **libreria** del control plane
> (zero-core, zero-datapath; opera sullo stesso Postgres, `apply_schema` proprio). **RBAC** con 3 ruoli
> fissi (`Viewer` read-only / `Operator` [tier write riservato] / `Admin`) + matrice `Permission` pura.
> **Auth locale**: account con password **argon2id** + **sessioni server-side** (cookie **HttpOnly +
> SameSite=Strict + Secure**). Con governance ON, `/api/*` accetta **una sessione (umano, RBAC per
> ruolo) OPPURE il bearer statico** (principale macchina/admin, `actor="api-token"`); `/ingest` resta
> col bearer; governance OFF (default) = comportamento attuale (solo bearer, backward-compat). **Audit
> log firmato**: catena **SHA-256 + Ed25519** (via `ring`) tamper-evident — ogni azione (login/logout,
> user create/disable/role-change, bootstrap) è un record che concatena l'hash del precedente + firma;
> `GET /api/audit` + `GET /api/audit/verify` (ricontrolla continuità + hash + firme). Endpoint
> `POST /api/login`·`/logout`·`GET /api/me`·`/api/users`(CRUD admin)·`/api/audit`(+verify). Bootstrap
> admin da config + env; secret (audit key, bootstrap pw) da env. Migrazione via `apply_schema` (tabelle
> `gov_users`/`gov_sessions`/`gov_audit_log`). e2e HTTP provato (login→RBAC 403/200→audit verify→tamper→
> fail). **Follow-on**: SSO **OIDC** (SAML deferito), **UI governance** (la UI migra l'auth a cookie
> HttpOnly), report di compliance automatici, e sblocca il **rule-management §7 (v3 write-path)**.
>
> **v2 IMPLEMENTATA (2026-07-06)** — **SSO OIDC** + **hardening auth**. *OIDC* (crate `openidconnect`,
> Authorization Code + **PKCE**): `[controlplane.governance.oidc]` (issuer/discovery + client + redirect +
> `role_claim`/`role_map`/`default_role`; secret da env). `GET /api/auth/oidc/login`→302 IdP (flow-state PKCE/
> nonce in `gov_oidc_flows`) → `/api/auth/oidc/callback` verifica l'id_token (firma **JWKS** + nonce + aud +
> exp), mappa il claim ruoli → ruolo (highest-priv; unmapped→deny salvo `default_role`), **provisiona l'utente
> federato** (`auth_source=oidc`, no password locale; NON dirotta un account local) e apre la sessione. Provato
> **live end-to-end** (Keycloak reale + browser headless: group `waf-admins`→`admin`). *Hardening*: **service-token
> nominali** revocabili role-bound (`gov_tokens`, solo hash memorizzato, plaintext una volta; bearer-resolution
> token-nominale→static-admin) · **gestione sessioni** (list/revoke own + admin revoke-all + auto-revoca su
> disable/cambio-pwd) · **password** self-change (revoca le altre sessioni) + admin reset · **throttle login**
> brute-force (in-memory per-processo → 429). Audit esteso (login.sso, token.*, session.*, password.*). Migrazione
> in-place backward-compat (ALTER + `gov_tokens`/`gov_oidc_flows`).
>
> **UI GOVERNANCE IMPLEMENTATA (2026-07-06)** — la SPA del control plane (§7) copre ora la governance.
> **Auto-detect** dell'auth via `GET /api/auth/config`: governance-ON → login user/password (+ bottone
> **"Sign in with SSO"** se OIDC) su **cookie HttpOnly** (niente token in sessionStorage → **chiude il
> trade-off XSS**); governance-OFF → il gate a token esistente (backward-compat). Viste role-gated:
> **Users** (admin: CRUD+ruolo+disable+reset-pwd), **Tokens** (admin: crea[plaintext una volta]/revoca),
> **Audit** (admin: tabella + Verify-chain), **Account** (tutti: cambio password + proprie sessioni).
> Provata **live nei 3 modi** (session via single-binary embeddato, OIDC via Keycloak, token-mode). CSRF
> = SameSite=Strict (token esplicito=follow-on). **Follow-on residui**: throttle cluster-wide, MFA,
> CSRF-token esplicito.
>
> **REPORT DI COMPLIANCE IMPLEMENTATI (2026-07-07)** — evidenza **SOC2/PCI** period-scoped **firmata**,
> aggregata da ciò che il sistema già ha (accessi governance + audit-log firmato + telemetria WAF).
> **Read-only, zero-core/zero-datapath**, **admin** (`ViewAudit`), montata **solo con governance ON**
> (riusa il signer audit). `GET /api/compliance/report?from=&to=` (default 90g) → bundle con **4 sezioni**
> ognuna annotata coi **controlli SOC2/PCI**: access-control (utenti/ruoli/token/sessioni · CC6/PCI 7-8) ·
> audit-integrity (`verify_chain` sull'INTERA catena → `chain_ok`/`verified_through_seq` + timeline eventi
> del periodo · CC7/PCI 10) · WAF-effectiveness (denied+top-rules+nodi · PCI 6.4.2/11) · alert (CC7.2/PCI
> 10.6). Il **bundle è firmato**: `content_hash`=SHA256 del corpo canonico (via `serde_json::Value`→chiavi
> ordinate = firma order-independent, sopravvive al round-trip JSON), `signature`=Ed25519 (chiave audit);
> `POST /api/compliance/verify` ricontrolla. **CAVEAT**: denied period-accurate (righe per-evento),
> allowed/totali cumulativi (counter Prometheus, non per-periodo). Vista UI **Compliance** (date-range →
> Generate → banner integrità + sezioni + chip controlli + firma + **Print**/Verify). Provata e2e
> (genera→verify ok→tamper→fail + RBAC viewer 403) + smoke browser. Runbook §K. **Follow-on**: PDF nativo,
> archivio report immutabile, ruolo `auditor` dedicato, report per-framework separati, schedulati/emailati.
>
> **SAML — DECISIONE CONGELATA (2026-07-07): nativo NON supportato, coperto via IdP broker.** L'SSO
> moderno è **OIDC** (FATTO v2, live Keycloak). Il **SAML nativo è deliberatamente fuori scope**: la
> verifica XML-DSig (canonicalizzazione **C14N** + **XML-Signature-Wrapping**) è la classe di bug che ha
> bucato per anni le librerie SAML mature di *ogni* ecosistema; un validatore hand-rolled sarebbe **falsa
> sicurezza** — stessa disciplina di §4-B (apollo-compiler), applicata al contrario: lì si scelse la
> libreria matura perché il controllo era critico; qui la libreria matura **pure-Rust non esiste**, quindi
> non si entra nel territorio. L'unica opzione matura (`samael` → `xmlsec`/`libxml2`, storico CVE)
> tradirebbe la postura pure-Rust/no-C **proprio nel crate di trust**. Gli IdP enterprise rilevanti (Okta,
> Entra ID, Ping, OneLogin, Keycloak, Google Workspace) parlano OIDC nativamente; il residuo "solo SAML"
> si copre con un **IdP broker** (Keycloak/Dex): l'IdP SAML del cliente federato *dietro* il broker, il
> control plane parla **solo OIDC** — il rischio XML-DSig lo gestisce chi lo fa di mestiere. Costo per
> noi: una **pagina di runbook** (§J). **Nativo = follow-on demand-driven**: si rivaluta SOLO su domanda
> reale di clienti paganti bloccati dal broker-path, e SOLO verso `samael` (**MAI** un hand-roll pure-Rust).

- **RBAC**: ruoli/permessi sul control plane (read-only / operatore / admin). **[FATTO v1]**
- **SSO**: OIDC nativo · SAML via IdP broker. **[OIDC FATTO v2; SAML nativo fuori scope per scelta
  (2026-07-07) → broker Keycloak/Dex, runbook §J; nativo = follow-on demand-driven]**
- **Audit log firmati**: ogni azione operatore (edit regole, cambio soglie, reload,
  override fail-mode) → record firmato (catena verificabile) per SOC2 / PCI-DSS. **[FATTO v1:
  hash-chain + Ed25519; le azioni di rule-management si aggiungeranno quando arriva il write-path]**
- **Report di compliance automatici** + retention a lungo termine. **[FATTO 2026-07-07: bundle SOC2/PCI
  period-scoped FIRMATO (Ed25519) con integrità audit + accessi + efficacia WAF, `GET /api/compliance/report`
  + vista UI; vedi callout sopra. Retention lunga già garantita da `retention_days`. Follow-on: PDF, archivio]**

L'audit enterprise è **distinto** dal decision-log OPEN: il core logga i **verdetti** (per
richiesta); l'enterprise logga le **azioni umane/amministrative** sul control plane.

---

## 9. Integrazione e supporto — `BOUNDARY.md` §2.5

> **CONNETTORI SIEM IMPLEMENTATI (2026-07-07)** — un **forwarder** in background nel control plane
> **PUSH**-a gli eventi memorizzati (verdetti WAF negati `decision_events` + **audit firmato** `gov_audit_log`
> + alert) verso sink SIEM HTTP, normalizzati in un evento **versionato ECS-like NDJSON** (`"version":1`,
> nomi ECS dove ovvio + namespace `waf.*`). **Read-only, zero-core/zero-datapath** (legge gli store; il WAF
> ignora il SIEM). Il valore vs il log-shipper OPEN (§7) = **normalizzazione + correlazione + stream audit
> firmato + affidabilità**. **At-least-once**: cursore per-`(destinazione,stream)` che avanza SOLO su ack
> 2xx dell'intero batch (fail → non avanza, ritrasmette; il SIEM deduplica su `event.id` stabile
> `waf-<stream>-<id>`). **Backpressure = Postgres** (bound = `retention_days`, niente code in-memory); il
> **lag** (`head-cursore`) è il segnale operativo chiave, esposto da `GET /api/siem/status` + log.
> **Formatter astratto dal giorno uno** (`SiemFormatter`; v1 = `EcsNdjsonFormatter`) → CEF/LEEF/syslog +
> adapter vendor = varianti future SENZA toccare il forwarder. Config `[controlplane.siem]` (destinazioni
> {endpoint, auth_header [env `WAF_CP_SIEM_AUTH_<NAME>`], format, streams} + batch + flush), default OFF.
> Migr `0005_siem` (`siem_cursors`). Provato e2e (at-least-once: fail→cursore fermo→recover→ri-consegna;
> 3 stream normalizzati + status API). Runbook §L. **Follow-on**: CEF/LEEF/syslog + vendor adapter,
> `/metrics` CP-nativo (`siem_forwarder_lag`), TLS client-cert, DLQ, filtri, OTLP, UI SIEM.

- **Connettori SIEM**: export degli eventi (decision-log OPEN + audit enterprise) verso
  Splunk/Elastic/QRadar/… Si appoggia al logging strutturato OPEN come sorgente. **[FATTO 2026-07-07:
  forwarder PUSH → NDJSON ECS-like, at-least-once, 3 stream, `GET /api/siem/status`; vedi callout sopra]**
- **SLA support** e **guided hardening** (servizio). **[non-software]**

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

---

## 12. Deployment Kubernetes-native — `BOUNDARY.md` §2.5

Feature **interamente enterprise, zero-core datapath**: packaging dichiarativo + integrazione
ecosistema, NON una riscrittura del datapath. L'unità è **WAF-per-workload** — un Deployment
`waf-enterprise` davanti a **una** Service applicativa (`[proxy].backend` = quella Service),
scalato/policy-ato per-app. NON è un ingress-controller cluster-wide: quello richiederebbe
routing multi-backend nel core (follow-on strategico), e finché non c'è **non si promette**.

### Componenti (tutti in `enterprise/`)
- **Immagini** (`Dockerfile.*` + `scripts/images/`): build multi-arch, SBOM + scan, OCI labels.
  **Mai push su registry pubblici** — build/verify locali o registry privato; la pubblicazione
  è azione manuale dell'operatore (come `cargo publish`).
- **Chart data-plane** `charts/waf`: Deployment + agent sidecar opzionale (`shareProcessNamespace`,
  reload `kill -HUP $(pidof waf-enterprise)` — sotto k8s il WAF NON è PID 1), ConfigMap che rende
  `config.toml`, Service, PodMonitor/PrometheusRule/Grafana, NetworkPolicy, HPA/PDB, Certificate
  (cert-manager), securityContext non-root 10001/readOnlyRootFS.
- **Chart control-plane** `charts/waf-controlplane`: Deployment (auto-migrate, embed-ui) + Service
  + Ingress + Secret + Postgres/Redis bundled opzionali.
- **Operator** `crates/waf-operator` (kube-rs): CRD `WafProxy` (namespaced) → riconcilia
  ConfigMap + Deployment + Service con ownerRefs. UX dichiarativa nativa senza routing nel core.
- **Log shipping**: DaemonSet Vector (`deploy/log-shipper/`) legge lo stdout dei pod WAF e forwarda
  il decision-log al control plane `/ingest/events` — off-process, zero datapath.

### Osservabilità
Metriche ABI del core (`waf_up`, `waf_requests_total{decision}`, `waf_request_duration_seconds`)
→ PodMonitor/PrometheusRule + dashboard Grafana. Nessuna label ad alta cardinalità (path/IP/rule).

### Graceful shutdown
Interim: `preStop` sleep + `terminationGracePeriodSeconds` (il pod esce dagli endpoint prima del
SIGTERM). Il drain in-process garantito arriva con la seam OPEN additiva `Proxy::run(shutdown)`.

### Confine
Il datapath resta il solo Deployment `waf-enterprise`. Control-plane, operator e log-shipper sono
**off request-path**: osservano/generano manifest, non ispezionano traffico. Verifica end-to-end su
kind: `scripts/k8s/e2e-kind.sh` (SQLi → 403 → evento nel control plane) e CI `e2e-kind.yml`.

## 13. Request Capture — `BOUNDARY.md` §2.2

Feature **interamente enterprise, opzionale (default OFF), zero-core**: cattura la richiesta HTTP
**completa** (method/path/query/**headers/cookies/body**) delle richieste **bloccate/rejected** e la
mostra nel drill-down evento del control plane. Il decision-log ordinario porta solo metadati (per
privacy + peso); il body **non** viaggia mai nei log/Vector, ma su un **canale laterale dedicato**.

### Seam ZERO-OPEN (nessuna modifica a `waf-core`/`waf-proxy`)
Tre pezzi nel crate `enterprise/crates/waf-capture`, gated `[enterprise.capture] enabled=false`:
- **Capture module** (`WafModule` iniettato via `module_factory`, `Phase::RequestLine` + `structural`):
  clona ogni richiesta in un **ring bounded** (count + byte + TTL); è un **osservatore puro** →
  ritorna sempre `Allow`, non tocca lo score. Gli allowed sono evictati senza spedire.
- **CaptureLayer** (`tracing::Layer` nel subscriber enterprise): intercetta le righe `request
  blocked`/`rejected`, legge il `request_id`, estrae la cattura dal ring e la accoda. È **armato
  deferred** (`OnceLock`): a capture OFF costa un solo load atomico per evento.
- **Shipper**: coda bounded + retry best-effort → `POST /ingest/captures` (bearer). **Drop-on-overflow
  con metrica/log, MAI backpressure sul datapath.**

### Privacy (raw-default + tre difese obbligatorie in v1)
La cattura è **raw di default**. Poiché segreti in chiaro possono atterrare nel DB del control plane,
v1 richiede insieme:
1. **Redazione node-side per-campo** (`[enterprise.capture.redaction]`): liste `headers` + `body_fields`
   → `***REDACTED***` applicate **sul nodo** (il valore redatto non lascia mai il nodo; solo i **nomi**
   redatti sono riportati, per il banner UI). Il body è redatto in modo **strutturale** (JSON ricorsivo
   + form-urlencoded).
2. **Retention corta e indipendente** nel control plane (`[controlplane.captures] retention_hours`,
   default 168 = 7g): un reaper orario fa **hard-delete** delle catture, più aggressivo di
   `retention_days` della telemetria.
3. **RBAC `ViewCaptures` (operator+) + audit della visione**: il drill-down `GET /api/events/{id}/capture`
   è gated e ogni visione scrive una riga di audit firmata (`capture.view`) — accesso attribuibile.

### Control plane (zero-core, estende il read-model)
Migrazione `0007_captures` (`request_captures`: `request_id` PK, headers/cookies/redacted **JSONB**,
body **BYTEA**, flag `body_truncated`); `POST /ingest/captures` (bearer, idempotente `ON CONFLICT`);
`GET /api/events/{id}/capture` (RBAC + audit); reaper `run_retention`. UI: pannello **"Captured
request"** nel dettaglio evento, **reveal-on-click** (l'accesso è deliberato + auditato), con banner
redazione/troncamento, tabelle headers/cookies e body **Text/Hex** + copy/download.

### Deploy
Chart `charts/waf`: `capture.enabled` + `capture.redaction.{headers,bodyFields}` + `capture.tokenSecret`
(→ env `WAF_CAPTURE_TOKEN`, mai nel ConfigMap). Chart `charts/waf-controlplane`:
`config.captures.retentionHours`. E2e su kind: `scripts/k8s/e2e-kind.sh` estende SQLi → 403 → evento →
**cattura completa** su `/api/events/{id}/capture`.

### Confine onesto / scope v1
Reject di **connection-phase** (rate-limit) e 400 da parser-limit avvengono **prima** dell'inspection →
il capture module non li vede → restano **solo-metadati** (documentato). Costo datapath a ON = un clone
`Bytes`+headers per richiesta nel ring bounded (trascurabile). Il `CaptureLayer` è accoppiato alle
stringhe di log `request blocked/rejected` (già contratto del CP). Follow-on: cattura response-body,
connection-phase, sampling/quota per-nodo, cifratura at-rest, export forense firmato.
