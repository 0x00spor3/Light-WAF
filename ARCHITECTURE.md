# ARCHITECTURE.md — Light WAF (Layer 7)

> Documento di riferimento per il progetto. Da rileggere all'inizio di ogni
> sessione di lavoro (incluso Claude Code) per mantenere coerenza architetturale.

---

## 1. Obiettivi del progetto

Realizzare un **Web Application Firewall (WAF)** operante al **Layer 7** della
pila OSI con i seguenti requisiti non funzionali:

- **Light**: footprint di memoria contenuto, poche dipendenze.
- **Veloce**: bassa latenza aggiunta per richiesta (target < 1 ms p99 sul path comune).
- **Modulare**: ogni capacità di detection è un plugin caricabile/disattivabile.
- **Osservabile**: logging strutturato, metriche, audit delle regole scattate.
- **Sicuro by design**: gestione esplicita di fail-open / fail-closed.

### Non-obiettivi (per ora)
- **Gestione certificati a scala** (ACME/Let's Encrypt, rotation, cert multi-nodo, mTLS con PKI
  gestita) → enterprise (`BOUNDARY.md` §3.2). NB: la **terminazione TLS base, cert-da-file** È
  implementata ed è **core** (Fase 12, §11) — vedi §8 "Terminazione TLS".
- Protezioni L3/L4 (DDoS volumetrico → demandato a infrastruttura di rete).
- WAF distribuito multi-nodo con stato condiviso (fase futura).

---

## 2. Scelte tecnologiche

| Ambito            | Scelta consigliata                     | Note |
|-------------------|----------------------------------------|------|
| Linguaggio        | **Rust**                               | Sicurezza memoria + throughput |
| Modello deploy    | Reverse proxy dedicato                 | Isolamento, semplicità |
| Regex engine      | crate **`regex`** (automi finiti)      | Tempo lineare garantito, niente backtracking catastrofico (stessa garanzia di RE2); multi-pattern via `RegexSet` |
| Config            | TOML / YAML                            | Regole, soglie, modalità |
| Logging           | JSON strutturato                       | request_id, regola, score |
| Test              | Unit + integration + suite WAF esterne | GoTestWAF, OWASP CRS test suite |

---

## 3. Architettura ad alto livello

```
            ┌─────────────────────────────────────────────┐
 Client ───▶│                 WAF (reverse proxy)          │───▶ Backend app
            │                                              │
            │  ┌────────────┐   ┌──────────────────────┐   │
            │  │  Listener  │──▶│   Pipeline a fasi     │   │
            │  └────────────┘   │  (orchestratore)      │   │
            │                   └──────────┬───────────┘   │
            │                              │                │
            │   ┌──────────────────────────┼─────────────┐  │
            │   │ Normalization │ Modules  │ Scoring      │  │
            │   └──────────────────────────┴─────────────┘  │
            │              │ Logging / Metrics              │
            └─────────────────────────────────────────────┘
```

### Superficie di estensione (embedding open-core)

Il core è pubblicato su crates.io come **libreria**; un eventuale tier enterprise **dipende** dai
crate pubblicati e **implementa i trait**, senza fork (`BOUNDARY.md` §4). I punti d'iniezione sono
esposti da un builder **stabile** — ogni seam ha un default, quindi un builder senza override è
identico a `Proxy::bind`:

```rust
let proxy = Proxy::builder(&config)
    .state_store(Arc::new(my_store))    // Arc<dyn StateStore>   — default: in-memory token bucket
    .cert_source(Arc::new(my_certs))    // Arc<dyn TlsCertSource> — default: FileCertSource (PEM)
    .modules(extra_modules)             // Vec<Box<dyn WafModule>> — extra, dopo i built-in
    .build().await?;
```

I tre seam del confine OPEN→ENTERPRISE:
- **`StateStore`** (`waf-core::state`) — stato rate-limit (e futura IP-reputation). Contratto = **una
  sola operazione atomica** `try_acquire(key, cost, params) -> Acquired`, **non** get/update: il
  refill-then-consume dev'essere indivisibile, altrimenti due nodi leggono lo stesso bucket ed
  entrambi consentono (over-allow cluster-wide / TOCTOU). In-memory lo garantisce sotto un lock; Redis
  con uno script server-side. Clock e cap memoria sono **interni** allo store (fuori dall'ABI). Impl
  OPEN = `InMemoryStateStore`; Redis = ENTERPRISE.
- **`TlsCertSource`** (`waf-proxy::tls`) — provenienza del certificato. Impl OPEN = `FileCertSource`;
  ACME/rotation/mTLS-PKI = ENTERPRISE. `[tls].enabled`/`alpn` restano da config.
- **`WafModule`** — moduli di detection aggiuntivi (premium = ENTERPRISE).

**Freeze ABI (pre-publish §5)**: i tre trait sono **public ABI** congelata via SemVer. `Config` è
`#[non_exhaustive]` → aggiungere una sezione top-level futura è **additivo non-breaking** (l'esterno
costruisce da `Config::default()`/TOML, non per literal). Idem per le sub-config prese per valore da
fn pubbliche (`TlsConfig`, `NetworkConfig`, `LimitsConfig`); le altre sono protette transitivamente.

---

## 4. Pipeline a fasi (hook chain)

Il traffico attraversa una catena di fasi. Ogni fase può **ALLOW**, **BLOCK**,
**MONITOR** o contribuire con uno **SCORE**.

1. `on_connection`   — IP reputation, geo-blocking, rate limiting iniziale.
2. `on_request_line` — metodo, path, versione HTTP.
3. `on_headers`      — validazione header, anti request-smuggling.
4. `on_body`         — ispezione body (streaming a chunk, con limiti).
5. `on_response`     — leak detection, header di sicurezza in uscita.

Regola: **normalizzare PRIMA di ispezionare**. La normalizzazione avviene
all'ingresso di ogni fase che produce dati ispezionabili.

> **Fast-path di skip (Fase 7 / Pilastro 3).** Tra normalizzazione e ispezione
> contenutistica, un **prefiltro** decide se *qualche* regola di content-detection
> *potrebbe* matchare il surface canonico. Se no, l'ispezione è **saltata** e la
> richiesta prosegue come Allow (stesso forward, stesso decision-log) — ottimizzazione
> trasparente sul benigno, non un secondo percorso decisionale. Il gate è
> `Pipeline::run_inspection_gated`, **unico** punto usato sia dal proxy sia
> dall'oracolo di equivalenza. Garanzie e numeri in §7.

---

## 5. Contratto dei moduli (plugin interface)

```rust
/// Decisione restituita da un modulo
pub enum Decision {
    Allow,
    Block { rule_id: String, reason: String },
    Monitor { rule_id: String },
    /// Contributo singolo a punti espliciti (regole ad alta confidenza /
    /// scoring diretto): il modulo conosce già il peso.
    Score { rule_id: String, points: u32 },
    /// N contributi, uno per regola matchata, ciascuno con la sua severità.
    /// La pipeline risolve `severity -> points` via `[waf.severity_scores]`,
    /// così lo score cumulativo somma OGNI regola (3 Notice pesano più di 1).
    Scores(Vec<ScoreItem>),
    /// Rifiuto diretto con status HTTP esplicito, distinto da `Block` (path 403).
    /// Due usi: `status:429` (rate limiting, con `Retry-After`) e `status:400`
    /// (request smuggling, framing illegale). Veicola `status` e un `Retry-After`
    /// opzionale. In detection-only la pipeline lo logga ma non rifiuta.
    /// Tabella delle tre semantiche di deny (403/400/429) in §9.
    Reject { rule_id: String, reason: String, status: u16, retry_after: Option<u64> },
}

/// Un contributo severità-taggato emesso dentro `Decision::Scores`.
pub struct ScoreItem { pub rule_id: String, pub severity: Severity }

pub enum Severity { Critical, Error, Warning, Notice }

/// Interfaccia che ogni modulo di detection deve implementare
pub trait WafModule: Send + Sync {
    fn id(&self) -> &str;
    fn phase(&self) -> Phase;          // in quale fase si attiva
    fn init(&mut self, cfg: &Config);  // compila regole UNA volta
    fn inspect(&self, ctx: &RequestContext) -> Decision;
}
```

- I moduli sono **stateless** rispetto alla richiesta (lo stato sta nel `Context`).
- La compilazione delle regole avviene in `init()`, mai in `inspect()`. In `init()`
  il modulo filtra le regole per **paranoia level** (`rule.paranoia <= cfg.waf.paranoia_level`).
- La firma `inspect -> Decision` è invariata: un modulo restituisce **una** `Decision`,
  ma `Scores` può trasportare **più contributi** (un `ScoreItem` per regola matchata).
- Il modulo **non** assegna punti: riporta `rule_id` + `severità`. La conversione
  `severità -> punti` e l'accumulo di `ctx.score` avvengono **solo nella pipeline**.
- Ogni modulo è caricabile/disattivabile da config.

### RequestContext (struttura condivisa)
- `client_ip`, `request_id`, `timestamp`
- `method`, `path`, `raw_path`, `query`, `http_version`
- `headers` (parsed + raw)
- `cookies`
- `body` (handle a chunk + parsed: form/multipart/json)
- `normalized` (versioni canonicalizzate dei campi)
- `score` (accumulatore mutabile)
- `score_contributions` (breakdown per regola: `{module, rule_id, severity, points}`, riempito dalla pipeline per audit/logging)

---

## 6. Normalizzazione / Canonicalizzazione

Punto **critico** per evitare bypass. Step minimi:

- URL decode (singola + rilevamento doppia codifica).
- Unicode normalization (NFKC) e gestione overlong encoding.
- Lowercasing dei path dove appropriato.
- Rimozione di null byte, normalizzazione separatori path (`..`, `//`).
- Decoding coerente di body in base a `Content-Type`.

> **Passata unica condivisa (query / body / cookie).** La canonicalizzazione
> valore-per-valore è un unico helper (`canonicalize_value`): percent-decode con
> **seconda passata condizionale** se rilevata doppia codifica (difesa
> anti-doppia-codifica) + **NFKC**. La usano query, body **e cookie**, così
> "normalizza una volta, ispeziona dati puliti" vale per tutti i campi e **tutti**
> i moduli di content-inspection (SQLi/XSS/RCE/LFI-RFI/Header-injection) ne
> beneficiano senza modifiche. Differenza voluta: i cookie usano `+` **letterale**
> (RFC 6265 non sono form-encoded), query/body trattano `+` come spazio.
> **Ordine vs limiti**: i cookie sono decodificati **dopo** l'applicazione dei
> limiti difensivi (count `max_cookies`, `max_header_size` sull'header grezzo),
> mai prima — un cookie corto encoded non può espandersi oltre i limiti già
> validati.

> **Field-coverage multipart (10b-cont + fix).** Per `multipart/form-data`
> l'ispezione copre, per OGNI part, **tutti e tre** i campi: il `name`, il
> `filename` e il **valore** del part. gotestwaf (`community-lfi-multipart`)
> nasconde il traversal nel **`name=`** (senza `filename`!) o nel valore, spesso
> **double-/overlong-encoded** — il fix B1-cont iniziale guardava solo `filename` e
> veniva bypassato. Parsing del `Content-Disposition` **case-insensitive** su header
> (`Content-disposition`) e attributi (`name`/`filename`). Ogni campo passa per
> `canonicalize_multipart_field` (vedi sotto) PRIMA delle regole. È estensione del
> **campo ispezionato** + normalizzazione, non broadening di pattern: girano le
> stesse regole path-traversal/LFI. (Solo i campi del part; il `name` resta
> contenuto attaccante, non metadato di routing.)

> **Deep-normalization multipart — overlong/`../`-base CHIUSO sul multipart
> (10b-cont fix).** `canonicalize_multipart_field` applica, prima del match: (1)
> percent-decode + collapse-overlong **ricorsivi** fino a punto fisso (cap 5 passate)
> → `%25C0%25AE`→`%C0%AE`→byte `0xC0 0xAE`→`.` e `..%2f`/`..%5c`→separatori; (2)
> NFKC. Gli **overlong-UTF8** 2-byte che codificano un ASCII (`0xC0/0xC1`, illegali)
> sono mappati al loro carattere PRIMA del `from_utf8_lossy` (altrimenti → `U+FFFD`,
> firma persa). Così `%25C0%25AE…etc%25C0%25AFpasswd` nel valore/`name` di un part
> risolve a `../../etc/passwd` ed è bloccato.

> **Overlong PIPELINE-WIDE — limite query/path RIMOSSO (Fase 10c).** Il collapse-overlong
> 2-byte è stato **promosso dalla scoped-multipart alla passata condivisa**
> `canonicalize_value` (query / body / cookie / multipart, un'unica sorgente di verità).
> Il limite residuo 10b-cont (`pt-overlong-utf8-passwd-query` come `ExpectedMiss`) è
> quindi **chiuso**: `?file=%C0%AE%C0%AE%C0%AF…` ora risolve a `../../etc/passwd` ed è
> bloccato come nel multipart. Il re-gate FP/perf richiesto per la generalizzazione è
> stato eseguito (P2 ladder invariata, FP 0, inspection flat) — vedi §11 Fase 10c.

> **Canale base64-derived (Fase 10c) — `decode-then-match-then-discard`.** Oltre alla
> canonicalizzazione *in-place* (sopra), §6 costruisce un canale **DERIVATO** separato:
> `normalized.derived_decoded`, una lista di varianti base64-decodificate dei valori
> ispezionati (query-value, body form/json/multipart, header non esclusi). Il prefilter
> e **ogni** modulo leggono `derived_decoded` in aggiunta alla superficie canonica, così
> un payload `Base64Flat` (es. `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`) viene decodificato
> a `<script>alert(1)</script>` e preso dalla regola del modulo competente.
> - **`decode-then-match-then-discard`**: una variante derivata contribuisce SOLO se
>   matcha una regola; altrimenti è scartata. Per questo la **candidacy** (`is_base64_candidate`:
>   alfabeto `[A-Za-z0-9+/]`+`=`, lunghezza `%4==0` e `≥ BASE64_MIN_LEN`) è un **gate di
>   COSTO, non di sicurezza** (reject O(1) sul traffico non-base64), e il blob decodificato
>   è tenuto solo se **`mostly_printable`** (≥90% ASCII stampabile): un token/hash benigno
>   ad alta entropia decodifica a rumore senza firma → scartato → **niente FP**.
> - **Budget condiviso `PIPELINE_CAP = 5`**: UN solo contatore di passate di fixed-point
>   è condiviso fra i due stadi (overlong-collapse + base64-recurse, incluso base64-of-base64
>   e base64-che-avvolge-percent/overlong) → terminazione garantita, linear-time (§13).
> - **I due canali hanno freeze-implication OPPOSTE.** L'**overlong** è un canale
>   *canonico* (stesso valore, re-encoding legale risolto) → è **pipeline-wide senza
>   eccezioni**. Il **base64** è un canale *derivato* statistico → ha un'**esclusione
>   header per-nome** (D3): `Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie`/
>   `ETag`/`If-None-Match`/`If-Match` + ogni header `*-token` sono base64-benign-heavy e
>   ad alto volume, quindi la scommessa decode-then-match lì non paga e li escludiamo.
>   I **cookie** sono fuori dal canale base64 (session-cookie base64-benign-heavy) ma
>   restano dentro il canale overlong/canonico.
> - **Leaf JSON via canale derivato (10c REOPEN, pcap-driven).** I valori-stringa di un
>   body `application/json` sono un punto cieco scoperto col pcap: `serde_json` fa già
>   l'unescape di `\uXXXX`/`\n`/… (NON serve uno stadio di JSON-unescape, e `\xNN` non è
>   JSON valido → serde rigetterebbe il body), ma il leaf è poi **ispezionato RAW** —
>   diversamente da form-urlencoded (decodificato al parse) e multipart (decodificato in
>   `body_str_values`), il leaf JSON non vede mai `canonicalize_value`. Così un leaf
>   `%25C0%25AE…`/`%3CsvG…` arriva ai moduli ancora codificato → bypass. Fix:
>   `json_leaf_derived` alimenta il canale **derivato** con la forma decodificata del leaf
>   (percent+overlong fixed-point, spinta solo se DIVERSA dal raw; + espansione base64),
>   condividendo l'**unico** `PIPELINE_CAP` (nessun nuovo cap). **Lo storage del leaf NON
>   è mutato** (decode-then-match-then-discard); il decoded entra solo via `derived_decoded`.
>   **Ricorsivo su ogni livello**: `flatten_json` discende oggetti+array, quindi ogni leaf
>   annidato (`{"a":{"b":payload}}`, array) è coperto — un wrapper non re-introduce il bypass.
>   Control isolante (probe): lo stesso `%25C0%25AE…` in query → score 12 (passa per
>   `canonicalize_value`); in leaf JSON pre-fix → score 0. FP-gate: trap base64-like/overlong
>   sulla superficie JSON-leaf → `benign_FP=[]` (alta-entropia scartata da `mostly_printable`).
> - **`derive_variants` — il canale derivato è MULTI-TRASFORMAZIONE (10c).** Oltre al base64,
>   ogni valore ispezionato passa per un insieme di trasformazioni anti-evasione, tutte
>   `decode-then-match-then-discard` (la variante conta SOLO se matcha una regola → niente FP):
>   - **§6-D1 entity-decode di EVASIONE** (`html_entity_decode_evasion`): decodifica entity named
>     (`&lpar;`→`(`, `&colon;`→`:`, `&equals;`→`=`, …) e numeriche (`&#99;`/`&#x28;`) **ESCLUDENDO
>     i 5 char strutturali `< > & " '`** — così l'escaping benigno (`&lt;b&gt;`) resta inerte,
>     l'evasione (`javas&#99;ript:`, `confirm&lpar;1&rpar;`) si risolve.
>   - **§6-D2 mid-token tag-strip** (`strip_midtoken_tags`): droppa un `<…>` SOLO se circondato
>     da word-char su entrambi i lati (`\w<…>\w`) → la mutation `o<x>nfocus`→`onfocus`, mentre i
>     tag che AVVOLGONO parole intere (`<code>onerror</code>`) restano → zero FP.
>   - **§6-D2b mid-token control-strip** (`strip_midtoken_controls`): droppa un run di control C0
>     (NUL/`0x01`–`0x1F`, esclusi `\t\n\r`) fra word-char → `<<scr\0ipt>`→`<<script>`.
>   - **§6-D3 de-obf VBScript-concat** (`strip_vbscript_concat`): fonde i giunti `"…&…"` della
>     concatenazione VBScript (`"Ex"&"e"&"cute`→`Execute`) per la forma well-formed `%26`.
>   **COMPOSIZIONE (cardine, scoperto col probe)**: le trasformazioni strutturali sono applicate
>   anche a OGNI variante **base64-decodata**, non solo al raw — un payload `Base64Flat` ha come
>   raw il blob opaco (niente `<`/`&`/control), quindi senza la composizione la mutation
>   decodificata resterebbe non-ricostruita (era il bug `o<x>nfocus`/`<<scr\0ipt>` Base64Flat).
>
> **Deferral 10d tracciato (NON silente) — `hdr-overlong-crlf-header-value`.** Un overlong
> LF `%C0%8A` (= `\n`) in un **valore di header** ispezionato da `header_injection` resta
> `ExpectedMiss{until_phase:"10d"}`: ripiegarlo nella superficie CRLF di quel modulo è un
> **cambio canonico** dell'input-surface senza bite in 10c (per disciplina §13 un cambio
> canonico entra con il suo bite + re-gate P1/P2/P3 completo). Documentato e sotto-test,
> non un buco silente; flippa a `Triggers` a 10d.

> **XSS-URL evasion — CHIUSO in 10c (era B2-cont).** Le due famiglie che mancavano di una
> passata di normalizzazione sono ora prese dal canale `derive_variants` (vedi sopra),
> `decode-then-match-then-discard`, senza aprire un FP-factory:
> - **Entity-obfuscation** (`javas&#99;ript:`, `confirm&lpar;1&rpar;`, `&lt;svg/onload&equals;…`):
>   `html_entity_decode_evasion` (§6-D1) decodifica le entity di evasione **escludendo** i 5 char
>   strutturali `< > & " '` → l'escaping benigno resta inerte.
> - **Mutation / tag-splitting** (`autof<x>ocus o<x>nfocus=…`, `<<scr\0ipt>`): `strip_midtoken_tags`
>   (§6-D2) e `strip_midtoken_controls` (§6-D2b) ricostruiscono il token SOLO mid-token (`\w<…>\w`)
>   → niente FP su markup che avvolge parole intere.
>
> NB residuo (frozen by-design): il **whitespace-collapse intra-token** (`java sc ript`, D2b-2) resta
> rinviato (alto FP su prosa, 0 payload wire); e alcuni "bypass" XSS-URL sono `Warning`/PL2 sub-soglia
> per la scelta anti-FP di accumulo (§7, Bucket-B) — bloccarli implicherebbe alzarne la severity (congelata).

> **SQLi-URL / MSSQL — CHIUSO in 10c (era B3-cont → 10b-bis).** Le 3 famiglie "medie"
> (inline-comment `/*!UNiOn*/`, subquery `information_schema`, stacked/blind `sleep()`) e le
> JSON-function (`JSON_EXTRACT`/`JSON_DEPTH`) bloccavano già (Critical). L'`xp_cmdshell` con
> padding di commenti (`3;/* a */…EXEC …xp_cmdshell @c`), prima sub-soglia, è ora preso dalla
> regola **`sqli-mssql-dangerous-proc`** (xp_cmdshell/xp_dirtree/xp_reg*/sp_oacreate/… Critical).
> **Invocation-anchored** per disciplina anti-FP: il proc-name conta solo se preceduto da
> `[.;(=]` o `exec[ute] [schema.]` (così il wire `Master.dbo.xp_cmdshell` matcha ma la prosa
> benigna `"how to disable xp_cmdshell"` NO — probe-dimostrato). `severity_scores` restano congelati.

### Limiti difensivi (anti-DoS sul parser)
- Dimensione massima header / body.
- Numero massimo di parametri / cookie / header.
- Profondità massima JSON/XML.

---

## 7. Anomaly Scoring

Modello ispirato a OWASP CRS: blocco **non binario** ma cumulativo.

- **Severità configurabili** (`[waf.severity_scores]`): `critical/error/warning/notice`
  → punti. Niente punteggi hardcoded nei moduli; ogni regola dichiara solo una severità.
- **Accumulo centralizzato nella pipeline**: ogni regola matchata (via `Decision::Scores`)
  aggiunge `severity_scores[severità]` al `ctx.score`. Lo score è la **somma di tutti i
  match**, sia tra moduli (SQLi + XSS) sia entro lo stesso modulo (3 Notice = 3×notice).
- **Tracciamento contributi**: la pipeline registra in `ctx.score_contributions` chi
  (`module`/`rule_id`/`severità`) ha aggiunto quanti `points`, per audit/logging.
- **Soglia configurabile** (`block_threshold`): se `score >= block_threshold` →
  in modalità `blocking` BLOCK, in `detection-only` solo log; altrimenti ALLOW.
- **Convivenza `Block` ↔ scoring**: `Decision::Block` resta una scorciatoia che blocca
  (in `blocking`) **a prescindere dallo score**, riservata a regole ad altissima confidenza;
  `Decision::Score`/`Scores` alimentano invece l'accumulo cumulativo. Entrambi i percorsi
  passano dalla stessa pipeline, unico punto che decide il verdetto finale.
- **Livelli di paranoia** (`paranoia_level`, 1..=4): ogni regola dichiara la paranoia
  minima a cui si attiva; `init()` compila solo le regole con `paranoia <= paranoia_level`.
  Livelli più alti = più regole = più aggressivo (e più falsi positivi).
- **Logging della decisione**: alla fine della pipeline si emette un record con
  `score` totale, `threshold`, `mode`, verdetto e il dettaglio dei contributi.

### Taratura dei pesi e della soglia (Fase 7 / Pilastro 2)

La taratura di `[waf.severity_scores]` e `block_threshold` è **giustificata
dall'evidenza del corpus** (§10), non da default ereditati. Tre fatti misurati la
inquadrano, senza edulcorarli:

- **Il corpus benigno NON vincola la soglia.** Tutti i benigni scoreano 0 (nessuna
  regola matcha): per qualunque `threshold >= 1` il margine benigno è `threshold-0`.
  Quindi la soglia **non separa** benigno da malevolo (qui è triviale) — **codifica
  la POLICY DI ACCUMULO**: quanti segnali deboli co-occorrenti servono per bloccare.
  La recall 100% del Pilastro 1 è **detection** recall (una regola matcha), distinta
  dalla **blocking** recall (`score >= soglia`) che il Pilastro 2 misura ex novo.
- **Critical blocca per merito proprio; Warning/Notice solo in accumulo.** Un
  segnale debole isolato è FP-prone: es. `rfi-remote-url` è Notice/PL3 **perché
  matcha qualsiasi URL** — farlo bloccare da solo bloccherebbe ogni `?redirect=
  https://…` in produzione. Il corpus mostra FP=0 solo perché **evita per
  costruzione** quegli input, non perché sia sicuro abbassare la soglia. Perciò i
  deboli restano sotto soglia by-design.
- **Config raccomandata C2**: `critical=6, error=4, warning=3, notice=2`,
  `block_threshold=5`. Alza Critical 5→6 così un singolo Critical blocca con
  **margine +1** (robustezza che il default CRS 5/T5 non ha), senza toccare la
  soglia né far bloccare i deboli (lone Warning 3 / Notice 2 / `2×Notice`=4 restano
  sotto 5). Scartate sull'evidenza: **C1** (`T4`) perché `2×Notice=4` bloccherebbe →
  FP di massa; **C3** (rescale ampio) perché elimina l'accumulo Warning+Notice e
  abbassa la blocking-recall. Lo sweep ha verificato che C2 ha lo **stesso
  blocking-set di C0**, benign-blocking 0 a ogni PL, `validate()` OK.
  **`block_margin` own-merit**: **PL1/PL2 +1** (vincolo = un Critical), **PL3 +0** —
  e quel +0 è **by-design**: il caso che lega il margine non è un Critical fragile
  ma `lfi-rfi-remote-script` con own = Warning(3)+Notice(2)=5, cioè la ladder
  "Warning+Notice in accumulo bloccano alla soglia". Pinnata e validata in
  `tests/validation.rs` (cinque proprietà-ladder).

**Limiti espliciti (onestà > apparenza di completezza):**
- **Overlap-masking (§8)**: a PL3 tre malevoli bloccano **solo** via overlap
  cross-modulo `rfi-remote-url`, non per merito proprio: `rce-download-exec-query`,
  `ssrf-loopback-query`, `ssrf-ip-obfuscation-query` (own=3, total=5). Il gap
  blocking-recall **own 50% vs total 56%** a PL3 quantifica il masking (3/50). Da
  leggere assieme a §8.
- **Assenza di malevoli multi-segnale intra-modulo**: il corpus non contiene casi
  che accumulano più regole dello **stesso** modulo. Il comportamento d'accumulo
  ("2×Warning blocca", "Warning+Notice blocca") è quindi **predetto dall'aritmetica**
  e testato solo da overlap incidentali, non da casi dedicati. Lavoro futuro
  post-congelamento, non colmato ora (detection congelata).

**Stato**: C2 è validata nel corpus e pinnata in `tests/validation.rs`, e il default
di produzione in `waf-core` è **allineato a C2** (`default_critical_score = 6`); il
test `waf-pipeline` che asserisce il default è aggiornato di conseguenza
(`c.points == 6`). Gli altri pesi restano CRS (`error=4, warning=3, notice=2`),
`block_threshold` default = 5.

### Fast-path di equivalenza (Fase 7 / Pilastro 3)

Riduce il costo del path completo sul traffico benigno **senza cambiare un verdetto**.
L'equivalenza è **testata** sul corpus (oracolo), non assunta.

- **Prefiltro scope-aware sound.** Unione `RegexSet` di tutte le regole content
  attive (derivata dalle stesse tabelle `*_RULES` → nessun drift), valutata sul
  **surface canonico** (post-§6). Soundness per costruzione: un match è l'OR di tutti
  i pattern → **nessun match ⟹ nessuna regola matcha ⟹ Allow**. Può solo sbagliare
  verso "candidate" (gira il full-path), mai verso uno skip errato.
  - **Due bucket di scope**: `MAIN` (6 moduli-content + header-injection non-host) su
    un **superset** delle superfici reali {path,query,cookie,header,body}; `HOST` (sole
    regole `Scope::HostHeaders`, pattern `[/@]` largo) **solo** sui valori host.
    Un'unione scope-blind matchava il `/` di ogni path → 0 skip; lo split lo risolve.
- **Char-pre-check SCARTATO come unsound** (mai implementarlo): (1) keyword
  alfanumeriche (`union select`, `sleep(`, `/etc/passwd`); (2) evasione §6
  (`%3C`/fullwidth → `<`). Entrambi = falsi negativi.
- **Equivalenza asimmetrica (DEC 1)**: coincide la **decisione** (Allow/Block/Reject);
  `score`+`matched_rules` solo dove l'ispezione gira (uno skip non li calcola; lo
  short-circuit-su-block già produce rules parziali by-design). **Fail-safe (DEC 3)**:
  fast→full inutile = solo perf; skip che nasconde un block = **falso negativo critico**
  → assert che urla.
- **Oracolo + guardie** (`tests/validation.rs`) sul gate reale `run_inspection_gated`:
  decisione full≡fast su 79 casi × PL1-3; soundness; completezza + **scope-correspondence**
  (bucket host == regole `Scope::HostHeaders`, derivato dalla sorgente); 2 fixture
  avversari (keyword-benigna + encoded). Il **bite-test** (mis-scoping/char-check
  deliberati) rende l'oracolo rosso su 3 fronti, verde al ripristino — la guardia morde.
- **Guadagno misurato** (`examples/fastpath_bench.rs`, @C2/PL3): **29/74** skip-eligible
  (tutti i benigni + 3 gap), **11.74×** sul path benigno (1520→130 ns), overhead 6.7%
  sul malevolo. Net positivo su traffico in maggioranza benigno.
- **Costruzione unica** (`build_reloadable`): prefiltro e pipeline dallo stesso snapshot
  → reload li rigenera insieme, mai disallineati.

---

## 8. Catalogo moduli (roadmap)

| Modulo            | Fase        | Priorità |
|-------------------|-------------|----------|
| Normalization     | tutte       | P0 ✅ |
| SQLi              | body/query  | P0 ✅ |
| XSS               | body/query  | P0 ✅ |
| Path traversal    | request_line| P1 ✅ |
| RCE / Cmd inj.    | body/query  | P1 ✅ |
| LFI / RFI         | query       | P1 ✅ |
| SSRF              | body/query  | P1 ✅ |
| Header injection  | headers     | P1 ✅ |
| Request smuggling | connection  | P1 ✅ |
| Rate limiting L7  | connection  | P1 ✅ |
| GraphQL (strutturale)| body     | Fase 11 ✅ |
| gRPC (strutturale)| body     | Fase gRPC ✅ |
| Geo / IP reputation| connection | P2 |
| Bot detection     | headers     | P2 |

Ogni modulo di detection è attivabile/disattivabile via config con la sezione
`[modules.<nome>]` e il flag `enabled` (es. `[modules.path_traversal] enabled = true`).
I moduli condividono lo schema di scoring della §7 (severità da `[waf.severity_scores]`,
filtro per `paranoia_level`); nessun punteggio è hardcoded nei moduli.

> **Tuning regole (pre-Fase 7, baseline FP pulito)** — tre pattern Critical/Warning
> sono stati **ristretti** per falsi positivi noti su traffico legittimo (id,
> severità e `paranoia_level` **invariati**, cambia solo il `pattern`; recall
> dimostrato dai test positivi esistenti):
> - `xss-event-handler`: da `on\w+=` (matchava `?online=true`, `?onsale=1`) a una
>   **lista chiusa** di event-handler reali (`onerror|onload|onclick|on…`).
> - `sqli-tautology-or` / `sqli-tautology-and`: la char-class includeva lo **spazio**
>   con `+`, attraversando frasi (`men or women=adult`, `color or size=large`).
>   Ora gli operandi sono **numerici o singolo-carattere** (`1=1`, `'a'='a'`, `x=x`).
>   NB: il crate `regex` non ha backreference → non si può imporre l'uguaglianza dei
>   due lati; il restringimento operando è l'approssimazione backref-free che separa
>   le tautologie iniettate dai `parola=parola` benigni.

> Rate limiting L7 (`[rate_limit]`, fase `on_connection`):
> - **Token bucket** per chiave: O(1) tempo/memoria, burst configurabile (`burst`),
>   refill = `requests / window_seconds` token/s. Scelto su fixed/sliding-window
>   per assenza di effetto-bordo e footprint costante (obiettivo light/fast).
> - **Esecuzione pre-normalizzazione**: la fase `on_connection` gira **prima** di
>   Fase 2 (`Pipeline::run_connection` nel proxy), così il traffico oltre-soglia è
>   rifiutato senza pagare il parsing.
> - **Azione** (`action`): `block` → `Decision::Reject` (HTTP **429** + `Retry-After`
>   calcolato dal bucket `ceil((1-tokens)/refill)`); `score` → contributo allo score
>   cumulativo (§7). In **detection-only** il superamento è loggato ma non rifiuta.
> - **Chiave** (`key`): `client_ip` = `ctx.client_ip`, ovvero l'**IP risolto** dal
>   resolver trusted-proxy condiviso (vedi §9 e `[network]`), **non** più la peer
>   addr grezza. ✅ **Opzione B risolta**: dietro un LB/CDN *fidato* la chiave è il
>   client reale preso da `X-Forwarded-For` contando gli hop da destra; il rate
>   limiter non legge l'IP direttamente — usa `ctx.client_ip`, derivato una volta
>   in `build_context`. L'enum `RateLimitKey` resta predisposto per chiavi future
>   (header, path).
> - **Memoria**: cap `max_tracked_keys`; allo sforamento si fa sweep dei bucket
>   idle (pieni → indistinguibili da chiavi nuove, quindi evictabili).

> Nota path traversal: il normalizzatore (Fase 2) **risolve già** `.`/`..` nel
> path, quindi le sequenze `../` si rilevano su query/cookie/body (dove
> sopravvivono dopo il decode), mentre sul `normalized.path` si rilevano i
> **target sensibili** (es. `/etc/passwd`) che restano dopo la risoluzione.

> Confini tra moduli (per evitare doppio conteggio dello score cumulativo):
> - **Path Traversal** = manipolazione del filesystem (`../`, `/etc/passwd`,
>   null-byte, UNC).
> - **LFI / RFI** = *meccanismi di inclusione* di codice/script: wrapper/stream
>   (`php://`, `phar://`, `data://`, `expect://`, `file://`, …) e inclusione
>   remota (`http(s)://`/`ftp://` di uno script). Non ri-rileva i path filesystem.
>   Pur essendo nel catalogo come fase `query`, **ispeziona query + body + cookie**
>   (l'LFI/RFI via POST esiste).
> - **SSRF** = il server che effettua richieste verso URL controllati
>   dall'attaccante (metadata `169.254.169.254`, `localhost`, schemi `gopher://`,
>   `dict://`). Rileva il **target** (IP/host/scheme SSRF-specifici), non gli
>   scheme `http(s)://`/`ftp://`/`file://` (che restano a RFI/LFI). Quindi
>   `http://169.254.169.254/` prende `rfi-remote-url` (Notice, debole) **e**
>   `ssrf-cloud-metadata` (Critical) — segnali diversi, non ridondanti.

> Note Header injection (CRLF / response splitting):
> - **Insight hyper**: il crate `http`/hyper **rifiuta CR/LF/NUL nei valori header
>   in ingresso** al parse, quindi la CRLF injection *negli header* non arriva al
>   WAF. La superficie viva è il **CRLF percent-encoded nei param query/body**
>   (`%0d%0a…Set-Cookie:`), decodificato da Fase 2 e potenzialmente riflesso dal
>   backend in un response header, più la **Host injection ad absolute-URI**
>   (`Host: http://evil`, che hyper accetta).
> - **Modulo field-aware**: a differenza degli altri moduli, le regole hanno uno
>   `scope` (All / NonBody / HostHeaders / Body) perché il CR/LF nudo è anomalo in
>   query/cookie/header ma legittimo nel body (textarea) — lì è Notice/PL3.
> - **Nota sulle fasi**: `phase()` indica solo l'**ordine** di esecuzione in
>   pipeline, **non** il campo ispezionato. Header injection è in `Phase::Headers`
>   ma ispeziona anche query/body (i dati normalizzati sono tutti disponibili a
>   prescindere dalla fase).
> - **Confine hyper**: condiviso con Request Smuggling — l'invariante "hyper
>   sanitizza il framing/header a monte" è descritto **una sola volta** nella nota
>   Request Smuggling (assunzione di sicurezza esplicita).

> Note Request Smuggling (modulo **strutturale**, non content-inspection — Fase 6/P4):
> - **Cos'è**: validazione del **framing HTTP** (confini del body: `Content-Length`
>   vs `Transfer-Encoding`). Lo smuggling è il disaccordo tra come WAF e upstream
>   interpretano quei confini; **inoltrare** un framing ambiguo È il vettore. Perciò
>   gira in `Phase::Connection` (in `run_connection`, **prima** di normalizzazione e
>   detection) e su framing illegale **rifiuta con 400** — **binario**, mai `Scores`.
> - **Regole** (tutte → `Reject{400}`): (1) CL **e** TE simultanei; (2) CL duplicato
>   o valore non-intero/lista; (3) TE duplicato o ≠ singolo token `chunked`
>   (case-insensitive) — `xchunked`, `chunked, chunked`, liste `gzip, chunked` incluse.
>   Postura **strict**: l'unico TE accettato è `chunked` (le liste sono il terreno
>   dello smuggling e ri-serializziamo comunque verso il backend).
> - **⚠️ ASSUNZIONE DI SICUREZZA ESPLICITA (confine hyper)**: l'**igiene del framing
>   a basso livello** — whitespace prima dei `:`, obs-fold, OWS attorno ai valori,
>   CR/LF/NUL negli header — è garantita da **hyper** che la **rifiuta/normalizza al
>   parse**, *prima* che i moduli vedano la richiesta; in più il WAF **parsa e
>   ri-serializza** verso il backend (il client hyper rigenera CL/TE), neutralizzando
>   strutturalmente gran parte dello smuggling. Questo modulo è **difesa-in-profondità**
>   sulle ambiguità semantiche residue. **Se si cambia parser HTTP, o si introduce un
>   path senza ri-serializzazione, le Rule 4 (whitespace-pre-`:`/obs-fold) vanno
>   re-implementate sui byte grezzi qui.** Vale anche per Header injection (CR/LF).
> - **Test**: la logica è coperta da **unit** deterministici (hyper non interferisce);
>   l'integration usa `gzip, chunked` (hyper lo accetta perché termina in `chunked`,
>   il modulo strict lo rifiuta) per esercitare lo stack completo fino al 400.

> Note SSRF:
> - **Overlap intra-modulo dichiarato**: `169.254.169.254` matcha sia
>   `ssrf-cloud-metadata` (Critical) sia `ssrf-private-ip` link-local (Notice, a PL3)
>   → contributo additivo 5+2 a PL3. È difesa-in-profondità voluta, non un bug.
> - **Gap noto (offuscamento IP)**: le regole decimale/hex/ottale coprono solo
>   `127.0.0.1`, non l'IP metadata (`169.254.169.254` decimale = `2852039166`).
> - **Gap noto (IPv6)**: la copertura è limitata a `[::1]` e `fd00:ec2::254`;
>   mancano `fc00::/7` (ULA) e `fe80::/10` (link-local IPv6).
> - Entrambi i gap sono presidiati da casi `ExpectedMiss` nel corpus di validazione
>   (§10): tracciati, non gating; se un giorno scattano, il caso va promosso a
>   `Triggers` (regressione in meglio).

> Cookie ora normalizzati come query/body (percent-decode double-aware + NFKC):
> un payload codificato in un cookie (es. `php%3a%2f%2f`) viene sciolto e le regole
> basate sul decode scattano anche sui cookie, per **tutti** i moduli di
> content-inspection. Vedi §6 (passata unica condivisa) per il punto e l'ordine
> rispetto ai limiti difensivi. NB: `parse_cookies_limited` conserva ancora il
> testo grezzo (per logging/limiti); il decode avviene **dopo**, nello stesso
> punto in cui si decodificano query/body.

> Note GraphQL (modulo **strutturale**, non content-inspection — Fase 11):
> - **Cos'è**: come `request_smuggling`, NON ispeziona contenuto (l'injection negli
>   argomenti/variabili è già presa dal canale JSON-leaf/derived, §6). Applica **cap
>   DoS/abuse sulla FORMA** dell'operazione GraphQL: profondità del selection-set, conteggio
>   alias/field/directive, dimensione del batch, + policy di introspection. I conteggi
>   vengono da una passata **lessicale** (`graphql_lex`, l'8° parser custom, fuzzato §13):
>   **depth paren-aware** (`{` conta solo fuori dagli argomenti `(...)`, così un input-object
>   annidato non gonfia la profondità), salta string/block-string/commenti.
> - **Transport**: estrae la query da JSON `query`/`<i>.query` leaf e GET `?query=` **solo sui
>   `paths` configurati** (così una JSON-API non-GraphQL con un campo `query` non è toccata),
>   e da un body `application/graphql` (per Content-Type, qualsiasi path). Default **OFF**
>   (endpoint-specifico, cap da tarare).
> - **Decisione**: cap DoS oltre soglia → `Reject{400}`; introspection (se `block_introspection`)
>   → `Block{403}`.
> - **⚠️ Modulo STRUTTURALE in `Phase::Body` → `WafModule::structural() = true`**: il fast-path
>   (Pillar 3, §7) prova "nessuna regola **content** può matchare" e salta l'ispezione content;
>   ma non può provare inerte un modulo strutturale, quindi gli strutturali girano **anche sul
>   percorso di skip** (`run_phases_filtered(structural_only)`). Senza questo flag un DoS GraphQL
>   privo di firma content-regex **bypasserebbe** il modulo. Regola: un nuovo modulo strutturale
>   `Phase::Body` DEVE marcarsi `structural()`.
> - **Fix §6 collegato (Step-0)**: un body `application/graphql` è `ParsedBody::Raw`, ispezionato
>   grezzo da `body_str_values` → la forma percent-decodata non veniva ispezionata (bypass
>   injection-encoded). Il collector body-derived ora spinge il **canonical del Raw-body** nel
>   `derived_decoded` (come `json_leaf_derived`).
> - **11-bis (gotestwaf re-capture, wire-driven)** — due bypass d'introspection, **due cause/layer
>   distinti**:
>   - **(a) buco §6 body-parsing CT-less** (generico, non GraphQL): un body **senza `Content-Type`**
>     cadeva su `ParsedBody::Raw` (il JSON è parsato solo con `application/json`) → il canale
>     **per-leaf** §6 (`json_leaf_derived`) era saltato e restava solo il canonicalize whole-string.
>     Conseguenza: un'injection **encoded-in-leaf** (base64 / JSON `\u`) bypassava droppando il CT
>     (il plaintext no — la stringa grezza è comunque ispezionata). Fix = **`parse_body` sniff JSON**:
>     se il body sembra JSON (`{`/`[`) e parsa, è trattato come `application/json` (`body.rs::sniff_json`);
>     altrimenti `Raw`; errore di depth propagato (fail-closed). Beneficia **tutti** i moduli.
>   - **(b) transport GraphQL su GET**: gotestwaf mette nell'`?query=` l'**intera busta JSON**
>     `{"query":"<doc>"}`, non un documento grezzo → `graphql_lex` salta il contenuto-stringa e non
>     vede `__schema` (depth≈1). Fix = `unwrap_query_envelope` (in `waf-normalizer`, serde già dep →
>     detection resta serde-free): ogni *carrier* passa per **"envelope-or-raw"** (`operations()`→`expand()`).
> - **Confine open/enterprise** (`BOUNDARY.md` §3.1): i **cap strutturali** sono core (OPEN);
>   la **schema-enforcement** (validare la query contro lo schema reale dell'app → gestione
>   schema = governance) resta **enterprise**.

> Note gRPC (modulo **strutturale** + canale content §6 — Fase gRPC; richiede HTTP/2 = Fase 12):
> - **Due responsabilità, contabilità SEPARATA** (la lezione del fix §6):
>   - **CONTENT (§6, always-on)**: il body gRPC è `application/grpc*` binario → il normalizer de-frama
>     e estrae i campi protobuf (leaf length-delimited) nel canale `derived_decoded`, così i moduli
>     content (SQLi/XSS/…) ispezionano un'injection nascosta in un campo. Una cattura SQLi-in-campo è
>     **creditata a §6/al modulo content**, NON al modulo grpc.
>   - **STRUCTURAL (modulo `grpc`)**: cap DoS sulla FORMA (dimensione messaggio / numero campi / depth
>     di nesting) + policy compressi → `Reject{400}`. Default OFF (`[modules.grpc]`).
> - **Parser** `grpc_extract` (9° parser hand-rolled, fuzzato §13): framing `[flag][len:4 BE][msg]` +
>   protobuf wire-format senza schema. Euristica length-delimited: **UTF-8 valido → leaf-string**,
>   altrimenti **ricorsione sub-message** (depth-capped). Il content-inspection è **best-effort
>   dichiarato** (il wire-format senza `.proto` è ambiguo: string|bytes|sub-message indistinguibili) —
>   il deliverable garantito è lo **strutturale**. NB: una sub-message UTF-8 resta UNA leaf, ma il testo
>   nidificato è comunque una SUA sottostringa → la regola content matcha lo stesso.
> - **Compressi** (`on_compressed`): `grpc-encoding`≠`identity` o flag per-messaggio = payload opaco →
>   `Reject` (fail-closed, default) o `Passthrough` (a verbale). `identity`/assente = ispezionato.
> - **`structural()=true`** (come GraphQL): gira anche sul fast-path-skip (un DoS gRPC senza firma
>   content non deve bypassare).
> - **Datapath (Fase gRPC, su HTTP/2 di Fase 12)**: forwarding **h2c end-to-end** via un client
>   `http2_only` **dedicato** ai target gRPC (il client generale resta h1 — niente flag globale) +
>   **relay dei trailer** `grpc-status`/`grpc-message` in entrambe le direzioni. Il modello resta
>   **buffer-then-inspect** (`collect_with_trailers` raccoglie body E trailer; `FramedBody` ri-emette
>   data-frame + trailers-frame) → unary coperto; **streaming deferito** (riscriverebbe il body-path).
>   `te: trailers` ri-aggiunto sul forward gRPC (richiesto dai server gRPC). Backend **h2-over-TLS**
>   (`https://`) deferito.
> - **Confine open/enterprise** (`BOUNDARY.md` §3.1): inspection gRPC = **core/OPEN** (datapath, come
>   JSON/multipart); firme premium / schema-enforcement = enterprise.

---

## 9. Operatività

### Configurazione esterna (Fase 6 — Pilastro 1)

Il caricamento della config da file esterno è una capability di prima classe; la
**validazione semantica** è separata e riusabile dall'hot reload (Pilastro 3).

- **Precedenza del path** (più esplicito/effimero → più implicito):
  1. flag CLI `--config <path>` (anche `--config=<path>`) — intento per-invocazione;
  2. env var `WAF_CONFIG` — livello deployment (container/systemd/CI);
  3. default `config.toml`.
  Parsing CLI manuale (nessun `clap`: una sola flag).
- **Pipeline esplicita** `resolve_path → load → parse → validate → build`:
  - `Config::validate()` (in `waf-core`, dependency-light) è il **controllo
    semantico** riusabile; `waf-proxy::config::{resolve_path,load,parse_and_validate}`
    orchestra fs/CLI e mappa gli errori; `Proxy::bind` è il build.
- **Fail-fast**: qualunque errore (I/O, TOML, semantico) → messaggio chiaro su
  **stderr** + **exit code 2**. Mai avvio con config parziale o default silenti.
- **File mancante = errore fatale, sempre** (qualsiasi sorgente). Un WAF non deve
  partire con config implicita (`trusted_proxies` vuoto, rate-limit off, soglie non
  tarate): è lo scenario "sembra protetto ma non lo è". `LoadError` distingue le
  diagnosi: `NotFound` ("file non trovato a <path>") vs `Parse` (TOML errato **o**
  campo obbligatorio mancante, es. "missing field `backend`") vs `Validation`.
- **Schema di validazione semantica** (`ConfigError`):
  - `proxy.backend`: URL assoluto `http(s)` con authority;
  - `waf.block_threshold >= 1`; `waf.paranoia_level ∈ 1..=4`
    (`MAX_PARANOIA_LEVEL`; PL4 è *forward-compatible* — vedi sotto);
  - `waf.severity_scores.*` ciascuno `>= 1`; `limits.*` ciascuno `>= 1`;
  - `rate_limit` (se `enabled`): `requests/window_seconds/max_tracked_keys >= 1`,
    `burst`(se presente)`>= 1`, `score >= 1` se `action="score"`;
  - `network.trusted_hops ∈ 1..=10` (`MAX_TRUSTED_HOPS`);
    `trusted_proxies` ogni entry CIDR valido; `client_ip_header` non vuoto.
  - La raggiungibilità di `block_threshold` è garantita per costruzione dai
    controlli `>= 1` su soglia e pesi (nessuna regola cross-field spuria).
- **PL4 "vuoto ma legale"**: il validatore presidia il *contratto* (`1..=4`), non lo
  stato corrente delle regole (max `HIGHEST_RULE_PARANOIA = 3`). Se
  `paranoia_level` supera la massima paranoia presente, `Proxy::bind` emette un
  **warn** a startup: nessuna regola aggiuntiva attivata. Così PL4 non si comporta
  silenziosamente come PL3.

- **Modalità**: `detection-only` (default in staging) vs `blocking`.
- **Fail mode**: per-scenario via `[resilience]` (vedi sotto) — NON un singolo
  booleano globale (il vecchio `waf.fail_open` è stato rimosso).
- **Hot reload**: ricarica regole/config senza restart via **SIGHUP** (vedi sotto).
- **Logging**: JSON con `request_id`, modulo, `rule_id`, `score`, decisione.
- **Metriche**: latenza per fase, richieste bloccate, falsi positivi stimati.
- **Status di risposta** — i **tre Reject/deny** hanno semantiche distinte:
  - `Decision::Block` (detection ad alta confidenza / soglia score) → **403 Forbidden**;
  - `Decision::Reject{status:400}` (request smuggling: **framing HTTP illegale**) → **400 Bad Request**;
  - `Decision::Reject{status:429}` (rate limiting) → **429 Too Many Requests** con `Retry-After`;
  - normalizzazione fallita (parser limit, Pilastro 2) → **400** secondo `on_parser_limit`.
  `deny_response` sceglie la reason-phrase dal `status` (400→Bad Request, 429→Too
  Many Requests); il 403 di `Block` è un arm separato. In detection-only nessun
  rifiuto: si logga soltanto.

### Resilienza: fail-open / fail-closed (Fase 6 — Pilastro 2)

Cosa fa il WAF **quando è lui in difficoltà**. Policy **esplicita e per-scenario**
(`[resilience]`), mai comportamento implicito. `FailMode` è uniforme su tutti gli
scenari per coerenza di schema, ma il *significato* di `fail_open` è
scenario-specifico (vedi nota upstream).

| Scenario (`[resilience]`) | Default | fail_closed | fail_open |
|---|---|---|---|
| `on_internal_error` (panic modulo / regex) | **fail_open** | Block sintetico (403 in blocking, solo-log in detection-only) | salta il modulo, la richiesta prosegue |
| `on_upstream_error` (origin giù/timeout) | **fail_closed** | **502** Bad Gateway | **503** Service Unavailable (retryable) |
| `on_parser_limit` (normalization fallita) | **fail_closed** | **400** | inoltra **non-ispezionato** (log critico) |
| `on_config_error` (reload invalido, P3) | **fail_open** | rifiuta serving finché config valida | mantiene **last-good** config |
| `upstream_timeout_ms` | 30000 | — | tetto round-trip (no hang del worker) |

**Razionale dei default:**
- `on_internal_error = fail_open`: il WAF è un controllo *additivo*; un suo bug
  (panic, regex blow-up) non deve ridurre la disponibilità sotto quella che l'app
  avrebbe *senza* WAF. Fallire closed su un difetto interno = single-point-of-failure.
- `on_upstream_error = fail_closed`: origin down non è mascherabile (servire vuoto
  è peggio); 5xx chiaro + timeout. **Nota**: `fail_open` su upstream **NON** significa
  "lascia passare" (non c'è origin da raggiungere) — sceglie solo il **503 retryable
  al posto del 502**. Semantica diversa da `fail_open` su `on_internal_error`.
- `on_parser_limit = fail_closed`: input oversize/malformato è vettore DoS ed
  evasione (ciò che non parso non ispeziono); inoltrarlo non-ispezionato vanifica
  il WAF.
- `on_config_error = fail_open`: un WAF sano non deve rompersi per un reload errato;
  tiene la last-good config. Lo **startup resta fail-fast** (Pilastro 1): lì non c'è
  last-good. Riusa `Config::validate()` per rilevare la corruzione.

**Panic isolation**: in `pipeline::run_phases` ogni `module.inspect()` gira dentro
`catch_unwind(AssertUnwindSafe(...))`. `inspect` è read-only su `&RequestContext`
→ un panic non lascia `ctx` parzialmente mutato (sound). Su panic: **log `error!`**
+ applicazione di `on_internal_error`. L'isolamento **cross-connessione** è dato
anche dai task tokio separati per connessione: un panic catturato non propaga, le
altre connessioni non sono toccate. Ogni attivazione fail-open/closed è **loggata**
(evento operativo critico).

> Migrazione: un `waf.fail_open` residuo nel TOML produce un **errore di load
> esplicito** (`LoadError::RemovedKey`, "usa [resilience]"), mai un no-op silenzioso.

### Hot reload (Fase 6 — Pilastro 3)

Ricarica della config a runtime **senza restart** e **senza droppare connessioni**.

- **Trigger: SIGHUP** (`tokio::signal`, `#[cfg(unix)]`) — pattern classico
  (nginx/haproxy), zero nuove dipendenze, intento esplicito dell'operatore.
  Scartati: file-watch/`notify` (dep + debounce/race su scritture parziali) ed
  endpoint admin (superficie HTTP da autenticare). Il segnale è **solo il bottone**:
  la logica validate-then-swap (`Reloader::reload_from`) è **OS-agnostica** e
  testata direttamente (anche su Windows, dove SIGHUP non esiste).
- **Swap atomico: `Arc<RwLock<Arc<Reloadable>>>` (std, zero-dep)**. Ogni richiesta
  fa `read()`, **clona l'`Arc`** e rilascia subito la guard (mai tenuta attraverso
  un `.await`) → sezione critica = una clone (ns), letture non in contesa. Lo swap
  è una **singola assegnazione di puntatore** che non può panicare → il lock non
  viene avvelenato da questo path (il poisoning è comunque recuperato con
  `into_inner` per difesa). `arc-swap` darebbe letture lock-free ma è una dep per
  un guadagno marginale (reload rarissimo): refactor indolore se un giorno servisse.
- **Validate-then-swap** (riusa Pilastro 1): `config::load` (read→parse→validate→
  guardia migrazione). **Config invalida → si TIENE la vecchia + log errore**: una
  reload fallita non degrada mai lo stato funzionante.
- **Ricompilazione regole**: `build_reloadable` ricostruisce **tutto** come unità
  (regex ricompilate via `Pipeline::new`, CIDR ri-parsati via `ClientIpResolver`,
  normalizer/limiti/backend/resilience) e lo swappa atomicamente → mai stato misto
  (regex vecchie + soglie nuove). Una richiesta vede o tutto il vecchio o tutto il
  nuovo `Reloadable`; le connessioni/richieste in volo completano col proprio
  snapshot e non vengono interrotte.

**Stato runtime (NON azzerato) vs config (ricostruita):**

| NON si resetta (process-lifetime) | Si ricostruisce nello swap |
|---|---|
| **token bucket rate-limit** (`StateStore` dietro `RateLimitState`, reiniettato; default in-memory, override `Proxy::builder().state_store(..)`) | regole/regex, filtro paranoia, soglie/severità |
| pool connessioni hyper (`client`) | parametri rate-limit (capacity/refill/action) |
| connessioni/richieste in volo | resolver CIDR `trusted_proxies`, policy resilience |
| contatore `request_id` | limiti, `backend` |

> **Non-sfruttabilità**: i bucket sopravvivono al reload → un attaccante non può
> azzerare il proprio throttle inducendo un reload. Se il nuovo limite **abbassa**
> la capacità, al refill successivo i token sono già clampati a `min(nuova_capacity)`
> (gestito in `inspect`) → sicuro.

**Campi reloadable vs restart-required:**

| Campo | Reload |
|---|---|
| `proxy.listen` (bind address) | **restart-required** — se cambia a runtime: **warn + valore vecchio mantenuto** (il socket è già in ascolto) |
| `proxy.backend`, `[waf]`, `[modules]`, `[limits]`, `[rate_limit]`, `[network]`, `[resilience]` | reloadable a caldo |

### Risoluzione dell'IP client (trusted-proxy)

Un WAF L7 sta quasi sempre dietro LB/CDN/TLS-terminator: la peer addr è l'IP del
proxy. Il **client reale** è risolto da un helper condiviso (`waf-core::network`,
`ClientIpResolver`), derivato **una sola volta** in `build_context` e scritto in
`ctx.client_ip` — *single source of truth* letta da rate limiting, logging
strutturato (Fase 1) e futura Geo/IP-reputation (Fase 8). Il rate limiter **non**
ri-risolve: legge `ctx.client_ip`.

Schema `[network]` (sezione globale, `#[serde(default)]`):
- `trusted_proxies` — CIDR dei propri proxy (IPv4/IPv6, parsing manuale, niente
  dipendenze). Default **vuoto**.
- `client_ip_header` — header della catena (default `X-Forwarded-For`).
- `trusted_hops` — quanti hop fidarsi contando **da destra**.

Logica (l'ordine **è** la frontiera di sicurezza):
1. peer **non** trusted → usa peer, header ignorato (`DirectPeer`).
2. peer trusted → IP a `trusted_hops` **da destra**; **mai** il primo IP (è
   controllato dal client → spoofabile) (`TrustedHeader`).
3. header assente / malformato / **catena più corta di `trusted_hops`** → fallback
   alla peer addr + `warn` (`FallbackMissingHeader`/`FallbackMalformed`); **mai**
   ripiegare sull'IP spoofabile.
4. **Fail-safe**: `trusted_proxies` vuoto (default) → **sempre** peer, XFF ignorato:
   un deploy non configurato non è spoofabile.

> Nota: l'header `X-Forwarded-For` che il proxy **aggiunge** verso il backend resta
> la **peer addr** (record dell'hop realmente osservato), distinta dall'IP risolto
> usato internamente per chiave/log.

### Terminazione TLS (Fase 12)

Terminazione TLS **base, cert-da-file** sul listener — **core/OPEN** (`BOUNDARY.md` §3.2; single-node
self-sufficiency). Config `[tls]` (default **off**): `enabled`, `cert_path`, `key_path`, `alpn`
(default `["h2","http/1.1"]`).

- **Libreria**: `rustls` (+ `tokio-rustls`, provider **ring**), no OpenSSL — l'**unica** eccezione
  legittima alla regola "parser hand-rolled" (il TLS non si hand-rolla mai).
- **Serving h1+h2 unificato**: il loop di `run()` usa `hyper-util` `auto::Builder` → una sola porta
  serve h1 e h2 (ALPN su TLS, preface su cleartext h2c). **`handle()` è INVARIATO**: il `Request` è
  protocol-neutral e `body.collect()` consegna lo **stesso** `Bytes` bufferizzato su h1 e h2 (invariante
  provato col probe Step-0). L'inspection è quindi **protocol-agnostica** — bite-test: un SQLi su
  h2-over-TLS è bloccato 403 come su h1.
- **ALPN h2-ready**: `["h2","http/1.1"]` negozia h2 col client capace e ripiega a h1 col client h1-only
  (non forza h2). Prerequisito per gRPC-over-TLS (fase successiva).
- **Seam §4 (`waf-proxy::tls`)**: `trait TlsCertSource` con impl OPEN `FileCertSource` (PEM). ACME/
  rotation/cert multi-nodo/**mTLS con PKI gestita** = impl ENTERPRISE dello stesso trait (mTLS è
  esplicitamente fuori dal core, `BOUNDARY.md` §3.2). **Iniezione**: `Proxy::builder().cert_source(..)`
  (default `FileCertSource` dai path di config); `acceptor_from_source` sceglie sorgente iniettata vs
  file. `[tls].enabled`/`alpn` restano da config — la sorgente governa solo la *provenienza* del cert.
- **No silent downgrade (fail-closed)**: con TLS abilitato il listener serve **solo** TLS. L'acceptor è
  costruito a `bind` ed è **immutabile** (non hot-reloadable, come `listen_addr` = restart-required):
  non esiste un path runtime che ripieghi a chiaro. `enabled=true` + cert illeggibile = **boot error
  fatale**. Un errore di **handshake** per-connessione è loggato e la connessione droppata, **non-fatale**
  per il listener.
- **Postura DoS HTTP/2 (a verbale)**: h2 apre superfici che h1 non ha (max-concurrent-streams, frame
  flood SETTINGS/PING/**RST = Rapid Reset, CVE-2023-44487**, HPACK). Fase 12 si affida ai **default di
  hyper/h2**; nessun knob esposto ora — scelta **consapevole e dichiarata**, possibile tuning futuro
  (estende i `[limits]` §6).

---

### Osservabilità: logging + metriche (B1)

- **Logging strutturato JSON** (`tracing` + `tracing_subscriber`, `EnvFilter`): una riga per decisione
  (`request_id`, decision, score, contributi), più `→ request`/`← response`.
- **Metriche Prometheus** (`[metrics]`, default **off**): esposizione text su `GET /metrics`. **Baseline
  OPEN** (`BOUNDARY.md` §1.6); OTLP-push deferito (i contatori sono **exporter-neutral**, `render()` è
  l'exporter Prometheus → un domani OTLP è un secondo sink, non una riscrittura).
  - **Listener SEPARATO** (`[metrics].listen`, default `127.0.0.1:9090`, loopback): **mai** la porta dati
    — `/metrics` espone postura interna (volumi blocked/rate_limited) ed è esso stesso info-leak se
    raggiungibile; inoltre verrebbe ispezionato dal WAF. Bind **fail-fast** a `bind` (porta occupata =
    boot error). Il service risponde **404** a tutto ciò che non è `GET /metrics`. *Bite-test cardine: la
    porta dati NON espone `/metrics`.*
  - **Metriche** (convenzioni Prom, **unità base = secondi**): `waf_requests_total{decision=...}` (set
    **chiuso**: `allowed|blocked|rate_limited|bad_request|upstream_error|internal_error` —
    `internal_error` ≠ `upstream_error`: errore interno del WAF vs backend fallito);
    `waf_request_duration_seconds` (**histogram a bucket fissi** + `_sum`/`_count`, **zero quantili
    in-process** → `histogram_quantile()` lato scrape); `waf_up`, `waf_build_info`.
  - **Regola cardinalità (vincolo)**: MAI label da input utente (no `path`/`ip`/`rule_id`) → un breakdown
    per-regola futuro è una metrica separata con cap, non un label su `requests_total`.
  - **Strumentazione = puro side-effect**: contatori `AtomicU64` relaxed, nessun lock/`.await` sul path
    caldo; registrazione in **un punto netto** (`handle`, via `Outcome` ritornato). I verdetti non
    cambiano — provato dalla validation invariata.

---

## 10. Strategia di test

- **Unit**: ogni parser e modulo con payload puliti e offuscati.
- **Integration**: pipeline end-to-end attraverso il proxy.
- **Suite esterne**: GoTestWAF, OWASP ModSecurity CRS test suite.
- **Performance**: benchmark throughput/latency, test regex contro ReDoS.
- **Regressione**: corpus di falsi positivi noti per evitare ricomparse.

### Corpus di validazione (Fase 7 / Pilastro 1)

Crate-libreria `waf-corpus`: un insieme **unico, versionato e riproducibile** di
casi malevoli (devono scattare) e benigni (non devono), che **misura** la detection
**congelata** invece di cambiarla. È libreria per riuso: stessa evidenza per il
tuning soglie (Pilastro 2) e oracolo di equivalenza per il fast-path (Pilastro 3).

- **Formato**: tabelle statiche Rust (`Case`), zero-parsing e type-safe. Ogni caso:
  `id`, `module`, `field` (Query/RawQuery/FormBody/JsonBody/Cookie/Header/Path/
  Smuggling — porta il payload **grezzo**), `min_pl`, `expect`
  (`Triggers`/`Clean`/`ExpectedMiss`) e `rules` (atteso rule_id).
- **Builder grezzi via `waf-core` feature `testkit`** (additiva, mai abilitata dal
  proxy → zero-cost in produzione): costruiscono i campi **pre-normalizzazione**;
  il corpus poi gira il **vero `Normalizer`**, così esercita la pipeline reale e non
  la bypassa (a differenza delle scorciatoie `normalized.*` degli unit dei moduli).
- **Runner = flusso del proxy**: `run_connection` → `normalize` → `run_inspection`,
  in Blocking con `block_threshold = u32::MAX` (la soglia non corto-circuita mai
  l'inspection → si raccoglie ogni match e lo score cumulato completo). **Invariante
  del runner**: **context fresco per caso** (ogni caso parte da `score = 0`, nessuno
  stato condiviso) + **rate-limit neutralizzato** per i casi non-rate-limit (nessun
  429 spurio da `client_ip` condivisa). La **paranoia è parametro** del runner,
  baseline **PL3** (worst-case = tutte le regole attive); `min_pl` per-caso fa
  **skippare** un caso quando `execution_pl < min_pl`, così un miss non è mai un
  artefatto di aver girato la regola sotto la sua attivazione.
- **Metriche, tre libri distinti**:
  - **recall / FP-rate** attribuiti a `case.module` (gli overlap **non** gonfiano il
    modulo bersaglio); un malevolo è "rilevato" se il verdetto è coerente e almeno
    una delle `rules` attese è scattata;
  - **score-distribution** col **`ctx.score` cumulato reale** (overlap inclusi) —
    ciò che la pipeline produrrebbe in produzione, input diretto a Pilastro 2;
  - **overlap dichiarati (§8)** elencati a parte e resi visibili (es. `rfi-remote-url`
    sui target SSRF con URL, `ssrf-private-ip` su `169.254.169.254`); **ExpectedMiss**
    (gap §8) contabilizzati a parte, né recall né FP.
- **Esecuzione**: `tests/validation.rs` gira **sempre in CI** come guardia
  anti-regressione — (a) 0 trigger-fail, (b) 0 FP, (c) overlap §8 presenti, (d)
  ExpectedMiss tutti ancora missed, più i target **misura-poi-fissa** (recall 100% /
  FP 0% sul baseline misurato + floor di copertura malevoli≥50/benigni≥26).
  Il report verboso (tabella metriche + score-distribution + overlap) è on-demand:
  `cargo run -p waf-corpus --example report`.

---

## 11. Roadmap per fasi (sintesi)

- **Fase 0** — Setup repo + reverse proxy passthrough.
- **Fase 1** — Pipeline + contratto moduli + detection-only + logging.
- **Fase 2** — Parsing + normalizzazione + limiti difensivi.
- **Fase 3** — Primi moduli (SQLi, XSS) con engine regex compilato.
- **Fase 4** — Anomaly scoring con soglia configurabile.
- **Fase 5** — Espansione moduli + rate limiting L7.
- **Fase 6 ✅** — Robustezza operativa (4 pilastri): config esterna ✅, fail-open/closed ✅, hot reload ✅, anti smuggling ✅.
- **Fase 7** — tre pilastri: **Pilastro 1 ✅** suite di validazione (`waf-corpus`, §10);
  **Pilastro 2 ✅** tuning soglie → config **C2** (`critical=6`, resto CRS,
  `block_threshold=5`), validata sul corpus con cinque proprietà-ladder (§7);
  **Pilastro 3 ✅** fast-path di equivalenza: prefiltro scope-aware sound (skip
  dell'ispezione sul benigno provabilmente pulito), equivalenza provata sull'oracolo
  (79 casi, gate di produzione), 11.74× sul path benigno (§7).
- **Fase 8 ✅ (sanitizer: smoke batch; fuzzing lungo in CI)** — Robustezza (fuzzing,
  ReDoS, differential): fuzzing dei 7 parser custom (cargo-fuzz/ASan, Linux/CI) +
  invarianti proptest cross-platform sempre-attive; ReDoS = motore `regex` lineare →
  backtracking impossibile per costruzione (test = guardia anti-regressione + scaling
  della composizione); differential canonicalization con oracolo indipendente
  (relazione A/B/C). 0 finding; policy canonicalization-vs-freeze in §13.
- **Fase 9** — Performance e resilienza sotto carico. **Latenza d'ispezione**
  (`enqueue→verdetto`, il numero che dipende SOLO dal nostro codice) sotto **criterion**
  con baseline versionata + **gate di REGRESSIONE relativo** in CI; il `<1ms p99`
  ASSOLUTO si dichiara on-demand su hardware pinnato, non su CI condiviso (CI varia
  3-10× → un assoluto lì è rumore). **Load-test e2e open-loop** rate-based (oha/wrk2/k6,
  arrival-rate costante → niente coordinated omission) come overhead informativo (delta
  WAF-in-path vs passthrough), MAI il gate. Bench sui **79 casi P1 reali** (§10), non
  sintetici; worst-case = i casi a più regole accumulate dalla score-distribution di P2
  (§7), non la media; gate **p99**, report p99.9/max come early-warning. **Resilienza**
  = bite-test e2e del contratto **§9 GIÀ dichiarato** (panic-modulo `on_internal_error`
  fail_open additivo / kill-upstream 502↔503 / corrupt-reload last-good — provati
  ENTRAMBI i `FailMode`, non solo il default), nessuna policy nuova e nessun re-pin. Il
  razionale **additive-control** del `fail_open`-su-panic è a verbale come contratto, non
  assunto: il WAF è un controllo *additivo* → un suo bug (panic) non deve ridurre la
  disponibilità sotto la baseline no-WAF; fail_open salta **solo** il modulo che panica
  (gli altri girano) → degrada-un-segnale, **non** bypass del WAF.
  - **Baseline pinnata (DEC 1/DEC 4)**: **~2 µs** ispezione worst-case PL3 (regole sature,
    `enqueue→verdetto`, bench `inspect_worst_case_pl3` su `lfi-rfi-remote-script-query`).
    NON è il regime fast-path (130–1520 ns) né deve esserlo — è il worst-case a regole
    sature. È il **riferimento versionato** del gate di regressione **relativa** (DEC 4).
    **Headroom dichiarato (storia di DEC 1)**: ~2 µs worst-case vs contratto **p99 1 ms**
    ≈ **500×** di margine — il numero che dipende SOLO dal nostro codice, isolato da
    upstream/rete.
  - **Distribuzione worst-case-set** (`examples/latency_distribution.rs`, on-demand): p50
    ~2.1 µs / **p99 ~3.1 µs** / p99.9 ~5.3 µs; il caso più pesante `ssrf-cloud-metadata`
    (3 regole) corona il p99 (~3.8 µs). **Riferimento del gate (d) = il single-case pinnato
    `inspect_worst_case_pl3`, NON l'aggregato** (l'aggregato varia col corpus; il single-case
    è stabile). **`max` NON è il contratto**: `max` (~97 µs nelle run osservate) è **jitter
    di scheduler**, non proprietà del codice — provato dal fatto che il caso più pesante
    corona il **p99**, non il `max`. DEC 2 gatea **p99**, mai `max`; il gate (d) DEVE
    ignorare `max` per costruzione. Lo split di tooling (criterion=gate stabile sempre-verde
    / example=distribuzione on-demand) ricalca il pattern P2/Fase9.
  - **Requisito permanente dei test di resilienza (lezione del finding)**: il traffico di
    **fault-injection deve essere prefilter-candidate** (raggiungere l'ispezione). Il
    prefiltro di Pilastro-3 salta l'ispezione sul benigno (§7), quindi traffico
    "dall'aspetto benigno" corto-circuita **proprio il percorso sotto test** e la guardia
    non misura nulla — stessa classe del `prop_path_invariants`-verde-col-resolver-rotto
    di Fase 8 (§13). Esposto dal bite-test col **contatore atomico** nel modulo che panica;
    vale per **tutti** gli scenari (panic, kill-upstream, corrupt-reload).
  - **Chiusura Fase 9 — ledger netto (provato vs in attesa dell'AMBIENTE, non del lavoro)**:
    - **PROVATO**: ispezione worst-case ~2 µs / p99 3.1 µs / p99.9 5.3 µs senza cliff
      alloc/lock (a); gate di regressione **relativa** bite-verificato (d, `examples/
      regression_gate.rs`); resilienza **kill-upstream + corrupt-reload + isolamento-panic**
      tutti bite-verificati e2e (b); anti-pattern §13 nominato (3 istanze); **candidacy bite
      e2e** verde (c, `examples/load_overhead.rs`: candidate→403/benign→200, immune al rumore).
    - **REFACTOR 1b** (freeze-safe, provato): `forward_to_backend` estratto (fwd/passthrough
      verdi prima E dopo, 17/17); `Proxy::bind_passthrough` `#[doc(hidden)]`, **non
      raggiungibile da config** (la linea vs il bypass dell'opzione-3 rifiutata); un solo
      forward → drift §13 rimosso alla radice.
    - **ASPETTA L'AMBIENTE (harness costruito + noto-corretto, manca solo dove misurare)**:
      curva overhead e2e 1k/5k/10k → **oha su box silenzioso** (in-process Windows: segnale
      ~3 µs sotto il noise floor e2e ~344 µs → delta perfino negativo = il sanity-check che
      SCATTA, DEC-C2 confermato; l'e2e **non è e non è mai stato** il contratto, che resta
      l'isolato (a)/(d)); wiring pipeline CI → ambiente git/CI; asserzione **assoluta <1 ms**
      e2e → hardware pinnato (mai su CI condiviso).
- **Fase 10a ✅** — Copertura detection: le rule-set che bypassavano anche in Plain/URL
  (interi moduli mancanti), derivate da `gotestwaf-report.json`. **5 moduli nuovi**
  (ldap, nosql, mail — B1; **ssti, scanner** — B2) + **2 estensioni** (B2:
  `header_injection` ispeziona ora il **path** per il CRLF response-splitting smuggla­to
  in URL; `rce` ispeziona il **path** per la command-injection in URL — gotestwaf
  `crlf` / `rce-urlpath`). Ogni modulo cabla gli 8 punti (file regola + `pub mod` +
  **`content_rules_split`** [HARD GATE: prefiltro = OR-union di quelle tabelle] +
  `ModulesConfig` + `build_modules` + `Module` enum/`name()` + `runner::build_pipeline` +
  casi corpus + asserzione union in `validation.rs`). Severità per decisione-3: firma
  inequivocabile = Critical block-alone (ssti template-arith/freemarker, scanner
  tool-UA/OOB-domain, rce chained-command), segnale debole = accumulo (rce backtick).
  - **Scoping per encoder (invariante 10a→10c):** misurato SOLO sul subset URL/Plain
    dedotto. I duplicati **Base64Flat → `ExpectedMiss{until_phase:"10c"}`** (servono il
    base64-decode di §6; l'oracolo `expected_miss_phase_deferrals_honored` FORZA il flip a
    Triggers quando `CURRENT_PHASE` raggiunge 10c). L'overlong-unicode CRLF `%e5%98%8d` →
    `ExpectedMiss{until:None}` (limite documentato: è UTF-8 valido `U+560D 嘍`, il
    normalizer NON fa best-fit mapping → nessun CR/LF appare mai; §6).
  - **Tutto bite-verificato** (metodologia §13): attribuzione esclusiva provata dal
    report contributi (ogni Triggers B2 accende SOLO le regole del suo modulo) + bite
    distruttivi (rotta la regola/lo scope-path → il caso va RED con NIENTE che lo salvi →
    ripristino → green): rce-path (3 casi), header-path (3), ssti (3), scanner (8).
  - **Re-baseline perf (decisione esplicita, "sforamento" accettato):** ispezione
    worst-case PL3 **~2.65 µs (fine B1) → ~4.3 µs (fine B2)**; il caso più pesante
    `ssrf-cloud-metadata-query` ~4.9 µs. Attribuibile ai 2 nuovi `RegexSet`/richiesta
    (ssti su query/cookie/body; scanner solo su User-Agent) + il path aggiunto a
    rce/header_injection. **ACCETTATO**: headroom ancora **~230×** vs il contratto p99
    1 ms (la storia di DEC 1 regge con ampio margine). Nuova baseline criterion `pinned`
    ri-salvata = riferimento del gate di regressione relativo (DEC 4) da qui in avanti.
  - **ASPETTA L'AMBIENTE (lavoro fatto, manca dove eseguire):** re-run gotestwaf →
    server live + tool (stessa classe di oha/CI assente, Fase 9); 10b/10c (encoder
    avanzati, base64-decode in §6) chiuderanno i deferral `until_phase:"10c"`.

- **Fase 10b ✅** — Copertura detection (continua): allargare regole ESISTENTI ma deboli
  (block <25% in URL/Plain) + chiudere gli ultimi moduli mancanti. Rischio invertito vs
  10a (allargare su moduli alto-traffico ri-apre il trade-off FP), quindi **precisione
  STRUTTURALE** (il crate `regex` è automa finito: NO lookaround → le fix di precisione
  sono strutturali, non `(?!…)`). Source = `gotestwaf-report.json`, **scoping per-payload**
  (URL/Plain → 10b; solo Base64Flat → `until_phase:"10c"`). Metodo chiave **PROBE-FIRST**:
  misurato il gap contro il CODICE attuale, non il report stale (molti payload erano GIÀ
  presi dall'evoluzione post-snapshot).
  - **B1 — `sqli` + `xss` (broadening):** 3 nuove Critical SQLi CRS-aligned alta-precisione
    (`sqli-mysql-versioned-comment` `/*!…`, `sqli-information-schema` underscore-anchored,
    `sqli-json-function`); XSS reso preciso (`xss-javascript-proto` → scheme-CALL
    `javascript\s*:[^()]*…\(` uccide il FP "JavaScript: Basics…") + recall
    (`xss-js-sink-call`/`xss-js-sink-invocation` per i bypass senza tag/handler).
  - **B2 — `shell-injection`/`rce`/`ss-include`:** rce esteso (chained `getent|host`,
    windows `set /[ap]`, `rce-yaml-deserialization` `!!python/…`); **nuovo modulo `ssi`**
    (`ssi-directive` `<!--#<verb>`, Critical/PL1) che sostituisce la mis-attribuzione
    fragile a `sqli-quote-comment` sul `"-->`.
  - **B3 — `xml`/XXE + `path-traversal`:** **nuovo modulo `xxe`** (Phase::Body, 3 regole
    Critical/PL1): `xxe-entity-declaration` `<!ENTITY`, `xxe-doctype-external`
    `<!DOCTYPE…SYSTEM` (**SYSTEM-only**, non PUBLIC → il doctype XHTML legacy con `PUBLIC`
    NON è FP), `xxe-utf7-encoding` `encoding="UTF-7"` (charset-smuggling: il vero
    `<!DOCTYPE`/`<!ENTITY` è UTF-7-encoded). **path-traversal** esteso: `pt-unc-path`
    allarga la host-class con `:` per la UNC a host IPv6-literal (`\\::1\c$\…`, i backslash
    sopravvivono alla normalizzazione → era solo la char-class a mancare).
  - **Limiti documentati (`ExpectedMiss{None}` — servono §6, fuori 10b rules-only):**
    XInclude/schema esterno (`xsi:schemaLocation`/`<xs:include>`) indistinguibile da SOAP/XSD
    benigno senza parsing semantico + URL-reputation → **deferito per non aprire un FP-factory
    SOAP** (catturato cmq come Notice da `rfi-remote-url` sull'URL esterno, defense-in-depth);
    overlong-UTF8 `%C0%AE`=`.`/`%C0%AF`=`/` → `from_utf8_lossy`→U+FFFD, nessuna firma
    `/etc/passwd` si forma (serve decode overlong §6).
  - **Bite-verificato (§13):** attribuzione ESCLUSIVA provata sul report contributi (i
    Triggers clean accendono SOLO la regola del loro modulo, set di size-1 → rompere la
    regola → RED senza nulla che salvi); i payload gotestwaf verbatim con `http://` tengono
    l'overlap `rfi-remote-url` DICHIARATO.
  - **P2 GATE verde** (`recommended_config_ladder_properties` + `baseline_targets_met`):
    nuove Critical SQLi/XXE + sink XSS → benign-blocking resta **0**, C2 regge, nessuna
    ri-taratura soglie. `CURRENT_PHASE="10b"`.
  - **Re-baseline perf (decisione, "sforamento" accettato):** ispezione worst-case PL3
    **~4.3 µs (fine 10a) → ~5.1 µs (fine 10b)**, caso più pesante `ssrf-cloud-metadata-query`
    ~5.5 µs. Attribuibile ai 2 nuovi `RegexSet`/richiesta (`ssi`, `xxe`) + le regole extra
    nei set esistenti. **ACCETTATO**: headroom ancora **~195×** vs il contratto p99 1 ms.
    Baseline criterion `pinned` ri-salvata (riferimento gate DEC 4).
  - **B1-cont — `path-traversal` `../`-base + field-coverage multipart:** due gap dal
    `gotestwaf-report-after-10b.json` chiusi. (1) **Recall `../`-base senza FP**: il faro
    `/static/img/../../etc/passwd` in querystring resta preso, ma `pt-dotdot-traversal` è
    **ristretto strutturalmente** `\.\.[\\/]` → `(?:\.\.[\\/]){2,}` (≥2 segmenti *consecutivi*
    = vera escape) così un `../` relativo benigno (`docs/../report.pdf`, `../images/logo.png`)
    resta **Clean**; i target sensibili restano coperti da `pt-sensitive-*` a prescindere.
    (2) **Field-coverage multipart**: `body_str_values` ora ispeziona anche il **filename**
    di ogni part (oltre al dato del part), prima punto cieco — il payload LFI/traversal in
    `filename="…/../../etc/passwd"` (gotestwaf `community-lfi-multipart`) ora viene ispezionato;
    i NOMI dei field restano fuori (metadati di controllo, non contenuto attaccante).
    **D1**: UNC `\\::1\c$\…` URL/Plain è GIÀ preso da `pt-unc-path` (host-class `:`, B3) → nessun
    broadening backslash Windows-specifico (rinvio a 10b-bis confermato); solo la forma Base64Flat
    resta deferita a 10c. **D2**: profondità multipart = filename + valore-part (i part testuali
    sono già coperti dal dato). **D3**: `file:///etc/./passwd` è coperto dallo scheme `file://`
    esistente in `lfi-stream-wrapper` (il `/./` è cosmetico) → estensione di copertura, non di
    pattern. **Limite `ExpectedMiss`**: overlong-UTF8 `%C0%AE%C0%AE%C0%AF…` resta distinto da
    `../`-base (ora coperto) — è un limite §6 (`from_utf8_lossy`→U+FFFD, vedi §6), non `../`.
    Faro/UNC Base64Flat → `until_phase:"10c"`. Bite/smoke red→green dimostrato (multipart-filename
    `[]`→preso; trap `../` benigno FP→Clean) prima dell'harvest. **P2 GATE verde** (recall corpus
    100% 103/103, FP **0/62**, ladder C2 invariata); **perf** worst-case PL3 ~4.5 µs (+~4.5% vs
    `pinned`, < gate 10% — il clone del filename multipart pesa solo sul traffico multipart, non
    sul worst-case query). Nessun re-pin (sotto-batch). `CURRENT_PHASE` resta `"10b"`.
  - **B1-cont FIX — multipart `name`/valore + overlong/double-encoding.** Il fix B1-cont
    iniziale guardava SOLO `filename`; gotestwaf (`community-lfi-multipart`, confermato a
    pcap) mette il traversal nel **`name=`** del Content-Disposition (senza filename) o nel
    **valore**, spesso **double-encoded/overlong** (`%25C0%25AE…`). Tre interventi: (1)
    `body_str_values` ispeziona ora **name + filename + valore** di ogni part; (2)
    parsing Content-Disposition **case-insensitive** su header e attributi (`name`/`filename`);
    (3) nuova `canonicalize_multipart_field` (waf-normalizer) = percent-decode + collapse
    **overlong-UTF8** ricorsivi a punto fisso (cap 5) + NFKC, applicata PRIMA del match
    (`%25C0%25AE`→`.`, `..%2f`→`/`). Smoke red→green: name-traversal `[]`→bloccato,
    overlong-value `[]`→bloccato, trap multipart benigno→Clean. **`pt-dotdot {2,}` invariato**
    (entrambi i casi-pcap risolvono a `../../` ≥2 + `/etc/passwd` → presi; NO ritorno a `{1,}`
    che riaprirebbe l'FP su `../` singolo benigno approvato in B1-cont). Overlong su QUERY
    resta `ExpectedMiss` (decode scoped al multipart, vedi §6). **GATE verde**: recall
    path_traversal **11/11**, aggregato **105/105**, **FP 0/63**, fast-path-equivalence verde;
    **perf** worst-case query ~5.3 µs (stabile su 2 misure, "no change" — invariato dal mio
    codice: il path query non tocca il multipart; cross-session vs ~5.1 µs end-10b). Costo
    multipart limitato (≤5 passate, stringhe corte, solo su traffico multipart). Nessun re-pin.
  - **B2-cont — `xss` URL: VALUTATO, CHIUSO SENZA AZIONE.** Probe-first sui 40 payload
    XSS-URL distinti (superficie canonica, PL3): **38/40 già intercettati**; gli unici 2
    veri pattern-miss sono i limiti §6 noti (entity-obfuscation, mutation/tag-split).
    I "bypass" residui del report NON sono pattern-miss: una regola matcha ma è
    `Warning`/PL2 sub-soglia (accumulo anti-FP). L'unico lever sarebbe alzare la severity
    → **escluso (severity congelati, decisione ciclo b)**, tanto più a paranoia massima.
    Zero modifiche; finding documentato in §6.
  - **B3-cont — `sqli` URL: VALUTATO, CHIUSO SENZA AZIONE.** Probe-first sulle 3 famiglie
    medie + le sofisticate (score C2, T=5): inline-comment / `information_schema` / blind
    `sleep()` **bloccano già** (`Critical` 6), come `JSON_EXTRACT`/`JSON_DEPTH`
    (`sqli-json-function`). Le Triggers-regression sono già nel corpus (B1-10b). Unico
    residuo `xp_cmdshell`: **rilevato** (`sqli-cast-convert`) ma sub-soglia (Notice/PL3) —
    NON un pattern-miss e NON tagabile `ExpectedMiss` (l'oracolo usa `still_missed =
    !triggered`: una regola scatta → risulterebbe "caught ahead of phase"). Regola MSSQL
    dedicata **rinviata a 10b-bis**. Severity congelati. Zero modifiche; finding in §6.
  - **Chiusura ciclo b — nota di metodo.** **Probe-first** ha guidato B1-cont (gap reale =
    field-coverage multipart, non broadening), B2-cont e B3-cont (gap reale = severità
    sub-soglia *by-design*, non copertura). Distinzione chiave del ciclo: **copertura vs
    severità** — un payload che bypassa il *blocco* non è un pattern-miss se una regola lo
    *rileva*; lo si chiude congelando gli score, non alzandoli. Gli `severity_scores` non
    sono MAI stati sbloccati a paranoia massima (il trade-off FP che P2 aveva congelato
    resta congelato). Aperto come deferral esplicito: **10b-bis** (UNC Windows-backslash
    broadening, `xp_cmdshell`/MSSQL stacked-with-comments) e **10c** (encoder Base64Flat +
    base64-decode §6). `CURRENT_PHASE` resta `"10b"`.

- **Fase 10c ✅** — Encoder avanzati: chiude i deferral `until_phase:"10c"` aprendo il
  canale §6 **base64-decode + overlong pipeline-wide** (`decode-then-match-then-discard`,
  vedi §6). `CURRENT_PHASE` → `"10c"`.
  - **15 deferral flippati a `Triggers`** (l'oracolo `expected_miss_phase_deferrals_honored`
    li FORZA caught a 10c): `ldap` 3, `mail` 3, `nosql` 3, `ssti` 3, `path_traversal` 3
    (faro base64 `/static/img/../../etc/passwd`, UNC IPv6, **overlong-UTF8 query** — ora
    pipeline-wide). Zero residui non-flippati. L'unico `ExpectedMiss` aperto è il **10d**
    `hdr-overlong-crlf-header-value` (cambio canonico CRLF senza bite in 10c — §6/§13).
  - **Bite per-stadio (§13, red→green dei due fari).** Doppia proprietà dimostrata su
    `pt-faro-base64` e `pt-overlong`: (1) **necessità indipendente** — `base64-decode→None`
    fa cadere SOLO il faro base64 (overlong resta 🟢), `overlong-collapse→identity` fa cadere
    SOLO il faro overlong (base64 resta 🟢); (2) **nessun salvataggio per altra via** —
    rompendo lo stadio il `prefilter_candidate` collassa a `false` INSIEME al `caught` (non è
    il prefiltro né un altro modulo a tenerlo su, è esattamente quel decode). Restore → 🟢🟢.
  - **Harvest recall-lock (1/modulo, non gotestwaf-tracked).** Aggiunti 4 Triggers-regression
    base64 su moduli non-coperti dai deferral del report — `xss-script-tag-b64`,
    `sqli-information-schema-b64`, `rce-chained-command-b64`, `ssi-exec-directive-b64` — per
    pinnare che il canale derivato alimenta anche xss/sqli/rce/ssi. **Tutti 🟢** (nessun RED
    da triare). Scopo: bloccare la recall sotto-test, non gonfiare il corpus.
  - **GATE verde** (tutti e 10 i test di validazione): `fastpath_equivalence` ✓,
    `no_false_positives` ✓, `recommended_config_ladder_properties` (P2) ✓ — la P2 ladder
    NON è ri-tarata (il canale derived contribuisce solo decode-then-match, niente shift
    di score sul benigno; FP 0), `expected_miss_phase_deferrals_honored` ✓.
  - **PERF — re-baseline (lettura onesta, pin NON ri-salvato).** Inspection worst-case PL3
    `lfi-rfi-remote-script-query` ~3.74 µs, heaviest `ssrf-cloud-metadata-query` ~4.11 µs,
    famiglia ssrf/rce 3.7–4.2 µs — tutti **≤ il pin end-10b ~5.1 µs**, nessuno sforamento del
    gate 10%. Criterion segna -14/-30% ma è **fuorviante**: la baseline salvata era di una run
    sotto carico (~5.3 µs); la lettura corretta è **flat/dentro l'envelope, nessuna regressione
    dalla `.chain(derived)`**. Il pin end-10b è lasciato com'è (heavy-load) e **dichiarato tale**:
    ri-salvarlo su una run possibilmente "leggera" falserebbe il confronto. **Caveat**: questo
    bench misura **inspection, non normalization** — il costo nuovo dei due stadi vive in
    normalization (candidacy pre-check O(1)-reject sul traffico non-base64 + fixpoint overlong
    bounded da `PIPELINE_CAP=5`); headroom **~165–270×** sotto il contratto p99 1ms anche col
    delta normalization. Un re-pin perf pulito è un item dedicato ("re-pin su misura controllata"),
    NON forzato dentro 10c.
  - **Aperto come deferral esplicito:** **10d** (`hdr-overlong-crlf-header-value` —
    cambio canonico CRLF con bite + re-gate P1/P2/P3 completo) e **10b-bis** (UNC
    Windows-backslash broadening, `xp_cmdshell`/MSSQL stacked-with-comments).
  - **REOPEN 10c (pcap-driven, probe-first) — leaf JSON canonicalize.** Un pcap tcpdump del
    traffico gotestwaf LIVE (`bypass.txt`) ha smentito il verde-corpus: due classi di bypass sul
    wire. Lo **STEP-1 probe** (sul normalizer+pipeline LIVE, non l'harness) ha **REFUTATO** le
    root-cause ipotizzate: (#1 JSON) serde fa GIÀ l'unescape `\u` → la causa è la
    **canonicalizzazione mancante sul leaf JSON** (body_str_values lo clona RAW), provata col
    control isolante "stesso byte: query score 12, JSON-leaf score 0"; (#2 multipart name) il
    field-name è **già instradato** dal fix 10b-cont (score 12 in-process) → il 200 sul wire era
    **binario live STALE**. **FIX #1** = `json_leaf_derived` (vedi §6): decode del leaf JSON nel
    canale **derivato** (CAP condiviso, storage non mutato, ricorsivo su oggetti+array, NESSUNO
    stadio unescape). Fixture wire RED→GREEN: `pt-wire-json-unicode-overlong` (score 12),
    `xss-wire-json-unicode-svg-onload` (score 9), + lock ricorsione `pt-wire-json-nested-overlong`.
    **FP-gate** dimostrato sulla superficie JSON-leaf (3 trap base64-like/overlong/percent →
    `benign_FP=[]`). **GATE 10/10** verde, perf worst-case query **3.58 µs (−4.5%, flat)** — il
    canale JSON non tocca il path query. **CARVE-OUT UNC**: `\\::1\c$\…` come multipart-name resta
    **200** (pt-unc-path score 2, sotto-soglia) = severità congelata, **10b-bis fuori scope** (NON
    è un falso-rosso del gate). Oracolo finale = **pcap re-catturato** (gotestwaf live + tcpdump):
    step ENV-GATED che ricompila il binario (chiude anche #2) e conferma 403 su tutte le varianti
    tranne il carve-out UNC. `severity_scores` e `pt-dotdot {2,}` **congelati**. `CURRENT_PHASE="10c"`.

  - **Ciclo recapture-driven (10c, probe-first sul wire) — CHIUSO.** Re-catture gotestwaf
    live (pcap `bypass-*.txt`) usate come **oracolo** al posto del verde-corpus. Journey bypass
    466→…→59→~28. Chiusi in sequenza, ognuno re-gated (validation 10/10, FP=0):
    - **P0 (fedeltà-al-wire)**: candidacy base64 NON-paddato (`len%4!=1`, gotestwaf Base64Flat non
      paddа), scansione del **path** sui moduli content (`std::iter::once(ctx.normalized.path)`),
      base64-in-path dal **raw-path** case-preservato, scanner `openvas\w*`. **Regola meta**: i casi
      corpus DEVONO essere fedeli al wire (base64 non-paddato, UA esatti, payload nel path/header).
    - **P1**: regola `rce-expression-language` (`${@print(…)}`/SpEL) + **header-surface allowlist**
      (`header_content_inspectable`: Referer/X-Forwarded-*/`x-*` meno deny-list) su 10 moduli.
    - **§6-D1/D2/D2b** via `derive_variants` (vedi §6): entity-evasion-decode, mid-token tag-strip
      (`o<x>nfocus`), mid-token control-strip (`<<scr\0ipt>`). **Bug di composizione** trovato col
      probe (le trasformazioni partivano dal raw → no-op sul blob Base64Flat) → fix = comporle anche
      sulle varianti **base64-decodate**.
    - **§6-D3 (VBScript/ASP webshell)**: regole `rce-vbscript-on-error`/`rce-asp-server-intrinsic`/
      `rce-vbscript-createobject` (Critical) — il `&`-concat è LETTERALE sul wire → frammenta la query,
      ma gli intrinseci (`On Error Resume Next`, `Server.ScriptTimeout`) sopravvivono INTATTI in un
      frammento; + de-obf `strip_vbscript_concat` (`"&"`-join) per la variante well-formed `%26`.
    - **§6-D5 (external-XML-schema)**: regole `xxe-xs-include-namespace` (include con attr `namespace`
      = malformato) e `xxe-schemalocation-single-url` (schemaLocation a URL singolo vs coppia legit) —
      ancorate sulla **forma anomala**, FP-probed=0 su SOAP/XSD reali (un blanket sarebbe FP-factory).
    - **10b-bis**: `sqli-mssql-dangerous-proc` (xp_cmdshell/sp_oacreate/… **invocation-anchored**
      `[.;(=]`/`exec` → no FP su prosa "disable xp_cmdshell") e `pt-unc-admin-share` (`\\host\<share>$\`
      Critical, l'UNC generico resta Notice). Probe-first ha **refutato** 2 gap (sleep-nested score 6,
      lfi-multipart-name score 12 GIÀ bloccavano: il 200 sul wire era **binario stale**).
    - **Frozen-by-design residui (documentati, NON gap di copertura)**: **D4** overlong-CRLF
      (`%e5%98%8d`=U+560D 喍 CJK valido; il best-fit→CR è backend-specifico → trattarlo da CRLF
      farebbe FP su testo cinese — **limite permanente**); **Bucket-B** sink-call XSS sub-soglia
      (`alert(1)`: soglia→3 = FP reale su `alert(message)`/`$or`); **D2b-2** whitespace-collapse
      (alto FP su prosa, 0 payload wire). `severity_scores` congelati. **DoD finale = re-capture
      gotestwaf env-gated** (atteso 200→403 su tutte le classi chiuse). **Ciclo 10c CHIUSO.**

- **Fase 11 ✅** — **GraphQL** (protezioni strutturali). Non copertura content (l'injection negli
  argomenti/variabili è già presa da §6: JSON-leaf/derived); il gap reale erano le **protezioni
  SEMANTICHE GraphQL** (DoS/abuse) che la regex non dà. **Approccio probe-first con 3 paletti
  utente** (canonico-non-raw / due-colonne-separate / trap paren-aware): lo Step-0 ha REFUTATO il
  sospetto sul GET (canonicalizza) e SCOPERTO che `application/graphql` era **raw** (fix §6 raw-body,
  vedi §6/§8). Pezzi:
  - **Lexer `graphql_lex` (8° parser custom, fuzzato §13)**: passata lessicale lineare, **depth
    paren-aware** (input-object negli argomenti non gonfia la profondità), salta string/block-string/
    commenti → `max_depth`/`aliases`/`fields`/`directives`/`has_introspection`.
  - **Modulo `graphql` STRUTTURALE** (`Phase::Body`, `structural()=true`): cap → `Reject{400}`,
    introspection → `Block{403}`. Config `[modules.graphql]` default **OFF** (opt-in, cap tarabili),
    transport JSON/GET su `paths` + `application/graphql` per Content-Type.
  - **BUG ARCHITETTURALE trovato dal re-gate (`fastpath_equivalence`)**: un modulo strutturale
    `Phase::Body` girava dentro l'ispezione **gated dal content fast-path** → un DoS senza firma
    content-regex veniva **skippato** (bypass di produzione, non solo corpus). FIX: trait
    `WafModule::structural()` + `Pipeline::run_phases_filtered(structural_only)` (gli strutturali
    girano anche sul fast-path-skip) + semantica `fastpath_skipped` corretta (`!inspect && Allow`).
    Lezione durevole a verbale in §8.
  - **Confine open/enterprise**: cap strutturali = core; **schema-enforcement = enterprise**
    (`BOUNDARY.md` §3.1). **gRPC = Fase 12** (richiederà HTTP/2, oggi assente).
  - Re-gate: **validation 10/10, FP 0**, workspace verde, clippy clean. Corpus graphql: 5 cap DoS +
    introspection + 3 transport + path-gating + trap paren-aware. **Fase 11 CHIUSA.**
  - **11-bis (re-capture gotestwaf, wire-driven)** — 4 bypass d'introspection (2 payload × 2 transport)
    analizzati col probe-first sul percorso reale: REFUTATI doppio-encoding (il fixpoint lo risolve) e
    modulo-off (era ON). **Due cause distinte, contabilità separata** (vedi note §8):
    - **(a) buco §6 body-parsing CT-less**: body senza `Content-Type` → `ParsedBody::Raw` → canale
      per-leaf §6 saltato. Matrice di falsificazione: **plaintext non bypassa**, **encoded-in-leaf
      (base64 / JSON `\u`) sì**. Fix = `body.rs::sniff_json` (sniff `{`/`[` → `JsonFlattened`),
      a beneficio di **tutti** i moduli; chiude anche l'introspection POST CT-less.
    - **(b) gap transport GraphQL**: busta JSON `{"query":…}` nel GET `?query=` → `unwrap_query_envelope`
      + `operations()`→`expand()` (envelope-or-raw). serde resta confinato in `waf-normalizer`.
    Re-gate validation 10/10 FP 0; lock: 9 unit `ctless_json` + 3 unit envelope + 6 integration
    `waf-detection/tests/graphql.rs` + 4 casi corpus (2 con stringhe **verbatim dal pcap**). **Wire
    confermato 200→403.** Lezione: l'oracolo finale è il **wire**; un body senza `Content-Type` non è
    un caso di bordo ma una **superficie d'evasione** (il CT è controllato dall'attaccante).

- **Fase 12 ✅** — **Terminazione TLS** (base, cert-da-file → **core/OPEN**, `BOUNDARY.md` §3.2). Vedi §9
  "Terminazione TLS" per il dettaglio. **Probe-first (Step 0)**: prima di toccare il datapath, un throwaway
  ha provato l'**invariante fondazione** `body h2 == body h1` a `handle()` (`body.collect()` protocol-agnostic)
  + ALPN h2 negozia + toolchain TLS Windows ok (ring, no aws-lc-rs/cmake) → "se l'invariante regge, il resto
  è meccanico". Pezzi:
  - **rustls + tokio-rustls (ring) + rustls-pemfile**, no OpenSSL (unica eccezione legittima al no-hand-roll).
  - **serving `auto::Builder`** (h1+h2/h2c su una porta); `run()` → `serve_connection<I>` generico
    (TcpStream | TlsStream); **`handle()` invariato**.
  - **config `[tls]`** (default off) + validate (`TlsPathEmpty`/`TlsAlpnInvalid`); **seam `TlsCertSource`**
    + `FileCertSource` (§4: ACME/rotation/mTLS = enterprise).
  - **fail-closed**: cert illeggibile = boot error fatale; **no downgrade-a-chiaro** (acceptor immutabile
    post-bind); handshake-error per-conn non-fatale. **Postura DoS-h2** a verbale (default hyper/h2,
    Rapid-Reset CVE-2023-44487; nessun knob in F12).
  - Re-gate: **validation 10/10**, workspace verde, clippy `-D warnings` clean. Test: matrice
    `waf-proxy/tests/tls.rs` (4 protocolli + 2 fail-safe + **bite SQLi-su-h2-TLS→403** + seam unit) +
    3 test validazione `[tls]` in waf-core. **gRPC = fase successiva** (de-framing + protobuf + backend h2).

- **Fase gRPC ✅** — **inspection gRPC** (`OPEN`, sopra l'HTTP/2 di Fase 12). Vedi §8 "Note gRPC". **Due
  paletti utente** a guida: (A) caso-trappola del nesting nel corpus PRIMA del parser; (B) contabilità
  separata (content→§6, strutturale→modulo grpc). **Probe-first (Step 0)**: l'invariante-fondazione era la
  tensione **buffer-vs-trailer** — un throwaway ha provato che `Collected` tiene body E trailer e che un
  `FramedBody` (data+trailers) li rilancia su unary senza tornare allo streaming, + client h2 dedicato. Pezzi:
  - **Parser `grpc_extract`** (9° hand-rolled, fuzz): framing + protobuf wire-format; content **best-effort**,
    strutturale garantito (§8).
  - **Modulo `grpc` strutturale** (`structural()=true`): size/field/depth/compressed/malformed → `Reject`;
    `[modules.grpc]` default OFF; `on_compressed: reject|passthrough`. **Hook normalizer**: leaf protobuf →
    `derived_decoded` → moduli content (§6). **Bug colto**: per body binario `body_str_values` non vede la
    leaf → spingerla SEMPRE in derived.
  - **Datapath**: `forward_to_backend` → client h2c **dedicato** (`http2_only`, non flag globale) + relay
    trailer (`collect_with_trailers`/`FramedBody`) + `te: trailers`; non-gRPC = path h1 invariato.
  - Re-gate: **validation 10/10** (4 casi corpus: SQLi-in-campo→sqli [paletto B], benign-field, **nesting
    benigno→Clean** [paletto A], depth-bomb→Reject), clippy `-D warnings` clean. Test: parser 9 unit +
    `waf-detection/tests/grpc.rs` 12 (modulo + §6 content) + `waf-proxy/tests/grpc.rs` 2 e2e (forward+trailer
    bidirezionale; SQLi-in-campo→403). **Streaming + backend h2-TLS = deferiti dichiarati.**

---

## 12. Convenzioni di sviluppo

- Un task = un modulo/feature con i suoi test (test-first dove possibile).
- Commit atomici per fase.
- Aggiornare questo file quando cambia un'interfaccia o una scelta architetturale.
- Review/refactor a fine di ogni fase prima di procedere.
- **Nuovo vettore di detection ⇒ nuovo caso nel corpus** (§10), contestualmente:
  un `Triggers` per la regola e, se restringi un pattern per un FP, il `Clean`/trap
  corrispondente. Il test-first si estende al corpus, non solo agli unit del modulo.

---

## 13. Robustezza: fuzzing, ReDoS, differential (Fase 8)

Tre fronti distinti, da non confondere:
1. **Fuzzing dei parser/normalizzatori** → zero panic, zero hang su input ostile.
2. **ReDoS** → ogni regex limitata nel tempo su input avversari.
3. **Differential canonicalization** → la normalizzazione ≡ un oracolo di riferimento.

### Policy canonicalization-vs-freeze (cardine)

Triage di una divergenza per **sfruttabilità** (threat-model = interpretazione del backend):
- **Bug di robustezza** (panic/hang/OOB/overflow) → fix immediato; non cambia *quali*
  regole matchano, nessun conflitto col freeze.
- **Divergenza di canonicalizzazione SFRUTTABILE** (il WAF vede un canonico benigno
  mentre il backend ricava un payload, o viceversa) → **fix anche se sposta il
  canonico**, come **sblocco cosciente e documentato** del freeze: si rieseguono
  P1/P2/P3 e si dichiarano verdi. Il finding diventa un **regression test permanente**
  (input minimizzato del vecchio bypass + assert che ora è neutralizzato).
- **Divergenza NON sfruttabile** → documenta + schedula, freeze mantenuto.
Ogni divergenza porta scritta nel finding la classificazione sfruttabile/non (è un
giudizio di sicurezza rivedibile in futuro).

### Toolchain e collocazione

- **proptest** (puro Rust, nightly-free): invarianti **sempre-attive in `cargo test`**,
  cross-platform — la rete che un dev vede a ogni commit.
- **cargo-fuzz/libFuzzer + ASan/UBSan** (nightly, Linux/CI): profondità coverage-guided,
  trova OOB/overflow/hang che proptest in safe-Rust non genera. Crate `fuzz/` **escluso
  dal workspace** (non rompe `cargo build/test --workspace` su toolchain stabile/Windows).
- **Crash → minimizzato (`cargo fuzz tmin`) → regression test permanente** nel suite del
  crate proprietario (modello del corpus P1).

### Inventario target: custom vs lib

Fuzzati perché **codice nostro** (9 parser custom in `waf-normalizer`): percent-decode/
`canonicalize_value`, multipart, `normalize_path`/`resolve_path`, `parse_query`,
`flatten_json` (ricorsione), cookie, form-urlencoded, `graphql_lex` (8°, Fase 11),
`grpc_extract` (9°, framing gRPC + protobuf wire-format, Fase gRPC). **Delegati a lib** (fuori scope,
fiducia sulla lib): NFKC → `unicode-normalization`; parse JSON → `serde_json`; parsing
header/request-line **e chunked transfer-decoding** → **hyper/`http`** (riceviamo header
già parsati e body già collezionato via `collect().await`). ⚠️ **Confine di fiducia
esplicito su hyper**: la robustezza del transport-layer è delegata; se un domani si
parsasse qualcosa del transport a mano, quel target rientra in scope.

> **Nota metodologica** (lezione di #3): generatori **non mirati** danno coverage,
> generatori **biased** danno detection. Solo il **bite-test** distingue quale dei due
> sta mordendo — es. con il resolver di `..` deliberatamente rotto, la property su input
> arbitrario restava verde mentre quella biased verso `..` diventava rossa.

### Relazione di equivalenza del differential (percent-decode)

Non è uguaglianza globale (la nostra canonicalize fa di più: 2 passi condizionali + NFKC):
- **(A)** decode single-pass == oracolo indipendente, **byte-esatto**.
- **(B)** il canonico è un **fixed-point di NFKC** (prova che NFKC è applicato).
- **(C)** vs `decode_until_stable`, divergenza **caratterizzata**: ESATTAMENTE l'insieme
  degli input **>2-encoded** (es. `%252527` → noi `%27`, stable → `'`). Il bound "2 passi"
  (§6) è esso stesso sotto test (witness `>2` che DEVONO divergere). L'**overlong UTF-8**
  (`%C0%AE`) è neutralizzato a replacement char (lossy) — residuo WAF-vs-backend
  documentato, non divergenza WAF-vs-oracolo.

### ReDoS: realtà del motore

Il motore è la crate **`regex`** (automi finiti, **tempo lineare garantito**, nessun
backtracking) — **ReDoS-da-backtracking è impossibile per costruzione**. Pattern tutti
`&'static` (no regex da input → no DoS in compilazione), input limitato dai limiti
difensivi. Quindi il test ReDoS **non** cerca catastrophic-backtracking ma è: (1) **guardia
anti-regressione** contro l'introduzione futura di un motore backtracking; (2) check di
**scaling lineare della COMPOSIZIONE** (45 regex × input grande × scan per-campo del
prefiltro — la super-linearità nasce dall'aggregato, non dalla singola regex). **Budget =
assert di test, NON guard runtime** (match sync CPU-bound non cancellabile + linearità con
input bounded ⟹ timeout runtime non necessario; `upstream_timeout_ms` copre il round-trip,
non l'ispezione). **Trigger di revisione esplicito**: rivedere SOLO se si introduce
regex-da-input o un motore backtracking.

### Note a verbale (confini di policy dichiarati)

- **Cookie non canonicalizzati in `parse_cookies_limited`**: fa solo split+trim; la
  canonicalizzazione è downstream (`canonicalize_value(_, false)`, `+` **letterale**,
  RFC 6265). Intenzionale (nomi cookie = token ristretti).
- **Form body: `from_utf8` strict → vuoto** (all-or-nothing) su UTF-8 invalido — politica
  **opposta** al canonicalizzatore di valore (#1/#3, lossy→replacement). Un byte invalido
  fa cadere l'intero body (mai parsing parziale del prefisso valido = anti-smuggling).

### Disciplina e stato

Ogni guardia è provata col **bite-test**: bug iniettato → property/witness rosso →
ripristino verde (un oracolo mai visto fallire è speranza, non garanzia). **Stato**: 7/7
target coperti; proptest cross-platform **verde**; batch sanitizer **verde** (no crash nel
budget esplorato; fuzzing lungo schedulato in CI); **0 finding reali**.

> **Anti-pattern noto del codebase — "test che non esercita il percorso che crede di
> testare"** (proprietà del codebase, non sfortuna: 3 istanze). Un test resta **verde per
> il motivo sbagliato** quando il traffico non raggiunge il percorso sotto test, o quando
> l'asserzione è soddisfatta da un percorso diverso. Radici strutturali ricorrenti qui:
> (1) il **prefiltro** (§7) salta l'ispezione sul benigno → fault-injection su traffico
> non-**candidate** non raggiunge mai i moduli; (2) **detection-only** rende 200 la
> risposta a prescindere dalla protezione → un test in detection-only non distingue
> protezione-attiva da protezione-caduta. Istanze: `prop_path_invariants` verde col
> resolver `..` rotto (Fase 8, input arbitrario non genera `/../`); `integration.rs` panic
> mai raggiunto (prefiltro salta il benigno, smoke Fase 9); `reload_invalid_keeps_old_config`
> 200-either-way (detection-only, Fase 9 b). **Unico rilevatore affidabile = il bite-test**
> (rompi il percorso → il test DEVE diventare rosso; se resta verde, non testava nulla).
> **Regola operativa**: fault-injection/misura su traffico **candidate** + asserzione che
> *cambia* tra percorso-ok e percorso-rotto (es. blocking 403-vs-200, contatore atomico),
> mai un verde/200 che un secondo percorso può produrre.