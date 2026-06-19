# Light WAF (Layer 7)

Web Application Firewall in **Rust** che opera come **reverse proxy** al Layer 7:
ispeziona ogni richiesta HTTP, applica regole di detection, accumula uno **score di
anomalia** (modello CRS-style) e decide **Allow / Block (403) / Reject (400 | 429)**
prima di inoltrare al backend.

Obiettivi: *light* (poche dipendenze), *veloce* (< 1 ms p99 sul path comune),
*modulare* (ogni detection è un plugin attivabile da config), *osservabile* (log JSON
strutturato), *sicuro by design* (fail-open / fail-closed espliciti per-scenario).

---

## Capacità

| Detection | Fase | Note |
|---|---|---|
| SQLi, XSS, RCE/Cmd-inj, LFI/RFI, SSRF | body/query/cookie | content-inspection regex su dati canonicalizzati |
| Path traversal | request_line | path + query/cookie/body |
| Header injection (CRLF) | headers | field-aware (scope per regola) |
| Request smuggling (CL/TE) | connection | validazione strutturale del framing → 400 |
| Rate limiting L7 | connection | token bucket per IP risolto |

Più: normalizzazione anti-evasione (percent-decode anti-doppia-codifica + NFKC),
anomaly scoring cumulativo configurabile, livelli di paranoia (PL1–4), config esterna
con hot reload (SIGHUP, Unix), risoluzione IP client trusted-proxy, e un **fast-path**
che salta l'ispezione sul traffico provabilmente benigno (equivalenza testata).

---

## Struttura del workspace (6 crate)

```
waf-core ────────┐ (tipi base, nessuna dipendenza interna)
   ▲   ▲   ▲      │
   │   │   │      ▼
   │   │   └── waf-normalizer   (Fase 2: decode + NFKC + parsing + limiti)
   │   └────── waf-pipeline     (orchestratore a fasi + anomaly scoring)
   └────────── waf-detection    (moduli/regole + ContentPrefilter fast-path)
                   ▲
         ┌─────────┴──────────┐
   waf-proxy (il binario)   waf-corpus (validazione/tuning/fast-path: lib + test + example)
```

| Crate | Ruolo |
|---|---|
| **waf-core** | `Config`, `Decision`, `RequestContext`, `Severity`, `Normalized`; risoluzione IP client; `testkit` (builder per test, dietro feature) |
| **waf-normalizer** | Fase 2: percent-decode (anti-doppia-codifica), NFKC, parse query/cookie/body, limiti difensivi |
| **waf-pipeline** | `Pipeline`: esegue i moduli per fase, accumula lo score, decide il verdetto |
| **waf-detection** | I moduli con le tabelle `*_RULES`; `ContentPrefilter` (fast-path scope-aware) |
| **waf-proxy** | Il **binario**: reverse proxy hyper/tokio, caricamento config, fail-open/closed, hot reload |
| **waf-corpus** | I 79 casi di validazione + runner + metriche. **Non** è in produzione: è lo strumento di evidenza (oracolo) |

### Flusso di una richiesta (`waf-proxy/src/lib.rs::handle`)

1. **`build_context`** — risolve l'IP client reale (trusted-proxy / `X-Forwarded-For`).
2. **`run_connection`** — rate limit + request smuggling, **prima** del parsing → può
   rifiutare 429/400 senza pagare la normalizzazione.
3. **`normalize`** (Fase 2) — decode + NFKC + parse; sforamento limiti → 400 (policy `[resilience]`).
4. **Fast-path + ispezione** — il prefiltro decide se *qualche* regola potrebbe matchare;
   se no salta l'ispezione (Allow), altrimenti gira i moduli content e a `score ≥ block_threshold` → 403.
5. **Forward** al backend, risposta al client.

---

## Hardening & performance (Fasi 8–9)

Le Fasi 8–9 **non** aggiungono detection: *dimostrano* (non assumono) le garanzie non
funzionali. Ogni guardia è provata col **bite-test** — rompi il percorso, il test DEVE
diventare rosso; se resta verde non stava testando nulla. Dettaglio in `ARCHITECTURE.md`
§11 (performance) e §13 (robustezza). Comandi per riprodurre: § *Strumenti on-demand*.

**Performance — latenza d'ispezione.** Il numero del contratto è la latenza che dipende
SOLO dal nostro codice (`enqueue→verdetto`), isolata da rete e upstream:

- **~2 µs** worst-case PL3 (regole sature) → **~500×** sotto il contratto **p99 < 1 ms**;
- distribuzione del worst-case-set: **p50 ~2.1 µs / p99 ~3.1 µs / p99.9 ~5.3 µs**, senza
  cliff di alloc/lock; il caso più pesante (`ssrf-cloud-metadata`, 3 regole) corona il p99;
- **`max` (~97 µs) NON è il contratto**: è jitter dello scheduler OS, non proprietà del
  codice (lo prova il fatto che il caso più pesante corona il **p99**, non il `max`);
- il gate CI è **relativo** sul single-case pinnato (`inspect_worst_case_pl3`), **non**
  sull'aggregato né sul `max`: cattura le regressioni senza il rumore di un assoluto su CI
  condiviso (un `<1 ms` assoluto su runner condiviso varia 3–10× → rumore).

**Resilienza — cosa fa il WAF quando è lui in difficoltà** (policy `[resilience]`
per-scenario, §9), tutto provato end-to-end e col bite-test:

- **kill-upstream** → 502/503 dichiarati, e il WAF **ispeziona comunque** — un attacco è
  bloccato *prima* dell'upstream morto (upstream giù ≠ bypass del WAF);
- **corrupt-reload** → validate-then-swap: una config invalida è **rifiutata**, la
  last-good resta attiva, **nessuna finestra senza protezione**;
- **panic in un modulo** → isolato (`catch_unwind`): `fail_open` salta **solo** il modulo
  rotto (gli altri girano), `fail_closed` → deny. Default **`fail_open`** (controllo
  *additivo*: un bug nostro non deve ridurre la disponibilità sotto la baseline no-WAF).

**Validazione — la base della fiducia** (Fase 7, §7/§10). La detection è **congelata** e
misurata da un corpus versionato (`waf-corpus`): **79 casi**, **100% detection-recall**,
**0% falsi positivi** a PL3. Pesi e soglia (config **C2**: `critical=6`, `block_threshold=5`)
sono giustificati dall'evidenza del corpus, non ereditati. NB la **detection-recall** (una
regola matcha) è distinta dalla **blocking-recall** (`score ≥ soglia`).

**Robustezza (Fase 8, §13).** Fuzzing dei 7 parser custom (cargo-fuzz/ASan, Linux/CI) +
invarianti **proptest** cross-platform sempre-attive; ReDoS **impossibile per costruzione**
(motore `regex` a tempo lineare, nessun backtracking); differential canonicalization vs un
oracolo indipendente. **0 finding reali.**

**Qualità dei test — un principio, non un dettaglio.** Esiste una classe nota di
anti-pattern (§13): *un test che non esercita il percorso che crede di testare* — verde per
il motivo sbagliato, perché il traffico non è **candidate** (il fast-path salta il benigno)
o perché l'asserzione è soddisfatta da un percorso diverso. **Unico rilevatore affidabile =
il bite-test.** Le misure di fault-injection girano su traffico **candidate**, con
asserzioni che *cambiano* tra percorso-ok e percorso-rotto (403-vs-200, contatore atomico),
mai un verde/200 che un secondo percorso può produrre.

**In attesa dell'AMBIENTE (non del lavoro).** Gli harness sono costruiti e *noti-corretti*
(provati dalla candidacy bite verde); manca solo **dove** misurare:

- **curva di overhead e2e** (1k/5k/10k RPS) → `oha` su un box **silenzioso**. In-process su
  loopback il segnale ~µs dell'ispezione è **sotto il noise floor e2e** (~344 µs di jitter):
  `examples/load_overhead` lo mostra onestamente (delta perfino negativo = il sanity-check
  che scatta) — l'e2e **non è e non è mai stato** il contratto, che resta l'isolato (a)/(d);
- **wiring della pipeline CI** del gate di regressione → ambiente git/CI;
- **asserzione assoluta `< 1 ms` e2e** → hardware pinnato (mai su CI condiviso).

---

## Requisiti

- **Rust** stabile (toolchain con `cargo`).
- Per vedere il proxy lavorare davvero serve un **backend** in ascolto sull'indirizzo
  in `config.toml` (`backend = "http://127.0.0.1:3000"`).

## Build

```sh
cargo build              # debug
cargo build --release    # ottimizzato
```

## Run

Il binario è `waf-proxy`. Precedenza del path di config: `--config` > env `WAF_CONFIG` > `config.toml`.

```sh
# usa ./config.toml di default
cargo run -p waf-proxy

# config esplicita
cargo run -p waf-proxy -- --config /percorso/mio.toml
```

```powershell
# PowerShell: via env var, oppure alzando il livello di log (JSON, default "info")
$env:WAF_CONFIG = "E:\percorso\mio.toml"; cargo run -p waf-proxy
$env:RUST_LOG = "debug"; cargo run -p waf-proxy
```

Note:

- Il **default** (`config.toml`) ascolta `0.0.0.0:8080`, inoltra a `127.0.0.1:3000`,
  in **`mode = "detection-only"`** (logga ma non blocca). Per bloccare: `mode = "blocking"`.
- Config invalida o file mancante → messaggio su **stderr** + **exit code 2** (fail-fast).
- **Hot reload via SIGHUP** è `#[cfg(unix)]` → non disponibile su Windows (la logica
  validate-then-swap resta testata a parte).
- Prova rapida (con un backend su :3000):
  ```sh
  curl "http://localhost:8080/?q=1%20UNION%20SELECT%20pass%20FROM%20users--"
  ```
  e guarda il log della decisione.

## Test

```sh
cargo test --workspace                       # tutta la suite (unit + integration)
cargo test -p waf-detection                  # un crate solo
cargo test -p waf-corpus --test validation   # l'oracolo (recall/FP + ladder + equivalenza fast-path)
cargo clippy --workspace --all-targets       # lint (deve essere clean)
```

## Strumenti on-demand (report eseguibili, non test CI)

Gli `example` di `waf-corpus` producono l'evidenza di Fase 7:

```sh
cargo run -p waf-corpus --example report      # recall/FP per modulo + score-distribution + overlap
cargo run -p waf-corpus --example coverage     # mappa regola → caso(i) → min_pl
cargo run -p waf-corpus --example tuning       # sweep config soglie × paranoia (margini)
cargo run --release -p waf-corpus --example fastpath_bench   # benchmark fast-path
```

Performance e resilienza (Fasi 8–9):

```sh
cargo bench -p waf-corpus                                          # microbench ispezione (criterion); baseline ~2µs
cargo run --release -p waf-corpus --example latency_distribution   # distribuzione worst-case-set: p50/p99/p99.9/max
cargo run --release -p waf-proxy  --example load_overhead          # smoke e2e WAF vs passthrough (candidacy bite; e2e informativo, non il contratto)
```

Gate di regressione **relativa** (DEC 4) — workflow a due run sullo **stesso** runner
(baseline pinnato sul commit base, confronto sul candidato), poi il gate esce `1` sulla
regressione oltre soglia:

```sh
cargo bench -p waf-corpus --bench inspection -- --save-baseline pinned   # sul commit base
cargo bench -p waf-corpus --bench inspection -- --baseline pinned        # sul candidato
cargo run  -p waf-corpus --example regression_gate                       # PASS / FAIL relativo (ignora max e aggregato)
```

> Le garanzie di resilienza (kill-upstream, corrupt-reload, isolamento-panic) e di
> robustezza (proptest sui parser) girano nella suite normale: `cargo test --workspace`.
> Il fuzzing coverage-guided (`fuzz/`, cargo-fuzz + ASan) è nightly/Linux, escluso dal
> workspace per non rompere build stabili/Windows.

---

## Configurazione

`config.toml` (auto-documentato, ogni sezione commentata) raccoglie: `[proxy]` (listen/backend),
`[waf]` (mode, `block_threshold`, `paranoia_level`, `severity_scores`), `[resilience]`
(fail-open/closed per-scenario), `[rate_limit]`, `[network]` (trusted-proxy), `[limits]`,
`[modules.*]` (attiva/disattiva ogni detection). Dettaglio dello schema e dei default in
`ARCHITECTURE.md` §9.

## Dove leggere il codice

- `crates/waf-proxy/src/lib.rs` → `handle()` per il flusso end-to-end.
- `crates/waf-pipeline/src/lib.rs` → accumulo score e verdetto.
- `crates/waf-detection/src/<modulo>.rs` → le regole (`*_RULES`) di ciascun modulo.
