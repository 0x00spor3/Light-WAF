CONTESTO
WAF L7 in Rust. ARCHITECTURE.md = source of truth. Fasi 0-5 completate; Fase 6
Pilastro 1 (config esterna con validazione load/parse/validate/build) FATTO.
Questo è il PILASTRO 2 di 4: FAIL-OPEN / FAIL-CLOSED. Va prima dell'hot reload
(P3) perché una reload di config invalida è uno scenario di degradazione, quindi
la policy va decisa adesso.

OBIETTIVO
Definire cosa fa il WAF quando È LUI in difficoltà. Policy ESPLICITA e
configurabile per-scenario, mai comportamento implicito.

SCENARI (trattali separatamente, NON un unico flag globale)
- Upstream irraggiungibile / timeout di connessione all'origin.
- Errore interno di un modulo di detection (panic catturato, regex che esplode).
- Config corrotta rilevata in esercizio.
- Body/parsing che eccede i limiti.

VINCOLI (rispetta e motiva)
1. CONFIG PER-SCENARIO: non un solo booleano. Es:
   [resilience]
   on_upstream_error = "fail_closed"   # 502/503
   on_internal_error = "fail_open"     # un bug del WAF non deve abbattere il sito
   MOTIVA I DEFAULT: postura WAF tipica = fail-OPEN sugli errori INTERNI del WAF
   (un bug del filtro non deve far cadere l'applicazione), fail-CLOSED su errori a
   monte/sicurezza. Argomenta, non darlo per scontato.
2. PANIC SAFETY: un panic in un modulo NON deve abbattere il worker né le
   connessioni di altri client. Isola il confine del modulo (catch_unwind o
   equivalente) e applica on_internal_error.
3. OSSERVABILITÀ: ogni attivazione di fail-open/closed va LOGGATA — è un evento
   operativo critico, non silenzioso.
4. Riusa la validazione del Pilastro 1 per "config corrotta".

TEST
- modulo che panica -> fail_open applicato, worker vivo, evento loggato.
- upstream down -> fail_closed -> 502/503, niente hang.
- override config della policy -> comportamento cambia di conseguenza.
- panic isolato: la connessione di un altro client NON viene interrotta.

DOC
- ARCHITECTURE.md: schema [resilience], policy per-scenario con razionale dei
  default, nota su panic isolation.

OUTPUT ATTESO
Prima un piano sintetico: schema [resilience], default scelti per ciascuno
scenario con motivazione, meccanismo di panic isolation, punti di log, test.
FERMATI e aspetta il mio OK prima del codice.