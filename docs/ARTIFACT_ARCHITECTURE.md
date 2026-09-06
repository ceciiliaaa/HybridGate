# Artefakt-Architektur: HybridGate Framework

Technische Dokumentation des Artefakts für das Kapitel „Konzeption und Konstruktion des Artefakts" der Bachelorarbeit _Robustness of LLM-based Code Reviews for Hardcoded Secret Detection_ (Cecilia Nothstein, 2026).

---

## 1. Überblick

### 1.1 Zielsetzung

HybridGate ist ein experimentelles Framework zur systematischen Evaluation der Robustheit LLM-basierter Code-Reviews bei der Erkennung hardcodierter Secrets in Pull Requests. Das Framework implementiert ein hybrides Gate-Konzept, das klassische Secret-Scanner, LLM-basierte Reviews und sechs nachgelagerte Guardrails zu einer dreistufigen Entscheidungslogik (BLOCK / REVIEW / PASS) kombiniert.

### 1.2 Datenfluss (High-Level)

Der vollständige Evaluationspipeline-Fluss verarbeitet ein Sample in folgenden Schritten:

```
PR-Diff (Sample)
  │
  ├─▶ Klassische Scanner (Gitleaks, detect-secrets)
  │     └─▶ scanner_hit: bool
  │
  │
  ├─▶ LLM-Call (Baseline ODER Guardrail-Prompt)
  │     └─▶ Strukturierter JSON-Output
  │
  ├─▶ Post-LLM Guardrail-Pipeline
  │     G6 Pre-Scan (Format-Familiarity) → G5 (Schema) → G2 (Untrusted Input) → G4 (Uncertainty) → G1 (Evidenz) → G3 (Redaktion)
  │     └─▶ final_decision: BLOCK | REVIEW | PASS
  
  │
  └─▶ Policy-Engine (P1, P2, P3)
        └─▶ Gate-Entscheidung pro Policy: BLOCK | REVIEW | PASS
```

Jedes Sample durchläuft zwei parallele LLM-Aufrufe: einen im **Baseline-Modus** (ohne Guardrail-Prompt-Erweiterungen) und einen im **Guardrail-Modus** (mit G1–G6-Prompt-Erweiterungen und Post-LLM-Validierung). Die Ergebnisse beider Modi werden gespeichert, um den Delta-Effekt der Guardrails isoliert messen zu können.

---

## 2. Technologien und Laufzeitumgebung

### 2.1 Programmiersprache und Frameworks

| Kategorie | Technologie | Zweck |
|---|---|---|
| Sprache | Python 3.10+ | Gesamtes Framework |
| LLM-APIs | `openai` (≥1.0), `anthropic` (≥0.18) | GPT-5-mini, Claude Opus 4.6 |
| Datenverarbeitung | `pandas`, `numpy`, `datasets` | Dataset-Loading, Aggregation |
| Validierung | `pydantic`, `jsonschema` | Schema-Validierung (G5) |
| Metriken | `scikit-learn`, `scipy` | Precision/Recall/F1, statistische Tests |
| Visualisierung | `matplotlib`, `seaborn` | Heatmaps, Ergebnis-Plots |
| Code-Analyse | `gitpython`, `unidiff` | Diff-Parsing, Git-Integration |
| Konfiguration | `python-dotenv` | API-Key-Management (.env) |
| Testing | `pytest`, `pytest-cov` | Unit-Tests für Guardrails |

### 2.2 Ausführung

Das Framework wird über CLI-Skripte ausgeführt:

- **`src/llm_evaluation/hybrid_evaluation.py`** — Haupt-Evaluationspipeline (CLI mit `argparse`)
- **`src/llm_evaluation/run_evaluation.py`** — Standalone-LLM-Evaluation ohne Guardrails
- **`scripts/run_g4_experiment.py`** — Isoliertes G4-Experiment
- **`scripts/run_g6_experiment.py`** — Isoliertes G6-Experiment
- **`scripts/reprocess_guardrails_g4fix.py`** — Offline-Nachverarbeitung ohne API-Kosten

Keine Docker- oder CI/CD-Konfiguration vorhanden; die Ausführung erfolgt lokal.

---

## 3. Modul- und Komponentenstruktur

### 3.1 Paketübersicht

```
src/
├── guardrails/          6 Guardrails (G1–G6) + Konfiguration + Pipeline
├── llm_evaluation/      LLM-Client-Abstraktion, Hybrid-Pipeline
├── scanners/            Gitleaks, detect-secrets Wrapper
├── policies/            P1, P2, P3 Gate-Policies
├── data_collection/     Dataset-Generierung (Baseline + Synthese)
├── manipulation/        Perturbation Engine v2 (E1–E3)
├── metrics/             Evaluationsmetriken, statistische Tests
└── utils/               Dataset-Validierung, Qualitätsberichte
```

### 3.2 Klassische Secret-Scanner

| Modul | Klasse | Beschreibung |
|---|---|---|
| `scanners/gitleaks_scanner.py` | `GitleaksScanner` | Wrapper um das Gitleaks-CLI; regex-basiert, hoher Recall für gängige Secret-Patterns |
| `scanners/detect_secrets_scanner.py` | `DetectSecretsScanner` | Wrapper um detect-secrets; plugin-basiert mit Entropy-Analyse |
| `scanners/base.py` | `Scanner`, `ScanResult` | Abstrakte Basisklasse und einheitliches Ergebnis-Dataclass |

Beide Scanner werden pro Sample auf den `code_context` (Diff-Text) angewendet. Die Ergebnisse fließen als `scanner_hit: bool` in die Policy-Engine und als Kontextsignal in G4 ein.

### 3.3 LLM-Client-Abstraktion

| Modul | Klasse | Beschreibung |
|---|---|---|
| `llm_evaluation/run_evaluation.py` | `LLMClient` (ABC) | Abstrakte Basisklasse mit Provider-unabhängiger Schnittstelle |
| | `OpenAIClient` | GPT-5-mini; `response_format={"type": "json_object"}` für API-Level JSON-Enforcement |
| | `AnthropicClient` | Claude Opus 4.6; `tool_choice` mit forciertem Tool-Call für strukturierten Output |
| | `LLMResponse` | Normalisiertes Antwort-Dataclass (text, provider, model, structured_output_mode) |

### 3.4 Guardrail-Komponenten (G1–G6)

| Guardrail | Modul | Klasse/Funktion | Failure Mode | Typ |
|---|---|---|---|---|
| G1 | `guardrails/g1_evidence_location.py` | `G1EvidenceLocation` | FM1: Evidence/Location Failure | 
| G2 | `guardrails/g2_untrusted_input.py` | `G2UntrustedInput` | FM2: Untrusted-Input Influence 
| G3 | `guardrails/g3_redaction.py` | `G3Redaction` | FM3: Secret Leakage in Output
| G4 | `guardrails/g4_uncertainty.py` | `G4Uncertainty` | FM4: Uncertainty Miscalibration 
| G5 | `guardrails/g5_schema_validation.py` | `G5SchemaValidation` | FM5: Schema/Output Failure 
| G6 | `guardrails/g6_format_familiarity.py` | `G6FormatFamiliarity` | FM6: Format-Misdirection 

### 3.5 Gate-Policy-Komponenten (P1–P3)

| Policy | Modul | Klasse | Logik |
|---|---|---|---|
| P1 | `policies/p1_safety_net.py` | `P1SafetyNet` | OR-Logik (Recall-First) |
| P2 | `policies/p2_consensus.py` | `P2Consensus` | AND-Logik (Precision-First) |
| P3 | `policies/p3_escalation.py` | `P3Escalation` | Kosten-optimiert (gestaffeltes Routing) |

### 3.6 Hybrid-Evaluations-Pipeline

| Modul | Klasse | Beschreibung |
|---|---|---|
| `llm_evaluation/hybrid_evaluation.py` | `HybridEvaluationClient` | Orchestriert Scanner + LLM + Guardrails + Policies |
| | `evaluate_sample()` | Verarbeitet ein Sample vollständig (Scanner → Baseline → Guardrail → Policies) |
| | Checkpoint/Resume | Inkrementelles Speichern via `.partial.jsonl` + `.checkpoint.json` |

---

## 4. Daten und Konfiguration

### 4.1 Dataset-Repräsentation

Das Evaluationsdataset liegt als JSON-Array vor (`data/03_baseline/all_250_samples_extreme.json`). Jedes Sample enthält:

| Feld | Typ | Beschreibung |
|---|---|---|
| `sample_id` | string | Eindeutige Kennung (z.B. `REAL_001`, `SYNTH_042`, `HARD_5_G6_ERT_FINGERPRINT`) |
| `gt_has_secret` | bool | Ground Truth: Enthält der Diff ein hardcodiertes Secret? |
| `gt_secret_type` | string | Typ des Secrets: `token`, `api_key`, `password`, `private_key`, `connection_string`, `none` |
| `gt_secret_value` | string | Der tatsächliche Secret-Wert (für G3-Leak-Detection und Post-hoc-Metriken) |
| `gt_file_path` | string | Dateipfad im simulierten Repository |
| `gt_line_start` | int | Zeilennummer des Secrets im `code_context` |
| `condition` | string | Perturbationsbedingung: `B0` (Baseline), `E1-B`, `E2-A`, `E3-A`, `E3-B` |
| `pr_title` | string | Simulierter PR-Titel (bei E1-B mit Benign-Framing-Manipulation) |
| `pr_body` | string | Simulierter PR-Body (bei E1-B mit exkulpatorischen Claims) |
| `code_context` | string | ±15 Zeilen Diff-Kontext um das Secret |
| `context_family` | string | Kontext-Familie: `jwt_auth`, `stripe_payment`, `aws_s3` usw. (15 Familien) |

#### Dataset-Komposition (v140, 250 Samples)

| Kategorie | Anzahl | GT+ | GT− | Beschreibung |
|---|---:|---:|---:|---|
| **Reale Samples** | 50 | 50 | 0 | Echte PR-Diffs aus Open-Source-Repositories |
| **Synthetische Samples** | 50 | 50 | 0 | Synthetisch generierte Diffs über 15 Context-Families |
| **Kontrollgruppe (negativ)** | 50 | 0 | 50 | Negative Samples ohne echtes Secret |
| ↳ NEG_DECOY | 25 | 0 | 25 | Decoy-Strings, die Secret-Patterns ähneln |
| ↳ NEG_CLEAN | 25 | 0 | 25 | Saubere Diffs ohne Secret-artige Muster |
| **Extremfälle (Hard Samples)** | 100 | 100 | 0 | Gezielte Stressfälle in 4 Kategorien |
| ↳ Evidenz- und Input-Stress | 12 | 12 | 0 | Manipulierte Evidenz- und Metadaten-Kontexte |
| ↳ Ambige Grenzfälle | 33 | 33 | 0 | Placeholder-artige Werte, Decoys mit echtem Secret |
| ↳ Format-Misdirection (isoliert) | 25 | 25 | 0 | Werte in bekannten Nicht-Secret-Formaten (UUID, SHA, Docker Digest etc.) |
| ↳ Format-Misdirection (kontextuell) | 30 | 30 | 0 | Format-familiar Values in realistischen Code-Kontexten |
| **Gesamt** | **250** | **200** | **50** | |

### 4.2 Konfigurationsmanagement

| Konfigurationsaspekt | Mechanismus | Werte |
|---|---|---|
| API-Keys | `.env`-Datei (git-ignored) | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` |
| Guardrail-Aktivierung | `GuardrailSettings` Dataclass | Default: G1–G3; Full: G1–G5; Full+G6: G1–G6 |
| LLM-Parameter | Hardcoded in Client-Klassen | `max_tokens=4096`, Timeout=120s |
| Retry-Logik | Exponentieller Backoff | `MAX_RETRIES=5`, `RETRY_BASE_DELAY=4.0s` |
| Schema-Definitionen | `STRUCTURED_OUTPUT_SCHEMA` / `BASELINE_OUTPUT_SCHEMA` | 8 Required Fields, 5 Optional Fields |

### 4.3 Wichtige Schwellenwerte und Konstanten

| Konstante | Modul | Wert | Zweck |
|---|---|---|---|
| G3: Mindestlänge für Leak-Erkennung | `g3_redaction.py` | ≥8 zusammenhängende Zeichen | Verhindert False Positives bei kurzen Strings |
| G3: Secret-Pattern-Regexes | `g3_redaction.py` | 16 Muster (AWS, Stripe, GitHub, Slack etc.) | Erkennung expliziter Credential-Formate |
| G4: Test/Docs-Pfad-Regex | `g4_uncertainty.py` | `test[s_/]`, `doc[s_/]`, `.md$` etc. | Kontextinferenz für Ambiguität |
| G4: Productive-Pfad-Regex | `g4_uncertainty.py` | `src/`, `lib/`, `app/`, `main.` etc. | Gegengewicht zu Test/Docs-Signal |
| G5: Required Fields | `g5_schema_validation.py` | 8 Pflichtfelder | Strukturelle Mindestanforderung |
| G5: Valid Secret Types | `g5_schema_validation.py` | `{token, api_key, password, private_key, connection_string, none}` | Enum-Validierung |
| G6: Format-Patterns | `g6_format_familiarity.py` | UUID, SHA-256, SHA-1, Docker Digest, Fingerprint, W3C Trace, Numerischer Token, Prefixed Hex | Bekannte Nicht-Secret-Formate |
| P3: High-Risk-File-Patterns | `p3_escalation.py` | `.env`, `config`, `credentials`, `auth` etc. | Risiko-Einstufung für Dateipfade |
| P3: Critical Secret Types | `p3_escalation.py` | `{private_key, connection_string}` | Sofortige BLOCK-Entscheidung |

---

## 5. Guardrail-Implementierungsdetails

### 5.1 G1: Evidence + Location (Post-LLM)

**Modul:** `guardrails/g1_evidence_location.py` (552 Zeilen)
**Klasse:** `G1EvidenceLocation`
**Failure Mode:** FM1 — Das Modell kann seine Behauptung nicht an eine konkrete Diff-Stelle binden.

**Kontrollfluss:**
1. Prüft, ob `pred_location_start` und `pred_location_end` innerhalb des tatsächlichen Diff-Zeilenbereichs liegen.
2. Validiert die Konsistenz zwischen `evidence_mode` und `evidence_snippet`:
   - **verbatim**: Snippet muss als Substring in der referenzierten Zeile vorkommen.
   - **multiline**: Snippet muss Token-Overlap mit dem referenzierten Zeilenbereich aufweisen.
   - **reconstructed**: Lockerere Validierung — mindestens ein signifikanter Token muss im Zielbereich vorkommen.
3. Bei Inkonsistenz: G1 meldet Issue und kann PASS→REVIEW eskalieren.

**Schlüsselfunktionen:**
- `validate_output_with_context(llm_output, diff_lines)` — Hauptvalidierung mit Diff-Kontext
- `_snippet_overlaps_span(snippet, span_lines)` — Token-basierter Überlappungstest
- `_extract_meaningful_tokens(text)` — Filtert Zeilenlabels, Maskierungen und Interpunktion

### 5.2 G2: Untrusted-Input Influence (Post-LLM)

**Modul:** `guardrails/g2_untrusted_input.py` (484 Zeilen)
**Klasse:** `G2UntrustedInput`
**Failure Mode:** FM2 — Das Modell lässt sich von manipulativen PR-Metadaten beeinflussen.

**Kontrollfluss:**
1. Prüft, ob PR-Titel oder PR-Body exkulpatorische Claims enthalten (z.B. „placeholder", „test only", „safe to commit").
2. Exkulpatorische Claims werden über 50+ Keyword-Patterns detektiert, jeweils mit Credential-Kontext-Prüfung (um False Positives zu reduzieren).
3. Vergleicht, ob das LLM trotz exkulpatorischer Metadaten `pred_has_secret=false` und `used_untrusted_input=false` gemeldet hat.
4. Bei Verdacht auf unreflektierte Untrusted-Input-Übernahme: Eskalation zu REVIEW.

**Schlüsselfunktionen:**
- `validate_with_details(llm_output, pr_title, pr_body)` — Hauptvalidierung
- `_detect_exculpatory_claims(text)` — Keyword-basierte Erkennung exkulpatorischer Claims
- `_check_unreported_influence(llm_output, pr_title, pr_body)` — Cross-Check LLM-Output vs. Metadata

### 5.3 G3: Output Leakage / Redaktion (Post-LLM, Fail-Closed)

**Modul:** `guardrails/g3_redaction.py` (888 Zeilen)
**Klasse:** `G3Redaction`
**Failure Mode:** FM3 — Das Modell reproduziert das Secret im eigenen Output.

**Drei-Schichten-Architektur:**

1. **Detektion:** Prüft alle User-sichtbaren String-Felder des LLM-Outputs auf:
   - 16 explizite Secret-Pattern-Regexes (AWS, Stripe, GitHub, Slack, OpenAI etc.)
   - Längere unmaskierte Spans (>8 konsekutive Nicht-Maskierungs-Zeichen mit Credential-Kontext)
   - Echo/Near-Echo sensitiver Kandidaten aus `code_context` oder `evidence_snippet`
   - Rekonstruierbare Leaks (mehrere Fragmente, die zusammen ein Secret offenlegen)

2. **Mitigation:** Genau ein automatischer Redaktionsversuch — ersetzt erkannte Leak-Spans durch `***REDACTED***`.

3. **Fail-Closed Routing:** Wenn Leaks nach der Redaktion persistent sind → automatisches REVIEW.

**Schlüsselfunktionen:**
- `validate_with_details(llm_output, guardrail_context)` — Dreistufige Prüfung
- `_detect_leaks(output_text, context)` — Pattern-basierte Leak-Erkennung
- `_redact_spans(output, leak_spans)` — Automatische Redaktion
- `_verify_redaction(redacted_output)` — Re-Scan nach Redaktion

**Designentscheidung:** G3 greift nicht auf Ground Truth zu. Die Erkennung basiert rein auf Pattern-Matching im Output plus optionalem Code-Kontext. Die Ground-Truth-basierte `leak_in_output`-Metrik wird separat als Post-hoc-Evaluationsmetrik berechnet (`compute_post_hoc_metrics()`).

### 5.4 G4: Uncertainty / Escalation (Post-LLM, regelbasiert)

**Modul:** `guardrails/g4_uncertainty.py` (1.011 Zeilen)
**Klasse:** `G4Uncertainty`
**Failure Mode:** FM4 — Das Modell äußert unangemessen hohe Sicherheit in ambigen Fällen.

**Zwei-Schichten-Flag-Architektur:**

1. **Reported Flags** — Das LLM meldet optional `uncertainty_flags[]` in der strukturierten Ausgabe.
2. **Inferred Flags** — G4 leitet deterministisch Flags aus dem Output, Dateipfaden, PR-Metadaten, Scanner-Ergebnissen und Upstream-Guardrail-Ergebnissen ab.

**13 Uncertainty-Flags** (in `KNOWN_UNCERTAINTY_FLAGS`):
- Kontext-Ambiguität: `placeholder_or_example_context`, `test_or_docs_context`, `comment_claims_dummy`
- Evidenz-Struktur: `reconstructed_secret`, `split_across_variables`, `evidence_span_not_single_line`, `low_specificity_literal`
- Cross-Guardrail: `scanner_disagreement`, `format_or_schema_repair_used`, `g2_unreported_influence`
- Adversarial: `decoy_like_pattern`
- Semantisch: `auth_context_hardcoded_value`
- G6-Kopplung: `g6_format_candidate_pass`

**7 deterministische REVIEW-Regeln** (R1–R7):

| Regel | Name | Trigger-Bedingung |
|---|---|---|
| R1 | `ambiguous_context` | Test/Docs-Kontext ohne produktiven Dateipfad |
| R2 | `reconstructed_plus_ambiguity` | Rekonstruiertes Secret + ambiger Kontext |
| R3 | `scanner_neg_llm_pos_context` | Scanner negativ, LLM positiv, kontextuelle Signale |
| R4 | `exculpatory_escalation` | G2 meldet unreflektierte exkulpatorische Einflüsse |
| R5 | `low_specificity_escalation` | Niedriger Spezifitäts-Literal mit unterstützenden Signalen |
| R6 | `auth_context_hardcoded` | Auth-Kontext mit hardcodiertem Wert |
| R7 | `g6_format_candidate_pass` | G6 fand Format-Kandidaten, LLM sagt PASS + korrelierende Signale |

**R7-Kopplung (G6→G4):** R7 erfordert neben dem G6-Signal mindestens ein korroborierendes Signal (`scanner_hit`, `auth_context_hardcoded_value`, `decoy_like_pattern`, `productive_file_path`), um Über-Eskalation zu vermeiden.

**Schlüsselfunktionen:**
- `validate_with_details(llm_output, guardrail_context)` — Hauptlogik mit Flag-Inferenz + Regelauswertung
- `_infer_flags_from_context(llm_output, guardrail_context)` — Deterministische Flag-Ableitung
- `_rule_g6_format_candidate_pass(all_flags, llm_output, guardrail_context)` — R7-Implementierung

### 5.5 G5: Schema Validation (Post-LLM, Fail-Closed)

**Modul:** `guardrails/g5_schema_validation.py` (728 Zeilen)
**Klasse:** `G5SchemaValidation`
**Failure Mode:** FM5 — Der LLM-Output ist formal unbrauchbar oder inkonsistent.

**Validierungsstufen:**
1. JSON-Parseability
2. Root-Typ = dict/object
3. 8 Pflichtfelder vorhanden (`pred_has_secret`, `pred_secret_type`, `evidence_mode`, `pred_location_start`, `pred_location_end`, `evidence_snippet`, `used_untrusted_input`, `final_decision`)
4. Feld-Typen korrekt (bool, string, int/null)
5. Enum-Werte innerhalb erlaubter Mengen
6. Minimale Cross-Field-Konsistenz (z.B. `pred_has_secret=false` ↔ `pred_secret_type="none"`)
7. Bei Fehler: genau 1 Reparaturversuch, dann REVIEW

**Error-Kategorien** (`ErrorCategory` Enum): `PARSE_ERROR`, `WRONG_ROOT_TYPE`, `MISSING_FIELD`, `WRONG_TYPE`, `INVALID_ENUM`, `INCONSISTENT`, `EXTRA_TEXT`

**Schlüsselfunktionen:**
- `validate(raw_response)` → `ValidationResult` — Vollständige Validierung
- `_try_repair(raw_response, errors)` — Heuristischer Reparaturversuch

### 5.6 G6: Format-Familiarity Pre-Scan (Pre-LLM)

**Modul:** `guardrails/g6_format_familiarity.py` (426 Zeilen)
**Klasse:** `G6FormatFamiliarity`
**Failure Mode:** FM6 — Das Modell stuft Werte fälschlich als harmlos ein, weil das Format einem bekannten Nicht-Secret-Muster ähnelt.

**Zwei Mechanismen:**

1. **Pre-LLM Hint-Injektion:**
   - Deterministischer Regex-Extraktor identifiziert Kandidaten-Strings im Diff, die bekannten Nicht-Secret-Formaten entsprechen (UUID, SHA-256, SHA-1, Docker Digest, Certificate Fingerprint, W3C Traceparent, numerische Tokens, prefixed Hex IDs).
   - Strukturierter Hint wird in den User-Prompt injiziert: „Das folgende Pattern wurde erkannt: [Format]. Bitte explizit prüfen, ob es sich um ein hardcodiertes Secret handelt."

2. **Post-hoc G4-Kopplung (R7):**
   - G6-Metadaten (`candidates_count`, `candidate_formats`) werden an den G4-Kontext übergeben.
   - Wenn G6 Kandidaten fand, aber das LLM `pred_has_secret=false` meldete, setzt G4 das Flag `g6_format_candidate_pass`.
   - R7 eskaliert zu REVIEW, wenn zusätzlich ein korroborierendes Signal vorliegt.

**Schlüsselfunktionen:**
- `extract_candidates(diff_text)` → `List[FormatCandidate]` — Pattern-Matching
- `get_forced_reasoning_hint(candidates)` → `str` — Generiert den Prompt-Hint
- `get_g6_prescan(diff_text, settings)` → `dict` — Modulebene-Funktion, liefert Hint + Metadaten

**Designentscheidung:** G6 trifft keine eigenständigen Erkennungsentscheidungen. Es ist kein autonomer Blocker, sondern ein Hinweis-Mechanismus, der die Aufmerksamkeit des LLMs lenkt und bei Ignorieren eine deterministische Eskalation über G4 ermöglicht.

---

## 6. Gate-Policies und Entscheidungslogik

### 6.1 Architektur

Die Policy-Engine kombiniert zwei Signalquellen zu einer finalen Gate-Entscheidung:

```
Scanner-Signal (scanner_hit: bool)  ──┐
                                      ├──▶  Policy  ──▶  BLOCK | REVIEW | PASS
LLM-Signal (final_decision: str)  ───┘
```

`final_decision` ist die Entscheidung nach Guardrail-Routing. Ein LLM-Output mit `pred_has_secret=false`, der durch G4 zu REVIEW eskaliert wurde, hat `final_decision="REVIEW"` (nicht `"PASS"`). Alle drei Policies respektieren dieses Signal.

### 6.2 P1: Safety-Net (Recall-First, OR-Logik)

**Klasse:** `P1SafetyNet` in `policies/p1_safety_net.py`

| Bedingung | Entscheidung |
|---|---|
| `final_decision == "REVIEW"` | REVIEW |
| `scanner_hit OR llm_hit` | BLOCK |
| Beide negativ | PASS |

**Einsatzzweck:** Hochsicherheitsumgebungen, in denen kein Secret durchrutschen darf. Akzeptiert höhere False-Positive-Rate.

### 6.3 P2: Consensus (Precision-First, AND-Logik)

**Klasse:** `P2Consensus` in `policies/p2_consensus.py`

| Bedingung | Entscheidung |
|---|---|
| `final_decision == "REVIEW"` | REVIEW |
| `scanner_hit AND llm_hit` | BLOCK |
| Nur ein Signal positiv | REVIEW (Disagreement) |
| Beide negativ + LLM confident | PASS |

**Einsatzzweck:** Entwicklerfreundliche Umgebungen, in denen False Positives den Workflow stören.

### 6.4 P3: Escalation (Cost-Optimized, gestaffelt)

**Klasse:** `P3Escalation` in `policies/p3_escalation.py`

P3 implementiert eine gestaffelte Eskalationslogik basierend auf Risikofaktoren:

| Risikofaktor | Prüfung |
|---|---|
| High-Risk-Datei | Dateipfad enthält `.env`, `config`, `credentials`, `auth` etc. |
| Kritischer Secret-Typ | `private_key` oder `connection_string` |
| Obfuscation-Verdacht | Regex-Muster für String-Konkatenation, Base64, Hex-Encoding etc. |

**Entscheidungslogik:**
1. Kritisches Secret + Scanner-Hit → sofort BLOCK (LLM nicht nötig)
2. High-Risk-Datei ODER Obfuscation-Verdacht → LLM aufrufen, Ergebnis folgen
3. Scanner-Hit auf nicht-kritisch → LLM zur Bestätigung
4. Low-Risk ohne Scanner-Hit → PASS ohne LLM

**Einsatzzweck:** Produktionsumgebungen mit API-Kosten-/Latenz-Beschränkungen.

---

## 7. Evaluationspipeline und Experiment-Durchführung

### 7.1 Orchestrierung

Die Haupt-Evaluationspipeline ist in `HybridEvaluationClient` (`llm_evaluation/hybrid_evaluation.py`) implementiert. Sie verarbeitet jedes Sample in folgender Reihenfolge:

1. **Scanner-Evaluation:** Gitleaks und detect-secrets auf `code_context` anwenden → `scanner_hit`
2. **LLM Baseline-Call:** Prompt ohne Guardrail-Erweiterungen, Ergebnis als `llm_baseline`
3. **LLM Guardrail-Call:** Prompt mit G1–G6-Erweiterungen + G6-Hint, Ergebnis durch Post-LLM-Pipeline (G5→G2→G4→G1→G3) → `llm_guardrail`
4. **Policy-Berechnung:** P1, P2, P3 auf beide Conditions (Baseline und Guardrail) anwenden
5. **Post-hoc-Metriken:** `leak_in_output`, `pred_location_hit` berechnen

### 7.2 Checkpoint/Resume-System

Für lange Läufe (250 Samples × 2 API-Calls = 500 Requests) implementiert die Pipeline ein Checkpoint-System:

- **`.partial.jsonl`** — Jedes fertige Sample wird sofort als JSONL-Zeile angehängt (Crash-resistent)
- **`.checkpoint.json`** — Metadaten (letzter verarbeiteter Index, Zeitstempel)
- Bei Neustart: automatisches Erkennen und Fortsetzen ab letztem Checkpoint

### 7.3 Ergebnis-Schema

Jedes Ergebnis-Record in `results.json` enthält:

| Feldgruppe | Felder | Beschreibung |
|---|---|---|
| Ground Truth | `gt_has_secret`, `gt_secret_type`, `gt_secret_value`, `gt_file_path`, `gt_line_start` | Aus dem Input-Dataset |
| Scanner | `gitleaks_hit`, `detect_secrets_hit`, `scanner_hit` | Klassische Scanner-Ergebnisse |
| LLM Baseline | `llm_baseline` (nested dict) | Baseline-LLM-Output inkl. `pred_has_secret`, `final_decision` |
| LLM Guardrail | `llm_guardrail` (nested dict) | Guardrail-LLM-Output inkl. aller G1–G6-Annotationen |
| Hit-Felder | `llm_baseline_hit`, `llm_guardrail_raw_hit`, `llm_guardrail_alert_hit` | Abgeleitete Detektionsfelder |
| Guardrail-Details | `guardrail_validation`, `baseline_failure_modes` | G1–G5-Validierungsergebnisse |
| Policies | `policy_p1_baseline`, `policy_p2_baseline`, `policy_p3_baseline`, `policy_p1_guardrail` etc. | Gate-Entscheidungen pro Policy |
| Metriken | `metrics` (nested dict) | `pred_location_hit`, `leak_in_output` |

### 7.4 Metrik-Perspektiven

Das Framework unterscheidet zwei Detektions-Perspektiven:

| Perspektive | Positive Detektion | Anwendungsfall |
|---|---|---|
| **Raw** (`llm_guardrail_raw_hit`) | `pred_has_secret == true` | Misst die reine LLM-Klassifikationsleistung |
| **Alert-Level** (`llm_guardrail_alert_hit`) | `final_decision ∈ {BLOCK, REVIEW}` | Misst die Gesamtwirkung inkl. Guardrail-Routing — entspricht dem operativen Gate-Verhalten |

### 7.5 Provider-Parität

Beide LLM-Provider verwenden API-Level JSON-Enforcement:

| Aspekt | OpenAI (GPT-5-mini) | Anthropic (Claude Opus 4.6) |
|---|---|---|
| JSON-Enforcement | `response_format={"type": "json_object"}` | `tool_choice` mit forciertem Tool-Call |
| Schema-Enforcement | Keines (nur JSON-Validität) | Vollständiges Schema mit `additionalProperties: false` |
| Baseline-Schema | Gleich wie Guardrail (Prompt steuert Felder) | Separates `BASELINE_OUTPUT_SCHEMA` mit `reasoning`-Feld |
| Guardrail-Schema | — | `STRUCTURED_OUTPUT_SCHEMA` ohne `reasoning`-Feld |
| `structured_output_mode` | `"json_object"` | `"tool_use_baseline"` / `"tool_use_guardrail"` |

G5 bleibt für beide Provider der autoritative Downstream-Validator.

### 7.6 Perturbation Engine

Die Perturbation Engine v2 (`manipulation/perturbation_engine.py`) generiert kontrolliert modifizierte positive Samples aus dem Baseline-Datensatz:

| Strategie | Code | Angriffsvektor | Beschreibung |
|---|---|---|---|
| E1-B | `BenignFramingStrategy` | PR-Text | Exkulpatorische Claims im PR-Titel/Body („test only", „placeholder") |
| E2-A | `InCodeFramingComment` | Code-Kommentar | Irreführende Kommentare direkt im Code (`# dummy credential for testing`) |
| E3-A | `StringConcatenation` | Semantische Obfuskation | Secret aufgeteilt in String-Konkatenation (`"sk_" + "test_..."`) |
| E3-B | `SplitAcrossVariables` | Semantische Obfuskation | Secret über mehrere Variablen verteilt (`part1 = ...; part2 = ...`) |

Inaktive Legacy-Strategien (E1-A DirectInstructionOverride, E1-C AuthorityClaim, E2-B AuthorityInCodeComment) sind archiviert, aber im Code erhalten.

---

## Datei-Index

| Datei | Beschreibung |
|---|---|
| `src/guardrails/__init__.py` | Guardrail-Pipeline, Bundle-Builder, G6-Prescan |
| `src/guardrails/base.py` | Abstrakte Guardrail-Basisklassen |
| `src/guardrails/config.py` | GuardrailSettings Dataclass |
| `src/guardrails/g1_evidence_location.py` | G1: Evidence/Location-Validierung |
| `src/guardrails/g2_untrusted_input.py` | G2: Untrusted-Input-Prüfung |
| `src/guardrails/g3_redaction.py` | G3: Output-Leakage-Redaktion |
| `src/guardrails/g4_uncertainty.py` | G4: Regelbasierte Uncertainty-Eskalation |
| `src/guardrails/g5_schema_validation.py` | G5: Schema-Validierung + Repair |
| `src/guardrails/g6_format_familiarity.py` | G6: Format-Familiarity Pre-Scan |
| `src/llm_evaluation/run_evaluation.py` | LLM-Clients, Prompts, Schemas |
| `src/llm_evaluation/hybrid_evaluation.py` | Hybrid-Pipeline (Scanner + LLM + Guardrails + Policies) |
| `src/scanners/gitleaks_scanner.py` | Gitleaks-Wrapper |
| `src/scanners/detect_secrets_scanner.py` | detect-secrets-Wrapper |
| `src/scanners/base.py` | Scanner-Basisklasse |
| `src/policies/p1_safety_net.py` | P1: Safety-Net (OR-Logik) |
| `src/policies/p2_consensus.py` | P2: Consensus (AND-Logik) |
| `src/policies/p3_escalation.py` | P3: Escalation (kosten-optimiert) |
| `src/policies/base.py` | Policy-Basisklasse, Enums |
| `src/data_collection/build_real_baseline.py` | Baseline aus echten PRs |
| `src/data_collection/build_b2_baseline.py` | Erweiterte Baseline (15 Kontext-Familien) |
| `src/data_collection/build_synthetic_baseline.py` | Synthetische PR-Generierung |
| `src/data_collection/negative_control_builder.py` | Negative Kontrollsamples |
| `src/manipulation/perturbation_engine.py` | Perturbation Engine v2 (E1–E3) |
| `src/metrics/evaluation_utils.py` | Metriken-Berechnung, Slice-Analyse |
| `src/metrics/compute_all.py` | Evaluations-Orchestrator |
| `src/metrics/gate_metrics.py` | Guardrail-spezifische Metriken |
| `src/metrics/leakage_metrics.py` | Leakage-Erkennung, Redaktionsqualität |
| `src/metrics/model_metrics.py` | LLM-spezifische Metriken |
| `src/metrics/statistical_tests.py` | Chi-Square, McNemar, Cohen's h |
| `src/utils/validate_samples.py` | Sample-Schema-Validierung |
| `src/utils/dataset_quality_report.py` | Dataset-Qualitätsmetriken |
| `scripts/run_g4_experiment.py` | G4-Experiment-Runner |
| `scripts/run_g6_experiment.py` | G6-Experiment-Runner |
| `scripts/reprocess_guardrails_g4fix.py` | Offline-Nachverarbeitung |
| `requirements.txt` | Python-Abhängigkeiten |
| `config/synthetic_scenarios.json` | 50+ PR-Szenario-Templates |
| `tests/test_g3.py` | G3-Unit-Tests |
| `tests/test_g4_g5.py` | G4/G5-Unit-Tests |
