# Evaluation Results: Scanner vs. LLM Baseline vs. LLM + Guardrails

**Run:** `v121_final_extreme_openai_g5fix`
**Datensatz:** `all_200_samples_extreme.json` (200 Samples, extreme Perturbation)
**Datum:** 16. März 2026
**Modell:** GPT-5 Mini (OpenAI, `gpt-5-mini`)
**Scanner:** Gitleaks + detect-secrets (kombiniert)
**Guardrails:** G1–G5, Pipeline-Order G5 → G2 → G4 → G1 → G3

---

## Guardrail-Bundle (G1–G5)

| Guardrail | Beschreibung | Modus |
|-----------|--------------|-------|
| **G5** Schema Validation | JSON-Struktur prüfen, reparieren oder → REVIEW | Post-LLM, zuerst |
| **G2** Untrusted-Input Policy | Exkulpatorische PR-Metadata-Abhängigkeit → REVIEW | Post-LLM |
| **G4** Uncertainty Escalation | Regelbasiert: Confidence + Context-Flags → REVIEW | Post-LLM |
| **G1** Evidence + Location | Evidenz-Konsistenz prüfen, invalide → REVIEW | Post-LLM |
| **G3** Output Leakage (Fail-Closed) | Detect → Redact once → REVIEW falls Leak bleibt | Post-LLM, zuletzt |

---

## Datensatz-Zusammensetzung

| Kategorie | Anzahl |
|-----------|--------|
| **Positive Samples (mit Secret)** | 150 |
| **Negative Samples (ohne Secret)** | 50 |
| davon NEG_CLEAN | 25 |
| davon NEG_DECOY | 25 |
| **Gesamt** | 200 |

### Perturbation-Conditions (positive Samples)

| Condition | n | Beschreibung |
|-----------|---|--------------|
| B0 (Baseline) | 100 | Unveränderte Samples |
| E1-B (BenignFraming) | 8 | PR-Text behauptet "kein echtes Secret" |
| E2-A (InCodeFramingComment) | 8 | Code-Kommentar behauptet "dummy/test" |
| E3-A (StringConcatenation) | 17 | Secret über String-Konkatenation verschleiert |
| E3-B (SplitAcrossVariables) | 17 | Secret über mehrere Variablen verteilt |

---

## Hauptergebnis

| Metrik | Scanner | LLM Baseline | LLM + Guardrails |
|--------|---------|--------------|------------------|
| **TP** | 126 | 149 | 150 |
| **FP** | 10 | 23 | 26 |
| **FN** | 24 | 0 | 0 |
| **TN** | 40 | 27 | 24 |
| **Precision** | 92.6% | 86.6% | 85.2% |
| **Recall** | 84.0% | 100.0% | 100.0% |
| **F1-Score** | 88.1% | 92.8% | 92.0% |
| **Specificity** | 80.0% | 54.0% | 48.0% |

---

## Per-Condition Recall (positive Samples)

| Condition | n | Scanner | LLM Baseline | LLM + Guardrails |
|-----------|---|---------|--------------|------------------|
| B0 (Baseline) | 100 | 97.0% | 100.0% | 100.0% |
| E1-B (BenignFraming) | 8 | 100.0% | 100.0% | 100.0% |
| E2-A (InCodeFramingComment) | 8 | 37.5% | 100.0% | 100.0% |
| E3-A (StringConcatenation) | 17 | 23.5% | 100.0% | 100.0% |
| E3-B (SplitAcrossVariables) | 17 | 82.4% | 100.0% | 100.0% |

**Kernaussage:** Scanner versagen bei semantischer Obfuscation (E3-A: 23.5%, E2-A: 37.5%). LLM erkennt alle Varianten.

---

## False-Positive-Analyse (negative Samples)

| Kategorie | n | Scanner FP | Baseline FP | Guardrail FP |
|-----------|---|-----------|-------------|-------------|
| NEG_CLEAN | 25 | 0 | 0 | 1 |
| NEG_DECOY | 25 | 10 | 23 | 25 |
| **Gesamt** | 50 | 10 | 23 | 26 |

### FP-Vergleich: Baseline vs. Guardrails

- In beiden FP: 23
- Nur Baseline FP: 0 (keine Korrektur durch Guardrails)
- Nur Guardrail FP: 3 (neue FPs durch G4-Eskalation PASS → REVIEW)

**Kernaussage:** NEG_DECOY-Samples sind für alle LLM-Modi problematisch. Guardrails korrigieren keine bestehenden FPs, erzeugen aber 3 zusätzliche durch G4-Eskalation.

---

## Guardrail-Routing-Analyse

### Decision Distribution (alle 200 Samples)

| Final Decision | Anzahl |
|----------------|--------|
| BLOCK | 85 |
| REVIEW | 91 |
| PASS | 24 |

### Routing nach Guardrail

| Guardrail | Positiv | Negativ | Gesamt |
|-----------|---------|---------|--------|
| Keine (LLM-Entscheidung) | 85 | 24 | 109 |
| G4 (Uncertainty) | 30 | 25 | 55 |
| G5 (Schema/Parse) | 24 | 1 | 25 |
| G3 (Output Leakage) | 10 | 0 | 10 |
| G2 (Untrusted Input) | 1 | 0 | 1 |

### Original → Final Decision

| Original | → Final | Anzahl |
|----------|---------|--------|
| BLOCK | → BLOCK | 85 |
| BLOCK | → REVIEW | 63 |
| PARSE_FAIL | → REVIEW | 25 |
| PASS | → PASS | 24 |
| PASS | → REVIEW | 3 |

### Positive Samples: BLOCK vs. REVIEW

- **BLOCK (autonom erkannt):** 85/150 (56.7%)
- **REVIEW (eskaliert):** 65/150 (43.3%)
- **PASS (durchgelassen):** 0/150 (0.0%)

---

## G4 Uncertainty Escalation — Detail

G4 eskaliert 55 Samples (30 positiv, 25 negativ) zu REVIEW.

### Triggered Rules

| Rule | Anzahl | Beschreibung |
|------|--------|--------------|
| R1_ambiguous_context | 24 | Placeholder/Test/Docs-Kontext |
| R4_exculpatory_escalation | 14 | Exkulpatorische Claims im Code/PR |
| R2_reconstructed_plus_ambiguity | 11 | Rekonstruiertes Secret + Ambiguität |
| R3_scanner_neg_llm_pos_context | 6 | Scanner-Disagreement |

### Häufigste Inferred Flags

| Flag | Anzahl |
|------|--------|
| comment_claims_dummy | 40 |
| scanner_disagreement | 21 |
| placeholder_or_example_context | 10 |
| evidence_span_not_single_line | 12 |
| decoy_like_pattern | 11 |
| reconstructed_secret | 10 |
| split_across_variables | 10 |

---

## G3 Output Leakage

- G3 triggered (Leak-Detection): 8/200
- G3 routed to REVIEW: 10
- Davon positiv: 10, negativ: 0

**G3 erzeugt keine False Positives** — reagiert ausschließlich auf echte Secrets.

---

## Confidence-Verteilung

| Confidence | Positiv | Negativ |
|------------|---------|---------|
| HIGH | 123 | 36 |
| MEDIUM | 1 | 2 |
| None (Parse-Fehler) | 26 | 12 |

---

## Data Leakage Audit

Geprüft am 16.03.2026. Ergebnis: **Keine ergebnisrelevante Leakage.**

| Vektor | Status | Detail |
|--------|--------|--------|
| LLM-Prompt | Sauber | Nur pr_title, pr_body, code_context |
| ground_truth → Guardrails | Toter Code | Parameter übergeben aber nie benutzt |
| gt_file_path → G4 | Minimal | Nur Post-Decision-Routing, auch im Diff-Header verfügbar |
| scanner_hit → G4 | Design | Hybrid-Architektur, kein GT-Leakage |
| Post-hoc Metriken | Sauber | gt_secret_value nur nach Decision für FM5-Berechnung |

---

## Schlussfolgerungen

### 1. Scanner vs. LLM: Komplementäre Stärken

| Stärke | Scanner | LLM |
|--------|---------|-----|
| Baseline (B0) | 97.0% Recall | 100% Recall |
| Obfuscation (E3-A) | **23.5%** Recall | 100% Recall |
| Code-Framing (E2-A) | **37.5%** Recall | 100% Recall |
| NEG_CLEAN Specificity | 100% | 96–100% |
| NEG_DECOY Specificity | 60% | 0–8% |
| Precision | **92.6%** | 85–87% |

### 2. Guardrail-Wirkung

| Aspekt | Bewertung |
|--------|-----------|
| Recall-Sicherung | Perfekt (100%, 0 FN) |
| Fail-Closed-Design | Funktioniert (Parse-Fehler, Unsicherheit → REVIEW) |
| G3 (Leakage) | Präzise, keine FPs |
| G4 (Uncertainty) | Aggressiv: 43% Eskalation, +3 FPs |
| FP-Reduktion | Nicht gegeben — Guardrails korrigieren keine Baseline-FPs |
| Precision-Kosten | –1.4% gegenüber Baseline |

### 3. Hauptlimitation: NEG_DECOY

Alle LLM-Modi scheitern an NEG_DECOY-Samples (designte Fake-Secrets). Dies ist ein fundamentales LLM-Limit: Decoys sehen syntaktisch identisch zu echten Secrets aus. In der Praxis erfordert dies menschliche Prüfung der REVIEW-Alerts.

---

## Run-Historie

| Run | Datum | Dataset | Anmerkung |
|-----|-------|---------|-----------|
| v100 | 2026-03-15 | all_150_samples.json | Frozen reference (150 Samples, G1-G3) |
| v110 | 2026-03-15 | all_200_samples.json | 200 Samples, G1-G5, Standard-Perturbation |
| v120 | 2026-03-16 | all_200_samples_extreme.json | Extreme-Perturbation, G5-Bug (confidence rejected) |
| **v121** | **2026-03-16** | **all_200_samples_extreme.json** | **Final: G5-Fix, alle Ergebnisse in diesem Dokument** |

### G5-Fix (v120 → v121)

- **Problem:** G5 lehnte `confidence`-Feld ab (G4 fordert es vom LLM, G5 kannte es nicht)
- **Effekt:** 166/200 Samples als Schema-Violation → REVIEW geroutet, Guardrail-Recall = 2%
- **Fix:** `("confidence", str, False)` zu `OPTIONAL_FIELDS` in `g5_schema_validation.py` hinzugefügt
- **Ergebnis:** Schema-valid 175/200 (25 verbleibende = echte Parse-Fehler)

---

## Dateipfade

| Datei | Pfad |
|-------|------|
| Ergebnisse (final) | `runs/v121_final_extreme_openai_g5fix/results.json` |
| Konfiguration | `runs/v121_final_extreme_openai_g5fix/config.json` |
| Datensatz | `data/03_baseline/all_200_samples_extreme.json` |
| Vorgänger-Run (G5-Bug) | `runs/v120_final_extreme_openai/results.json` |
| Historischer Run (150 Samples) | `runs/v100_full_openai_frozen/` |

---

## Frühere Ergebnisse (150-Sample-Runs, historisch)

Die folgenden Ergebnisse stammen aus den ursprünglichen 150-Sample-Runs mit G1–G3 Guardrails (ohne G4/G5). Sie dienen als historische Referenz.

### Modellvergleich (150 Samples, G1–G3)

| Modell | Baseline Prec. | Baseline Rec. | Guardrail Prec. | Guardrail Rec. | FM4-Violations |
|--------|---------------|---------------|-----------------|----------------|----------------|
| Claude Sonnet 4 | 84.75% | 100% | 84.75% | 100% | 86 |
| GPT-5 Mini | 81.30% | 100% | 93.65% | 59% | 5 |
| GPT-4o | 92.86% | 78% | 85.87% | 79% | 27 |

**Kontext:** Diese Runs nutzten nur prompt-basierte G3 (keine fail-closed Redaction), kein G4/G5, und den Standard-Datensatz ohne extreme Perturbationen.
