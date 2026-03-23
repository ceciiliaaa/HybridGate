# Evaluation Results: Scanner vs. LLM Baseline vs. LLM + Guardrails

**Run:** `v140_full_g6_250samples`
**Datensatz:** `all_250_samples_extreme.json` (250 Samples, extreme Perturbation)
**Datum:** 23. März 2026
**Modell:** GPT-5 Mini (OpenAI, `gpt-5-mini`)
**Scanner:** Gitleaks + detect-secrets (kombiniert)
**Guardrails:** G1-G5 Post-LLM (Pipeline: G5 -> G2 -> G4 -> G1 -> G3), G6 Pre-LLM (Format-Familiarity Hint)

---

## Methodische Vorbemerkung: Metrik-Definitionen

Das Guardrail-System ist kein reiner binarer Klassifikator, sondern ein **dreistufiges Decision-/Routing-System** mit den Ausgangen BLOCK, REVIEW und PASS. Daher werden zwei Metrik-Perspektiven unterschieden:

### Perspektive A: Autonome Klassifikation (Autonomous-Level)

Nur BLOCK zahlt als Detection. REVIEW-Eskalationen durch Guardrails werden **nicht** als TP gewertet. Diese Perspektive misst die reine autonome Entscheidungsfahigkeit des Systems ohne menschliche Prufung.

### Perspektive B: Alert-Level / Sicherheits-Gating

BLOCK **und** REVIEW zahlen gemeinsam als Alert/Detection. Ein Sample gilt nur als unerkannt (FN), wenn es als PASS durchgelassen wird. Diese Perspektive misst die Sicherheitsgarantie des Gesamtsystems -- kein positives Sample darf ungeprüft passieren.

**Perspektive B ist die primare Sicht fur ein Sicherheitssystem**, weil REVIEW eine kontrollierte Eskalation darstellt, nicht ein Durchlassen. Wo nicht anders angegeben, verwenden die Hauptergebnisse Perspektive B.

---

## Guardrail-Bundle (G1-G6)

| Guardrail | Beschreibung | Modus |
|-----------|--------------|-------|
| **G6** Format-Familiarity Pre-Scan | Regex-basierte Erkennung bekannter Non-Secret-Formate (UUID, SHA, JWT, CUID etc.) -> Forced-Reasoning-Hint im User-Prompt | Pre-LLM |
| **G5** Schema Validation | JSON-Struktur prufen, reparieren oder -> REVIEW | Post-LLM, zuerst |
| **G2** Untrusted-Input Policy | Exkulpatorische PR-Metadata-Abhangigkeit -> REVIEW | Post-LLM |
| **G4** Uncertainty Escalation | Regelbasiert: Confidence + Context-Flags -> REVIEW | Post-LLM |
| **G1** Evidence + Location | Evidenz-Konsistenz prufen, invalide -> REVIEW | Post-LLM |
| **G3** Output Leakage (Fail-Closed) | Detect -> Redact once -> REVIEW falls Leak bleibt | Post-LLM, zuletzt |

---

## Datensatz-Zusammensetzung

| Kategorie | Anzahl |
|-----------|--------|
| **Positive Samples (mit Secret)** | 200 |
| **Negative Samples (ohne Secret)** | 50 |
| davon NEG_CLEAN | 25 |
| davon NEG_DECOY | 25 |
| **Gesamt** | 250 |

### Herkunft

| Herkunft | Anzahl |
|----------|--------|
| REAL (echte Repositories) | 75 |
| SYNTH (synthetisch generiert) | 75 |
| NEG (Kontroll-Samples) | 100 |

### Perturbation-Conditions (positive Samples)

| Condition | n | Beschreibung |
|-----------|---|--------------|
| B0 (Baseline) | 150 | Unveranderte Samples (100 REAL/SYNTH + 50 NEG) |
| E1-B (BenignFraming) | 8 | PR-Text behauptet "kein echtes Secret" |
| E2-A (InCodeFramingComment) | 8 | Code-Kommentar behauptet "dummy/test" |
| E3-A (StringConcatenation) | 18 | Secret uber String-Konkatenation verschleiert |
| E3-B (SplitAcrossVariables) | 17 | Secret uber mehrere Variablen verteilt |
| E4-F (Multi-FM) | 8 | Mehrere Failure-Modes kombiniert |
| E4-G (Multi-FM) | 8 | Mehrere Failure-Modes kombiniert |
| E4-H (Hardened) | 9 | Gehartete Positive mit Obfuscation |
| E4-I (Hardened) | 24 | Gehartete Positive mit Obfuscation |

---

## Hauptergebnis

### Perspektive B: Alert-Level (BLOCK + REVIEW = Detection)

| Metrik | Scanner | LLM Baseline | LLM + Guardrails |
|--------|---------|--------------|------------------|
| **TP** | 137 | 174 | 198 |
| **FP** | 10 | 24 | 26 |
| **FN** | 63 | 26 | 2 |
| **TN** | 40 | 26 | 24 |
| **Precision** | 93.2% | 87.9% | 88.4% |
| **Recall** | 68.5% | 87.0% | 99.0% |
| **F1-Score** | 79.0% | 87.4% | 93.4% |
| **Specificity** | 80.0% | 52.0% | 48.0% |
| **Escape Rate** | 31.5% | 13.0% | 1.0% |

### Perspektive A: Autonomous-Level (nur BLOCK = Detection)

| Metrik | Scanner | LLM Baseline | LLM + Guardrails |
|--------|---------|--------------|------------------|
| **TP** | 137 | 167 | 96 |
| **FP** | 10 | 23 | 0 |
| **FN** | 63 | 33 | 104 |
| **TN** | 40 | 27 | 50 |
| **Precision** | 93.2% | 87.9% | 100.0% |
| **Recall** | 68.5% | 83.5% | 48.0% |
| **F1-Score** | 79.0% | 85.6% | 64.9% |
| **Specificity** | 80.0% | 54.0% | 100.0% |

**Kernaussage:** Die Guardrails transformieren das System in ein fail-closed Gating-System. Alert-Level: Recall 99.0%, Escape Rate 1.0% (2 von 200 positiven Samples durchgelassen). Autonomous-Level: Precision 100% (kein einziges negatives Sample als BLOCK klassifiziert), aber Recall nur 48.0% -- die restlichen 52% werden zu REVIEW eskaliert, nicht durchgelassen. Der hohe REVIEW-Anteil ist designbedingt: Unsicherheit wird eskaliert, nicht ignoriert.

---

## Per-Condition Recall (positive Samples, Alert-Level)

| Condition | n | Scanner | LLM Baseline | Guardrails |
|-----------|---|---------|--------------|------------|
| B0 (Baseline) | 150 | 97.0% | 100.0% | 100.0% |
| E1-B (BenignFraming) | 8 | 100.0% | 100.0% | 100.0% |
| E2-A (InCodeFramingComment) | 8 | 37.5% | 100.0% | 100.0% |
| E3-A (StringConcatenation) | 18 | 27.8% | 100.0% | 100.0% |
| E3-B (SplitAcrossVariables) | 17 | 82.4% | 100.0% | 100.0% |
| E4-F (Multi-FM) | 8 | 12.5% | 100.0% | 87.5% |
| E4-G (Multi-FM) | 8 | 37.5% | 100.0% | 87.5% |
| E4-H (Hardened) | 9 | 0.0% | 100.0% | 100.0% |
| E4-I (Hardened) | 24 | 25.0% | 100.0% | 100.0% |

**Kernaussage:** Scanner versagen bei semantischer Obfuscation (E3-A: 27.8%, E4-H: 0.0%, E4-I: 25.0%). Das LLM erkennt nahezu alle Varianten. Die 2 FN der Guardrails stammen aus E4-F und E4-G (je 1 Sample), beides Multi-FM-Stress-Conditions.

---

## False-Positive-Analyse (negative Samples)

| Kategorie | n | Scanner FP | Baseline FP | Guardrail FP (Alert) |
|-----------|---|-----------|-------------|---------------------|
| NEG_CLEAN | 25 | 0 | 0 | 1 |
| NEG_DECOY | 25 | 10 | 24 | 25 |
| **Gesamt** | 50 | 10 | 24 | 26 |

**Kernaussage:** NEG_DECOY-Samples sind fur alle LLM-Modi problematisch (Baseline: 24/25 FP, Guardrails: 25/25 FP). Die Guardrails korrigieren keine bestehenden FPs, erzeugen aber auch nur 2 zusatzliche (1 NEG_CLEAN, 1 NEG_DECOY). Die Guardrails sind **nicht darauf ausgelegt, FPs zu reduzieren** -- ihr Ziel ist Recall-Sicherung und kontrollierte Eskalation bei Unsicherheit.

---

## Decision-Routing-Analyse

### Decision Distribution (alle 250 Samples)

| Final Decision | Anzahl | Anteil | Bedeutung |
|----------------|--------|--------|-----------|
| BLOCK | 96 | 38.4% | Autonom als gefahrlich klassifiziert |
| REVIEW | 128 | 51.2% | Zur menschlichen Prufung eskaliert |
| PASS | 26 | 10.4% | Autonom als ungefahrlich klassifiziert |

### Positive Samples: BLOCK vs. REVIEW vs. PASS

| Decision | Anzahl | Anteil |
|----------|--------|--------|
| **BLOCK (autonom erkannt)** | 96/200 | 48.0% |
| **REVIEW (eskaliert)** | 102/200 | 51.0% |
| **PASS (durchgelassen)** | 2/200 | 1.0% |

### Negative Samples: Entscheidungsverteilung

| Decision | Anzahl | Anteil |
|----------|--------|--------|
| PASS (korrekt) | 24/50 | 48.0% |
| BLOCK (FP) | 0/50 | 0.0% |
| REVIEW (FP, eskaliert) | 26/50 | 52.0% |

### Routing nach Guardrail

| Guardrail | Trigger | Trigger Rate | Routed | Routed Rate |
|-----------|---------|--------------|--------|-------------|
| G3 (Output Leakage) | 226 | 90.4% | 15 | 6.0% |
| G4 (Uncertainty) | 104 | 41.6% | 101 | 40.4% |
| G2 (Untrusted Input) | 10 | 4.0% | 10 | 4.0% |
| G1 (Evidence + Location) | 6 | 2.4% | 2 | 0.8% |
| G5 (Schema Validation) | 0 | 0.0% | 0 | 0.0% |

*"Trigger" = Guardrail hat ein Problem erkannt. "Routed" = Guardrail hat die finale Entscheidung bestimmt (hochste Prioritat unter den Triggern).*

### Multi-Trigger-Verhalten

| Metrik | Wert |
|--------|------|
| Samples mit mindestens einem Trigger | 226/250 (90.4%) |
| Single-Trigger | 113 (45.2%) |
| Multi-Trigger | 113 (45.2%) |
| Max. Trigger pro Sample | 3 |

| Haufigste Kombinationen | Anzahl | Anteil |
|--------------------------|--------|--------|
| G3 allein | 113 | 45.2% |
| G4+G3 | 97 | 38.8% |
| G2+G3 | 7 | 2.8% |
| G4+G1+G3 | 4 | 1.6% |
| G2+G4+G3 | 3 | 1.2% |
| G1+G3 | 2 | 0.8% |

---

## G3: Output Leakage

| Metrik | Baseline | Guardrails |
|--------|----------|------------|
| Leakage (Secret im Output) | 131/250 (52.4%) | 0/250 (0.0%) |
| G3 Triggered | -- | 226/250 (90.4%) |
| G3 Routed (finale Entscheidung) | -- | 15/250 (6.0%) |

**Kernaussage:** G3 eliminiert Output-Leakage vollstandig (Residual: 0%). G3 triggert haufig (90.4%), weil es konservativ Pattern- und Entropie-basiert pruft, aber nur 6% der Samples werden tatsachlich durch G3 geroutet (die anderen werden bereits von hoherprioritierten Guardrails eskaliert).

---

## G4: Uncertainty Escalation

| Metrik | Wert |
|--------|------|
| Trigger | 104/250 (41.6%) |
| Routed | 101/250 (40.4%) |
| davon auf positiven Samples | 80 |
| davon auf negativen Samples | 24 |

### Triggered Rules

| Rule | Anzahl | Beschreibung |
|------|--------|--------------|
| R3_scanner_neg_llm_pos_context | 39 | Scanner-Disagreement |
| R1_ambiguous_context | 32 | Placeholder/Test/Docs-Kontext |
| R4_exculpatory_escalation | 17 | Exkulpatorische Claims im Code/PR |
| R2_reconstructed_plus_ambiguity | 15 | Rekonstruiertes Secret + Ambiguitat |
| R6_auth_context_hardcoded | 1 | Auth-Kontext mit hardcoded Value |

### Haufigste Inferred Flags

| Flag | Anzahl |
|------|--------|
| auth_context_hardcoded_value | 91 |
| placeholder_or_example_context | 73 |
| scanner_disagreement | 63 |
| comment_claims_dummy | 61 |
| test_or_docs_context | 35 |
| decoy_like_pattern | 34 |

---

## G6: Format-Familiarity Pre-LLM Hint (explorativ)

G6 ist ein explorativer Pre-LLM-Guardrail, der hardcoded Values erkennt, die bekannten Non-Secret-Formaten entsprechen (UUID, SHA-256, Git-SHA, Docker Digest, JWT, CUID, BSON ObjectId, etc.) und einen Forced-Reasoning-Hint in den LLM-Prompt injiziert.

| Metrik | Wert |
|--------|------|
| Hint injiziert | 30/250 (12.0%) |
| Kein Hint | 220/250 |
| Detection Rate mit Hint | 93.3% (28/30) |
| Detection Rate ohne Hint | 87.7% (193/220) |
| Hint auf GT_POS Samples | 29/200 (14.5%) |
| Hint auf GT_NEG Samples | 1/50 |
| Schema-valid bei Hint | 30/30 (100%) |
| Schema-Fail bei Hint | 0 |

**Kernaussage:** G6 ist schema-kompatibel (0 Schema-Failures). Die Detection Rate mit Hint (93.3%) liegt uber der ohne Hint (87.7%), was auf einen positiven Effekt hindeutet. Die Stichprobe (n=30) ist jedoch zu klein fur statistisch belastbare Aussagen. G6 erzeugt keine eigenen False Positives, da es nur Hints injiziert und keine Routing-Entscheidungen trifft.

---

## Failure-Mode PRI-Analyse

Bewertet das Guardrail-Bundle als Kontrollebene via Prevalence (P), Intervention (I) und Residual (R) pro Failure Mode.

| FM | Guardrail | Prevalence | Prev Rate | Intervention Rate | Residual Rate | Observability |
|----|-----------|-----------|-----------|-------------------|---------------|---------------|
| FM1 (Evidence/Location) | G1 | 26 | 10.4% | 7.7% | 7.7% | partial |
| FM2 (Untrusted Input) | G2 | 0 | 0.0% | n/a | n/a | n/a |
| FM3 (Secret Leakage) | G3 | 131 | 52.4% | 100.0% | 0.0% | direct |
| FM4 (Uncertainty) | G4 | 73 | 29.2% | 89.0% | 89.0% | partial |
| FM5 (Schema Failure) | G5 | 0 | 0.0% | n/a | n/a | n/a |

**Kernaussage:** FM3 (Leakage) ist vollstandig kontrolliert: 100% Intervention, 0% Residual. FM4 (Uncertainty) hat hohe Prevalence (29.2%) und hohe Interventionsrate (89.0%), aber das Residual bleibt hoch (89.0%), was bedeutet, dass die strukturellen Unsicherheits-Indikatoren auch nach Guardrail-Intervention noch vorhanden sind. FM2 und FM5 treten im Datensatz nicht auf.

---

## Slice-Analyse (Ubersicht)

### Alert-Level Recall nach Slice

| Slice | n | Scanner | LLM Baseline | Guardrails |
|-------|---|---------|--------------|------------|
| base | 150 | 97.0% | 100.0% | 100.0% |
| stress | 100 | 40.0% | 74.0% | 98.0% |
| real | 75 | 80.0% | 100.0% | 100.0% |
| synthetic | 75 | 88.0% | 100.0% | 100.0% |

### Escape Rate nach Slice

| Slice | Scanner | LLM Baseline | Guardrails |
|-------|---------|--------------|------------|
| base | 3.0% | 0.0% | 0.0% |
| stress | 60.0% | 26.0% | 2.0% |
| neg_clean | n/a | n/a | n/a |
| neg_decoy | n/a | n/a | n/a |

**Kernaussage:** Der grosste Unterschied zeigt sich bei Stress-Samples: Scanner erkennen nur 40% (Escape Rate 60%), LLM Baseline 74%, Guardrails 98%. Die Guardrails reduzieren die Escape Rate auf Stress-Samples von 26% (Baseline) auf 2%.

---

## Schlussfolgerungen

### 1. Scanner vs. LLM: Komplementare Starken

| Starke | Scanner | LLM |
|--------|---------|-----|
| Baseline (B0) | 97.0% Recall | 100% Recall |
| Obfuscation (E3-A) | **27.8%** Recall | 100% Recall |
| Hardened (E4-H) | **0.0%** Recall | 100% Recall |
| NEG_CLEAN Specificity | 100% | 96-100% |
| NEG_DECOY Specificity | 60% | 0-4% |
| Precision (Alert) | **93.2%** | 87.9-88.4% |

### 2. Guardrail-Wirkung

| Aspekt | Bewertung |
|--------|-----------|
| Recall-Sicherung (Alert) | Nahezu perfekt (99.0%, 2 FN, Escape Rate 1.0%) |
| Autonome Precision | Perfekt (100%, 0 FP bei BLOCK) |
| Fail-Closed-Design | Funktioniert (Unsicherheit -> REVIEW) |
| G3 (Leakage) | Vollstandig wirksam (Residual 0%) |
| G4 (Uncertainty) | Aggressiv: 41.6% Trigger, +2 neue FPs |
| G6 (Format-Familiarity) | Schema-kompatibel, +5.6pp Detection Rate bei getriggerten Samples |
| FP-Reduktion | Nicht gegeben -- Guardrails korrigieren keine Baseline-FPs |
| Reviewer-Last | 128/250 Samples (51.2%) eskaliert zu REVIEW |

### 3. Hauptlimitation: NEG_DECOY

Alle LLM-Modi scheitern an NEG_DECOY-Samples (designte Fake-Secrets). Dies ist ein fundamentales LLM-Limit: Decoys sehen syntaktisch identisch zu echten Secrets aus. In der Praxis erfordert dies menschliche Prufung der REVIEW-Alerts. Dies ist zugleich der **wichtigste Ansatzpunkt fur zukunftige Forschung**.

### 4. Hauptbotschaft

Der LLM-basierte Ansatz verbessert die Erkennung deutlich gegenuber klassischen Scannern, insbesondere bei semantischer Obfuscation (Stress-Recall: Scanner 40% vs. LLM 74-98%). Die Guardrails steigern den Recall von 87% (Baseline) auf 99% (Alert-Level) und eliminieren Output-Leakage vollstandig. Der zentrale Trade-off ist die hohe Reviewer-Last (51.2% REVIEW) und die False-Positive-Belastung bei Decoy-Fallen.

---

## Run-Historie

| Run | Datum | Dataset | Samples | Guardrails | Anmerkung |
|-----|-------|---------|---------|------------|-----------|
| v100 | 2026-03-15 | all_150_samples.json | 150 | G1-G3 | Frozen reference |
| v110 | 2026-03-15 | all_200_samples.json | 200 | G1-G5 | Standard-Perturbation |
| v120 | 2026-03-16 | all_200_samples_extreme.json | 200 | G1-G5 | G5-Bug (confidence rejected) |
| v121 | 2026-03-16 | all_200_samples_extreme.json | 200 | G1-G5 | G5-Fix, vorherige Referenz |
| v130 | 2026-03-19 | all_250_samples_extreme.json | 250 | G1-G5 | Erweiterter Datensatz, Baseline-FM-Multitrigger |
| **v140** | **2026-03-23** | **all_250_samples_extreme.json** | **250** | **G1-G6** | **Final: G6 integriert, alle Ergebnisse in diesem Dokument** |

---

## Dateipfade

| Datei | Pfad |
|-------|------|
| Ergebnisse (final) | `runs/v140_full_g6_250samples/results.json` |
| Konfiguration | `runs/v140_full_g6_250samples/config.json` |
| Evaluation Outputs | `runs/v140_full_g6_250samples/evaluation_outputs/` |
| Datensatz | `data/03_baseline/all_250_samples_extreme.json` |
| Vorganger-Run (ohne G6) | `runs/v130_baseline_fm_multitrigger/` |
| Historischer Run (200 Samples) | `runs/v121_final_extreme_openai_g5fix/` |
| Historischer Run (150 Samples) | `runs/v100_full_openai_frozen/` |

---

## Fruhere Ergebnisse (150-Sample-Runs, historisch)

Die folgenden Ergebnisse stammen aus den ursprunglichen 150-Sample-Runs mit G1-G3 Guardrails (ohne G4/G5/G6). Sie dienen als historische Referenz.

### Modellvergleich (150 Samples, G1-G3)

| Modell | Baseline Prec. | Baseline Rec. | Guardrail Prec. | Guardrail Rec. | FM4-Violations |
|--------|---------------|---------------|-----------------|----------------|----------------|
| Claude Sonnet 4 | 84.75% | 100% | 84.75% | 100% | 86 |
| GPT-5 Mini | 81.30% | 100% | 93.65% | 59% | 5 |
| GPT-4o | 92.86% | 78% | 85.87% | 79% | 27 |

**Kontext:** Diese Runs nutzten nur prompt-basierte G3 (keine fail-closed Redaction), kein G4/G5/G6, und den Standard-Datensatz ohne extreme Perturbationen.
