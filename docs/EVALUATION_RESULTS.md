# Evaluation Results: Baseline vs. Guardrails

**Datensatz:** `all_150_samples.json` (150 Samples)
**Datum:** 11. März 2026
**Evaluierte Modelle:** Claude Sonnet 4, GPT-5 Mini, GPT-4o
**Scanner:** Gitleaks, detect-secrets

---

## Guardrail-Bundle (Intervention)

Die Evaluation vergleicht **Baseline** (ohne Guardrails) mit einem **Guardrail-Bundle** bestehend aus:

| Guardrail | Beschreibung | Adressiert FM |
|-----------|--------------|---------------|
| **G1** Evidence + Location | Pflichtfelder: `file_path`, `line_start`, `evidence_snippet` | FM2 (Evidence Deficit) |
| **G2** Untrusted-Input Policy | PR-Body/Kommentare als untrusted; Entscheidung nur anhand Code-Diff | FM1 (Metadata Susceptibility) |
| **G3** Redaction / Never-Echo | Secrets maskieren; Output darf keine Secret-Strings enthalten | FM4 (Secret Leakage) |

---

## Datensatz-Zusammensetzung

| Kategorie | Anzahl |
|-----------|--------|
| **Positive Samples (mit Secret)** | 100 |
| **Negative Samples (ohne Secret)** | 50 |
| **Gesamt** | 150 |

---

## Hauptergebnis: Baseline vs. Guardrails

### Claude Sonnet 4

| Metrik | Baseline | Mit Guardrails | Differenz |
|--------|----------|----------------|-----------|
| **Precision** | 84.75% | 84.75% | 0% |
| **Recall** | 100.00% | 100.00% | 0% |
| **F1-Score** | 91.74% | 91.74% | 0% |
| **FM4-Violations** | 86 | 86 | 0 |

**Fazit:** Bei Claude zeigen die Guardrails keine messbare Wirkung. Das Modell gibt weiterhin in 86 von 150 Fällen das Secret im Output aus (FM4: Secret Leakage).

---

### GPT-5 Mini

| Metrik | Baseline | Mit Guardrails | Differenz |
|--------|----------|----------------|-----------|
| **Precision** | 81.30% | 93.65% | **+12.35%** |
| **Recall** | 100.00% | 59.00% | **-41.00%** |
| **F1-Score** | 89.69% | 72.39% | -17.30% |
| **FM4-Violations** | n/a | 5 | **-81 vs. Claude** |

**Fazit:** GPT-5 Mini reagiert stark auf Guardrails:
- **Positiv:** Precision steigt um 12%, FM4-Violations drastisch reduziert (nur 5 statt 86 bei Claude)
- **Negativ:** Recall fällt von 100% auf 59% - das Modell wird zu konservativ und übersieht 41 echte Secrets

---

### GPT-4o

| Metrik | Baseline | Mit Guardrails | Differenz |
|--------|----------|----------------|-----------|
| **Precision** | 92.86% | 85.87% | **-7.00%** |
| **Recall** | 78.00% | 79.00% | +1.00% |
| **F1-Score** | 84.78% | 82.29% | -2.49% |
| **FM4-Violations** | n/a | 27 | - |

**Fazit:** GPT-4o zeigt gemischte Ergebnisse mit Guardrails:
- Precision sinkt um 7% (mehr False Positives)
- Recall bleibt stabil
- Mittlere FM4-Rate (27 Samples)

---

## Vergleichstabelle: Alle Modelle

### Ohne Guardrails (Baseline)

| Modell | Precision | Recall | F1-Score | TP | FP | FN | TN |
|--------|-----------|--------|----------|----|----|----|----|
| **Claude Sonnet 4** | 84.75% | **100%** | **91.74%** | 100 | 18 | 0 | 32 |
| **GPT-5 Mini** | 81.30% | **100%** | 89.69% | 100 | 23 | 0 | 27 |
| **GPT-4o** | **92.86%** | 78% | 84.78% | 78 | 6 | 22 | 44 |

### Mit Guardrails (G1 + G2 + G3)

| Modell | Precision | Recall | F1-Score | TP | FP | FN | TN | FM4 |
|--------|-----------|--------|----------|----|----|----|----|-----|
| **Claude Sonnet 4** | 84.75% | **100%** | **91.74%** | 100 | 18 | 0 | 32 | 86 |
| **GPT-5 Mini** | **93.65%** | 59% | 72.39% | 59 | 4 | 41 | 46 | **5** |
| **GPT-4o** | 85.87% | 79% | 82.29% | 79 | 13 | 21 | 37 | 27 |

---

## FM4-Compliance: Secret Leakage in Output

**FM4 (Failure Mode 4):** Das Modell reproduziert das Secret im Klartext im Output (Reasoning/Evidence).
**G3 (Redaction/Never-Echo):** Guardrail zur Mitigation - Secrets sollen maskiert werden.

| Modell | FM4-Violations | Quote | G3-Wirksamkeit |
|--------|----------------|-------|----------------|
| **GPT-5 Mini** | 5 | **3.3%** | Hoch |
| **GPT-4o** | 27 | 18.0% | Mittel |
| **Claude Sonnet 4** | 86 | 57.3% | Keine |

**Interpretation:**
- GPT-5 Mini hält G3 (Redaction) am besten ein (nur 3.3% Leaks)
- Claude ignoriert G3 weitgehend (57.3% Leaks trotz Guardrail-Prompt)

---

## Static Scanner als Referenz

| Metrik | Wert |
|--------|------|
| Precision | 90.65% |
| Recall | 97.00% |
| F1-Score | 93.72% |
| TP / FP / FN / TN | 97 / 10 / 3 / 40 |

Die Scanner (Gitleaks + detect-secrets) erreichen ohne LLM bereits sehr gute Ergebnisse.

---

## Schlussfolgerungen

### 1. Guardrail-Wirkung ist modellabhängig

| Modell | G1 (Evidence) | G2 (Untrusted) | G3 (Redaction) | Gesamtwirkung |
|--------|---------------|----------------|----------------|---------------|
| **Claude** | Keine Änderung | Keine Änderung | Ignoriert | Keine |
| **GPT-5 Mini** | Wirksam | Wirksam | **Sehr wirksam** | Stark (aber Recall-Verlust) |
| **GPT-4o** | Teilweise | Teilweise | Teilweise | Moderat |

### 2. Trade-off: Sicherheit vs. Recall

| Ansatz | Vorteil | Nachteil |
|--------|---------|----------|
| **Baseline (ohne Guardrails)** | Hoher Recall (100% bei Claude/GPT-5) | FM4: Secrets werden im Output geleakt |
| **Mit Guardrails** | FM4 reduziert (GPT-5: nur 5 Leaks) | Recall kann drastisch sinken |

### 3. Empfehlung

Für produktive Systeme mit Secret-Detection:
- **Wenn Recall kritisch:** Claude Baseline + Post-Processing zur Leak-Vermeidung
- **Wenn FM4-Vermeidung kritisch:** GPT-5 Mini mit Guardrails (akzeptiere niedrigeren Recall)
- **Hybrid-Ansatz:** Scanner (97% Recall) + LLM für Grenzfälle

---

## Referenzen

### Failure Modes (aus Arbeitsplan)

| FM | Beschreibung | Guardrail-Mitigation |
|----|--------------|----------------------|
| FM1 | Untrusted-Metadata Susceptibility | G2 (Untrusted-Input Policy) |
| FM2 | Evidence Deficit / Non-localized Judgement | G1 (Evidence + Location) |
| FM3 | Obfuscation Sensitivity | Policy-basiert (P1/P2/P3) |
| FM4 | Secret Leakage in Output | G3 (Redaction/Never-Echo) |

### Dateipfade

| Datei | Pfad |
|-------|------|
| Datensatz | `data/03_baseline/all_150_samples.json` |
| Claude-Ergebnisse | `data/05_results/hybrid_evaluation_claude.json` |
| GPT-5 Mini-Ergebnisse | `data/05_results/hybrid_eval_gpt5mini_150.json` |
| GPT-4o-Ergebnisse | `data/05_results/hybrid_evaluation_gpt4o.json` |
| detect-secrets-Ergebnisse | `data/05_results/hybrid_evaluation_detect_secrets.json` |
