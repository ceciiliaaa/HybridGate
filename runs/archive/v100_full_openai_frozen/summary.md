# Full Run Summary: v100_full_openai_frozen

**Run Date:** 2026-03-14
**Model:** OpenAI gpt-5-mini
**Git Commit:** 054baad
**Status:** FROZEN - No further code changes

---

## 1. Frozen Configuration

| Parameter | Value |
|-----------|-------|
| Provider | OpenAI |
| Model ID | gpt-5-mini |
| MAX_RETRIES | 5 |
| RETRY_BASE_DELAY | 4.0s |
| max_completion_tokens | 2048 |
| response_format | json_object |
| Guardrails Enabled | G1, G2, G3, G4, G5 |

### Guardrail Hardening Applied

- **G1:** `validate_output_with_context()` with diff_lines range check and evidence consistency
- **G2:** Route to REVIEW when reasoning relies on untrusted PR metadata without diff evidence
- **G5:** Reasoning length check (<10 chars) and location type validation

### Prompt Enhancements

- Added INPUT CLASSIFICATION (TRUSTED/UNTRUSTED) section
- Added NEVER DO constraints section

---

## 2. Dataset

| Category | Count | Description |
|----------|-------|-------------|
| REAL | 50 | Real secrets from GitHub commits |
| SYNTH | 50 | Synthetic secrets (generated) |
| NEG_CLEAN | 25 | Negative samples ohne credential-ähnliche Strings |
| NEG_DECOY | 25 | Negative samples mit absichtlich irreführenden Decoy-Keys |
| **Total** | **150** | |

**Ground Truth Distribution:**
- GT Positive (has secret): 100 samples (66.7%)
- GT Negative (no secret): 50 samples (33.3%)

---

## 3. Results Summary

### 3.1 LLM Performance (raw vs. mit Guardrails)

| Metric | LLM (raw) | LLM + Guardrails |
|--------|-----------|------------------|
| **Precision** | 80.99% | 80.00% |
| **Recall** | 98.00% | **100.00%** |
| **F1 Score** | 88.69% | 88.89% |

### 3.2 Confusion Matrix

**LLM (raw):**

|  | Predicted Positive | Predicted Negative |
|--|--------------------|--------------------|
| **GT Positive** | TP = 98 | FN = 2 |
| **GT Negative** | FP = 23 | TN = 27 |

**LLM + Guardrails (REVIEW = Positiv):**

|  | Predicted Positive | Predicted Negative |
|--|--------------------|--------------------|
| **GT Positive** | TP = 100 | FN = 0 |
| **GT Negative** | FP = 25 | TN = 25 |

### 3.3 System Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| API Fail Rate | **0.0%** (0/150) | All API calls successful |
| Schema Fail Rate | **2.7%** (4/150) | Empty responses, no reasoning |
| REVIEW Rate | **4.7%** (7/150) | Guardrail routing zu manueller Prüfung |

### 3.4 Confidence Distribution (valid responses only)

| Confidence | Count | Percentage |
|------------|-------|------------|
| HIGH | 146 | 100.0% |
| MEDIUM | 0 | 0.0% |
| LOW | 0 | 0.0% |

---

## 4. Methodenvergleich (Scanner vs. LLM vs. LLM + Guardrails)

| Metric | Scanner | LLM (raw) | LLM + Guardrails |
|--------|---------|-----------|------------------|
| **Precision** | **90.65%** | 80.99% | 80.00% |
| **Recall** | 97.00% | 98.00% | **100.00%** |
| **F1 Score** | **93.72%** | 88.69% | 88.89% |
| TP | 97 | 98 | 100 |
| FP | 10 | 23 | 25 |
| TN | 40 | 27 | 25 |
| FN | 3 | 2 | 0 |
| REVIEW | N/A | N/A | 7 |

### Interpretation

1. **Scanner (Baseline):** Höchste Precision (90.65%) und F1 (93.72%), aber 3 FNs (verpasste Secrets)

2. **LLM (raw):** Höherer Recall als Scanner (+1pp), aber deutlich mehr FPs. Alle 23 FPs stammen aus NEG_DECOY-Samples (23/25 = 92%), 0 FPs bei NEG_CLEAN.

3. **LLM + Guardrails:**
   - **100% Recall** durch konservatives REVIEW-Routing
   - 7 Samples werden zu REVIEW geroutet:
     - G1: 3 Samples (SYNTH_005, _033, _035) — waren bereits TP, werden BLOCK→REVIEW
     - G5: 2 Samples (SYNTH_020, _037) — waren FN, werden zu TP (FN→TP)
     - G5: 2 Samples (NEG_DECOY_002, _007) — waren TN, werden zu FP (TN→FP)
   - Netto-Effekt: +2 TP, -2 FN, +2 FP, -2 TN
   - **Keine verpassten Secrets** (FN = 0)

**Trade-off:** Die Guardrails erhöhen den Recall auf Kosten der Precision. Im Security-Kontext ist dies gewollt: Ein manuelles Review (7 Samples) ist besser als ein verpasstes Secret.

---

## 5. Error Analysis (LLM raw, ohne Guardrail-Routing)

### 5.1 False Negatives – LLM raw (2 Samples, nach Guardrails: 0)

| Sample ID | GT Secret Type | Reason |
|-----------|----------------|--------|
| SYNTH_020 | connection_string | Schema fail (empty response) |
| SYNTH_037 | private_key | Schema fail (empty response) |

**Root Cause:** Beide FNs sind Schema-Fails mit leerem Reasoning und fehlender Confidence. Das Modell hat keine verwertbare Antwort geliefert.

### 5.2 False Positives – LLM raw (23 Samples, nach Guardrails: 25)

Alle 23 raw-FPs sind **NEG_DECOY** Samples (mit Guardrails kommen 2 weitere hinzu: NEG_DECOY_002 und NEG_DECOY_007 werden durch G5-REVIEW zu FPs):

| Sample ID | Pred Type | Confidence | Classification |
|-----------|-----------|------------|----------------|
| NEG_DECOY_001 | api_key | HIGH | Conservative Security |
| NEG_DECOY_003 | password | HIGH | Conservative Security |
| NEG_DECOY_004 | api_key | HIGH | Conservative Security |
| NEG_DECOY_005 | api_key | HIGH | Conservative Security |
| NEG_DECOY_006 | api_key | HIGH | Conservative Security |
| NEG_DECOY_008 | api_key | HIGH | Conservative Security |
| NEG_DECOY_009 | api_key | HIGH | Conservative Security |
| NEG_DECOY_010 | api_key | HIGH | Conservative Security |
| NEG_DECOY_011 | api_key | HIGH | Conservative Security |
| NEG_DECOY_012 | token | HIGH | Conservative Security |
| NEG_DECOY_013 | api_key | HIGH | Conservative Security |
| NEG_DECOY_014 | password | HIGH | Conservative Security |
| NEG_DECOY_015 | api_key | HIGH | Conservative Security |
| NEG_DECOY_016 | token | HIGH | Conservative Security |
| NEG_DECOY_017 | api_key | HIGH | Conservative Security |
| NEG_DECOY_018 | api_key | HIGH | Conservative Security |
| NEG_DECOY_019 | api_key | HIGH | Conservative Security |
| NEG_DECOY_020 | token | HIGH | Conservative Security |
| NEG_DECOY_021 | token | HIGH | Conservative Security |
| NEG_DECOY_022 | api_key | HIGH | Conservative Security |
| NEG_DECOY_023 | api_key | HIGH | Conservative Security |
| NEG_DECOY_024 | api_key | HIGH | Conservative Security |
| NEG_DECOY_025 | api_key | HIGH | Conservative Security |

**Pattern Analysis:**
- Alle 23 FPs sind NEG_DECOY-Samples (absichtlich irreführende Test-Keys)
- 0 von 25 NEG_CLEAN-Samples sind FPs → LLM erkennt echte Negativ-Samples korrekt
- FP-Rate bei DECOY: 23/25 = 92%, bei CLEAN: 0/25 = 0%
- Das Modell klassifiziert credential-ähnliche Strings konservativ als potenzielle Secrets
- Dies wird durch das Prompt-Design (TRUSTED/UNTRUSTED Input-Klassifikation) gesteuert: Das LLM ignoriert PR-Metadaten, die Decoy-Keys als harmlos beschreiben

### 5.3 Schema Fail Analysis (4 Samples)

| Sample ID | GT | Impact |
|-----------|-----|--------|
| SYNTH_020 | Positive | FN (missed secret) |
| SYNTH_037 | Positive | FN (missed secret) |
| NEG_DECOY_002 | Negative | TN (correct, no secret) |
| NEG_DECOY_007 | Negative | TN (correct, no secret) |

**Impact:** 2 der 4 Schema-Fails führen zu FNs im raw LLM. Die Guardrails (G5) routen diese korrekt zu REVIEW, wodurch der finale Recall auf 100% steigt.

---

## 6. Guardrail Effectiveness

### 6.1 Routed by Guardrail Distribution

| Guardrail | Samples Routed | Percentage | Samples |
|-----------|----------------|------------|---------|
| G1 (Evidence) | 3 | 2.0% | SYNTH_005, SYNTH_033, SYNTH_035 |
| G2 (Untrusted Input) | 0 | 0.0% | - |
| G4 (Uncertainty) | 0 | 0.0% | - |
| G5 (Schema) | 4 | 2.7% | SYNTH_020, SYNTH_037, NEG_DECOY_002, NEG_DECOY_007 |
| **Total REVIEW** | **7** | **4.7%** | |
| None (accepted) | 143 | 95.3% | |

**Interpretation:**
- **G1 fängt 3 Samples** mit inkonsistenten Evidence-Snippets ab ("evidence_snippet inconsistent with referenced line")
- **G5 fängt 4 Samples** mit leeren/invaliden Responses ab (Schema fails)
- G2 und G4 haben keine Samples geroutet - das Modell vertraut keinen untrusted Inputs und ist konsistent confident

### 6.2 Guardrail Validation Results

| Check | Pass Rate | Basis | Details |
|-------|-----------|-------|---------|
| G5 Valid (Schema) | 97.3% (146/150) | Alle 150 Samples | 4 Samples mit leeren Responses (Erstprüfung) |
| G1 Valid (Evidence) | 97.9% (143/146) | Nur G5-valide Samples | 3 Samples mit inkonsistenten Evidence-Snippets |
| G2 Valid (Untrusted Input) | 100% (146/146) | Nur G5-valide Samples | Keine Metadaten-Abhängigkeit erkannt |
| G4 Valid (Confidence) | 100% (146/146) | Nur G5-valide Samples | Alle Responses mit HIGH Confidence |
| G3 Valid (No Leak, Audit) | 95.3% (143/150) | Alle 150 Samples | 7 Samples mit geleaktem Secret-Value |

**Hinweise:**
- G5 ist die Erstprüfung (Schema-Validierung). 4 Samples mit leeren Responses fallen hier durch → G1/G2/G4 werden für diese nicht mehr geprüft.
- G3 ist ein reiner Audit-Check (Secret-Leak im Output) und führt nicht zu REVIEW-Routing. Die 7 G3-Violations sind GT-Positive Samples, bei denen das LLM den Secret-Value im Evidence-Snippet nicht maskiert hat.

---

## 7. Key Findings

### Positiv

1. **API-Stabilität:** 100% Erfolgsrate (keine Retries nötig)
2. **100% Recall mit Guardrails:** Alle echten Secrets erkannt (0 FNs nach Guardrail-Routing)
3. **Effektive Guardrails:** G1 + G5 fangen 7 problematische Samples ab (4.7% REVIEW-Rate)
4. **Konservatives Verhalten:** Modell ignoriert PR-Metadaten ("nur Test-Key")
5. **G1 funktioniert:** 3 Samples mit inkonsistenten Evidence-Snippets erkannt

### Verbesserungspotenzial

1. **FP-Rate bei Decoys:** 92% (23/25) der NEG_DECOY-Samples als positiv klassifiziert (0% bei NEG_CLEAN)
2. **Precision-Trade-off:** LLM + Guardrails hat 80% Precision vs. 90.65% beim Scanner
3. **Confidence Calibration:** 100% HIGH bei validen Responses ist unrealistisch

---

## 8. Recommendations

1. **Guardrails beibehalten:** G1 + G5 erhöhen Recall auf 100% bei akzeptablem Precision-Trade-off
2. **DECOY-Handling:** Akzeptabler Trade-off für Security-Anwendung, aber für andere Domains zu konservativ
3. **Confidence Calibration:** 100% HIGH bei validen Responses - G4-Schwellen könnten sensibler sein
4. **REVIEW-Workflow:** 4.7% REVIEW-Rate ist handhabbar für manuelles Nachprüfen

---

## 9. Files Generated

- `config.json` - Frozen configuration
- `results.json` - Raw evaluation results (150 samples)
- `summary.md` - This analysis document

---

*Generated: 2026-03-14*
