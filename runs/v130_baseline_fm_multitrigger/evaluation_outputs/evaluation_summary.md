# Evaluation Summary — v130_baseline_fm_multitrigger

Generated from 200 samples.

## Metric Definitions

**Ground Truth**: `gt_has_secret == true` → positive class.

**Three evaluation systems, two views:**

| System | Decision Source |
| --- | --- |
| Scanner | `scanner_hit`: true → BLOCK, false → PASS |
| LLM Baseline | `llm_baseline.final_decision` ∈ {PASS, BLOCK, REVIEW} |
| LLM + Guardrails | `llm_guardrail.final_decision` ∈ {PASS, BLOCK, REVIEW} |

**Alert-Level view**: BLOCK or REVIEW → positive detection (security gating perspective).
**Autonomous-Level view**: only BLOCK → positive detection (no human review needed).

Scanner has no REVIEW concept; both views are identical for Scanner.

## Dataset Composition

| Category | Count |
| --- | --- |
| Positive (gt_has_secret=true) | 150 |
| Negative (gt_has_secret=false) | 50 |
| Total | 200 |

### By Condition

| Condition | Count |
| --- | --- |
| B0 | 150 |
| E3-A | 17 |
| E3-B | 17 |
| E1-B | 8 |
| E2-A | 8 |

### Negative Types

| Type | Count |
| --- | --- |
| NEG_DECOY | 25 |
| NEG_CLEAN | 25 |

## Mode Comparison — Three Systems × Two Views

### Table 2A — Alert-Level Confusion Metrics

| Mode | n_total | n_eval | n_miss | TP | FP | TN | FN | Precision | Recall | F1 | Specificity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 200 | 200 | 0 | 126 | 10 | 40 | 24 | 0.9265 | 0.8400 | 0.8811 | 0.8000 |
| LLM_Baseline | 200 | 200 | 0 | 150 | 24 | 26 | 0 | 0.8621 | 1.0000 | 0.9259 | 0.5200 |
| LLM_Guardrails | 200 | 200 | 0 | 150 | 26 | 24 | 0 | 0.8523 | 1.0000 | 0.9202 | 0.4800 |

### Table 2B — Alert-Level Decision Profile

| Mode | n_total | n_eval | n_miss | Pass Rate | Block Rate | Review Rate | Escape Rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 200 | 200 | 0 | 0.3200 | 0.6800 | 0.0000 | 0.1600 |
| LLM_Baseline | 200 | 200 | 0 | 0.1300 | 0.8250 | 0.0450 | 0.0000 |
| LLM_Guardrails | 200 | 200 | 0 | 0.1200 | 0.4000 | 0.4800 | 0.0000 |

### Table 2C — Autonomous-Level Confusion Metrics

| Mode | n_total | n_eval | n_miss | TP | FP | TN | FN | Precision | Recall | F1 | Specificity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 200 | 200 | 0 | 126 | 10 | 40 | 24 | 0.9265 | 0.8400 | 0.8811 | 0.8000 |
| LLM_Baseline | 200 | 200 | 0 | 144 | 21 | 29 | 6 | 0.8727 | 0.9600 | 0.9143 | 0.5800 |
| LLM_Guardrails | 200 | 200 | 0 | 80 | 0 | 50 | 70 | 1.0000 | 0.5333 | 0.6957 | 1.0000 |

### Table 2D — Alert vs Autonomous Comparison

| Mode | Recall Alert | Recall Auto | Δ Recall | Precision Alert | Precision Auto | Δ Precision | Review Rate | Escape Rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 0.8400 | 0.8400 | 0.0000 | 0.9265 | 0.9265 | 0.0000 | 0.0000 | 0.1600 |
| LLM_Baseline | 1.0000 | 0.9600 | 0.0400 | 0.8621 | 0.8727 | -0.0106 | 0.0450 | 0.0000 |
| LLM_Guardrails | 1.0000 | 0.5333 | 0.4667 | 0.8523 | 1.0000 | -0.1477 | 0.4800 | 0.0000 |

## Step 3 — Decision Profile

Step 3 shows the **operative decision behavior** of each system — how often it outputs PASS, BLOCK, or REVIEW, and how this shifts relative to the Baseline. `escape_rate` appears here intentionally alongside Step 2: in Step 2 it serves as an alert-level safety metric, here it captures the system's tendency to let GT_POS samples pass as an operational behavior signal.

### 3A. Global Decision Profile

| Mode | n_total | n_eval | n_miss | PASS | BLOCK | REVIEW | Pass Rate | Block Rate | Review Rate | Escape Rate | Block Share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 200 | 200 | 0 | 64 | 136 | 0 | 0.3200 | 0.6800 | 0.0000 | 0.1600 | 1.0000 |
| LLM_Baseline | 200 | 200 | 0 | 26 | 165 | 9 | 0.1300 | 0.8250 | 0.0450 | 0.0000 | 0.9483 |
| LLM_Guardrails | 200 | 200 | 0 | 24 | 80 | 96 | 0.1200 | 0.4000 | 0.4800 | 0.0000 | 0.4545 |

### 3B. Decision Counts on GT_POS

| Mode | n_gt_pos_eval | PASS | BLOCK | REVIEW |
| --- | --- | --- | --- | --- |
| Scanner | 150 | 24 | 126 | 0 |
| LLM_Baseline | 150 | 0 | 144 | 6 |
| LLM_Guardrails | 150 | 0 | 80 | 70 |

### 3C. Decision Counts on GT_NEG

| Mode | n_gt_neg_eval | PASS | BLOCK | REVIEW |
| --- | --- | --- | --- | --- |
| Scanner | 50 | 40 | 10 | 0 |
| LLM_Baseline | 50 | 26 | 21 | 3 |
| LLM_Guardrails | 50 | 24 | 0 | 26 |

### 3D. Behavioral Shift vs Baseline

| Comparison | Δ Pass Rate | Δ Block Rate | Δ Review Rate | Δ Escape Rate | Δ Block Share |
| --- | --- | --- | --- | --- | --- |
| Scanner_vs_Baseline | 0.1900 | -0.1450 | -0.0450 | 0.1600 | 0.0517 |
| LLM_Guardrails_vs_Baseline | -0.0100 | -0.4250 | 0.4350 | 0.0000 | -0.4938 |

## Step 4 — Guardrail KPIs

Operational activity of the guardrail bundle. Measures intervention frequency, per-guardrail participation vs routing authority, leakage containment (G3), and fail-closed behavior (G5).

### 4A. Bundle Activity Summary

| Metric | Value |
| --- | --- |
| n_total_guardrail_samples | 200 |
| n_evaluable_guardrail_samples | 200 |
| n_missing_guardrail_samples | 0 |
| samples_with_any_trigger | 168 (0.8400) |
| single_trigger_samples | 103 (0.5150) |
| multi_trigger_samples | 65 (0.3250) |
| max_triggers_on_single_sample | 2 |

### 4B. Per-Guardrail Activity

| Guardrail | Trigger Count | Trigger Rate | Routed Count | Routed Rate |
| --- | --- | --- | --- | --- |
| G5 | 27 | 0.1350 | 27 | 0.1350 |
| G2 | 3 | 0.0150 | 3 | 0.0150 |
| G4 | 62 | 0.3100 | 56 | 0.2800 |
| G1 | 0 | 0.0000 | 0 | 0.0000 |
| G3 | 141 | 0.7050 | 10 | 0.0500 |

### 4C. G3 Leakage KPIs

| Metric | Value |
| --- | --- |
| baseline_leakage | 103 (0.5150) |
| g3_triggered | 141 (0.7050) |
| residual_guardrail_leakage | 0 (0.0000) |
| residual_share_of_baseline_leak | 0.0000 |
| g3_on_gt_pos | 117 (0.7800) |

### 4D. G5 Schema / Fail-Closed KPIs

| Metric | Value |
| --- | --- |
| schema_invalid | 27 (0.1350) |
| g5_routed | 27 (0.1350) |
| g5_fail_closed_review | 27 (0.1350) |
| g5_fail_closed_share_of_g5 | 1.0000 |

### 4E. Trigger Combination Summary

| Combination | Count | Rate |
| --- | --- | --- |
| G3 | 82 | 0.4100 |
| G4+G3 | 56 | 0.2800 |
| G5 | 21 | 0.1050 |
| G5+G4 | 6 | 0.0300 |
| G2+G3 | 3 | 0.0150 |

## Step 5 — Failure-Mode PRI Analysis

Evaluates the guardrail bundle as a control layer via Prevalence (P), Intervention (I), and Residual (R) per failure mode. Rates are conditioned on their respective denominators: prevalence on n_baseline_evaluable, intervention and residual on prevalence_count. Residual is reported only where directly or partially observable — no proxy values are used.

### 5A. PRI Summary per Failure Mode

| FM | Guardrail | n_eval | Prev | Prev Rate | Interv | Interv Rate|Prev | Resid | Resid Rate|Prev | Observability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FM1_evidence_location | G1 | 190 | 16 | 0.0842 | 0 | 0.0000 | 0 | 0.0000 | partial |
| FM2_untrusted_input | G2 | 190 | 0 | 0.0000 | — | n/a | — | n/a | n/a |
| FM3_secret_leakage | G3 | 190 | 103 | 0.5421 | 89 | 0.8641 | 0 | 0.0000 | direct |
| FM4_uncertainty_miscalibration | G4 | 190 | 52 | 0.2737 | 48 | 0.9231 | 43 | 0.8269 | partial |
| FM5_schema_output_failure | G5 | 200 | 27 | 0.1350 | 27 | 1.0000 | — | n/a | not_robustly_observable |

### 5B. PRI Definitions

| FM | Guardrail | Prevalence Field Logic | Intervention Field Logic | Residual Field Logic | Notes |
| --- | --- | --- | --- | --- | --- |
| FM1_evidence_location | G1 | baseline_failure_modes.g1_valid == false | G1 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G1 | llm_guardrail.g1_valid == false (on prevalence cases) | Residual observed via guardrail-side g1_valid flag, which is structurally analogous but not identical to the baseline g1_valid check. Interpretation should account for this structural difference. |
| FM2_untrusted_input | G2 | baseline_failure_modes.g2_valid == false | G2 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G2 | Not robustly observable. Guardrail-side g2_valid exists but lacks independent validation of FM2 resolution. | Residual not reported: guardrail-side g2_valid is structurally available but does not constitute a robust independent measure of whether untrusted-input influence was resolved. Additionally, zero prevalence in this dataset means PRI is structurally not evaluable for FM2. |
| FM3_secret_leakage | G3 | metrics.leak_in_baseline == true | llm_guardrail.g3_triggered == true | metrics.leak_in_guardrail == true (on prevalence cases) | All three PRI components are directly and independently observable via separate fields. Leakage detection is based on gt_secret_value string matching in model output. |
| FM4_uncertainty_miscalibration | G4 | baseline_failure_modes.g4_details.should_review == true | G4 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G4 | llm_guardrail.g4_details.should_review == true (on prevalence cases) | Residual is indicative, not definitive. The guardrail-side should_review flag measures structural presence of miscalibration indicators, not whether the bundle's routing action resolved the operational impact. Unlike FM3, there is no independent objective measure of FM4 resolution. |
| FM5_schema_output_failure | G5 | llm_guardrail.schema_valid == false (asymmetric: guardrail-side, not baseline-side) | G5 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G5 | Not robustly observable. No independent post-intervention field measures whether the schema failure persists as a problematic end state after G5 treatment. | Asymmetric operationalization: FM5 prevalence is observed on the guardrail/structured-output side only. The baseline does not undergo schema validation. Residual is not reported because absence of G5 routing does not robustly indicate a persisting problematic end state. |

### 5C. PRI Coverage / Observability

| FM | Guardrail | n_eval | Prev n | Resid Observability | Multi-FM Note | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FM1_evidence_location | G1 | 190 | 16 | partial | Multiple guardrails may act on the same sample. Observed FM1 residual may reflect bundle-wide output quality rather than G1-specific correction. | Residual based on guardrail-side g1_valid, which is structurally analogous but not identical to the baseline validity check. G1 did not trigger in this dataset; observed residual=0 may reflect overall guardrail output quality rather than targeted G1 intervention. |
| FM2_untrusted_input | G2 | 190 | 0 | not_robustly_observable | Zero prevalence in this dataset. PRI not structurally evaluable. | No baseline samples exhibited g2_valid=false. Residual not reported: guardrail-side g2_valid lacks independent validation of FM2 resolution. |
| FM3_secret_leakage | G3 | 190 | 103 | direct | G3 leakage detection operates independently of other guardrails via gt_secret_value string matching. | All three PRI components observed via independent fields. No structural cross-dependency with other guardrails. |
| FM4_uncertainty_miscalibration | G4 | 190 | 52 | partial | Potential overlap with G1 in ambiguity-heavy contexts. Multiple guardrails may act on the same sample; intervention attribution not always exclusive to G4. | Residual is indicative only. Guardrail-side should_review measures structural miscalibration presence, not whether routing resolved the operational impact. No independent objective measure of FM4 resolution available. |
| FM5_schema_output_failure | G5 | 200 | 27 | not_robustly_observable | G5 operates first in pipeline (G5 → G2 → G4 → G1 → G3). No structural overlap with other guardrails for schema failures. | Asymmetric operationalization: prevalence observed on guardrail output side only. Residual not reported: no independent post-intervention field to assess whether schema failure persists as a problematic end state. |

## Step 6 — Slice Analysis (Supplementary)

Segments the main findings from Steps 2, 3, and 5 by dataset slices. This is a **supplementary analysis layer** — the authoritative results are reported in Steps 2–5.

### 6A. Slice Performance Summary

| Slice | n | Mode | n_eval | Rec Alert | Prec Alert | Rec Auto | Prec Auto | Esc Rate | Review % | Block % | Pass % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base | 150 | Scanner | 150 | 0.9700 | 0.9065 | 0.9700 | 0.9065 | 0.0300 | 0.0000 | 0.7133 | 0.2867 |
| base | 150 | LLM_Baseline | 150 | 1.0000 | 0.8065 | 1.0000 | 0.8264 | 0.0000 | 0.0200 | 0.8067 | 0.1733 |
| base | 150 | LLM_Guardrails | 150 | 1.0000 | 0.7937 | 0.7200 | 1.0000 | 0.0000 | 0.3600 | 0.4800 | 0.1600 |
| stress | 50 | Scanner | 50 | 0.5800 | 1.0000 | 0.5800 | 1.0000 | 0.4200 | 0.0000 | 0.5800 | 0.4200 |
| stress | 50 | LLM_Baseline | 50 | 1.0000 | 1.0000 | 0.8800 | 1.0000 | 0.0000 | 0.1200 | 0.8800 | 0.0000 |
| stress | 50 | LLM_Guardrails | 50 | 1.0000 | 1.0000 | 0.1600 | 1.0000 | 0.0000 | 0.8400 | 0.1600 | 0.0000 |
| neg_clean | 25 | Scanner | 25 | n/a | n/a | n/a | n/a | n/a | 0.0000 | 0.0000 | 1.0000 |
| neg_clean | 25 | LLM_Baseline | 25 | n/a | 0.0000 | n/a | 0.0000 | n/a | 0.0000 | 0.0400 | 0.9600 |
| neg_clean | 25 | LLM_Guardrails | 25 | n/a | 0.0000 | n/a | n/a | n/a | 0.0400 | 0.0000 | 0.9600 |
| neg_decoy | 25 | Scanner | 25 | n/a | 0.0000 | n/a | 0.0000 | n/a | 0.0000 | 0.4000 | 0.6000 |
| neg_decoy | 25 | LLM_Baseline | 25 | n/a | 0.0000 | n/a | 0.0000 | n/a | 0.1200 | 0.8000 | 0.0800 |
| neg_decoy | 25 | LLM_Guardrails | 25 | n/a | 0.0000 | n/a | n/a | n/a | 1.0000 | 0.0000 | 0.0000 |
| real | 75 | Scanner | 75 | 0.8000 | 1.0000 | 0.8000 | 1.0000 | 0.2000 | 0.0000 | 0.8000 | 0.2000 |
| real | 75 | LLM_Baseline | 75 | 1.0000 | 1.0000 | 0.9333 | 1.0000 | 0.0000 | 0.0667 | 0.9333 | 0.0000 |
| real | 75 | LLM_Guardrails | 75 | 1.0000 | 1.0000 | 0.6800 | 1.0000 | 0.0000 | 0.3200 | 0.6800 | 0.0000 |
| synthetic | 75 | Scanner | 75 | 0.8800 | 1.0000 | 0.8800 | 1.0000 | 0.1200 | 0.0000 | 0.8800 | 0.1200 |
| synthetic | 75 | LLM_Baseline | 75 | 1.0000 | 1.0000 | 0.9867 | 1.0000 | 0.0000 | 0.0133 | 0.9867 | 0.0000 |
| synthetic | 75 | LLM_Guardrails | 75 | 1.0000 | 1.0000 | 0.3867 | 1.0000 | 0.0000 | 0.6133 | 0.3867 | 0.0000 |

*Coverage notes: `real` + `synthetic` covers positive samples only (NEG\_ controls excluded). `neg_clean` + `neg_decoy` are control-specific subgroups, not an exhaustive partition of all GT-negative cases.*

*Slices with n < 10 (stress_untrusted_input, stress_uncertainty) should be interpreted with caution.*


<details><summary>Stress subtype breakdown (click to expand)</summary>

| Slice | n | Mode | n_eval | Rec Alert | Prec Alert | Rec Auto | Prec Auto | Esc Rate | Review % | Block % | Pass % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| stress_untrusted_input | 8 | Scanner | 8 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_untrusted_input | 8 | LLM_Baseline | 8 | 1.0000 | 1.0000 | 0.8750 | 1.0000 | 0.0000 | 0.1250 | 0.8750 | 0.0000 |
| stress_untrusted_input | 8 | LLM_Guardrails | 8 | 1.0000 | 1.0000 | 0.0000 | n/a | 0.0000 | 1.0000 | 0.0000 | 0.0000 |
| stress_uncertainty | 8 | Scanner | 8 | 0.3750 | 1.0000 | 0.3750 | 1.0000 | 0.6250 | 0.0000 | 0.3750 | 0.6250 |
| stress_uncertainty | 8 | LLM_Baseline | 8 | 1.0000 | 1.0000 | 0.5000 | 1.0000 | 0.0000 | 0.5000 | 0.5000 | 0.0000 |
| stress_uncertainty | 8 | LLM_Guardrails | 8 | 1.0000 | 1.0000 | 0.0000 | n/a | 0.0000 | 1.0000 | 0.0000 | 0.0000 |
| stress_multi_fm | 17 | Scanner | 17 | 0.2353 | 1.0000 | 0.2353 | 1.0000 | 0.7647 | 0.0000 | 0.2353 | 0.7647 |
| stress_multi_fm | 17 | LLM_Baseline | 17 | 1.0000 | 1.0000 | 0.9412 | 1.0000 | 0.0000 | 0.0588 | 0.9412 | 0.0000 |
| stress_multi_fm | 17 | LLM_Guardrails | 17 | 1.0000 | 1.0000 | 0.0000 | n/a | 0.0000 | 1.0000 | 0.0000 | 0.0000 |
| stress_hardened | 17 | Scanner | 17 | 0.8235 | 1.0000 | 0.8235 | 1.0000 | 0.1765 | 0.0000 | 0.8235 | 0.1765 |
| stress_hardened | 17 | LLM_Baseline | 17 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_hardened | 17 | LLM_Guardrails | 17 | 1.0000 | 1.0000 | 0.4706 | 1.0000 | 0.0000 | 0.5294 | 0.4706 | 0.0000 |

</details>


### 6B. Slice PRI Spotlight

FM3 (secret leakage) and FM4 (uncertainty miscalibration) PRI rates per slice. Rates conditioned on respective denominators as in Step 5.

*FM4 values are indicative only. They are based on partially observable uncertainty/should-review indicators and are not comparable in directness to FM3 leakage measurements (see Step 5 for observability details).*

| Slice | n | FM3 Prev | FM3 Prev Rate | FM3 Interv|Prev | FM3 Resid|Prev | FM4 Prev | FM4 Prev Rate | FM4 Interv|Prev |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base | 150 | 90 | 0.6207 | 0.8556 | 0.0000 | 34 | 0.2345 | 0.9412 |
| stress | 50 | 13 | 0.2889 | 0.9231 | 0.0000 | 18 | 0.4000 | 0.8889 |
| neg_clean | 25 | 0 | 0.0000 | n/a | n/a | 1 | 0.0400 | 1.0000 |
| neg_decoy | 25 | 0 | 0.0000 | n/a | n/a | 25 | 1.0000 | 0.9600 |
| real | 75 | 52 | 0.7429 | 0.8846 | 0.0000 | 8 | 0.1143 | 0.7500 |
| synthetic | 75 | 51 | 0.7286 | 0.8431 | 0.0000 | 18 | 0.2571 | 0.9444 |
| stress_untrusted_input | 8 | 8 | 1.0000 | 1.0000 | 0.0000 | 8 | 1.0000 | 0.8750 |
| stress_uncertainty | 8 | 2 | 0.2500 | 1.0000 | 0.0000 | 4 | 0.5000 | 1.0000 |
| stress_multi_fm | 17 | 3 | 0.2500 | 0.6667 | 0.0000 | 4 | 0.3333 | 1.0000 |
| stress_hardened | 17 | 0 | 0.0000 | n/a | n/a | 2 | 0.1176 | 0.5000 |

### 6C. Slice Definitions

| Slice | Definition | Notes |
| --- | --- | --- |
| base | condition == B0 | Baseline dataset: standard positive and negative samples. |
| stress | condition starts with E (E1-B, E2-A, E3-A, E3-B) | All stress/perturbation samples. All are GT positive. |
| neg_clean | control_type == no_secret | Control-specific negative subgroup. Not intended as exhaustive partition of all GT-negative cases. |
| neg_decoy | control_type == decoy | Control-specific negative subgroup (decoy/misleading patterns). Not intended as exhaustive partition of all GT-negative cases. |
| real | sample_id starts with REAL | Samples derived from real-world code repositories. Does not cover NEG_* control samples — real + synthetic is not a full partition of the dataset. |
| synthetic | sample_id starts with SYNTH | Synthetically generated samples. Does not cover NEG_* control samples — real + synthetic is not a full partition of the dataset. |
| stress_untrusted_input | condition == E1-B | Stress samples targeting FM2 (untrusted-input influence). |
| stress_uncertainty | condition == E2-A | Stress samples targeting FM4 (uncertainty/miscalibration). |
| stress_multi_fm | condition == E3-A | Multi-FM stress (FM6/general, FM1/FM3/FM5 targeted). |
| stress_hardened | condition == E3-B | Hardened positive samples with obfuscation patterns. |

## Policy Metrics

| Policy | Variant | View | TP | FP | TN | FN | Precision | Recall | F1 | Escape Rate | Reviewer Load |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| p1 | baseline | alert | 145 | 24 | 26 | 0 | 0.8580 | 1.0000 | 0.9236 | 0.0000 | 0.0450 |
| p1 | baseline | autonomous | 139 | 21 | 29 | 6 | 0.8688 | 0.9586 | 0.9115 | 0.0000 | 0.0450 |
| p1 | guardrail | alert | 150 | 26 | 24 | 0 | 0.8523 | 1.0000 | 0.9202 | 0.0000 | 0.4800 |
| p1 | guardrail | autonomous | 80 | 0 | 50 | 70 | 1.0000 | 0.5333 | 0.6957 | 0.0000 | 0.4800 |
| p2 | baseline | alert | 145 | 24 | 26 | 0 | 0.8580 | 1.0000 | 0.9236 | 0.0000 | 0.1850 |
| p2 | baseline | autonomous | 122 | 10 | 40 | 23 | 0.9242 | 0.8414 | 0.8809 | 0.0000 | 0.1850 |
| p2 | guardrail | alert | 150 | 26 | 24 | 0 | 0.8523 | 1.0000 | 0.9202 | 0.0000 | 0.5050 |
| p2 | guardrail | autonomous | 75 | 0 | 50 | 75 | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 0.5050 |
| p3 | baseline | alert | 135 | 16 | 34 | 10 | 0.8940 | 0.9310 | 0.9122 | 0.0667 | 0.0350 |
| p3 | baseline | autonomous | 129 | 15 | 35 | 16 | 0.8958 | 0.8897 | 0.8927 | 0.0667 | 0.0350 |
| p3 | guardrail | alert | 138 | 16 | 34 | 12 | 0.8961 | 0.9200 | 0.9079 | 0.0800 | 0.3650 |
| p3 | guardrail | autonomous | 81 | 0 | 50 | 69 | 1.0000 | 0.5400 | 0.7013 | 0.0800 | 0.3650 |

## Supplementary — Slice Metrics

Segmented analysis across dataset dimensions. Complements the system-level results from Steps 2 and 3.

### Recall by Condition (LLM + Guardrails, Alert-Level)

| Condition | n | TP | FN | Recall | Precision | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| B0 | 150 | 100 | 0 | 1.0000 | 0.7937 | 0.8850 |
| E1-B | 8 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E2-A | 8 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E3-A | 17 | 17 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E3-B | 17 | 17 | 0 | 1.0000 | 1.0000 | 1.0000 |

### False Positives by Negative Type (all systems)

| Neg Type | Mode | n | FP | TN | Specificity |
| --- | --- | --- | --- | --- | --- |
| NEG_CLEAN | Guardrails_Alert | 25 | 1 | 24 | 0.9600 |
| NEG_CLEAN | Guardrails_Autonomous | 25 | 0 | 25 | 1.0000 |
| NEG_CLEAN | LLM_Baseline | 25 | 1 | 24 | 0.9600 |
| NEG_CLEAN | Scanner | 25 | 0 | 25 | 1.0000 |
| NEG_DECOY | Guardrails_Alert | 25 | 25 | 0 | 0.0000 |
| NEG_DECOY | Guardrails_Autonomous | 25 | 0 | 25 | 1.0000 |
| NEG_DECOY | LLM_Baseline | 25 | 23 | 2 | 0.0800 |
| NEG_DECOY | Scanner | 25 | 10 | 15 | 0.6000 |

### Scanner — Recall by Condition

| Condition | n | TP | FN | Recall |
| --- | --- | --- | --- | --- |
| B0 | 150 | 97 | 3 | 0.9700 |
| E1-B | 8 | 8 | 0 | 1.0000 |
| E2-A | 8 | 3 | 5 | 0.3750 |
| E3-A | 17 | 4 | 13 | 0.2353 |
| E3-B | 17 | 14 | 3 | 0.8235 |

## Appendix — Legacy Mode Comparison (hit-level predicates)

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Specificity | Skipped |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 126 | 10 | 40 | 24 | 0.9265 | 0.8400 | 0.8811 | 0.8000 | 0 |
| LLM_Baseline | 150 | 24 | 26 | 0 | 0.8621 | 1.0000 | 0.9259 | 0.5200 | 0 |
| Guardrails_Alert | 150 | 26 | 24 | 0 | 0.8523 | 1.0000 | 0.9202 | 0.4800 | 0 |
| Guardrails_Autonomous | 80 | 0 | 50 | 70 | 1.0000 | 0.5333 | 0.6957 | 1.0000 | 0 |

### Decision Distributions

**Scanner:** BLOCK=136, REVIEW=0, PASS=64, None=0
**LLM_Baseline:** BLOCK=165, REVIEW=9, PASS=26, None=0
**Guardrails_Alert:** BLOCK=80, REVIEW=96, PASS=24, None=0
**Guardrails_Autonomous:** BLOCK=80, REVIEW=96, PASS=24, None=0

## Appendix — Legacy Guardrail KPI Details

### Routing Summary

| Routed By | Count |
| --- | --- |
| None | 104 |
| G4 | 56 |
| G5 | 27 |
| G3 | 10 |
| G2 | 3 |

### G1

- **trigger_count:** 0
- **trigger_rate:** 0.0
- **routed_count:** 0
- **g1_valid_false_count:** 0
- **issue_breakdown:**

### G2

- **trigger_count:** 5
- **trigger_rate:** 0.025
- **routed_count:** 3
- **g2_valid_false_count:** 3
- **issue_breakdown:**
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example, not real) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_EXCULPATORY: untrusted_effect='exculpatory_claim' (role=pr_body) — untrusted input must not exculpate findings: 3
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example) in pr_title, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1

### G3

- **g3_initial_leak_count:** 10
- **g3_post_mitigation_leak_count:** 0
- **leak_escape_rate_total:** 0.0
- **leak_escape_rate_of_detected:** 0.0
- **routed_count:** 10
- **g3_valid_false_count:** 10

### G4

- **escalation_count:** 56
- **escalation_rate:** 0.28
- **routed_count:** 56
- **rule_breakdown:**
  - R1_ambiguous_context: 23
  - R4_exculpatory_escalation: 17
  - R2_reconstructed_plus_ambiguity: 9
  - R3_scanner_neg_llm_pos_context: 7
- **flag_breakdown:**
  - comment_claims_dummy: 46
  - placeholder_or_example_context: 43
  - test_or_docs_context: 30
  - scanner_disagreement: 21
  - decoy_like_pattern: 13
  - evidence_span_not_single_line: 12
  - reconstructed_secret: 10
  - split_across_variables: 10
  - low_specificity_literal: 6
  - g2_unreported_influence: 2
- **on_positive:** 33
- **on_negative:** 23

### G5

- **trigger_count:** 27
- **trigger_rate:** 0.135
- **routed_count:** 27
- **schema_fail_count:** 27
- **schema_fail_rate:** 0.135
- **error_category_breakdown:**
  - PARSE_ERROR: 27
- **repair_success_count:** 0
- **repair_fail_count:** 0
- **note_repair:** repair_success_rate is None when no REPAIR_SUCCESS/REPAIR_FAIL categories are present in results

### Multi-Trigger Summary

- **samples_with_any_trigger_count:** 168
- **single_trigger_samples_count:** 103
- **multi_trigger_samples_count:** 65
- **multi_trigger_rate:** 0.325
- **max_triggers_on_single_sample:** 2

**Per-Guardrail Trigger Count (from triggered_guardrails):**

| Guardrail | Trigger Count |
| --- | --- |
| G5 | 27 |
| G2 | 3 |
| G4 | 62 |
| G1 | 0 |
| G3 | 141 |

**Trigger Combination Breakdown:**

| Combination | Count |
| --- | --- |
| G3 | 82 |
| G4+G3 | 56 |
| G5 | 21 |
| G5+G4 | 6 |
| G2+G3 | 3 |

## Data Availability Notes

- `context_family`: not present on all samples (NEG samples lack it)
- `failure_mode_target`: only present on stress/extreme samples
- `is_extreme_case`: only present on stress samples
- `llm_baseline`: may be None for individual samples (API failure)
- G5 `repair_success_rate`: only computable when REPAIR_SUCCESS/REPAIR_FAIL error categories are present in results

