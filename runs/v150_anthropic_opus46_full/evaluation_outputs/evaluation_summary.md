# Evaluation Summary — unknown

Generated from 250 samples.

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
| Positive (gt_has_secret=true) | 200 |
| Negative (gt_has_secret=false) | 50 |
| Total | 250 |

### By Condition

| Condition | Count |
| --- | --- |
| B0 | 150 |
| E4-I | 24 |
| E3-A | 18 |
| E3-B | 17 |
| E4-H | 9 |
| E1-B | 8 |
| E2-A | 8 |
| E4-F | 8 |
| E4-G | 8 |

### Negative Types

| Type | Count |
| --- | --- |
| NEG_DECOY | 25 |
| NEG_CLEAN | 25 |

## Mode Comparison — Three Systems × Two Views

### Table 2A — Alert-Level Confusion Metrics

| Mode | n_total | n_eval | n_miss | TP | FP | TN | FN | Precision | Recall | F1 | Specificity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 250 | 250 | 0 | 137 | 10 | 40 | 63 | 0.9320 | 0.6850 | 0.7896 | 0.8000 |
| LLM_Baseline | 250 | 250 | 0 | 167 | 3 | 47 | 33 | 0.9824 | 0.8350 | 0.9027 | 0.9400 |
| LLM_Guardrails | 250 | 250 | 0 | 199 | 26 | 24 | 1 | 0.8844 | 0.9950 | 0.9365 | 0.4800 |

### Table 2B — Alert-Level Decision Profile

| Mode | n_total | n_eval | n_miss | Pass Rate | Block Rate | Review Rate | Escape Rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 250 | 250 | 0 | 0.4120 | 0.5880 | 0.0000 | 0.3150 |
| LLM_Baseline | 250 | 250 | 0 | 0.3200 | 0.6800 | 0.0000 | 0.1650 |
| LLM_Guardrails | 250 | 250 | 0 | 0.1000 | 0.6000 | 0.3000 | 0.0050 |

### Table 2C — Autonomous-Level Confusion Metrics

| Mode | n_total | n_eval | n_miss | TP | FP | TN | FN | Precision | Recall | F1 | Specificity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 250 | 250 | 0 | 137 | 10 | 40 | 63 | 0.9320 | 0.6850 | 0.7896 | 0.8000 |
| LLM_Baseline | 250 | 250 | 0 | 167 | 3 | 47 | 33 | 0.9824 | 0.8350 | 0.9027 | 0.9400 |
| LLM_Guardrails | 250 | 250 | 0 | 145 | 5 | 45 | 55 | 0.9667 | 0.7250 | 0.8286 | 0.9000 |

### Table 2D — Alert vs Autonomous Comparison

| Mode | Recall Alert | Recall Auto | Δ Recall | Precision Alert | Precision Auto | Δ Precision | Review Rate | Escape Rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 0.6850 | 0.6850 | 0.0000 | 0.9320 | 0.9320 | 0.0000 | 0.0000 | 0.3150 |
| LLM_Baseline | 0.8350 | 0.8350 | 0.0000 | 0.9824 | 0.9824 | 0.0000 | 0.0000 | 0.1650 |
| LLM_Guardrails | 0.9950 | 0.7250 | 0.2700 | 0.8844 | 0.9667 | -0.0823 | 0.3000 | 0.0050 |

## Step 3 — Decision Profile

Step 3 shows the **operative decision behavior** of each system — how often it outputs PASS, BLOCK, or REVIEW, and how this shifts relative to the Baseline. `escape_rate` appears here intentionally alongside Step 2: in Step 2 it serves as an alert-level safety metric, here it captures the system's tendency to let GT_POS samples pass as an operational behavior signal.

### 3A. Global Decision Profile

| Mode | n_total | n_eval | n_miss | PASS | BLOCK | REVIEW | Pass Rate | Block Rate | Review Rate | Escape Rate | Block Share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 250 | 250 | 0 | 103 | 147 | 0 | 0.4120 | 0.5880 | 0.0000 | 0.3150 | 1.0000 |
| LLM_Baseline | 250 | 250 | 0 | 80 | 170 | 0 | 0.3200 | 0.6800 | 0.0000 | 0.1650 | 1.0000 |
| LLM_Guardrails | 250 | 250 | 0 | 25 | 150 | 75 | 0.1000 | 0.6000 | 0.3000 | 0.0050 | 0.6667 |

### 3B. Decision Counts on GT_POS

| Mode | n_gt_pos_eval | PASS | BLOCK | REVIEW |
| --- | --- | --- | --- | --- |
| Scanner | 200 | 63 | 137 | 0 |
| LLM_Baseline | 200 | 33 | 167 | 0 |
| LLM_Guardrails | 200 | 1 | 145 | 54 |

### 3C. Decision Counts on GT_NEG

| Mode | n_gt_neg_eval | PASS | BLOCK | REVIEW |
| --- | --- | --- | --- | --- |
| Scanner | 50 | 40 | 10 | 0 |
| LLM_Baseline | 50 | 47 | 3 | 0 |
| LLM_Guardrails | 50 | 24 | 5 | 21 |

### 3D. Behavioral Shift vs Baseline

| Comparison | Δ Pass Rate | Δ Block Rate | Δ Review Rate | Δ Escape Rate | Δ Block Share |
| --- | --- | --- | --- | --- | --- |
| Scanner_vs_Baseline | 0.0920 | -0.0920 | 0.0000 | 0.1500 | 0.0000 |
| LLM_Guardrails_vs_Baseline | -0.2200 | -0.0800 | 0.3000 | -0.1600 | -0.3333 |

## Step 4 — Guardrail KPIs

Operational activity of the guardrail bundle. Measures intervention frequency, per-guardrail participation vs routing authority, leakage containment (G3), and fail-closed behavior (G5).

### 4A. Bundle Activity Summary

| Metric | Value |
| --- | --- |
| n_total_guardrail_samples | 250 |
| n_evaluable_guardrail_samples | 250 |
| n_missing_guardrail_samples | 0 |
| samples_with_any_trigger | 218 (0.8720) |
| single_trigger_samples | 145 (0.5800) |
| multi_trigger_samples | 73 (0.2920) |
| max_triggers_on_single_sample | 3 |

### 4B. Per-Guardrail Activity

| Guardrail | Trigger Count | Trigger Rate | Routed Count | Routed Rate |
| --- | --- | --- | --- | --- |
| G5 | 2 | 0.0080 | 2 | 0.0080 |
| G2 | 0 | 0.0000 | 0 | 0.0000 |
| G4 | 102 | 0.4080 | 53 | 0.2120 |
| G1 | 4 | 0.0160 | 4 | 0.0160 |
| G3 | 187 | 0.7480 | 16 | 0.0640 |

### 4C. G3 Leakage KPIs

| Metric | Value |
| --- | --- |
| baseline_leakage | 70 (0.2800) |
| g3_triggered | 187 (0.7480) |
| residual_guardrail_leakage | 0 (0.0000) |
| residual_share_of_baseline_leak | 0.0000 |
| g3_on_gt_pos | 168 (0.8400) |

### 4D. G5 Schema / Fail-Closed KPIs

| Metric | Value |
| --- | --- |
| schema_invalid | 2 (0.0080) |
| g5_routed | 2 (0.0080) |
| g5_fail_closed_review | 2 (0.0080) |
| g5_fail_closed_share_of_g5 | 1.0000 |

### 4E. Trigger Combination Summary

| Combination | Count | Rate |
| --- | --- | --- |
| G3 | 114 | 0.4560 |
| G4+G3 | 68 | 0.2720 |
| G4 | 30 | 0.1200 |
| G4+G1+G3 | 3 | 0.0120 |
| G5 | 1 | 0.0040 |
| G1+G3 | 1 | 0.0040 |
| G5+G4+G3 | 1 | 0.0040 |

### 4F. G6 Pre-LLM Hint KPIs

| Metric | Value |
| --- | --- |
| g6_hint_injected | 30 (0.1200) |
| g6_no_hint | 220 |
| g6_hint_detection_rate | 0.3333 |
| g6_no_hint_detection_rate | 0.7273 |
| g6_hint_on_gt_pos | 29 (0.1450) |
| g6_hint_on_gt_neg | 1 |
| g6_hint_schema_valid | 30 (1.0000) |
| g6_hint_schema_fail | 0 |

## Step 5 — Failure-Mode PRI Analysis

Evaluates the guardrail bundle as a control layer via Prevalence (P), Intervention (I), and Residual (R) per failure mode. Rates are conditioned on their respective denominators: prevalence on n_baseline_evaluable, intervention and residual on prevalence_count. Residual is reported only where directly or partially observable — no proxy values are used.

### 5A. PRI Summary per Failure Mode

| FM | Guardrail | n_eval | Prev | Prev Rate | Interv | Interv Rate|Prev | Resid | Resid Rate|Prev | Observability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FM1_evidence_location | G1 | 250 | 9 | 0.0360 | 1 | 0.1111 | 1 | 0.1111 | partial |
| FM2_untrusted_input | G2 | 250 | 0 | 0.0000 | — | n/a | — | n/a | n/a |
| FM3_secret_leakage | G3 | 250 | 70 | 0.2800 | 63 | 0.9000 | 0 | 0.0000 | direct |
| FM4_uncertainty_miscalibration | G4 | 250 | 67 | 0.2680 | 67 | 1.0000 | 66 | 0.9851 | partial |
| FM5_schema_output_failure | G5 | 250 | 2 | 0.0080 | 2 | 1.0000 | — | n/a | not_robustly_observable |
| FM6_format_familiarity | G6 | 250 | 30 | 0.1200 | 30 | 1.0000 | 20 | 0.6667 | direct |

### 5B. PRI Definitions

| FM | Guardrail | Prevalence Field Logic | Intervention Field Logic | Residual Field Logic | Notes |
| --- | --- | --- | --- | --- | --- |
| FM1_evidence_location | G1 | baseline_failure_modes.g1_valid == false | G1 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G1 | llm_guardrail.g1_valid == false (on prevalence cases) | Residual observed via guardrail-side g1_valid flag, which is structurally analogous but not identical to the baseline g1_valid check. Interpretation should account for this structural difference. |
| FM2_untrusted_input | G2 | baseline_failure_modes.g2_valid == false | G2 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G2 | Not robustly observable. Guardrail-side g2_valid exists but lacks independent validation of FM2 resolution. | Residual not reported: guardrail-side g2_valid is structurally available but does not constitute a robust independent measure of whether untrusted-input influence was resolved. Additionally, zero prevalence in this dataset means PRI is structurally not evaluable for FM2. |
| FM3_secret_leakage | G3 | metrics.leak_in_baseline == true | llm_guardrail.g3_triggered == true | metrics.leak_in_guardrail == true (on prevalence cases) | All three PRI components are directly and independently observable via separate fields. Leakage detection is based on gt_secret_value string matching in model output. |
| FM4_uncertainty_miscalibration | G4 | baseline_failure_modes.g4_details.should_review == true | G4 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G4 | llm_guardrail.g4_details.should_review == true (on prevalence cases) | Residual is indicative, not definitive. The guardrail-side should_review flag measures structural presence of miscalibration indicators, not whether the bundle's routing action resolved the operational impact. Unlike FM3, there is no independent objective measure of FM4 resolution. |
| FM5_schema_output_failure | G5 | llm_guardrail.schema_valid == false (asymmetric: guardrail-side, not baseline-side) | G5 in llm_guardrail.triggered_guardrails OR llm_guardrail.routed_by_guardrail == G5 | Not robustly observable. No independent post-intervention field measures whether the schema failure persists as a problematic end state after G5 treatment. | Asymmetric operationalization: FM5 prevalence is observed on the guardrail/structured-output side only. The baseline does not undergo schema validation. Residual is not reported because absence of G5 routing does not robustly indicate a persisting problematic end state. |
| FM6_format_familiarity | G6 | llm_guardrail.g6_hint_injected == true | llm_guardrail.g6_hint_injected == true (G6 always injects hint on detection — intervention rate = 1.0 by construction) | llm_guardrail.g6_hint_injected == true AND gt_has_secret == true AND llm_guardrail.pred_has_secret == false | G6 is a pre-processing guardrail that injects a format hint before the LLM call. Intervention is definitionally complete (100%) for all prevalence cases. Residual measures cases where the hint was insufficient to recover detection on true-positive samples. |

### 5C. PRI Coverage / Observability

| FM | Guardrail | n_eval | Prev n | Resid Observability | Multi-FM Note | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FM1_evidence_location | G1 | 250 | 9 | partial | Multiple guardrails may act on the same sample. Observed FM1 residual may reflect bundle-wide output quality rather than G1-specific correction. | Residual based on guardrail-side g1_valid, which is structurally analogous but not identical to the baseline validity check. G1 did not trigger in this dataset; observed residual=0 may reflect overall guardrail output quality rather than targeted G1 intervention. |
| FM2_untrusted_input | G2 | 250 | 0 | not_robustly_observable | Zero prevalence in this dataset. PRI not structurally evaluable. | No baseline samples exhibited g2_valid=false. Residual not reported: guardrail-side g2_valid lacks independent validation of FM2 resolution. |
| FM3_secret_leakage | G3 | 250 | 70 | direct | G3 leakage detection operates independently of other guardrails via gt_secret_value string matching. | All three PRI components observed via independent fields. No structural cross-dependency with other guardrails. |
| FM4_uncertainty_miscalibration | G4 | 250 | 67 | partial | Potential overlap with G1 in ambiguity-heavy contexts. Multiple guardrails may act on the same sample; intervention attribution not always exclusive to G4. | Residual is indicative only. Guardrail-side should_review measures structural miscalibration presence, not whether routing resolved the operational impact. No independent objective measure of FM4 resolution available. |
| FM5_schema_output_failure | G5 | 250 | 2 | not_robustly_observable | G5 operates first in pipeline (G5 → G2 → G4 → G1 → G3). No structural overlap with other guardrails for schema failures. | Asymmetric operationalization: prevalence observed on guardrail output side only. Residual not reported: no independent post-intervention field to assess whether schema failure persists as a problematic end state. |
| FM6_format_familiarity | G6 | 250 | 30 | direct | G6 is a pre-processing guardrail (hint injection before LLM call). Can co-occur with G4 on the same sample if LLM uncertainty persists despite the hint. | G6 intervenes by construction on every detected format-candidate (intervention rate = 1.0). Residual directly observable: gt_has_secret=true AND pred_has_secret=false after hint injection. |

## Step 6 — Slice Analysis (Supplementary)

Segments the main findings from Steps 2, 3, and 5 by dataset slices. This is a **supplementary analysis layer** — the authoritative results are reported in Steps 2–5.

### 6A. Slice Performance Summary

| Slice | n | Mode | n_eval | Rec Alert | Prec Alert | Rec Auto | Prec Auto | Esc Rate | Review % | Block % | Pass % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base | 150 | Scanner | 150 | 0.9700 | 0.9065 | 0.9700 | 0.9065 | 0.0300 | 0.0000 | 0.7133 | 0.2867 |
| base | 150 | LLM_Baseline | 150 | 1.0000 | 0.9709 | 1.0000 | 0.9709 | 0.0000 | 0.0000 | 0.6867 | 0.3133 |
| base | 150 | LLM_Guardrails | 150 | 1.0000 | 0.7937 | 0.8500 | 0.9444 | 0.0000 | 0.2400 | 0.6000 | 0.1600 |
| stress | 100 | Scanner | 100 | 0.4000 | 1.0000 | 0.4000 | 1.0000 | 0.6000 | 0.0000 | 0.4000 | 0.6000 |
| stress | 100 | LLM_Baseline | 100 | 0.6700 | 1.0000 | 0.6700 | 1.0000 | 0.3300 | 0.0000 | 0.6700 | 0.3300 |
| stress | 100 | LLM_Guardrails | 100 | 0.9900 | 1.0000 | 0.6000 | 1.0000 | 0.0100 | 0.3900 | 0.6000 | 0.0100 |
| neg_clean | 25 | Scanner | 25 | n/a | n/a | n/a | n/a | n/a | 0.0000 | 0.0000 | 1.0000 |
| neg_clean | 25 | LLM_Baseline | 25 | n/a | n/a | n/a | n/a | n/a | 0.0000 | 0.0000 | 1.0000 |
| neg_clean | 25 | LLM_Guardrails | 25 | n/a | 0.0000 | n/a | n/a | n/a | 0.0400 | 0.0000 | 0.9600 |
| neg_decoy | 25 | Scanner | 25 | n/a | 0.0000 | n/a | 0.0000 | n/a | 0.0000 | 0.4000 | 0.6000 |
| neg_decoy | 25 | LLM_Baseline | 25 | n/a | 0.0000 | n/a | 0.0000 | n/a | 0.0000 | 0.1200 | 0.8800 |
| neg_decoy | 25 | LLM_Guardrails | 25 | n/a | 0.0000 | n/a | 0.0000 | n/a | 0.8000 | 0.2000 | 0.0000 |
| real | 75 | Scanner | 75 | 0.8000 | 1.0000 | 0.8000 | 1.0000 | 0.2000 | 0.0000 | 0.8000 | 0.2000 |
| real | 75 | LLM_Baseline | 75 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| real | 75 | LLM_Guardrails | 75 | 1.0000 | 1.0000 | 0.9067 | 1.0000 | 0.0000 | 0.0933 | 0.9067 | 0.0000 |
| synthetic | 75 | Scanner | 75 | 0.8800 | 1.0000 | 0.8800 | 1.0000 | 0.1200 | 0.0000 | 0.8800 | 0.1200 |
| synthetic | 75 | LLM_Baseline | 75 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| synthetic | 75 | LLM_Guardrails | 75 | 1.0000 | 1.0000 | 0.8133 | 1.0000 | 0.0000 | 0.1867 | 0.8133 | 0.0000 |

*Coverage notes: `real` + `synthetic` covers positive samples only (NEG\_ controls excluded). `neg_clean` + `neg_decoy` are control-specific subgroups, not an exhaustive partition of all GT-negative cases.*

*Slices with n < 10 (stress_untrusted_input, stress_uncertainty) should be interpreted with caution.*


<details><summary>Stress subtype breakdown (click to expand)</summary>

| Slice | n | Mode | n_eval | Rec Alert | Prec Alert | Rec Auto | Prec Auto | Esc Rate | Review % | Block % | Pass % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| stress_untrusted_input | 8 | Scanner | 8 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_untrusted_input | 8 | LLM_Baseline | 8 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_untrusted_input | 8 | LLM_Guardrails | 8 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_uncertainty | 8 | Scanner | 8 | 0.3750 | 1.0000 | 0.3750 | 1.0000 | 0.6250 | 0.0000 | 0.3750 | 0.6250 |
| stress_uncertainty | 8 | LLM_Baseline | 8 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_uncertainty | 8 | LLM_Guardrails | 8 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_multi_fm | 18 | Scanner | 18 | 0.2778 | 1.0000 | 0.2778 | 1.0000 | 0.7222 | 0.0000 | 0.2778 | 0.7222 |
| stress_multi_fm | 18 | LLM_Baseline | 18 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_multi_fm | 18 | LLM_Guardrails | 18 | 1.0000 | 1.0000 | 0.7778 | 1.0000 | 0.0000 | 0.2222 | 0.7778 | 0.0000 |
| stress_hardened | 17 | Scanner | 17 | 0.8235 | 1.0000 | 0.8235 | 1.0000 | 0.1765 | 0.0000 | 0.8235 | 0.1765 |
| stress_hardened | 17 | LLM_Baseline | 17 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 |
| stress_hardened | 17 | LLM_Guardrails | 17 | 1.0000 | 1.0000 | 0.8824 | 1.0000 | 0.0000 | 0.1176 | 0.8824 | 0.0000 |

</details>


### 6B. Slice PRI Spotlight

FM3 (secret leakage) and FM4 (uncertainty miscalibration) PRI rates per slice. Rates conditioned on respective denominators as in Step 5.

*FM4 values are indicative only. They are based on partially observable uncertainty/should-review indicators and are not comparable in directness to FM3 leakage measurements (see Step 5 for observability details).*

| Slice | n | FM3 Prev | FM3 Prev Rate | FM3 Interv|Prev | FM3 Resid|Prev | FM4 Prev | FM4 Prev Rate | FM4 Interv|Prev |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base | 150 | 54 | 0.3600 | 0.8704 | 0.0000 | 31 | 0.2067 | 1.0000 |
| stress | 100 | 16 | 0.1600 | 1.0000 | 0.0000 | 36 | 0.3600 | 1.0000 |
| neg_clean | 25 | 0 | 0.0000 | n/a | n/a | 1 | 0.0400 | 1.0000 |
| neg_decoy | 25 | 0 | 0.0000 | n/a | n/a | 25 | 1.0000 | 1.0000 |
| real | 75 | 38 | 0.5067 | 0.8421 | 0.0000 | 7 | 0.0933 | 1.0000 |
| synthetic | 75 | 24 | 0.3200 | 0.9583 | 0.0000 | 16 | 0.2133 | 1.0000 |
| stress_untrusted_input | 8 | 5 | 0.6250 | 1.0000 | 0.0000 | 8 | 1.0000 | 1.0000 |
| stress_uncertainty | 8 | 0 | 0.0000 | n/a | n/a | 4 | 0.5000 | 1.0000 |
| stress_multi_fm | 18 | 3 | 0.1667 | 1.0000 | 0.0000 | 6 | 0.3333 | 1.0000 |
| stress_hardened | 17 | 0 | 0.0000 | n/a | n/a | 1 | 0.0588 | 1.0000 |

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
| p1 | baseline | alert | 169 | 13 | 37 | 31 | 0.9286 | 0.8450 | 0.8848 | 0.1550 | 0.0000 |
| p1 | baseline | autonomous | 169 | 13 | 37 | 31 | 0.9286 | 0.8450 | 0.8848 | 0.1550 | 0.0000 |
| p2 | baseline | alert | 169 | 13 | 37 | 31 | 0.9286 | 0.8450 | 0.8848 | 0.1550 | 0.1880 |
| p2 | baseline | autonomous | 135 | 0 | 50 | 65 | 1.0000 | 0.6750 | 0.8060 | 0.1550 | 0.1880 |
| p3 | baseline | alert | 151 | 12 | 38 | 49 | 0.9264 | 0.7550 | 0.8320 | 0.2450 | 0.0480 |
| p3 | baseline | autonomous | 149 | 2 | 48 | 51 | 0.9868 | 0.7450 | 0.8490 | 0.2450 | 0.0480 |
| p1 | guardrail | alert | 200 | 26 | 24 | 0 | 0.8850 | 1.0000 | 0.9390 | 0.0000 | 0.2560 |
| p1 | guardrail | autonomous | 149 | 13 | 37 | 51 | 0.9198 | 0.7450 | 0.8232 | 0.0000 | 0.2560 |
| p2 | guardrail | alert | 197 | 21 | 29 | 3 | 0.9037 | 0.9850 | 0.9426 | 0.0150 | 0.3920 |
| p2 | guardrail | autonomous | 118 | 2 | 48 | 82 | 0.9833 | 0.5900 | 0.7375 | 0.0150 | 0.3920 |
| p3 | guardrail | alert | 188 | 17 | 33 | 12 | 0.9171 | 0.9400 | 0.9284 | 0.0600 | 0.2920 |
| p3 | guardrail | autonomous | 125 | 7 | 43 | 75 | 0.9470 | 0.6250 | 0.7530 | 0.0600 | 0.2920 |

## Supplementary — Slice Metrics

Segmented analysis across dataset dimensions. Complements the system-level results from Steps 2 and 3.

### Recall by Condition (LLM + Guardrails, Alert-Level)

| Condition | n | TP | FN | Recall | Precision | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| B0 | 150 | 100 | 0 | 1.0000 | 0.7937 | 0.8850 |
| E1-B | 8 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E2-A | 8 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E3-A | 18 | 18 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E3-B | 17 | 17 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E4-F | 8 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E4-G | 8 | 7 | 1 | 0.8750 | 1.0000 | 0.9333 |
| E4-H | 9 | 9 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E4-I | 24 | 24 | 0 | 1.0000 | 1.0000 | 1.0000 |

### False Positives by Negative Type (all systems)

| Neg Type | Mode | n | FP | TN | Specificity |
| --- | --- | --- | --- | --- | --- |
| NEG_CLEAN | Guardrails_Alert | 25 | 1 | 24 | 0.9600 |
| NEG_CLEAN | Guardrails_Autonomous | 25 | 0 | 25 | 1.0000 |
| NEG_CLEAN | LLM_Baseline | 25 | 0 | 25 | 1.0000 |
| NEG_CLEAN | Scanner | 25 | 0 | 25 | 1.0000 |
| NEG_DECOY | Guardrails_Alert | 25 | 25 | 0 | 0.0000 |
| NEG_DECOY | Guardrails_Autonomous | 25 | 5 | 20 | 0.8000 |
| NEG_DECOY | LLM_Baseline | 25 | 3 | 22 | 0.8800 |
| NEG_DECOY | Scanner | 25 | 10 | 15 | 0.6000 |

### Scanner — Recall by Condition

| Condition | n | TP | FN | Recall |
| --- | --- | --- | --- | --- |
| B0 | 150 | 97 | 3 | 0.9700 |
| E1-B | 8 | 8 | 0 | 1.0000 |
| E2-A | 8 | 3 | 5 | 0.3750 |
| E3-A | 18 | 5 | 13 | 0.2778 |
| E3-B | 17 | 14 | 3 | 0.8235 |
| E4-F | 8 | 1 | 7 | 0.1250 |
| E4-G | 8 | 3 | 5 | 0.3750 |
| E4-H | 9 | 0 | 9 | 0.0000 |
| E4-I | 24 | 6 | 18 | 0.2500 |

## Appendix — Legacy Mode Comparison (hit-level predicates)

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Specificity | Skipped |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 137 | 10 | 40 | 63 | 0.9320 | 0.6850 | 0.7896 | 0.8000 | 0 |
| LLM_Baseline | 167 | 3 | 47 | 33 | 0.9824 | 0.8350 | 0.9027 | 0.9400 | 0 |
| Guardrails_Alert | 199 | 26 | 24 | 1 | 0.8844 | 0.9950 | 0.9365 | 0.4800 | 0 |
| Guardrails_Autonomous | 145 | 5 | 45 | 55 | 0.9667 | 0.7250 | 0.8286 | 0.9000 | 0 |

### Decision Distributions

**Scanner:** BLOCK=147, REVIEW=0, PASS=103, None=0
**LLM_Baseline:** BLOCK=170, REVIEW=0, PASS=80, None=0
**Guardrails_Alert:** BLOCK=150, REVIEW=75, PASS=25, None=0
**Guardrails_Autonomous:** BLOCK=150, REVIEW=75, PASS=25, None=0

## Appendix — Legacy Guardrail KPI Details

### Routing Summary

| Routed By | Count |
| --- | --- |
| None | 175 |
| G4 | 53 |
| G3 | 16 |
| G1 | 4 |
| G5 | 2 |

### G1

- **trigger_count:** 4
- **trigger_rate:** 0.016
- **routed_count:** 4
- **g1_valid_false_count:** 4
- **issue_breakdown:**
  - evidence_mode='reconstructed': snippet covers assembly evidence but not fragment (L10–L52): 1
  - evidence_mode='reconstructed': snippet covers assembly evidence but not fragment (L13–L47): 1
  - evidence_mode='reconstructed': snippet covers assembly evidence but not fragment (L11–L64): 1
  - evidence_mode='reconstructed': snippet covers assembly evidence but not fragment (L10–L57): 1

### G2

- **trigger_count:** 26
- **trigger_rate:** 0.104
- **routed_count:** 0
- **g2_valid_false_count:** 0
- **issue_breakdown:**
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example) in pr_title, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 4
  - G2_UNREPORTED: PR metadata contains exculpatory claims (mock) in pr_title, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 2
  - G2_UNREPORTED: PR metadata contains exculpatory claims (not a real) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder) in pr_title, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 4
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, not a real) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 2
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example, not real) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example, not a real) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 2
  - G2_UNREPORTED: PR metadata contains exculpatory claims (fake, placeholder) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (fake, placeholder, not a real) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (non-production) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 6

### G3

- **g3_initial_leak_count:** 40
- **g3_post_mitigation_leak_count:** 0
- **leak_escape_rate_total:** 0.0
- **leak_escape_rate_of_detected:** 0.0
- **routed_count:** 16
- **g3_valid_false_count:** 40

### G4

- **escalation_count:** 101
- **escalation_rate:** 0.404
- **routed_count:** 53
- **rule_breakdown:**
  - R4_exculpatory_escalation: 41
  - R7_g6_format_candidate_pass: 19
  - R2_reconstructed_plus_ambiguity: 17
  - R1_ambiguous_context: 16
  - R6_auth_context_hardcoded: 5
  - R3_scanner_neg_llm_pos_context: 3
- **flag_breakdown:**
  - comment_claims_dummy: 68
  - auth_context_hardcoded_value: 41
  - scanner_disagreement: 31
  - decoy_like_pattern: 26
  - g2_unreported_influence: 26
  - placeholder_or_example_context: 22
  - evidence_span_not_single_line: 19
  - g6_format_candidate_pass: 19
  - low_specificity_literal: 18
  - reconstructed_secret: 17
  - split_across_variables: 17
  - test_or_docs_context: 12
  - ***redacted***: 7
  - exculpatory_claim: 2
- **on_positive:** 75
- **on_negative:** 26

### G5

- **trigger_count:** 2
- **trigger_rate:** 0.008
- **routed_count:** 2
- **schema_fail_count:** 2
- **schema_fail_rate:** 0.008
- **error_category_breakdown:**
  - CONSISTENCY_VIOLATION: 2
  - REPAIR_FAIL: 2
- **repair_success_count:** 0
- **repair_fail_count:** 2
- **repair_success_rate:** 0.0

### Multi-Trigger Summary

- **samples_with_any_trigger_count:** 218
- **single_trigger_samples_count:** 145
- **multi_trigger_samples_count:** 73
- **multi_trigger_rate:** 0.292
- **max_triggers_on_single_sample:** 3

**Per-Guardrail Trigger Count (from triggered_guardrails):**

| Guardrail | Trigger Count |
| --- | --- |
| G5 | 2 |
| G2 | 0 |
| G4 | 102 |
| G1 | 4 |
| G3 | 187 |

**Trigger Combination Breakdown:**

| Combination | Count |
| --- | --- |
| G3 | 114 |
| G4+G3 | 68 |
| G4 | 30 |
| G4+G1+G3 | 3 |
| G5 | 1 |
| G1+G3 | 1 |
| G5+G4+G3 | 1 |

## Data Availability Notes

- `context_family`: not present on all samples (NEG samples lack it)
- `failure_mode_target`: only present on stress/extreme samples
- `is_extreme_case`: only present on stress samples
- `llm_baseline`: may be None for individual samples (API failure)
- G5 `repair_success_rate`: only computable when REPAIR_SUCCESS/REPAIR_FAIL error categories are present in results

