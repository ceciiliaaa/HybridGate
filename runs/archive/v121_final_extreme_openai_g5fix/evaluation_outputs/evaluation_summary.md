# Evaluation Summary — v121 Final Run

Generated from 200 samples.

## Metric Definitions

**Ground Truth**: `gt_has_secret == true` → positive class.

**Four evaluation modes:**

| Mode | Positive-Detection Definition |
| --- | --- |
| Scanner | `scanner_hit == true` |
| LLM Baseline | `llm_baseline_hit == true` |
| Guardrails Alert-Level | `final_decision in {BLOCK, REVIEW}` |
| Guardrails Autonomous-Level | `llm_guardrail_hit == true` |

**Alert-Level** treats REVIEW as detection (security gating perspective).
**Autonomous-Level** counts only autonomous LLM classifications (no guardrail escalation).

Scanner has no REVIEW concept; `scanner_hit == true` maps to BLOCK, `false` to PASS.

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

**Note:** 1 sample(s) have `llm_baseline = None` (API failure). These are excluded from Baseline metrics but included in Scanner and Guardrail metrics.

## Mode Comparison

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Specificity | Skipped |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Scanner | 126 | 10 | 40 | 24 | 0.9265 | 0.8400 | 0.8811 | 0.8000 | 0 |
| LLM_Baseline | 149 | 23 | 27 | 0 | 0.8663 | 1.0000 | 0.9283 | 0.5400 | 1 |
| Guardrails_Alert | 150 | 26 | 24 | 0 | 0.8523 | 1.0000 | 0.9202 | 0.4800 | 0 |
| Guardrails_Autonomous | 126 | 22 | 28 | 24 | 0.8514 | 0.8400 | 0.8456 | 0.5600 | 0 |

### Decision Distributions

**Scanner:** BLOCK=136, REVIEW=0, PASS=64, None=0
**LLM_Baseline:** BLOCK=161, REVIEW=11, PASS=27, None=1
**Guardrails_Alert:** BLOCK=85, REVIEW=91, PASS=24, None=0
**Guardrails_Autonomous:** BLOCK=85, REVIEW=91, PASS=24, None=0

## Guardrail KPIs

### Routing Summary

| Routed By | Count |
| --- | --- |
| None | 109 |
| G4 | 55 |
| G5 | 25 |
| G3 | 10 |
| G2 | 1 |

### G1

- **trigger_count:** 0
- **trigger_rate:** 0.0
- **routed_count:** 0
- **g1_valid_false_count:** 0
- **issue_breakdown:**

### G2

- **trigger_count:** 3
- **trigger_rate:** 0.015
- **routed_count:** 1
- **g2_valid_false_count:** 1
- **issue_breakdown:**
  - G2_EXCULPATORY: untrusted_effect='exculpatory_claim' (role=pr_body) — untrusted input must not exculpate findings: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example, not real) in pr_body, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1
  - G2_UNREPORTED: PR metadata contains exculpatory claims (placeholder, example) in pr_title, but LLM reported used_untrusted_input=false with PASS/no-secret — potential unacknowledged influence: 1

### G3

- **g3_initial_leak_count:** 8
- **g3_post_mitigation_leak_count:** 0
- **leak_escape_rate_total:** 0.0
- **leak_escape_rate_of_detected:** 0.0
- **routed_count:** 10
- **g3_valid_false_count:** 8

### G4

- **escalation_count:** 55
- **escalation_rate:** 0.275
- **routed_count:** 55
- **rule_breakdown:**
  - R1_ambiguous_context: 24
  - R4_exculpatory_escalation: 14
  - R2_reconstructed_plus_ambiguity: 11
  - R3_scanner_neg_llm_pos_context: 6
- **flag_breakdown:**
  - placeholder_or_example_context: 48
  - comment_claims_dummy: 45
  - test_or_docs_context: 30
  - scanner_disagreement: 21
  - evidence_span_not_single_line: 12
  - decoy_like_pattern: 11
  - reconstructed_secret: 11
  - split_across_variables: 11
  - low_specificity_literal: 7
  - g2_unreported_influence: 2
- **on_positive:** 30
- **on_negative:** 25

### G5

- **trigger_count:** 25
- **trigger_rate:** 0.125
- **routed_count:** 25
- **schema_fail_count:** 25
- **schema_fail_rate:** 0.125
- **error_category_breakdown:**
  - PARSE_ERROR: 25
- **repair_success_count:** 0
- **repair_fail_count:** 0
- **note_repair:** repair_success_rate is None when no REPAIR_SUCCESS/REPAIR_FAIL categories are present in results

## Policy Metrics

| Policy | Variant | View | TP | FP | TN | FN | Precision | Recall | F1 | Escape Rate | Reviewer Load |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| p1 | baseline | alert | 149 | 23 | 27 | 0 | 0.8663 | 1.0000 | 0.9283 | 0.0000 | 0.0550 |
| p1 | baseline | autonomous | 142 | 19 | 31 | 7 | 0.8820 | 0.9530 | 0.9161 | 0.0000 | 0.0550 |
| p1 | guardrail | alert | 150 | 26 | 24 | 0 | 0.8523 | 1.0000 | 0.9202 | 0.0000 | 0.4550 |
| p1 | guardrail | autonomous | 85 | 0 | 50 | 65 | 1.0000 | 0.5667 | 0.7234 | 0.0000 | 0.4550 |
| p2 | baseline | alert | 149 | 23 | 27 | 0 | 0.8663 | 1.0000 | 0.9283 | 0.0000 | 0.1900 |
| p2 | baseline | autonomous | 125 | 9 | 41 | 24 | 0.9328 | 0.8389 | 0.8834 | 0.0000 | 0.1900 |
| p2 | guardrail | alert | 150 | 26 | 24 | 0 | 0.8523 | 1.0000 | 0.9202 | 0.0000 | 0.4750 |
| p2 | guardrail | autonomous | 81 | 0 | 50 | 69 | 1.0000 | 0.5400 | 0.7013 | 0.0000 | 0.4750 |
| p3 | baseline | alert | 137 | 15 | 35 | 12 | 0.9013 | 0.9195 | 0.9103 | 0.0800 | 0.0400 |
| p3 | baseline | autonomous | 130 | 14 | 36 | 19 | 0.9028 | 0.8725 | 0.8874 | 0.0800 | 0.0400 |
| p3 | guardrail | alert | 138 | 16 | 34 | 12 | 0.8961 | 0.9200 | 0.9079 | 0.0800 | 0.3400 |
| p3 | guardrail | autonomous | 86 | 0 | 50 | 64 | 1.0000 | 0.5733 | 0.7288 | 0.0800 | 0.3400 |

## Slice Metrics (selected)

### Recall by Condition (Guardrails Alert-Level)

| Condition | n | TP | FN | Recall | Precision | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| B0 | 150 | 100 | 0 | 1.0000 | 0.7937 | 0.8850 |
| E1-B | 8 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E2-A | 8 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E3-A | 17 | 17 | 0 | 1.0000 | 1.0000 | 1.0000 |
| E3-B | 17 | 17 | 0 | 1.0000 | 1.0000 | 1.0000 |

### False Positives by Negative Type

| Neg Type | Mode | n | FP | TN | Specificity |
| --- | --- | --- | --- | --- | --- |
| NEG_CLEAN | Guardrails_Alert | 25 | 1 | 24 | 0.9600 |
| NEG_CLEAN | Guardrails_Autonomous | 25 | 0 | 25 | 1.0000 |
| NEG_CLEAN | LLM_Baseline | 25 | 0 | 25 | 1.0000 |
| NEG_CLEAN | Scanner | 25 | 0 | 25 | 1.0000 |
| NEG_DECOY | Guardrails_Alert | 25 | 25 | 0 | 0.0000 |
| NEG_DECOY | Guardrails_Autonomous | 25 | 22 | 3 | 0.1200 |
| NEG_DECOY | LLM_Baseline | 25 | 23 | 2 | 0.0800 |
| NEG_DECOY | Scanner | 25 | 10 | 15 | 0.6000 |

### Scanner Recall by Condition

| Condition | n | TP | FN | Recall |
| --- | --- | --- | --- | --- |
| B0 | 150 | 97 | 3 | 0.9700 |
| E1-B | 8 | 8 | 0 | 1.0000 |
| E2-A | 8 | 3 | 5 | 0.3750 |
| E3-A | 17 | 4 | 13 | 0.2353 |
| E3-B | 17 | 14 | 3 | 0.8235 |

## Data Availability Notes

- `context_family`: not present on all samples (NEG samples lack it)
- `failure_mode_target`: only present on stress/extreme samples
- `is_extreme_case`: only present on stress samples
- `llm_baseline`: may be None for individual samples (API failure)
- G5 `repair_success_rate`: only computable when REPAIR_SUCCESS/REPAIR_FAIL error categories are present in results

