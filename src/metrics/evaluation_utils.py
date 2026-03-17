"""
Evaluation Utilities for HybridGate Metrics

Pure computation functions — no file I/O.  All functions accept
List[Dict] results and return Dict, List[Dict], or str.

Metric Perspectives:
    Alert-Level:      BLOCK or REVIEW → positive detection (security gating)
    Autonomous-Level: only llm_guardrail_hit == True → positive detection

Author: Cecilia Nothstein
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════
#  A. Safe accessors
# ═══════════════════════════════════════════════════════════════════════

def _g(sample: Dict, *keys, default=None):
    """Nested safe-get.  _g(s, 'llm_guardrail', 'confidence') """
    cur = sample
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur


# ═══════════════════════════════════════════════════════════════════════
#  B. Confusion-matrix primitives
# ═══════════════════════════════════════════════════════════════════════

def confusion_counts(
    results: List[Dict],
    pred_fn: Callable[[Dict], Optional[bool]],
    gt_key: str = "gt_has_secret",
) -> Dict[str, int]:
    """
    Compute TP / FP / TN / FN from a predicate function.

    pred_fn(sample) → True  (positive prediction)
                    → False (negative prediction)
                    → None  (skip sample)
    """
    tp = fp = tn = fn = skipped = 0
    for s in results:
        pred = pred_fn(s)
        if pred is None:
            skipped += 1
            continue
        gt = bool(s.get(gt_key, False))
        if gt and pred:
            tp += 1
        elif gt and not pred:
            fn += 1
        elif not gt and pred:
            fp += 1
        else:
            tn += 1
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "skipped": skipped}


def derive_rates(cm: Dict[str, int]) -> Dict[str, Any]:
    """
    From TP/FP/TN/FN derive Precision, Recall, F1, Specificity.

    Returns a new dict with all input keys **plus** the derived rates.
    """
    tp, fp, tn, fn = cm["TP"], cm["FP"], cm["TN"], cm["FN"]
    total = tp + fp + tn + fn

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    spec = tn / (tn + fp) if (tn + fp) else 0.0
    acc  = (tp + tn) / total if total else 0.0

    return {
        **cm,
        "total_evaluated": total,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "specificity": round(spec, 4),
        "accuracy": round(acc, 4),
    }


def decision_distribution(
    results: List[Dict],
    decision_fn: Callable[[Dict], Optional[str]],
) -> Dict[str, Any]:
    """
    Count BLOCK / REVIEW / PASS (and None) from a decision function.

    Returns counts and rates.
    """
    counts: Dict[str, int] = Counter()
    for s in results:
        d = decision_fn(s)
        counts[d or "None"] += 1
    total = sum(counts.values())
    rates = {}
    for k, v in counts.items():
        rates[f"{k.lower()}_count"] = v
        rates[f"{k.lower()}_rate"] = round(v / total, 4) if total else 0.0
    rates["total"] = total
    return rates


# ═══════════════════════════════════════════════════════════════════════
#  C. Mode comparison  (Section A of requirements)
# ═══════════════════════════════════════════════════════════════════════

# ---- predicate functions -------------------------------------------

def _pred_scanner(s: Dict) -> Optional[bool]:
    return s.get("scanner_hit")


def _pred_baseline(s: Dict) -> Optional[bool]:
    """Positive if llm_baseline_hit == True.  Skip if baseline is None."""
    bl = s.get("llm_baseline")
    if bl is None:
        return None  # API failure → skip
    return bool(s.get("llm_baseline_hit", False))


def _pred_guardrail_alert(s: Dict) -> Optional[bool]:
    """Alert-Level: BLOCK or REVIEW → positive detection."""
    gr = s.get("llm_guardrail")
    if gr is None:
        return None
    fd = gr.get("final_decision")
    return fd in ("BLOCK", "REVIEW")


def _pred_guardrail_autonomous(s: Dict) -> Optional[bool]:
    """Autonomous-Level: llm_guardrail_hit == True → positive."""
    gr = s.get("llm_guardrail")
    if gr is None:
        return None
    return bool(s.get("llm_guardrail_hit", False))


# ---- decision functions --------------------------------------------

def _decision_scanner(s: Dict) -> Optional[str]:
    hit = s.get("scanner_hit")
    if hit is None:
        return None
    return "BLOCK" if hit else "PASS"


def _decision_baseline(s: Dict) -> Optional[str]:
    bl = s.get("llm_baseline")
    if bl is None:
        return None
    return bl.get("final_decision")


def _decision_guardrail(s: Dict) -> Optional[str]:
    gr = s.get("llm_guardrail")
    if gr is None:
        return None
    return gr.get("final_decision")


# ---- registry -------------------------------------------------------

MODE_DEFS = {
    "Scanner": {
        "pred_fn": _pred_scanner,
        "decision_fn": _decision_scanner,
        "description": "Gitleaks + detect-secrets combined (scanner_hit)",
    },
    "LLM_Baseline": {
        "pred_fn": _pred_baseline,
        "decision_fn": _decision_baseline,
        "description": "LLM without guardrails (llm_baseline_hit)",
    },
    "Guardrails_Alert": {
        "pred_fn": _pred_guardrail_alert,
        "decision_fn": _decision_guardrail,
        "description": "LLM + Guardrails, alert-level: BLOCK or REVIEW = detection",
    },
    "Guardrails_Autonomous": {
        "pred_fn": _pred_guardrail_autonomous,
        "decision_fn": _decision_guardrail,
        "description": "LLM + Guardrails, autonomous: llm_guardrail_hit = detection",
    },
}


def compute_mode_metrics(
    results: List[Dict],
    mode_name: str,
    mode_def: Dict,
) -> Dict[str, Any]:
    """Full metrics for one mode: confusion matrix + rates + decision dist."""
    cm = confusion_counts(results, mode_def["pred_fn"])
    rates = derive_rates(cm)
    dist = decision_distribution(results, mode_def["decision_fn"])
    return {
        "mode": mode_name,
        "description": mode_def["description"],
        **rates,
        "decision_distribution": dist,
    }


def compute_all_mode_metrics(results: List[Dict]) -> Dict[str, Dict]:
    """Return {mode_name: metrics_dict} for all four modes."""
    return {
        name: compute_mode_metrics(results, name, mdef)
        for name, mdef in MODE_DEFS.items()
    }


# ═══════════════════════════════════════════════════════════════════════
#  D. Guardrail-specific KPIs  (Section B)
# ═══════════════════════════════════════════════════════════════════════

def _g1_triggered(s: Dict) -> bool:
    gr = s.get("llm_guardrail") or {}
    if gr.get("routed_by_guardrail") == "G1":
        return True
    if gr.get("g1_valid") is False:
        return True
    if gr.get("g1_issues"):
        return True
    return False


def _g2_triggered(s: Dict) -> bool:
    gr = s.get("llm_guardrail") or {}
    if gr.get("routed_by_guardrail") == "G2":
        return True
    if gr.get("g2_valid") is False:
        return True
    if gr.get("g2_issues"):
        return True
    return False


def _g3_initial_leak(s: Dict) -> bool:
    gv = s.get("guardrail_validation") or {}
    return bool(gv.get("g3_leak_detected"))


def _g3_post_mitigation_leak(s: Dict) -> bool:
    m = s.get("metrics") or {}
    return bool(m.get("leak_in_guardrail"))


def _g4_triggered(s: Dict) -> bool:
    gr = s.get("llm_guardrail") or {}
    if gr.get("routed_by_guardrail") == "G4":
        return True
    details = gr.get("g4_details") or {}
    return bool(details.get("should_review"))


def _g5_triggered(s: Dict) -> bool:
    gr = s.get("llm_guardrail") or {}
    if gr.get("routed_by_guardrail") == "G5":
        return True
    if gr.get("g5_valid") is False:
        return True
    if gr.get("schema_valid") is False:
        return True
    if gr.get("error_categories"):
        return True
    return False


def compute_guardrail_kpis(results: List[Dict]) -> Dict[str, Any]:
    """Compute trigger counts and breakdowns for G1–G5."""
    n = len(results)
    kpis: Dict[str, Any] = {}

    # -- G1 ---------------------------------------------------------
    g1_samples = [s for s in results if _g1_triggered(s)]
    g1_routed  = [s for s in results if _g(s, "llm_guardrail", "routed_by_guardrail") == "G1"]
    g1_issues_flat: List[str] = []
    for s in results:
        g1_issues_flat.extend(_g(s, "llm_guardrail", "g1_issues") or [])
    kpis["g1"] = {
        "trigger_count": len(g1_samples),
        "trigger_rate": round(len(g1_samples) / n, 4) if n else 0,
        "routed_count": len(g1_routed),
        "g1_valid_false_count": sum(1 for s in results if _g(s, "llm_guardrail", "g1_valid") is False),
        "issue_breakdown": dict(Counter(g1_issues_flat)),
    }

    # -- G2 ---------------------------------------------------------
    g2_samples = [s for s in results if _g2_triggered(s)]
    g2_routed  = [s for s in results if _g(s, "llm_guardrail", "routed_by_guardrail") == "G2"]
    g2_issues_flat: List[str] = []
    for s in results:
        g2_issues_flat.extend(_g(s, "llm_guardrail", "g2_issues") or [])
    kpis["g2"] = {
        "trigger_count": len(g2_samples),
        "trigger_rate": round(len(g2_samples) / n, 4) if n else 0,
        "routed_count": len(g2_routed),
        "g2_valid_false_count": sum(1 for s in results if _g(s, "llm_guardrail", "g2_valid") is False),
        "issue_breakdown": dict(Counter(g2_issues_flat)),
    }

    # -- G3 ---------------------------------------------------------
    g3_initial = sum(1 for s in results if _g3_initial_leak(s))
    g3_post    = sum(1 for s in results if _g3_post_mitigation_leak(s))
    g3_routed  = [s for s in results if _g(s, "llm_guardrail", "routed_by_guardrail") == "G3"]
    g3_valid_f = sum(1 for s in results if _g(s, "guardrail_validation", "g3_valid") is False)
    kpis["g3"] = {
        "g3_initial_leak_count": g3_initial,
        "g3_post_mitigation_leak_count": g3_post,
        "leak_escape_rate_total": round(g3_post / n, 4) if n else 0,
        "leak_escape_rate_of_detected": (
            round(g3_post / g3_initial, 4) if g3_initial else 0.0
        ),
        "routed_count": len(g3_routed),
        "g3_valid_false_count": g3_valid_f,
    }

    # -- G4 ---------------------------------------------------------
    g4_samples = [s for s in results if _g4_triggered(s)]
    g4_routed  = [s for s in results if _g(s, "llm_guardrail", "routed_by_guardrail") == "G4"]

    rule_counter: Counter = Counter()
    flag_counter: Counter = Counter()
    for s in g4_samples:
        details = _g(s, "llm_guardrail", "g4_details") or {}
        rule = details.get("triggered_rule")
        if rule:
            rule_counter[rule] += 1
        for f in details.get("all_flags") or []:
            flag_counter[f] += 1

    kpis["g4"] = {
        "escalation_count": len(g4_samples),
        "escalation_rate": round(len(g4_samples) / n, 4) if n else 0,
        "routed_count": len(g4_routed),
        "rule_breakdown": dict(rule_counter.most_common()),
        "flag_breakdown": dict(flag_counter.most_common()),
        "on_positive": sum(1 for s in g4_samples if s.get("gt_has_secret")),
        "on_negative": sum(1 for s in g4_samples if not s.get("gt_has_secret")),
    }

    # -- G5 ---------------------------------------------------------
    g5_samples = [s for s in results if _g5_triggered(s)]
    g5_routed  = [s for s in results if _g(s, "llm_guardrail", "routed_by_guardrail") == "G5"]

    error_cat_counter: Counter = Counter()
    for s in results:
        for cat in _g(s, "llm_guardrail", "error_categories") or []:
            error_cat_counter[cat] += 1

    schema_fail = sum(
        1 for s in results if _g(s, "llm_guardrail", "schema_valid") is False
    )
    # Repair stats: REPAIR_SUCCESS / REPAIR_FAIL in error_categories
    repair_success = error_cat_counter.get("REPAIR_SUCCESS", 0)
    repair_fail    = error_cat_counter.get("REPAIR_FAIL", 0)
    repair_total   = repair_success + repair_fail

    kpis["g5"] = {
        "trigger_count": len(g5_samples),
        "trigger_rate": round(len(g5_samples) / n, 4) if n else 0,
        "routed_count": len(g5_routed),
        "schema_fail_count": schema_fail,
        "schema_fail_rate": round(schema_fail / n, 4) if n else 0,
        "error_category_breakdown": dict(error_cat_counter.most_common()),
        "repair_success_count": repair_success,
        "repair_fail_count": repair_fail,
        "repair_success_rate": (
            round(repair_success / repair_total, 4) if repair_total else None
        ),
        "note_repair": (
            "repair_success_rate is None when no REPAIR_SUCCESS/REPAIR_FAIL "
            "categories are present in results"
            if repair_total == 0 else None
        ),
    }

    # -- Routing summary --------------------------------------------
    routing_counter: Counter = Counter()
    for s in results:
        rb = _g(s, "llm_guardrail", "routed_by_guardrail")
        routing_counter[rb or "None"] += 1
    kpis["routing_summary"] = dict(routing_counter.most_common())

    return kpis


# ═══════════════════════════════════════════════════════════════════════
#  E. Slice metrics  (Section C)
# ═══════════════════════════════════════════════════════════════════════

def _neg_type(s: Dict) -> str:
    if s.get("gt_has_secret"):
        return "POS"
    ct = s.get("control_type")
    if ct == "decoy":
        return "NEG_DECOY"
    if ct == "no_secret":
        return "NEG_CLEAN"
    # Fallback: derive from sample_id
    sid = s.get("sample_id", "")
    if "DECOY" in sid.upper():
        return "NEG_DECOY"
    if "CLEAN" in sid.upper():
        return "NEG_CLEAN"
    return "NEG_OTHER"


def _origin(s: Dict) -> str:
    sid = s.get("sample_id", "")
    if sid.startswith("REAL"):
        return "REAL"
    if sid.startswith("SYNTH") or sid.startswith("SYNT"):
        return "SYNTH"
    return "NEG"


def _stress_slice(s: Dict) -> str:
    if s.get("condition", "B0") != "B0" or s.get("is_extreme_case"):
        return "STRESS"
    return "B0"


SLICE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "by_condition":       {"fn": lambda s: s.get("condition", "unknown")},
    "by_stress":          {"fn": _stress_slice},
    "by_neg_type":        {"fn": _neg_type},
    "by_origin":          {"fn": _origin},
    "by_failure_mode":    {"fn": lambda s: s.get("failure_mode_target") or "none"},
    "by_context_family":  {"fn": lambda s: s.get("context_family") or "unknown"},
    "by_secret_type":     {"fn": lambda s: s.get("gt_secret_type") or "none"},
    "by_high_risk_file":  {"fn": lambda s: str(_g(s, "policy_tags", "is_high_risk_file"))},
    "by_obfuscation":     {"fn": lambda s: str(_g(s, "policy_tags", "obfuscation_suspected"))},
}


def slice_results(
    results: List[Dict],
    slice_fn: Callable[[Dict], str],
) -> Dict[str, List[Dict]]:
    """Group results by slice function."""
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for s in results:
        groups[slice_fn(s)].append(s)
    return dict(groups)


def compute_slice_metrics(results: List[Dict]) -> List[Dict[str, Any]]:
    """
    For every slice definition × every mode, compute confusion matrix + rates.

    Returns flat list of dicts (one row per slice_value × mode),
    suitable for CSV.
    """
    rows: List[Dict[str, Any]] = []

    for slice_name, sdef in SLICE_DEFINITIONS.items():
        groups = slice_results(results, sdef["fn"])
        for slice_val, samples in sorted(groups.items()):
            for mode_name, mdef in MODE_DEFS.items():
                cm = confusion_counts(samples, mdef["pred_fn"])
                rates = derive_rates(cm)
                rows.append({
                    "slice_name": slice_name,
                    "slice_value": slice_val,
                    "mode": mode_name,
                    "n": len(samples),
                    **rates,
                })
    return rows


# ═══════════════════════════════════════════════════════════════════════
#  F. Policy evaluation  (Section D)
# ═══════════════════════════════════════════════════════════════════════

_POLICY_KEYS = [
    ("p1", "baseline"),
    ("p1", "guardrail"),
    ("p2", "baseline"),
    ("p2", "guardrail"),
    ("p3", "baseline"),
    ("p3", "guardrail"),
]


def _policy_field(policy: str, variant: str) -> str:
    """e.g. ('p1', 'guardrail') → 'policy_p1_guardrail'"""
    return f"policy_{policy}_{variant}"


def compute_policy_metrics(
    results: List[Dict],
    policy: str,
    variant: str,
    view: str,
) -> Dict[str, Any]:
    """
    Compute confusion matrix + rates for one policy/variant/view.

    view='alert':      BLOCK or REVIEW → positive
    view='autonomous': BLOCK only → positive
    """
    field = _policy_field(policy, variant)

    def pred_fn(s: Dict) -> Optional[bool]:
        val = s.get(field)
        if val is None:
            return None
        if view == "alert":
            return val in ("BLOCK", "REVIEW")
        else:  # autonomous
            return val == "BLOCK"

    def decision_fn(s: Dict) -> Optional[str]:
        return s.get(field)

    cm = confusion_counts(results, pred_fn)
    rates = derive_rates(cm)
    dist = decision_distribution(results, decision_fn)

    # Escape rate: positive samples that got PASS
    pos_samples = [s for s in results if s.get("gt_has_secret")]
    escaped = sum(1 for s in pos_samples if s.get(field) == "PASS")
    escape_rate = round(escaped / len(pos_samples), 4) if pos_samples else 0.0

    # Reviewer load
    review_count = dist.get("review_count", 0)
    total = dist.get("total", len(results))
    reviewer_load = round(review_count / total, 4) if total else 0.0

    return {
        "policy": policy,
        "variant": variant,
        "view": view,
        **rates,
        "escape_count": escaped,
        "escape_rate": escape_rate,
        "reviewer_load": reviewer_load,
        "decision_distribution": dist,
    }


def compute_all_policy_metrics(results: List[Dict]) -> List[Dict[str, Any]]:
    """
    Cross-product of {p1,p2,p3} × {baseline,guardrail} × {alert,autonomous}.

    Returns flat list of 12 dicts.
    """
    rows = []
    for policy, variant in _POLICY_KEYS:
        for view in ("alert", "autonomous"):
            rows.append(compute_policy_metrics(results, policy, variant, view))
    return rows


# ═══════════════════════════════════════════════════════════════════════
#  G. Dataset summary
# ═══════════════════════════════════════════════════════════════════════

def build_dataset_summary(
    results: List[Dict],
    config: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Dataset composition overview."""
    n = len(results)
    n_pos = sum(1 for s in results if s.get("gt_has_secret"))
    n_neg = n - n_pos

    cond_dist  = dict(Counter(s.get("condition", "unknown") for s in results).most_common())
    origin_dist = dict(Counter(_origin(s) for s in results).most_common())
    neg_dist    = dict(Counter(
        _neg_type(s) for s in results if not s.get("gt_has_secret")
    ).most_common())
    secret_types = dict(Counter(
        s.get("gt_secret_type", "none") for s in results if s.get("gt_has_secret")
    ).most_common())
    fm_dist = dict(Counter(
        s.get("failure_mode_target") or "none" for s in results
    ).most_common())

    # Samples with missing baseline
    bl_none = sum(1 for s in results if s.get("llm_baseline") is None)

    summary: Dict[str, Any] = {
        "total_samples": n,
        "positive_samples": n_pos,
        "negative_samples": n_neg,
        "condition_distribution": cond_dist,
        "origin_distribution": origin_dist,
        "negative_type_distribution": neg_dist,
        "secret_type_distribution": secret_types,
        "failure_mode_distribution": fm_dist,
        "baseline_none_count": bl_none,
    }

    if config:
        summary["run_id"] = config.get("run_id")
        summary["model"] = config.get("model", {}).get("model_id")
        summary["dataset_path"] = config.get("dataset", {}).get("path")

    return summary


# ═══════════════════════════════════════════════════════════════════════
#  H. Markdown report generation
# ═══════════════════════════════════════════════════════════════════════

def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    """Render a Markdown table."""
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def _fmt(val, fmt=".4f") -> str:
    if val is None:
        return "n/a"
    if isinstance(val, float):
        return format(val, fmt)
    return str(val)


def generate_markdown_report(
    mode_metrics: Dict[str, Dict],
    guardrail_kpis: Dict[str, Any],
    policy_metrics: List[Dict],
    slice_metrics: List[Dict],
    dataset_summary: Dict,
) -> str:
    """Generate evaluation_summary.md — purely descriptive, no interpretation."""
    parts: List[str] = []

    # ── Title ──────────────────────────────────────────────────────
    parts.append("# Evaluation Summary — v121 Final Run\n")
    parts.append(f"Generated from {dataset_summary.get('total_samples', '?')} samples.\n")

    # ── Definitions ────────────────────────────────────────────────
    parts.append("## Metric Definitions\n")
    parts.append("""\
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
""")

    # ── Dataset ────────────────────────────────────────────────────
    parts.append("## Dataset Composition\n")
    ds = dataset_summary
    rows_ds = [
        ["Positive (gt_has_secret=true)", str(ds.get("positive_samples", "?"))],
        ["Negative (gt_has_secret=false)", str(ds.get("negative_samples", "?"))],
        ["Total", str(ds.get("total_samples", "?"))],
    ]
    parts.append(_md_table(["Category", "Count"], rows_ds))
    parts.append("")

    if ds.get("condition_distribution"):
        parts.append("### By Condition\n")
        rows_c = [[k, str(v)] for k, v in ds["condition_distribution"].items()]
        parts.append(_md_table(["Condition", "Count"], rows_c))
        parts.append("")

    if ds.get("negative_type_distribution"):
        parts.append("### Negative Types\n")
        rows_n = [[k, str(v)] for k, v in ds["negative_type_distribution"].items()]
        parts.append(_md_table(["Type", "Count"], rows_n))
        parts.append("")

    if ds.get("baseline_none_count"):
        parts.append(
            f"**Note:** {ds['baseline_none_count']} sample(s) have "
            f"`llm_baseline = None` (API failure). These are excluded from "
            f"Baseline metrics but included in Scanner and Guardrail metrics.\n"
        )

    # ── Mode Comparison ────────────────────────────────────────────
    parts.append("## Mode Comparison\n")
    mode_headers = [
        "Mode", "TP", "FP", "TN", "FN", "Precision", "Recall",
        "F1", "Specificity", "Skipped",
    ]
    mode_rows = []
    for name in ["Scanner", "LLM_Baseline", "Guardrails_Alert", "Guardrails_Autonomous"]:
        m = mode_metrics.get(name, {})
        mode_rows.append([
            name,
            m.get("TP", "?"), m.get("FP", "?"),
            m.get("TN", "?"), m.get("FN", "?"),
            _fmt(m.get("precision")), _fmt(m.get("recall")),
            _fmt(m.get("f1")), _fmt(m.get("specificity")),
            m.get("skipped", 0),
        ])
    parts.append(_md_table(mode_headers, mode_rows))
    parts.append("")

    # Decision distributions
    parts.append("### Decision Distributions\n")
    for name in ["Scanner", "LLM_Baseline", "Guardrails_Alert", "Guardrails_Autonomous"]:
        m = mode_metrics.get(name, {})
        dd = m.get("decision_distribution", {})
        parts.append(f"**{name}:** "
                     f"BLOCK={dd.get('block_count', 0)}, "
                     f"REVIEW={dd.get('review_count', 0)}, "
                     f"PASS={dd.get('pass_count', 0)}, "
                     f"None={dd.get('none_count', 0)}")
    parts.append("")

    # ── Guardrail KPIs ─────────────────────────────────────────────
    parts.append("## Guardrail KPIs\n")

    parts.append("### Routing Summary\n")
    rs = guardrail_kpis.get("routing_summary", {})
    rows_rs = [[k, str(v)] for k, v in rs.items()]
    parts.append(_md_table(["Routed By", "Count"], rows_rs))
    parts.append("")

    for gname in ["g1", "g2", "g3", "g4", "g5"]:
        gk = guardrail_kpis.get(gname, {})
        parts.append(f"### {gname.upper()}\n")
        for key, val in gk.items():
            if isinstance(val, dict):
                parts.append(f"- **{key}:**")
                for k2, v2 in val.items():
                    parts.append(f"  - {k2}: {v2}")
            elif val is not None:
                parts.append(f"- **{key}:** {val}")
        parts.append("")

    # ── Policy Metrics ─────────────────────────────────────────────
    parts.append("## Policy Metrics\n")
    pol_headers = [
        "Policy", "Variant", "View", "TP", "FP", "TN", "FN",
        "Precision", "Recall", "F1", "Escape Rate", "Reviewer Load",
    ]
    pol_rows = []
    for pm in policy_metrics:
        pol_rows.append([
            pm["policy"], pm["variant"], pm["view"],
            pm.get("TP", "?"), pm.get("FP", "?"),
            pm.get("TN", "?"), pm.get("FN", "?"),
            _fmt(pm.get("precision")), _fmt(pm.get("recall")),
            _fmt(pm.get("f1")),
            _fmt(pm.get("escape_rate")), _fmt(pm.get("reviewer_load")),
        ])
    parts.append(_md_table(pol_headers, pol_rows))
    parts.append("")

    # ── Slice Metrics (selected) ───────────────────────────────────
    parts.append("## Slice Metrics (selected)\n")

    # Show by_condition for Guardrails_Alert
    parts.append("### Recall by Condition (Guardrails Alert-Level)\n")
    cond_rows = [
        r for r in slice_metrics
        if r["slice_name"] == "by_condition" and r["mode"] == "Guardrails_Alert"
    ]
    if cond_rows:
        h = ["Condition", "n", "TP", "FN", "Recall", "Precision", "F1"]
        rows_c = []
        for cr in sorted(cond_rows, key=lambda x: x["slice_value"]):
            rows_c.append([
                cr["slice_value"], cr["n"],
                cr["TP"], cr["FN"],
                _fmt(cr["recall"]), _fmt(cr["precision"]), _fmt(cr["f1"]),
            ])
        parts.append(_md_table(h, rows_c))
    parts.append("")

    # Show by_neg_type for all modes
    parts.append("### False Positives by Negative Type\n")
    neg_rows = [
        r for r in slice_metrics
        if r["slice_name"] == "by_neg_type" and r["slice_value"] != "POS"
    ]
    if neg_rows:
        h = ["Neg Type", "Mode", "n", "FP", "TN", "Specificity"]
        rows_n = []
        for nr in sorted(neg_rows, key=lambda x: (x["slice_value"], x["mode"])):
            rows_n.append([
                nr["slice_value"], nr["mode"], nr["n"],
                nr["FP"], nr["TN"], _fmt(nr["specificity"]),
            ])
        parts.append(_md_table(h, rows_n))
    parts.append("")

    # Show by_condition for Scanner (to highlight obfuscation weakness)
    parts.append("### Scanner Recall by Condition\n")
    scanner_cond = [
        r for r in slice_metrics
        if r["slice_name"] == "by_condition" and r["mode"] == "Scanner"
    ]
    if scanner_cond:
        h = ["Condition", "n", "TP", "FN", "Recall"]
        rows_sc = []
        for cr in sorted(scanner_cond, key=lambda x: x["slice_value"]):
            rows_sc.append([
                cr["slice_value"], cr["n"],
                cr["TP"], cr["FN"], _fmt(cr["recall"]),
            ])
        parts.append(_md_table(h, rows_sc))
    parts.append("")

    # ── Data Availability Notes ────────────────────────────────────
    parts.append("## Data Availability Notes\n")
    parts.append(
        "- `context_family`: not present on all samples (NEG samples lack it)\n"
        "- `failure_mode_target`: only present on stress/extreme samples\n"
        "- `is_extreme_case`: only present on stress samples\n"
        "- `llm_baseline`: may be None for individual samples (API failure)\n"
        "- G5 `repair_success_rate`: only computable when REPAIR_SUCCESS/REPAIR_FAIL "
        "error categories are present in results\n"
    )

    return "\n".join(parts) + "\n"
