"""
Evaluation Utilities for HybridGate Metrics

Pure computation functions — no file I/O.  All functions accept
List[Dict] results and return Dict, List[Dict], or str.

Metric Perspectives:
    Alert-Level:      BLOCK or REVIEW → positive detection (security gating)
    Autonomous-Level: only BLOCK → positive detection (no human review needed)

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
#  Step 2: Three-System Mode Comparison (Alert + Autonomous)
# ═══════════════════════════════════════════════════════════════════════

# ---- Decision extraction per system ----------------------------------

def _decision_scanner(s: Dict) -> Optional[str]:
    """Scanner: hit → BLOCK, no hit → PASS, None → missing."""
    hit = s.get("scanner_hit")
    if hit is None:
        return None
    return "BLOCK" if hit else "PASS"


def _decision_baseline_system(s: Dict) -> Optional[str]:
    """Baseline: use final_decision, fallback to pred_has_secret."""
    bl = s.get("llm_baseline")
    if bl is None:
        return None
    fd = bl.get("final_decision")
    if fd in ("PASS", "BLOCK", "REVIEW"):
        return fd
    # Fallback: derive from pred_has_secret
    pred = bl.get("pred_has_secret")
    if pred is None:
        return None
    return "BLOCK" if pred else "PASS"


def _decision_guardrail_system(s: Dict) -> Optional[str]:
    """Guardrail: use final_decision."""
    gr = s.get("llm_guardrail")
    if gr is None:
        return None
    fd = gr.get("final_decision")
    if fd in ("PASS", "BLOCK", "REVIEW"):
        return fd
    return None


_MODE_COMPARISON_SYSTEMS = {
    "Scanner": _decision_scanner,
    "LLM_Baseline": _decision_baseline_system,
    "LLM_Guardrails": _decision_guardrail_system,
}


def _safe_div(num: int, den: int, digits: int = 4) -> Optional[float]:
    """Safe division: returns None when denominator is 0."""
    if den == 0:
        return None
    return round(num / den, digits)


def compute_mode_comparison(results: List[Dict]) -> Dict[str, Any]:
    """
    Step 2: Reproducible three-system mode comparison.

    Systems: Scanner, LLM_Baseline, LLM_Guardrails
    Views:   Alert-Level  (BLOCK|REVIEW = positive)
             Autonomous   (BLOCK only   = positive)

    Returns dict with four blocks:
        alert_level          → Table 2A (confusion metrics)
        alert_profile        → Table 2B (decision profile + escape rate)
        autonomous_level     → Table 2C (confusion metrics)
        alert_vs_autonomous  → Table 2D (cross-view comparison)
    """
    n_total = len(results)

    # Pre-extract decisions + ground truth per system
    system_entries: Dict[str, List[Tuple[Optional[str], bool]]] = {}
    for sys_name, dfn in _MODE_COMPARISON_SYSTEMS.items():
        entries = []
        for s in results:
            decision = dfn(s)
            gt = bool(s.get("gt_has_secret", False))
            entries.append((decision, gt))
        system_entries[sys_name] = entries

    alert_rows: List[Dict[str, Any]] = []
    profile_rows: List[Dict[str, Any]] = []
    auto_rows: List[Dict[str, Any]] = []
    comparison_rows: List[Dict[str, Any]] = []

    for sys_name, entries in system_entries.items():
        n_missing = sum(1 for d, _ in entries if d is None)
        n_evaluable = n_total - n_missing

        # Decision counts (evaluable only)
        n_block = sum(1 for d, _ in entries if d == "BLOCK")
        n_review = sum(1 for d, _ in entries if d == "REVIEW")
        n_pass = sum(1 for d, _ in entries if d == "PASS")

        block_rate = _safe_div(n_block, n_evaluable)
        review_rate = _safe_div(n_review, n_evaluable)
        pass_rate = _safe_div(n_pass, n_evaluable)

        # GT_POS among evaluable samples
        gt_pos_eval = sum(1 for d, gt in entries if d is not None and gt)

        # ── Alert-Level (BLOCK|REVIEW = positive) ────────────────
        tp_a = sum(1 for d, gt in entries if d in ("BLOCK", "REVIEW") and gt)
        fp_a = sum(1 for d, gt in entries if d in ("BLOCK", "REVIEW") and not gt)
        fn_a = sum(1 for d, gt in entries if d == "PASS" and gt)
        tn_a = sum(1 for d, gt in entries if d == "PASS" and not gt)

        prec_a = _safe_div(tp_a, tp_a + fp_a)
        rec_a = _safe_div(tp_a, tp_a + fn_a)
        f1_a = _safe_div(2 * tp_a, 2 * tp_a + fp_a + fn_a)
        spec_a = _safe_div(tn_a, tn_a + fp_a)
        escape_rate = _safe_div(fn_a, gt_pos_eval)

        alert_rows.append({
            "mode": sys_name,
            "n_total": n_total,
            "n_evaluable": n_evaluable,
            "n_missing": n_missing,
            "tp_alert": tp_a,
            "fp_alert": fp_a,
            "tn_alert": tn_a,
            "fn_alert": fn_a,
            "precision_alert": prec_a,
            "recall_alert": rec_a,
            "f1_alert": f1_a,
            "specificity_alert": spec_a,
        })

        profile_rows.append({
            "mode": sys_name,
            "n_total": n_total,
            "n_evaluable": n_evaluable,
            "n_missing": n_missing,
            "pass_rate": pass_rate,
            "block_rate": block_rate,
            "review_rate": review_rate,
            "escape_rate": escape_rate,
        })

        # ── Autonomous-Level (BLOCK only = positive) ─────────────
        tp_u = sum(1 for d, gt in entries if d == "BLOCK" and gt)
        fp_u = sum(1 for d, gt in entries if d == "BLOCK" and not gt)
        fn_u = sum(1 for d, gt in entries if d in ("PASS", "REVIEW") and gt)
        tn_u = sum(1 for d, gt in entries if d in ("PASS", "REVIEW") and not gt)

        prec_u = _safe_div(tp_u, tp_u + fp_u)
        rec_u = _safe_div(tp_u, tp_u + fn_u)
        f1_u = _safe_div(2 * tp_u, 2 * tp_u + fp_u + fn_u)
        spec_u = _safe_div(tn_u, tn_u + fp_u)

        auto_rows.append({
            "mode": sys_name,
            "n_total": n_total,
            "n_evaluable": n_evaluable,
            "n_missing": n_missing,
            "tp_auto": tp_u,
            "fp_auto": fp_u,
            "tn_auto": tn_u,
            "fn_auto": fn_u,
            "precision_auto": prec_u,
            "recall_auto": rec_u,
            "f1_auto": f1_u,
            "specificity_auto": spec_u,
        })

        # ── Alert vs Autonomous comparison ───────────────────────
        delta_recall = (
            round(rec_a - rec_u, 4) if rec_a is not None and rec_u is not None
            else None
        )
        delta_prec = (
            round(prec_a - prec_u, 4) if prec_a is not None and prec_u is not None
            else None
        )

        comparison_rows.append({
            "mode": sys_name,
            "recall_alert": rec_a,
            "recall_auto": rec_u,
            "delta_recall_alert_vs_auto": delta_recall,
            "precision_alert": prec_a,
            "precision_auto": prec_u,
            "delta_precision_alert_vs_auto": delta_prec,
            "review_rate": review_rate,
            "escape_rate": escape_rate,
        })

    return {
        "alert_level": alert_rows,
        "alert_profile": profile_rows,
        "autonomous_level": auto_rows,
        "alert_vs_autonomous": comparison_rows,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Step 3: Decision Profile
#  Complements Step 2 (confusion metrics) with operative decision logic:
#  how often each system outputs PASS / BLOCK / REVIEW, GT-conditional
#  counts, and behavioral shift relative to Baseline.
# ═══════════════════════════════════════════════════════════════════════

def compute_decision_profile(results: List[Dict]) -> Dict[str, Any]:
    """
    Step 3: Decision Profile for the three systems.

    Returns dict with four blocks:
        global         → Table 3A (decision counts + rates + escape + block_share)
        gt_pos_counts  → Table 3B (decision counts on GT_POS only)
        gt_neg_counts  → Table 3C (decision counts on GT_NEG only)
        vs_baseline    → Table 3D (delta rates vs LLM_Baseline)
    """
    n_total = len(results)

    # Pre-extract decisions + ground truth per system (reuse Step 2 systems)
    system_data: Dict[str, List[Tuple[Optional[str], bool]]] = {}
    for sys_name, dfn in _MODE_COMPARISON_SYSTEMS.items():
        entries = []
        for s in results:
            decision = dfn(s)
            gt = bool(s.get("gt_has_secret", False))
            entries.append((decision, gt))
        system_data[sys_name] = entries

    global_rows: List[Dict[str, Any]] = []
    gt_pos_rows: List[Dict[str, Any]] = []
    gt_neg_rows: List[Dict[str, Any]] = []

    # Per-system profiles (keyed for delta computation)
    rate_cache: Dict[str, Dict[str, Any]] = {}

    for sys_name, entries in system_data.items():
        n_missing = sum(1 for d, _ in entries if d is None)
        n_evaluable = n_total - n_missing

        # Global decision counts (evaluable only)
        n_pass = sum(1 for d, _ in entries if d == "PASS")
        n_block = sum(1 for d, _ in entries if d == "BLOCK")
        n_review = sum(1 for d, _ in entries if d == "REVIEW")

        pass_rate = _safe_div(n_pass, n_evaluable)
        block_rate = _safe_div(n_block, n_evaluable)
        review_rate = _safe_div(n_review, n_evaluable)

        # Escape rate: GT_POS with decision PASS / GT_POS evaluable
        gt_pos_eval = sum(1 for d, gt in entries if d is not None and gt)
        gt_pos_pass = sum(1 for d, gt in entries if d == "PASS" and gt)
        escape_rate = _safe_div(gt_pos_pass, gt_pos_eval)

        # Block share among alerts
        n_alerts = n_block + n_review
        block_share = _safe_div(n_block, n_alerts)

        row = {
            "mode": sys_name,
            "n_total": n_total,
            "n_evaluable": n_evaluable,
            "n_missing": n_missing,
            "pass_count": n_pass,
            "block_count": n_block,
            "review_count": n_review,
            "pass_rate": pass_rate,
            "block_rate": block_rate,
            "review_rate": review_rate,
            "escape_rate": escape_rate,
            "block_share_among_alerts": block_share,
        }
        global_rows.append(row)

        # Cache rates for delta computation
        rate_cache[sys_name] = {
            "pass_rate": pass_rate,
            "block_rate": block_rate,
            "review_rate": review_rate,
            "escape_rate": escape_rate,
            "block_share_among_alerts": block_share,
        }

        # ── GT_POS counts ──────────────────────────────────────────
        gt_pos_block = sum(1 for d, gt in entries if d == "BLOCK" and gt)
        gt_pos_review = sum(1 for d, gt in entries if d == "REVIEW" and gt)

        gt_pos_rows.append({
            "mode": sys_name,
            "n_gt_pos_evaluable": gt_pos_eval,
            "pass_count_gt_pos": gt_pos_pass,
            "block_count_gt_pos": gt_pos_block,
            "review_count_gt_pos": gt_pos_review,
        })

        # ── GT_NEG counts ──────────────────────────────────────────
        gt_neg_eval = sum(1 for d, gt in entries if d is not None and not gt)
        gt_neg_pass = sum(1 for d, gt in entries if d == "PASS" and not gt)
        gt_neg_block = sum(1 for d, gt in entries if d == "BLOCK" and not gt)
        gt_neg_review = sum(1 for d, gt in entries if d == "REVIEW" and not gt)

        gt_neg_rows.append({
            "mode": sys_name,
            "n_gt_neg_evaluable": gt_neg_eval,
            "pass_count_gt_neg": gt_neg_pass,
            "block_count_gt_neg": gt_neg_block,
            "review_count_gt_neg": gt_neg_review,
        })

    # ── Table 3D: Behavioral shift vs Baseline ─────────────────────
    baseline_rates = rate_cache.get("LLM_Baseline", {})
    vs_baseline_rows: List[Dict[str, Any]] = []

    def _delta(a: Optional[float], b: Optional[float]) -> Optional[float]:
        if a is None or b is None:
            return None
        return round(a - b, 4)

    for sys_name in ("Scanner", "LLM_Guardrails"):
        sys_rates = rate_cache.get(sys_name, {})
        vs_baseline_rows.append({
            "comparison": f"{sys_name}_vs_Baseline",
            "delta_pass_rate_vs_baseline": _delta(
                sys_rates.get("pass_rate"), baseline_rates.get("pass_rate"),
            ),
            "delta_block_rate_vs_baseline": _delta(
                sys_rates.get("block_rate"), baseline_rates.get("block_rate"),
            ),
            "delta_review_rate_vs_baseline": _delta(
                sys_rates.get("review_rate"), baseline_rates.get("review_rate"),
            ),
            "delta_escape_rate_vs_baseline": _delta(
                sys_rates.get("escape_rate"), baseline_rates.get("escape_rate"),
            ),
            "delta_block_share_among_alerts_vs_baseline": _delta(
                sys_rates.get("block_share_among_alerts"),
                baseline_rates.get("block_share_among_alerts"),
            ),
        })

    return {
        "global": global_rows,
        "gt_pos_counts": gt_pos_rows,
        "gt_neg_counts": gt_neg_rows,
        "vs_baseline": vs_baseline_rows,
    }


# ═══════════════════════════════════════════════════════════════════════
#  C. Legacy 4-mode comparison (hit-level predicates)
#     Kept for backward compatibility; Step 2 above is the authoritative
#     three-system mode comparison for the BA thesis.
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
    """Autonomous-Level: final_decision == BLOCK → positive."""
    gr = s.get("llm_guardrail")
    if gr is None:
        return None
    return gr.get("final_decision") == "BLOCK"


# ---- registry -------------------------------------------------------
# Decision functions reuse the Step 2 definitions above:
# _decision_scanner, _decision_baseline_system, _decision_guardrail_system

MODE_DEFS = {
    "Scanner": {
        "pred_fn": _pred_scanner,
        "decision_fn": _decision_scanner,
        "description": "Gitleaks + detect-secrets combined (scanner_hit)",
    },
    "LLM_Baseline": {
        "pred_fn": _pred_baseline,
        "decision_fn": _decision_baseline_system,
        "description": "LLM without guardrails (llm_baseline_hit)",
    },
    "Guardrails_Alert": {
        "pred_fn": _pred_guardrail_alert,
        "decision_fn": _decision_guardrail_system,
        "description": "LLM + Guardrails, alert-level: BLOCK or REVIEW = detection",
    },
    "Guardrails_Autonomous": {
        "pred_fn": _pred_guardrail_autonomous,
        "decision_fn": _decision_guardrail_system,
        "description": "LLM + Guardrails, autonomous: BLOCK only = detection",
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

    # -- Multi-trigger summary (from triggered_guardrails field) ----
    # Pipeline order for stable combination keys
    _PIPELINE_ORDER = ["G5", "G2", "G4", "G1", "G3"]

    all_trigger_lists: List[List[str]] = []
    for s in results:
        tg = _g(s, "llm_guardrail", "triggered_guardrails") or []
        all_trigger_lists.append(tg)

    # Per-guardrail trigger count (from triggered_guardrails)
    per_guardrail: Counter = Counter()
    for tg in all_trigger_lists:
        for g in tg:
            per_guardrail[g] += 1

    # Combination breakdown (sorted in pipeline order)
    combo_counter: Counter = Counter()
    for tg in all_trigger_lists:
        if not tg:
            continue
        sorted_tg = sorted(tg, key=lambda x: _PIPELINE_ORDER.index(x) if x in _PIPELINE_ORDER else 99)
        combo_counter["+".join(sorted_tg)] += 1

    samples_with_any = sum(1 for tg in all_trigger_lists if len(tg) >= 1)
    samples_multi    = sum(1 for tg in all_trigger_lists if len(tg) >= 2)
    samples_single   = sum(1 for tg in all_trigger_lists if len(tg) == 1)
    max_triggers     = max((len(tg) for tg in all_trigger_lists), default=0)

    kpis["triggered_guardrails_summary"] = {
        "samples_with_any_trigger_count": samples_with_any,
        "single_trigger_samples_count": samples_single,
        "multi_trigger_samples_count": samples_multi,
        "multi_trigger_rate": round(samples_multi / n, 4) if n else 0,
        "max_triggers_on_single_sample": max_triggers,
        "per_guardrail_trigger_count": {
            g: per_guardrail.get(g, 0) for g in _PIPELINE_ORDER
        },
        "trigger_combination_counts": dict(combo_counter.most_common()),
    }

    return kpis


# ═══════════════════════════════════════════════════════════════════════
#  Step 4: Guardrail KPIs (compact, operational)
#  Measures the intervention layer: bundle activity, per-guardrail
#  participation vs routing, G3 leakage containment, G5 fail-closed,
#  G6 pre-LLM hint coverage, and multi-trigger combinations.
# ═══════════════════════════════════════════════════════════════════════

_PIPELINE_ORDER = ["G5", "G2", "G4", "G1", "G3"]


def compute_guardrail_kpis_step4(results: List[Dict]) -> Dict[str, Any]:
    """
    Step 4: Compact Guardrail KPIs.

    Returns dict with five blocks:
        activity_summary       → 4A (bundle-level activity)
        per_guardrail          → 4B (trigger vs routing per G1–G5)
        g3                     → 4C (leakage containment)
        g5                     → 4D (schema / fail-closed)
        trigger_combinations   → 4E (top combination patterns)
    """
    n_total = len(results)
    n_evaluable = sum(1 for s in results if s.get("llm_guardrail") is not None)
    n_missing = n_total - n_evaluable

    # Only evaluable samples for all guardrail KPIs
    evaluable = [s for s in results if s.get("llm_guardrail") is not None]

    # Pre-extract trigger lists for evaluable samples
    trigger_lists: List[List[str]] = []
    for s in evaluable:
        tg = _g(s, "llm_guardrail", "triggered_guardrails") or []
        trigger_lists.append(tg)

    # ── 4A: Bundle Activity Summary ──────────────────────────────────
    samples_any = sum(1 for tg in trigger_lists if len(tg) >= 1)
    samples_single = sum(1 for tg in trigger_lists if len(tg) == 1)
    samples_multi = sum(1 for tg in trigger_lists if len(tg) >= 2)
    max_triggers = max((len(tg) for tg in trigger_lists), default=0)

    activity_summary = {
        "n_total_guardrail_samples": n_total,
        "n_evaluable_guardrail_samples": n_evaluable,
        "n_missing_guardrail_samples": n_missing,
        "samples_with_any_trigger_count": samples_any,
        "samples_with_any_trigger_rate": _safe_div(samples_any, n_evaluable),
        "single_trigger_samples_count": samples_single,
        "single_trigger_rate": _safe_div(samples_single, n_evaluable),
        "multi_trigger_samples_count": samples_multi,
        "multi_trigger_rate": _safe_div(samples_multi, n_evaluable),
        "max_triggers_on_single_sample": max_triggers,
    }

    # ── 4B: Per-Guardrail Activity ───────────────────────────────────
    # Count from triggered_guardrails (participation) and routed_by_guardrail (lead)
    trigger_counter: Counter = Counter()
    for tg in trigger_lists:
        for g in tg:
            trigger_counter[g] += 1

    routing_counter: Counter = Counter()
    for s in evaluable:
        rb = _g(s, "llm_guardrail", "routed_by_guardrail")
        if rb:
            routing_counter[rb] += 1

    per_guardrail_rows: List[Dict[str, Any]] = []
    for g in _PIPELINE_ORDER:
        tc = trigger_counter.get(g, 0)
        rc = routing_counter.get(g, 0)
        per_guardrail_rows.append({
            "guardrail": g,
            "trigger_count": tc,
            "trigger_rate": _safe_div(tc, n_evaluable),
            "routed_count": rc,
            "routed_rate": _safe_div(rc, n_evaluable),
        })

    # ── 4C: G3 Leakage KPIs (compact) ───────────────────────────────
    baseline_leak = sum(
        1 for s in evaluable
        if _g(s, "metrics", "leak_in_baseline") is True
    )
    g3_triggered = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g3_triggered") is True
    )
    residual_leak = sum(
        1 for s in evaluable
        if _g(s, "metrics", "leak_in_guardrail") is True
    )
    # Optional: G3 on GT_POS
    g3_on_gt_pos = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g3_triggered") is True
        and s.get("gt_has_secret")
    )
    gt_pos_evaluable = sum(1 for s in evaluable if s.get("gt_has_secret"))

    g3_kpis = {
        "baseline_leakage_count": baseline_leak,
        "baseline_leakage_rate": _safe_div(baseline_leak, n_evaluable),
        "g3_triggered_count": g3_triggered,
        "g3_triggered_rate": _safe_div(g3_triggered, n_evaluable),
        "residual_guardrail_leakage_count": residual_leak,
        "residual_guardrail_leakage_rate": _safe_div(residual_leak, n_evaluable),
        "residual_guardrail_leakage_share_of_baseline_leak": _safe_div(residual_leak, baseline_leak),
        "g3_on_gt_pos_count": g3_on_gt_pos,
        "g3_on_gt_pos_rate": _safe_div(g3_on_gt_pos, gt_pos_evaluable),
    }

    # ── 4D: G5 Schema / Fail-Closed KPIs (compact) ──────────────────
    schema_invalid = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "schema_valid") is False
    )
    g5_routed = routing_counter.get("G5", 0)
    g5_fail_closed_review = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "routed_by_guardrail") == "G5"
        and _g(s, "llm_guardrail", "final_decision") == "REVIEW"
    )

    g5_kpis = {
        "schema_invalid_count": schema_invalid,
        "schema_invalid_rate": _safe_div(schema_invalid, n_evaluable),
        "g5_routed_count": g5_routed,
        "g5_routed_rate": _safe_div(g5_routed, n_evaluable),
        "g5_fail_closed_review_count": g5_fail_closed_review,
        "g5_fail_closed_review_rate": _safe_div(g5_fail_closed_review, n_evaluable),
        "g5_fail_closed_review_share_of_g5": _safe_div(g5_fail_closed_review, g5_routed),
    }

    # ── 4F: G6 Pre-LLM Hint KPIs ───────────────────────────────────
    # G6 is a pre-LLM guardrail: it injects a hint into the user prompt
    # before the LLM call. It does not appear in triggered_guardrails.
    g6_hint_injected = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g6_hint_injected") is True
    )
    g6_no_hint = n_evaluable - g6_hint_injected

    # Detection rate WITH G6 hint (pred_has_secret among G6-hinted samples)
    g6_hint_detected = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g6_hint_injected") is True
        and _g(s, "llm_guardrail", "pred_has_secret") is True
    )
    # Detection rate WITHOUT G6 hint (pred_has_secret among non-hinted samples)
    g6_no_hint_detected = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g6_hint_injected") is not True
        and _g(s, "llm_guardrail", "pred_has_secret") is True
    )

    # G6 hint on GT_POS samples
    g6_hint_on_gt_pos = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g6_hint_injected") is True
        and s.get("gt_has_secret")
    )
    # G6 hint on GT_NEG samples (potential FP concern)
    g6_hint_on_gt_neg = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g6_hint_injected") is True
        and not s.get("gt_has_secret")
    )

    # Schema validity among G6-hinted samples (G5 compatibility check)
    g6_hint_schema_valid = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g6_hint_injected") is True
        and _g(s, "llm_guardrail", "schema_valid") is True
    )
    g6_hint_schema_fail = sum(
        1 for s in evaluable
        if _g(s, "llm_guardrail", "g6_hint_injected") is True
        and _g(s, "llm_guardrail", "schema_valid") is False
    )

    g6_kpis = {
        "g6_hint_injected_count": g6_hint_injected,
        "g6_hint_injected_rate": _safe_div(g6_hint_injected, n_evaluable),
        "g6_no_hint_count": g6_no_hint,
        "g6_hint_detected_count": g6_hint_detected,
        "g6_hint_detection_rate": _safe_div(g6_hint_detected, g6_hint_injected),
        "g6_no_hint_detected_count": g6_no_hint_detected,
        "g6_no_hint_detection_rate": _safe_div(g6_no_hint_detected, g6_no_hint),
        "g6_hint_on_gt_pos_count": g6_hint_on_gt_pos,
        "g6_hint_on_gt_pos_rate": _safe_div(g6_hint_on_gt_pos, gt_pos_evaluable),
        "g6_hint_on_gt_neg_count": g6_hint_on_gt_neg,
        "g6_hint_schema_valid_count": g6_hint_schema_valid,
        "g6_hint_schema_fail_count": g6_hint_schema_fail,
        "g6_hint_schema_valid_rate": _safe_div(g6_hint_schema_valid, g6_hint_injected),
    }

    # ── 4E: Trigger Combination Summary (top 10) ────────────────────
    combo_counter: Counter = Counter()
    for tg in trigger_lists:
        if not tg:
            continue
        sorted_tg = sorted(
            tg,
            key=lambda x: _PIPELINE_ORDER.index(x) if x in _PIPELINE_ORDER else 99,
        )
        combo_counter["+".join(sorted_tg)] += 1

    combo_rows: List[Dict[str, Any]] = []
    for combo, cnt in combo_counter.most_common(10):
        combo_rows.append({
            "trigger_combination": combo,
            "count": cnt,
            "rate": _safe_div(cnt, n_evaluable),
        })

    return {
        "activity_summary": activity_summary,
        "per_guardrail": per_guardrail_rows,
        "g3": g3_kpis,
        "g5": g5_kpis,
        "g6": g6_kpis,
        "trigger_combinations": combo_rows,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Step 5: Failure-Mode PRI Analysis
#  Evaluates the guardrail bundle as a control layer via
#  Prevalence / Intervention / Residual per failure mode.
# ═══════════════════════════════════════════════════════════════════════

def compute_failure_mode_pri(results: List[Dict]) -> Dict[str, Any]:
    """
    Step 5: Failure-Mode PRI (Prevalence / Intervention / Residual).

    Returns dict with three blocks:
        summary      → 5A (one row per FM with PRI counts/rates)
        definitions  → 5B (field logic per FM for traceability)
        coverage     → 5C (observability and multi-FM notes)
    """
    # ── Evaluable populations ─────────────────────────────────────
    # FM1/FM2/FM4 require baseline_failure_modes.analysis_executed
    bfm_evaluable = [
        s for s in results
        if _g(s, "baseline_failure_modes", "analysis_executed") is True
    ]
    n_bfm = len(bfm_evaluable)

    # FM3 requires metrics.leak_in_baseline to be present
    fm3_evaluable = [
        s for s in results
        if _g(s, "metrics", "leak_in_baseline") is not None
    ]
    n_fm3 = len(fm3_evaluable)

    # FM5 requires llm_guardrail.schema_valid to be present
    fm5_evaluable = [
        s for s in results
        if _g(s, "llm_guardrail", "schema_valid") is not None
    ]
    n_fm5 = len(fm5_evaluable)

    # ── Helper: check intervention (triggered OR routed) ──────────
    def _intervened(s: Dict, guardrail: str) -> bool:
        gr = s.get("llm_guardrail") or {}
        triggered = gr.get("triggered_guardrails") or []
        routed = gr.get("routed_by_guardrail")
        return guardrail in triggered or routed == guardrail

    # ══════════════════════════════════════════════════════════════
    #  FM1 — Evidence / Location Failure
    # ══════════════════════════════════════════════════════════════
    fm1_prev = [s for s in bfm_evaluable
                if _g(s, "baseline_failure_modes", "g1_valid") is False]
    fm1_prev_n = len(fm1_prev)
    fm1_interv_n = sum(1 for s in fm1_prev if _intervened(s, "G1"))

    # Residual: guardrail-side g1_valid on prevalence cases
    fm1_resid_n = sum(1 for s in fm1_prev
                      if _g(s, "llm_guardrail", "g1_valid") is False)

    # ══════════════════════════════════════════════════════════════
    #  FM2 — Untrusted-Input Influence
    # ══════════════════════════════════════════════════════════════
    fm2_prev = [s for s in bfm_evaluable
                if _g(s, "baseline_failure_modes", "g2_valid") is False]
    fm2_prev_n = len(fm2_prev)
    fm2_interv_n = sum(1 for s in fm2_prev if _intervened(s, "G2"))
    # FM2 residual intentionally not computed — not robustly observable.

    # ══════════════════════════════════════════════════════════════
    #  FM3 — Secret Leakage in Output
    # ══════════════════════════════════════════════════════════════
    fm3_prev = [s for s in fm3_evaluable
                if _g(s, "metrics", "leak_in_baseline") is True]
    fm3_prev_n = len(fm3_prev)
    fm3_interv_n = sum(1 for s in fm3_prev
                       if _g(s, "llm_guardrail", "g3_triggered") is True)
    fm3_resid_n = sum(1 for s in fm3_prev
                      if _g(s, "metrics", "leak_in_guardrail") is True)

    # ══════════════════════════════════════════════════════════════
    #  FM4 — Uncertainty Miscalibration
    # ══════════════════════════════════════════════════════════════
    fm4_prev = [s for s in bfm_evaluable
                if _g(s, "baseline_failure_modes", "g4_details",
                      "should_review") is True]
    fm4_prev_n = len(fm4_prev)
    fm4_interv_n = sum(1 for s in fm4_prev if _intervened(s, "G4"))

    # Residual: guardrail-side g4_details.should_review on prevalence cases
    # Observable but partial — the field measures structural presence of
    # miscalibration indicators in the guardrail output, not whether the
    # bundle's routing action adequately addressed the operational impact.
    fm4_resid_n = sum(1 for s in fm4_prev
                      if _g(s, "llm_guardrail", "g4_details",
                            "should_review") is True)

    # ══════════════════════════════════════════════════════════════
    #  FM5 — Schema / Output Failure  (asymmetric operationalization)
    # ══════════════════════════════════════════════════════════════
    # FM5 manifests on the guardrail/structured-output side:
    # baseline schema_valid=false is 0 in practice because the baseline
    # does not undergo the same schema-validation pipeline.
    # Prevalence is therefore measured on the guardrail output side.
    fm5_prev = [s for s in fm5_evaluable
                if _g(s, "llm_guardrail", "schema_valid") is False]
    fm5_prev_n = len(fm5_prev)
    fm5_interv_n = sum(1 for s in fm5_prev if _intervened(s, "G5"))
    # FM5 residual intentionally not computed — not robustly observable.

    # ══════════════════════════════════════════════════════════════
    #  Build output tables
    # ══════════════════════════════════════════════════════════════

    def _pri_row(
        fm: str, guardrail: str, n_eval: int,
        prev_n: int, interv_n: int,
        resid_n, observability: str,
    ) -> Dict[str, Any]:
        return {
            "failure_mode": fm,
            "mapped_guardrail": guardrail,
            "n_baseline_evaluable": n_eval,
            "prevalence_count": prev_n,
            "prevalence_rate": _safe_div(prev_n, n_eval),
            "intervention_count": interv_n if prev_n > 0 else None,
            "intervention_rate_given_prevalence": (
                _safe_div(interv_n, prev_n) if prev_n > 0 else None
            ),
            "residual_count": resid_n,
            "residual_rate_given_prevalence": (
                _safe_div(resid_n, prev_n) if resid_n is not None and prev_n > 0
                else None
            ),
            "residual_observability": observability if prev_n > 0 else "n/a",
        }

    # ── 5A: PRI Summary ──────────────────────────────────────────
    summary = [
        _pri_row("FM1_evidence_location", "G1", n_bfm,
                 fm1_prev_n, fm1_interv_n, fm1_resid_n, "partial"),
        _pri_row("FM2_untrusted_input", "G2", n_bfm,
                 fm2_prev_n, fm2_interv_n,
                 None,
                 "not_robustly_observable"),
        _pri_row("FM3_secret_leakage", "G3", n_fm3,
                 fm3_prev_n, fm3_interv_n, fm3_resid_n, "direct"),
        _pri_row("FM4_uncertainty_miscalibration", "G4", n_bfm,
                 fm4_prev_n, fm4_interv_n, fm4_resid_n, "partial"),
        _pri_row("FM5_schema_output_failure", "G5", n_fm5,
                 fm5_prev_n, fm5_interv_n, None,
                 "not_robustly_observable"),
    ]

    # ── 5B: PRI Definitions ──────────────────────────────────────
    definitions = [
        {
            "failure_mode": "FM1_evidence_location",
            "mapped_guardrail": "G1",
            "prevalence_field_logic":
                "baseline_failure_modes.g1_valid == false",
            "intervention_field_logic":
                "G1 in llm_guardrail.triggered_guardrails "
                "OR llm_guardrail.routed_by_guardrail == G1",
            "residual_field_logic":
                "llm_guardrail.g1_valid == false (on prevalence cases)",
            "notes":
                "Residual observed via guardrail-side g1_valid flag, which "
                "is structurally analogous but not identical to the baseline "
                "g1_valid check. Interpretation should account for this "
                "structural difference.",
        },
        {
            "failure_mode": "FM2_untrusted_input",
            "mapped_guardrail": "G2",
            "prevalence_field_logic":
                "baseline_failure_modes.g2_valid == false",
            "intervention_field_logic":
                "G2 in llm_guardrail.triggered_guardrails "
                "OR llm_guardrail.routed_by_guardrail == G2",
            "residual_field_logic":
                "Not robustly observable. Guardrail-side g2_valid exists "
                "but lacks independent validation of FM2 resolution.",
            "notes":
                "Residual not reported: guardrail-side g2_valid is "
                "structurally available but does not constitute a robust "
                "independent measure of whether untrusted-input influence "
                "was resolved. Additionally, zero prevalence in this "
                "dataset means PRI is structurally not evaluable for FM2.",
        },
        {
            "failure_mode": "FM3_secret_leakage",
            "mapped_guardrail": "G3",
            "prevalence_field_logic":
                "metrics.leak_in_baseline == true",
            "intervention_field_logic":
                "llm_guardrail.g3_triggered == true",
            "residual_field_logic":
                "metrics.leak_in_guardrail == true (on prevalence cases)",
            "notes":
                "All three PRI components are directly and independently "
                "observable via separate fields. Leakage detection is based "
                "on gt_secret_value string matching in model output.",
        },
        {
            "failure_mode": "FM4_uncertainty_miscalibration",
            "mapped_guardrail": "G4",
            "prevalence_field_logic":
                "baseline_failure_modes.g4_details.should_review == true",
            "intervention_field_logic":
                "G4 in llm_guardrail.triggered_guardrails "
                "OR llm_guardrail.routed_by_guardrail == G4",
            "residual_field_logic":
                "llm_guardrail.g4_details.should_review == true "
                "(on prevalence cases)",
            "notes":
                "Residual is indicative, not definitive. The guardrail-side "
                "should_review flag measures structural presence of "
                "miscalibration indicators, not whether the bundle's routing "
                "action resolved the operational impact. Unlike FM3, there "
                "is no independent objective measure of FM4 resolution.",
        },
        {
            "failure_mode": "FM5_schema_output_failure",
            "mapped_guardrail": "G5",
            "prevalence_field_logic":
                "llm_guardrail.schema_valid == false "
                "(asymmetric: guardrail-side, not baseline-side)",
            "intervention_field_logic":
                "G5 in llm_guardrail.triggered_guardrails "
                "OR llm_guardrail.routed_by_guardrail == G5",
            "residual_field_logic":
                "Not robustly observable. No independent post-intervention "
                "field measures whether the schema failure persists as a "
                "problematic end state after G5 treatment.",
            "notes":
                "Asymmetric operationalization: FM5 prevalence is observed "
                "on the guardrail/structured-output side only. The baseline "
                "does not undergo schema validation. Residual is not "
                "reported because absence of G5 routing does not robustly "
                "indicate a persisting problematic end state.",
        },
    ]

    # ── 5C: PRI Coverage / Observability ─────────────────────────
    coverage = [
        {
            "failure_mode": "FM1_evidence_location",
            "mapped_guardrail": "G1",
            "n_baseline_evaluable": n_bfm,
            "prevalence_base_n": fm1_prev_n,
            "residual_observability": "partial",
            "multi_fm_interference_note":
                "Multiple guardrails may act on the same sample. "
                "Observed FM1 residual may reflect bundle-wide output "
                "quality rather than G1-specific correction.",
            "notes":
                "Residual based on guardrail-side g1_valid, which is "
                "structurally analogous but not identical to the baseline "
                "validity check. G1 did not trigger in this dataset; "
                "observed residual=0 may reflect overall guardrail output "
                "quality rather than targeted G1 intervention.",
        },
        {
            "failure_mode": "FM2_untrusted_input",
            "mapped_guardrail": "G2",
            "n_baseline_evaluable": n_bfm,
            "prevalence_base_n": fm2_prev_n,
            "residual_observability": "not_robustly_observable",
            "multi_fm_interference_note":
                "Zero prevalence in this dataset. PRI not structurally "
                "evaluable.",
            "notes":
                "No baseline samples exhibited g2_valid=false. Residual "
                "not reported: guardrail-side g2_valid lacks independent "
                "validation of FM2 resolution.",
        },
        {
            "failure_mode": "FM3_secret_leakage",
            "mapped_guardrail": "G3",
            "n_baseline_evaluable": n_fm3,
            "prevalence_base_n": fm3_prev_n,
            "residual_observability": "direct",
            "multi_fm_interference_note":
                "G3 leakage detection operates independently of other "
                "guardrails via gt_secret_value string matching.",
            "notes":
                "All three PRI components observed via independent fields. "
                "No structural cross-dependency with other guardrails.",
        },
        {
            "failure_mode": "FM4_uncertainty_miscalibration",
            "mapped_guardrail": "G4",
            "n_baseline_evaluable": n_bfm,
            "prevalence_base_n": fm4_prev_n,
            "residual_observability": "partial",
            "multi_fm_interference_note":
                "Potential overlap with G1 in ambiguity-heavy contexts. "
                "Multiple guardrails may act on the same sample; "
                "intervention attribution not always exclusive to G4.",
            "notes":
                "Residual is indicative only. Guardrail-side should_review "
                "measures structural miscalibration presence, not whether "
                "routing resolved the operational impact. No independent "
                "objective measure of FM4 resolution available.",
        },
        {
            "failure_mode": "FM5_schema_output_failure",
            "mapped_guardrail": "G5",
            "n_baseline_evaluable": n_fm5,
            "prevalence_base_n": fm5_prev_n,
            "residual_observability": "not_robustly_observable",
            "multi_fm_interference_note":
                "G5 operates first in pipeline (G5 → G2 → G4 → G1 → G3). "
                "No structural overlap with other guardrails for schema "
                "failures.",
            "notes":
                "Asymmetric operationalization: prevalence observed on "
                "guardrail output side only. Residual not reported: no "
                "independent post-intervention field to assess whether "
                "schema failure persists as a problematic end state.",
        },
    ]

    return {
        "summary": summary,
        "definitions": definitions,
        "coverage": coverage,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Step 6: Slice Analysis (segmented evaluation)
#  Segments the main findings from Steps 2, 3, and 5 by dataset slices.
# ═══════════════════════════════════════════════════════════════════════

# ---- Slice definitions ---------------------------------------------------

_SLICE_DEFINITIONS: List[Dict[str, str]] = [
    # A. Base vs Stress
    {
        "slice_name": "base",
        "definition_logic": "condition == B0",
        "notes": "Baseline dataset: standard positive and negative samples.",
    },
    {
        "slice_name": "stress",
        "definition_logic": "condition starts with E (E1-B, E2-A, E3-A, E3-B)",
        "notes": "All stress/perturbation samples. All are GT positive.",
    },
    # B. Negative-type slices (within base)
    {
        "slice_name": "neg_clean",
        "definition_logic": "control_type == no_secret",
        "notes": "Control-specific negative subgroup. Not intended as exhaustive partition of all GT-negative cases.",
    },
    {
        "slice_name": "neg_decoy",
        "definition_logic": "control_type == decoy",
        "notes": "Control-specific negative subgroup (decoy/misleading patterns). Not intended as exhaustive partition of all GT-negative cases.",
    },
    # C. Data source (covers positive samples only; NEG_* controls excluded)
    {
        "slice_name": "real",
        "definition_logic": "sample_id starts with REAL",
        "notes": "Samples derived from real-world code repositories. Does not cover NEG_* control samples — real + synthetic is not a full partition of the dataset.",
    },
    {
        "slice_name": "synthetic",
        "definition_logic": "sample_id starts with SYNTH",
        "notes": "Synthetically generated samples. Does not cover NEG_* control samples — real + synthetic is not a full partition of the dataset.",
    },
    # D. Stress subtypes
    {
        "slice_name": "stress_untrusted_input",
        "definition_logic": "condition == E1-B",
        "notes": "Stress samples targeting FM2 (untrusted-input influence).",
    },
    {
        "slice_name": "stress_uncertainty",
        "definition_logic": "condition == E2-A",
        "notes": "Stress samples targeting FM4 (uncertainty/miscalibration).",
    },
    {
        "slice_name": "stress_multi_fm",
        "definition_logic": "condition == E3-A",
        "notes": "Multi-FM stress (FM6/general, FM1/FM3/FM5 targeted).",
    },
    {
        "slice_name": "stress_hardened",
        "definition_logic": "condition == E3-B",
        "notes": "Hardened positive samples with obfuscation patterns.",
    },
]


def _assign_slices(s: Dict) -> List[str]:
    """Return list of slice names a sample belongs to."""
    slices = []
    cond = s.get("condition", "")
    ct = s.get("control_type")
    sid = s.get("sample_id", "")

    # A. Base vs Stress (mutually exclusive)
    if cond == "B0":
        slices.append("base")
    elif cond.startswith("E"):
        slices.append("stress")

    # B. Negative types
    if ct == "no_secret":
        slices.append("neg_clean")
    elif ct == "decoy":
        slices.append("neg_decoy")

    # C. Data source
    if sid.startswith("REAL"):
        slices.append("real")
    elif sid.startswith("SYNTH"):
        slices.append("synthetic")

    # D. Stress subtypes (only for stress samples)
    if cond == "E1-B":
        slices.append("stress_untrusted_input")
    elif cond == "E2-A":
        slices.append("stress_uncertainty")
    elif cond == "E3-A":
        slices.append("stress_multi_fm")
    elif cond == "E3-B":
        slices.append("stress_hardened")

    return slices


def compute_slice_analysis(results: List[Dict]) -> Dict[str, Any]:
    """
    Step 6: Slice Analysis.

    Segments findings from Steps 2, 3, and 5 by dataset slices.

    Returns dict with three blocks:
        performance   → 6A (slice × mode performance)
        pri_spotlight → 6B (FM3 + FM4 PRI per slice)
        definitions   → 6C (slice definition table)
    """
    # ── Group samples by slice ────────────────────────────────────
    slice_samples: Dict[str, List[Dict]] = {}
    for s in results:
        for sl in _assign_slices(s):
            slice_samples.setdefault(sl, []).append(s)

    # Stable slice order matching _SLICE_DEFINITIONS
    slice_order = [d["slice_name"] for d in _SLICE_DEFINITIONS]

    # ── 6A: Performance per slice × mode ─────────────────────────
    performance_rows: List[Dict[str, Any]] = []

    for sl_name in slice_order:
        samples = slice_samples.get(sl_name, [])
        if not samples:
            continue
        sl_n = len(samples)

        for sys_name, dfn in _MODE_COMPARISON_SYSTEMS.items():
            # Collect decisions
            entries = []
            for s in samples:
                decision = dfn(s)
                gt = bool(s.get("gt_has_secret", False))
                entries.append((decision, gt))

            evaluable = [(d, gt) for d, gt in entries if d is not None]
            n_eval = len(evaluable)
            if n_eval == 0:
                continue

            # Alert-level: BLOCK|REVIEW = positive
            tp_a = sum(1 for d, gt in evaluable if d in ("BLOCK", "REVIEW") and gt)
            fp_a = sum(1 for d, gt in evaluable if d in ("BLOCK", "REVIEW") and not gt)
            fn_a = sum(1 for d, gt in evaluable if d == "PASS" and gt)
            tn_a = sum(1 for d, gt in evaluable if d == "PASS" and not gt)

            # Autonomous-level: BLOCK only = positive
            tp_u = sum(1 for d, gt in evaluable if d == "BLOCK" and gt)
            fp_u = sum(1 for d, gt in evaluable if d == "BLOCK" and not gt)
            fn_u = sum(1 for d, gt in evaluable if d in ("REVIEW", "PASS") and gt)
            tn_u = sum(1 for d, gt in evaluable if d in ("REVIEW", "PASS") and not gt)

            # Decision profile counts
            block_n = sum(1 for d, _ in evaluable if d == "BLOCK")
            review_n = sum(1 for d, _ in evaluable if d == "REVIEW")
            pass_n = sum(1 for d, _ in evaluable if d == "PASS")

            # Escape rate: FN_alert / gt_pos_evaluable
            gt_pos_eval = sum(1 for _, gt in evaluable if gt)

            performance_rows.append({
                "slice_name": sl_name,
                "slice_n": sl_n,
                "mode": sys_name,
                "n_evaluable": n_eval,
                "recall_alert": _safe_div(tp_a, tp_a + fn_a),
                "precision_alert": _safe_div(tp_a, tp_a + fp_a),
                "recall_auto": _safe_div(tp_u, tp_u + fn_u),
                "precision_auto": _safe_div(tp_u, tp_u + fp_u),
                "escape_rate": _safe_div(fn_a, gt_pos_eval),
                "review_rate": _safe_div(review_n, n_eval),
                "block_rate": _safe_div(block_n, n_eval),
                "pass_rate": _safe_div(pass_n, n_eval),
            })

    # ── 6B: PRI Spotlight per slice (FM3 + FM4) ─────────────────
    pri_rows: List[Dict[str, Any]] = []

    for sl_name in slice_order:
        samples = slice_samples.get(sl_name, [])
        if not samples:
            continue
        sl_n = len(samples)

        # FM3 — Secret Leakage
        fm3_eval = [s for s in samples
                    if _g(s, "metrics", "leak_in_baseline") is not None]
        fm3_prev = [s for s in fm3_eval
                    if _g(s, "metrics", "leak_in_baseline") is True]
        fm3_prev_n = len(fm3_prev)
        fm3_interv_n = sum(1 for s in fm3_prev
                           if _g(s, "llm_guardrail", "g3_triggered") is True)
        fm3_resid_n = sum(1 for s in fm3_prev
                          if _g(s, "metrics", "leak_in_guardrail") is True)

        # FM4 — Uncertainty Miscalibration
        fm4_eval = [s for s in samples
                    if _g(s, "baseline_failure_modes",
                          "analysis_executed") is True]
        fm4_prev = [s for s in fm4_eval
                    if _g(s, "baseline_failure_modes", "g4_details",
                          "should_review") is True]
        fm4_prev_n = len(fm4_prev)
        fm4_interv_n = sum(1 for s in fm4_prev
                           if "G4" in (_g(s, "llm_guardrail",
                                         "triggered_guardrails") or [])
                           or _g(s, "llm_guardrail",
                                 "routed_by_guardrail") == "G4")

        row: Dict[str, Any] = {
            "slice_name": sl_name,
            "slice_n": sl_n,
            "fm3_prevalence_count": fm3_prev_n,
            "fm3_prevalence_rate": _safe_div(fm3_prev_n, len(fm3_eval))
                if fm3_eval else None,
            "fm3_intervention_rate_given_prevalence":
                _safe_div(fm3_interv_n, fm3_prev_n),
            "fm3_residual_rate_given_prevalence":
                _safe_div(fm3_resid_n, fm3_prev_n),
            "fm4_prevalence_count": fm4_prev_n,
            "fm4_prevalence_rate": _safe_div(fm4_prev_n, len(fm4_eval))
                if fm4_eval else None,
            "fm4_intervention_rate_given_prevalence":
                _safe_div(fm4_interv_n, fm4_prev_n),
        }
        pri_rows.append(row)

    # ── 6C: Definitions ──────────────────────────────────────────
    definitions = list(_SLICE_DEFINITIONS)

    return {
        "performance": performance_rows,
        "pri_spotlight": pri_rows,
        "definitions": definitions,
    }


# ═══════════════════════════════════════════════════════════════════════
#  E. Slice metrics  (Section C)  [legacy]
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
    mode_comparison: Optional[Dict[str, Any]] = None,
    decision_profile: Optional[Dict[str, Any]] = None,
    guardrail_kpis_step4: Optional[Dict[str, Any]] = None,
    failure_mode_pri: Optional[Dict[str, Any]] = None,
    slice_analysis: Optional[Dict[str, Any]] = None,
    config: Optional[Dict] = None,
    include_legacy: bool = True,
    include_legacy_guardrail_details: bool = True,
) -> str:
    """Generate evaluation_summary.md — purely descriptive, no interpretation."""
    parts: List[str] = []

    # ── Title ──────────────────────────────────────────────────────
    run_id = (config or {}).get("run_id") or dataset_summary.get("run_id") or "unknown"
    parts.append(f"# Evaluation Summary — {run_id}\n")
    parts.append(f"Generated from {dataset_summary.get('total_samples', '?')} samples.\n")

    # ── Definitions ────────────────────────────────────────────────
    parts.append("## Metric Definitions\n")
    parts.append("""\
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

    # ── Mode Comparison — Three Systems × Two Views ────────────────
    if mode_comparison:
        parts.append("## Mode Comparison — Three Systems × Two Views\n")

        # Table 2A: Alert-Level Confusion Metrics
        parts.append("### Table 2A — Alert-Level Confusion Metrics\n")
        h2a = ["Mode", "n_total", "n_eval", "n_miss",
               "TP", "FP", "TN", "FN",
               "Precision", "Recall", "F1", "Specificity"]
        rows_2a = []
        for r in mode_comparison.get("alert_level", []):
            rows_2a.append([
                r["mode"], r["n_total"], r["n_evaluable"], r["n_missing"],
                r["tp_alert"], r["fp_alert"], r["tn_alert"], r["fn_alert"],
                _fmt(r["precision_alert"]), _fmt(r["recall_alert"]),
                _fmt(r["f1_alert"]), _fmt(r["specificity_alert"]),
            ])
        parts.append(_md_table(h2a, rows_2a))
        parts.append("")

        # Table 2B: Alert-Level Decision Profile
        parts.append("### Table 2B — Alert-Level Decision Profile\n")
        h2b = ["Mode", "n_total", "n_eval", "n_miss",
               "Pass Rate", "Block Rate", "Review Rate", "Escape Rate"]
        rows_2b = []
        for r in mode_comparison.get("alert_profile", []):
            rows_2b.append([
                r["mode"], r["n_total"], r["n_evaluable"], r["n_missing"],
                _fmt(r["pass_rate"]), _fmt(r["block_rate"]),
                _fmt(r["review_rate"]), _fmt(r["escape_rate"]),
            ])
        parts.append(_md_table(h2b, rows_2b))
        parts.append("")

        # Table 2C: Autonomous-Level Confusion Metrics
        parts.append("### Table 2C — Autonomous-Level Confusion Metrics\n")
        h2c = ["Mode", "n_total", "n_eval", "n_miss",
               "TP", "FP", "TN", "FN",
               "Precision", "Recall", "F1", "Specificity"]
        rows_2c = []
        for r in mode_comparison.get("autonomous_level", []):
            rows_2c.append([
                r["mode"], r["n_total"], r["n_evaluable"], r["n_missing"],
                r["tp_auto"], r["fp_auto"], r["tn_auto"], r["fn_auto"],
                _fmt(r["precision_auto"]), _fmt(r["recall_auto"]),
                _fmt(r["f1_auto"]), _fmt(r["specificity_auto"]),
            ])
        parts.append(_md_table(h2c, rows_2c))
        parts.append("")

        # Table 2D: Alert vs Autonomous Comparison
        parts.append("### Table 2D — Alert vs Autonomous Comparison\n")
        h2d = ["Mode", "Recall Alert", "Recall Auto", "Δ Recall",
               "Precision Alert", "Precision Auto", "Δ Precision",
               "Review Rate", "Escape Rate"]
        rows_2d = []
        for r in mode_comparison.get("alert_vs_autonomous", []):
            rows_2d.append([
                r["mode"],
                _fmt(r["recall_alert"]), _fmt(r["recall_auto"]),
                _fmt(r["delta_recall_alert_vs_auto"]),
                _fmt(r["precision_alert"]), _fmt(r["precision_auto"]),
                _fmt(r["delta_precision_alert_vs_auto"]),
                _fmt(r["review_rate"]), _fmt(r["escape_rate"]),
            ])
        parts.append(_md_table(h2d, rows_2d))
        parts.append("")

    # ── Step 3: Decision / Behavior Profile ────────────────────────
    if decision_profile:
        parts.append("## Step 3 — Decision Profile\n")
        parts.append(
            "Step 3 shows the **operative decision behavior** of each system — "
            "how often it outputs PASS, BLOCK, or REVIEW, and how this shifts "
            "relative to the Baseline. "
            "`escape_rate` appears here intentionally alongside Step 2: "
            "in Step 2 it serves as an alert-level safety metric, "
            "here it captures the system's tendency to let GT_POS samples pass "
            "as an operational behavior signal.\n"
        )

        # Table 3A: Global Decision Profile
        parts.append("### 3A. Global Decision Profile\n")
        h3a = ["Mode", "n_total", "n_eval", "n_miss",
               "PASS", "BLOCK", "REVIEW",
               "Pass Rate", "Block Rate", "Review Rate",
               "Escape Rate", "Block Share"]
        rows_3a = []
        for r in decision_profile.get("global", []):
            rows_3a.append([
                r["mode"], r["n_total"], r["n_evaluable"], r["n_missing"],
                r["pass_count"], r["block_count"], r["review_count"],
                _fmt(r["pass_rate"]), _fmt(r["block_rate"]),
                _fmt(r["review_rate"]), _fmt(r["escape_rate"]),
                _fmt(r["block_share_among_alerts"]),
            ])
        parts.append(_md_table(h3a, rows_3a))
        parts.append("")

        # Table 3B: Decision Counts on GT_POS
        parts.append("### 3B. Decision Counts on GT_POS\n")
        h3b = ["Mode", "n_gt_pos_eval", "PASS", "BLOCK", "REVIEW"]
        rows_3b = []
        for r in decision_profile.get("gt_pos_counts", []):
            rows_3b.append([
                r["mode"], r["n_gt_pos_evaluable"],
                r["pass_count_gt_pos"], r["block_count_gt_pos"],
                r["review_count_gt_pos"],
            ])
        parts.append(_md_table(h3b, rows_3b))
        parts.append("")

        # Table 3C: Decision Counts on GT_NEG
        parts.append("### 3C. Decision Counts on GT_NEG\n")
        h3c = ["Mode", "n_gt_neg_eval", "PASS", "BLOCK", "REVIEW"]
        rows_3c = []
        for r in decision_profile.get("gt_neg_counts", []):
            rows_3c.append([
                r["mode"], r["n_gt_neg_evaluable"],
                r["pass_count_gt_neg"], r["block_count_gt_neg"],
                r["review_count_gt_neg"],
            ])
        parts.append(_md_table(h3c, rows_3c))
        parts.append("")

        # Table 3D: Behavioral Shift vs Baseline
        parts.append("### 3D. Behavioral Shift vs Baseline\n")
        h3d = ["Comparison", "Δ Pass Rate", "Δ Block Rate", "Δ Review Rate",
               "Δ Escape Rate", "Δ Block Share"]
        rows_3d = []
        for r in decision_profile.get("vs_baseline", []):
            rows_3d.append([
                r["comparison"],
                _fmt(r["delta_pass_rate_vs_baseline"]),
                _fmt(r["delta_block_rate_vs_baseline"]),
                _fmt(r["delta_review_rate_vs_baseline"]),
                _fmt(r["delta_escape_rate_vs_baseline"]),
                _fmt(r.get("delta_block_share_among_alerts_vs_baseline")),
            ])
        parts.append(_md_table(h3d, rows_3d))
        parts.append("")

    # ── Step 4: Guardrail KPIs ──────────────────────────────────────
    if guardrail_kpis_step4:
        parts.append("## Step 4 — Guardrail KPIs\n")
        parts.append(
            "Operational activity of the guardrail bundle. "
            "Measures intervention frequency, per-guardrail participation "
            "vs routing authority, leakage containment (G3), "
            "and fail-closed behavior (G5).\n"
        )

        # 4A: Bundle Activity Summary
        act = guardrail_kpis_step4.get("activity_summary", {})
        parts.append("### 4A. Bundle Activity Summary\n")
        h4a = ["Metric", "Value"]
        rows_4a = [
            ["n_total_guardrail_samples", str(act.get("n_total_guardrail_samples", "?"))],
            ["n_evaluable_guardrail_samples", str(act.get("n_evaluable_guardrail_samples", "?"))],
            ["n_missing_guardrail_samples", str(act.get("n_missing_guardrail_samples", "?"))],
            ["samples_with_any_trigger", f"{act.get('samples_with_any_trigger_count', '?')} ({_fmt(act.get('samples_with_any_trigger_rate'))})"],
            ["single_trigger_samples", f"{act.get('single_trigger_samples_count', '?')} ({_fmt(act.get('single_trigger_rate'))})"],
            ["multi_trigger_samples", f"{act.get('multi_trigger_samples_count', '?')} ({_fmt(act.get('multi_trigger_rate'))})"],
            ["max_triggers_on_single_sample", str(act.get("max_triggers_on_single_sample", "?"))],
        ]
        parts.append(_md_table(h4a, rows_4a))
        parts.append("")

        # 4B: Per-Guardrail Activity
        parts.append("### 4B. Per-Guardrail Activity\n")
        h4b = ["Guardrail", "Trigger Count", "Trigger Rate",
               "Routed Count", "Routed Rate"]
        rows_4b = []
        for r in guardrail_kpis_step4.get("per_guardrail", []):
            rows_4b.append([
                r["guardrail"], r["trigger_count"],
                _fmt(r["trigger_rate"]),
                r["routed_count"], _fmt(r["routed_rate"]),
            ])
        parts.append(_md_table(h4b, rows_4b))
        parts.append("")

        # 4C: G3 Leakage KPIs
        g3 = guardrail_kpis_step4.get("g3", {})
        parts.append("### 4C. G3 Leakage KPIs\n")
        h4c = ["Metric", "Value"]
        rows_4c = [
            ["baseline_leakage", f"{g3.get('baseline_leakage_count', '?')} ({_fmt(g3.get('baseline_leakage_rate'))})"],
            ["g3_triggered", f"{g3.get('g3_triggered_count', '?')} ({_fmt(g3.get('g3_triggered_rate'))})"],
            ["residual_guardrail_leakage", f"{g3.get('residual_guardrail_leakage_count', '?')} ({_fmt(g3.get('residual_guardrail_leakage_rate'))})"],
            ["residual_share_of_baseline_leak", _fmt(g3.get("residual_guardrail_leakage_share_of_baseline_leak"))],
            ["g3_on_gt_pos", f"{g3.get('g3_on_gt_pos_count', '?')} ({_fmt(g3.get('g3_on_gt_pos_rate'))})"],
        ]
        parts.append(_md_table(h4c, rows_4c))
        parts.append("")

        # 4D: G5 Schema / Fail-Closed KPIs
        g5 = guardrail_kpis_step4.get("g5", {})
        parts.append("### 4D. G5 Schema / Fail-Closed KPIs\n")
        h4d = ["Metric", "Value"]
        rows_4d = [
            ["schema_invalid", f"{g5.get('schema_invalid_count', '?')} ({_fmt(g5.get('schema_invalid_rate'))})"],
            ["g5_routed", f"{g5.get('g5_routed_count', '?')} ({_fmt(g5.get('g5_routed_rate'))})"],
            ["g5_fail_closed_review", f"{g5.get('g5_fail_closed_review_count', '?')} ({_fmt(g5.get('g5_fail_closed_review_rate'))})"],
            ["g5_fail_closed_share_of_g5", _fmt(g5.get("g5_fail_closed_review_share_of_g5"))],
        ]
        parts.append(_md_table(h4d, rows_4d))
        parts.append("")

        # 4E: Trigger Combination Summary
        combos = guardrail_kpis_step4.get("trigger_combinations", [])
        if combos:
            parts.append("### 4E. Trigger Combination Summary\n")
            h4e = ["Combination", "Count", "Rate"]
            rows_4e = []
            for r in combos:
                rows_4e.append([
                    r["trigger_combination"], r["count"], _fmt(r["rate"]),
                ])
            parts.append(_md_table(h4e, rows_4e))
            parts.append("")

        # 4F: G6 Pre-LLM Hint KPIs
        g6 = guardrail_kpis_step4.get("g6", {})
        if g6.get("g6_hint_injected_count", 0) > 0:
            parts.append("### 4F. G6 Pre-LLM Hint KPIs\n")
            h4f = ["Metric", "Value"]
            rows_4f = [
                ["g6_hint_injected", f"{g6.get('g6_hint_injected_count', '?')} ({_fmt(g6.get('g6_hint_injected_rate'))})"],
                ["g6_no_hint", str(g6.get('g6_no_hint_count', '?'))],
                ["g6_hint_detection_rate", _fmt(g6.get('g6_hint_detection_rate'))],
                ["g6_no_hint_detection_rate", _fmt(g6.get('g6_no_hint_detection_rate'))],
                ["g6_hint_on_gt_pos", f"{g6.get('g6_hint_on_gt_pos_count', '?')} ({_fmt(g6.get('g6_hint_on_gt_pos_rate'))})"],
                ["g6_hint_on_gt_neg", str(g6.get('g6_hint_on_gt_neg_count', '?'))],
                ["g6_hint_schema_valid", f"{g6.get('g6_hint_schema_valid_count', '?')} ({_fmt(g6.get('g6_hint_schema_valid_rate'))})"],
                ["g6_hint_schema_fail", str(g6.get('g6_hint_schema_fail_count', '?'))],
            ]
            parts.append(_md_table(h4f, rows_4f))
            parts.append("")

    # ── Step 5: Failure-Mode PRI Analysis ────────────────────────────
    if failure_mode_pri:
        parts.append("## Step 5 — Failure-Mode PRI Analysis\n")
        parts.append(
            "Evaluates the guardrail bundle as a control layer via "
            "Prevalence (P), Intervention (I), and Residual (R) per "
            "failure mode. Rates are conditioned on their respective "
            "denominators: prevalence on n_baseline_evaluable, "
            "intervention and residual on prevalence_count. "
            "Residual is reported only where directly or partially "
            "observable — no proxy values are used.\n"
        )

        # 5A: PRI Summary
        parts.append("### 5A. PRI Summary per Failure Mode\n")
        h5a = [
            "FM", "Guardrail", "n_eval", "Prev", "Prev Rate",
            "Interv", "Interv Rate|Prev", "Resid", "Resid Rate|Prev",
            "Observability",
        ]
        rows_5a = []
        for r in failure_mode_pri.get("summary", []):
            rows_5a.append([
                r["failure_mode"],
                r["mapped_guardrail"],
                r["n_baseline_evaluable"],
                r["prevalence_count"],
                _fmt(r["prevalence_rate"]),
                r["intervention_count"] if r["intervention_count"] is not None else "—",
                _fmt(r["intervention_rate_given_prevalence"]),
                r["residual_count"] if r["residual_count"] is not None else "—",
                _fmt(r["residual_rate_given_prevalence"]),
                r["residual_observability"],
            ])
        parts.append(_md_table(h5a, rows_5a))
        parts.append("")

        # 5B: PRI Definitions
        parts.append("### 5B. PRI Definitions\n")
        h5b = [
            "FM", "Guardrail", "Prevalence Field Logic",
            "Intervention Field Logic", "Residual Field Logic", "Notes",
        ]
        rows_5b = []
        for d in failure_mode_pri.get("definitions", []):
            rows_5b.append([
                d["failure_mode"],
                d["mapped_guardrail"],
                d["prevalence_field_logic"],
                d["intervention_field_logic"],
                d["residual_field_logic"],
                d["notes"],
            ])
        parts.append(_md_table(h5b, rows_5b))
        parts.append("")

        # 5C: PRI Coverage / Observability
        parts.append("### 5C. PRI Coverage / Observability\n")
        h5c = [
            "FM", "Guardrail", "n_eval", "Prev n",
            "Resid Observability", "Multi-FM Note", "Notes",
        ]
        rows_5c = []
        for c in failure_mode_pri.get("coverage", []):
            rows_5c.append([
                c["failure_mode"],
                c["mapped_guardrail"],
                c["n_baseline_evaluable"],
                c["prevalence_base_n"],
                c["residual_observability"],
                c["multi_fm_interference_note"],
                c["notes"],
            ])
        parts.append(_md_table(h5c, rows_5c))
        parts.append("")

    # ── Step 6: Slice Analysis ──────────────────────────────────────
    if slice_analysis:
        parts.append("## Step 6 — Slice Analysis (Supplementary)\n")
        parts.append(
            "Segments the main findings from Steps 2, 3, and 5 by dataset "
            "slices. This is a **supplementary analysis layer** — the "
            "authoritative results are reported in Steps 2–5.\n"
        )

        # 6A: Performance Summary — primary slices in main table,
        #     stress subtypes in a compact appendix sub-table
        _PRIMARY_SLICES = {"base", "stress", "neg_clean", "neg_decoy",
                           "real", "synthetic"}
        _STRESS_SUBTYPES = {"stress_untrusted_input", "stress_uncertainty",
                            "stress_multi_fm", "stress_hardened"}

        parts.append("### 6A. Slice Performance Summary\n")
        perf = slice_analysis.get("performance", [])
        h6a = [
            "Slice", "n", "Mode", "n_eval",
            "Rec Alert", "Prec Alert", "Rec Auto", "Prec Auto",
            "Esc Rate", "Review %", "Block %", "Pass %",
        ]

        def _perf_row(r):
            return [
                r["slice_name"], r["slice_n"], r["mode"],
                r["n_evaluable"],
                _fmt(r.get("recall_alert")),
                _fmt(r.get("precision_alert")),
                _fmt(r.get("recall_auto")),
                _fmt(r.get("precision_auto")),
                _fmt(r.get("escape_rate")),
                _fmt(r.get("review_rate")),
                _fmt(r.get("block_rate")),
                _fmt(r.get("pass_rate")),
            ]

        rows_6a_primary = [_perf_row(r) for r in perf
                           if r["slice_name"] in _PRIMARY_SLICES]
        parts.append(_md_table(h6a, rows_6a_primary))

        parts.append(
            "\n*Coverage notes: `real` + `synthetic` covers positive "
            "samples only (NEG\\_ controls excluded). "
            "`neg_clean` + `neg_decoy` are control-specific subgroups, "
            "not an exhaustive partition of all GT-negative cases.*\n"
        )

        note_small = [
            r["slice_name"] for r in slice_analysis.get("pri_spotlight", [])
            if r["slice_n"] < 10
        ]
        if note_small:
            parts.append(
                f"*Slices with n < 10 ({', '.join(note_small)}) "
                f"should be interpreted with caution.*\n"
            )

        # Stress subtypes — compact sub-table
        rows_6a_stress = [_perf_row(r) for r in perf
                          if r["slice_name"] in _STRESS_SUBTYPES]
        if rows_6a_stress:
            parts.append(
                "\n<details><summary>Stress subtype breakdown "
                "(click to expand)</summary>\n"
            )
            parts.append(_md_table(h6a, rows_6a_stress))
            parts.append("\n</details>\n")
        parts.append("")

        # 6B: PRI Spotlight
        parts.append("### 6B. Slice PRI Spotlight\n")
        parts.append(
            "FM3 (secret leakage) and FM4 (uncertainty miscalibration) "
            "PRI rates per slice. Rates conditioned on respective "
            "denominators as in Step 5.\n"
        )
        parts.append(
            "*FM4 values are indicative only. They are based on partially "
            "observable uncertainty/should-review indicators and are not "
            "comparable in directness to FM3 leakage measurements "
            "(see Step 5 for observability details).*\n"
        )
        h6b = [
            "Slice", "n",
            "FM3 Prev", "FM3 Prev Rate", "FM3 Interv|Prev", "FM3 Resid|Prev",
            "FM4 Prev", "FM4 Prev Rate", "FM4 Interv|Prev",
        ]
        rows_6b = []
        for r in slice_analysis.get("pri_spotlight", []):
            rows_6b.append([
                r["slice_name"], r["slice_n"],
                r["fm3_prevalence_count"],
                _fmt(r.get("fm3_prevalence_rate")),
                _fmt(r.get("fm3_intervention_rate_given_prevalence")),
                _fmt(r.get("fm3_residual_rate_given_prevalence")),
                r["fm4_prevalence_count"],
                _fmt(r.get("fm4_prevalence_rate")),
                _fmt(r.get("fm4_intervention_rate_given_prevalence")),
            ])
        parts.append(_md_table(h6b, rows_6b))
        parts.append("")

        # 6C: Definitions
        parts.append("### 6C. Slice Definitions\n")
        h6c = ["Slice", "Definition", "Notes"]
        rows_6c = []
        for d in slice_analysis.get("definitions", []):
            rows_6c.append([
                d["slice_name"], d["definition_logic"], d["notes"],
            ])
        parts.append(_md_table(h6c, rows_6c))
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

    # ── Slice Metrics (supplementary segmented analysis) ───────────
    parts.append("## Supplementary — Slice Metrics\n")
    parts.append(
        "Segmented analysis across dataset dimensions. "
        "Complements the system-level results from Steps 2 and 3.\n"
    )

    # Show by_condition for Guardrails_Alert
    parts.append("### Recall by Condition (LLM + Guardrails, Alert-Level)\n")
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
    parts.append("### False Positives by Negative Type (all systems)\n")
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

    # Show by_condition for Scanner
    parts.append("### Scanner — Recall by Condition\n")
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

    # ── Appendix: Legacy Mode Comparison (hit-level) ───────────────
    if include_legacy:
        parts.append("## Appendix — Legacy Mode Comparison (hit-level predicates)\n")
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

    # ── Appendix: Legacy Guardrail KPI Details ─────────────────────
    if include_legacy_guardrail_details:
        parts.append("## Appendix — Legacy Guardrail KPI Details\n")

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

        # Multi-trigger summary
        tg_summary = guardrail_kpis.get("triggered_guardrails_summary", {})
        if tg_summary:
            parts.append("### Multi-Trigger Summary\n")
            parts.append(f"- **samples_with_any_trigger_count:** {tg_summary.get('samples_with_any_trigger_count', 0)}")
            parts.append(f"- **single_trigger_samples_count:** {tg_summary.get('single_trigger_samples_count', 0)}")
            parts.append(f"- **multi_trigger_samples_count:** {tg_summary.get('multi_trigger_samples_count', 0)}")
            parts.append(f"- **multi_trigger_rate:** {tg_summary.get('multi_trigger_rate', 0)}")
            parts.append(f"- **max_triggers_on_single_sample:** {tg_summary.get('max_triggers_on_single_sample', 0)}")
            parts.append("")

            per_g = tg_summary.get("per_guardrail_trigger_count", {})
            if per_g:
                parts.append("**Per-Guardrail Trigger Count (from triggered_guardrails):**\n")
                rows_tg = [[g, str(c)] for g, c in per_g.items()]
                parts.append(_md_table(["Guardrail", "Trigger Count"], rows_tg))
                parts.append("")

            combos = tg_summary.get("trigger_combination_counts", {})
            if combos:
                parts.append("**Trigger Combination Breakdown:**\n")
                rows_combo = [[combo, str(cnt)] for combo, cnt in combos.items()]
                parts.append(_md_table(["Combination", "Count"], rows_combo))
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
