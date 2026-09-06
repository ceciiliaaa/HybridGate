"""
Compute All Metrics for HybridGate Evaluation Results

Comprehensive, reproducible evaluation script for the final BA run.
Produces structured output artefacts (JSON, CSV, Markdown).

CLI:
    python -m src.metrics.compute_all \\
        --results runs/v121_final_extreme_openai_g5fix/results.json \\
        --config  runs/v121_final_extreme_openai_g5fix/config.json \\
        --outdir  runs/v121_final_extreme_openai_g5fix/evaluation_outputs

Outputs (all in --outdir):
    metrics_summary.json     Full nested metrics
    metrics_tables.csv       Mode comparison (4 rows)
    slice_metrics.csv        All slice × mode breakdowns
    policy_metrics.csv       3 policies × 2 variants × 2 views = 12 rows
    guardrail_metrics.json   G1–G5 KPIs
    evaluation_summary.md    Human-readable tables (descriptive, no interpretation)

Author: Cecilia Nothstein
"""

import argparse
import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .evaluation_utils import (
    build_dataset_summary,
    compute_all_mode_metrics,
    compute_all_policy_metrics,
    compute_decision_profile,
    compute_guardrail_kpis,
    compute_failure_mode_pri,
    compute_guardrail_kpis_step4,
    compute_mode_comparison,
    compute_slice_analysis,
    compute_slice_metrics,
    generate_markdown_report,
)
from .leakage_metrics import compare_baseline_vs_guardrail_leakage
from .statistical_tests import compare_detectors_mcnemar

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  I/O helpers
# ═══════════════════════════════════════════════════════════════════════

def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(data: Any, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info(f"  → {path}")


def _write_csv(rows: List[Dict], path: Path) -> None:
    if not rows:
        logger.warning(f"  → {path}  (empty — no rows)")
        return

    # Stable column order: pull known important columns to front
    priority = [
        "mode", "slice_name", "slice_value", "policy", "variant", "view",
        "n", "total_evaluated",
        "TP", "FP", "TN", "FN", "skipped",
        "precision", "recall", "f1", "specificity", "accuracy",
        "escape_rate", "escape_count", "reviewer_load",
    ]
    all_keys = list(dict.fromkeys(
        k for row in rows for k in row.keys()
        if not isinstance(row[k], (dict, list))  # skip nested
    ))
    ordered = [k for k in priority if k in all_keys]
    ordered += [k for k in all_keys if k not in ordered]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Flatten: skip nested dicts/lists
            flat = {k: v for k, v in row.items() if not isinstance(v, (dict, list))}
            writer.writerow(flat)
    logger.info(f"  → {path}  ({len(rows)} rows)")


def _write_text(text: str, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    logger.info(f"  → {path}")


# ═══════════════════════════════════════════════════════════════════════
#  Statistical tests (wrapper around existing module)
# ═══════════════════════════════════════════════════════════════════════

def run_statistical_tests(results: List[Dict]) -> Dict[str, Any]:
    """
    McNemar tests for key detector pairs.

    Legacy hit-level tests use scanner_hit / llm_baseline_hit / llm_guardrail_hit.
    Alert-level tests use synthetic _guardrail_alert_hit (BLOCK|REVIEW).
    These are complementary to — but independent of — the Step 2 mode comparison.
    """
    tests = {}

    # --- Legacy hit-level comparisons ---
    # Scanner vs LLM Baseline
    tests["scanner_vs_baseline_hit"] = compare_detectors_mcnemar(
        results,
        method1_key="scanner_hit",
        method2_key="llm_baseline_hit",
        method1_name="Scanner",
        method2_name="LLM_Baseline",
    )

    # Scanner vs Guardrails (hit-level)
    tests["scanner_vs_guardrail_hit"] = compare_detectors_mcnemar(
        results,
        method1_key="scanner_hit",
        method2_key="llm_guardrail_hit",
        method1_name="Scanner",
        method2_name="Guardrails_Hit",
    )

    # Baseline vs Guardrails (hit-level)
    tests["baseline_vs_guardrail_hit"] = compare_detectors_mcnemar(
        results,
        method1_key="llm_baseline_hit",
        method2_key="llm_guardrail_hit",
        method1_name="LLM_Baseline",
        method2_name="Guardrails_Hit",
    )

    # --- Alert-level comparisons (BLOCK|REVIEW = hit) ---
    alert_results = []
    for s in results:
        gr = s.get("llm_guardrail") or {}
        fd = gr.get("final_decision")
        alert_results.append({
            **s,
            "_guardrail_alert_hit": fd in ("BLOCK", "REVIEW"),
        })

    tests["scanner_vs_guardrail_alert"] = compare_detectors_mcnemar(
        alert_results,
        method1_key="scanner_hit",
        method2_key="_guardrail_alert_hit",
        method1_name="Scanner",
        method2_name="Guardrails_Alert",
    )

    tests["baseline_vs_guardrail_alert"] = compare_detectors_mcnemar(
        alert_results,
        method1_key="llm_baseline_hit",
        method2_key="_guardrail_alert_hit",
        method1_name="LLM_Baseline",
        method2_name="Guardrails_Alert",
    )

    return tests


# ═══════════════════════════════════════════════════════════════════════
#  Policy audit hook (Section D2)
# ═══════════════════════════════════════════════════════════════════════

def policy_resimulation_hook(
    results: List[Dict],
) -> Optional[List[Dict]]:
    """
    Re-simulate P1/P2/P3 on guardrail inputs using current policy code.

    Returns 6 rows (3 policies × 2 views, variant='guardrail') that
    replace the stale stored-field guardrail rows from compute_all_policy_metrics().
    Baseline rows are unaffected (still read from stored fields).
    """
    try:
        from src.policies import P1SafetyNet, P2ContextualVeto, P3RiskWeighted
        from src.scripts.run_policy_comparison_v2 import _guardrail_inputs
    except ImportError:
        return None

    policies = [
        ("p1", P1SafetyNet()),
        ("p2", P2ContextualVeto()),
        ("p3", P3RiskWeighted()),
    ]

    rows = []
    for pname, policy_obj in policies:
        sample_decisions: List[tuple] = []
        for s in results:
            inputs = _guardrail_inputs(s)
            if inputs is None:
                continue
            dec = policy_obj.get_full_result(**inputs).decision.value
            sample_decisions.append((dec, bool(s.get("gt_has_secret", False))))

        n = len(sample_decisions)
        n_pos = sum(1 for _, g in sample_decisions if g)
        review_count = sum(1 for d, _ in sample_decisions if d == "REVIEW")
        escaped = sum(1 for d, g in sample_decisions if g and d == "PASS")

        for view in ("alert", "autonomous"):
            tp = fp = tn = fn = 0
            for dec, gt in sample_decisions:
                pred = dec in ("BLOCK", "REVIEW") if view == "alert" else dec == "BLOCK"
                if gt and pred:       tp += 1
                elif not gt and pred: fp += 1
                elif gt and not pred: fn += 1
                else:                 tn += 1

            prec = tp / (tp + fp) if (tp + fp) else 0.0
            rec  = tp / (tp + fn) if (tp + fn) else 0.0
            f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
            spec = tn / (tn + fp) if (tn + fp) else 0.0
            acc  = (tp + tn) / n if n else 0.0

            rows.append({
                "policy": pname,
                "variant": "guardrail",
                "view": view,
                "total_evaluated": n,
                "TP": tp, "FP": fp, "TN": tn, "FN": fn,
                "skipped": 0,
                "precision":    round(prec, 4),
                "recall":       round(rec, 4),
                "f1":           round(f1, 4),
                "specificity":  round(spec, 4),
                "accuracy":     round(acc, 4),
                "escape_count": escaped,
                "escape_rate":  round(escaped / n_pos, 4) if n_pos else 0.0,
                "reviewer_load": round(review_count / n, 4) if n else 0.0,
                "decision_distribution": {
                    "BLOCK": sum(1 for d, _ in sample_decisions if d == "BLOCK"),
                    "REVIEW": review_count,
                    "PASS":  sum(1 for d, _ in sample_decisions if d == "PASS"),
                    "total": n,
                },
            })

    return rows


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute comprehensive evaluation metrics for HybridGate results",
    )
    parser.add_argument(
        "--results", required=True,
        help="Path to results.json",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to config.json (optional, for run metadata)",
    )
    parser.add_argument(
        "--dataset", default=None,
        help="Path to dataset JSON (optional, not used for computation)",
    )
    parser.add_argument(
        "--outdir", required=True,
        help="Output directory for all metric files",
    )
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # ── Load inputs ────────────────────────────────────────────────
    logger.info(f"Loading results from {args.results}")
    results = _load_json(args.results)
    logger.info(f"Loaded {len(results)} samples")

    config = _load_json(args.config) if args.config else None

    # ── 1. Dataset summary ─────────────────────────────────────────
    logger.info("Building dataset summary ...")
    ds_summary = build_dataset_summary(results, config)

    # ── 2. Mode comparison — 3 systems × 2 views (authoritative) ──
    logger.info("Computing mode comparison (3 systems × 2 views) ...")
    mode_comparison = compute_mode_comparison(results)

    # ── 3. Decision profile (Step 3) ────────────────────────────
    logger.info("Computing decision profile (Step 3) ...")
    decision_prof = compute_decision_profile(results)

    # ── 4. Guardrail KPIs (Step 4) ─────────────────────────────
    logger.info("Computing guardrail KPIs (Step 4) ...")
    guardrail_kpis_s4 = compute_guardrail_kpis_step4(results)

    # ── 5. Failure-Mode PRI Analysis (Step 5) ───────────────────
    logger.info("Computing failure-mode PRI analysis (Step 5) ...")
    fm_pri = compute_failure_mode_pri(results)

    # ── 6. Slice analysis (Step 6) ────────────────────────────────
    logger.info("Computing slice analysis (Step 6) ...")
    slice_ana = compute_slice_analysis(results)

    # ── Legacy: Slice metrics ─────────────────────────────────────
    logger.info("Computing legacy slice metrics ...")
    slice_rows = compute_slice_metrics(results)

    # ── 7. Policy metrics (P1–P3 × baseline/guardrail × alert/autonomous)
    logger.info("Computing policy metrics ...")
    policy_rows = compute_all_policy_metrics(results)

    # Section D2: re-simulation with current policy code replaces stale guardrail rows
    resim = policy_resimulation_hook(results)
    if resim:
        policy_rows = [r for r in policy_rows if r.get("variant") != "guardrail"]
        policy_rows.extend(resim)

    # ── 8. Statistical tests ──────────────────────────────────────
    logger.info("Running statistical tests (McNemar) ...")
    stat_tests = run_statistical_tests(results)

    # ── 9. Leakage comparison (FM3) ───────────────────────────────
    logger.info("Computing leakage metrics (FM3) ...")
    leakage = compare_baseline_vs_guardrail_leakage(results)

    # ── Legacy: 4-mode comparison (hit-level predicates) ──────────
    logger.info("Computing legacy mode metrics (hit-level predicates) ...")
    legacy_mode_metrics = compute_all_mode_metrics(results)

    # ══════════════════════════════════════════════════════════════
    #  Write outputs
    # ══════════════════════════════════════════════════════════════
    logger.info("Writing output files ...")

    # metrics_summary.json — full nested metrics
    _write_json(
        {
            "dataset": ds_summary,
            "legacy_mode_metrics": legacy_mode_metrics,
            "mode_comparison": mode_comparison,
            "decision_profile": decision_prof,
            "guardrail_kpis": guardrail_kpis_s4,
            "failure_mode_pri": fm_pri,
            "slice_analysis": slice_ana,
            "policy_metrics": policy_rows,
            "statistical_tests": stat_tests,
            "leakage": leakage,
        },
        outdir / "metrics_summary.json",
    )

    # metrics_tables.csv — legacy mode comparison flat
    _write_csv(
        [{"mode": name, **m} for name, m in legacy_mode_metrics.items()],
        outdir / "metrics_tables.csv",
    )

    # Step 2 CSVs — three-system mode comparison
    _write_csv(
        mode_comparison["alert_level"],
        outdir / "mode_comparison_alert.csv",
    )
    _write_csv(
        mode_comparison["alert_profile"],
        outdir / "mode_comparison_alert_profile.csv",
    )
    _write_csv(
        mode_comparison["autonomous_level"],
        outdir / "mode_comparison_autonomous.csv",
    )
    _write_csv(
        mode_comparison["alert_vs_autonomous"],
        outdir / "mode_comparison_comparison.csv",
    )

    # Step 3 CSVs — decision profile
    _write_csv(
        decision_prof["global"],
        outdir / "decision_profile_global.csv",
    )
    _write_csv(
        decision_prof["gt_pos_counts"],
        outdir / "decision_profile_gt_pos.csv",
    )
    _write_csv(
        decision_prof["gt_neg_counts"],
        outdir / "decision_profile_gt_neg.csv",
    )
    _write_csv(
        decision_prof["vs_baseline"],
        outdir / "decision_profile_vs_baseline.csv",
    )

    # Step 4 CSVs — guardrail KPIs
    _write_csv(
        [guardrail_kpis_s4["activity_summary"]],
        outdir / "guardrail_kpis_activity_summary.csv",
    )
    _write_csv(
        guardrail_kpis_s4["per_guardrail"],
        outdir / "guardrail_kpis_per_guardrail.csv",
    )
    _write_csv(
        [guardrail_kpis_s4["g3"]],
        outdir / "guardrail_kpis_g3.csv",
    )
    _write_csv(
        [guardrail_kpis_s4["g5"]],
        outdir / "guardrail_kpis_g5.csv",
    )
    _write_csv(
        guardrail_kpis_s4["trigger_combinations"],
        outdir / "guardrail_kpis_trigger_combinations.csv",
    )
    _write_csv(
        [guardrail_kpis_s4["g6"]],
        outdir / "guardrail_kpis_g6.csv",
    )

    # Step 5 CSVs — failure-mode PRI analysis
    _write_csv(
        fm_pri["summary"],
        outdir / "failure_mode_pri_summary.csv",
    )
    _write_csv(
        fm_pri["definitions"],
        outdir / "failure_mode_pri_definitions.csv",
    )
    _write_csv(
        fm_pri["coverage"],
        outdir / "failure_mode_pri_coverage.csv",
    )

    # Step 6 CSVs — slice analysis
    _write_csv(
        slice_ana["performance"],
        outdir / "slice_analysis_performance.csv",
    )
    _write_csv(
        slice_ana["pri_spotlight"],
        outdir / "slice_analysis_pri_spotlight.csv",
    )
    _write_csv(
        slice_ana["definitions"],
        outdir / "slice_analysis_definitions.csv",
    )

    # slice_metrics.csv (legacy)
    _write_csv(slice_rows, outdir / "slice_metrics.csv")

    # policy_metrics.csv
    _write_csv(policy_rows, outdir / "policy_metrics.csv")

    # guardrail_metrics.json (legacy detail)
    guardrail_kpis_legacy = compute_guardrail_kpis(results)
    _write_json(guardrail_kpis_legacy, outdir / "guardrail_metrics.json")

    # evaluation_summary.md
    md = generate_markdown_report(
        legacy_mode_metrics, guardrail_kpis_legacy, policy_rows,
        slice_rows, ds_summary, mode_comparison, decision_prof,
        guardrail_kpis_s4, fm_pri, slice_ana, config,
    )
    _write_text(md, outdir / "evaluation_summary.md")

    logger.info(f"Done — all outputs in {outdir}/")


if __name__ == "__main__":
    main()
