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
    compute_guardrail_kpis,
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

    Compares on the binary hit-level (autonomous classification).
    """
    tests = {}

    # Scanner vs LLM Baseline
    tests["scanner_vs_baseline"] = compare_detectors_mcnemar(
        results,
        method1_key="scanner_hit",
        method2_key="llm_baseline_hit",
        method1_name="Scanner",
        method2_name="LLM_Baseline",
    )

    # Scanner vs Guardrails (autonomous)
    tests["scanner_vs_guardrail_autonomous"] = compare_detectors_mcnemar(
        results,
        method1_key="scanner_hit",
        method2_key="llm_guardrail_hit",
        method1_name="Scanner",
        method2_name="Guardrails_Autonomous",
    )

    # Baseline vs Guardrails (autonomous)
    tests["baseline_vs_guardrail_autonomous"] = compare_detectors_mcnemar(
        results,
        method1_key="llm_baseline_hit",
        method2_key="llm_guardrail_hit",
        method1_name="LLM_Baseline",
        method2_name="Guardrails_Autonomous",
    )

    # Alert-level comparisons need a synthetic hit field
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
    Placeholder for future policy re-simulation.

    Currently returns None — only the stored policy decisions from
    results.json are evaluated (Section D1).  To add re-simulation,
    implement custom P1/P2/P3 logic here and return a list of dicts
    with the same schema as compute_all_policy_metrics() output.
    """
    return None


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

    # ── 2. Mode comparison (Section A) ─────────────────────────────
    logger.info("Computing mode metrics (Scanner / Baseline / Guardrails Alert / Guardrails Autonomous) ...")
    mode_metrics = compute_all_mode_metrics(results)

    # ── 3. Guardrail KPIs (Section B) ─────────────────────────────
    logger.info("Computing guardrail KPIs (G1–G5) ...")
    guardrail_kpis = compute_guardrail_kpis(results)

    # ── 4. Slice metrics (Section C) ──────────────────────────────
    logger.info("Computing slice metrics ...")
    slice_rows = compute_slice_metrics(results)

    # ── 5. Policy metrics (Section D1) ────────────────────────────
    logger.info("Computing policy metrics (P1–P3 × baseline/guardrail × alert/autonomous) ...")
    policy_rows = compute_all_policy_metrics(results)

    # Section D2: hook for future re-simulation
    resim = policy_resimulation_hook(results)
    if resim:
        policy_rows.extend(resim)

    # ── 6. Statistical tests ──────────────────────────────────────
    logger.info("Running statistical tests (McNemar) ...")
    stat_tests = run_statistical_tests(results)

    # ── 7. Leakage comparison (FM5) ───────────────────────────────
    logger.info("Computing leakage metrics (FM5) ...")
    leakage = compare_baseline_vs_guardrail_leakage(results)

    # ══════════════════════════════════════════════════════════════
    #  Write outputs
    # ══════════════════════════════════════════════════════════════
    logger.info("Writing output files ...")

    # metrics_summary.json — full nested metrics
    _write_json(
        {
            "dataset": ds_summary,
            "mode_comparison": mode_metrics,
            "guardrail_kpis": guardrail_kpis,
            "policy_metrics": policy_rows,
            "statistical_tests": stat_tests,
            "leakage": leakage,
        },
        outdir / "metrics_summary.json",
    )

    # metrics_tables.csv — mode comparison flat
    _write_csv(
        [{"mode": name, **m} for name, m in mode_metrics.items()],
        outdir / "metrics_tables.csv",
    )

    # slice_metrics.csv
    _write_csv(slice_rows, outdir / "slice_metrics.csv")

    # policy_metrics.csv
    _write_csv(policy_rows, outdir / "policy_metrics.csv")

    # guardrail_metrics.json
    _write_json(guardrail_kpis, outdir / "guardrail_metrics.json")

    # evaluation_summary.md
    md = generate_markdown_report(
        mode_metrics, guardrail_kpis, policy_rows,
        slice_rows, ds_summary,
    )
    _write_text(md, outdir / "evaluation_summary.md")

    logger.info(f"Done — all outputs in {outdir}/")


if __name__ == "__main__":
    main()
