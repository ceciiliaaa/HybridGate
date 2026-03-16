"""
Compute All Metrics for HybridGate Evaluation Results

CLI script to compute comprehensive metrics from evaluation results.

Usage:
    python src/metrics/compute_all.py --input data/05_results/hybrid_eval.json

Author: Cecilia Nothstein
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Any

from .model_metrics import (
    compute_model_metrics,
    compute_metrics_by_condition,
    compute_metrics_by_secret_type
)
from .gate_metrics import (
    compute_gate_metrics,
    compare_policies
)
from .statistical_tests import (
    compare_detectors_mcnemar
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def compute_all_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute all metrics from evaluation results.

    Args:
        results: List of evaluation result dictionaries

    Returns:
        Comprehensive metrics dictionary
    """
    metrics = {
        "summary": {},
        "model_metrics": {},
        "gate_metrics": {},
        "statistical_tests": {},
        "by_condition": {},
        "by_secret_type": {}
    }

    total = len(results)
    with_secrets = sum(1 for r in results if r.get("gt_has_secret"))

    metrics["summary"] = {
        "total_samples": total,
        "samples_with_secrets": with_secrets,
        "samples_without_secrets": total - with_secrets
    }

    # Model metrics for different detectors
    logger.info("Computing model metrics...")

    # Scanner (combined)
    scanner_results = [{
        **r,
        "pred_has_secret": r.get("scanner_hit", False)
    } for r in results]
    metrics["model_metrics"]["scanner_combined"] = compute_model_metrics(
        scanner_results, detector_name="scanner_combined"
    )

    # Gitleaks
    gitleaks_results = [{
        **r,
        "pred_has_secret": r.get("gitleaks_hit", False)
    } for r in results]
    metrics["model_metrics"]["gitleaks"] = compute_model_metrics(
        gitleaks_results, detector_name="gitleaks"
    )

    # TruffleHog
    trufflehog_results = [{
        **r,
        "pred_has_secret": r.get("trufflehog_hit", False)
    } for r in results]
    metrics["model_metrics"]["trufflehog"] = compute_model_metrics(
        trufflehog_results, detector_name="trufflehog"
    )

    # LLM Baseline
    baseline_results = [{
        **r,
        "pred_has_secret": r.get("llm_baseline_hit", False),
        "pred_location_start": r.get("llm_baseline", {}).get("pred_location_start") if r.get("llm_baseline") else None,
        "pred_location_end": r.get("llm_baseline", {}).get("pred_location_end") if r.get("llm_baseline") else None,
    } for r in results]
    metrics["model_metrics"]["llm_baseline"] = compute_model_metrics(
        baseline_results, detector_name="llm_baseline"
    )

    # LLM Guardrail
    guardrail_results = [{
        **r,
        "pred_has_secret": r.get("llm_guardrail_hit", False),
        "pred_location_start": r.get("llm_guardrail", {}).get("pred_location_start") if r.get("llm_guardrail") else None,
        "pred_location_end": r.get("llm_guardrail", {}).get("pred_location_end") if r.get("llm_guardrail") else None,
    } for r in results]
    metrics["model_metrics"]["llm_guardrail"] = compute_model_metrics(
        guardrail_results, detector_name="llm_guardrail"
    )

    # Gate metrics for all policies
    logger.info("Computing gate metrics...")
    metrics["gate_metrics"]["policy_p1"] = compute_gate_metrics(results, "policy_p1")
    metrics["gate_metrics"]["policy_p2"] = compute_gate_metrics(results, "policy_p2")
    metrics["gate_metrics"]["policy_p3"] = compute_gate_metrics(results, "policy_p3")
    metrics["gate_metrics"]["comparison"] = compare_policies(results)

    # Statistical tests
    logger.info("Running statistical tests...")

    # Scanner vs LLM Baseline
    metrics["statistical_tests"]["scanner_vs_llm_baseline"] = compare_detectors_mcnemar(
        results,
        method1_key="scanner_hit",
        method2_key="llm_baseline_hit",
        method1_name="Scanner",
        method2_name="LLM Baseline"
    )

    # LLM Baseline vs LLM Guardrail
    metrics["statistical_tests"]["baseline_vs_guardrail"] = compare_detectors_mcnemar(
        results,
        method1_key="llm_baseline_hit",
        method2_key="llm_guardrail_hit",
        method1_name="LLM Baseline",
        method2_name="LLM Guardrail"
    )

    # Gitleaks vs TruffleHog
    metrics["statistical_tests"]["gitleaks_vs_trufflehog"] = compare_detectors_mcnemar(
        results,
        method1_key="gitleaks_hit",
        method2_key="trufflehog_hit",
        method1_name="Gitleaks",
        method2_name="TruffleHog"
    )

    # Metrics by condition
    logger.info("Computing metrics by condition...")
    metrics["by_condition"]["scanner"] = compute_metrics_by_condition(
        scanner_results, pred_key="pred_has_secret"
    )
    metrics["by_condition"]["llm_baseline"] = compute_metrics_by_condition(
        baseline_results, pred_key="pred_has_secret"
    )
    metrics["by_condition"]["llm_guardrail"] = compute_metrics_by_condition(
        guardrail_results, pred_key="pred_has_secret"
    )

    # Metrics by secret type
    logger.info("Computing metrics by secret type...")
    metrics["by_secret_type"]["scanner"] = compute_metrics_by_secret_type(
        scanner_results, pred_key="pred_has_secret"
    )
    metrics["by_secret_type"]["llm_baseline"] = compute_metrics_by_secret_type(
        baseline_results, pred_key="pred_has_secret"
    )
    metrics["by_secret_type"]["llm_guardrail"] = compute_metrics_by_secret_type(
        guardrail_results, pred_key="pred_has_secret"
    )

    return metrics


def print_summary(metrics: Dict[str, Any]) -> None:
    """Print a formatted summary of metrics."""
    print("\n" + "=" * 60)
    print("HYBRIDGATE EVALUATION METRICS SUMMARY")
    print("=" * 60)

    summary = metrics["summary"]
    print(f"\nTotal samples: {summary['total_samples']}")
    print(f"  With secrets: {summary['samples_with_secrets']}")
    print(f"  Without secrets: {summary['samples_without_secrets']}")

    print("\n--- Model Performance ---")
    for name, m in metrics["model_metrics"].items():
        print(f"\n{name}:")
        print(f"  Precision: {m['precision']:.3f}")
        print(f"  Recall:    {m['recall']:.3f}")
        print(f"  F1:        {m['f1']:.3f}")
        cm = m['confusion_matrix']
        print(f"  TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}")

    print("\n--- Gate Effectiveness ---")
    for policy in ["policy_p1", "policy_p2", "policy_p3"]:
        g = metrics["gate_metrics"][policy]
        print(f"\n{policy}:")
        print(f"  Leak-Escape-Rate:  {g['leak_escape_rate']:.3f}")
        print(f"  False-Block-Rate:  {g['false_block_rate']:.3f}")
        print(f"  Review-Load:       {g['review_load']:.3f}")

    print("\n--- Statistical Significance ---")
    for name, test in metrics["statistical_tests"].items():
        print(f"\n{test['comparison']}:")
        print(f"  McNemar p-value: {test['mcnemar_test']['p_value']:.6f}")
        print(f"  Significant (α=0.05): {test['mcnemar_test']['significant_at_005']}")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Compute metrics from HybridGate evaluation results")
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to evaluation results JSON"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path for metrics output JSON (optional)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress summary output"
    )

    args = parser.parse_args()

    # Load results
    logger.info(f"Loading results from {args.input}")
    with open(args.input, "r") as f:
        results = json.load(f)
    logger.info(f"Loaded {len(results)} results")

    # Compute metrics
    metrics = compute_all_metrics(results)

    # Print summary
    if not args.quiet:
        print_summary(metrics)

    # Save if output path specified
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Saved metrics to {args.output}")
    else:
        # Default output path
        input_path = Path(args.input)
        output_path = input_path.parent / f"{input_path.stem}_metrics.json"
        with open(output_path, "w") as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Saved metrics to {output_path}")


if __name__ == "__main__":
    main()
