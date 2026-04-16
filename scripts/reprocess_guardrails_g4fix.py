"""
Offline Reprocessing: Apply G4 routing fix to existing v140 results.

Re-derives the guardrail routing decisions from existing trigger data
in results.json, applying the G4 fix: G4 only escalates PASS -> REVIEW,
never BLOCK -> REVIEW.

No API calls.  No re-running of G5/G2/G4/G1/G3 detection logic.
Only the routing priority is recomputed from existing trigger results.

This is mathematically equivalent to re-running the full pipeline because:
- G5, G2, G4, G1, G3 detection/trigger results are unchanged (same inputs)
- Only the G4 routing condition changed (added original_decision == "PASS")
- The routing priority logic (G5 > G2 > G4 > G1 > G3) is deterministic

Usage:
    python -m scripts.reprocess_guardrails_g4fix \
        --input  runs/v140_full_g6_250samples/results.json \
        --output runs/v140_full_g6_250samples/results_g4fix.json

Author: Cecilia Nothstein
"""

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def recompute_routing(gr: dict) -> dict:
    """
    Recompute routed_by_guardrail and final_decision from existing triggers.

    Applies the pipeline priority G5 > G2 > G4 > G1 > G3 with the G4 fix:
    G4 only routes when original_decision == "PASS".

    Returns dict with updated routing fields.
    """
    original_decision = gr.get("original_decision", "PASS")

    # --- Determine which guardrails WOULD route (in priority order) ---

    # G5: routes if validation failed (mirrors __init__.py L267-269:
    #     g5_failed = not validation.is_valid → stored as g5_valid)
    g5_would_route = not gr.get("g5_valid", True)

    # G2: routes if untrusted input issues
    g2_would_route = not gr.get("g2_valid", True)

    # G4: routes if should_review AND original is PASS (G4 FIX)
    g4_details = gr.get("g4_details", {})
    g4_should_review = g4_details.get("should_review", False)
    g4_would_route = g4_should_review and original_decision == "PASS"

    # G1: routes if evidence invalid
    g1_would_route = not gr.get("g1_valid", True)

    # G3: routes if leak persists after mitigation (mitigation failed)
    g3_details = gr.get("g3_details", {})
    g3_would_route = (
        g3_details.get("g3_triggered", False)
        and not g3_details.get("mitigation_succeeded", True)
    )

    # --- Apply priority: first match wins ---
    routed_by = None
    if g5_would_route:
        routed_by = "G5"
    elif g2_would_route:
        routed_by = "G2"
    elif g4_would_route:
        routed_by = "G4"
    elif g1_would_route:
        routed_by = "G1"
    elif g3_would_route:
        routed_by = "G3"

    # --- Determine final decision ---
    if routed_by is not None:
        final_decision = "REVIEW"
    else:
        final_decision = original_decision

    # --- triggered_guardrails is unchanged (trigger != route) ---
    # G4 still appears in triggered_guardrails if should_review is True,
    # regardless of whether it actually routes.

    return {
        "routed_by_guardrail": routed_by,
        "final_decision": final_decision,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Reprocess guardrail routing with G4 fix (no API calls)",
    )
    parser.add_argument(
        "--input", required=True,
        help="Path to existing results.json",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path for reprocessed output file",
    )
    args = parser.parse_args()

    # Load
    logger.info(f"Loading results from {args.input}")
    with open(args.input, "r", encoding="utf-8") as f:
        results = json.load(f)
    logger.info(f"Loaded {len(results)} samples")

    # Reprocess
    changes = {
        "block_restored": 0,
        "g1_rerouted": 0,
        "g3_rerouted": 0,
        "unchanged": 0,
        "other": 0,
    }

    for sample in results:
        gr = sample.get("llm_guardrail", {})
        if not gr:
            continue

        old_final = gr.get("final_decision")
        old_routed = gr.get("routed_by_guardrail")

        new = recompute_routing(gr)
        new_final = new["final_decision"]
        new_routed = new["routed_by_guardrail"]

        # Apply changes
        gr["final_decision"] = new_final
        gr["routed_by_guardrail"] = new_routed

        # Update top-level alert hit flag
        sample["llm_guardrail_hit"] = new_final in ("BLOCK", "REVIEW")

        # Track
        if old_final == new_final and old_routed == new_routed:
            changes["unchanged"] += 1
        elif old_routed == "G4" and new_final == "BLOCK" and new_routed is None:
            changes["block_restored"] += 1
        elif old_routed == "G4" and new_routed == "G1":
            changes["g1_rerouted"] += 1
        elif old_routed == "G4" and new_routed == "G3":
            changes["g3_rerouted"] += 1
        else:
            changes["other"] += 1
            logger.info(
                f"  {sample['sample_id']}: "
                f"{old_final}({old_routed}) -> {new_final}({new_routed})"
            )

    # Summary
    total_changed = sum(v for k, v in changes.items() if k != "unchanged")
    logger.info("=" * 60)
    logger.info("Reprocessing complete:")
    logger.info(f"  Unchanged:          {changes['unchanged']}")
    logger.info(f"  BLOCK restored:     {changes['block_restored']} (G4 no longer downgrades)")
    logger.info(f"  Re-routed by G1:    {changes['g1_rerouted']} (G1 routes instead of G4)")
    logger.info(f"  Re-routed by G3:    {changes['g3_rerouted']} (G3 routes instead of G4)")
    if changes["other"]:
        logger.info(f"  Other changes:      {changes['other']} (see log above)")
    logger.info(f"  Total changed:      {total_changed}")
    logger.info("=" * 60)

    # Quick metrics
    tp = sum(1 for s in results
             if s["gt_has_secret"] and s["llm_guardrail"]["final_decision"] != "PASS")
    fp = sum(1 for s in results
             if not s["gt_has_secret"] and s["llm_guardrail"]["final_decision"] != "PASS")
    fn = sum(1 for s in results
             if s["gt_has_secret"] and s["llm_guardrail"]["final_decision"] == "PASS")
    tn = sum(1 for s in results
             if not s["gt_has_secret"] and s["llm_guardrail"]["final_decision"] == "PASS")

    n_block = sum(1 for s in results if s["llm_guardrail"]["final_decision"] == "BLOCK")
    n_review = sum(1 for s in results if s["llm_guardrail"]["final_decision"] == "REVIEW")
    n_pass = sum(1 for s in results if s["llm_guardrail"]["final_decision"] == "PASS")

    recall = tp / (tp + fn) if (tp + fn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    specificity = tn / (tn + fp) if (tn + fp) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    logger.info("Alert-level metrics (Guardrails):")
    logger.info(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    logger.info(f"  Recall={recall:.4f}  Precision={precision:.4f}  F1={f1:.4f}  Specificity={specificity:.4f}")
    logger.info(f"  BLOCK={n_block}  REVIEW={n_review}  PASS={n_pass}")
    logger.info(f"  REVIEW rate: {n_review}/{len(results)} = {n_review/len(results):.1%}")
    logger.info(f"  Escape rate: {fn}/{tp+fn} = {fn/(tp+fn):.1%}")

    # Write
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info(f"Written to {output_path}")


if __name__ == "__main__":
    main()
