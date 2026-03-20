#!/usr/bin/env python3
"""
G6 Format-Familiarity Pre-Scan — Isolated Exploratory Experiment

Runs hard samples under up to four conditions:
  1. BASELINE:       GPT-5-mini with BASELINE_PROMPT (no guardrails, no G6)
  2. G6 HINT:        BASELINE + G6 static awareness + dynamic hint (v1)
  3. G6 FORCED:      BASELINE + G6 forced-reasoning system prompt + structured
                     per-candidate field schema in user prompt (v2)
  4. G6 FORCED+FLOOR: Same LLM output as G6 FORCED, but with an experimental
                     post-LLM review floor: if any g6_analysis candidate has
                     verdict 'uncertain' or 'likely_secret', the sample is
                     escalated to at least REVIEW.  This is NOT a guardrail —
                     it is a separate experimental evaluation condition.

Compares FN rate between conditions on the isolated hard-sample set.
Results saved to runs/g6_experiment/results.json

NOTE: This is an exploratory experiment on a small, targeted test set (n=20).
      It does NOT modify the main evaluation pipeline or main dataset.

Usage:
    python scripts/run_g6_experiment.py                             # all 4 conditions
    python scripts/run_g6_experiment.py --condition baseline         # baseline only
    python scripts/run_g6_experiment.py --condition g6_hint          # hint-only
    python scripts/run_g6_experiment.py --condition g6_forced        # forced reasoning
    python scripts/run_g6_experiment.py --condition g6_forced_floor  # forced + floor
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.llm_evaluation.run_evaluation import (
    BASELINE_PROMPT,
    OpenAIClient,
    USER_PROMPT_TEMPLATE,
    extract_json,
    number_lines,
)
from src.guardrails.g6_format_familiarity import G6FormatFamiliarity


# Extended token limit for hard samples (more reasoning needed)
def _call_api_extended(self, system_prompt, user_prompt):
    response = self.client.chat.completions.create(
        model=self.model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        max_completion_tokens=8192,
    )
    return response.choices[0].message.content


OpenAIClient._call_api = _call_api_extended


def run_sample(client, system_prompt, user_prompt, sample_id):
    """Run a single sample with retry logic."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            raw = client._call_api(system_prompt, user_prompt)
            pred = extract_json(raw)
            if pred is not None:
                return pred, raw
            print(f"  [{sample_id}] Parse error on attempt {attempt+1}")
        except Exception as e:
            print(f"  [{sample_id}] API error on attempt {attempt+1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(4 * (attempt + 1))
    return None, None


def evaluate_condition(
    client, samples, condition_name, system_prompt,
    g6=None, g6_mode=None,
):
    """Run all samples under one condition.

    Args:
        g6: G6FormatFamiliarity instance, or None for baseline.
        g6_mode: "hint" for v1 hint-only, "forced" for v2 forced reasoning.
                 Ignored when g6 is None.

    G6 only provides hints / structured prompts — no routing or decision logic.
    """
    # Build effective system prompt based on G6 mode
    effective_system_prompt = system_prompt
    if g6 is not None:
        if g6_mode == "forced":
            effective_system_prompt = system_prompt + g6.get_prompt_forced_reasoning()
        else:
            effective_system_prompt = system_prompt + g6.get_prompt()

    print(f"\n{'='*60}")
    print(f"CONDITION: {condition_name}")
    print(f"{'='*60}\n")

    results = []
    for i, s in enumerate(samples):
        sid = s["sample_id"]
        code_context = s.get("code_context", "")
        numbered_diff = number_lines(code_context)

        user_prompt = USER_PROMPT_TEMPLATE.format(
            pr_title=s.get("pr_title", ""),
            pr_body=s.get("pr_body", ""),
            code_context=numbered_diff,
        )

        # G6: Inject dynamic hint into user prompt if enabled
        g6_candidates = []
        g6_hint = ""
        if g6 is not None:
            g6_candidates = g6.extract_candidates(code_context)
            if g6_mode == "forced":
                g6_hint = g6.get_forced_reasoning_hint(g6_candidates)
            else:
                g6_hint = g6.get_hint(g6_candidates)
            if g6_hint:
                user_prompt += g6_hint

        print(f"[{i+1}/{len(samples)}] {sid} ({s.get('condition', '?')})", end="")
        if g6_candidates:
            print(f" — G6 found {len(g6_candidates)} candidate(s)", end="")
        print()

        pred, raw = run_sample(client, effective_system_prompt, user_prompt, sid)

        if pred is None:
            print(f"  => PARSE ERROR")
            results.append({
                "sample_id": sid,
                "condition": s.get("condition", ""),
                "error": "parse_error",
            })
            continue

        detected = pred.get("pred_has_secret", False)
        decision = pred.get("final_decision", "?")
        reasoning = pred.get("reasoning", "")
        gt_has_secret = s.get("gt_has_secret", True)

        is_fn = gt_has_secret and not detected
        is_tp = gt_has_secret and detected
        is_fp = not gt_has_secret and detected
        is_tn = not gt_has_secret and not detected

        if is_fn:
            label = "FALSE NEGATIVE"
        elif is_tp:
            label = "TRUE POSITIVE"
        elif is_fp:
            label = "FALSE POSITIVE"
        else:
            label = "TRUE NEGATIVE"

        print(f"  pred_has_secret: {detected} | decision: {decision} | => {label}")
        if reasoning:
            print(f"  reasoning: {reasoning[:120]}")

        # Preserve g6_analysis from forced-reasoning output (if present)
        g6_analysis = pred.get("g6_analysis", [])
        if not isinstance(g6_analysis, list):
            g6_analysis = []

        result_entry = {
            "sample_id": sid,
            "condition": s.get("condition", ""),
            "gt_has_secret": gt_has_secret,
            "pred_has_secret": detected,
            "final_decision": decision,
            "reasoning": reasoning,
            "classification": label,
            "g6_candidates_count": len(g6_candidates),
            "g6_hint_injected": bool(g6_hint),
            "g6_analysis": g6_analysis,
        }
        results.append(result_entry)

    return results


def compute_metrics(results, label):
    """Compute basic metrics for a condition."""
    valid = [r for r in results if "error" not in r]
    errors = len(results) - len(valid)

    tp = sum(1 for r in valid if r["classification"] == "TRUE POSITIVE")
    fn = sum(1 for r in valid if r["classification"] == "FALSE NEGATIVE")
    fp = sum(1 for r in valid if r["classification"] == "FALSE POSITIVE")
    tn = sum(1 for r in valid if r["classification"] == "TRUE NEGATIVE")

    gt_pos = tp + fn
    recall = tp / gt_pos if gt_pos > 0 else 0.0
    fn_rate = fn / gt_pos if gt_pos > 0 else 0.0

    return {
        "condition": label,
        "total": len(results),
        "valid": len(valid),
        "errors": errors,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "gt_positive": gt_pos,
        "recall": round(recall, 4),
        "fn_rate": round(fn_rate, 4),
    }


def apply_review_floor(forced_results):
    """Derive review-floor condition from g6_forced results (no extra API call).

    This is an EXPERIMENTAL post-LLM evaluation condition, not a guardrail.
    It reuses the same LLM output from g6_forced and applies a conservative
    floor: if any g6_analysis candidate has verdict 'uncertain' or
    'likely_secret', the sample is escalated to pred_has_secret=true and
    final_decision=REVIEW (minimum).

    Returns:
        Tuple of (floor_results, verdict_stats) where verdict_stats contains
        diagnostic info about how many samples had escalation-triggering
        verdicts in g6_analysis.
    """
    floor_results = []
    verdict_stats = {
        "samples_with_g6_analysis": 0,
        "samples_with_escalation_verdict": 0,
        "samples_escalated_by_floor": 0,  # actually changed by floor
        "escalation_verdict_sample_ids": [],
        "per_sample_verdicts": {},
    }

    for r in forced_results:
        entry = dict(r)  # shallow copy

        if "error" in entry:
            floor_results.append(entry)
            continue

        g6_analysis = entry.get("g6_analysis", [])
        if g6_analysis:
            verdict_stats["samples_with_g6_analysis"] += 1

        # Collect per-candidate verdicts for diagnostics
        verdicts = []
        has_escalation_verdict = False
        for candidate in g6_analysis:
            v = candidate.get("verdict", "").lower().strip()
            verdicts.append(v)
            if v in ("uncertain", "likely_secret"):
                has_escalation_verdict = True

        sid = entry["sample_id"]
        verdict_stats["per_sample_verdicts"][sid] = verdicts

        if has_escalation_verdict:
            verdict_stats["samples_with_escalation_verdict"] += 1
            verdict_stats["escalation_verdict_sample_ids"].append(sid)

            # Apply floor: override to at least REVIEW
            was_pass = not entry["pred_has_secret"]
            entry["pred_has_secret"] = True
            if entry["final_decision"] == "PASS":
                entry["final_decision"] = "REVIEW"
            entry["review_floor_applied"] = True

            if was_pass:
                verdict_stats["samples_escalated_by_floor"] += 1
        else:
            entry["review_floor_applied"] = False

        # Recompute classification after floor
        gt = entry["gt_has_secret"]
        det = entry["pred_has_secret"]
        if gt and det:
            entry["classification"] = "TRUE POSITIVE"
        elif gt and not det:
            entry["classification"] = "FALSE NEGATIVE"
        elif not gt and det:
            entry["classification"] = "FALSE POSITIVE"
        else:
            entry["classification"] = "TRUE NEGATIVE"

        floor_results.append(entry)

    return floor_results, verdict_stats


def main():
    parser = argparse.ArgumentParser(description="G6 Experiment Runner")
    parser.add_argument(
        "--condition",
        choices=["baseline", "g6_hint", "g6_forced", "g6_forced_floor", "all"],
        default="all",
        help="Which condition(s) to run (default: all four)",
    )
    parser.add_argument(
        "--samples-path",
        default=str(ROOT / "data" / "03_baseline" / "hardSamples_claude.json"),
        help="Path to hard samples JSON",
    )
    args = parser.parse_args()

    # Load samples
    samples_path = Path(args.samples_path)
    samples = json.loads(samples_path.read_text())
    print(f"Loaded {len(samples)} hard samples from {samples_path.name}\n")

    # Initialize client
    client = OpenAIClient(model="gpt-5-mini")
    g6 = G6FormatFamiliarity()

    # Run conditions
    all_results = {}
    cond = args.condition

    if cond in ("baseline", "all"):
        baseline_results = evaluate_condition(
            client, samples, "BASELINE (no G6)", BASELINE_PROMPT,
            g6=None,
        )
        all_results["baseline"] = baseline_results

    if cond in ("g6_hint", "all"):
        hint_results = evaluate_condition(
            client, samples, "BASELINE + G6 hint-only", BASELINE_PROMPT,
            g6=g6, g6_mode="hint",
        )
        all_results["g6_hint"] = hint_results

    if cond in ("g6_forced", "g6_forced_floor", "all"):
        forced_results = evaluate_condition(
            client, samples, "BASELINE + G6 forced-reasoning", BASELINE_PROMPT,
            g6=g6, g6_mode="forced",
        )
        all_results["g6_forced"] = forced_results

    # Review-floor is derived from g6_forced (no extra API call).
    # This is an experimental post-LLM evaluation condition, not a guardrail.
    verdict_stats = None
    if cond in ("g6_forced_floor", "all"):
        if "g6_forced" not in all_results:
            print("ERROR: g6_forced_floor requires g6_forced results.")
            sys.exit(1)
        floor_results, verdict_stats = apply_review_floor(all_results["g6_forced"])

        print(f"\n{'='*60}")
        print("CONDITION: G6 forced-reasoning + experimental review floor")
        print(f"{'='*60}")
        print(f"  (Derived from g6_forced — no additional API calls)")
        print(f"  Samples with g6_analysis: "
              f"{verdict_stats['samples_with_g6_analysis']}")
        print(f"  Samples with escalation verdict (uncertain/likely_secret): "
              f"{verdict_stats['samples_with_escalation_verdict']}")
        print(f"  Samples actually escalated by floor (PASS→REVIEW): "
              f"{verdict_stats['samples_escalated_by_floor']}")
        if verdict_stats["escalation_verdict_sample_ids"]:
            print(f"  Escalation-verdict samples: "
                  f"{', '.join(verdict_stats['escalation_verdict_sample_ids'])}")
        print()

        # Show per-sample verdict distribution
        print("  --- PER-SAMPLE VERDICT DISTRIBUTION ---")
        for sid, vlist in verdict_stats["per_sample_verdicts"].items():
            if vlist:
                print(f"  {sid}: {vlist}")
        print()

        all_results["g6_forced_floor"] = floor_results

    # Compute and display metrics
    print(f"\n{'='*60}")
    print("METRICS COMPARISON")
    print(f"{'='*60}\n")

    metrics = {}
    for cond_key, cond_results in all_results.items():
        m = compute_metrics(cond_results, cond_key)
        metrics[cond_key] = m
        print(f"--- {cond_key.upper()} ---")
        print(f"  Samples:  {m['total']} ({m['errors']} errors)")
        print(f"  TP: {m['tp']}  FN: {m['fn']}  FP: {m['fp']}  TN: {m['tn']}")
        print(f"  Recall:   {m['recall']:.1%}")
        print(f"  FN Rate:  {m['fn_rate']:.1%}")
        print()

    # G6-specific metrics — computed for each G6 condition vs baseline
    g6_metrics = {}
    g6_condition_keys = [k for k in all_results if k != "baseline"]

    for g6_key in g6_condition_keys:
        g6_valid = [r for r in all_results[g6_key] if "error" not in r]
        flagged = sum(1 for r in g6_valid if r["g6_candidates_count"] > 0)
        coverage = round(flagged / len(g6_valid), 4) if g6_valid else 0.0

        print(f"--- G6 FLAG COVERAGE ({g6_key}) ---")
        print(f"  Samples with G6 candidates: {flagged}/{len(g6_valid)} "
              f"({coverage:.1%})")
        print()

        g6_metrics[g6_key] = {
            "g6_flag_coverage": coverage,
            "g6_flagged_samples": flagged,
        }

    # Pairwise comparison: each G6 condition vs baseline
    if "baseline" in metrics:
        bl_map = {
            r["sample_id"]: r
            for r in all_results.get("baseline", []) if "error" not in r
        }

        for g6_key in g6_condition_keys:
            if g6_key not in metrics:
                continue

            delta_fn = metrics["baseline"]["fn"] - metrics[g6_key]["fn"]
            delta_recall = metrics[g6_key]["recall"] - metrics["baseline"]["recall"]
            print(f"--- DELTA ({g6_key} vs baseline) ---")
            print(f"  FN reduction: {delta_fn} fewer FN")
            print(f"  Recall improvement: {delta_recall:+.1%}")
            print()

            # Per-sample comparison
            print(f"--- PER-SAMPLE COMPARISON ({g6_key} vs baseline) ---")
            cond_map = {
                r["sample_id"]: r
                for r in all_results[g6_key] if "error" not in r
            }

            flipped = []
            recovered = []
            regressed = []
            for sid in bl_map:
                if sid in cond_map:
                    bl_cls = bl_map[sid]["classification"]
                    c_cls = cond_map[sid]["classification"]
                    if bl_cls != c_cls:
                        flipped.append((sid, bl_cls, c_cls))
                        print(f"  FLIP: {sid}: {bl_cls} -> {c_cls}")
                        if bl_cls == "FALSE NEGATIVE" and c_cls == "TRUE POSITIVE":
                            recovered.append(sid)
                        elif bl_cls == "TRUE POSITIVE" and c_cls == "FALSE NEGATIVE":
                            regressed.append(sid)

            if not flipped:
                print("  No classification changes between conditions.")
            print()

            baseline_fn_count = metrics["baseline"]["fn"]
            recovery_count = len(recovered)
            recovery_rate = (
                round(recovery_count / baseline_fn_count, 4)
                if baseline_fn_count > 0 else 0.0
            )

            print(f"--- RECOVERY ANALYSIS ({g6_key}) ---")
            print(f"  Baseline FN count:  {baseline_fn_count}")
            print(f"  Recovery count:     {recovery_count}")
            print(f"  Recovery rate:      {recovery_rate:.1%}")
            if recovered:
                print(f"  Recovered samples:  {', '.join(recovered)}")
            if regressed:
                print(f"  REGRESSED samples:  {', '.join(regressed)}")
            print()

            g6_metrics[g6_key].update({
                "g6_recovery_count": recovery_count,
                "g6_recovery_rate": recovery_rate,
                "g6_recovered_samples": recovered,
                "g6_regressed_samples": regressed,
            })

    # Save results
    out_dir = ROOT / "runs" / "g6_experiment"
    out_dir.mkdir(parents=True, exist_ok=True)

    output = {
        "experiment": "G6 Format-Familiarity Pre-Scan (exploratory)",
        "timestamp": datetime.now().isoformat(),
        "model": "gpt-5-mini",
        "samples_file": samples_path.name,
        "n_samples": len(samples),
        "token_limit": 8192,
        "conditions_run": list(all_results.keys()),
        "conditions": all_results,
        "metrics": metrics,
        "g6_metrics": g6_metrics,
    }
    if verdict_stats is not None:
        output["review_floor_verdict_stats"] = verdict_stats

    out_path = out_dir / "results.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"Results saved to {out_path}")


if __name__ == "__main__":
    main()
