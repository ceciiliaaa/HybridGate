#!/usr/bin/env python3
"""
G4 Hard Samples Experiment — Isolated Test Run

Runs G4 hard samples (FM4: Uncertainty Miscalibration) under two conditions:
  1. BASELINE: GPT-5-mini with BASELINE_PROMPT (no guardrails)
  2. GUARDRAIL: GPT-5-mini with SYSTEM_PROMPT + G1-G5 guardrails (post-LLM routing)

Compares baseline vs guardrail decisions to measure G4's routing effect.

Usage:
    python scripts/run_g4_experiment.py --condition baseline
    python scripts/run_g4_experiment.py --condition guardrail
    python scripts/run_g4_experiment.py --condition all
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.llm_evaluation.run_evaluation import (
    BASELINE_PROMPT,
    SYSTEM_PROMPT,
    OpenAIClient,
    USER_PROMPT_TEMPLATE,
    extract_json,
    number_lines,
)
from src.guardrails import (
    get_guardrail_bundle,
    apply_guardrails_with_routing,
    GuardrailSettings,
)

# Use full guardrail settings (G1-G5 all enabled)
FULL_SETTINGS = GuardrailSettings.full()


# Extended token limit
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


DEFAULT_SAMPLES_PATH = ROOT / "data" / "03_baseline" / "g4_hardSamples.json"
OUTPUT_DIR = ROOT / "runs" / "g4_experiment"


def run_sample(client, system_prompt, user_prompt, sample_id):
    """Run a single sample with retry logic."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            raw = client._call_api(system_prompt, user_prompt)
            return raw
        except Exception as e:
            print(f"  [{sample_id}] API error attempt {attempt+1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(4 * (attempt + 1))
    return None


def run_baseline(client, samples):
    """Run samples in baseline mode (no guardrails)."""
    print(f"\n{'='*60}")
    print("CONDITION: BASELINE (no guardrails)")
    print(f"{'='*60}\n")

    results = []
    for i, s in enumerate(samples):
        sid = s["sample_id"]
        numbered_diff = number_lines(s.get("code_context", ""))
        user_prompt = USER_PROMPT_TEMPLATE.format(
            pr_title=s.get("pr_title", ""),
            pr_body=s.get("pr_body", ""),
            code_context=numbered_diff,
        )

        print(f"[{i+1}/{len(samples)}] {sid}", end="")
        raw = run_sample(client, BASELINE_PROMPT, user_prompt, sid)

        if raw is None:
            print(" => API ERROR")
            results.append({"sample_id": sid, "error": "api_error"})
            continue

        pred = extract_json(raw)
        if pred is None:
            print(" => PARSE ERROR")
            results.append({"sample_id": sid, "error": "parse_error"})
            continue

        has_secret = pred.get("pred_has_secret", False)
        decision = pred.get("final_decision", "BLOCK" if has_secret else "PASS")
        gt = s.get("gt_has_secret", True)
        tp = has_secret and gt
        fn = not has_secret and gt

        label = "TP" if tp else ("FN" if fn else ("FP" if has_secret else "TN"))
        print(f" => {label} | decision={decision} | has_secret={has_secret}")

        results.append({
            "sample_id": sid,
            "condition": s.get("condition", ""),
            "gt_has_secret": gt,
            "pred_has_secret": has_secret,
            "decision": decision,
            "classification": label,
            "confidence": pred.get("confidence"),
            "reasoning": pred.get("reasoning", ""),
            "evidence_snippet": pred.get("evidence_snippet", ""),
        })

    return results


def run_guardrail(client, samples):
    """Run samples with full guardrail bundle (G1-G5)."""
    print(f"\n{'='*60}")
    print("CONDITION: GUARDRAIL (G1-G5)")
    print(f"{'='*60}\n")

    # Build guardrail-enhanced system prompt
    guardrail_bundle = get_guardrail_bundle(FULL_SETTINGS)
    system_prompt = SYSTEM_PROMPT + "\n\n" + guardrail_bundle

    results = []
    for i, s in enumerate(samples):
        sid = s["sample_id"]
        numbered_diff = number_lines(s.get("code_context", ""))
        user_prompt = USER_PROMPT_TEMPLATE.format(
            pr_title=s.get("pr_title", ""),
            pr_body=s.get("pr_body", ""),
            code_context=numbered_diff,
        )

        print(f"[{i+1}/{len(samples)}] {sid}", end="")
        raw = run_sample(client, system_prompt, user_prompt, sid)

        if raw is None:
            print(" => API ERROR")
            results.append({"sample_id": sid, "error": "api_error"})
            continue

        # Apply full guardrail pipeline (G5 -> G2 -> G4 -> G1 -> G3)
        guardrail_result = apply_guardrails_with_routing(
            raw,
            ground_truth={"gt_secret_value": s.get("gt_secret_value")},
            settings=FULL_SETTINGS,
            diff_context=numbered_diff,
            pr_title=s.get("pr_title", ""),
            pr_body=s.get("pr_body", ""),
            scanner_hit=False,  # no scanner in isolated test
            file_path=s.get("gt_file_path", ""),
        )

        parsed = guardrail_result.get("parsed_output") or {}
        has_secret = bool(parsed.get("pred_has_secret", False))
        original_decision = guardrail_result.get("original_decision", "")
        final_decision = guardrail_result.get("final_decision", "")
        routed_by = guardrail_result.get("routed_by_guardrail")
        triggered = guardrail_result.get("triggered_guardrails", [])

        gt = s.get("gt_has_secret", True)
        tp = has_secret and gt
        fn = not has_secret and gt
        label = "TP" if tp else ("FN" if fn else ("FP" if has_secret else "TN"))

        # G4 details
        g4_details = guardrail_result.get("g4_details", {})
        g4_should_review = g4_details.get("should_review", False)
        g4_rule = g4_details.get("triggered_rule", "")
        g4_reason = g4_details.get("trigger_reason", "")

        routing_info = ""
        if routed_by:
            routing_info = f" | routed={routed_by} ({original_decision}->{final_decision})"
        if g4_should_review:
            routing_info += f" | G4_rule={g4_rule}"

        print(f" => {label} | final={final_decision} | has_secret={has_secret}{routing_info}")
        if triggered:
            print(f"     triggered: {triggered}")

        results.append({
            "sample_id": sid,
            "condition": s.get("condition", ""),
            "gt_has_secret": gt,
            "pred_has_secret": has_secret,
            "original_decision": original_decision,
            "final_decision": final_decision,
            "routed_by_guardrail": routed_by,
            "triggered_guardrails": triggered,
            "classification": label,
            "confidence": guardrail_result.get("confidence"),
            "g4_should_review": g4_should_review,
            "g4_triggered_rule": g4_rule,
            "g4_trigger_reason": g4_reason,
            "g4_reported_flags": g4_details.get("reported_flags", []),
            "g4_inferred_flags": g4_details.get("inferred_flags", []),
            "g4_all_flags": g4_details.get("all_flags", []),
            "g1_valid": guardrail_result.get("g1_valid"),
            "g2_valid": guardrail_result.get("g2_valid"),
            "g5_valid": guardrail_result.get("g5_valid"),
            "schema_valid": guardrail_result.get("schema_valid"),
            "evidence_snippet": parsed.get("evidence_snippet", ""),
        })

    return results


def print_summary(results, condition_name):
    """Print summary statistics."""
    valid = [r for r in results if "error" not in r]
    if not valid:
        print(f"\n  No valid results for {condition_name}")
        return

    tp = sum(1 for r in valid if r["classification"] == "TP")
    fn = sum(1 for r in valid if r["classification"] == "FN")
    fp = sum(1 for r in valid if r["classification"] == "FP")
    tn = sum(1 for r in valid if r["classification"] == "TN")

    total_pos = tp + fn
    recall = tp / total_pos if total_pos > 0 else 0
    fn_rate = fn / total_pos if total_pos > 0 else 0

    print(f"\n{'─'*40}")
    print(f"  {condition_name} Summary (n={len(valid)})")
    print(f"{'─'*40}")
    print(f"  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    print(f"  Recall: {recall:.1%}  |  FN-Rate: {fn_rate:.1%}")

    if condition_name == "GUARDRAIL":
        routed = [r for r in valid if r.get("routed_by_guardrail")]
        g4_routed = [r for r in valid if r.get("g4_should_review")]
        print(f"  Routed to REVIEW: {len(routed)}/{len(valid)}")
        print(f"  G4 triggered: {len(g4_routed)}/{len(valid)}")
        for r in g4_routed:
            print(f"    - {r['sample_id']}: rule={r['g4_triggered_rule']}, "
                  f"decision={r['original_decision']}->{r['final_decision']}")


def main():
    parser = argparse.ArgumentParser(description="G4 Hard Samples Experiment")
    parser.add_argument(
        "--condition", choices=["baseline", "guardrail", "all"],
        default="all", help="Which condition to run"
    )
    parser.add_argument(
        "--samples-path", type=Path, default=DEFAULT_SAMPLES_PATH,
        help="Path to hard samples JSON file"
    )
    args = parser.parse_args()

    # Load samples
    with open(args.samples_path) as f:
        samples = json.load(f)
    print(f"Loaded {len(samples)} samples from {args.samples_path}")

    client = OpenAIClient(model="gpt-5-mini")
    all_results = {}

    if args.condition in ("baseline", "all"):
        baseline_results = run_baseline(client, samples)
        all_results["baseline"] = baseline_results
        print_summary(baseline_results, "BASELINE")

    if args.condition in ("guardrail", "all"):
        guardrail_results = run_guardrail(client, samples)
        all_results["guardrail"] = guardrail_results
        print_summary(guardrail_results, "GUARDRAIL")

    # Save results
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / "results.json"
    output = {
        "timestamp": datetime.now().isoformat(),
        "samples_path": str(args.samples_path),
        "n_samples": len(samples),
        "conditions": all_results,
    }
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
