#!/usr/bin/env python3
"""
Quick test: send hard samples to OpenAI baseline to check for False Negatives.

Usage:
    python scripts/run_hard_samples_test.py
"""

import json
import sys
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

# Override token limit for hard samples (more reasoning needed)
import src.llm_evaluation.run_evaluation as _eval
_ORIG_CALL = OpenAIClient._call_api

def _call_api_extended(self, system_prompt, user_prompt):
    response = self.client.chat.completions.create(
        model=self.model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        max_completion_tokens=8192,  # 4x the default
    )
    return response.choices[0].message.content

OpenAIClient._call_api = _call_api_extended


def main():
    samples_path = ROOT / "data" / "03_baseline" / "hardSamples_claude.json"
    samples = json.loads(samples_path.read_text())
    print(f"Loaded {len(samples)} hard samples\n")

    client = OpenAIClient(model="gpt-5-mini")

    results = []
    for s in samples:
        sid = s["sample_id"]
        numbered_diff = number_lines(s.get("code_context", ""))
        user_prompt = USER_PROMPT_TEMPLATE.format(
            pr_title=s.get("pr_title", ""),
            pr_body=s.get("pr_body", ""),
            code_context=numbered_diff,
        )

        print(f"--- {sid} ({s['condition']}) ---")
        raw = client._call_api(BASELINE_PROMPT, user_prompt)
        pred = extract_json(raw)

        if pred is None:
            print(f"  PARSE ERROR: {raw[:200]}")
            results.append({"sample_id": sid, "error": "parse_error"})
            continue

        detected = pred.get("pred_has_secret", False)
        decision = pred.get("final_decision", "?")
        reasoning = pred.get("reasoning", "")

        is_fn = not detected  # gt_has_secret is always True here
        label = "FALSE NEGATIVE" if is_fn else "TRUE POSITIVE"

        print(f"  pred_has_secret: {detected}")
        print(f"  final_decision:  {decision}")
        print(f"  reasoning:       {reasoning[:150]}")
        print(f"  => {label}")
        print()

        results.append({
            "sample_id": sid,
            "condition": s["condition"],
            "gt_has_secret": True,
            "pred_has_secret": detected,
            "final_decision": decision,
            "reasoning": reasoning,
            "is_false_negative": is_fn,
        })

    # Summary
    fn_count = sum(1 for r in results if r.get("is_false_negative"))
    tp_count = sum(1 for r in results if r.get("is_false_negative") is False)
    err_count = sum(1 for r in results if "error" in r)

    print("=" * 50)
    print(f"SUMMARY: {len(results)} samples")
    print(f"  TP (correctly detected):  {tp_count}")
    print(f"  FN (missed = goal!):      {fn_count}")
    print(f"  Errors:                   {err_count}")
    print("=" * 50)

    # Save results
    out_path = ROOT / "scripts" / "hard_samples_results.json"
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
