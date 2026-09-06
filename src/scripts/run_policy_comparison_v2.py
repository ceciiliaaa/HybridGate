"""
Policy Comparison v2 Runner

Applies P1/P2/P3 policies exclusively to LLM guardrail results.
Policies are a decision layer on top of the guardrail output —
they are never applied to baseline LLM output.

Inputs per sample:
  - scanner_hit           (from sample)
  - llm_decision          (from llm_guardrail.final_decision)
  - guardrail_results     (extracted from llm_guardrail: g1/g2/g3/g4/g5/g6 flags)
  - file_path             (from gt_file_path — metadata, not ground truth label)
  - pred_secret_type      (from llm_guardrail.pred_secret_type — never gt_secret_type)

Usage:
    python -m src.scripts.run_policy_comparison_v2
"""

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# --- Paths ------------------------------------------------------------------
REPO = Path(__file__).resolve().parents[2]
RESULTS = {
    "openai":    REPO / "runs/v140_full_g6_250samples/results_g4fix.json",
    "anthropic": REPO / "runs/v150_anthropic_opus46_full/results.json",
}
OUT_FILE = REPO / "runs/policy_results/policy_comparison_v2.json"


# --- Field extraction -------------------------------------------------------

def _extract_guardrail_results(llm_guardrail: Optional[Dict]) -> Dict[str, Any]:
    """Normalise llm_guardrail flags into the guardrail_results dict the policies expect."""
    if not llm_guardrail:
        return {}
    g4 = llm_guardrail.get("g4_details") or {}
    g3 = llm_guardrail.get("g3_details") or {}
    return {
        "g5_schema_valid":   llm_guardrail.get("g5_valid", True),
        "g3_leak_persisted": g3.get("leak_detected_after_mitigation", False),
        "g4_review":         g4.get("should_review", False),
        "g1_fail":           not llm_guardrail.get("g1_valid", True),
        "g2_triggered":      not llm_guardrail.get("g2_valid", True),
        # g6_hint_injected: raw G6 format-candidate signal (used as Q in P3)
        "g6_hint_injected":  bool(llm_guardrail.get("g6_hint_injected")),
        # g6_ignored: hint injected but LLM still said no secret (used in P1/P2 review signal)
        "g6_ignored": bool(
            llm_guardrail.get("g6_hint_injected")
            and not llm_guardrail.get("pred_has_secret", True)
        ),
    }


def _guardrail_inputs(sample: Dict) -> Optional[Dict]:
    """
    Return the policy input dict for a sample, or None if guardrail was not run.
    Policies are ONLY applied to guardrail results.

    pred_has_secret: raw LLM binary judgment (before guardrail routing).
    pred_secret_type: LLM-predicted type — never gt_secret_type.
    llm_decision: final_decision (post-guardrail, used by P1/P3).
    """
    llm_g = sample.get("llm_guardrail")
    if not llm_g:
        return None
    return {
        "scanner_hit":       sample.get("scanner_hit", False),
        "llm_hit":           sample.get("llm_guardrail_hit", False),
        "llm_decision":      (llm_g.get("final_decision") or "").upper() or None,
        "pred_has_secret":   llm_g.get("pred_has_secret"),   # raw, pre-guardrail routing
        "file_path":         sample.get("gt_file_path"),
        "pred_secret_type":  llm_g.get("pred_secret_type"),
        "guardrail_results": _extract_guardrail_results(llm_g),
    }


# --- Metrics ----------------------------------------------------------------

def _clf(decisions: List[str], gts: List[bool], pos) -> Dict:
    tp = fp = tn = fn = 0
    for d, g in zip(decisions, gts):
        p = d in pos
        if g and p:     tp += 1
        elif not g and p: fp += 1
        elif g and not p: fn += 1
        else:             tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)}


def _dist(decisions: List[str]) -> Dict:
    n = len(decisions)
    cnt = Counter(decisions)
    return {
        "n": n,
        "BLOCK": cnt["BLOCK"], "REVIEW": cnt["REVIEW"], "PASS": cnt["PASS"],
        "block_rate":  round(cnt["BLOCK"]  / n, 4) if n else 0.0,
        "review_rate": round(cnt["REVIEW"] / n, 4) if n else 0.0,
        "pass_rate":   round(cnt["PASS"]   / n, 4) if n else 0.0,
    }


def _ler(decisions: List[str], gts: List[bool]) -> Dict:
    secrets = [(d, g) for d, g in zip(decisions, gts) if g]
    if not secrets:
        return {"leak_escape_rate": 0.0, "escaped": 0, "total_secrets": 0}
    escaped = sum(1 for d, _ in secrets if d == "PASS")
    return {"leak_escape_rate": round(escaped / len(secrets), 4),
            "escaped": escaped, "total_secrets": len(secrets)}


def _fbr(decisions: List[str], gts: List[bool]) -> Dict:
    clean = [(d, g) for d, g in zip(decisions, gts) if not g]
    if not clean:
        return {"false_block_rate": 0.0, "false_blocks": 0, "total_clean": 0}
    fb = sum(1 for d, _ in clean if d == "BLOCK")
    return {"false_block_rate": round(fb / len(clean), 4),
            "false_blocks": fb, "total_clean": len(clean)}


# --- Policy evaluation ------------------------------------------------------

def _evaluate_policy(policy_obj, samples: List[Dict]) -> Dict:
    """Run policy on all samples that have guardrail results."""
    decisions, gts, meta = [], [], []

    for s in samples:
        inputs = _guardrail_inputs(s)
        if inputs is None:
            continue
        gt = s.get("gt_has_secret", False)
        result = policy_obj.get_full_result(**inputs)
        decisions.append(result.decision.value)
        gts.append(gt)
        meta.append(result.metadata)

    out = {
        "n_evaluated":       len(decisions),
        "autonomous_view":   _clf(decisions, gts, ("BLOCK",)),
        "alert_view":        _clf(decisions, gts, ("BLOCK", "REVIEW")),
        "distribution":      _dist(decisions),
        "leak_escape":       _ler(decisions, gts),
        "false_block":       _fbr(decisions, gts),
    }

    # P2: count LLM-override cases (scanner=hit, LLM=PASS → PASS)
    if hasattr(policy_obj, "_is_high_risk_file"):
        out["llm_override_count"] = sum(m.get("llm_override_count", 0) for m in meta)

    # P3: score histogram
    if hasattr(policy_obj, "compute_score"):
        hist = Counter(m.get("score", 0) for m in meta)
        out["score_histogram"] = {str(k): v for k, v in sorted(hist.items())}

    return out


# --- Main -------------------------------------------------------------------

def main():
    from src.policies.p1_safety_net    import P1SafetyNet
    from src.policies.p2_contextual_veto import P2ContextualVeto
    from src.policies.p3_risk_weighted import P3RiskWeighted

    policies = {
        "P1_SafetyNet":      P1SafetyNet(),
        "P2_ContextualVeto": P2ContextualVeto(),
        "P3_RiskWeighted":   P3RiskWeighted(),
    }

    data: Dict[str, List[Dict]] = {}
    for provider, path in RESULTS.items():
        if not path.exists():
            print(f"WARNING: {path} not found, skipping {provider}", file=sys.stderr)
            continue
        with open(path) as f:
            data[provider] = json.load(f)
        print(f"Loaded {len(data[provider])} samples — {provider}")

    output: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "Policies applied exclusively to LLM guardrail results.",
        "policies": {},
        "comparison": {},
    }

    for policy_name, policy_obj in policies.items():
        print(f"\n{'='*52}\n  {policy_name}\n{'='*52}")
        output["policies"][policy_name] = {}

        for provider, samples in data.items():
            m = _evaluate_policy(policy_obj, samples)
            output["policies"][policy_name][provider] = m
            extras = ""
            if "llm_override_count" in m:
                extras += f"  overrides={m['llm_override_count']}"
            if "score_histogram" in m:
                extras += f"  scores={dict(m['score_histogram'])}"
            print(
                f"  {provider}: n={m['n_evaluated']}  "
                f"auto F1={m['autonomous_view']['f1']:.3f}  "
                f"alert F1={m['alert_view']['f1']:.3f}  "
                f"B={m['distribution']['BLOCK']} R={m['distribution']['REVIEW']} P={m['distribution']['PASS']}"
                + extras
            )

    # --- P1 vs P2 PASS differentiation ---
    def _pass_ids(policy_obj, samples):
        ids = []
        for s in samples:
            inputs = _guardrail_inputs(s)
            if inputs is None:
                continue
            dec = policy_obj.decide(**inputs)
            if dec.value == "PASS":
                ids.append(s["sample_id"])
        return ids

    diff: Dict[str, Any] = {}
    for provider, samples in data.items():
        p1_pass = set(_pass_ids(policies["P1_SafetyNet"],      samples))
        p2_pass = set(_pass_ids(policies["P2_ContextualVeto"], samples))
        diff[provider] = {
            "p1_pass_count":    len(p1_pass),
            "p2_pass_count":    len(p2_pass),
            "identical":        p1_pass == p2_pass,
            "p2_only_pass":     sorted(p2_pass - p1_pass),
            "p1_only_pass":     sorted(p1_pass - p2_pass),
        }
    output["comparison"]["p1_vs_p2_pass"] = diff

    # --- Console summary ---
    print("\n" + "="*60)
    print("P1 vs P2 PASS differentiation (guardrail only)")
    print("="*60)
    for provider, v in diff.items():
        print(f"  {provider}: P1={v['p1_pass_count']} P2={v['p2_pass_count']}  "
              f"identical={v['identical']}  P2 extra={len(v['p2_only_pass'])}")
        if v["p2_only_pass"]:
            print(f"    P2-only PASS: {v['p2_only_pass'][:10]}")

    print("\n" + "="*60)
    print("Distribution summary (guardrail only)")
    print("="*60)
    for policy_name in policies:
        for provider in data:
            d = output["policies"][policy_name][provider]["distribution"]
            av = output["policies"][policy_name][provider]["autonomous_view"]
            al = output["policies"][policy_name][provider]["alert_view"]
            print(f"  {policy_name}/{provider}: "
                  f"B={d['block_rate']:.0%} R={d['review_rate']:.0%} P={d['pass_rate']:.0%}  "
                  f"auto-F1={av['f1']:.3f}  alert-F1={al['f1']:.3f}")

    print("\n" + "="*60)
    print("P3 Score Histogram")
    print("="*60)
    for provider in data:
        h = output["policies"]["P3_RiskWeighted"][provider].get("score_histogram", {})
        print(f"  {provider}: {h}")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved → {OUT_FILE}")


if __name__ == "__main__":
    main()
