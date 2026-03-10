"""
Gate Effectiveness Metrics for HybridGate Framework

Computes metrics specific to security gate evaluation:
- Leak-Escape-Rate: Secrets that passed through the gate
- False-Block-Rate: Clean code incorrectly blocked
- Review-Load: Proportion requiring manual review
"""

from typing import Dict, List, Any


def compute_leak_escape_rate(
    results: List[Dict[str, Any]],
    policy_key: str = "policy_p1",
    gt_key: str = "gt_has_secret"
) -> Dict[str, Any]:
    """
    Compute Leak-Escape-Rate (LER).

    LER = (secrets that got PASS) / (total secrets)

    This is the most critical security metric - it measures how many
    real secrets would have been leaked to the repository.

    Args:
        results: List of result dictionaries
        policy_key: Key for policy decision (policy_p1, policy_p2, policy_p3)
        gt_key: Key for ground truth

    Returns:
        Dictionary with LER and supporting counts
    """
    # Filter to samples with actual secrets
    with_secrets = [r for r in results if r.get(gt_key, False)]

    if not with_secrets:
        return {
            "leak_escape_rate": 0.0,
            "escaped_secrets": 0,
            "total_secrets": 0,
            "blocked_secrets": 0,
            "reviewed_secrets": 0
        }

    # Count by policy decision
    escaped = 0  # PASS with secret
    blocked = 0  # BLOCK with secret
    reviewed = 0  # REVIEW with secret

    for r in with_secrets:
        decision = r.get(policy_key, "PASS")
        if decision == "PASS":
            escaped += 1
        elif decision == "BLOCK":
            blocked += 1
        elif decision == "REVIEW":
            reviewed += 1

    ler = escaped / len(with_secrets)

    return {
        "leak_escape_rate": round(ler, 4),
        "escaped_secrets": escaped,
        "total_secrets": len(with_secrets),
        "blocked_secrets": blocked,
        "reviewed_secrets": reviewed
    }


def compute_false_block_rate(
    results: List[Dict[str, Any]],
    policy_key: str = "policy_p1",
    gt_key: str = "gt_has_secret"
) -> Dict[str, Any]:
    """
    Compute False-Block-Rate (FBR).

    FBR = (clean PRs that got BLOCK) / (total clean PRs)

    Measures developer friction - how often legitimate code is blocked.

    Args:
        results: List of result dictionaries
        policy_key: Key for policy decision
        gt_key: Key for ground truth

    Returns:
        Dictionary with FBR and supporting counts
    """
    # Filter to samples WITHOUT secrets (negative controls + clean code)
    without_secrets = [r for r in results if not r.get(gt_key, False)]

    if not without_secrets:
        return {
            "false_block_rate": 0.0,
            "false_blocks": 0,
            "total_clean": 0,
            "correctly_passed": 0,
            "sent_to_review": 0
        }

    # Count by policy decision
    false_blocks = 0  # BLOCK without secret
    correctly_passed = 0  # PASS without secret
    sent_to_review = 0  # REVIEW without secret

    for r in without_secrets:
        decision = r.get(policy_key, "PASS")
        if decision == "BLOCK":
            false_blocks += 1
        elif decision == "PASS":
            correctly_passed += 1
        elif decision == "REVIEW":
            sent_to_review += 1

    fbr = false_blocks / len(without_secrets)

    return {
        "false_block_rate": round(fbr, 4),
        "false_blocks": false_blocks,
        "total_clean": len(without_secrets),
        "correctly_passed": correctly_passed,
        "sent_to_review": sent_to_review
    }


def compute_review_load(
    results: List[Dict[str, Any]],
    policy_key: str = "policy_p1"
) -> Dict[str, Any]:
    """
    Compute Review-Load (RL).

    RL = (samples sent to REVIEW) / (total samples)

    Measures the manual review burden on security teams.

    Args:
        results: List of result dictionaries
        policy_key: Key for policy decision

    Returns:
        Dictionary with RL and supporting counts
    """
    if not results:
        return {
            "review_load": 0.0,
            "reviews_required": 0,
            "total_samples": 0,
            "auto_passed": 0,
            "auto_blocked": 0
        }

    reviews = 0
    passed = 0
    blocked = 0

    for r in results:
        decision = r.get(policy_key, "PASS")
        if decision == "REVIEW":
            reviews += 1
        elif decision == "PASS":
            passed += 1
        elif decision == "BLOCK":
            blocked += 1

    rl = reviews / len(results)

    return {
        "review_load": round(rl, 4),
        "reviews_required": reviews,
        "total_samples": len(results),
        "auto_passed": passed,
        "auto_blocked": blocked
    }


def compute_gate_metrics(
    results: List[Dict[str, Any]],
    policy_key: str = "policy_p1"
) -> Dict[str, Any]:
    """
    Compute all gate effectiveness metrics for a policy.

    Args:
        results: List of result dictionaries
        policy_key: Key for policy decision

    Returns:
        Comprehensive gate metrics dictionary
    """
    ler = compute_leak_escape_rate(results, policy_key=policy_key)
    fbr = compute_false_block_rate(results, policy_key=policy_key)
    rl = compute_review_load(results, policy_key=policy_key)

    return {
        "policy": policy_key,
        "leak_escape_rate": ler["leak_escape_rate"],
        "false_block_rate": fbr["false_block_rate"],
        "review_load": rl["review_load"],
        "details": {
            "leak_escape": ler,
            "false_block": fbr,
            "review_load": rl
        }
    }


def compute_all_policies_metrics(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Compute gate metrics for all three policies.

    Args:
        results: List of result dictionaries

    Returns:
        Dictionary mapping policy name -> metrics
    """
    policies = ["policy_p1", "policy_p2", "policy_p3"]

    all_metrics = {}
    for policy in policies:
        all_metrics[policy] = compute_gate_metrics(results, policy_key=policy)

    return all_metrics


def compare_policies(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a comparison summary of all policies.

    Args:
        results: List of result dictionaries

    Returns:
        Comparison summary with recommendations
    """
    all_metrics = compute_all_policies_metrics(results)

    # Find best policy for each metric
    best_ler = min(all_metrics.items(), key=lambda x: x[1]["leak_escape_rate"])
    best_fbr = min(all_metrics.items(), key=lambda x: x[1]["false_block_rate"])
    best_rl = min(all_metrics.items(), key=lambda x: x[1]["review_load"])

    return {
        "metrics": all_metrics,
        "best_for_security": best_ler[0],  # Lowest LER
        "best_for_developer_experience": best_fbr[0],  # Lowest FBR
        "best_for_efficiency": best_rl[0],  # Lowest RL
        "summary": {
            "P1_SafetyNet": "Maximizes security (lowest LER), highest review load",
            "P2_Consensus": "Balanced approach, requires agreement",
            "P3_Escalation": "Cost-optimized, selective LLM usage"
        }
    }
