"""
Policies Module for HybridGate Framework

Implements hybrid gate decision policies combining scanner and LLM results:
- P1: Safety-Net Policy (Recall-First / OR logic)
- P2: Consensus Policy (Precision-First / AND logic)
- P3: Escalation Policy (Cost-Optimized)
"""

from .base import PolicyDecision, PolicyResult
from .p1_safety_net import P1SafetyNet
from .p2_consensus import P2Consensus
from .p3_escalation import P3Escalation

__all__ = [
    'PolicyDecision',
    'PolicyResult',
    'P1SafetyNet',
    'P2Consensus',
    'P3Escalation',
    'compute_all_policies'
]


def compute_all_policies(
    scanner_hit: bool,
    llm_hit: bool,
    llm_decision: str = None,
    file_path: str = None,
    secret_type: str = None,
    code_diff: str = None
) -> dict:
    """
    Compute decisions for all three policies.

    Args:
        scanner_hit: Whether any classic scanner detected a secret
        llm_hit: Whether LLM detected a secret (pred_has_secret=True)
        llm_decision: LLM's decision string (PASS/BLOCK/REVIEW)
        file_path: File path for risk assessment
        secret_type: Detected secret type for criticality check
        code_diff: Code diff for obfuscation detection

    Returns:
        Dictionary with decisions from all policies
    """
    p1 = P1SafetyNet()
    p2 = P2Consensus()
    p3 = P3Escalation()

    return {
        "policy_p1": p1.decide(scanner_hit, llm_hit, llm_decision).value,
        "policy_p2": p2.decide(scanner_hit, llm_hit, llm_decision).value,
        "policy_p3": p3.decide(
            scanner_hit=scanner_hit,
            llm_hit=llm_hit,
            llm_decision=llm_decision,
            file_path=file_path,
            secret_type=secret_type,
            code_diff=code_diff
        ).value
    }
