"""
Policies Module for HybridGate Framework

Implements hybrid gate decision policies combining scanner and LLM results:
- P1: Safety-Net Policy (Recall-First / OR logic + hard-fail pre-check)
- P2: Contextual-Veto Policy (Developer Experience / LLM can override scanner)
- P3: Risk-Weighted Scoring Policy (Enterprise / score-based)

Legacy policies (kept for reference):
- P2Consensus (src/policies/p2_consensus.py)
- P3Escalation (src/policies/p3_escalation.py)
"""

from .base import PolicyDecision, PolicyResult
from .p1_safety_net import P1SafetyNet
from .p2_contextual_veto import P2ContextualVeto
from .p3_risk_weighted import P3RiskWeighted

__all__ = [
    'PolicyDecision',
    'PolicyResult',
    'P1SafetyNet',
    'P2ContextualVeto',
    'P3RiskWeighted',
    'compute_all_policies',
]


def compute_all_policies(
    scanner_hit: bool,
    llm_hit: bool,
    llm_decision: str = None,
    file_path: str = None,
    pred_secret_type: str = None,
    guardrail_results: dict = None,
) -> dict:
    """
    Compute decisions for all three policies.

    Args:
        scanner_hit: Whether any classic scanner detected a secret
        llm_hit: Whether LLM detected a secret (pred_has_secret=True)
        llm_decision: LLM's final decision string (PASS/BLOCK/REVIEW)
        file_path: File path for high-risk file check
        pred_secret_type: LLM-predicted secret type (never use gt_secret_type)
        guardrail_results: Dict with g1_fail, g2_triggered, g4_review,
                           g5_schema_valid, g3_leak_persisted, g6_ignored

    Returns:
        Dictionary with decisions from all three policies
    """
    if guardrail_results is None:
        guardrail_results = {}

    p1 = P1SafetyNet()
    p2 = P2ContextualVeto()
    p3 = P3RiskWeighted()

    ctx = dict(
        guardrail_results=guardrail_results,
        file_path=file_path,
        pred_secret_type=pred_secret_type,
    )

    return {
        "policy_p1": p1.decide(scanner_hit, llm_hit, llm_decision, **ctx).value,
        "policy_p2": p2.decide(scanner_hit, llm_hit, llm_decision, **ctx).value,
        "policy_p3": p3.decide(scanner_hit, llm_hit, llm_decision, **ctx).value,
    }
