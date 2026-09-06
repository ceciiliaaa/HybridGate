"""
P1: Safety-Net Policy (Recall-First)

Prioritizes recall — blocks if EITHER scanner OR LLM detects a secret.
Hard-fails (G5 schema invalid, G3 leak persisted) force REVIEW before policy logic.
Review signals (G1/G2/G4/G6) are checked AFTER the OR-detection check.
"""

from typing import Optional, Dict, Any
from .base import Policy, PolicyDecision, PolicyResult


class P1SafetyNet(Policy):
    """
    Policy P1: Safety-Net (Recall-First)

    Logic:
    Pre-Policy:  IF hard_fail → REVIEW
    IF scanner_hit OR llm_decision == "BLOCK" → BLOCK
    IF llm_decision == "REVIEW" OR review_signal → REVIEW
    ELSE → PASS

    Use case: High-security environments where missing a secret is unacceptable.
    Trade-off: Higher false positive rate, more manual reviews.
    """

    @property
    def name(self) -> str:
        return "P1_SafetyNet"

    @property
    def description(self) -> str:
        return "Recall-First: BLOCK if scanner OR LLM detects. Hard-fail forces REVIEW."

    @staticmethod
    def _check_hard_fail(guardrail_results: Dict[str, Any]) -> bool:
        g5_failed = guardrail_results.get("g5_schema_valid") is False
        g3_persisted = guardrail_results.get("g3_leak_persisted") is True
        return g5_failed or g3_persisted

    @staticmethod
    def _has_review_signal(guardrail_results: Dict[str, Any]) -> bool:
        return (
            guardrail_results.get("g4_review") is True
            or guardrail_results.get("g1_fail") is True
            or guardrail_results.get("g2_triggered") is True
            or guardrail_results.get("g6_ignored") is True
        )

    def decide(self, scanner_hit: bool, llm_hit: bool,
               llm_decision: Optional[str] = None, **kwargs) -> PolicyDecision:
        guardrail_results: Dict[str, Any] = kwargs.get("guardrail_results", {})
        llm_dec = (llm_decision or "").upper()

        if self._check_hard_fail(guardrail_results):
            return PolicyDecision.REVIEW

        if scanner_hit or llm_dec == "BLOCK":
            return PolicyDecision.BLOCK

        if llm_dec == "REVIEW" or self._has_review_signal(guardrail_results):
            return PolicyDecision.REVIEW

        return PolicyDecision.PASS

    def _get_reasoning(self, scanner_hit: bool, llm_hit: bool,
                       decision: PolicyDecision,
                       llm_decision: Optional[str] = None, **kwargs) -> str:
        guardrail_results = kwargs.get("guardrail_results", {})
        llm_dec = llm_decision or "NOT_INVOKED"

        if decision == PolicyDecision.BLOCK:
            triggers = []
            if scanner_hit:
                triggers.append("scanner")
            if (llm_decision or "").upper() == "BLOCK":
                triggers.append("LLM")
            return f"BLOCK: Detected by {' and '.join(triggers) or 'unknown'} (OR logic)"

        if decision == PolicyDecision.REVIEW:
            if self._check_hard_fail(guardrail_results):
                return "REVIEW: Hard-fail condition (G5 schema invalid or G3 leak persisted)"
            if (llm_decision or "").upper() == "REVIEW":
                return f"REVIEW: LLM uncertain (decision={llm_dec})"
            return f"REVIEW: Epistemic signal from guardrails"

        return "PASS: No detection from scanner or LLM"

    def get_full_result(self, scanner_hit: bool, llm_hit: bool,
                        llm_decision: Optional[str] = None, **kwargs) -> PolicyResult:
        decision = self.decide(scanner_hit, llm_hit, llm_decision, **kwargs)
        guardrail_results = kwargs.get("guardrail_results", {})
        llm_dec = (llm_decision or "NOT_INVOKED").upper()

        return PolicyResult(
            policy_name=self.name,
            decision=decision,
            scanner_hit=scanner_hit,
            llm_hit=llm_hit,
            llm_decision=llm_dec,
            reasoning=self._get_reasoning(scanner_hit, llm_hit, decision, llm_decision, **kwargs),
            metadata={
                "policy_type": "recall_first",
                "logic": "OR",
                "hard_fail": self._check_hard_fail(guardrail_results),
                "review_signal": self._has_review_signal(guardrail_results),
                "detection_count": int(scanner_hit) + int(llm_dec == "BLOCK"),
            }
        )
