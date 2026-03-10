"""
P1: Safety-Net Policy (Recall-First / OR Logic)

Prioritizes recall - blocks if EITHER scanner OR LLM detects a secret.
Minimizes false negatives at the cost of more false positives.
"""

from typing import Optional
from .base import Policy, PolicyDecision, PolicyResult, LLMDecision


class P1SafetyNet(Policy):
    """
    Policy P1: Safety-Net (Recall-First)

    Logic:
    - BLOCK if scanner_hit OR llm_hit
    - REVIEW if llm_decision is "REVIEW" (uncertain)
    - PASS only if both scanner and LLM agree no secret

    Use case: High-security environments where missing a secret is unacceptable.
    Trade-off: Higher false positive rate, more manual reviews.
    """

    @property
    def name(self) -> str:
        return "P1_SafetyNet"

    @property
    def description(self) -> str:
        return "Recall-First: BLOCK if scanner OR LLM detects. Minimizes missed secrets."

    def decide(self, scanner_hit: bool, llm_hit: bool,
               llm_decision: Optional[str] = None, **kwargs) -> PolicyDecision:
        """
        Make safety-net decision (OR logic).

        Args:
            scanner_hit: Whether classic scanner detected a secret
            llm_hit: Whether LLM detected a secret (pred_has_secret=True)
            llm_decision: LLM decision string (PASS/BLOCK/REVIEW/NOT_INVOKED)

        Returns:
            PolicyDecision
        """
        llm_dec = (llm_decision or "").upper()

        # G4/G5: If LLM final decision is REVIEW, respect that first
        # This ensures guardrail routing is not overridden by llm_hit
        if llm_dec == "REVIEW":
            return PolicyDecision.REVIEW

        # If either detector flags a secret -> BLOCK
        # (only if LLM decision is not REVIEW)
        if scanner_hit or llm_hit:
            return PolicyDecision.BLOCK

        # If LLM is uncertain (legacy support) -> REVIEW
        if llm_dec == "UNCERTAIN":
            return PolicyDecision.REVIEW

        # Both agree no secret -> PASS
        return PolicyDecision.PASS

    def _get_reasoning(self, scanner_hit: bool, llm_hit: bool,
                       decision: PolicyDecision,
                       llm_decision: Optional[str] = None, **kwargs) -> str:
        """Generate detailed reasoning."""
        llm_dec = llm_decision or "NOT_INVOKED"

        if decision == PolicyDecision.BLOCK:
            triggers = []
            if scanner_hit:
                triggers.append("scanner")
            if llm_hit:
                triggers.append("LLM")
            return f"BLOCK: Secret detected by {' and '.join(triggers)} (OR logic)"

        if decision == PolicyDecision.REVIEW:
            return f"REVIEW: LLM uncertain (decision={llm_dec})"

        return "PASS: No detection from scanner or LLM"

    def get_full_result(self, scanner_hit: bool, llm_hit: bool,
                        llm_decision: Optional[str] = None, **kwargs) -> PolicyResult:
        """Get full result with safety-net specific metadata."""
        decision = self.decide(scanner_hit, llm_hit, llm_decision, **kwargs)
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
                "detection_count": int(scanner_hit) + int(llm_hit)
            }
        )
