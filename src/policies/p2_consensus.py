"""
P2: Consensus Policy (Precision-First / AND Logic)

Prioritizes precision - blocks only if BOTH scanner AND LLM detect a secret.
Minimizes false positives at the cost of potentially missing some secrets.

Design Decision:
- P2 now considers llm_decision, not just llm_hit
- If llm_decision is REVIEW or UNCERTAIN, we don't auto-PASS
- This prevents cases where LLM uncertainty leads to missed secrets
"""

from typing import Optional
from .base import Policy, PolicyDecision, PolicyResult, LLMDecision


class P2Consensus(Policy):
    """
    Policy P2: Consensus (Precision-First)

    Logic:
    - BLOCK only if scanner_hit AND llm_hit
    - REVIEW if:
      - Only one detector flags (disagreement)
      - LLM decision is REVIEW/UNCERTAIN (even if scanner clean)
    - PASS only if both agree no secret AND LLM is confident

    Use case: Developer-friendly environments where false positives are disruptive.
    Trade-off: Lower false positive rate, but may miss some obfuscated secrets.
    """

    @property
    def name(self) -> str:
        return "P2_Consensus"

    @property
    def description(self) -> str:
        return "Precision-First: BLOCK only if scanner AND LLM agree. Considers LLM uncertainty."

    def decide(self, scanner_hit: bool, llm_hit: bool,
               llm_decision: Optional[str] = None, **kwargs) -> PolicyDecision:
        """
        Make consensus decision (AND logic with uncertainty handling).

        Args:
            scanner_hit: Whether classic scanner detected a secret
            llm_hit: Whether LLM detected a secret (pred_has_secret=True)
            llm_decision: LLM's decision (BLOCK/PASS/REVIEW/NOT_INVOKED)

        Returns:
            PolicyDecision
        """
        # Normalize llm_decision
        llm_dec = (llm_decision or "").upper()

        # G4/G5: If LLM final decision is REVIEW, respect that first
        # This ensures guardrail routing is not overridden by llm_hit
        if llm_dec == "REVIEW":
            return PolicyDecision.REVIEW

        # Both agree secret exists -> BLOCK
        # (only if LLM decision is not REVIEW)
        if scanner_hit and llm_hit:
            return PolicyDecision.BLOCK

        # LLM uncertain (legacy support) -> REVIEW
        if llm_dec == "UNCERTAIN":
            return PolicyDecision.REVIEW

        # One detector flags -> REVIEW (disagreement)
        if scanner_hit or llm_hit:
            return PolicyDecision.REVIEW

        # LLM not invoked -> can't have consensus, use scanner result
        if llm_dec == "NOT_INVOKED":
            return PolicyDecision.REVIEW if scanner_hit else PolicyDecision.PASS

        # Both agree no secret and LLM is confident -> PASS
        return PolicyDecision.PASS

    def _get_reasoning(self, scanner_hit: bool, llm_hit: bool,
                       decision: PolicyDecision,
                       llm_decision: Optional[str] = None, **kwargs) -> str:
        """Generate detailed reasoning."""
        llm_dec = (llm_decision or "NOT_INVOKED").upper()

        if decision == PolicyDecision.BLOCK:
            return "BLOCK: Both scanner and LLM detected secret (consensus)"

        if decision == PolicyDecision.REVIEW:
            if llm_dec in ("REVIEW", "UNCERTAIN"):
                return f"REVIEW: LLM uncertain (decision={llm_dec})"
            if scanner_hit and not llm_hit:
                return "REVIEW: Scanner detected but LLM did not (disagreement)"
            if not scanner_hit and llm_hit:
                return "REVIEW: LLM detected but scanner did not (disagreement)"
            if llm_dec == "NOT_INVOKED":
                return "REVIEW: LLM not invoked, cannot establish consensus"
            return "REVIEW: Detector disagreement"

        return "PASS: Both scanner and LLM agree no secret (confident consensus)"

    def get_full_result(self, scanner_hit: bool, llm_hit: bool,
                        llm_decision: Optional[str] = None, **kwargs) -> PolicyResult:
        """Get full result with consensus-specific metadata."""
        decision = self.decide(scanner_hit, llm_hit, llm_decision, **kwargs)
        llm_dec = (llm_decision or "NOT_INVOKED").upper()

        # Determine agreement status
        if llm_dec == "NOT_INVOKED":
            agreement = "llm_not_invoked"
        elif scanner_hit == llm_hit:
            if llm_dec in ("REVIEW", "UNCERTAIN"):
                agreement = "partial_agreement_llm_uncertain"
            else:
                agreement = "full_agreement"
        else:
            agreement = "disagreement"

        return PolicyResult(
            policy_name=self.name,
            decision=decision,
            scanner_hit=scanner_hit,
            llm_hit=llm_hit,
            llm_decision=llm_dec,
            reasoning=self._get_reasoning(scanner_hit, llm_hit, decision, llm_decision, **kwargs),
            metadata={
                "policy_type": "precision_first",
                "logic": "AND",
                "agreement_status": agreement,
                "detection_count": int(scanner_hit) + int(llm_hit)
            }
        )
