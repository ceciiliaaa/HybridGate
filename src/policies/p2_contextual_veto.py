"""
P2: Contextual-Veto Policy (Developer Experience / Precision-First)

LLM can override scanner hits when context is low-risk.
Hard-fails force REVIEW before policy logic.
"""

from typing import Optional, Dict, Any
from .base import Policy, PolicyDecision, PolicyResult


class P2ContextualVeto(Policy):
    """
    Policy P2: Contextual-Veto (Developer Experience)

    Logic:
    Pre-Policy:  IF hard_fail → REVIEW
    IF scanner_hit AND llm_decision == "BLOCK" → BLOCK
    IF scanner_hit AND llm_decision == "PASS"
       AND NOT review_signal AND NOT high_risk_file AND NOT critical_secret_type
       → PASS  (LLM overrides scanner)
    IF scanner_hit OR llm_decision IN {"BLOCK","REVIEW"} OR review_signal → REVIEW
    ELSE → PASS

    Use case: Developer-friendly environments where false positives are disruptive.
    Trade-off: Requires both scanner and LLM to agree on block; LLM can veto scanner.
    """

    HIGH_RISK_PATTERNS = [".env", "config", "credentials", "auth", "secret", "key"]
    CRITICAL_SECRET_TYPES = {"private_key", "connection_string"}

    @property
    def name(self) -> str:
        return "P2_ContextualVeto"

    @property
    def description(self) -> str:
        return "Developer Experience: LLM can veto scanner in low-risk context."

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

    def _is_high_risk_file(self, file_path: Optional[str]) -> bool:
        if not file_path:
            return False
        lower = file_path.lower()
        return any(p in lower for p in self.HIGH_RISK_PATTERNS)

    def _is_critical_secret_type(self, pred_secret_type: Optional[str]) -> bool:
        if not pred_secret_type:
            return False
        return pred_secret_type.lower() in self.CRITICAL_SECRET_TYPES

    def decide(self, scanner_hit: bool, llm_hit: bool,
               llm_decision: Optional[str] = None, **kwargs) -> PolicyDecision:
        guardrail_results: Dict[str, Any] = kwargs.get("guardrail_results", {})
        file_path: Optional[str] = kwargs.get("file_path")
        pred_secret_type: Optional[str] = kwargs.get("pred_secret_type")
        # Raw LLM binary judgment — True/False/None (None = LLM not invoked)
        pred_has_secret: Optional[bool] = kwargs.get("pred_has_secret")
        llm_dec = (llm_decision or "").upper()

        if self._check_hard_fail(guardrail_results):
            return PolicyDecision.REVIEW

        if scanner_hit and llm_dec == "BLOCK":
            return PolicyDecision.BLOCK

        # Veto: Scanner hit, but raw LLM judgment says no secret, in low-risk context.
        # Uses pred_has_secret (raw), not final_decision (guardrail-processed),
        # because guardrails (G4) may escalate to REVIEW even when LLM sees no secret.
        if (scanner_hit
                and pred_has_secret is False
                and not self._is_high_risk_file(file_path)
                and not self._is_critical_secret_type(pred_secret_type)):
            return PolicyDecision.PASS

        if scanner_hit or llm_dec in ("BLOCK", "REVIEW") or self._has_review_signal(guardrail_results):
            return PolicyDecision.REVIEW

        return PolicyDecision.PASS

    def _get_reasoning(self, scanner_hit: bool, llm_hit: bool,
                       decision: PolicyDecision,
                       llm_decision: Optional[str] = None, **kwargs) -> str:
        guardrail_results = kwargs.get("guardrail_results", {})
        pred_has_secret = kwargs.get("pred_has_secret")
        llm_dec = (llm_decision or "NOT_INVOKED").upper()

        if decision == PolicyDecision.BLOCK:
            return "BLOCK: Both scanner and LLM agree secret exists"

        if decision == PolicyDecision.REVIEW:
            if self._check_hard_fail(guardrail_results):
                return "REVIEW: Hard-fail condition (G5 or G3)"
            if scanner_hit and pred_has_secret is False:
                return "REVIEW: Scanner hit, LLM says no secret, but high-risk context blocks veto"
            if llm_dec == "REVIEW":
                return "REVIEW: LLM uncertain"
            if self._has_review_signal(guardrail_results):
                return "REVIEW: Epistemic signal from guardrails"
            return "REVIEW: Scanner or LLM raised concern"

        if scanner_hit and pred_has_secret is False:
            return "PASS: LLM-veto (pred_has_secret=False) overrides scanner in low-risk context"
        return "PASS: No scanner hit and LLM confirmed clean"

    def get_full_result(self, scanner_hit: bool, llm_hit: bool,
                        llm_decision: Optional[str] = None, **kwargs) -> PolicyResult:
        decision = self.decide(scanner_hit, llm_hit, llm_decision, **kwargs)
        guardrail_results = kwargs.get("guardrail_results", {})
        file_path = kwargs.get("file_path")
        pred_secret_type = kwargs.get("pred_secret_type")
        pred_has_secret = kwargs.get("pred_has_secret")
        llm_dec = (llm_decision or "NOT_INVOKED").upper()

        is_veto = (
            decision == PolicyDecision.PASS
            and scanner_hit
            and pred_has_secret is False
        )

        return PolicyResult(
            policy_name=self.name,
            decision=decision,
            scanner_hit=scanner_hit,
            llm_hit=llm_hit,
            llm_decision=llm_dec,
            reasoning=self._get_reasoning(scanner_hit, llm_hit, decision, llm_decision, **kwargs),
            metadata={
                "policy_type": "precision_first",
                "logic": "contextual_veto",
                "hard_fail": self._check_hard_fail(guardrail_results),
                "review_signal": self._has_review_signal(guardrail_results),
                "high_risk_file": self._is_high_risk_file(file_path),
                "critical_secret_type": self._is_critical_secret_type(pred_secret_type),
                "llm_override_count": int(is_veto),
            }
        )
