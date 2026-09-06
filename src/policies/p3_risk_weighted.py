"""
P3: Risk-Weighted Scoring Policy (Enterprise / Configurable)

Computes a risk score from multiple signals and maps score to BLOCK/REVIEW/PASS.
Hard-fails force REVIEW before scoring.
"""

from typing import Optional, Dict, Any
from .base import Policy, PolicyDecision, PolicyResult


class P3RiskWeighted(Policy):
    """
    Policy P3: Risk-Weighted Scoring (Enterprise)

    Score:
        +2  scanner_hit
        +2  llm_decision == "BLOCK"
        +1  llm_decision == "REVIEW"
        +1  review_signal (G1/G2/G4/G6)
        +1  high_risk_file
        +1  pred_secret_type in {private_key, connection_string}

    Gate:
        Score >= 4 → BLOCK
        Score 2–3  → REVIEW
        Score <= 1 → PASS

    Use case: Enterprise environments needing configurable risk thresholds.
    """

    HIGH_RISK_PATTERNS = [".env", "config", "credentials", "auth", "secret", "key"]
    CRITICAL_SECRET_TYPES = {"private_key", "connection_string"}

    @property
    def name(self) -> str:
        return "P3_RiskWeighted"

    @property
    def description(self) -> str:
        return "Risk-Weighted: Score-based gate with configurable thresholds."

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

    def compute_score(
        self,
        scanner_hit: bool,
        llm_decision: Optional[str],
        guardrail_results: Dict[str, Any],
        file_path: Optional[str],
        pred_secret_type: Optional[str],
    ) -> Dict[str, Any]:
        """
        σ = 2·S + 2·LB + I(LR∨R) + Q + F + C

        I(LR∨R) = 1 if EITHER final_decision==REVIEW OR any G1/G2/G4 review signal fires.
        Q = g6_hint_injected (format-candidate signal, independent of R).
        BLOCK requires σ ≥ 4 AND (S OR LB) to prevent blocking on context signals alone.
        """
        llm_dec = (llm_decision or "").upper()
        score = 0
        breakdown = {}

        breakdown["scanner_hit"] = 2 if scanner_hit else 0
        score += breakdown["scanner_hit"]

        breakdown["llm_block"] = 2 if llm_dec == "BLOCK" else 0
        score += breakdown["llm_block"]

        # I(LR ∨ R): indicator — 1 point if EITHER LR or review signal, not additive
        rs = self._has_review_signal(guardrail_results)
        lr_or_r = (llm_dec == "REVIEW") or rs
        breakdown["lr_or_review_signal"] = 1 if lr_or_r else 0
        score += breakdown["lr_or_review_signal"]

        # Q: G6 format-candidate signal (independent of R)
        q = guardrail_results.get("g6_hint_injected", False)
        breakdown["g6_format_candidate"] = 1 if q else 0
        score += breakdown["g6_format_candidate"]

        hrf = self._is_high_risk_file(file_path)
        breakdown["high_risk_file"] = 1 if hrf else 0
        score += breakdown["high_risk_file"]

        cst = self._is_critical_secret_type(pred_secret_type)
        breakdown["critical_secret_type"] = 1 if cst else 0
        score += breakdown["critical_secret_type"]

        breakdown["total"] = score
        breakdown["has_detection_signal"] = scanner_hit or (llm_dec == "BLOCK")
        return breakdown

    def decide(self, scanner_hit: bool, llm_hit: bool,
               llm_decision: Optional[str] = None, **kwargs) -> PolicyDecision:
        guardrail_results: Dict[str, Any] = kwargs.get("guardrail_results", {})
        file_path: Optional[str] = kwargs.get("file_path")
        pred_secret_type: Optional[str] = kwargs.get("pred_secret_type")

        if self._check_hard_fail(guardrail_results):
            return PolicyDecision.REVIEW

        score_info = self.compute_score(
            scanner_hit, llm_decision, guardrail_results, file_path, pred_secret_type
        )
        score = score_info["total"]

        # BLOCK requires detection signal (S or LB) to prevent pure-context BLOCKs
        if score >= 4 and score_info["has_detection_signal"]:
            return PolicyDecision.BLOCK
        if score >= 2:
            return PolicyDecision.REVIEW
        return PolicyDecision.PASS

    def _get_reasoning(self, scanner_hit: bool, llm_hit: bool,
                       decision: PolicyDecision,
                       llm_decision: Optional[str] = None, **kwargs) -> str:
        guardrail_results = kwargs.get("guardrail_results", {})
        file_path = kwargs.get("file_path")
        pred_secret_type = kwargs.get("pred_secret_type")

        if self._check_hard_fail(guardrail_results):
            return "REVIEW: Hard-fail condition (G5 or G3)"

        score_info = self.compute_score(
            scanner_hit, llm_decision, guardrail_results, file_path, pred_secret_type
        )
        score = score_info["total"]
        return f"{decision.value}: Risk score={score} (scanner={score_info['scanner_hit']}, llm={score_info['llm_block']}, lr_or_R={score_info['lr_or_review_signal']}, Q={score_info['g6_format_candidate']}, context={score_info['high_risk_file']+score_info['critical_secret_type']})"

    def get_full_result(self, scanner_hit: bool, llm_hit: bool,
                        llm_decision: Optional[str] = None, **kwargs) -> PolicyResult:
        decision = self.decide(scanner_hit, llm_hit, llm_decision, **kwargs)
        guardrail_results = kwargs.get("guardrail_results", {})
        file_path = kwargs.get("file_path")
        pred_secret_type = kwargs.get("pred_secret_type")
        llm_dec = (llm_decision or "NOT_INVOKED").upper()

        score_info = self.compute_score(
            scanner_hit, llm_decision, guardrail_results, file_path, pred_secret_type
        )

        return PolicyResult(
            policy_name=self.name,
            decision=decision,
            scanner_hit=scanner_hit,
            llm_hit=llm_hit,
            llm_decision=llm_dec,
            reasoning=self._get_reasoning(scanner_hit, llm_hit, decision, llm_decision, **kwargs),
            metadata={
                "policy_type": "risk_weighted",
                "score": score_info["total"],
                "score_breakdown": score_info,
                "hard_fail": self._check_hard_fail(guardrail_results),
            }
        )
