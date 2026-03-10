"""
P3: Escalation Policy (Cost-Optimized)

Intelligent routing that uses LLM selectively based on risk factors.
Balances security with API cost and latency.

Design Decision:
- llm_decision = "NOT_INVOKED" when LLM was not called (cost optimization)
- This avoids redundant llm_invoked boolean field
- Policy tags (is_high_risk_file, is_critical_secret_type, obfuscation_suspected)
  are computed and stored for reproducibility
"""

import re
from typing import Optional
from .base import Policy, PolicyDecision, PolicyResult, LLMDecision


class P3Escalation(Policy):
    """
    Policy P3: Escalation (Cost-Optimized)

    Logic:
    - Critical secret type + scanner hit -> immediate BLOCK (skip LLM)
    - High-risk file OR obfuscation suspected -> trigger LLM review
    - Scanner hit on non-critical -> trigger LLM for confirmation
    - Low-risk scenario -> PASS without LLM

    Use case: Production environments with cost/latency constraints.
    Trade-off: Reduces LLM calls while maintaining security for high-risk cases.
    """

    # File patterns that indicate high risk
    HIGH_RISK_FILE_PATTERNS = [
        '.env', 'config', 'settings', 'credentials', 'secrets',
        'auth', 'password', 'key', 'token', 'certificate'
    ]

    # Critical secret types that warrant immediate blocking
    CRITICAL_SECRET_TYPES = ['private_key', 'connection_string']

    # Patterns that suggest obfuscation
    OBFUSCATION_PATTERNS = [
        r'\+\s*"[^"]*"\s*\+\s*"',  # String concatenation
        r'part\d?\s*=',            # Split into parts
        r'base64',                  # Base64 encoding
        r'\.decode\s*\(',          # Decode calls
        r'\\x[0-9a-f]{2}',         # Hex encoding
        r'chr\s*\(',               # Character codes
        r'join\s*\(\s*\[',         # Join array of chars
    ]

    @property
    def name(self) -> str:
        return "P3_Escalation"

    @property
    def description(self) -> str:
        return "Cost-Optimized: Selective LLM use based on risk factors."

    @staticmethod
    def compute_is_high_risk_file(file_path: Optional[str]) -> bool:
        """Check if file path indicates high risk for secrets."""
        if not file_path:
            return False
        file_lower = file_path.lower()
        return any(pattern in file_lower for pattern in P3Escalation.HIGH_RISK_FILE_PATTERNS)

    @staticmethod
    def compute_is_critical_secret_type(secret_type: Optional[str]) -> bool:
        """Check if secret type is critical (high impact if leaked)."""
        if not secret_type:
            return False
        return secret_type.lower() in P3Escalation.CRITICAL_SECRET_TYPES

    @staticmethod
    def compute_obfuscation_suspected(code_diff: Optional[str]) -> bool:
        """Check if code shows signs of secret obfuscation."""
        if not code_diff:
            return False
        for pattern in P3Escalation.OBFUSCATION_PATTERNS:
            if re.search(pattern, code_diff, re.IGNORECASE):
                return True
        return False

    def should_invoke_llm(
        self,
        scanner_hit: bool,
        is_high_risk_file: bool,
        is_critical_secret_type: bool,
        obfuscation_suspected: bool
    ) -> bool:
        """
        Determine if LLM should be invoked based on risk factors.

        Args:
            scanner_hit: Whether scanner detected something
            is_high_risk_file: Whether file is high-risk
            is_critical_secret_type: Whether secret type is critical
            obfuscation_suspected: Whether obfuscation patterns detected

        Returns:
            True if LLM should be invoked
        """
        # Critical scanner hit -> immediate block, no LLM needed
        if scanner_hit and is_critical_secret_type:
            return False

        # Trigger LLM for: high-risk files, obfuscation, or non-critical scanner hits
        return (
            is_high_risk_file or
            obfuscation_suspected or
            (scanner_hit and not is_critical_secret_type)
        )

    def decide(self, scanner_hit: bool, llm_hit: bool,
               llm_decision: Optional[str] = None,
               file_path: Optional[str] = None,
               secret_type: Optional[str] = None,
               code_diff: Optional[str] = None,
               **kwargs) -> PolicyDecision:
        """
        Make escalation decision based on risk factors.

        Args:
            scanner_hit: Whether classic scanner detected a secret
            llm_hit: Whether LLM detected a secret
            llm_decision: LLM's decision string (BLOCK/PASS/REVIEW/NOT_INVOKED)
            file_path: File path for risk assessment
            secret_type: Detected secret type
            code_diff: Code diff for obfuscation detection

        Returns:
            PolicyDecision
        """
        is_high_risk = self.compute_is_high_risk_file(file_path)
        is_critical = self.compute_is_critical_secret_type(secret_type)
        is_obfuscated = self.compute_obfuscation_suspected(code_diff)

        llm_dec = (llm_decision or "").upper()

        # Rule 1: Critical secret type + scanner hit -> immediate BLOCK
        if scanner_hit and is_critical:
            return PolicyDecision.BLOCK

        # Determine if LLM should be triggered
        llm_should_trigger = self.should_invoke_llm(
            scanner_hit, is_high_risk, is_critical, is_obfuscated
        )

        # If LLM wasn't triggered (low risk, no scanner hit)
        if not llm_should_trigger:
            if scanner_hit:
                return PolicyDecision.REVIEW  # Scanner hit but low risk
            return PolicyDecision.PASS

        # LLM was triggered - check its result
        if llm_dec == "NOT_INVOKED":
            # LLM should have been called but wasn't - fall back to REVIEW
            return PolicyDecision.REVIEW if scanner_hit else PolicyDecision.PASS

        # G4/G5: If LLM final decision is REVIEW, respect that first
        # This ensures guardrail routing is not overridden by llm_hit
        if llm_dec in ("REVIEW", "UNCERTAIN"):
            return PolicyDecision.REVIEW

        if llm_hit:
            return PolicyDecision.BLOCK

        # LLM says no secret
        if scanner_hit:
            # Scanner disagrees -> REVIEW for human
            return PolicyDecision.REVIEW

        return PolicyDecision.PASS

    def _get_reasoning(self, scanner_hit: bool, llm_hit: bool,
                       decision: PolicyDecision,
                       llm_decision: Optional[str] = None, **kwargs) -> str:
        """Generate detailed reasoning."""
        file_path = kwargs.get("file_path")
        secret_type = kwargs.get("secret_type")
        code_diff = kwargs.get("code_diff")

        is_high_risk = self.compute_is_high_risk_file(file_path)
        is_critical = self.compute_is_critical_secret_type(secret_type)
        is_obfuscated = self.compute_obfuscation_suspected(code_diff)

        factors = []
        if is_high_risk:
            factors.append("high-risk file")
        if is_critical:
            factors.append("critical secret type")
        if is_obfuscated:
            factors.append("obfuscation detected")

        factors_str = f" (factors: {', '.join(factors)})" if factors else ""

        if decision == PolicyDecision.BLOCK:
            if scanner_hit and is_critical:
                return f"BLOCK: Critical secret ({secret_type}) detected by scanner - immediate block"
            return f"BLOCK: LLM confirmed secret{factors_str}"

        if decision == PolicyDecision.REVIEW:
            return f"REVIEW: Disagreement or uncertainty{factors_str}"

        return f"PASS: No secret detected{factors_str}"

    def get_full_result(self, scanner_hit: bool, llm_hit: bool,
                        llm_decision: Optional[str] = None, **kwargs) -> PolicyResult:
        """Get full result with escalation-specific metadata."""
        file_path = kwargs.get("file_path")
        secret_type = kwargs.get("secret_type")
        code_diff = kwargs.get("code_diff")

        decision = self.decide(scanner_hit, llm_hit, llm_decision, **kwargs)

        is_high_risk = self.compute_is_high_risk_file(file_path)
        is_critical = self.compute_is_critical_secret_type(secret_type)
        is_obfuscated = self.compute_obfuscation_suspected(code_diff)

        llm_should_trigger = self.should_invoke_llm(
            scanner_hit, is_high_risk, is_critical, is_obfuscated
        )

        llm_dec = (llm_decision or "NOT_INVOKED").upper()

        return PolicyResult(
            policy_name=self.name,
            decision=decision,
            scanner_hit=scanner_hit,
            llm_hit=llm_hit,
            llm_decision=llm_dec,
            reasoning=self._get_reasoning(scanner_hit, llm_hit, decision, llm_decision, **kwargs),
            metadata={
                "policy_type": "cost_optimized",
                "is_high_risk_file": is_high_risk,
                "is_critical_secret_type": is_critical,
                "obfuscation_suspected": is_obfuscated,
                "llm_should_trigger": llm_should_trigger
            }
        )


# Convenience function for computing policy tags
def compute_policy_tags(
    file_path: Optional[str],
    secret_type: Optional[str],
    code_diff: Optional[str]
) -> dict:
    """
    Compute policy-relevant tags for a sample.

    These tags are stored in the result schema for reproducibility
    and debugging of P3 policy decisions.

    Args:
        file_path: File path from sample
        secret_type: Detected or ground truth secret type
        code_diff: Code diff content

    Returns:
        Dictionary with policy tags
    """
    return {
        "is_high_risk_file": P3Escalation.compute_is_high_risk_file(file_path),
        "is_critical_secret_type": P3Escalation.compute_is_critical_secret_type(secret_type),
        "obfuscation_suspected": P3Escalation.compute_obfuscation_suspected(code_diff)
    }
