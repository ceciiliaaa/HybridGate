"""
G4: Uncertainty / Abstention Guardrail

Forces the LLM to provide a confidence level for its assessment.
When confidence is LOW, the decision is routed to REVIEW instead of
accepting the LLM's judgment.

Design:
- Hybrid guardrail: prompt extension + deterministic routing
- Prompt instructs LLM to output 'confidence' field
- Post-processing routes LOW confidence to REVIEW
"""

from typing import Optional, Tuple
from .base import Guardrail, GuardrailResult


# Valid confidence levels
VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}


class G4Uncertainty(Guardrail):
    """
    Guardrail G4: Uncertainty / Abstention

    Rules:
    - LLM MUST provide a 'confidence' field with value HIGH, MEDIUM, or LOW
    - If confidence == LOW, final decision is routed to REVIEW
    - Prevents overconfident wrong decisions
    """

    @property
    def name(self) -> str:
        return "G4_Uncertainty"

    def get_prompt(self) -> str:
        return """
=== GUARDRAIL G4: UNCERTAINTY / ABSTENTION ===

You MUST include a 'confidence' field in your response with one of these values:
- "HIGH": You are confident your assessment is correct based on clear code evidence.
- "MEDIUM": There are indicators, but the evidence is not unambiguous (e.g., placeholder-like strings, unclear variable names).
- "LOW": You are uncertain - the evidence is weak, contradictory, or you are primarily relying on context rather than concrete code.

RULES:
1. When in doubt, choose "LOW" rather than "HIGH".
2. If you cannot clearly identify a secret pattern in the diff, use "LOW".
3. If your assessment relies heavily on PR title/description rather than code, use "LOW".
4. Outputs with confidence="LOW" will be routed to manual review.

OUTPUT SCHEMA (add to existing):
{
  ...
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}
"""

    def validate_output(self, llm_output: dict) -> bool:
        """
        Validate that LLM output contains a valid confidence field.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            True if confidence field is present and valid
        """
        confidence = llm_output.get("confidence")
        if confidence is None:
            return False
        return str(confidence).upper() in VALID_CONFIDENCE_LEVELS

    def get_confidence(self, llm_output: dict) -> Optional[str]:
        """
        Extract and normalize the confidence value from LLM output.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            Normalized confidence string (HIGH/MEDIUM/LOW) or None if invalid
        """
        confidence = llm_output.get("confidence")
        if confidence is None:
            return None
        normalized = str(confidence).upper()
        return normalized if normalized in VALID_CONFIDENCE_LEVELS else None

    def should_route_to_review(self, llm_output: dict) -> bool:
        """
        Determine if the output should be routed to REVIEW based on confidence.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            True if confidence is LOW and should be routed to REVIEW
        """
        confidence = self.get_confidence(llm_output)
        return confidence == "LOW"

    def apply_routing(
        self,
        llm_output: dict,
        original_decision: str
    ) -> Tuple[str, dict]:
        """
        Apply G4 uncertainty routing to the decision.

        Args:
            llm_output: The LLM's response dictionary
            original_decision: The decision before G4 routing (PASS/BLOCK/REVIEW)

        Returns:
            Tuple of (final_decision, metadata_dict)
        """
        confidence = self.get_confidence(llm_output)
        metadata = {
            "confidence": confidence,
            "original_decision": original_decision,
            "routed_by_guardrail": None
        }

        # G4: Route LOW confidence to REVIEW
        if confidence == "LOW":
            metadata["routed_by_guardrail"] = "G4"
            return "REVIEW", metadata

        return original_decision, metadata

    def get_detailed_validation(self, llm_output: dict) -> GuardrailResult:
        """
        Get detailed validation result with specific violations.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            GuardrailResult with details
        """
        violations = []
        warnings = []
        confidence = llm_output.get("confidence")

        if confidence is None:
            violations.append("Missing 'confidence' field")
        elif str(confidence).upper() not in VALID_CONFIDENCE_LEVELS:
            violations.append(f"Invalid confidence value: '{confidence}'. Must be HIGH, MEDIUM, or LOW")

        # Warning for MEDIUM confidence
        if str(confidence or "").upper() == "MEDIUM":
            warnings.append("MEDIUM confidence - consider if evidence is sufficient")

        return GuardrailResult(
            guardrail_name=self.name,
            is_valid=len(violations) == 0,
            violations=violations,
            warnings=warnings,
            metadata={
                "confidence": self.get_confidence(llm_output),
                "would_route_to_review": self.should_route_to_review(llm_output)
            }
        )
