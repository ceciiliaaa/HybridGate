"""
G1: Evidence + Location Guardrail

Forces the LLM to provide concrete evidence (file path, line number, code snippet)
for any secret detection claim. Prevents hallucinated findings.
"""

import re
from typing import List, Optional, Tuple
from .base import Guardrail, GuardrailResult


class G1EvidenceLocation(Guardrail):
    """
    Guardrail G1: Evidence + Location Requirement

    Rules:
    - Every finding MUST include file_path, line_number, and evidence_snippet
    - If no concrete evidence exists in the diff, LLM must decide REVIEW (not PASS)
    - Prevents false negatives from insufficient analysis
    """

    @property
    def name(self) -> str:
        return "G1_EvidenceLocation"

    def get_prompt(self) -> str:
        return """
=== GUARDRAIL G1: EVIDENCE + LOCATION REQUIREMENT ===

STRICT RULES:
1. For EVERY secret finding, you MUST provide:
   - pred_location_line: The exact line number where the secret appears
   - evidence_snippet: A code snippet showing the secret (with value masked)

2. If you detect a potential secret but CANNOT identify:
   - The exact file path in the diff
   - The exact line number
   - A concrete code snippet as evidence

   Then you MUST set decision to "REVIEW" (not "PASS").

3. NEVER claim "no secrets found" unless you have thoroughly examined
   EVERY added line (lines starting with '+') in the diff.

4. Your evidence_snippet MUST be copy-paste from the actual diff content.
   Do NOT paraphrase or summarize - show the actual code.

OUTPUT SCHEMA REQUIREMENTS:
{
  "pred_has_secret": boolean,
  "pred_secret_type": string,
  "pred_location_line": integer,      // REQUIRED if pred_has_secret=true
  "evidence_snippet": string,         // REQUIRED if pred_has_secret=true
  "reasoning": string
}
"""

    def validate_output(self, llm_output: dict) -> bool:
        """
        Validate that LLM output contains required evidence fields.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            True if evidence requirements are met
        """
        # If no secret claimed, G1 is satisfied
        if not llm_output.get("pred_has_secret", False):
            return True

        # If secret claimed, must have location and evidence
        has_location = llm_output.get("pred_location_line") is not None
        has_evidence = bool(llm_output.get("evidence_snippet", "").strip())

        return has_location and has_evidence

    def validate_output_with_context(
        self,
        llm_output: dict,
        diff_lines: Optional[List[str]] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate evidence exists AND is plausible given the diff context.

        Args:
            llm_output: The LLM's response dictionary
            diff_lines: List of diff lines for context-aware validation

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        # If no secret claimed, G1 is satisfied
        if not llm_output.get("pred_has_secret", False):
            return True, []

        location = llm_output.get("pred_location_line")
        evidence = llm_output.get("evidence_snippet", "").strip()

        # Basic checks (same as validate_output)
        if location is None:
            issues.append("Missing pred_location_line")
        if not evidence:
            issues.append("Missing or empty evidence_snippet")

        # Context-aware plausibility checks (only if diff_lines provided)
        if diff_lines and location is not None:
            # Check 1: Location within valid range
            if location < 1 or location > len(diff_lines):
                issues.append(
                    f"pred_location_line={location} outside diff range 1-{len(diff_lines)}"
                )

            # Check 2: Evidence roughly consistent with referenced line
            elif evidence:
                referenced_line = diff_lines[location - 1]  # 1-indexed

                # Extract meaningful tokens from evidence
                # Ignore: line prefixes like "L29:", masking "***", short tokens
                evidence_tokens = []
                for token in evidence.split():
                    # Skip line prefixes (L01:, L29:, etc.)
                    if re.match(r'^L?\d+:?$', token):
                        continue
                    # Skip masked content
                    if '***' in token:
                        continue
                    # Skip short/trivial tokens
                    if len(token) <= 3:
                        continue
                    # Skip pure punctuation
                    if all(c in '+-=<>(){}[]"\',.:;' for c in token):
                        continue
                    evidence_tokens.append(token)

                # If we have meaningful tokens, check overlap with referenced line
                if evidence_tokens:
                    has_overlap = any(
                        token in referenced_line for token in evidence_tokens[:3]
                    )
                    if not has_overlap:
                        issues.append(
                            "evidence_snippet inconsistent with referenced line"
                        )
                # If no meaningful tokens (all masked), rely on basic checks only

        return len(issues) == 0, issues

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

        if llm_output.get("pred_has_secret", False):
            if llm_output.get("pred_location_line") is None:
                violations.append("Missing pred_location_line for claimed secret")

            evidence = llm_output.get("evidence_snippet", "")
            if not evidence or not evidence.strip():
                violations.append("Missing evidence_snippet for claimed secret")
            elif len(evidence) < 10:
                warnings.append("Evidence snippet seems too short")

        return GuardrailResult(
            guardrail_name=self.name,
            is_valid=len(violations) == 0,
            violations=violations,
            warnings=warnings,
            metadata={
                "has_location": llm_output.get("pred_location_line") is not None,
                "has_evidence": bool(llm_output.get("evidence_snippet", "").strip())
            }
        )
