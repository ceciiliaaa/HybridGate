"""
G5: Schema Validation / Parse-Fail Routing Guardrail

Validates LLM outputs before processing. Routes invalid/inconsistent
outputs to REVIEW rather than failing silently.

Design:
- Runs BEFORE G4 (needs valid schema to evaluate confidence)
- Checks: JSON parse, required fields, allowed values, field consistency
- On failure: routes to REVIEW with detailed error info
"""

import json
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from .base import Guardrail, GuardrailResult


# Valid values for enum fields
VALID_DECISIONS = {"PASS", "BLOCK", "REVIEW"}
VALID_SECRET_TYPES = {"token", "api_key", "password", "private_key", "connection_string", "none"}
VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}


@dataclass
class ValidationResult:
    """Result of schema validation."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    parsed_output: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_valid": self.is_valid,
            "validation_errors": self.errors,
            "validation_warnings": self.warnings
        }


class G5SchemaValidation(Guardrail):
    """
    Guardrail G5: Schema Validation / Parse-Fail Routing

    Validates:
    A. JSON parsability
    B. Required fields presence
    C. Allowed values for enum fields
    D. Field consistency rules

    On validation failure: routes to REVIEW
    """

    @property
    def name(self) -> str:
        return "G5_SchemaValidation"

    def get_prompt(self) -> str:
        """G5 is primarily post-processing, but we add schema reminder."""
        return """
=== GUARDRAIL G5: OUTPUT SCHEMA REQUIREMENTS ===

Your response MUST be valid JSON with these fields:
{
  "reasoning": string (brief explanation),
  "pred_has_secret": boolean (true or false),
  "pred_secret_type": "token" | "api_key" | "password" | "private_key" | "connection_string" | "none",
  "pred_location_line": integer or null,
  "evidence_snippet": string (code snippet with secret MASKED),
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}

CONSISTENCY RULES:
- If pred_has_secret=true, you MUST provide pred_location_line and evidence_snippet
- If pred_has_secret=true, pred_secret_type cannot be "none"
- If pred_has_secret=false, pred_secret_type should be "none"
"""

    def validate_json_parsable(self, raw_response: str) -> Tuple[bool, Optional[dict], List[str]]:
        """
        Check if the response is valid JSON.

        Args:
            raw_response: Raw string response from LLM

        Returns:
            Tuple of (success, parsed_dict, errors)
        """
        import re

        errors = []

        # Try direct parse
        try:
            return True, json.loads(raw_response), []
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code fences
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw_response, re.DOTALL)
        if fence_match:
            try:
                return True, json.loads(fence_match.group(1)), []
            except json.JSONDecodeError:
                pass

        # Try finding the first { ... } block
        brace_match = re.search(r"\{.*\}", raw_response, re.DOTALL)
        if brace_match:
            try:
                return True, json.loads(brace_match.group(0)), []
            except json.JSONDecodeError:
                errors.append(f"Found JSON-like structure but failed to parse: {brace_match.group(0)[:100]}...")

        errors.append("Response is not valid JSON")
        return False, None, errors

    def validate_required_fields(self, output: dict, include_confidence: bool = True) -> List[str]:
        """
        Check for required fields.

        Args:
            output: Parsed LLM output
            include_confidence: Whether to require 'confidence' field (for G4 integration)

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        # Always required fields
        required_fields = ["pred_has_secret"]

        # Check basic required fields
        for f in required_fields:
            if f not in output:
                errors.append(f"Missing required field: '{f}'")

        # Conditional: confidence required when G4 is active
        if include_confidence and "confidence" not in output:
            errors.append("Missing required field: 'confidence'")

        # Conditional: if secret claimed, need location and evidence
        if output.get("pred_has_secret", False):
            if output.get("pred_location_line") is None:
                errors.append("Missing 'pred_location_line' when pred_has_secret=true")
            if not output.get("evidence_snippet", "").strip():
                errors.append("Missing or empty 'evidence_snippet' when pred_has_secret=true")

        return errors

    def validate_allowed_values(self, output: dict, include_confidence: bool = True) -> List[str]:
        """
        Check that enum fields have valid values.

        Args:
            output: Parsed LLM output
            include_confidence: Whether to validate confidence field

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        # pred_has_secret must be boolean
        if "pred_has_secret" in output:
            val = output["pred_has_secret"]
            if not isinstance(val, bool):
                errors.append(f"'pred_has_secret' must be boolean, got: {type(val).__name__}")

        # pred_secret_type validation
        if "pred_secret_type" in output:
            val = str(output["pred_secret_type"]).lower()
            if val not in VALID_SECRET_TYPES:
                errors.append(f"Invalid 'pred_secret_type': '{val}'. Must be one of: {VALID_SECRET_TYPES}")

        # confidence validation (when G4 is active)
        if include_confidence and "confidence" in output:
            val = str(output["confidence"]).upper()
            if val not in VALID_CONFIDENCE_LEVELS:
                errors.append(f"Invalid 'confidence': '{output['confidence']}'. Must be one of: {VALID_CONFIDENCE_LEVELS}")

        return errors

    def validate_field_consistency(self, output: dict) -> Tuple[List[str], List[str]]:
        """
        Check consistency rules between fields.

        Rules (errors - cause REVIEW routing):
        - has_secret=true + secret_type=none → inconsistent
        - has_secret=true + decision=PASS → inconsistent (if decision field exists)
        - has_secret=false + decision=BLOCK → inconsistent (if decision field exists)

        Rules (warnings - logged but don't cause routing):
        - has_secret=false + secret_type != none → unusual but not blocking

        Note: The 'decision' field is not in our standard schema (decision is derived
        from pred_has_secret). The decision checks are for robustness if an LLM
        outputs an explicit decision field.

        Args:
            output: Parsed LLM output

        Returns:
            Tuple of (errors, warnings)
        """
        errors = []
        warnings = []
        has_secret = output.get("pred_has_secret", False)
        secret_type = str(output.get("pred_secret_type", "none")).lower()

        # has_secret=true but secret_type=none → ERROR
        if has_secret and secret_type == "none":
            errors.append("Inconsistent: pred_has_secret=true but pred_secret_type='none'")

        # has_secret=false but secret_type is not none → WARNING
        # This could happen if LLM explains "looks like api_key but is test value"
        if not has_secret and secret_type != "none":
            warnings.append(f"Unusual: pred_has_secret=false but pred_secret_type='{secret_type}'")

        # If 'decision' field exists, check consistency with pred_has_secret
        if "decision" in output:
            decision = str(output["decision"]).upper()
            if has_secret and decision == "PASS":
                errors.append("Inconsistent: pred_has_secret=true but decision='PASS'")
            if not has_secret and decision == "BLOCK":
                errors.append("Inconsistent: pred_has_secret=false but decision='BLOCK'")

        return errors, warnings

    def validate(
        self,
        raw_response: str,
        include_confidence: bool = True
    ) -> ValidationResult:
        """
        Full validation pipeline for LLM output.

        Args:
            raw_response: Raw string response from LLM
            include_confidence: Whether to validate confidence field (for G4 integration)

        Returns:
            ValidationResult with all validation info
        """
        all_errors = []
        all_warnings = []

        # A. JSON parse check
        is_parsable, parsed, parse_errors = self.validate_json_parsable(raw_response)
        all_errors.extend(parse_errors)

        if not is_parsable or parsed is None:
            return ValidationResult(
                is_valid=False,
                errors=all_errors,
                warnings=all_warnings,
                parsed_output=None
            )

        # B. Required fields
        field_errors = self.validate_required_fields(parsed, include_confidence)
        all_errors.extend(field_errors)

        # C. Allowed values
        value_errors = self.validate_allowed_values(parsed, include_confidence)
        all_errors.extend(value_errors)

        # D. Field consistency
        consistency_errors, consistency_warnings = self.validate_field_consistency(parsed)
        all_errors.extend(consistency_errors)
        all_warnings.extend(consistency_warnings)

        return ValidationResult(
            is_valid=len(all_errors) == 0,
            errors=all_errors,
            warnings=all_warnings,
            parsed_output=parsed
        )

    def validate_output(self, llm_output: dict) -> bool:
        """
        Simple validation check for Guardrail interface compatibility.

        Args:
            llm_output: The LLM's response dictionary (already parsed)

        Returns:
            True if valid
        """
        # Since this is already parsed, just check fields and consistency
        errors = []
        errors.extend(self.validate_required_fields(llm_output))
        errors.extend(self.validate_allowed_values(llm_output))
        consistency_errors, _ = self.validate_field_consistency(llm_output)
        errors.extend(consistency_errors)
        return len(errors) == 0

    def apply_routing(
        self,
        validation_result: ValidationResult,
        original_decision: str = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Apply G5 routing based on validation result.

        Args:
            validation_result: Result from validate()
            original_decision: Original decision (may be None if parse failed)

        Returns:
            Tuple of (final_decision, metadata_dict)
        """
        metadata = {
            "schema_valid": validation_result.is_valid,
            "validation_errors": validation_result.errors,
            "original_decision": original_decision,
            "routed_by_guardrail": None
        }

        # G5: Route validation failures to REVIEW
        if not validation_result.is_valid:
            metadata["routed_by_guardrail"] = "G5"
            return "REVIEW", metadata

        return original_decision or "REVIEW", metadata

    def get_detailed_validation(self, llm_output: dict) -> GuardrailResult:
        """
        Get detailed validation result.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            GuardrailResult with details
        """
        errors = []
        warnings = []
        errors.extend(self.validate_required_fields(llm_output))
        errors.extend(self.validate_allowed_values(llm_output))
        consistency_errors, consistency_warnings = self.validate_field_consistency(llm_output)
        errors.extend(consistency_errors)
        warnings.extend(consistency_warnings)

        return GuardrailResult(
            guardrail_name=self.name,
            is_valid=len(errors) == 0,
            violations=errors,
            warnings=warnings,
            metadata={
                "field_count": len(llm_output),
                "has_confidence": "confidence" in llm_output,
                "has_evidence": bool(llm_output.get("evidence_snippet", "").strip())
            }
        )
