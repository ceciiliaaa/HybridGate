"""
Guardrails Module for HybridGate Framework

Implements safety guardrails for LLM-based secret detection:
- G1: Evidence + Location (require concrete evidence)
- G2: Untrusted Input Policy (ignore PR metadata)
- G3: Redaction / Never-Echo (mask secrets in output)
- G4: Uncertainty / Abstention (route LOW confidence to REVIEW)
- G5: Schema Validation (validate output structure, route invalid to REVIEW)

Guardrail Order (after LLM call):
1. G5 (Schema Validation) - runs first, skips G4 if invalid
2. G4 (Uncertainty Routing) - runs on valid output
3. G3 (Redaction Check) - runs last
"""

from .base import GuardrailConfig, GuardrailResult
from .g1_evidence_location import G1EvidenceLocation
from .g2_untrusted_input import G2UntrustedInput
from .g3_redaction import G3Redaction
from .g4_uncertainty import G4Uncertainty, VALID_CONFIDENCE_LEVELS
from .g5_schema_validation import G5SchemaValidation, ValidationResult
from .config import GuardrailSettings, DEFAULT_SETTINGS

__all__ = [
    'GuardrailConfig',
    'GuardrailResult',
    'G1EvidenceLocation',
    'G2UntrustedInput',
    'G3Redaction',
    'G4Uncertainty',
    'G5SchemaValidation',
    'ValidationResult',
    'GuardrailSettings',
    'DEFAULT_SETTINGS',
    'VALID_CONFIDENCE_LEVELS',
    'get_guardrail_bundle',
    'apply_guardrails',
    'apply_guardrails_with_routing'
]


def get_guardrail_bundle(settings: GuardrailSettings = None) -> str:
    """
    Get combined prompt text for enabled guardrails.

    Args:
        settings: Guardrail settings (defaults to DEFAULT_SETTINGS)

    Returns:
        Combined prompt text for all enabled guardrails
    """
    if settings is None:
        settings = DEFAULT_SETTINGS

    prompts = []

    if settings.is_enabled("G1"):
        g1 = G1EvidenceLocation()
        prompts.append(g1.get_prompt())

    if settings.is_enabled("G2"):
        g2 = G2UntrustedInput()
        prompts.append(g2.get_prompt())

    if settings.is_enabled("G3"):
        g3 = G3Redaction()
        prompts.append(g3.get_prompt())

    # G4 adds confidence field requirement
    if settings.is_enabled("G4"):
        g4 = G4Uncertainty()
        prompts.append(g4.get_prompt())

    # G5 adds schema reminder
    if settings.is_enabled("G5"):
        g5 = G5SchemaValidation()
        prompts.append(g5.get_prompt())

    return "\n".join(prompts)


def apply_guardrails(llm_output: dict, ground_truth: dict = None) -> dict:
    """
    Apply post-processing guardrail validations to LLM output.
    (Backward compatible version - does not modify decisions)

    Args:
        llm_output: The LLM's response dictionary
        ground_truth: Optional ground truth for leak detection

    Returns:
        Dictionary with validation results
    """
    from ..metrics.leakage_metrics import detect_output_leakage

    results = {
        "g1_valid": False,
        "g2_valid": True,  # G2 is prompt-based, always valid post-hoc
        "g3_valid": False,
        "g3_leak_detected": False
    }

    # G1: Check evidence and location
    g1 = G1EvidenceLocation()
    results["g1_valid"] = g1.validate_output(llm_output)

    # G3: Check for secret leakage using FM5 metrics module
    g3 = G3Redaction()
    if ground_truth and ground_truth.get("gt_secret_value"):
        # Use the centralized leakage detection (FM5 evaluation metric)
        leak_result = detect_output_leakage(llm_output, ground_truth["gt_secret_value"])
        results["g3_leak_detected"] = leak_result.leak_detected
        results["g3_valid"] = not leak_result.leak_detected
    else:
        # No ground truth secret - use pattern-based heuristic
        results["g3_valid"] = g3.validate_output(llm_output)

    return results


def apply_guardrails_with_routing(
    raw_response: str,
    ground_truth: dict = None,
    settings: GuardrailSettings = None
) -> dict:
    """
    Apply guardrails with decision routing (G5 -> G4 -> G3 order).

    This is the new comprehensive guardrail application function that:
    1. G5: Validates schema, routes invalid to REVIEW
    2. G4: Checks confidence, routes LOW to REVIEW
    3. G3: Checks for secret leakage

    Args:
        raw_response: Raw LLM response string (before JSON parsing)
        ground_truth: Optional ground truth for leak detection
        settings: Guardrail settings (defaults to DEFAULT_SETTINGS)

    Returns:
        Dictionary with:
        - parsed_output: The parsed LLM output (or None if parse failed)
        - final_decision: Final decision after guardrail routing
        - original_decision: Decision before guardrail routing
        - confidence: Confidence value from LLM (or None)
        - schema_valid: Whether G5 validation passed
        - validation_errors: List of G5 validation errors
        - routed_by_guardrail: Which guardrail triggered routing (G4/G5/None)
        - g1_valid, g2_valid, g3_valid, g3_leak_detected: Legacy validation flags
    """
    # Import with fallback for testing
    try:
        from ..metrics.leakage_metrics import detect_output_leakage
    except ImportError:
        # Fallback for testing without full package context
        detect_output_leakage = None

    if settings is None:
        settings = DEFAULT_SETTINGS

    # Initialize result with defaults
    result = {
        "parsed_output": None,
        "final_decision": "REVIEW",
        "original_decision": None,
        "confidence": None,
        "schema_valid": False,
        "validation_errors": [],
        "routed_by_guardrail": None,
        # Legacy flags for backward compatibility
        "g1_valid": False,
        "g2_valid": True,  # G2 is prompt-based
        "g3_valid": False,
        "g3_leak_detected": False,
        "g4_valid": False,
        "g5_valid": False
    }

    # =========================================================================
    # STEP 1: G5 Schema Validation (runs first)
    # =========================================================================
    g5 = G5SchemaValidation()
    g5_enabled = settings.is_enabled("G5")
    g4_enabled = settings.is_enabled("G4")

    # Validate the raw response
    validation = g5.validate(raw_response, include_confidence=g4_enabled)

    result["schema_valid"] = validation.is_valid
    result["validation_errors"] = validation.errors
    result["g5_valid"] = validation.is_valid

    if not validation.is_valid:
        # G5: Route to REVIEW on validation failure
        if g5_enabled:
            result["routed_by_guardrail"] = "G5"
            result["final_decision"] = "REVIEW"
        return result

    # Schema valid - we have parsed output
    llm_output = validation.parsed_output
    result["parsed_output"] = llm_output

    # Extract confidence
    result["confidence"] = llm_output.get("confidence")
    if result["confidence"]:
        result["confidence"] = str(result["confidence"]).upper()

    # Determine original decision from pred_has_secret
    has_secret = llm_output.get("pred_has_secret", False)
    original_decision = "BLOCK" if has_secret else "PASS"
    result["original_decision"] = original_decision
    result["final_decision"] = original_decision

    # =========================================================================
    # STEP 2: G4 Uncertainty Routing (runs on valid output)
    # =========================================================================
    if g4_enabled:
        g4 = G4Uncertainty()
        result["g4_valid"] = g4.validate_output(llm_output)

        if g4.should_route_to_review(llm_output):
            # G4: Route LOW confidence to REVIEW
            result["routed_by_guardrail"] = "G4"
            result["final_decision"] = "REVIEW"

    # =========================================================================
    # STEP 3: G3 Leakage Check (runs last)
    # =========================================================================
    g3 = G3Redaction()
    if ground_truth and ground_truth.get("gt_secret_value") and detect_output_leakage:
        leak_result = detect_output_leakage(llm_output, ground_truth["gt_secret_value"])
        result["g3_leak_detected"] = leak_result.leak_detected
        result["g3_valid"] = not leak_result.leak_detected
    else:
        result["g3_valid"] = g3.validate_output(llm_output)

    # =========================================================================
    # G1 Evidence Check (for logging, does not affect routing)
    # =========================================================================
    g1 = G1EvidenceLocation()
    result["g1_valid"] = g1.validate_output(llm_output)

    return result
