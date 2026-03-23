"""
Guardrails Module for HybridGate Framework

Implements safety guardrails for LLM-based secret detection:
- G1: Evidence + Location (require concrete evidence)
- G2: Untrusted Input Policy (ignore PR metadata)
- G3: Output Leakage (fail-closed: detect → redact once → REVIEW)
- G4: Uncertainty / Abstention (rule-based escalation to REVIEW)
- G5: Schema Validation (validate output structure, route invalid to REVIEW)
- G6: Format-Familiarity Pre-Scan (pre-LLM hint mechanism, exploratory)

Guardrail Order:
0. G6 (Format-Familiarity) - PRE-LLM: extracts candidates, injects hint
1. G5 (Schema Validation) - runs first post-LLM, routes invalid to REVIEW
2. G2 (Untrusted Input) - runs before G4 so G4 can use G2 issues
3. G4 (Uncertainty Routing) - rule-based escalation
4. G1 (Evidence Check) - validates evidence on unredacted output
5. G3 (Output Leakage) - final output safety layer (detect → redact → REVIEW)
"""

from .base import GuardrailConfig, GuardrailResult
from .g1_evidence_location import G1EvidenceLocation
from .g2_untrusted_input import G2UntrustedInput
from .g3_redaction import G3Redaction
from .g4_uncertainty import G4Uncertainty, VALID_CONFIDENCE_LEVELS
from .g5_schema_validation import (
    G5SchemaValidation, ValidationResult, ErrorCategory,
    VALID_SECRET_TYPES, VALID_EVIDENCE_MODES, VALID_FINAL_DECISIONS,
)
from .g6_format_familiarity import G6FormatFamiliarity, FormatCandidate
from .config import GuardrailSettings, DEFAULT_SETTINGS

__all__ = [
    'GuardrailConfig',
    'GuardrailResult',
    'G1EvidenceLocation',
    'G2UntrustedInput',
    'G3Redaction',
    'G4Uncertainty',
    'G5SchemaValidation',
    'G6FormatFamiliarity',
    'FormatCandidate',
    'ValidationResult',
    'ErrorCategory',
    'VALID_SECRET_TYPES',
    'VALID_EVIDENCE_MODES',
    'VALID_FINAL_DECISIONS',
    'GuardrailSettings',
    'DEFAULT_SETTINGS',
    'VALID_CONFIDENCE_LEVELS',
    'get_guardrail_bundle',
    'get_g6_hint',
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

    # G6 adds format-familiarity forced-reasoning system prompt;
    # the dynamic hint is generated separately via get_g6_hint()
    if settings.is_enabled("G6"):
        g6 = G6FormatFamiliarity()
        prompts.append(g6.get_prompt_forced_reasoning())

    return "\n".join(prompts)


def get_g6_hint(
    diff_text: str,
    settings: GuardrailSettings = None,
) -> str:
    """
    Run G6 pre-scan on a diff and return the dynamic hint string.

    This should be appended to the user prompt before the LLM call.
    Returns empty string if G6 is disabled or no candidates found.

    Args:
        diff_text: Raw diff text (before line numbering)
        settings: Guardrail settings

    Returns:
        Hint string to append to user prompt, or ""
    """
    if settings is None:
        settings = DEFAULT_SETTINGS

    if not settings.is_enabled("G6"):
        return ""

    g6 = G6FormatFamiliarity()
    candidates = g6.extract_candidates(diff_text)
    return g6.get_forced_reasoning_hint(candidates)


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
    settings: GuardrailSettings = None,
    diff_context: str = None,
    pr_title: str = "",
    pr_body: str = "",
    scanner_hit: bool = None,
    file_path: str = "",
) -> dict:
    """
    Apply guardrails with decision routing (G5 -> G2 -> G4 -> G1 -> G3 order).

    This is the comprehensive guardrail application function that:
    1. G5: Validates schema, routes invalid to REVIEW (fail-closed)
    2. G2: Checks untrusted-input influence, routes exculpatory to REVIEW
    3. G4: Rule-based uncertainty escalation (flags + context rules)
    4. G1: Validates evidence on unredacted output, routes invalid to REVIEW
    5. G3: Final output safety layer (detect → redact once → REVIEW)

    When G5 fails, it locks the routing decision (routed_by_guardrail="G5",
    final_decision="REVIEW").  Downstream guardrails G2–G3 still run for
    failure-mode annotation but cannot override the locked decision.

    Note: G2 runs before G4 so that G4 can use G2 issues as context
    for its ambiguity assessment.

    Args:
        raw_response: Raw LLM response string (before JSON parsing)
        ground_truth: Optional ground truth for leak detection
        settings: Guardrail settings (defaults to DEFAULT_SETTINGS)
        diff_context: Optional diff content for context-aware G1 validation
        pr_title: Original PR title (for G2 cross-check, optional)
        pr_body: Original PR body (for G2 cross-check, optional)
        scanner_hit: Optional scanner result for G4 disagreement detection
        file_path: Optional source file path (for G4 context inference)

    Returns:
        Dictionary with:
        - parsed_output: The parsed LLM output (or None if parse failed)
        - final_decision: Final decision after guardrail routing
        - original_decision: Decision before guardrail routing
        - confidence: Confidence value from LLM (or None)
        - schema_valid: Whether G5 validation passed
        - validation_errors: List of G5 validation errors
        - routed_by_guardrail: Which guardrail triggered routing (G1/G2/G4/G5/None)
        - triggered_guardrails: All guardrails that triggered, in pipeline order
        - g4_details: G4 flag/rule details (reported_flags, inferred_flags, triggered_rule)
        - g3_details: G3 leak detection/mitigation details
        - g1_valid, g1_issues, g2_valid, g2_issues, g3_valid, g3_leak_detected, g3_triggered: Validation flags
    """
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
        # Guardrail validation flags
        "g1_valid": False,
        "g1_issues": [],
        "g2_valid": True,
        "g2_issues": [],
        "g3_valid": False,
        "g3_triggered": False,
        "g3_leak_detected": False,
        "g3_details": {},
        "g4_valid": False,
        "g4_details": {},
        "g5_valid": False,
        "triggered_guardrails": [],
    }

    # =========================================================================
    # STEP 1: G5 Schema Validation (runs first)
    # =========================================================================
    g5 = G5SchemaValidation()
    g5_enabled = settings.is_enabled("G5")
    g4_enabled = settings.is_enabled("G4")

    # Validate the raw response (G5 is now independent of G4/confidence)
    validation = g5.validate(raw_response)

    result["schema_valid"] = validation.schema_valid
    result["validation_errors"] = validation.errors
    result["g5_valid"] = validation.is_valid
    result["error_categories"] = sorted(validation.error_categories)

    # G5 fail-closed: lock routing decision.  Downstream guardrails still
    # run for annotation but the existing `routed_by_guardrail is None`
    # guards prevent them from overriding this decision.
    g5_failed = not validation.is_valid
    if g5_failed and g5_enabled:
        result["routed_by_guardrail"] = "G5"
        result["final_decision"] = "REVIEW"

    # Use parsed output if available, empty dict as fallback for G5 failures.
    # Downstream guardrails run their real logic on whatever is available;
    # missing fields naturally produce "nothing to flag" rather than
    # synthetic triggers.
    llm_output = validation.parsed_output or {}
    result["parsed_output"] = validation.parsed_output  # None if parse failed

    # Extract confidence (for G4, if present in output)
    result["confidence"] = llm_output.get("confidence")
    if result["confidence"]:
        result["confidence"] = str(result["confidence"]).upper()

    # Determine original decision from pred_has_secret
    has_secret = llm_output.get("pred_has_secret", False)
    original_decision = "BLOCK" if has_secret else "PASS"
    result["original_decision"] = original_decision
    if not g5_failed:
        result["final_decision"] = original_decision

    # =========================================================================
    # STEP 2: G2 Untrusted Input Check (runs before G4 so G4 can use issues)
    # =========================================================================
    g2 = G2UntrustedInput()
    g2_valid, g2_issues = g2.validate_with_details(llm_output, pr_title, pr_body)
    result["g2_valid"] = g2_valid
    result["g2_issues"] = g2_issues

    # G2: Route to REVIEW if untrusted input influence detected
    if not g2_valid and result["routed_by_guardrail"] is None:
        result["routed_by_guardrail"] = "G2"
        result["final_decision"] = "REVIEW"

    # =========================================================================
    # STEP 3: G4 Uncertainty Escalation (rule-based, uses G2 results)
    # =========================================================================
    g4_details = {}
    if g4_enabled:
        g4 = G4Uncertainty()
        result["g4_valid"] = g4.validate_output(llm_output)

        # Build full guardrail context for flag inference
        guardrail_context = {
            "file_path": file_path,
            "pr_title": pr_title,
            "pr_body": pr_body,
            "code_context": diff_context,
            "scanner_hit": scanner_hit,
            "schema_repaired": (
                validation.repair_attempted and validation.repair_succeeded
            ),
            "g2_issues": g2_issues,
        }

        g4_details = g4.validate_with_details(llm_output, guardrail_context)
        result["g4_details"] = g4_details

        if g4_details["should_review"] and result["routed_by_guardrail"] is None:
            result["routed_by_guardrail"] = "G4"
            result["final_decision"] = "REVIEW"

    # =========================================================================
    # STEP 4: G1 Evidence Check (on unredacted output, before G3 redaction)
    # =========================================================================
    g1 = G1EvidenceLocation()

    # Parse diff_lines for context-aware validation
    diff_lines = None
    if diff_context:
        diff_lines = diff_context.split('\n')

    g1_valid, g1_issues = g1.validate_output_with_context(llm_output, diff_lines)
    result["g1_valid"] = g1_valid
    result["g1_issues"] = g1_issues

    # G1: Route to REVIEW if evidence validation fails (and not already routed)
    if not g1_valid and result["routed_by_guardrail"] is None:
        result["routed_by_guardrail"] = "G1"
        result["final_decision"] = "REVIEW"

    # =========================================================================
    # STEP 5: G3 Output Leakage — final safety layer
    # (detect → redact once → REVIEW if still leaky)
    # G3 runs last so that G1 validates evidence on the unredacted output,
    # while G3 serves as the final output-safety gate.
    # =========================================================================
    g3 = G3Redaction()
    g3_context = {
        "code_context": diff_context,
    }
    # For G5 PARSE_ERROR (no parsed dict), wrap the raw response so G3's
    # full-text scanner can still check for leaked secret patterns.
    g3_input = llm_output if llm_output else {"_raw_text": raw_response}
    g3_details = g3.validate_with_details(g3_input, guardrail_context=g3_context)
    result["g3_triggered"] = g3_details["g3_triggered"]
    result["g3_leak_detected"] = g3_details["leak_detected_initial"]
    result["g3_valid"] = not g3_details["g3_triggered"] or g3_details["mitigation_succeeded"]
    result["g3_details"] = {
        "g3_triggered": g3_details["g3_triggered"],
        "leak_detected_initial": g3_details["leak_detected_initial"],
        "initial_findings_count": g3_details["initial_findings_count"],
        "mitigation_attempted": g3_details["mitigation_attempted"],
        "mitigation_succeeded": g3_details["mitigation_succeeded"],
        "leak_detected_after_mitigation": g3_details["leak_detected_after_mitigation"],
        "g3_flags": g3_details["g3_flags"],
    }

    # G3: Route to REVIEW if mitigation failed (fail-closed)
    if g3_details["recommended_decision"] == "REVIEW" and result["routed_by_guardrail"] is None:
        result["routed_by_guardrail"] = "G3"
        result["final_decision"] = "REVIEW"

    # If G3 successfully redacted, update parsed_output with sanitised version
    if g3_details["mitigation_succeeded"] and g3_details["sanitised_output"]:
        result["parsed_output"] = g3_details["sanitised_output"]

    # =========================================================================
    # Multi-trigger list: all guardrails that triggered, in pipeline order.
    # Independent of routed_by_guardrail (which records only the first router).
    # =========================================================================
    triggered = []
    if g5_failed:
        triggered.append("G5")
    if not g2_valid:
        triggered.append("G2")
    if g4_enabled and g4_details and g4_details.get("should_review"):
        triggered.append("G4")
    if not g1_valid:
        triggered.append("G1")
    if g3_details["g3_triggered"]:
        triggered.append("G3")
    result["triggered_guardrails"] = triggered

    return result
