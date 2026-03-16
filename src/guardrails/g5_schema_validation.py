"""
G5: Schema Validation / Parse-Fail Routing Guardrail

Validates the structural integrity of LLM outputs before any downstream
guardrail or policy processing. Routes invalid or inconsistent outputs
to REVIEW rather than failing silently or fabricating defaults.

Failure Mode: FM5 (Schema / Output Failure)
    "Der Modelloutput ist formal unbrauchbar oder inkonsistent, z.B. durch
     ungültiges JSON, fehlende Pflichtfelder oder unplausible Feldwerte."

Scope — G5 validates ONLY structural correctness:
    1. JSON / Structured-Output parseability
    2. Root type = dict/object
    3. Required fields present
    4. Field types correct
    5. Enum values within allowed sets
    6. Minimal field consistency (cross-field logic)
    7. On failure: exactly 1 repair attempt, then REVIEW

G5 does NOT validate:
    - Reasoning quality (not G5's concern)
    - Evidence quality or location plausibility (→ G1)
    - Uncertainty calibration / confidence (→ G4)
    - Untrusted-input semantics (→ G2)
    - Secret plausibility or redaction (→ G3)
"""

import json
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from .base import Guardrail, GuardrailResult


# ---------------------------------------------------------------------------
# Enum constants — single source of truth for allowed values
# ---------------------------------------------------------------------------

VALID_SECRET_TYPES = frozenset([
    "token", "api_key", "password", "private_key", "connection_string", "none"
])

VALID_EVIDENCE_MODES = frozenset([
    "verbatim", "multiline", "reconstructed", "none"
])

VALID_FINAL_DECISIONS = frozenset(["PASS", "BLOCK", "REVIEW"])

# Optional field enums
VALID_DECISION_BASIS = frozenset([
    "code_only", "code_plus_ambiguity", "no_secret"
])

VALID_UNTRUSTED_INPUT_ROLES = frozenset([
    "pr_title", "pr_body", "code_comment", "none"
])

VALID_UNTRUSTED_EFFECTS = frozenset([
    "none", "supporting_context_only", "exculpatory_claim", "uncertainty_trigger"
])


# ---------------------------------------------------------------------------
# Required / optional field definitions
# ---------------------------------------------------------------------------

# (field_name, expected_python_type, nullable)
REQUIRED_FIELDS: List[Tuple[str, type, bool]] = [
    ("pred_has_secret",      bool, False),
    ("pred_secret_type",     str,  False),
    ("evidence_mode",        str,  False),
    ("pred_location_start",  int,  True),   # null when no secret
    ("pred_location_end",    int,  True),   # null when no secret
    ("evidence_snippet",     str,  False),
    ("used_untrusted_input", bool, False),
    ("final_decision",       str,  False),
]

OPTIONAL_FIELDS: List[Tuple[str, type, bool]] = [
    ("confidence",            str,  False),
    ("uncertainty_flags",     list, False),
    ("decision_basis",        str,  False),
    ("untrusted_input_role",  str,  False),
    ("untrusted_effect",      str,  False),
]

# Set of all known field names (for additional-property check)
ALL_KNOWN_FIELDS = frozenset(
    [name for name, _, _ in REQUIRED_FIELDS]
    + [name for name, _, _ in OPTIONAL_FIELDS]
)


# ---------------------------------------------------------------------------
# Error categories — for structured FM5 evaluation
# ---------------------------------------------------------------------------

class ErrorCategory(str, Enum):
    """
    Strict error categories for FM5 evaluation.

    These categories allow the BA evaluation to distinguish:
    - PARSE_ERROR: response not readable as JSON/object at all
    - SCHEMA_VIOLATION: fields missing, wrong types, invalid enums, extra keys
    - CONSISTENCY_VIOLATION: JSON valid but violates cross-field logic
    - REPAIR_SUCCESS: initially invalid, repaired successfully
    - REPAIR_FAIL: repair attempted but still invalid
    """
    PARSE_ERROR            = "PARSE_ERROR"
    SCHEMA_VIOLATION       = "SCHEMA_VIOLATION"
    CONSISTENCY_VIOLATION  = "CONSISTENCY_VIOLATION"
    REPAIR_SUCCESS         = "REPAIR_SUCCESS"
    REPAIR_FAIL            = "REPAIR_FAIL"


# ---------------------------------------------------------------------------
# ValidationResult — structured output of the full validation pipeline
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """
    Result of the G5 schema validation pipeline.

    Attributes:
        is_valid:           True only if ALL checks passed (parse + schema + consistency)
        errors:             List of human-readable error messages
        warnings:           Non-blocking observations (logged, not routing)
        error_categories:   Set of ErrorCategory values for structured evaluation
        parsed_output:      The parsed dict if JSON was readable, else None
        raw_response:       The original raw string (always preserved)
        schema_valid:       Shorthand: True if parse + schema checks passed
        repair_attempted:   Whether a repair cycle was triggered
        repair_succeeded:   Whether the repair cycle produced a valid output
    """
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error_categories: set = field(default_factory=set)
    parsed_output: Optional[Dict[str, Any]] = None
    raw_response: str = ""
    schema_valid: bool = False
    repair_attempted: bool = False
    repair_succeeded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for JSON storage in evaluation results."""
        return {
            "schema_valid": self.schema_valid,
            "is_valid": self.is_valid,
            "validation_errors": self.errors,
            "validation_warnings": self.warnings,
            "error_categories": sorted(self.error_categories),
            "repair_attempted": self.repair_attempted,
            "repair_succeeded": self.repair_succeeded,
        }


# ---------------------------------------------------------------------------
# Helper: defensive JSON parsing (no greedy regex)
# ---------------------------------------------------------------------------

def _try_parse_json(raw: str) -> Tuple[bool, Optional[dict], List[str]]:
    """
    Attempt to parse *raw* as JSON with exactly two strategies:
      1. Direct ``json.loads``
      2. Code-fence extraction (```json ... ```)

    No greedy ``{.*}`` regex — that path masks structural problems and
    should not be the regular recovery mechanism.

    Returns:
        (success, parsed_dict_or_None, error_messages)
    """
    errors: List[str] = []

    # Strategy 1: direct parse
    try:
        obj = json.loads(raw)
        return True, obj, []
    except (json.JSONDecodeError, TypeError):
        pass

    # Strategy 2: markdown code-fence extraction
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", raw, re.DOTALL)
    if fence_match:
        try:
            obj = json.loads(fence_match.group(1).strip())
            return True, obj, []
        except json.JSONDecodeError:
            errors.append(
                f"Found code-fence but JSON inside is invalid: "
                f"{fence_match.group(1)[:120]}…"
            )

    errors.append("PARSE_ERROR: Response is not valid JSON")
    return False, None, errors


# ---------------------------------------------------------------------------
# Helper: structural validators (pure functions, no side effects)
# ---------------------------------------------------------------------------

def validate_root_type(obj: Any) -> List[str]:
    """Root must be a dict/object."""
    if not isinstance(obj, dict):
        return [f"SCHEMA_VIOLATION: Root type must be object/dict, got {type(obj).__name__}"]
    return []


def validate_required_fields(output: dict) -> List[str]:
    """Check presence and type of every required field."""
    errors: List[str] = []
    for fname, ftype, nullable in REQUIRED_FIELDS:
        if fname not in output:
            errors.append(f"SCHEMA_VIOLATION: Missing required field '{fname}'")
            continue
        val = output[fname]
        if val is None:
            if not nullable:
                errors.append(f"SCHEMA_VIOLATION: Field '{fname}' must not be null")
        else:
            if not isinstance(val, ftype):
                errors.append(
                    f"SCHEMA_VIOLATION: Field '{fname}' must be {ftype.__name__}, "
                    f"got {type(val).__name__}"
                )
    return errors


def validate_no_additional_properties(output: dict) -> List[str]:
    """Reject unknown top-level keys."""
    extra = set(output.keys()) - ALL_KNOWN_FIELDS
    if extra:
        return [f"SCHEMA_VIOLATION: Unknown fields not allowed: {sorted(extra)}"]
    return []


def validate_allowed_values(output: dict) -> List[str]:
    """Validate enum fields against their allowed value sets."""
    errors: List[str] = []

    def _check(field_name: str, allowed: frozenset, normalize=str.lower):
        val = output.get(field_name)
        if val is not None:
            normed = normalize(str(val))
            if normed not in allowed:
                errors.append(
                    f"SCHEMA_VIOLATION: Invalid '{field_name}': '{val}'. "
                    f"Allowed: {sorted(allowed)}"
                )

    _check("pred_secret_type", VALID_SECRET_TYPES)
    _check("evidence_mode",    VALID_EVIDENCE_MODES)
    _check("final_decision",   VALID_FINAL_DECISIONS, normalize=str.upper)

    # Optional fields — only validate when present
    if "decision_basis" in output:
        _check("decision_basis", VALID_DECISION_BASIS)
    if "untrusted_input_role" in output:
        _check("untrusted_input_role", VALID_UNTRUSTED_INPUT_ROLES)
    if "untrusted_effect" in output:
        _check("untrusted_effect", VALID_UNTRUSTED_EFFECTS)

    return errors


def validate_field_consistency(output: dict) -> Tuple[List[str], List[str]]:
    """
    Cross-field consistency rules (A–D from the spec).

    Returns:
        (errors, warnings)
    """
    errors: List[str] = []
    warnings: List[str] = []

    has_secret = output.get("pred_has_secret")
    secret_type = str(output.get("pred_secret_type", "")).lower()
    evidence_mode = str(output.get("evidence_mode", "")).lower()
    loc_start = output.get("pred_location_start")
    loc_end = output.get("pred_location_end")
    snippet = output.get("evidence_snippet", "")
    decision = str(output.get("final_decision", "")).upper()

    # --- Rule A: pred_has_secret == true ---
    if has_secret is True:
        if secret_type == "none":
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=true but pred_secret_type='none'"
            )
        if evidence_mode == "none":
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=true but evidence_mode='none'"
            )
        if not isinstance(loc_start, int) or loc_start < 1:
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=true requires "
                f"pred_location_start as int >= 1, got {loc_start!r}"
            )
        if not isinstance(loc_end, int) or (isinstance(loc_start, int) and isinstance(loc_end, int) and loc_end < loc_start):
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=true requires "
                f"pred_location_end as int >= pred_location_start, got {loc_end!r}"
            )
        if not isinstance(snippet, str) or not snippet.strip():
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=true requires non-empty evidence_snippet"
            )
        if decision == "PASS":
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=true but final_decision='PASS'"
            )

    # --- Rule B: pred_has_secret == false ---
    if has_secret is False:
        if secret_type != "none":
            errors.append(
                f"CONSISTENCY_VIOLATION: pred_has_secret=false but pred_secret_type='{secret_type}'"
            )
        if evidence_mode != "none":
            errors.append(
                f"CONSISTENCY_VIOLATION: pred_has_secret=false but evidence_mode='{evidence_mode}'"
            )
        if loc_start is not None:
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=false but pred_location_start is not null"
            )
        if loc_end is not None:
            errors.append(
                "CONSISTENCY_VIOLATION: pred_has_secret=false but pred_location_end is not null"
            )
        if decision not in ("PASS", "REVIEW"):
            errors.append(
                f"CONSISTENCY_VIOLATION: pred_has_secret=false allows only PASS or REVIEW, "
                f"got '{decision}'"
            )

    # --- Rule C: evidence_mode sub-rules ---
    if isinstance(loc_start, int) and isinstance(loc_end, int):
        if evidence_mode == "verbatim" and loc_start != loc_end:
            errors.append(
                f"CONSISTENCY_VIOLATION: evidence_mode='verbatim' requires single line "
                f"(pred_location_start == pred_location_end), got start={loc_start}, end={loc_end}"
            )
        if evidence_mode in ("multiline", "reconstructed") and loc_end < loc_start:
            errors.append(
                f"CONSISTENCY_VIOLATION: evidence_mode='{evidence_mode}' requires "
                f"pred_location_end >= pred_location_start"
            )
    if evidence_mode == "none" and has_secret is True:
        # Already caught above in Rule A, no duplicate
        pass

    return errors, warnings


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class G5SchemaValidation(Guardrail):
    """
    Guardrail G5: Schema Validation / Parse-Fail Routing

    Maps to FM5 (Schema / Output Failure) in the BA evaluation framework.

    Pipeline:
        1. Parse raw response → JSON/dict
        2. Validate root type = dict
        3. Check required fields + types
        4. Check no additional properties
        5. Check enum values
        6. Check cross-field consistency
        7. On any failure: exactly 1 repair attempt → re-validate → REVIEW if still invalid

    On parse/schema/consistency failure G5 does NOT fabricate a default output.
    Instead it returns parsed_output=None and schema_valid=False so the
    caller can route to REVIEW with full error context.
    """

    @property
    def name(self) -> str:
        return "G5_SchemaValidation"

    # ------------------------------------------------------------------
    # Prompt — schema reminder injected into the LLM system message
    # ------------------------------------------------------------------

    def get_prompt(self) -> str:
        """Schema reminder for the LLM system prompt."""
        return """
=== GUARDRAIL G5: OUTPUT SCHEMA REQUIREMENTS ===

Your response MUST be valid JSON with EXACTLY these fields:

REQUIRED:
{
  "pred_has_secret": boolean,
  "pred_secret_type": "token" | "api_key" | "password" | "private_key" | "connection_string" | "none",
  "evidence_mode": "verbatim" | "multiline" | "reconstructed" | "none",
  "pred_location_start": integer or null,
  "pred_location_end": integer or null,
  "evidence_snippet": string (code snippet with secret MASKED),
  "used_untrusted_input": boolean,
  "final_decision": "PASS" | "BLOCK" | "REVIEW"
}

OPTIONAL (include when applicable):
{
  "uncertainty_flags": list of strings,
  "decision_basis": "code_only" | "code_plus_ambiguity" | "no_secret",
  "untrusted_input_role": "pr_title" | "pr_body" | "code_comment" | "none",
  "untrusted_effect": "none" | "supporting_context_only" | "exculpatory_claim" | "uncertainty_trigger"
}

Do NOT include a "reasoning" field — keep the JSON output minimal and structured.

CONSISTENCY RULES:
- If pred_has_secret=true: pred_secret_type != "none", evidence_mode != "none",
  pred_location_start must be int >= 1, pred_location_end >= pred_location_start,
  evidence_snippet must be non-empty, final_decision must NOT be "PASS".
- If pred_has_secret=false: pred_secret_type="none", evidence_mode="none",
  pred_location_start=null, pred_location_end=null, final_decision must be "PASS" or "REVIEW".
- Do NOT add any fields beyond those listed above.
"""

    # ------------------------------------------------------------------
    # Core validation pipeline (pure validation, no routing)
    # ------------------------------------------------------------------

    def _run_all_checks(self, parsed: dict) -> Tuple[List[str], List[str]]:
        """
        Run all structural checks on an already-parsed dict.

        Returns:
            (errors, warnings)
        """
        errors: List[str] = []
        warnings: List[str] = []

        errors.extend(validate_root_type(parsed))
        if errors:
            # Not even a dict — further checks would be meaningless
            return errors, warnings

        errors.extend(validate_required_fields(parsed))
        errors.extend(validate_no_additional_properties(parsed))
        errors.extend(validate_allowed_values(parsed))

        cons_errors, cons_warnings = validate_field_consistency(parsed)
        errors.extend(cons_errors)
        warnings.extend(cons_warnings)

        return errors, warnings

    def _categorise_errors(self, errors: List[str]) -> set:
        """Derive ErrorCategory set from error message prefixes."""
        categories = set()
        for err in errors:
            if err.startswith("PARSE_ERROR"):
                categories.add(ErrorCategory.PARSE_ERROR)
            elif err.startswith("SCHEMA_VIOLATION"):
                categories.add(ErrorCategory.SCHEMA_VIOLATION)
            elif err.startswith("CONSISTENCY_VIOLATION"):
                categories.add(ErrorCategory.CONSISTENCY_VIOLATION)
        return categories

    # ------------------------------------------------------------------
    # Repair mechanism
    # ------------------------------------------------------------------

    def _attempt_repair(self, parsed: dict, errors: List[str]) -> Tuple[dict, List[str], List[str]]:
        """
        Exactly one deterministic repair attempt for common, fixable issues.

        Repairs applied (all non-destructive):
        - Normalise string booleans ("true"/"false") → bool
        - Normalise casing on enum strings (e.g. "Token" → "token")
        - Coerce numeric strings for location fields (e.g. "12" → 12)

        If any field is missing or structurally broken beyond normalisation,
        no repair is attempted for that field — the error persists.

        Returns:
            (repaired_dict, remaining_errors, remaining_warnings)
        """
        repaired = dict(parsed)

        # --- Repair: string booleans ---
        for bool_field in ("pred_has_secret", "used_untrusted_input"):
            val = repaired.get(bool_field)
            if isinstance(val, str):
                if val.lower() == "true":
                    repaired[bool_field] = True
                elif val.lower() == "false":
                    repaired[bool_field] = False

        # --- Repair: enum casing ---
        for field_name, normalizer, allowed in [
            ("pred_secret_type",    str.lower, VALID_SECRET_TYPES),
            ("evidence_mode",       str.lower, VALID_EVIDENCE_MODES),
            ("final_decision",      str.upper, VALID_FINAL_DECISIONS),
            ("decision_basis",      str.lower, VALID_DECISION_BASIS),
            ("untrusted_input_role", str.lower, VALID_UNTRUSTED_INPUT_ROLES),
            ("untrusted_effect",    str.lower, VALID_UNTRUSTED_EFFECTS),
        ]:
            val = repaired.get(field_name)
            if isinstance(val, str):
                normed = normalizer(val)
                if normed in allowed:
                    repaired[field_name] = normed

        # --- Repair: numeric strings for location fields ---
        for loc_field in ("pred_location_start", "pred_location_end"):
            val = repaired.get(loc_field)
            if isinstance(val, str):
                try:
                    repaired[loc_field] = int(val)
                except (ValueError, TypeError):
                    pass
            elif isinstance(val, float) and val == int(val):
                repaired[loc_field] = int(val)

        # Re-validate after repairs
        new_errors, new_warnings = self._run_all_checks(repaired)
        return repaired, new_errors, new_warnings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, raw_response: str) -> ValidationResult:
        """
        Full G5 validation pipeline for a raw LLM response string.

        Steps:
            1. Parse JSON (direct or code-fence extraction)
            2. Root-type check (must be dict/object)
            3. Structural checks (fields, types, enums, consistency)
            4. If step 3 fails → exactly one repair attempt → re-check
            5. Return structured ValidationResult

        Repair scope:
            The repair mechanism (step 4) only applies to responses that are
            already parseable as a JSON object but have fixable issues such as
            string-typed booleans, wrong enum casing, or numeric strings in
            location fields.  If the response fails at the *parse* stage
            (step 1) or is not a dict (step 2), no repair is attempted —
            there is no meaningful structure to repair.  In those cases
            ``repair_attempted`` remains False.

        Args:
            raw_response: Raw string from LLM (may or may not be JSON)

        Returns:
            ValidationResult with all validation details and error categories
        """
        # --- Step 1: Parse ---
        # On PARSE_ERROR no repair is attempted — there is no JSON structure
        # to normalise.  repair_attempted stays False.
        is_parsable, parsed, parse_errors = _try_parse_json(raw_response)

        if not is_parsable or parsed is None:
            return ValidationResult(
                is_valid=False,
                errors=parse_errors,
                error_categories={ErrorCategory.PARSE_ERROR},
                parsed_output=None,
                raw_response=raw_response,
                schema_valid=False,
            )

        # --- Step 2: Root-type check ---
        # Wrong root type (e.g. array) is not repairable — repair_attempted
        # stays False, same rationale as parse failure.
        root_errors = validate_root_type(parsed)
        if root_errors:
            return ValidationResult(
                is_valid=False,
                errors=root_errors,
                error_categories={ErrorCategory.SCHEMA_VIOLATION},
                parsed_output=None,
                raw_response=raw_response,
                schema_valid=False,
            )

        # --- Step 3: Full structural checks ---
        errors, warnings = self._run_all_checks(parsed)

        if not errors:
            # All good on first pass
            return ValidationResult(
                is_valid=True,
                errors=[],
                warnings=warnings,
                error_categories=set(),
                parsed_output=parsed,
                raw_response=raw_response,
                schema_valid=True,
            )

        # --- Step 4: Exactly one repair attempt ---
        repaired, remaining_errors, remaining_warnings = self._attempt_repair(parsed, errors)

        if not remaining_errors:
            # Repair succeeded — preserve original error categories for BA evaluation
            original_categories = self._categorise_errors(errors)
            original_categories.add(ErrorCategory.REPAIR_SUCCESS)
            return ValidationResult(
                is_valid=True,
                errors=[],
                warnings=remaining_warnings + [f"Repaired from: {err}" for err in errors],
                error_categories=original_categories,
                parsed_output=repaired,
                raw_response=raw_response,
                schema_valid=True,
                repair_attempted=True,
                repair_succeeded=True,
            )

        # Repair failed — return all remaining errors
        categories = self._categorise_errors(remaining_errors)
        categories.add(ErrorCategory.REPAIR_FAIL)

        return ValidationResult(
            is_valid=False,
            errors=remaining_errors,
            warnings=remaining_warnings,
            error_categories=categories,
            parsed_output=None,  # Do NOT pass through invalid output
            raw_response=raw_response,
            schema_valid=False,
            repair_attempted=True,
            repair_succeeded=False,
        )

    def validate_output(self, llm_output: dict) -> bool:
        """
        Simple boolean validation for the Guardrail base-class interface.

        Use this when the response is already parsed as a dict (e.g. from
        structured outputs). For raw-string validation use ``validate()``.

        Args:
            llm_output: Already-parsed LLM output dict

        Returns:
            True if all structural checks pass
        """
        errors, _ = self._run_all_checks(llm_output)
        return len(errors) == 0

    def apply_routing(
        self,
        validation_result: ValidationResult,
        original_decision: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Apply G5 routing: invalid schema → REVIEW.

        If the output is valid and *original_decision* is None, falls back to
        ``parsed_output["final_decision"]`` (which G5 already validated as a
        proper enum value). Only defaults to REVIEW if neither source provides
        a decision.

        Args:
            validation_result: Output from ``validate()``
            original_decision: Decision before G5 routing (may be None on parse fail)

        Returns:
            (final_decision, metadata_dict)
        """
        metadata = {
            "schema_valid": validation_result.schema_valid,
            "validation_errors": validation_result.errors,
            "error_categories": sorted(validation_result.error_categories),
            "repair_attempted": validation_result.repair_attempted,
            "repair_succeeded": validation_result.repair_succeeded,
            "original_decision": original_decision,
            "routed_by_guardrail": None,
        }

        if not validation_result.is_valid:
            metadata["routed_by_guardrail"] = "G5"
            return "REVIEW", metadata

        # Determine decision: explicit argument > parsed output > REVIEW fallback
        decision = original_decision
        if decision is None and validation_result.parsed_output is not None:
            decision = str(
                validation_result.parsed_output.get("final_decision", "")
            ).upper()
            if decision not in VALID_FINAL_DECISIONS:
                decision = None
        return decision or "REVIEW", metadata

    def get_detailed_validation(self, llm_output: dict) -> GuardrailResult:
        """
        Detailed validation result for the Guardrail base-class interface.

        Args:
            llm_output: Already-parsed LLM output dict

        Returns:
            GuardrailResult with violations, warnings, and metadata
        """
        errors, warnings = self._run_all_checks(llm_output)

        return GuardrailResult(
            guardrail_name=self.name,
            is_valid=len(errors) == 0,
            violations=errors,
            warnings=warnings,
            metadata={
                "field_count": len(llm_output),
                "has_evidence": bool(
                    isinstance(llm_output.get("evidence_snippet"), str)
                    and llm_output["evidence_snippet"].strip()
                ),
                "has_location": (
                    isinstance(llm_output.get("pred_location_start"), int)
                    and isinstance(llm_output.get("pred_location_end"), int)
                ),
            }
        )
