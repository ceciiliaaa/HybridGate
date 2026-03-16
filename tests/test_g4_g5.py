"""
Tests for G4 (Uncertainty Routing) and G5 (Schema Validation) Guardrails

G5 tests validate against the new 8-field required schema:
  pred_has_secret, pred_secret_type, evidence_mode,
  pred_location_start, pred_location_end, evidence_snippet,
  used_untrusted_input, final_decision

G4 tests remain unchanged (confidence routing is G4's concern, not G5's).

Run with: python -m pytest tests/test_g4_g5.py -v
"""

import json
import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from guardrails import (
    G4Uncertainty,
    G5SchemaValidation,
    GuardrailSettings,
    apply_guardrails_with_routing
)
from guardrails.g5_schema_validation import ErrorCategory


# ---------------------------------------------------------------------------
# Fixtures: valid outputs for reuse across tests
# ---------------------------------------------------------------------------

def _valid_secret():
    """Minimal valid output: secret found."""
    return {
        "pred_has_secret": True,
        "pred_secret_type": "api_key",
        "evidence_mode": "verbatim",
        "pred_location_start": 5,
        "pred_location_end": 5,
        "evidence_snippet": "API_KEY = 'sk_t***'",
        "used_untrusted_input": False,
        "final_decision": "BLOCK",
    }


def _valid_no_secret():
    """Minimal valid output: no secret."""
    return {
        "pred_has_secret": False,
        "pred_secret_type": "none",
        "evidence_mode": "none",
        "pred_location_start": None,
        "pred_location_end": None,
        "evidence_snippet": "",
        "used_untrusted_input": False,
        "final_decision": "PASS",
    }


# =========================================================================
# G4 Tests — rule-based uncertainty escalation
# =========================================================================

class TestG4Uncertainty:
    """Tests for G4 Uncertainty / Abstention Guardrail (rule-based)."""

    # --- Basics: confidence is optional, G4 always valid ---

    def test_g4_always_valid_without_confidence(self):
        """G4: Missing confidence does NOT invalidate G4."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}  # no confidence field
        assert g4.validate_output(llm_output) is True

    def test_g4_confidence_optional_read(self):
        """G4: confidence is read but not required."""
        g4 = G4Uncertainty()
        assert g4.get_confidence({"confidence": "low"}) == "LOW"
        assert g4.get_confidence({"confidence": "HIGH"}) == "HIGH"
        assert g4.get_confidence({}) is None  # missing = None, not invalid

    def test_g4_no_flags_no_review(self):
        """G4: Clean output without ambiguity signals → no REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret(), "confidence": "HIGH"}
        result = g4.validate_with_details(llm_output)
        assert result["should_review"] is False
        assert result["g4_valid"] is True
        assert len(result["all_flags"]) == 0

    def test_g4_no_review_for_clean_no_secret(self):
        """G4: Clean no-secret output → no REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_no_secret()}
        result = g4.validate_with_details(llm_output)
        assert result["should_review"] is False

    # --- R1: Ambiguous context without productive path → REVIEW ---

    def test_g4_r1_placeholder_in_snippet(self):
        """G4 R1: Placeholder-like evidence without productive path → REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "evidence_snippet": "API_KEY = 'your_api_key_here'",
        }
        result = g4.validate_with_details(llm_output)
        assert result["should_review"] is True
        assert result["triggered_rule"] == "R1_ambiguous_context"
        assert "placeholder_or_example_context" in result["inferred_flags"]

    def test_g4_r1_test_file_path(self):
        """G4 R1: Test file path → test_or_docs_context → REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {"file_path": "tests/test_config.py"}

        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "test_or_docs_context" in result["inferred_flags"]
        assert result["should_review"] is True
        assert result["triggered_rule"] == "R1_ambiguous_context"

    def test_g4_r1_productive_path_suppresses(self):
        """G4 R1: Productive file path suppresses ambiguity REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "evidence_snippet": "API_KEY = 'your_api_key_here'",
        }
        ctx = {"file_path": "src/config/settings.py"}

        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "placeholder_or_example_context" in result["inferred_flags"]
        # R1 suppressed by productive path
        assert result["triggered_rule"] != "R1_ambiguous_context" or \
               result["should_review"] is False

    def test_g4_r1_low_specificity_alone_no_review(self):
        """G4 R1: low_specificity_literal alone does NOT trigger R1."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "evidence_snippet": "DB_PASS = '1234'",
        }
        # '1234' matches low_specificity but NOT placeholder patterns
        result = g4.validate_with_details(llm_output)
        assert "low_specificity_literal" in result["inferred_flags"]
        assert "placeholder_or_example_context" not in result["inferred_flags"]
        assert result["triggered_rule"] != "R1_ambiguous_context"

    def test_g4_r1_no_file_path_needs_core_flag(self):
        """G4 R1: Missing file_path alone doesn't cause R1 — needs core flag."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        # No file_path, no ambiguity flags → no R1
        result = g4.validate_with_details(llm_output)
        assert result["should_review"] is False

    def test_g4_r1_real_secret_no_review(self):
        """G4 R1: Real-looking evidence → no ambiguity flag → no REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "evidence_snippet": "API_KEY = 'sk_live_a1b2c3d4e5f6g7h8'",
        }
        result = g4.validate_with_details(llm_output)
        assert "placeholder_or_example_context" not in result["inferred_flags"]
        assert result["should_review"] is False

    # --- R2: Reconstructed + ambiguous context → REVIEW ---

    def test_g4_r2_reconstructed_plus_placeholder(self):
        """G4 R2: Reconstructed secret + placeholder context in productive path → REVIEW via R2."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "evidence_mode": "reconstructed",
            "pred_location_start": 3,
            "pred_location_end": 5,
            "evidence_snippet": "key = p1 + p2  # example concat",
        }
        # Productive path suppresses R1, so R2 fires for reconstructed + ambiguity
        ctx = {"file_path": "src/config/settings.py"}
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert result["should_review"] is True
        assert result["triggered_rule"] == "R2_reconstructed_plus_ambiguity"
        assert "reconstructed_secret" in result["inferred_flags"]

    def test_g4_r2_reconstructed_no_ambiguity_no_review(self):
        """G4 R2: Reconstructed secret without ambiguity → no R2 REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "evidence_mode": "reconstructed",
            "evidence_snippet": "API_KEY = part_a + part_b",
        }
        result = g4.validate_with_details(llm_output)
        assert "reconstructed_secret" in result["inferred_flags"]
        # No ambiguity flags → R2 does not fire
        # (R1 also shouldn't fire — no placeholder/test patterns)
        assert result["should_review"] is False

    # --- R3: Scanner negative + LLM positive + docs/test context → REVIEW ---

    def test_g4_r3_scanner_neg_llm_pos_test_path(self):
        """G4 R3: Scanner negative + LLM positive + test path → REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {
            "scanner_hit": False,
            "file_path": "tests/test_secrets.py",
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "scanner_disagreement" in result["inferred_flags"]
        assert "test_or_docs_context" in result["inferred_flags"]
        # R1 fires first (test_or_docs_context without productive path)
        assert result["should_review"] is True

    def test_g4_r3_scanner_neg_llm_pos_no_context_no_r3(self):
        """G4 R3: Scanner neg + LLM pos but no test/docs context → no R3."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {
            "scanner_hit": False,
            "file_path": "src/auth/credentials.py",
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "scanner_disagreement" in result["inferred_flags"]
        # Productive path → R1 suppressed, R3 needs test/docs context
        assert result["should_review"] is False

    def test_g4_r3_scanner_pos_llm_neg(self):
        """G4 R3: Scanner pos + LLM neg → disagreement flag but R3 only targets scanner-neg."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_no_secret()}
        ctx = {"scanner_hit": True}

        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "scanner_disagreement" in result["inferred_flags"]
        # R3 only fires on scanner_neg + llm_pos, not this direction
        assert result["triggered_rule"] != "R3_scanner_neg_llm_pos_context"

    def test_g4_scanner_agreement_no_flag(self):
        """G4: Scanner and LLM agree → no disagreement flag."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_no_secret()}
        ctx = {"scanner_hit": False}

        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "scanner_disagreement" not in result["inferred_flags"]
        assert result["should_review"] is False

    # --- R4: Exculpatory escalation (G2 signal or PR claims) ---

    def test_g4_r4_g2_unreported_signal(self):
        """G4 R4: G2 flagged unreported influence (soft warning) → REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {
            "g2_issues": [
                "G2_UNREPORTED: PR metadata contains exculpatory claims"
            ],
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "g2_unreported_influence" in result["inferred_flags"]
        assert result["should_review"] is True
        assert result["triggered_rule"] == "R4_exculpatory_escalation"

    def test_g4_r4_g2_hard_exculpatory_not_retriggered(self):
        """G4 R4: G2 hard EXCULPATORY (already routed by G2) does NOT trigger G4."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {
            "g2_issues": [
                "G2_EXCULPATORY: untrusted_effect='exculpatory_claim'"
            ],
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        # G2_EXCULPATORY is NOT picked up by G4 — only G2_UNREPORTED is
        assert "g2_unreported_influence" not in result["inferred_flags"]

    def test_g4_r4_pr_claims_dummy_unreported(self):
        """G4 R4: PR text has dummy claims + LLM denies untrusted input → REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "used_untrusted_input": False,
        }
        ctx = {
            "pr_title": "Add dummy api key for testing",
            "pr_body": "This is a fake key placeholder",
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "comment_claims_dummy" in result["inferred_flags"]
        assert result["should_review"] is True

    def test_g4_r4_no_exculpatory_no_review(self):
        """G4 R4: No exculpatory signals → no R4 REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {"g2_issues": [], "pr_title": "Fix auth module", "pr_body": ""}
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "g2_unreported_influence" not in result["inferred_flags"]
        assert "comment_claims_dummy" not in result["inferred_flags"]

    # --- R5: Schema repair → REVIEW ---

    def test_g4_r5_schema_repaired(self):
        """G4 R5: G5 schema repair → REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {"schema_repaired": True}

        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "format_or_schema_repair_used" in result["inferred_flags"]
        assert result["should_review"] is True
        assert result["triggered_rule"] == "R5_schema_repair"

    def test_g4_r5_no_repair_no_review(self):
        """G4 R5: No schema repair → no R5 REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {"schema_repaired": False}

        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "format_or_schema_repair_used" not in result["inferred_flags"]

    # --- Flag inference: reported vs inferred ---

    def test_g4_reported_flags_passthrough(self):
        """G4: LLM-reported uncertainty_flags are collected separately."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "uncertainty_flags": ["test_or_docs_context", "comment_claims_dummy"],
        }
        result = g4.validate_with_details(llm_output)
        assert "test_or_docs_context" in result["reported_flags"]
        assert "comment_claims_dummy" in result["reported_flags"]

    def test_g4_low_specificity_from_generic_value(self):
        """G4: Generic token value → low_specificity_literal flag."""
        g4 = G4Uncertainty()
        llm_output = {
            **_valid_secret(),
            "evidence_snippet": "PASSWORD = 'changeme'",
        }
        result = g4.validate_with_details(llm_output)
        assert "low_specificity_literal" in result["inferred_flags"]

    def test_g4_comment_claims_dummy_from_code(self):
        """G4: Exculpatory code comment with secret context → comment_claims_dummy."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret(), "used_untrusted_input": False}
        ctx = {
            "code_context": 'API_KEY = "sk_live_abc123"  # dummy key for testing',
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "comment_claims_dummy" in result["inferred_flags"]
        # R4 should fire (comment_claims_dummy + used_untrusted_input=false)
        assert result["should_review"] is True

    def test_g4_comment_claims_dummy_no_secret_context(self):
        """G4: Code comment with exculpatory word but no secret context → no flag."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {
            "code_context": 'config = load()  # placeholder for now',
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        # "placeholder" present but no secret-context word in the comment
        assert "comment_claims_dummy" not in result["inferred_flags"]

    def test_g4_decoy_pattern_in_code(self):
        """G4: Decoy comment in code → decoy_like_pattern flag."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {
            "code_context": 'API_KEY = "sk_live_abc123"  # not a real key, safe to commit',
        }
        result = g4.validate_with_details(llm_output, guardrail_context=ctx)
        assert "decoy_like_pattern" in result["inferred_flags"]

    def test_g4_apply_routing_backward_compat(self):
        """G4: apply_routing interface works with new rule-based logic."""
        g4 = G4Uncertainty()
        llm_output = {**_valid_secret()}
        ctx = {"schema_repaired": True}

        final_decision, metadata = g4.apply_routing(
            llm_output, "BLOCK", guardrail_context=ctx
        )
        assert final_decision == "REVIEW"
        assert metadata["routed_by_guardrail"] == "G4"
        assert metadata["triggered_rule"] == "R5_schema_repair"
        assert "format_or_schema_repair_used" in metadata["inferred_flags"]


# =========================================================================
# G5 Tests — new schema
# =========================================================================

class TestG5SchemaValidation:
    """Tests for G5 Schema Validation Guardrail (new 8-field schema)."""

    # --- Parse errors ---

    def test_g5_invalid_json(self):
        """G5.1: Invalid JSON should fail with PARSE_ERROR."""
        g5 = G5SchemaValidation()
        result = g5.validate("This is not JSON at all")

        assert result.is_valid is False
        assert ErrorCategory.PARSE_ERROR in result.error_categories
        assert result.parsed_output is None
        assert result.repair_attempted is False

    def test_g5_array_root_rejected(self):
        """G5: Array root type should fail with SCHEMA_VIOLATION."""
        g5 = G5SchemaValidation()
        result = g5.validate("[1, 2, 3]")

        assert result.is_valid is False
        assert ErrorCategory.SCHEMA_VIOLATION in result.error_categories

    # --- Missing required fields ---

    def test_g5_missing_required_field(self):
        """G5.2: Missing required fields should fail."""
        g5 = G5SchemaValidation()
        result = g5.validate(json.dumps({"pred_has_secret": True}))

        assert result.is_valid is False
        assert any("Missing required field" in e for e in result.errors)

    # --- Enum validation ---

    def test_g5_invalid_secret_type(self):
        """G5: Invalid pred_secret_type should fail."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["pred_secret_type"] = "invalid_type"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("pred_secret_type" in e for e in result.errors)

    def test_g5_invalid_evidence_mode(self):
        """G5: Invalid evidence_mode should fail."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["evidence_mode"] = "partial"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("evidence_mode" in e for e in result.errors)

    def test_g5_invalid_final_decision(self):
        """G5: Invalid final_decision should fail."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["final_decision"] = "DENY"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("final_decision" in e for e in result.errors)

    # --- Consistency: has_secret=true ---

    def test_g5_has_secret_true_type_none(self):
        """G5: pred_has_secret=true + pred_secret_type='none' is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["pred_secret_type"] = "none"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("CONSISTENCY_VIOLATION" in e for e in result.errors)

    def test_g5_has_secret_true_evidence_mode_none(self):
        """G5: pred_has_secret=true + evidence_mode='none' is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["evidence_mode"] = "none"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("CONSISTENCY_VIOLATION" in e and "evidence_mode" in e for e in result.errors)

    def test_g5_has_secret_true_empty_evidence(self):
        """G5: pred_has_secret=true + empty evidence_snippet is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["evidence_snippet"] = ""
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("evidence_snippet" in e for e in result.errors)

    def test_g5_has_secret_true_null_location(self):
        """G5: pred_has_secret=true + null locations is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["pred_location_start"] = None
        data["pred_location_end"] = None
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("pred_location_start" in e for e in result.errors)

    def test_g5_has_secret_true_decision_pass(self):
        """G5: pred_has_secret=true + final_decision='PASS' is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["final_decision"] = "PASS"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("CONSISTENCY_VIOLATION" in e and "PASS" in e for e in result.errors)

    # --- Consistency: has_secret=false ---

    def test_g5_has_secret_false_type_not_none(self):
        """G5: pred_has_secret=false + pred_secret_type!='none' is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["pred_secret_type"] = "api_key"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("CONSISTENCY_VIOLATION" in e for e in result.errors)

    def test_g5_has_secret_false_decision_block(self):
        """G5: pred_has_secret=false + final_decision='BLOCK' is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["final_decision"] = "BLOCK"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("CONSISTENCY_VIOLATION" in e for e in result.errors)

    def test_g5_has_secret_false_non_null_location(self):
        """G5: pred_has_secret=false + non-null location is inconsistent."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["pred_location_start"] = 3
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False

    # --- Verbatim rule ---

    def test_g5_verbatim_multiline_is_error(self):
        """G5: evidence_mode='verbatim' + start!=end is CONSISTENCY_VIOLATION."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["evidence_mode"] = "verbatim"
        data["pred_location_start"] = 3
        data["pred_location_end"] = 7
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("verbatim" in e for e in result.errors)

    # --- Additional properties ---

    def test_g5_unknown_fields_rejected(self):
        """G5: Unknown fields should be rejected."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["reasoning"] = "This should be rejected"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is False
        assert any("Unknown fields" in e for e in result.errors)

    def test_g5_confidence_field_accepted(self):
        """G5: 'confidence' is a valid optional field (used by G4)."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["confidence"] = "HIGH"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is True
        assert len(result.errors) == 0

    # --- Valid outputs ---

    def test_g5_valid_secret_passes(self):
        """G5: Valid secret output should pass."""
        g5 = G5SchemaValidation()
        result = g5.validate(json.dumps(_valid_secret()))

        assert result.is_valid is True
        assert len(result.errors) == 0
        assert result.schema_valid is True

    def test_g5_valid_no_secret_passes(self):
        """G5: Valid no-secret output should pass."""
        g5 = G5SchemaValidation()
        result = g5.validate(json.dumps(_valid_no_secret()))

        assert result.is_valid is True

    def test_g5_valid_with_optional_fields(self):
        """G5: Output with valid optional fields should pass."""
        g5 = G5SchemaValidation()
        data = _valid_secret()
        data["uncertainty_flags"] = ["ambiguous_pattern"]
        data["decision_basis"] = "code_plus_ambiguity"
        data["untrusted_input_role"] = "pr_body"
        data["untrusted_effect"] = "exculpatory_claim"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is True

    # --- Repair ---

    def test_g5_repair_string_booleans(self):
        """G5: String booleans should be repaired."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["pred_has_secret"] = "false"
        data["used_untrusted_input"] = "false"
        result = g5.validate(json.dumps(data))

        assert result.is_valid is True
        assert result.repair_attempted is True
        assert result.repair_succeeded is True
        assert ErrorCategory.REPAIR_SUCCESS in result.error_categories
        assert ErrorCategory.SCHEMA_VIOLATION in result.error_categories

    def test_g5_repair_preserves_original_categories(self):
        """G5: REPAIR_SUCCESS should preserve original error categories."""
        g5 = G5SchemaValidation()
        data = _valid_no_secret()
        data["pred_has_secret"] = "false"  # SCHEMA_VIOLATION → repaired
        result = g5.validate(json.dumps(data))

        assert result.is_valid is True
        assert ErrorCategory.SCHEMA_VIOLATION in result.error_categories
        assert ErrorCategory.REPAIR_SUCCESS in result.error_categories

    def test_g5_unrepairable_stays_invalid(self):
        """G5: Missing fields cannot be repaired."""
        g5 = G5SchemaValidation()
        result = g5.validate(json.dumps({"pred_has_secret": True}))

        assert result.is_valid is False
        assert result.repair_attempted is True
        assert result.repair_succeeded is False
        assert ErrorCategory.REPAIR_FAIL in result.error_categories

    # --- Code-fence extraction ---

    def test_g5_code_fence_extraction(self):
        """G5: JSON inside code fences should be extracted."""
        g5 = G5SchemaValidation()
        raw = "```json\n" + json.dumps(_valid_no_secret()) + "\n```"
        result = g5.validate(raw)

        assert result.is_valid is True

    # --- apply_routing ---

    def test_g5_routing_invalid_to_review(self):
        """G5: Invalid output should route to REVIEW."""
        g5 = G5SchemaValidation()
        result = g5.validate("not json")
        decision, meta = g5.apply_routing(result)

        assert decision == "REVIEW"
        assert meta["routed_by_guardrail"] == "G5"

    def test_g5_routing_valid_uses_parsed_decision(self):
        """G5: Valid output with no original_decision uses parsed final_decision."""
        g5 = G5SchemaValidation()
        result = g5.validate(json.dumps(_valid_secret()))
        decision, meta = g5.apply_routing(result, original_decision=None)

        assert decision == "BLOCK"

    def test_g5_routing_explicit_decision_takes_precedence(self):
        """G5: Explicit original_decision takes precedence over parsed."""
        g5 = G5SchemaValidation()
        result = g5.validate(json.dumps(_valid_secret()))
        decision, meta = g5.apply_routing(result, original_decision="REVIEW")

        assert decision == "REVIEW"


# =========================================================================
# Integration: apply_guardrails_with_routing with new schema
# =========================================================================

class TestApplyGuardrailsWithRouting:
    """Tests for the integrated G5 → G4 → G1 → G3 pipeline."""

    def test_g5_routing_on_invalid_json(self):
        """G5 should route invalid JSON to REVIEW."""
        settings = GuardrailSettings.full()
        result = apply_guardrails_with_routing("not valid json", settings=settings)

        assert result["final_decision"] == "REVIEW"
        assert result["routed_by_guardrail"] == "G5"
        assert result["schema_valid"] is False

    def test_valid_output_passes_through(self):
        """Valid output with new schema should pass through without routing."""
        settings = GuardrailSettings.full()
        raw = json.dumps(_valid_secret())
        result = apply_guardrails_with_routing(raw, settings=settings)

        assert result["schema_valid"] is True
        assert result["parsed_output"] is not None
        assert result["parsed_output"]["pred_has_secret"] is True
        assert result["final_decision"] == "BLOCK"

    def test_no_secret_valid_output(self):
        """Valid no-secret output should pass through."""
        settings = GuardrailSettings.full()
        raw = json.dumps(_valid_no_secret())
        result = apply_guardrails_with_routing(raw, settings=settings)

        assert result["schema_valid"] is True
        assert result["final_decision"] == "PASS"


# =========================================================================
# GuardrailSettings tests (unchanged)
# =========================================================================

class TestGuardrailSettings:
    """Tests for GuardrailSettings configuration."""

    def test_baseline_settings(self):
        settings = GuardrailSettings.baseline()
        assert settings.is_enabled("G1") is True
        assert settings.is_enabled("G2") is True
        assert settings.is_enabled("G3") is True
        assert settings.is_enabled("G4") is False
        assert settings.is_enabled("G5") is False

    def test_full_settings(self):
        settings = GuardrailSettings.full()
        for g in ("G1", "G2", "G3", "G4", "G5"):
            assert settings.is_enabled(g) is True

    def test_enable_g4_g5(self):
        settings = GuardrailSettings.baseline()
        settings.enable_g4_g5()
        assert settings.is_enabled("G4") is True
        assert settings.is_enabled("G5") is True


# =========================================================================
# Policy REVIEW handling (unchanged logic, updated fixtures)
# =========================================================================

class TestPolicyREVIEWHandling:
    """Tests for P1/P2/P3 REVIEW priority over llm_hit."""

    def test_p1_review_overrides_llm_hit(self):
        from policies.p1_safety_net import P1SafetyNet
        policy = P1SafetyNet()
        decision = policy.decide(scanner_hit=False, llm_hit=True, llm_decision="REVIEW")
        assert decision.value == "REVIEW"

    def test_p2_review_overrides_consensus(self):
        from policies.p2_consensus import P2Consensus
        policy = P2Consensus()
        decision = policy.decide(scanner_hit=True, llm_hit=True, llm_decision="REVIEW")
        assert decision.value == "REVIEW"

    def test_p3_review_overrides_llm_hit(self):
        from policies.p3_escalation import P3Escalation
        policy = P3Escalation()
        decision = policy.decide(
            scanner_hit=False, llm_hit=True, llm_decision="REVIEW",
            file_path="config/settings.py"
        )
        assert decision.value == "REVIEW"

    def test_p1_block_when_no_review(self):
        from policies.p1_safety_net import P1SafetyNet
        policy = P1SafetyNet()
        decision = policy.decide(scanner_hit=False, llm_hit=True, llm_decision="BLOCK")
        assert decision.value == "BLOCK"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
