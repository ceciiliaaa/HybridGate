"""
Tests for G4 (Uncertainty Routing) and G5 (Schema Validation) Guardrails

Test Cases:
- G4: confidence=LOW → REVIEW
- G5.1: Invalid JSON → REVIEW
- G5.2: Missing required field → REVIEW
- G5.3: Invalid confidence value → REVIEW
- G5.4: has_secret=true + empty evidence → REVIEW
- G5.5: has_secret=true + decision=PASS → REVIEW
- G5.6: has_secret=false + decision=BLOCK → REVIEW
- Compatibility: Valid output with HIGH confidence behaves normally

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


class TestG4Uncertainty:
    """Tests for G4 Uncertainty / Abstention Guardrail."""

    def test_g4_low_confidence_routes_to_review(self):
        """G4: confidence=LOW should route to REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {
            "reasoning": "Found a potential secret",
            "pred_has_secret": True,
            "pred_secret_type": "api_key",
            "pred_location_line": 5,
            "evidence_snippet": "API_KEY = 'sk_t***'",
            "confidence": "LOW"
        }

        assert g4.validate_output(llm_output) == True
        assert g4.should_route_to_review(llm_output) == True

        final_decision, metadata = g4.apply_routing(llm_output, "BLOCK")
        assert final_decision == "REVIEW"
        assert metadata["routed_by_guardrail"] == "G4"
        assert metadata["original_decision"] == "BLOCK"

    def test_g4_high_confidence_no_routing(self):
        """G4: confidence=HIGH should NOT route to REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {
            "confidence": "HIGH",
            "pred_has_secret": True
        }

        assert g4.should_route_to_review(llm_output) == False

        final_decision, metadata = g4.apply_routing(llm_output, "BLOCK")
        assert final_decision == "BLOCK"
        assert metadata["routed_by_guardrail"] is None

    def test_g4_medium_confidence_no_routing(self):
        """G4: confidence=MEDIUM should NOT route to REVIEW."""
        g4 = G4Uncertainty()
        llm_output = {"confidence": "MEDIUM"}

        assert g4.should_route_to_review(llm_output) == False

    def test_g4_confidence_case_insensitive(self):
        """G4: confidence values should be case-insensitive."""
        g4 = G4Uncertainty()

        assert g4.get_confidence({"confidence": "low"}) == "LOW"
        assert g4.get_confidence({"confidence": "Low"}) == "LOW"
        assert g4.get_confidence({"confidence": "HIGH"}) == "HIGH"


class TestG5SchemaValidation:
    """Tests for G5 Schema Validation Guardrail."""

    def test_g5_invalid_json(self):
        """G5.1: Invalid JSON should fail validation."""
        g5 = G5SchemaValidation()
        raw_response = "This is not JSON at all"

        result = g5.validate(raw_response)

        assert result.is_valid == False
        assert "not valid JSON" in result.errors[0]

    def test_g5_missing_required_field(self):
        """G5.2: Missing required field should fail validation."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "reasoning": "Some analysis",
            # Missing pred_has_secret
        })

        result = g5.validate(raw_response, include_confidence=False)

        assert result.is_valid == False
        assert any("pred_has_secret" in e for e in result.errors)

    def test_g5_invalid_confidence_value(self):
        """G5.3: Invalid confidence value should fail validation."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "pred_has_secret": False,
            "confidence": "VERY_HIGH"  # Invalid value
        })

        result = g5.validate(raw_response, include_confidence=True)

        assert result.is_valid == False
        assert any("confidence" in e.lower() for e in result.errors)

    def test_g5_has_secret_true_empty_evidence(self):
        """G5.4: has_secret=true with empty evidence should fail validation."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "pred_has_secret": True,
            "pred_secret_type": "api_key",
            "pred_location_line": None,  # Missing
            "evidence_snippet": "",  # Empty
            "confidence": "HIGH"
        })

        result = g5.validate(raw_response)

        assert result.is_valid == False
        assert any("evidence" in e.lower() or "location" in e.lower() for e in result.errors)

    def test_g5_has_secret_true_but_type_none(self):
        """G5.5: has_secret=true with secret_type='none' is inconsistent."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "pred_has_secret": True,
            "pred_secret_type": "none",  # Inconsistent
            "pred_location_line": 5,
            "evidence_snippet": "secret = '***'",
            "confidence": "HIGH"
        })

        result = g5.validate(raw_response)

        assert result.is_valid == False
        assert any("inconsistent" in e.lower() for e in result.errors)

    def test_g5_valid_output_passes(self):
        """G5: Valid output should pass validation."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "reasoning": "Found API key",
            "pred_has_secret": True,
            "pred_secret_type": "api_key",
            "pred_location_line": 10,
            "evidence_snippet": "API_KEY = 'sk_t***'",
            "confidence": "HIGH"
        })

        result = g5.validate(raw_response)

        assert result.is_valid == True
        assert len(result.errors) == 0

    def test_g5_no_secret_passes(self):
        """G5: No secret output with correct types should pass."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "reasoning": "No secrets found",
            "pred_has_secret": False,
            "pred_secret_type": "none",
            "pred_location_line": None,
            "evidence_snippet": "",
            "confidence": "HIGH"
        })

        result = g5.validate(raw_response)

        assert result.is_valid == True

    def test_g5_has_secret_true_decision_pass(self):
        """G5.5: has_secret=true with explicit decision=PASS is inconsistent."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "pred_has_secret": True,
            "pred_secret_type": "api_key",
            "pred_location_line": 5,
            "evidence_snippet": "key = '***'",
            "confidence": "HIGH",
            "decision": "PASS"  # Inconsistent with pred_has_secret=true
        })

        result = g5.validate(raw_response)

        assert result.is_valid == False
        assert any("inconsistent" in e.lower() and "pass" in e.lower() for e in result.errors)

    def test_g5_has_secret_false_decision_block(self):
        """G5.6: has_secret=false with explicit decision=BLOCK is inconsistent."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "pred_has_secret": False,
            "pred_secret_type": "none",
            "pred_location_line": None,
            "evidence_snippet": "",
            "confidence": "HIGH",
            "decision": "BLOCK"  # Inconsistent with pred_has_secret=false
        })

        result = g5.validate(raw_response)

        assert result.is_valid == False
        assert any("inconsistent" in e.lower() and "block" in e.lower() for e in result.errors)

    def test_g5_has_secret_false_with_type_generates_warning(self):
        """G5: has_secret=false with secret_type != 'none' should generate warning."""
        g5 = G5SchemaValidation()
        raw_response = json.dumps({
            "reasoning": "Looks like api_key format but it's a test value",
            "pred_has_secret": False,
            "pred_secret_type": "api_key",  # Unusual but not blocking
            "pred_location_line": None,
            "evidence_snippet": "",
            "confidence": "HIGH"
        })

        result = g5.validate(raw_response)

        # Should be valid (not an error) but have warning
        assert result.is_valid == True
        assert len(result.warnings) > 0
        assert any("unusual" in w.lower() for w in result.warnings)


class TestApplyGuardrailsWithRouting:
    """Tests for the integrated G5 -> G4 -> G3 pipeline."""

    def test_g5_routing_on_invalid_json(self):
        """G5 should route invalid JSON to REVIEW."""
        settings = GuardrailSettings.full()
        raw_response = "not valid json"

        result = apply_guardrails_with_routing(raw_response, settings=settings)

        assert result["final_decision"] == "REVIEW"
        assert result["routed_by_guardrail"] == "G5"
        assert result["schema_valid"] == False

    def test_g4_routing_on_low_confidence(self):
        """G4 should route LOW confidence to REVIEW."""
        settings = GuardrailSettings.full()
        raw_response = json.dumps({
            "reasoning": "Uncertain finding",
            "pred_has_secret": True,
            "pred_secret_type": "api_key",
            "pred_location_line": 5,
            "evidence_snippet": "key = 'abc***'",
            "confidence": "LOW"
        })

        result = apply_guardrails_with_routing(raw_response, settings=settings)

        assert result["final_decision"] == "REVIEW"
        assert result["routed_by_guardrail"] == "G4"
        assert result["confidence"] == "LOW"
        assert result["original_decision"] == "BLOCK"

    def test_no_routing_on_valid_high_confidence(self):
        """Valid output with HIGH confidence should pass through without routing."""
        settings = GuardrailSettings.full()
        raw_response = json.dumps({
            "reasoning": "Clear secret found",
            "pred_has_secret": True,
            "pred_secret_type": "api_key",
            "pred_location_line": 5,
            "evidence_snippet": "API_KEY = 'sk_t***'",
            "confidence": "HIGH"
        })

        result = apply_guardrails_with_routing(raw_response, settings=settings)

        assert result["final_decision"] == "BLOCK"
        assert result["routed_by_guardrail"] is None
        assert result["schema_valid"] == True
        assert result["confidence"] == "HIGH"

    def test_backward_compatibility_without_g4_g5(self):
        """With G4/G5 disabled, should behave like before."""
        settings = GuardrailSettings.baseline()  # Only G1, G2, G3
        raw_response = json.dumps({
            "reasoning": "Found secret",
            "pred_has_secret": True,
            "pred_secret_type": "api_key",
            "pred_location_line": 5,
            "evidence_snippet": "key = '***'"
            # No confidence field
        })

        result = apply_guardrails_with_routing(raw_response, settings=settings)

        # Should still work without confidence field
        assert result["schema_valid"] == True
        assert result["final_decision"] == "BLOCK"


class TestGuardrailSettings:
    """Tests for GuardrailSettings configuration."""

    def test_baseline_settings(self):
        """Baseline settings should have G1, G2, G3 enabled but not G4, G5."""
        settings = GuardrailSettings.baseline()

        assert settings.is_enabled("G1") == True
        assert settings.is_enabled("G2") == True
        assert settings.is_enabled("G3") == True
        assert settings.is_enabled("G4") == False
        assert settings.is_enabled("G5") == False

    def test_full_settings(self):
        """Full settings should have all guardrails enabled."""
        settings = GuardrailSettings.full()

        assert settings.is_enabled("G1") == True
        assert settings.is_enabled("G2") == True
        assert settings.is_enabled("G3") == True
        assert settings.is_enabled("G4") == True
        assert settings.is_enabled("G5") == True

    def test_enable_g4_g5(self):
        """enable_g4_g5() should add G4 and G5 to existing settings."""
        settings = GuardrailSettings.baseline()
        settings.enable_g4_g5()

        assert settings.is_enabled("G4") == True
        assert settings.is_enabled("G5") == True


class TestPolicyREVIEWHandling:
    """Tests for P1/P2/P3 REVIEW priority over llm_hit."""

    def test_p1_review_overrides_llm_hit(self):
        """P1: llm_decision=REVIEW should return REVIEW even if llm_hit=True."""
        from policies.p1_safety_net import P1SafetyNet

        policy = P1SafetyNet()
        # llm_hit=True but llm_decision=REVIEW (e.g., from G4 routing)
        decision = policy.decide(
            scanner_hit=False,
            llm_hit=True,
            llm_decision="REVIEW"
        )

        # REVIEW should take priority over BLOCK
        assert decision.value == "REVIEW"

    def test_p2_review_overrides_consensus(self):
        """P2: llm_decision=REVIEW should return REVIEW even if both detect."""
        from policies.p2_consensus import P2Consensus

        policy = P2Consensus()
        # Both hit but llm_decision=REVIEW
        decision = policy.decide(
            scanner_hit=True,
            llm_hit=True,
            llm_decision="REVIEW"
        )

        # REVIEW should take priority over BLOCK
        assert decision.value == "REVIEW"

    def test_p3_review_overrides_llm_hit(self):
        """P3: llm_decision=REVIEW should return REVIEW even if llm_hit=True."""
        from policies.p3_escalation import P3Escalation

        policy = P3Escalation()
        # llm_hit=True but llm_decision=REVIEW, on high-risk file
        decision = policy.decide(
            scanner_hit=False,
            llm_hit=True,
            llm_decision="REVIEW",
            file_path="config/settings.py"  # High-risk file triggers LLM
        )

        # REVIEW should take priority over BLOCK
        assert decision.value == "REVIEW"

    def test_p1_block_when_no_review(self):
        """P1: llm_hit=True with llm_decision=BLOCK should return BLOCK."""
        from policies.p1_safety_net import P1SafetyNet

        policy = P1SafetyNet()
        decision = policy.decide(
            scanner_hit=False,
            llm_hit=True,
            llm_decision="BLOCK"
        )

        assert decision.value == "BLOCK"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
