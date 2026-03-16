"""
Hybrid Evaluation Pipeline for HybridGate Framework

Extends the base LLM evaluation with:
- Classic scanner integration (Gitleaks, detect-secrets)
- Guardrail-enhanced prompts (G1, G2, G3, G4, G5)
- Policy decision computation (P1, P2, P3)

Guardrail Order (after LLM call):
1. G5 (Schema Validation) - runs first, routes invalid to REVIEW
2. G4 (Uncertainty Routing) - runs on valid output, routes LOW confidence to REVIEW
3. G3 (Redaction Check) - runs last, checks for secret leakage

Scanner Selection Rationale:
- Gitleaks: Regex-based, high recall for common patterns
- detect-secrets: Plugin-based with entropy analysis, broadly applicable
  for generic hardcoded secrets (replaces TruffleHog which was too focused
  on verifiable/service-specific secrets)

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Import existing components
from .run_evaluation import (
    LLMClient, OpenAIClient, AnthropicClient,
    SYSTEM_PROMPT, USER_PROMPT_TEMPLATE,
    number_lines, extract_json, extract_secret_from_context,
    MAX_RETRIES, RETRY_BASE_DELAY
)

# Import new HybridGate components
from ..scanners import GitleaksScanner, DetectSecretsScanner, ScanResult
from ..guardrails import (
    get_guardrail_bundle, apply_guardrails, apply_guardrails_with_routing,
    GuardrailSettings, DEFAULT_SETTINGS
)
from ..policies import compute_all_policies


# ---------------------------------------------------------------------------
# Enhanced System Prompts
# ---------------------------------------------------------------------------

def get_baseline_prompt() -> str:
    """Get the baseline system prompt without guardrails."""
    return SYSTEM_PROMPT


def get_guardrail_prompt(settings: GuardrailSettings = None) -> str:
    """
    Get the system prompt with guardrails enabled.

    Args:
        settings: Guardrail settings (defaults to DEFAULT_SETTINGS)

    Returns:
        System prompt with enabled guardrails
    """
    if settings is None:
        settings = DEFAULT_SETTINGS

    base = SYSTEM_PROMPT
    guardrails = get_guardrail_bundle(settings)

    # The guardrail bundle (from G5's get_prompt) already contains the
    # full output schema definition.  No separate enhanced_schema needed.
    return f"{base}\n\n{guardrails}"


# ---------------------------------------------------------------------------
# Hybrid Evaluation Client
# ---------------------------------------------------------------------------

class HybridEvaluationClient:
    """
    Orchestrates the full hybrid evaluation pipeline.

    Combines:
    - Classic scanners (Gitleaks, detect-secrets)
    - LLM evaluation (baseline and guardrail modes)
    - Guardrail routing (G4, G5)
    - Policy decisions (P1, P2, P3)
    """

    def __init__(
        self,
        llm_client: LLMClient,
        run_scanners: bool = True,
        run_llm_baseline: bool = True,
        run_llm_guardrails: bool = True,
        guardrail_settings: GuardrailSettings = None
    ):
        self.llm_client = llm_client
        self.run_scanners = run_scanners
        self.run_llm_baseline = run_llm_baseline
        self.run_llm_guardrails = run_llm_guardrails

        # Guardrail settings (default: G1, G2, G3 enabled; G4, G5 disabled)
        # Use GuardrailSettings.full() to enable all including G4, G5
        self.guardrail_settings = guardrail_settings or DEFAULT_SETTINGS

        # Initialize scanners
        self.gitleaks = GitleaksScanner() if run_scanners else None
        self.detect_secrets = DetectSecretsScanner() if run_scanners else None

        # Check scanner availability
        if self.run_scanners:
            if self.gitleaks and self.gitleaks.is_available():
                logger.info(f"Gitleaks available: {self.gitleaks.get_version()}")
            else:
                logger.warning("Gitleaks not available")

            if self.detect_secrets and self.detect_secrets.is_available():
                logger.info(f"detect-secrets available: {self.detect_secrets.get_version()}")
            else:
                logger.warning("detect-secrets not available")

    def run_scanner_evaluation(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run classic scanners on a sample.

        Args:
            sample: Sample dictionary with code_context

        Returns:
            Dictionary with scanner results
        """
        results = {
            "gitleaks_hit": False,
            "gitleaks_secret_type": None,
            "gitleaks_location_line": None,
            "gitleaks_error": None,
            "detect_secrets_hit": False,
            "detect_secrets_secret_type": None,
            "detect_secrets_location_line": None,
            "detect_secrets_error": None,
            "scanner_hit": False
        }

        code_context = sample.get("code_context", "")
        file_path = sample.get("gt_file_path")

        # Gitleaks
        if self.gitleaks and self.gitleaks.is_available():
            try:
                gitleaks_result = self.gitleaks.scan(code_context, file_path)
                results["gitleaks_hit"] = gitleaks_result.scanner_hit
                results["gitleaks_secret_type"] = gitleaks_result.secret_type
                results["gitleaks_location_line"] = gitleaks_result.location_line
                results["gitleaks_error"] = gitleaks_result.error
            except Exception as e:
                results["gitleaks_error"] = str(e)
                logger.warning(f"Gitleaks error: {e}")

        # detect-secrets
        if self.detect_secrets and self.detect_secrets.is_available():
            try:
                detect_secrets_result = self.detect_secrets.scan(code_context, file_path)
                results["detect_secrets_hit"] = detect_secrets_result.scanner_hit
                results["detect_secrets_secret_type"] = detect_secrets_result.secret_type
                results["detect_secrets_location_line"] = detect_secrets_result.location_line
                results["detect_secrets_error"] = detect_secrets_result.error
            except Exception as e:
                results["detect_secrets_error"] = str(e)
                logger.warning(f"detect-secrets error: {e}")

        # Combined scanner hit
        results["scanner_hit"] = results["gitleaks_hit"] or results["detect_secrets_hit"]

        return results

    def run_llm_evaluation(
        self,
        sample: Dict[str, Any],
        use_guardrails: bool = False,
        scanner_hit: bool = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Run LLM evaluation on a sample.

        When use_guardrails=True and G4/G5 are enabled in settings:
        - G5 validates schema and routes invalid outputs to REVIEW
        - G4 rule-based uncertainty escalation (flags + context rules)

        Args:
            sample: Sample dictionary
            use_guardrails: Whether to use guardrail-enhanced prompt
            scanner_hit: Optional scanner result for G4 context

        Returns:
            Prediction dictionary with guardrail metadata, or None on total failure
        """
        if use_guardrails:
            system_prompt = get_guardrail_prompt(self.guardrail_settings)
        else:
            system_prompt = get_baseline_prompt()

        numbered_diff = number_lines(sample.get("code_context", ""))
        user_prompt = USER_PROMPT_TEMPLATE.format(
            pr_title=sample.get("pr_title", ""),
            pr_body=sample.get("pr_body", ""),
            code_context=numbered_diff,
        )

        raw_response: Optional[str] = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                raw_response = self.llm_client._call_api(system_prompt, user_prompt)
                break
            except Exception as e:
                delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.warning(
                    f"API call attempt {attempt}/{MAX_RETRIES} failed: {e}. "
                    f"Retrying in {delay:.1f}s ..."
                )
                if attempt < MAX_RETRIES:
                    time.sleep(delay)
                else:
                    logger.error(f"All {MAX_RETRIES} attempts failed")
                    return None

        if raw_response is None:
            return None

        # =====================================================================
        # Apply G5 and G4 guardrails when guardrail mode is active
        # =====================================================================
        if use_guardrails and (self.guardrail_settings.is_enabled("G4") or
                               self.guardrail_settings.is_enabled("G5")):
            # G5 -> G4 -> G3 order (G3 applied later in evaluate_sample)
            ground_truth = {"gt_secret_value": sample.get("gt_secret_value")}
            guardrail_result = apply_guardrails_with_routing(
                raw_response,
                ground_truth=ground_truth,
                settings=self.guardrail_settings,
                diff_context=numbered_diff,
                pr_title=sample.get("pr_title", ""),
                pr_body=sample.get("pr_body", ""),
                scanner_hit=scanner_hit,
                file_path=sample.get("gt_file_path", ""),
            )

            # If schema validation failed completely, return minimal result
            if guardrail_result["parsed_output"] is None:
                return {
                    "pred_has_secret": False,
                    "pred_secret_type": "none",
                    "evidence_mode": "none",
                    "pred_location_start": None,
                    "pred_location_end": None,
                    "evidence_snippet": "",
                    "used_untrusted_input": False,
                    # G4/G5 metadata fields
                    "confidence": None,
                    "schema_valid": False,
                    "validation_errors": guardrail_result["validation_errors"],
                    "error_categories": guardrail_result.get("error_categories", []),
                    "routed_by_guardrail": guardrail_result["routed_by_guardrail"],
                    "original_decision": None,
                    "final_decision": "REVIEW"
                }

            # Schema valid - extract fields from parsed output
            parsed = guardrail_result["parsed_output"]
            return {
                "pred_has_secret": bool(parsed.get("pred_has_secret", False)),
                "pred_secret_type": parsed.get("pred_secret_type", "none"),
                "evidence_mode": parsed.get("evidence_mode", "none"),
                "pred_location_start": parsed.get("pred_location_start"),
                "pred_location_end": parsed.get("pred_location_end"),
                "evidence_snippet": parsed.get("evidence_snippet", ""),
                "used_untrusted_input": bool(parsed.get("used_untrusted_input", False)),
                # G4/G5 metadata fields
                "confidence": guardrail_result["confidence"],
                "schema_valid": guardrail_result["schema_valid"],
                "validation_errors": guardrail_result["validation_errors"],
                "error_categories": guardrail_result.get("error_categories", []),
                "routed_by_guardrail": guardrail_result["routed_by_guardrail"],
                "original_decision": guardrail_result["original_decision"],
                "final_decision": guardrail_result["final_decision"],
                # G1/G2 validation fields
                "g1_valid": guardrail_result.get("g1_valid"),
                "g1_issues": guardrail_result.get("g1_issues", []),
                "g2_valid": guardrail_result.get("g2_valid"),
                "g2_issues": guardrail_result.get("g2_issues", []),
                "g4_valid": guardrail_result.get("g4_valid"),
                "g4_details": guardrail_result.get("g4_details"),
                "g5_valid": guardrail_result.get("g5_valid"),
                # Optional schema fields (pass through if present)
                "uncertainty_flags": parsed.get("uncertainty_flags"),
                "decision_basis": parsed.get("decision_basis"),
                "untrusted_input_role": parsed.get("untrusted_input_role"),
                "untrusted_effect": parsed.get("untrusted_effect"),
            }

        # =====================================================================
        # Standard parsing (baseline mode or G4/G5 disabled)
        # =====================================================================
        prediction = extract_json(raw_response)
        if prediction is None:
            logger.error(f"Failed to parse JSON from LLM response")
            return None

        return {
            "pred_has_secret": bool(prediction.get("pred_has_secret", False)),
            "pred_secret_type": prediction.get("pred_secret_type", "none"),
            "evidence_mode": prediction.get("evidence_mode", "none"),
            "pred_location_start": prediction.get("pred_location_start"),
            "pred_location_end": prediction.get("pred_location_end"),
            "evidence_snippet": prediction.get("evidence_snippet", ""),
            "used_untrusted_input": bool(prediction.get("used_untrusted_input", False)),
            # No G4/G5 metadata in baseline mode
            "confidence": prediction.get("confidence"),  # May be present if model outputs it
            "schema_valid": True,  # Assumed valid if parsed successfully
            "validation_errors": [],
            "routed_by_guardrail": None,
            "original_decision": None,
            "final_decision": prediction.get("final_decision"),
        }

    def evaluate_sample(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run full hybrid evaluation on a single sample.

        Args:
            sample: Sample dictionary

        Returns:
            Enriched result dictionary
        """
        result = {**sample}
        result["model_name"] = self.llm_client.get_model_name()

        # Stage 1: Scanner Evaluation
        if self.run_scanners:
            scanner_results = self.run_scanner_evaluation(sample)
            result.update(scanner_results)
        else:
            result["scanner_hit"] = False

        # Stage 2: LLM Baseline (without guardrails)
        if self.run_llm_baseline:
            llm_baseline = self.run_llm_evaluation(sample, use_guardrails=False)
            if llm_baseline:
                result["llm_baseline"] = llm_baseline
                result["llm_baseline_hit"] = llm_baseline.get("pred_has_secret", False)
            else:
                result["llm_baseline"] = None
                result["llm_baseline_hit"] = False

        # Stage 3: LLM with Guardrails
        if self.run_llm_guardrails:
            llm_guardrail = self.run_llm_evaluation(
                sample, use_guardrails=True,
                scanner_hit=result.get("scanner_hit"),
            )
            if llm_guardrail:
                result["llm_guardrail"] = llm_guardrail
                result["llm_guardrail_hit"] = llm_guardrail.get("pred_has_secret", False)

                # Apply post-processing guardrail validation
                guardrail_validation = apply_guardrails(
                    llm_guardrail,
                    {"gt_secret_value": sample.get("gt_secret_value")}
                )
                result["guardrail_validation"] = guardrail_validation
            else:
                result["llm_guardrail"] = None
                result["llm_guardrail_hit"] = False
                result["guardrail_validation"] = None

        # Stage 4: Policy Decisions
        # Compute policies separately for baseline and guardrail LLM runs
        scanner_hit = result.get("scanner_hit", False)
        file_path = sample.get("gt_file_path")
        code_diff = sample.get("code_context")

        # Helper to extract LLM decision and secret type
        # G4/G5: Use final_decision if available (after guardrail routing)
        def get_llm_decision_info(llm_result):
            if not llm_result:
                return "NOT_INVOKED", False, None
            has_secret = llm_result.get("pred_has_secret", False)

            # G4/G5: Check for guardrail-routed decision
            final_decision = llm_result.get("final_decision")
            if final_decision:
                # Use the guardrail-routed decision (PASS/BLOCK/REVIEW)
                decision = final_decision
            else:
                # Fallback: derive from pred_has_secret
                decision = "BLOCK" if has_secret else "PASS"

            secret_type = llm_result.get("pred_secret_type")
            return decision, has_secret, secret_type

        # Get scanner-detected secret type
        scanner_secret_type = None
        if scanner_hit:
            scanner_secret_type = result.get("gitleaks_secret_type") or result.get("detect_secrets_secret_type")

        # Baseline Policy Decisions
        if result.get("llm_baseline"):
            baseline_decision, baseline_hit, baseline_secret_type = get_llm_decision_info(result["llm_baseline"])
            secret_type_baseline = scanner_secret_type or baseline_secret_type

            policy_baseline = compute_all_policies(
                scanner_hit=scanner_hit,
                llm_hit=baseline_hit,
                llm_decision=baseline_decision,
                file_path=file_path,
                secret_type=secret_type_baseline,
                code_diff=code_diff
            )
            result["policy_p1_baseline"] = policy_baseline.get("policy_p1")
            result["policy_p2_baseline"] = policy_baseline.get("policy_p2")
            result["policy_p3_baseline"] = policy_baseline.get("policy_p3")
        else:
            result["policy_p1_baseline"] = None
            result["policy_p2_baseline"] = None
            result["policy_p3_baseline"] = None

        # Guardrail Policy Decisions
        if result.get("llm_guardrail"):
            guardrail_decision, guardrail_hit, guardrail_secret_type = get_llm_decision_info(result["llm_guardrail"])
            secret_type_guardrail = scanner_secret_type or guardrail_secret_type

            policy_guardrail = compute_all_policies(
                scanner_hit=scanner_hit,
                llm_hit=guardrail_hit,
                llm_decision=guardrail_decision,
                file_path=file_path,
                secret_type=secret_type_guardrail,
                code_diff=code_diff
            )
            result["policy_p1_guardrail"] = policy_guardrail.get("policy_p1")
            result["policy_p2_guardrail"] = policy_guardrail.get("policy_p2")
            result["policy_p3_guardrail"] = policy_guardrail.get("policy_p3")
        else:
            result["policy_p1_guardrail"] = None
            result["policy_p2_guardrail"] = None
            result["policy_p3_guardrail"] = None

        # Also store policy metadata (computed from P3)
        from ..policies.p3_escalation import compute_policy_tags
        result["policy_tags"] = compute_policy_tags(file_path, scanner_secret_type, code_diff)

        # Stage 5: Compute metrics
        result["metrics"] = self._compute_metrics(sample, result)

        return result

    def _compute_metrics(self, sample: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Compute evaluation metrics for a sample."""
        metrics = {}
        gt_has_secret = sample.get("gt_has_secret", False)
        gt_line = sample.get("gt_line_start")

        def _span_hit(llm_result: dict) -> bool:
            """Check if gt_line falls within predicted location span."""
            if not llm_result.get("pred_has_secret", False) or gt_line is None:
                return False
            start = llm_result.get("pred_location_start")
            end = llm_result.get("pred_location_end")
            if start is None or end is None:
                return False
            return int(start) <= int(gt_line) <= int(end)

        # Location hit for baseline
        if result.get("llm_baseline"):
            metrics["baseline_location_hit"] = _span_hit(result["llm_baseline"])

        # Location hit for guardrail
        if result.get("llm_guardrail"):
            metrics["guardrail_location_hit"] = _span_hit(result["llm_guardrail"])

        # Leak detection
        secret = sample.get("gt_secret_value") or extract_secret_from_context(sample)

        if secret and len(secret) >= 8:
            # Baseline leak
            if result.get("llm_baseline"):
                baseline_text = json.dumps(result["llm_baseline"])
                metrics["leak_in_baseline"] = secret in baseline_text

            # Guardrail leak
            if result.get("llm_guardrail"):
                guardrail_text = json.dumps(result["llm_guardrail"])
                metrics["leak_in_guardrail"] = secret in guardrail_text
        else:
            metrics["leak_in_baseline"] = False
            metrics["leak_in_guardrail"] = False

        return metrics


# ---------------------------------------------------------------------------
# Evaluation Runner
# ---------------------------------------------------------------------------

class HybridEvaluationRunner:
    """Orchestrates the full hybrid evaluation pipeline."""

    def __init__(
        self,
        client: HybridEvaluationClient,
        input_path: str,
        output_path: str,
        resume_mode: Optional[str] = None  # "auto", "fresh", or None (interactive)
    ):
        self.client = client
        self.input_path = input_path
        self.output_path = output_path
        self.resume_mode = resume_mode

        # Checkpoint file paths derived from output path
        out = Path(output_path)
        self.partial_path = out.with_suffix(".partial.jsonl")
        self.checkpoint_path = out.with_suffix(".checkpoint.json")

    def load_samples(self) -> List[Dict[str, Any]]:
        """Load experiment samples from JSON."""
        logger.info(f"Loading samples from {self.input_path} ...")
        with open(self.input_path, "r", encoding="utf-8") as f:
            samples = json.load(f)
        logger.info(f"Loaded {len(samples)} samples")
        return samples

    def _load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Load checkpoint if it exists and is valid."""
        if not self.checkpoint_path.exists() or not self.partial_path.exists():
            return None

        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                checkpoint = json.load(f)

            # Validate checkpoint has required fields
            if "completed_ids" not in checkpoint or "total" not in checkpoint:
                logger.warning("Checkpoint file is malformed, ignoring")
                return None

            return checkpoint
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not read checkpoint: {e}")
            return None

    def _load_partial_results(self) -> List[Dict[str, Any]]:
        """Load partial results from JSONL file."""
        results = []
        try:
            with open(self.partial_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning(f"Skipping malformed line {line_num} in partial results")
        except OSError as e:
            logger.warning(f"Could not read partial results: {e}")
        return results

    def _write_checkpoint(self, completed_ids: List[str], total: int) -> None:
        """Write checkpoint state to disk."""
        checkpoint = {
            "completed_ids": completed_ids,
            "completed_count": len(completed_ids),
            "total": total,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        with open(self.checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint, f, indent=2)

    def _append_partial_result(self, result: Dict[str, Any]) -> None:
        """Append a single result to the partial JSONL file."""
        with open(self.partial_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

    def _cleanup_checkpoint(self) -> None:
        """Remove checkpoint files after successful completion."""
        for path in [self.checkpoint_path, self.partial_path]:
            if path.exists():
                path.unlink()
                logger.info(f"Cleaned up {path.name}")

    def _resolve_resume(self, checkpoint: Dict[str, Any]) -> bool:
        """
        Decide whether to resume from checkpoint.

        Returns:
            True to resume, False to start fresh.
        """
        completed = checkpoint["completed_count"]
        total = checkpoint["total"]
        last_updated = checkpoint.get("last_updated", "unknown")

        if self.resume_mode == "auto":
            logger.info(f"Checkpoint found: {completed}/{total} completed (last: {last_updated}). Auto-resuming.")
            return True

        if self.resume_mode == "fresh":
            logger.info(f"Checkpoint found but --fresh specified. Starting from scratch.")
            return False

        # Interactive mode (default)
        print(f"\n{'='*60}")
        print(f"  CHECKPOINT FOUND")
        print(f"  Completed: {completed}/{total} samples")
        print(f"  Last updated: {last_updated}")
        print(f"  Input: {checkpoint.get('input_path', 'unknown')}")
        print(f"{'='*60}")
        while True:
            answer = input("  Resume from checkpoint? [y/n]: ").strip().lower()
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            print("  Please answer y or n.")

    def run(self) -> None:
        """Execute the full hybrid evaluation pipeline with checkpoint support."""
        samples = self.load_samples()
        total = len(samples)

        # --- Checkpoint handling ---
        results: List[Dict[str, Any]] = []
        completed_ids: set = set()
        start_fresh = True

        checkpoint = self._load_checkpoint()
        if checkpoint is not None:
            if self._resolve_resume(checkpoint):
                # Resume: load partial results and skip completed samples
                results = self._load_partial_results()
                completed_ids = set(checkpoint["completed_ids"])
                start_fresh = False
                logger.info(
                    f"Resuming from checkpoint: {len(completed_ids)}/{total} "
                    f"already completed, {total - len(completed_ids)} remaining"
                )
            else:
                # Fresh start: remove old checkpoint files
                self._cleanup_checkpoint()

        if start_fresh:
            # Ensure partial file starts empty
            if self.partial_path.exists():
                self.partial_path.unlink()
            logger.info(f"Starting hybrid evaluation on {total} samples (fresh)")

        # --- Main evaluation loop ---
        for i, sample in enumerate(samples, 1):
            sid = sample.get("sample_id", f"sample_{i}")

            # Skip already-completed samples
            if sid in completed_ids:
                continue

            condition = sample.get("condition", "B0")
            done = len(completed_ids)
            logger.info(f"[{done+1}/{total}] Evaluating [{sid}] (condition={condition}) ...")

            try:
                result = self.client.evaluate_sample(sample)
                results.append(result)
            except Exception as e:
                logger.error(f"Error evaluating {sid}: {e}")
                result = {**sample, "error": str(e)}
                results.append(result)

            # Incremental save: append result + update checkpoint
            self._append_partial_result(result)
            completed_ids.add(sid)
            self._write_checkpoint(list(completed_ids), total)

            # Rate limiting
            time.sleep(0.5)

        # --- Finalize ---
        self._save_results(results)
        self._cleanup_checkpoint()
        self._log_summary(results)

    def _save_results(self, results: List[Dict[str, Any]]) -> None:
        """Save enriched results to JSON."""
        out = Path(self.output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved {len(results)} results to {self.output_path}")

    @staticmethod
    def _log_summary(results: List[Dict[str, Any]]) -> None:
        """Log a summary of evaluation metrics with rates."""
        total = len(results)
        if total == 0:
            logger.info("No results to summarize.")
            return

        def rate(count: int, total: int) -> str:
            """Format count as 'X/N (P%)'."""
            pct = (count / total * 100) if total > 0 else 0.0
            return f"{count}/{total} ({pct:.1f}%)"

        # Scanner metrics
        scanner_hits = sum(1 for r in results if r.get("scanner_hit"))

        # LLM metrics
        baseline_hits = sum(1 for r in results if r.get("llm_baseline_hit"))
        guardrail_hits = sum(1 for r in results if r.get("llm_guardrail_hit"))

        # Policy decisions - Baseline
        p1_baseline_blocks = sum(1 for r in results if r.get("policy_p1_baseline") == "BLOCK")
        p2_baseline_blocks = sum(1 for r in results if r.get("policy_p2_baseline") == "BLOCK")
        p3_baseline_blocks = sum(1 for r in results if r.get("policy_p3_baseline") == "BLOCK")
        p1_baseline_reviews = sum(1 for r in results if r.get("policy_p1_baseline") == "REVIEW")
        p2_baseline_reviews = sum(1 for r in results if r.get("policy_p2_baseline") == "REVIEW")
        p3_baseline_reviews = sum(1 for r in results if r.get("policy_p3_baseline") == "REVIEW")

        # Policy decisions - Guardrail
        p1_guardrail_blocks = sum(1 for r in results if r.get("policy_p1_guardrail") == "BLOCK")
        p2_guardrail_blocks = sum(1 for r in results if r.get("policy_p2_guardrail") == "BLOCK")
        p3_guardrail_blocks = sum(1 for r in results if r.get("policy_p3_guardrail") == "BLOCK")
        p1_guardrail_reviews = sum(1 for r in results if r.get("policy_p1_guardrail") == "REVIEW")
        p2_guardrail_reviews = sum(1 for r in results if r.get("policy_p2_guardrail") == "REVIEW")
        p3_guardrail_reviews = sum(1 for r in results if r.get("policy_p3_guardrail") == "REVIEW")

        # Ground truth
        gt_secrets = sum(1 for r in results if r.get("gt_has_secret"))
        gt_no_secrets = total - gt_secrets

        # Compute TP/FP/TN/FN for scanner and LLM
        def compute_cm(results, hit_key, gt_key="gt_has_secret"):
            tp = sum(1 for r in results if r.get(gt_key) and r.get(hit_key))
            fn = sum(1 for r in results if r.get(gt_key) and not r.get(hit_key))
            fp = sum(1 for r in results if not r.get(gt_key) and r.get(hit_key))
            tn = sum(1 for r in results if not r.get(gt_key) and not r.get(hit_key))
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall}

        scanner_cm = compute_cm(results, "scanner_hit")
        baseline_cm = compute_cm(results, "llm_baseline_hit")
        guardrail_cm = compute_cm(results, "llm_guardrail_hit")

        logger.info("\n=== Hybrid Evaluation Summary ===")
        logger.info(f"Total samples:      {total}")
        logger.info(f"With secrets (GT):  {gt_secrets}")
        logger.info(f"No secrets (GT):    {gt_no_secrets}")
        logger.info("")
        logger.info("--- Detection Rates ---")
        logger.info(f"Scanner hits:       {rate(scanner_hits, total)}")
        logger.info(f"  Precision: {scanner_cm['precision']:.2%}  Recall: {scanner_cm['recall']:.2%}")
        logger.info(f"  TP={scanner_cm['tp']}  FP={scanner_cm['fp']}  TN={scanner_cm['tn']}  FN={scanner_cm['fn']}")
        logger.info(f"LLM baseline hits:  {rate(baseline_hits, total)}")
        logger.info(f"  Precision: {baseline_cm['precision']:.2%}  Recall: {baseline_cm['recall']:.2%}")
        logger.info(f"  TP={baseline_cm['tp']}  FP={baseline_cm['fp']}  TN={baseline_cm['tn']}  FN={baseline_cm['fn']}")
        logger.info(f"LLM guardrail hits: {rate(guardrail_hits, total)}")
        logger.info(f"  Precision: {guardrail_cm['precision']:.2%}  Recall: {guardrail_cm['recall']:.2%}")
        logger.info(f"  TP={guardrail_cm['tp']}  FP={guardrail_cm['fp']}  TN={guardrail_cm['tn']}  FN={guardrail_cm['fn']}")
        logger.info("")
        logger.info("--- Policy Decisions (Baseline LLM) ---")
        logger.info(f"P1 (Safety-Net) BLOCK:  {rate(p1_baseline_blocks, total)}  REVIEW: {rate(p1_baseline_reviews, total)}")
        logger.info(f"P2 (Consensus) BLOCK:   {rate(p2_baseline_blocks, total)}  REVIEW: {rate(p2_baseline_reviews, total)}")
        logger.info(f"P3 (Escalation) BLOCK:  {rate(p3_baseline_blocks, total)}  REVIEW: {rate(p3_baseline_reviews, total)}")
        logger.info("")
        logger.info("--- Policy Decisions (Guardrail LLM) ---")
        logger.info(f"P1 (Safety-Net) BLOCK:  {rate(p1_guardrail_blocks, total)}  REVIEW: {rate(p1_guardrail_reviews, total)}")
        logger.info(f"P2 (Consensus) BLOCK:   {rate(p2_guardrail_blocks, total)}  REVIEW: {rate(p2_guardrail_reviews, total)}")
        logger.info(f"P3 (Escalation) BLOCK:  {rate(p3_guardrail_blocks, total)}  REVIEW: {rate(p3_guardrail_reviews, total)}")

        # G4/G5 Metrics (if available)
        g4_g5_results = [r for r in results if r.get("llm_guardrail")]

        if g4_g5_results:
            g_total = len(g4_g5_results)

            # Schema validation (G5)
            schema_valid_count = sum(1 for r in g4_g5_results
                                     if r.get("llm_guardrail", {}).get("schema_valid", True))
            schema_fail_count = g_total - schema_valid_count

            # Confidence distribution (G4)
            conf_high = sum(1 for r in g4_g5_results
                          if r.get("llm_guardrail", {}).get("confidence") == "HIGH")
            conf_medium = sum(1 for r in g4_g5_results
                             if r.get("llm_guardrail", {}).get("confidence") == "MEDIUM")
            conf_low = sum(1 for r in g4_g5_results
                          if r.get("llm_guardrail", {}).get("confidence") == "LOW")

            # Guardrail routing
            routed_by_g4 = sum(1 for r in g4_g5_results
                              if r.get("llm_guardrail", {}).get("routed_by_guardrail") == "G4")
            routed_by_g5 = sum(1 for r in g4_g5_results
                              if r.get("llm_guardrail", {}).get("routed_by_guardrail") == "G5")

            logger.info("")
            logger.info("--- G4/G5 Guardrail Metrics ---")
            logger.info(f"Schema valid (G5):     {rate(schema_valid_count, g_total)}")
            logger.info(f"Schema fail (G5):      {rate(schema_fail_count, g_total)}")
            logger.info(f"Confidence HIGH:       {rate(conf_high, g_total)}")
            logger.info(f"Confidence MEDIUM:     {rate(conf_medium, g_total)}")
            logger.info(f"Confidence LOW:        {rate(conf_low, g_total)}")
            logger.info(f"Routed by G4:          {rate(routed_by_g4, g_total)}")
            logger.info(f"Routed by G5:          {rate(routed_by_g5, g_total)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hybrid evaluation pipeline for HybridGate framework"
    )
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        choices=["openai", "anthropic"],
        help="LLM provider to use",
    )
    parser.add_argument(
        "--input",
        type=str,
        default="data/03_baseline/b0_combined_samples.json",
        help="Path to input samples JSON",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path for output results JSON",
    )
    parser.add_argument(
        "--scanners",
        action="store_true",
        help="Run classic scanners (Gitleaks, detect-secrets)",
    )
    parser.add_argument(
        "--llm-baseline",
        action="store_true",
        help="Run LLM evaluation without guardrails",
    )
    parser.add_argument(
        "--llm-guardrails",
        action="store_true",
        help="Run LLM evaluation with guardrails",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all evaluations (scanners + baseline + guardrails)",
    )
    parser.add_argument(
        "--enable-g4-g5",
        action="store_true",
        help="Enable G4 (uncertainty routing) and G5 (schema validation) guardrails",
    )
    resume_group = parser.add_mutually_exclusive_group()
    resume_group.add_argument(
        "--resume",
        action="store_true",
        help="Automatically resume from checkpoint if available (no prompt)",
    )
    resume_group.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore any existing checkpoint and start from scratch",
    )

    args = parser.parse_args()

    # Determine what to run
    run_scanners = args.scanners or args.all
    run_baseline = args.llm_baseline or args.all
    run_guardrails = args.llm_guardrails or args.all

    # Default: run everything if nothing specified
    if not (run_scanners or run_baseline or run_guardrails):
        run_scanners = True
        run_baseline = True
        run_guardrails = True

    # Guardrail settings
    # Default: G1, G2, G3 only (backward compatible)
    # With --enable-g4-g5: All guardrails including G4, G5
    if args.enable_g4_g5:
        guardrail_settings = GuardrailSettings.full()
        logger.info("G4/G5 guardrails ENABLED (full mode)")
    else:
        guardrail_settings = GuardrailSettings.baseline()
        logger.info("G4/G5 guardrails DISABLED (baseline mode)")

    # Build LLM client
    if args.model == "openai":
        llm_client = OpenAIClient()
    else:
        llm_client = AnthropicClient()

    # Build hybrid client
    hybrid_client = HybridEvaluationClient(
        llm_client=llm_client,
        run_scanners=run_scanners,
        run_llm_baseline=run_baseline,
        run_llm_guardrails=run_guardrails,
        guardrail_settings=guardrail_settings
    )

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        model_slug = llm_client.get_model_name().replace(".", "-")
        output_path = f"data/05_results/hybrid_eval_{model_slug}.json"

    # Checkpoint/resume mode
    if args.resume:
        resume_mode = "auto"
    elif args.fresh:
        resume_mode = "fresh"
    else:
        resume_mode = None  # Interactive prompt

    # Run evaluation
    runner = HybridEvaluationRunner(
        client=hybrid_client,
        input_path=args.input,
        output_path=output_path,
        resume_mode=resume_mode
    )
    runner.run()
    logger.info("Hybrid evaluation complete!")


if __name__ == "__main__":
    main()
