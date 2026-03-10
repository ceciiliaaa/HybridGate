"""
Scanner-Only Update Script

Updates existing evaluation results with new scanner results
without re-running the LLM API calls.

Scanners:
- Gitleaks: Regex-based pattern matching
- detect-secrets: Plugin-based with entropy analysis
"""

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

from ..scanners import GitleaksScanner, DetectSecretsScanner
from ..policies import compute_all_policies
from ..policies.p3_escalation import compute_policy_tags


def update_scanner_results(input_path: str, output_path: str) -> None:
    """
    Re-run scanners on all samples and update the results.

    Args:
        input_path: Path to existing evaluation results JSON
        output_path: Path for updated results
    """
    # Load existing results
    logger.info(f"Loading existing results from {input_path}")
    with open(input_path, "r", encoding="utf-8") as f:
        results = json.load(f)

    # Initialize scanners
    gitleaks = GitleaksScanner()
    detect_secrets = DetectSecretsScanner()

    if gitleaks.is_available():
        logger.info(f"Gitleaks available: {gitleaks.get_version()}")
    else:
        logger.warning("Gitleaks NOT available!")

    if detect_secrets.is_available():
        logger.info(f"detect-secrets available: {detect_secrets.get_version()}")
    else:
        logger.warning("detect-secrets NOT available!")

    # Process each sample
    total = len(results)
    updated = 0

    for i, result in enumerate(results, 1):
        sid = result.get("sample_id", f"sample_{i}")
        code_context = result.get("code_context", "")
        file_path = result.get("gt_file_path")

        logger.info(f"Scanning {i}/{total} [{sid}] ...")

        # Run Gitleaks
        old_gitleaks = result.get("gitleaks_hit", False)
        try:
            gl_result = gitleaks.scan(code_context, file_path)
            result["gitleaks_hit"] = gl_result.scanner_hit
            result["gitleaks_secret_type"] = gl_result.secret_type
            result["gitleaks_location_line"] = gl_result.location_line
            result["gitleaks_error"] = gl_result.error
            if gl_result.scanner_hit != old_gitleaks:
                logger.info(f"  Gitleaks: {old_gitleaks} -> {gl_result.scanner_hit}")
                updated += 1
        except Exception as e:
            result["gitleaks_error"] = str(e)
            logger.warning(f"  Gitleaks error: {e}")

        # Run detect-secrets
        old_detect_secrets = result.get("detect_secrets_hit", False)
        try:
            ds_result = detect_secrets.scan(code_context, file_path)
            result["detect_secrets_hit"] = ds_result.scanner_hit
            result["detect_secrets_secret_type"] = ds_result.secret_type
            result["detect_secrets_location_line"] = ds_result.location_line
            result["detect_secrets_error"] = ds_result.error
            if ds_result.scanner_hit != old_detect_secrets:
                logger.info(f"  detect-secrets: {old_detect_secrets} -> {ds_result.scanner_hit}")
        except Exception as e:
            result["detect_secrets_error"] = str(e)
            logger.warning(f"  detect-secrets error: {e}")

        # Remove old trufflehog fields if present
        for key in ["trufflehog_hit", "trufflehog_secret_type", "trufflehog_location_line", "trufflehog_error"]:
            result.pop(key, None)

        # Update combined scanner hit
        result["scanner_hit"] = result.get("gitleaks_hit", False) or result.get("detect_secrets_hit", False)

        # Re-compute policy decisions with updated scanner results
        scanner_hit = result["scanner_hit"]
        scanner_secret_type = result.get("gitleaks_secret_type") or result.get("detect_secrets_secret_type")

        # Update baseline policies
        if result.get("llm_baseline"):
            baseline = result["llm_baseline"]
            baseline_hit = baseline.get("pred_has_secret", False)
            baseline_decision = "BLOCK" if baseline_hit else "PASS"
            secret_type = scanner_secret_type or baseline.get("pred_secret_type")

            policy = compute_all_policies(
                scanner_hit=scanner_hit,
                llm_hit=baseline_hit,
                llm_decision=baseline_decision,
                file_path=file_path,
                secret_type=secret_type,
                code_diff=code_context
            )
            result["policy_p1_baseline"] = policy.get("policy_p1")
            result["policy_p2_baseline"] = policy.get("policy_p2")
            result["policy_p3_baseline"] = policy.get("policy_p3")

        # Update guardrail policies
        if result.get("llm_guardrail"):
            guardrail = result["llm_guardrail"]
            guardrail_hit = guardrail.get("pred_has_secret", False)
            guardrail_decision = "BLOCK" if guardrail_hit else "PASS"
            secret_type = scanner_secret_type or guardrail.get("pred_secret_type")

            policy = compute_all_policies(
                scanner_hit=scanner_hit,
                llm_hit=guardrail_hit,
                llm_decision=guardrail_decision,
                file_path=file_path,
                secret_type=secret_type,
                code_diff=code_context
            )
            result["policy_p1_guardrail"] = policy.get("policy_p1")
            result["policy_p2_guardrail"] = policy.get("policy_p2")
            result["policy_p3_guardrail"] = policy.get("policy_p3")

        # Update policy tags
        result["policy_tags"] = compute_policy_tags(file_path, scanner_secret_type, code_context)

    # Save updated results
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    logger.info(f"Updated {updated} scanner results")
    logger.info(f"Saved to {output_path}")

    # Summary
    scanner_hits = sum(1 for r in results if r.get("scanner_hit"))
    gitleaks_hits = sum(1 for r in results if r.get("gitleaks_hit"))
    detect_secrets_hits = sum(1 for r in results if r.get("detect_secrets_hit"))

    logger.info("\n=== Scanner Summary ===")
    logger.info(f"Total samples:        {total}")
    logger.info(f"Gitleaks hits:        {gitleaks_hits}/{total}")
    logger.info(f"detect-secrets hits:  {detect_secrets_hits}/{total}")
    logger.info(f"Combined hits:        {scanner_hits}/{total}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Update scanner results without LLM API calls")
    parser.add_argument("--input", type=str, required=True, help="Existing evaluation results")
    parser.add_argument("--output", type=str, required=True, help="Output path for updated results")

    args = parser.parse_args()
    update_scanner_results(args.input, args.output)
