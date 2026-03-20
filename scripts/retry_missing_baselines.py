"""
Retry only the missing baseline evaluations from results_merged.json.

- Uses NO timeout on the OpenAI client
- Retries up to 10 times per sample (including for empty/unparseable responses)
- Patches results back into results_merged.json

Usage:
    python -m scripts.retry_missing_baselines

Author: auto-generated helper script (does NOT modify any project source files)
"""

import json
import logging
import os
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Import project components (no modifications)
# ---------------------------------------------------------------------------
from src.llm_evaluation.run_evaluation import (
    USER_PROMPT_TEMPLATE,
    number_lines,
    extract_json,
    BASELINE_PROMPT,
)
from src.policies import compute_all_policies

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MERGED_PATH = Path("runs/v130_baseline_fm_multitrigger/results_merged.json")
MAX_RETRIES = 10
RETRY_BASE_DELAY = 5.0  # seconds


def make_no_timeout_client():
    """Create an OpenAI client with NO timeout."""
    import openai
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise ValueError("OPENAI_API_KEY not set")
    client = openai.OpenAI(api_key=key, timeout=None)
    return client


def call_baseline(client, sample: dict) -> dict | None:
    """Call the baseline LLM for a single sample, with extended retries.

    Retries on BOTH API errors AND empty/unparseable responses.
    """
    system_prompt = BASELINE_PROMPT
    numbered_diff = number_lines(sample.get("code_context", ""))
    user_prompt = USER_PROMPT_TEMPLATE.format(
        pr_title=sample.get("pr_title", ""),
        pr_body=sample.get("pr_body", ""),
        code_context=numbered_diff,
    )

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"  Attempt {attempt}/{MAX_RETRIES} ...")
            response = client.chat.completions.create(
                model="gpt-5-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                max_completion_tokens=4096,  # doubled from normal
            )
            raw_response = response.choices[0].message.content

            # Check for empty response
            if not raw_response or not raw_response.strip():
                logger.warning(f"  Attempt {attempt}: empty response, retrying ...")
                time.sleep(RETRY_BASE_DELAY * (2 ** (attempt - 1)))
                continue

            # Try to parse
            prediction = extract_json(raw_response)
            if prediction is None:
                logger.warning(
                    f"  Attempt {attempt}: unparseable JSON "
                    f"({len(raw_response)} chars), retrying ..."
                )
                logger.debug(f"  Raw: {raw_response[:200]}")
                time.sleep(RETRY_BASE_DELAY)
                continue

            # Success!
            return {
                "pred_has_secret": bool(prediction.get("pred_has_secret", False)),
                "pred_secret_type": prediction.get("pred_secret_type", "none"),
                "evidence_mode": prediction.get("evidence_mode", "none"),
                "pred_location_start": prediction.get("pred_location_start"),
                "pred_location_end": prediction.get("pred_location_end"),
                "evidence_snippet": prediction.get("evidence_snippet", ""),
                "used_untrusted_input": bool(prediction.get("used_untrusted_input", False)),
                "final_decision": prediction.get("final_decision", "REVIEW"),
                "reasoning": prediction.get("reasoning", ""),
            }

        except Exception as e:
            delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
            logger.warning(f"  Attempt {attempt} API error: {e}. Retrying in {delay:.0f}s ...")
            if attempt < MAX_RETRIES:
                time.sleep(delay)

    logger.error(f"  All {MAX_RETRIES} attempts failed.")
    return None


def main():
    # Load merged results
    logger.info(f"Loading {MERGED_PATH} ...")
    with open(MERGED_PATH, "r", encoding="utf-8") as f:
        results = json.load(f)

    # Find samples with null baselines
    missing = [(i, s) for i, s in enumerate(results) if s.get("llm_baseline") is None]
    logger.info(f"Found {len(missing)} samples with missing baselines")

    if not missing:
        logger.info("Nothing to do!")
        return

    for idx, sample in missing:
        logger.info(f"  - [{sample['sample_id']}]")

    # Create no-timeout client
    client = make_no_timeout_client()
    logger.info("Created OpenAI client with NO timeout")

    # Retry each missing sample
    patched = 0
    for idx, sample in missing:
        sid = sample["sample_id"]
        logger.info(f"\n{'='*60}")
        logger.info(f"Retrying baseline for [{sid}] ...")

        baseline = call_baseline(client, sample)

        if baseline is None:
            logger.warning(f"[{sid}] Still failed after {MAX_RETRIES} attempts — leaving as null")
            continue

        logger.info(f"[{sid}] SUCCESS! decision={baseline['final_decision']}")

        # Update the result
        results[idx]["llm_baseline"] = baseline
        results[idx]["llm_baseline_hit"] = baseline.get("pred_has_secret", False)

        # Recompute policies for baseline
        scanner_hit = results[idx].get("scanner_hit", False)
        scanner_secret_type = results[idx].get("scanner_secret_type")
        bl_decision = baseline.get("final_decision", "REVIEW")
        bl_hit = baseline.get("pred_has_secret", False)
        secret_type = scanner_secret_type or baseline.get("pred_secret_type", "none")

        policy_baseline = compute_all_policies(
            scanner_hit=scanner_hit,
            llm_hit=bl_hit,
            llm_decision=bl_decision,
            secret_type=secret_type,
        )
        results[idx]["policy_p1_baseline"] = policy_baseline.get("policy_p1")
        results[idx]["policy_p2_baseline"] = policy_baseline.get("policy_p2")
        results[idx]["policy_p3_baseline"] = policy_baseline.get("policy_p3")

        # Recompute leak_in_baseline
        gt_secret = sample.get("gt_secret_value")
        if gt_secret and len(gt_secret) >= 6:
            baseline_text = json.dumps(baseline)
            results[idx]["leak_in_baseline"] = gt_secret in baseline_text
        else:
            results[idx]["leak_in_baseline"] = False

        patched += 1

    # Save back
    logger.info(f"\n{'='*60}")
    logger.info(f"Patched {patched}/{len(missing)} missing baselines")

    remaining_null = sum(1 for s in results if s.get("llm_baseline") is None)
    logger.info(f"Remaining baseline nulls: {remaining_null}")

    with open(MERGED_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved updated results to {MERGED_PATH}")


if __name__ == "__main__":
    main()
