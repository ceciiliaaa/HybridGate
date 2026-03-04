"""
LLM-based Secret Injection for Real GitHub PRs

This module takes raw GitHub PR data and uses an LLM to inject realistic
hardcoded secrets into the actual diffs. This preserves the authentic
code context while ensuring a valid injection point.

Pipeline:
1. Load raw GitHub PRs (from github_pr_collector.py)
2. For each PR, send diff to LLM with injection prompt
3. LLM returns modified diff + secret location
4. Validate and save as baseline sample

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dotenv import load_dotenv
import openai
import random


# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class GroundTruthSample:
    """Ground truth schema for a baseline sample."""
    sample_id: str
    gt_has_secret: bool
    gt_secret_type: str
    gt_file_path: str
    gt_line_start: int
    condition: str
    pr_title: str
    pr_body: str
    code_context: str

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class SecretInjector:
    """
    Injects secrets into real GitHub PR diffs using LLM.

    The LLM analyzes the diff and finds a suitable location to inject
    a realistic hardcoded secret that fits the code context.
    """

    # Secret types to distribute evenly
    SECRET_TYPES = [
        'api_key',
        'token',
        'password',
        'private_key',
        'connection_string'
    ]

    # Example secrets by type (for the LLM to reference)
    SECRET_EXAMPLES = {
        'api_key': 'AKIAIOSFODNN7EXAMPLE or sk_live_abcd1234...',
        'token': 'ghp_xxxxxxxxxxxx or sk_test_4eC39HqLyjWDarjtT1zdp7dc',
        'password': 'MyS3cur3P@ssw0rd! or db_password_123',
        'private_key': '-----BEGIN RSA PRIVATE KEY----- ... or a base64 encoded key',
        'connection_string': 'postgresql://user:password@host:5432/db or mongodb://...'
    }

    INJECTION_PROMPT = """You are a security researcher creating test data for evaluating code review tools.

TASK: Inject a realistic hardcoded {secret_type} into this real git diff.

DIFF TO MODIFY:
```
{diff}
```

REQUIREMENTS:
1. Find a plausible location in the diff where a {secret_type} would realistically appear
2. Add a NEW line (starting with +) that contains a hardcoded {secret_type}
3. The secret should look realistic (example: {secret_example})
4. Keep the diff valid - preserve all existing lines and structure
5. The injection should make sense in the code context
6. If the diff is about config/settings/auth, inject there
7. If no good location exists, add a config-style assignment

OUTPUT FORMAT (JSON only, no other text):
{{
  "modified_diff": "the complete modified diff with injected secret",
  "injected_line_content": "the exact line you added (with the + prefix)",
  "line_number": the line number in the modified diff where the secret appears,
  "file_path": "the file path from the diff header",
  "secret_type": "{secret_type}",
  "success": true
}}

If you absolutely cannot inject a secret (e.g., diff is empty or binary), return:
{{
  "success": false,
  "reason": "explanation"
}}

Return ONLY valid JSON, no markdown or explanation."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini"):
        """
        Initialize the injector.

        Args:
            api_key: OpenAI API key (or use OPENAI_API_KEY env var)
            model: OpenAI model to use
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError(
                "OpenAI API key required. Set OPENAI_API_KEY environment variable "
                "or pass api_key parameter."
            )

        self.client = openai.OpenAI(api_key=self.api_key)
        self.model = model
        self.secret_type_index = 0  # For round-robin distribution

        logger.info(f"Initialized SecretInjector with model: {model}")

    def _get_next_secret_type(self) -> str:
        """Get next secret type in round-robin fashion for even distribution."""
        secret_type = self.SECRET_TYPES[self.secret_type_index % len(self.SECRET_TYPES)]
        self.secret_type_index += 1
        return secret_type

    def inject_secret(self, diff: str, secret_type: Optional[str] = None) -> Optional[Dict]:
        """
        Inject a secret into a diff using LLM.

        Args:
            diff: The original git diff
            secret_type: Type of secret to inject (or auto-select)

        Returns:
            Dictionary with injection result or None if failed
        """
        if not secret_type:
            secret_type = self._get_next_secret_type()

        secret_example = self.SECRET_EXAMPLES.get(secret_type, 'secret_value_123')

        # Truncate very long diffs to avoid token limits
        if len(diff) > 8000:
            diff = diff[:8000] + "\n... (truncated)"
            logger.warning("Diff truncated due to length")

        prompt = self.INJECTION_PROMPT.format(
            diff=diff,
            secret_type=secret_type,
            secret_example=secret_example
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security researcher. Output only valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.7,
                max_tokens=4000
            )

            result = json.loads(response.choices[0].message.content)

            if result.get('success', True):
                logger.info(f"✓ Injected {secret_type} successfully")
                return result
            else:
                logger.warning(f"Injection failed: {result.get('reason', 'unknown')}")
                return None

        except Exception as e:
            logger.error(f"LLM injection failed: {e}")
            return None

    def extract_file_path_from_diff(self, diff: str) -> str:
        """Extract primary file path from diff."""
        match = re.search(r'^\+\+\+ b/(.+)$', diff, re.MULTILINE)
        if match:
            return match.group(1)
        return "unknown_file.py"


class RealBaselineBuilder:
    """
    Builds baseline samples from real GitHub PRs with LLM-injected secrets.
    """

    def __init__(self, target_samples: int = 50):
        """
        Initialize the builder.

        Args:
            target_samples: Number of samples to generate
        """
        self.target_samples = target_samples
        self.samples: List[GroundTruthSample] = []
        self.injector: Optional[SecretInjector] = None

    def load_raw_prs(self, input_path: str) -> List[Dict]:
        """
        Load raw GitHub PR data.

        Args:
            input_path: Path to raw PRs JSON file

        Returns:
            List of PR dictionaries
        """
        logger.info(f"Loading raw PRs from {input_path}...")

        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                prs = json.load(f)

            logger.info(f"Loaded {len(prs)} raw PRs")
            return prs

        except Exception as e:
            logger.error(f"Failed to load PRs: {e}")
            return []

    def process_pr(self, pr_data: Dict, sample_index: int) -> Optional[GroundTruthSample]:
        """
        Process a single PR: inject secret and create sample.

        Args:
            pr_data: Raw PR data from GitHub
            sample_index: Sample index for ID

        Returns:
            GroundTruthSample or None if failed
        """
        if not self.injector:
            logger.error("Injector not initialized")
            return None

        diff = pr_data.get('diff', '')
        if not diff or len(diff) < 50:
            logger.warning("Skipping PR: diff too short or empty")
            return None

        # Inject secret
        result = self.injector.inject_secret(diff)

        if not result:
            return None

        # Extract data
        modified_diff = result.get('modified_diff', '')
        line_number = result.get('line_number', 1)
        file_path = result.get('file_path') or self.injector.extract_file_path_from_diff(modified_diff)
        secret_type = result.get('secret_type', 'token')

        # Validate modified diff
        if not modified_diff or 'diff --git' not in modified_diff:
            logger.warning("Invalid modified diff returned")
            return None

        # Create sample
        sample = GroundTruthSample(
            sample_id=f"REAL_{sample_index:03d}",
            gt_has_secret=True,
            gt_secret_type=secret_type,
            gt_file_path=file_path,
            gt_line_start=line_number,
            condition="B0",
            pr_title=pr_data.get('title', 'Unknown PR'),
            pr_body=pr_data.get('body', '') or 'No description provided.',
            code_context=modified_diff
        )

        logger.info(f"✓ Created sample {sample.sample_id} ({secret_type})")
        return sample

    def build_baseline(self, input_path: str, output_path: str,
                      api_key: Optional[str] = None, model: str = "gpt-4o-mini"):
        """
        Build baseline dataset from raw GitHub PRs.

        Args:
            input_path: Path to raw PRs JSON
            output_path: Output JSON path
            api_key: OpenAI API key
            model: OpenAI model
        """
        logger.info("Starting real baseline generation with LLM injection...")

        # Initialize injector
        try:
            self.injector = SecretInjector(api_key=api_key, model=model)
        except ValueError as e:
            logger.error(f"Failed to initialize injector: {e}")
            return

        # Load raw PRs
        raw_prs = self.load_raw_prs(input_path)

        if not raw_prs:
            logger.error("No raw PRs to process")
            return

        # Process PRs
        sample_count = 0
        pr_index = 0

        while sample_count < self.target_samples and pr_index < len(raw_prs) * 3:
            # Cycle through PRs if needed
            pr_data = raw_prs[pr_index % len(raw_prs)]
            pr_index += 1

            sample = self.process_pr(pr_data, sample_count + 1)

            if sample:
                self.samples.append(sample)
                sample_count += 1
                logger.info(f"Progress: {sample_count}/{self.target_samples}")

                # Rate limiting
                import time
                time.sleep(0.5)

        logger.info(f"Generated {len(self.samples)} real baseline samples")

        # Save
        self._save_to_json(output_path)

    def _save_to_json(self, output_path: str):
        """Save samples to JSON file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        samples_dict = [sample.to_dict() for sample in self.samples]

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(samples_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved {len(self.samples)} samples to {output_path}")

        # Log statistics
        from collections import Counter
        secret_types = Counter(s.gt_secret_type for s in self.samples)
        logger.info(f"Secret type distribution: {dict(secret_types)}")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Inject secrets into real GitHub PRs using LLM"
    )
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Path to raw GitHub PRs JSON (from github_pr_collector.py)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/03_baseline/b0_real_samples.json',
        help='Output baseline JSON file'
    )
    parser.add_argument(
        '--target-samples',
        type=int,
        default=50,
        help='Number of samples to generate (default: 50)'
    )
    parser.add_argument(
        '--api-key',
        type=str,
        help='OpenAI API key (or set OPENAI_API_KEY env var)'
    )
    parser.add_argument(
        '--model',
        type=str,
        default='gpt-4o-mini',
        help='OpenAI model to use (default: gpt-4o-mini)'
    )

    args = parser.parse_args()

    # Build baseline
    builder = RealBaselineBuilder(target_samples=args.target_samples)

    builder.build_baseline(
        input_path=args.input,
        output_path=args.output,
        api_key=args.api_key,
        model=args.model
    )

    logger.info("Real baseline generation complete!")


if __name__ == '__main__':
    main()
