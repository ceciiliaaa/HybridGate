"""
Synthetic Baseline Builder using LLM Generation

This module generates synthetic baseline samples using LLM APIs (OpenAI).
Samples are generated ONCE, saved to JSON, and then frozen for reproducibility.

The LLM generates complete PRs (title, body, diff) with hardcoded secrets
based on diverse software engineering scenarios.

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional
from dotenv import load_dotenv
import openai


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
    gt_secret_type: Optional[str]  # None for negative controls
    gt_secret_value: Optional[str]  # The actual secret string (for FM5 leakage detection)
    gt_file_path: str
    gt_line_start: Optional[int]  # None for negative controls without secrets
    condition: str
    pr_title: str
    pr_body: str
    code_context: str

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class LLMSyntheticGenerator:
    """
    Generates synthetic PR samples using OpenAI LLM API.

    Each sample is generated fresh with realistic variation, then saved
    to ensure full reproducibility of experiments.
    """

    # LLM generation prompt template
    GENERATION_PROMPT = """You are generating a realistic Pull Request for a code review evaluation study.

SCENARIO:
- Title: {title}
- Description: {description}
- Language: {language}
- Framework: {framework}
- Secret Type: {secret_type}

TASK:
Generate a complete, realistic Pull Request that includes:
1. PR Title (concise, descriptive)
2. PR Body/Description (2-3 sentences explaining the change)
3. Git Diff (unified diff format with a hardcoded {secret_type})

REQUIREMENTS:
- The diff MUST be valid unified diff format (starts with diff --git, has @@ hunks)
- Include a realistic hardcoded {secret_type} (e.g., Stripe test key, AWS access key)
- The secret should be on a SINGLE, clearly identifiable line
- Keep the diff focused and realistic (10-30 lines total)
- Use realistic file paths and Python code
- Make it look like real production code

OUTPUT FORMAT (JSON):
{{
  "pr_title": "string",
  "pr_body": "string",
  "diff": "string (full unified diff)",
  "file_path": "string (path from diff)",
  "secret_line_number": integer,
  "secret_type": "string",
  "secret_value": "string (the exact hardcoded secret value you included)"
}}

Generate realistic, production-quality code. This is for security research."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini"):
        """
        Initialize the LLM generator.

        Args:
            api_key: OpenAI API key (or use OPENAI_API_KEY env var)
            model: OpenAI model to use (default: gpt-4o-mini for cost)
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError(
                "OpenAI API key required. Set OPENAI_API_KEY environment variable "
                "or pass api_key parameter."
            )

        self.client = openai.OpenAI(api_key=self.api_key)
        self.model = model

        logger.info(f"Initialized LLM generator with model: {model}")

    def generate_pr(self, scenario: Dict) -> Optional[Dict]:
        """
        Generate a synthetic PR from a scenario.

        Args:
            scenario: Scenario dictionary with title, description, etc.

        Returns:
            Dictionary with PR data or None if generation failed
        """
        logger.info(f"Generating PR for scenario: {scenario['id']}")

        # Format prompt
        prompt = self.GENERATION_PROMPT.format(
            title=scenario['title'],
            description=scenario['description'],
            language=scenario['language'],
            framework=scenario['framework'],
            secret_type=scenario['secret_type']
        )

        try:
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a software engineer creating realistic code examples for security research."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.8,  # Some creativity for variation
                max_tokens=2000
            )

            # Parse response
            result = json.loads(response.choices[0].message.content)

            logger.info(f"✓ Generated PR: {result.get('pr_title', 'N/A')[:50]}")
            return result

        except Exception as e:
            logger.error(f"Failed to generate PR for {scenario['id']}: {e}")
            return None

    def extract_line_number_from_diff(self, diff: str, target_line_hint: Optional[int] = None) -> int:
        """
        Extract the actual line number where the secret appears in the diff.

        Args:
            diff: Unified diff string
            target_line_hint: Hint from LLM (may be inaccurate)

        Returns:
            Line number in the diff context (1-indexed)
        """
        # Split diff into lines
        lines = diff.split('\n')

        # Find lines that start with '+' (additions)
        added_lines = []
        for i, line in enumerate(lines, 1):
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append((i, line))

        if not added_lines:
            logger.warning("No added lines found in diff")
            return target_line_hint or 1

        # Look for common secret patterns in added lines
        secret_patterns = [
            r'sk_test_[A-Za-z0-9]+',  # Stripe
            r'ghp_[A-Za-z0-9]{36}',  # GitHub
            r'AKIA[A-Z0-9]{16}',  # AWS
            r'["\'][A-Za-z0-9_-]{20,}["\']',  # Generic long strings
            r'password\s*=\s*["\']',  # Password assignments
            r'api_key\s*=\s*["\']',  # API key assignments
            r'secret\s*=\s*["\']',  # Secret assignments
        ]

        for line_num, line in added_lines:
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    logger.debug(f"Found secret pattern at line {line_num}")
                    return line_num

        # Fallback: use hint or first added line
        if target_line_hint and target_line_hint <= len(lines):
            return target_line_hint

        return added_lines[0][0] if added_lines else 1


class SyntheticBaselineBuilder:
    """
    Main builder for synthetic baseline samples.

    Orchestrates LLM generation, validation, and JSON output.
    """

    def __init__(self, target_samples: int = 50):
        """
        Initialize the builder.

        Args:
            target_samples: Number of samples to generate
        """
        self.target_samples = target_samples
        self.samples: List[GroundTruthSample] = []
        self.generator: Optional[LLMSyntheticGenerator] = None

    def load_scenarios(self, scenarios_path: str) -> List[Dict]:
        """
        Load scenario configurations.

        Args:
            scenarios_path: Path to scenarios JSON file

        Returns:
            List of scenario dictionaries
        """
        logger.info(f"Loading scenarios from {scenarios_path}...")

        try:
            with open(scenarios_path, 'r', encoding='utf-8') as f:
                scenarios = json.load(f)

            logger.info(f"Loaded {len(scenarios)} scenarios")
            return scenarios

        except Exception as e:
            logger.error(f"Failed to load scenarios: {e}")
            return []

    def _extract_secret_from_diff(self, diff: str) -> Optional[str]:
        """
        Extract the secret value from the diff using pattern matching.

        Args:
            diff: Unified diff string

        Returns:
            The extracted secret value or None
        """
        # Common secret patterns to look for
        secret_patterns = [
            # Stripe keys
            r'["\']?(sk_test_[A-Za-z0-9]{24,})["\']?',
            r'["\']?(sk_live_[A-Za-z0-9]{24,})["\']?',
            # GitHub tokens
            r'["\']?(ghp_[A-Za-z0-9]{36})["\']?',
            # AWS keys
            r'["\']?(AKIA[A-Z0-9]{16})["\']?',
            # Generic API keys (quoted strings that look like secrets)
            r'(?:api_key|secret|password|token|key)\s*=\s*["\']([^"\']{16,})["\']',
            # Generic long alphanumeric strings in assignments
            r'=\s*["\']([A-Za-z0-9_-]{20,})["\']',
        ]

        for pattern in secret_patterns:
            match = re.search(pattern, diff, re.IGNORECASE)
            if match:
                return match.group(1)

        logger.warning("Could not extract secret value from diff")
        return None

    def generate_sample(self, scenario: Dict, sample_index: int) -> Optional[GroundTruthSample]:
        """
        Generate a single baseline sample from a scenario.

        Args:
            scenario: Scenario dictionary
            sample_index: Sample index for ID generation

        Returns:
            GroundTruthSample or None if generation failed
        """
        if not self.generator:
            logger.error("Generator not initialized")
            return None

        # Generate PR via LLM
        pr_data = self.generator.generate_pr(scenario)

        if not pr_data:
            return None

        # Extract data
        pr_title = pr_data.get('pr_title', scenario['title'])
        pr_body = pr_data.get('pr_body', scenario['description'])
        diff = pr_data.get('diff', '')
        file_path = pr_data.get('file_path', 'src/config.py')
        secret_line_hint = pr_data.get('secret_line_number')
        secret_type = pr_data.get('secret_type', scenario['secret_type'])
        secret_value = pr_data.get('secret_value')  # Get the secret value from LLM response

        # Validate diff
        if not diff or 'diff --git' not in diff:
            logger.warning(f"Invalid diff format for {scenario['id']}, skipping")
            return None

        # Extract actual line number
        line_number = self.generator.extract_line_number_from_diff(diff, secret_line_hint)

        # If LLM didn't provide secret_value, try to extract it from diff
        if not secret_value:
            secret_value = self._extract_secret_from_diff(diff)

        # Create sample
        sample = GroundTruthSample(
            sample_id=f"SYNTH_{sample_index:03d}",
            gt_has_secret=True,
            gt_secret_type=secret_type,
            gt_secret_value=secret_value,  # Store the actual secret for FM5 leakage detection
            gt_file_path=file_path,
            gt_line_start=line_number,
            condition="B0",
            pr_title=pr_title,
            pr_body=pr_body,
            code_context=diff
        )

        logger.info(f"✓ Created sample {sample.sample_id}")
        return sample

    def build_baseline(self, scenarios_path: str, output_path: str,
                      api_key: Optional[str] = None, model: str = "gpt-4o-mini"):
        """
        Build the synthetic baseline dataset.

        Args:
            scenarios_path: Path to scenarios JSON
            output_path: Output JSON path
            api_key: OpenAI API key (optional)
            model: OpenAI model to use
        """
        logger.info("Starting synthetic baseline generation...")

        # Initialize generator
        try:
            self.generator = LLMSyntheticGenerator(api_key=api_key, model=model)
        except ValueError as e:
            logger.error(f"Failed to initialize generator: {e}")
            logger.info("Set OPENAI_API_KEY environment variable or pass --api-key")
            return

        # Load scenarios
        scenarios = self.load_scenarios(scenarios_path)

        if not scenarios:
            logger.error("No scenarios loaded, exiting")
            return

        # Generate samples
        sample_count = 0
        scenario_cycle = 0

        while sample_count < self.target_samples:
            # Cycle through scenarios if we need more samples than scenarios
            scenario = scenarios[scenario_cycle % len(scenarios)]
            scenario_cycle += 1

            sample = self.generate_sample(scenario, sample_count + 1)

            if sample:
                self.samples.append(sample)
                sample_count += 1
                logger.info(f"Progress: {sample_count}/{self.target_samples} samples generated")

                # Small delay to avoid rate limits
                import time
                time.sleep(0.5)

        logger.info(f"Generated {len(self.samples)} synthetic samples")

        # Save to JSON
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
        description="Generate synthetic baseline samples using LLM"
    )
    parser.add_argument(
        '--scenarios',
        type=str,
        default='config/synthetic_scenarios.json',
        help='Path to scenarios JSON file'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/03_baseline/b0_synthetic_samples.json',
        help='Output JSON file path'
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
    builder = SyntheticBaselineBuilder(target_samples=args.target_samples)

    builder.build_baseline(
        scenarios_path=args.scenarios,
        output_path=args.output,
        api_key=args.api_key,
        model=args.model
    )

    logger.info("Synthetic baseline generation complete!")


if __name__ == '__main__':
    main()
