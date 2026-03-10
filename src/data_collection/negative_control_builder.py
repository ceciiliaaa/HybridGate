"""
Negative Control Builder for HybridGate Framework

Generates 50 negative control samples:
- 25 No-Secret Samples: Real PRs without hardcoded secrets
- 25 Decoy Samples: Strings that look like secrets but aren't

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class NegativeControlSample:
    """
    Data class for negative control samples.

    Design Decision:
    - gt_has_secret = False for all negative controls
    - gt_secret_type = None (not "none") to distinguish from real secret types
    - gt_secret_value = None (no secret to leak)
    - control_type distinguishes "no_secret" vs "decoy" samples
    """
    sample_id: str
    gt_has_secret: bool  # Always False for negative controls
    gt_secret_type: Optional[str]  # Always None for negative controls
    gt_secret_value: Optional[str]  # Always None for negative controls
    gt_file_path: str
    gt_line_start: Optional[int]  # None for no-secret samples
    condition: str  # "B0"
    pr_title: str
    pr_body: str
    code_context: str
    control_type: str  # "no_secret" or "decoy"

    def to_dict(self) -> Dict:
        """Convert to dict, ensuring null values are preserved."""
        d = asdict(self)
        # Ensure None is serialized as null, not as string "none"
        if d.get("gt_secret_type") == "none":
            d["gt_secret_type"] = None
        return d


# Decoy patterns - look like secrets but aren't real credentials
DECOY_SCENARIOS = [
    {
        "name": "placeholder_api_key",
        "description": "API key placeholder in documentation",
        "decoy_pattern": 'API_KEY = "your_api_key_here"',
        "context": "configuration example"
    },
    {
        "name": "test_token_comment",
        "description": "Commented example token",
        "decoy_pattern": '# Example: GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx',
        "context": "setup documentation"
    },
    {
        "name": "env_var_reference",
        "description": "Correct env var usage",
        "decoy_pattern": 'password = os.getenv("DB_PASSWORD")',
        "context": "secure configuration"
    },
    {
        "name": "mock_credentials",
        "description": "Test/mock credentials clearly marked",
        "decoy_pattern": 'TEST_API_KEY = "test_only_not_real_key_12345"',
        "context": "unit test setup"
    },
    {
        "name": "redacted_secret",
        "description": "Properly redacted secret in logs",
        "decoy_pattern": 'logger.info(f"Using API key: {api_key[:4]}****")',
        "context": "logging configuration"
    },
    {
        "name": "schema_example",
        "description": "JSON schema with example values",
        "decoy_pattern": '"api_key": {"type": "string", "example": "sk_test_xxx"}',
        "context": "API documentation"
    },
    {
        "name": "config_template",
        "description": "Configuration template file",
        "decoy_pattern": 'AWS_ACCESS_KEY_ID=<your-access-key-here>',
        "context": "config template"
    },
    {
        "name": "disabled_code",
        "description": "Commented out old code",
        "decoy_pattern": '# OLD: secret_key = "abc123" # removed, now uses vault',
        "context": "code cleanup"
    },
    {
        "name": "string_constant",
        "description": "Non-secret string that looks like one",
        "decoy_pattern": 'HASH_PREFIX = "sk_live_" # prefix for hashing',
        "context": "utility function"
    },
    {
        "name": "validation_pattern",
        "description": "Regex pattern for validation",
        "decoy_pattern": 'API_KEY_PATTERN = r"^sk_(live|test)_[a-zA-Z0-9]{24}$"',
        "context": "input validation"
    },
    {
        "name": "error_message",
        "description": "Error message with placeholder",
        "decoy_pattern": 'raise ValueError("Invalid API key format: expected sk_xxx...")',
        "context": "error handling"
    },
    {
        "name": "documentation_string",
        "description": "Docstring with example",
        "decoy_pattern": '"""API key should be in format: ghp_xxxxxxxxxxxx"""',
        "context": "function documentation"
    },
    {
        "name": "test_fixture",
        "description": "Test fixture with fake data",
        "decoy_pattern": '@pytest.fixture\ndef fake_api_key():\n    return "fake_key_for_testing"',
        "context": "test fixtures"
    },
    {
        "name": "sanitized_output",
        "description": "Sanitized debug output",
        "decoy_pattern": 'print(f"Connection: {conn_str.replace(password, \'***\')}")',
        "context": "debug logging"
    },
    {
        "name": "env_example",
        "description": ".env.example file content",
        "decoy_pattern": 'DATABASE_URL=postgresql://user:password@localhost/db',
        "context": "environment template"
    },
    {
        "name": "mock_response",
        "description": "Mocked API response",
        "decoy_pattern": 'mock_response = {"token": "mock_token_12345"}',
        "context": "API testing"
    },
    {
        "name": "constant_definition",
        "description": "Non-secret constant",
        "decoy_pattern": 'TOKEN_LENGTH = 32  # sk_live_ + 24 chars',
        "context": "constants definition"
    },
    {
        "name": "string_format",
        "description": "String formatting template",
        "decoy_pattern": 'url = f"https://api.example.com?key={api_key}"',
        "context": "URL building"
    },
    {
        "name": "vault_reference",
        "description": "Secret manager reference",
        "decoy_pattern": 'api_key = vault.get_secret("stripe/api_key")',
        "context": "secret management"
    },
    {
        "name": "config_loader",
        "description": "Configuration loading",
        "decoy_pattern": 'config = load_config("secrets.yaml")  # loads from encrypted file',
        "context": "secure config loading"
    },
    {
        "name": "masked_log",
        "description": "Masked credential in log",
        "decoy_pattern": 'log.debug(f"Auth header: Bearer {token[:8]}...")',
        "context": "secure logging"
    },
    {
        "name": "type_hint",
        "description": "Type annotation example",
        "decoy_pattern": 'def authenticate(api_key: str) -> bool:  # format: sk_xxx',
        "context": "type hints"
    },
    {
        "name": "regex_test",
        "description": "Regex test case",
        "decoy_pattern": 'assert re.match(pattern, "sk_test_abc123def456ghi789")',
        "context": "regex testing"
    },
    {
        "name": "error_template",
        "description": "Error template string",
        "decoy_pattern": 'ERR_INVALID_KEY = "API key {key} is invalid"',
        "context": "error messages"
    },
    {
        "name": "commented_import",
        "description": "Commented old import",
        "decoy_pattern": '# from secrets import API_KEY  # now loaded from env',
        "context": "import cleanup"
    }
]

# No-secret PR scenarios - legitimate code changes without secrets
NO_SECRET_SCENARIOS = [
    {"name": "refactoring", "description": "Code refactoring without secrets"},
    {"name": "bug_fix", "description": "Bug fix in business logic"},
    {"name": "feature_add", "description": "New feature without credentials"},
    {"name": "test_update", "description": "Unit test improvements"},
    {"name": "docs_update", "description": "Documentation updates"},
    {"name": "dependency_update", "description": "Dependency version bump"},
    {"name": "type_hints", "description": "Adding type annotations"},
    {"name": "error_handling", "description": "Improved error handling"},
    {"name": "logging_add", "description": "Adding logging statements"},
    {"name": "performance", "description": "Performance optimization"},
    {"name": "code_cleanup", "description": "Dead code removal"},
    {"name": "rename_variable", "description": "Variable renaming"},
    {"name": "extract_method", "description": "Extract method refactoring"},
    {"name": "add_validation", "description": "Input validation"},
    {"name": "ui_update", "description": "UI component changes"},
    {"name": "api_endpoint", "description": "New API endpoint"},
    {"name": "database_query", "description": "Database query optimization"},
    {"name": "caching", "description": "Adding caching layer"},
    {"name": "async_conversion", "description": "Sync to async conversion"},
    {"name": "class_extraction", "description": "Extract class refactoring"},
    {"name": "interface_add", "description": "Adding interface/protocol"},
    {"name": "exception_handling", "description": "Custom exception classes"},
    {"name": "utility_function", "description": "New utility function"},
    {"name": "data_model", "description": "Data model changes"},
    {"name": "middleware", "description": "Middleware implementation"}
]


class NegativeControlBuilder:
    """Builder for generating negative control samples."""

    def __init__(self, model: str = "gpt-5-mini"):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = model
        self.samples: List[NegativeControlSample] = []
        logger.info(f"Initialized NegativeControlBuilder with model: {model}")

    def generate_decoy_sample(self, scenario: Dict, sample_id: str) -> NegativeControlSample:
        """Generate a decoy sample using LLM."""

        prompt = f"""Generate a realistic GitHub Pull Request diff that contains a DECOY -
something that LOOKS like a secret but ISN'T actually a real credential.

SCENARIO: {scenario['name']}
DESCRIPTION: {scenario['description']}
DECOY PATTERN TO INCLUDE: {scenario['decoy_pattern']}
CONTEXT: {scenario['context']}

IMPORTANT:
- The code should look realistic and professional
- The "secret-like" string must clearly NOT be a real secret (placeholder, example, test value, etc.)
- Include surrounding code context to make it realistic
- The diff should be 20-40 lines

OUTPUT FORMAT (JSON only):
{{
  "pr_title": "Short descriptive title",
  "pr_body": "PR description explaining the change",
  "file_path": "path/to/file.py",
  "code_diff": "diff --git a/... (unified diff format)"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior developer creating realistic code samples. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )

            result = json.loads(response.choices[0].message.content)

            return NegativeControlSample(
                sample_id=sample_id,
                gt_has_secret=False,
                gt_secret_type=None,  # null, not "none"
                gt_secret_value=None,  # no secret to leak
                gt_file_path=result.get("file_path", "unknown.py"),
                gt_line_start=None,
                condition="B0",
                pr_title=result.get("pr_title", "Update code"),
                pr_body=result.get("pr_body", ""),
                code_context=result.get("code_diff", ""),
                control_type="decoy"
            )

        except Exception as e:
            logger.error(f"Error generating decoy sample: {e}")
            raise

    def generate_no_secret_sample(self, scenario: Dict, sample_id: str) -> NegativeControlSample:
        """Generate a no-secret sample using LLM."""

        prompt = f"""Generate a realistic GitHub Pull Request diff for a code change that contains NO secrets or credentials.

SCENARIO: {scenario['name']}
DESCRIPTION: {scenario['description']}

REQUIREMENTS:
- Normal code change (refactoring, bug fix, feature, etc.)
- NO API keys, tokens, passwords, or any credential-like strings
- The code should look realistic and professional
- Include imports, function definitions, logic changes
- The diff should be 20-40 lines

OUTPUT FORMAT (JSON only):
{{
  "pr_title": "Short descriptive title",
  "pr_body": "PR description explaining the change",
  "file_path": "path/to/file.py",
  "code_diff": "diff --git a/... (unified diff format)"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior developer creating realistic code samples. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )

            result = json.loads(response.choices[0].message.content)

            return NegativeControlSample(
                sample_id=sample_id,
                gt_has_secret=False,
                gt_secret_type=None,  # null, not "none"
                gt_secret_value=None,  # no secret to leak
                gt_file_path=result.get("file_path", "unknown.py"),
                gt_line_start=None,
                condition="B0",
                pr_title=result.get("pr_title", "Update code"),
                pr_body=result.get("pr_body", ""),
                code_context=result.get("code_diff", ""),
                control_type="no_secret"
            )

        except Exception as e:
            logger.error(f"Error generating no-secret sample: {e}")
            raise

    def build_negative_controls(self,
                                 decoy_count: int = 25,
                                 no_secret_count: int = 25) -> List[NegativeControlSample]:
        """Build all negative control samples."""

        logger.info(f"Building {decoy_count} decoy + {no_secret_count} no-secret samples...")
        self.samples = []

        # Generate decoy samples
        logger.info("Generating decoy samples...")
        for i in range(decoy_count):
            scenario = DECOY_SCENARIOS[i % len(DECOY_SCENARIOS)]
            sample_id = f"NEG_DECOY_{i+1:03d}"

            try:
                sample = self.generate_decoy_sample(scenario, sample_id)
                self.samples.append(sample)
                logger.info(f"  Created {sample_id} ({scenario['name']})")
            except Exception as e:
                logger.error(f"  Failed to create {sample_id}: {e}")

            time.sleep(0.5)  # Rate limiting

        # Generate no-secret samples
        logger.info("Generating no-secret samples...")
        for i in range(no_secret_count):
            scenario = NO_SECRET_SCENARIOS[i % len(NO_SECRET_SCENARIOS)]
            sample_id = f"NEG_CLEAN_{i+1:03d}"

            try:
                sample = self.generate_no_secret_sample(scenario, sample_id)
                self.samples.append(sample)
                logger.info(f"  Created {sample_id} ({scenario['name']})")
            except Exception as e:
                logger.error(f"  Failed to create {sample_id}: {e}")

            time.sleep(0.5)  # Rate limiting

        logger.info(f"Generated {len(self.samples)} negative control samples")
        return self.samples

    def save_to_json(self, output_path: str):
        """Save samples to JSON file."""
        samples_dict = [s.to_dict() for s in self.samples]

        with open(output_path, 'w') as f:
            json.dump(samples_dict, f, indent=2)

        logger.info(f"Saved {len(samples_dict)} samples to {output_path}")

        # Statistics
        decoy_count = sum(1 for s in self.samples if s.control_type == "decoy")
        clean_count = sum(1 for s in self.samples if s.control_type == "no_secret")
        logger.info(f"  Decoy samples: {decoy_count}")
        logger.info(f"  No-secret samples: {clean_count}")


def merge_with_baseline(baseline_path: str, negative_controls_path: str, output_path: str):
    """Merge negative controls with existing baseline samples."""

    # Load baseline
    with open(baseline_path, 'r') as f:
        baseline = json.load(f)
    logger.info(f"Loaded {len(baseline)} baseline samples")

    # Load negative controls
    with open(negative_controls_path, 'r') as f:
        negatives = json.load(f)
    logger.info(f"Loaded {len(negatives)} negative control samples")

    # Merge
    combined = baseline + negatives

    # Save
    with open(output_path, 'w') as f:
        json.dump(combined, f, indent=2)

    logger.info(f"Saved {len(combined)} total samples to {output_path}")

    # Statistics
    has_secret = sum(1 for s in combined if s.get('gt_has_secret', True))
    no_secret = len(combined) - has_secret
    logger.info(f"  With secret: {has_secret}")
    logger.info(f"  Without secret (negative controls): {no_secret}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate negative control samples")
    parser.add_argument("--output", type=str, default="data/03_baseline/b0_negative_controls.json",
                       help="Output path for negative controls")
    parser.add_argument("--decoy-count", type=int, default=25,
                       help="Number of decoy samples")
    parser.add_argument("--no-secret-count", type=int, default=25,
                       help="Number of no-secret samples")
    parser.add_argument("--merge-baseline", type=str, default=None,
                       help="Path to baseline to merge with")
    parser.add_argument("--merge-output", type=str, default=None,
                       help="Output path for merged dataset")

    args = parser.parse_args()

    # Build negative controls
    builder = NegativeControlBuilder()
    builder.build_negative_controls(
        decoy_count=args.decoy_count,
        no_secret_count=args.no_secret_count
    )
    builder.save_to_json(args.output)

    # Optionally merge with baseline
    if args.merge_baseline and args.merge_output:
        merge_with_baseline(args.merge_baseline, args.output, args.merge_output)
