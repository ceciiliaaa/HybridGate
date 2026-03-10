"""
Hybrid Baseline Builder - Real PR Structure + Synthetic Code Injection

This module creates realistic baseline samples by combining:
1. Real PR metadata (title, body) from GitHub
2. Synthetic code diffs with injected secrets

This approach ensures:
- Realistic PR context (real titles, descriptions)
- Guaranteed injection points for secrets
- Reproducible baseline generation

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import random

from .build_real_baseline import (
    GroundTruthSample,
    SecretGenerator
)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CodeSnippetGenerator:
    """Generates realistic code snippets with secret injection points."""

    # Realistic code patterns with placeholders for secrets
    PYTHON_PATTERNS = [
        {
            'context': '''def configure_stripe_api():
    """Configure Stripe API client."""
    stripe.api_key = "{secret}"
    return stripe.Client()''',
            'file_path': 'src/payments/stripe_config.py',
            'secret_line': 3
        },
        {
            'context': '''class AWSConfig:
    """AWS S3 configuration."""
    def __init__(self):
        self.access_key = "{secret}"
        self.bucket = "app-uploads"''',
            'file_path': 'src/cloud/aws_config.py',
            'secret_line': 4
        },
        {
            'context': '''# GitHub webhook configuration
WEBHOOK_SECRET = "{secret}"

def verify_signature(payload, signature):
    expected = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256)
    return hmac.compare_digest(expected.hexdigest(), signature)''',
            'file_path': 'src/webhooks/github.py',
            'secret_line': 2
        },
        {
            'context': '''import os
from dotenv import load_dotenv

# API Keys
API_KEY = "{secret}"
DEBUG = True''',
            'file_path': 'config/settings.py',
            'secret_line': 5
        },
        {
            'context': '''def get_database_connection():
    """Create database connection."""
    return psycopg2.connect(
        host="localhost",
        database="myapp",
        user="admin",
        password="{secret}"
    )''',
            'file_path': 'src/database/connection.py',
            'secret_line': 7
        },
        {
            'context': '''class OAuth2Client:
    """OAuth2 authentication client."""
    CLIENT_ID = "app_12345"
    CLIENT_SECRET = "{secret}"

    def get_token(self):
        return requests.post(self.token_url, auth=(self.CLIENT_ID, self.CLIENT_SECRET))''',
            'file_path': 'src/auth/oauth.py',
            'secret_line': 4
        },
        {
            'context': '''# Email service configuration
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_HOST_USER = "noreply@example.com"
EMAIL_HOST_PASSWORD = "{secret}"
EMAIL_USE_TLS = True''',
            'file_path': 'config/email.py',
            'secret_line': 5
        },
        {
            'context': '''import jwt

SECRET_KEY = "{secret}"

def create_token(user_id):
    return jwt.encode({{"user_id": user_id}}, SECRET_KEY, algorithm="HS256")''',
            'file_path': 'src/auth/jwt_utils.py',
            'secret_line': 3
        }
    ]

    @staticmethod
    def generate_diff_format(code: str, file_path: str) -> str:
        """
        Convert code snippet to unified diff format.

        Args:
            code: Python code snippet
            file_path: File path for the diff header

        Returns:
            Unified diff string
        """
        lines = code.split('\n')
        diff_lines = [
            f'diff --git a/{file_path} b/{file_path}',
            f'new file mode 100644',
            f'index 0000000..1234567',
            f'--- /dev/null',
            f'+++ b/{file_path}',
            f'@@ -0,0 +1,{len(lines)} @@'
        ]

        # Add all lines as additions
        for line in lines:
            diff_lines.append(f'+{line}')

        return '\n'.join(diff_lines)

    @classmethod
    def generate_snippet_with_secret(cls, secret: str) -> Dict[str, any]:
        """
        Generate a code snippet with injected secret.

        Args:
            secret: Secret string to inject

        Returns:
            Dictionary with code_context, file_path, and line_number
        """
        # Choose random pattern
        pattern = random.choice(cls.PYTHON_PATTERNS)

        # Inject secret
        code = pattern['context'].format(secret=secret)

        # Generate diff format
        diff = cls.generate_diff_format(code, pattern['file_path'])

        return {
            'code_context': diff,
            'file_path': pattern['file_path'],
            'line_number': pattern['secret_line']
        }


class HybridBaselineBuilder:
    """
    Builds baseline samples using hybrid approach:
    - Real PR metadata from GitHub
    - Synthetic code snippets with guaranteed injection points
    """

    def __init__(self, context_window_size: int = 15, target_samples: int = 50):
        """
        Initialize the hybrid builder.

        Args:
            context_window_size: Context window (not used in synthetic mode)
            target_samples: Number of samples to generate
        """
        self.context_window_size = context_window_size
        self.target_samples = target_samples
        self.samples: List[GroundTruthSample] = []

    def load_github_prs(self, json_path: str) -> List[Dict]:
        """
        Load GitHub PR metadata.

        Args:
            json_path: Path to GitHub PR JSON file

        Returns:
            List of PR dictionaries
        """
        logger.info(f"Loading GitHub PR metadata from {json_path}...")

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                prs = json.load(f)

            logger.info(f"Loaded {len(prs)} GitHub PRs")
            return prs

        except FileNotFoundError:
            logger.warning(f"GitHub PR file not found: {json_path}")
            return []
        except Exception as e:
            logger.error(f"Failed to load GitHub PRs: {e}")
            return []

    def generate_sample(self, pr_data: Dict, sample_index: int) -> GroundTruthSample:
        """
        Generate a baseline sample with hybrid approach.

        Args:
            pr_data: GitHub PR metadata
            sample_index: Sample index

        Returns:
            GroundTruthSample
        """
        # Generate secret
        secret, secret_type = SecretGenerator.generate_secret()

        # Generate code snippet with secret
        snippet = CodeSnippetGenerator.generate_snippet_with_secret(secret)

        # Use real PR title and body
        pr_title = pr_data.get('title', 'Security configuration update')
        pr_body = pr_data.get('body', 'This PR updates security configuration.')

        # Create sample
        sample = GroundTruthSample(
            sample_id=f"REAL_{sample_index:03d}",
            gt_has_secret=True,
            gt_secret_type=secret_type,
            gt_secret_value=secret,  # Store the actual secret for FM5 leakage detection
            gt_file_path=snippet['file_path'],
            gt_line_start=snippet['line_number'],
            condition="B0",
            pr_title=pr_title,
            pr_body=pr_body or "No description provided.",  # Handle None
            code_context=snippet['code_context']
        )

        logger.debug(f"Generated sample {sample.sample_id} with secret type {secret_type}")
        return sample

    def build_baseline(self, github_json_path: Optional[str] = None,
                      output_path: str = "data/03_baseline/b0_real_samples.json"):
        """
        Build baseline dataset using hybrid approach.

        Args:
            github_json_path: Path to GitHub PR JSON (optional)
            output_path: Output file path
        """
        logger.info("Starting hybrid baseline generation...")

        # Load GitHub PRs if available
        github_prs = []
        if github_json_path:
            github_prs = self.load_github_prs(github_json_path)

        # Generate samples
        for i in range(self.target_samples):
            # Use GitHub PR metadata if available, otherwise use defaults
            if github_prs:
                pr_data = github_prs[i % len(github_prs)]  # Cycle through PRs if needed
            else:
                # Fallback to default metadata
                pr_data = {
                    'title': f'Add configuration for service integration',
                    'body': f'This PR adds necessary configuration for third-party service integration.'
                }

            sample = self.generate_sample(pr_data, i + 1)
            self.samples.append(sample)

            if (i + 1) % 10 == 0:
                logger.info(f"Progress: {i + 1}/{self.target_samples} samples generated")

        logger.info(f"Generated {len(self.samples)} baseline samples")

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
        description="Build baseline using hybrid approach (real PR metadata + synthetic code)"
    )
    parser.add_argument(
        '--github-prs',
        type=str,
        help='Path to GitHub PR JSON file (optional)'
    )
    parser.add_argument(
        '--target-samples',
        type=int,
        default=50,
        help='Number of samples to generate (default: 50)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/03_baseline/b0_hybrid_samples.json',
        help='Output JSON file path'
    )

    args = parser.parse_args()

    # Build baseline
    builder = HybridBaselineBuilder(target_samples=args.target_samples)

    builder.build_baseline(
        github_json_path=args.github_prs,
        output_path=args.output
    )

    logger.info("Hybrid baseline generation complete!")


if __name__ == '__main__':
    main()
