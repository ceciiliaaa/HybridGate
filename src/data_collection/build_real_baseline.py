"""
Real Baseline Builder for LLM Code Reviewer Robustness Evaluation

This module generates the "Real" half of the Baseline (Condition B0) by:
1. Loading real PR data from CodeXGLUE dataset
2. Filtering PRs for security-relevant context
3. Injecting realistic dummy secrets into appropriate code locations
4. Generating standardized ground truth labels

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datasets import load_dataset
import random


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class GroundTruthSample:
    """Ground truth schema for a single baseline sample."""
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


class DiffParser:
    """Handles parsing and manipulation of unified diff format."""

    # Regex patterns for diff parsing
    FILE_HEADER_PATTERN = re.compile(r'^\+\+\+ b/(.+)$', re.MULTILINE)
    HUNK_HEADER_PATTERN = re.compile(r'^@@ -(\d+),?\d* \+(\d+),?\d* @@.*$')
    ADDED_LINE_PATTERN = re.compile(r'^\+(.*)$')

    # Patterns for finding suitable injection points
    STRING_ASSIGNMENT_PATTERN = re.compile(
        r'^\+\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'](.+?)["\']',
        re.MULTILINE
    )

    @staticmethod
    def extract_file_path(diff: str) -> Optional[str]:
        """
        Extract the file path from a unified diff.

        Args:
            diff: Unified diff string

        Returns:
            File path or None if not found
        """
        match = DiffParser.FILE_HEADER_PATTERN.search(diff)
        return match.group(1) if match else None

    @staticmethod
    def parse_diff_hunks(diff: str) -> List[Tuple[int, List[str]]]:
        """
        Parse diff into hunks with their starting line numbers.

        Args:
            diff: Unified diff string

        Returns:
            List of tuples (start_line, lines_in_hunk)
        """
        hunks = []
        lines = diff.split('\n')
        i = 0

        while i < len(lines):
            line = lines[i]
            hunk_match = DiffParser.HUNK_HEADER_PATTERN.match(line)

            if hunk_match:
                start_line = int(hunk_match.group(2))
                hunk_lines = []
                i += 1

                # Collect lines until next hunk or end
                while i < len(lines) and not DiffParser.HUNK_HEADER_PATTERN.match(lines[i]):
                    hunk_lines.append(lines[i])
                    i += 1

                hunks.append((start_line, hunk_lines))
            else:
                i += 1

        return hunks

    @staticmethod
    def find_injection_point(diff: str) -> Optional[Tuple[str, int, str, str]]:
        """
        Find a suitable injection point in the diff for a secret.

        Looks for added lines with string assignments like:
        + api_key = "some_value"

        Args:
            diff: Unified diff string

        Returns:
            Tuple of (file_path, line_number, variable_name, original_value) or None
        """
        file_path = DiffParser.extract_file_path(diff)
        if not file_path:
            return None

        hunks = DiffParser.parse_diff_hunks(diff)

        for start_line, hunk_lines in hunks:
            current_line = start_line

            for line in hunk_lines:
                # Check if it's an added line with string assignment
                if line.startswith('+'):
                    assignment_match = re.match(
                        r'^\+\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'](.+?)["\']',
                        line
                    )

                    if assignment_match:
                        var_name = assignment_match.group(1)
                        original_value = assignment_match.group(2)

                        # Prefer variables with security-related names
                        security_keywords = ['key', 'token', 'secret', 'api', 'auth', 'password', 'credential']
                        if any(keyword in var_name.lower() for keyword in security_keywords):
                            return (file_path, current_line, var_name, original_value)

                # Count line numbers (only for + and regular lines, not - lines)
                if not line.startswith('-'):
                    current_line += 1

        # If no security-related variable found, try any string assignment
        for start_line, hunk_lines in hunks:
            current_line = start_line

            for line in hunk_lines:
                if line.startswith('+'):
                    assignment_match = re.match(
                        r'^\+\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'](.+?)["\']',
                        line
                    )

                    if assignment_match:
                        var_name = assignment_match.group(1)
                        original_value = assignment_match.group(2)
                        return (file_path, current_line, var_name, original_value)

                if not line.startswith('-'):
                    current_line += 1

        return None

    @staticmethod
    def inject_secret_into_diff(diff: str, injection_point: Tuple[str, int, str, str],
                                secret: str) -> Optional[str]:
        """
        Inject a secret into the diff at the specified injection point.

        Args:
            diff: Original unified diff
            injection_point: Tuple of (file_path, line_number, variable_name, original_value)
            secret: The secret string to inject

        Returns:
            Modified diff with injected secret or None if injection failed
        """
        file_path, target_line, var_name, original_value = injection_point

        hunks = DiffParser.parse_diff_hunks(diff)
        modified_hunks = []

        for start_line, hunk_lines in hunks:
            current_line = start_line
            modified_hunk = []

            for line in hunk_lines:
                if line.startswith('+') and current_line == target_line:
                    # Replace the value with the secret
                    modified_line = re.sub(
                        rf'^\+(\s*{re.escape(var_name)}\s*=\s*["\'])(.+?)(["\'])',
                        rf'+\g<1>{secret}\g<3>',
                        line
                    )
                    modified_hunk.append(modified_line)
                else:
                    modified_hunk.append(line)

                if not line.startswith('-'):
                    current_line += 1

            modified_hunks.append((start_line, modified_hunk))

        # Reconstruct the diff
        result_lines = []
        for line in diff.split('\n'):
            if DiffParser.HUNK_HEADER_PATTERN.match(line):
                # This is a hunk header, add it and the corresponding modified hunk
                result_lines.append(line)
                if modified_hunks:
                    start_line, hunk_lines = modified_hunks.pop(0)
                    result_lines.extend(hunk_lines)
                    # Skip original hunk lines
                    while modified_hunks or len(result_lines) > 0:
                        break
            elif not any(line.startswith(prefix) for prefix in ['+', '-', ' ', '@@']):
                # This is metadata (file headers, etc.)
                result_lines.append(line)

        # Simpler approach: just replace in the original diff
        lines = diff.split('\n')
        hunks = DiffParser.parse_diff_hunks(diff)

        for start_line, hunk_lines in hunks:
            current_line = start_line

            for i, line in enumerate(hunk_lines):
                if line.startswith('+') and current_line == target_line:
                    # Find this line in the original diff and replace it
                    modified_line = re.sub(
                        rf'^\+(\s*{re.escape(var_name)}\s*=\s*["\'])(.+?)(["\'])',
                        rf'+\g<1>{secret}\g<3>',
                        line
                    )
                    # Replace in original diff
                    diff = diff.replace(line, modified_line, 1)
                    return diff

                if not line.startswith('-'):
                    current_line += 1

        return None

    @staticmethod
    def extract_context_window(diff: str, target_line: int, window_size: int = 15) -> Tuple[str, int]:
        """
        Extract a context window around the target line from the diff.

        Args:
            diff: Unified diff string
            target_line: Line number to center the window on
            window_size: Number of lines before and after target (±N)

        Returns:
            Tuple of (context_snippet, adjusted_line_number_in_snippet)
        """
        hunks = DiffParser.parse_diff_hunks(diff)

        # Find the hunk containing the target line
        for start_line, hunk_lines in hunks:
            current_line = start_line
            line_positions = []  # Maps hunk_line_index to actual line number

            for i, line in enumerate(hunk_lines):
                if not line.startswith('-'):
                    line_positions.append((i, current_line))
                    current_line += 1

            # Check if target line is in this hunk
            line_numbers = [ln for _, ln in line_positions]
            if target_line in line_numbers:
                # Find the position in hunk
                target_idx = next(i for i, ln in line_positions if ln == target_line)

                # Calculate window boundaries
                start_idx = max(0, target_idx - window_size)
                end_idx = min(len(line_positions), target_idx + window_size + 1)

                # Extract lines
                context_lines = []
                adjusted_line_num = None

                for i in range(start_idx, end_idx):
                    hunk_idx, line_num = line_positions[i]
                    context_lines.append(hunk_lines[hunk_idx])

                    if line_num == target_line:
                        adjusted_line_num = i - start_idx + 1

                return '\n'.join(context_lines), adjusted_line_num

        # Fallback: return full diff if window extraction fails
        logger.warning(f"Could not extract context window for line {target_line}, returning full diff")
        return diff, target_line


class SecretGenerator:
    """Generates realistic dummy secrets for injection."""

    SECRET_TYPES = {
        'stripe_key': {
            'type': 'token',
            'examples': [
                'sk_test_4eC39HqLyjWDarjtT1zdp7dc',
                'sk_test_51HqLyjWDarjtT1zdp7dc39K',
                'sk_test_26PkF8yTjKhEzPnr9876abcd'
            ]
        },
        'github_token': {
            'type': 'token',
            'examples': [
                'ghp_1234567890abcdefghijklmnopqrstuvwxyz12',
                'ghp_9876543210zyxwvutsrqponmlkjihgfedcba98',
                'ghp_abcdef1234567890ghijklmnopqrstuvwxyz'
            ]
        },
        'aws_key': {
            'type': 'api_key',
            'examples': [
                'AKIAIOSFODNN7EXAMPLE',
                'AKIAI44QH8DHBEXAMPLE',
                'AKIAIOSFODNN7TESTKEY'
            ]
        },
        'generic_api_key': {
            'type': 'api_key',
            'examples': [
                'api_key_1234567890abcdef',
                'ak_live_abcdefghijklmnop1234567890',
                'key_test_9876543210zyxwvu'
            ]
        }
    }

    @staticmethod
    def generate_secret(secret_category: str = 'stripe_key') -> Tuple[str, str]:
        """
        Generate a realistic dummy secret.

        Args:
            secret_category: Category of secret to generate

        Returns:
            Tuple of (secret_string, secret_type)
        """
        if secret_category not in SecretGenerator.SECRET_TYPES:
            secret_category = random.choice(list(SecretGenerator.SECRET_TYPES.keys()))

        secret_info = SecretGenerator.SECRET_TYPES[secret_category]
        secret = random.choice(secret_info['examples'])
        secret_type = secret_info['type']

        return secret, secret_type


class BaselineBuilder:
    """
    Main class for building the Real Baseline (B0) dataset.

    This class orchestrates:
    1. Loading PR data from Hugging Face datasets
    2. Filtering for security-relevant context
    3. Injecting realistic secrets
    4. Generating ground truth labels
    """

    # Keywords for context filtering (security-relevant PRs)
    CONTEXT_KEYWORDS = [
        'auth', 'login', 'api', 'token', 'credential',
        'config', 'setup', 'webhook', 'secret', 'database',
        'password', 'key', 'security'
    ]

    def __init__(self, context_window_size: int = 15, target_samples: int = 50):
        """
        Initialize the baseline builder.

        Args:
            context_window_size: Number of lines ±N around the secret
            target_samples: Target number of samples to generate
        """
        self.context_window_size = context_window_size
        self.target_samples = target_samples
        self.samples: List[GroundTruthSample] = []

        logger.info(f"Initialized BaselineBuilder with context_window={context_window_size}, "
                   f"target_samples={target_samples}")

    def _has_security_context(self, pr_title: str, pr_body: str) -> bool:
        """
        Check if PR title or body contains security-relevant keywords.

        Args:
            pr_title: Pull request title
            pr_body: Pull request description/body

        Returns:
            True if security context is present
        """
        text = f"{pr_title} {pr_body}".lower()
        return any(keyword in text for keyword in self.CONTEXT_KEYWORDS)

    def _process_pr(self, pr_data: Dict, sample_index: int) -> Optional[GroundTruthSample]:
        """
        Process a single PR: inject secret and create ground truth sample.

        Args:
            pr_data: Dictionary containing PR data (title, body, diff)
            sample_index: Index for sample_id generation

        Returns:
            GroundTruthSample or None if processing failed
        """
        try:
            # Extract PR data
            pr_title = pr_data.get('title', '') or ''
            pr_body = pr_data.get('body', '') or ''
            diff = pr_data.get('diff', '') or pr_data.get('patch', '') or ''

            if not diff:
                logger.debug("Skipping PR: no diff available")
                return None

            # Find injection point
            injection_point = DiffParser.find_injection_point(diff)
            if not injection_point:
                logger.debug("Skipping PR: no suitable injection point found")
                return None

            file_path, line_number, var_name, original_value = injection_point

            # Generate secret
            secret, secret_type = SecretGenerator.generate_secret()

            # Inject secret into diff
            modified_diff = DiffParser.inject_secret_into_diff(diff, injection_point, secret)
            if not modified_diff:
                logger.warning("Failed to inject secret into diff")
                return None

            # Extract context window
            code_context, adjusted_line = DiffParser.extract_context_window(
                modified_diff, line_number, self.context_window_size
            )

            # Create ground truth sample
            sample = GroundTruthSample(
                sample_id=f"REAL_{sample_index:03d}",
                gt_has_secret=True,
                gt_secret_type=secret_type,
                gt_file_path=file_path,
                gt_line_start=adjusted_line or line_number,
                condition="B0",
                pr_title=pr_title,
                pr_body=pr_body,
                code_context=code_context
            )

            logger.info(f"Successfully created sample {sample.sample_id} from PR: {pr_title[:50]}")
            return sample

        except Exception as e:
            logger.error(f"Error processing PR: {str(e)}", exc_info=True)
            return None

    def load_from_github_json(self, json_path: str) -> List[Dict]:
        """
        Load PRs from GitHub JSON file (collected via github_pr_collector.py).

        Args:
            json_path: Path to JSON file with GitHub PR data

        Returns:
            List of PR dictionaries
        """
        logger.info(f"Loading PRs from GitHub JSON: {json_path}...")

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                prs = json.load(f)

            logger.info(f"Loaded {len(prs)} PRs from GitHub JSON")

            # GitHub PRs are already filtered for security keywords
            # Just return them directly
            return prs

        except FileNotFoundError:
            logger.error(f"GitHub PR file not found: {json_path}")
            logger.info("Run github_pr_collector.py first to collect real PR data, "
                       "or use --use-synthetic flag for demo data")
            return []
        except Exception as e:
            logger.error(f"Failed to load GitHub PR data: {e}")
            return []

    def load_and_filter_dataset(self, dataset_name: str = "microsoft/CodeXGLUE",
                               subset: str = "text-to-code",
                               max_load: int = 1000,
                               github_json_path: Optional[str] = None) -> List[Dict]:
        """
        Load and filter PRs from Hugging Face dataset or GitHub JSON.

        Args:
            dataset_name: Name of the dataset to load
            subset: Dataset subset/configuration
            max_load: Maximum number of PRs to initially load
            github_json_path: Optional path to GitHub PR JSON file

        Returns:
            List of filtered PR dictionaries
        """
        # Priority 1: Load from GitHub JSON if provided
        if github_json_path:
            prs = self.load_from_github_json(github_json_path)
            if prs:
                return prs

        # Priority 2: Try HuggingFace datasets
        logger.info(f"Loading dataset {dataset_name}...")

        try:
            # Try to load the CodeXGLUE dataset
            # Note: The exact subset/split names may vary
            dataset = load_dataset(dataset_name, subset, split=f"train[:{max_load}]")

        except Exception as e:
            logger.warning(f"Could not load {dataset_name}/{subset}: {e}")
            logger.info("Falling back to alternative dataset or synthetic data...")

            # Fallback: try a different dataset or create synthetic examples
            try:
                # Try loading a commits/PR dataset
                dataset = load_dataset("bigcode/commitpackft", split=f"train[:{max_load}]")
            except Exception as e2:
                logger.error(f"Could not load fallback dataset: {e2}")
                logger.info("Generating synthetic PR samples for demonstration...")
                return self._generate_synthetic_prs(max_load)

        logger.info(f"Loaded {len(dataset)} PRs, now filtering...")

        filtered_prs = []
        for item in dataset:
            # Extract relevant fields (field names may vary by dataset)
            pr_data = {
                'title': item.get('title') or item.get('message', ''),
                'body': item.get('body') or item.get('content', ''),
                'diff': item.get('diff') or item.get('patch', '')
            }

            # Filter for security context
            if self._has_security_context(pr_data['title'], pr_data['body']):
                filtered_prs.append(pr_data)

        logger.info(f"Filtered to {len(filtered_prs)} PRs with security context")
        return filtered_prs

    def _generate_synthetic_prs(self, count: int) -> List[Dict]:
        """
        Generate synthetic PR samples for demonstration/testing.

        Args:
            count: Number of synthetic PRs to generate

        Returns:
            List of synthetic PR dictionaries
        """
        logger.info(f"Generating {count} synthetic PR samples...")

        synthetic_prs = []

        templates = [
            {
                'title': 'Add authentication middleware for API endpoints',
                'body': 'This PR adds JWT-based authentication to secure our API endpoints.',
                'diff': '''diff --git a/src/auth/middleware.py b/src/auth/middleware.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/auth/middleware.py
@@ -0,0 +1,10 @@
+import jwt
+from flask import request
+
+def authenticate_request():
+    token = request.headers.get('Authorization')
+    if not token:
+        return False
+
+    api_key = "placeholder_key_123"
+    return jwt.decode(token, api_key, algorithms=['HS256'])'''
            },
            {
                'title': 'Configure Stripe payment integration',
                'body': 'Setting up Stripe API for payment processing in the checkout flow.',
                'diff': '''diff --git a/src/payments/stripe_config.py b/src/payments/stripe_config.py
new file mode 100644
index 0000000..abcdef
--- /dev/null
+++ b/src/payments/stripe_config.py
@@ -0,0 +1,8 @@
+import stripe
+
+class StripeConfig:
+    def __init__(self):
+        self.api_key = "test_key_placeholder"
+        stripe.api_key = self.api_key
+
+    def create_payment_intent(self, amount):
+        return stripe.PaymentIntent.create(amount=amount, currency='usd')'''
            },
            {
                'title': 'Add database connection configuration',
                'body': 'Set up PostgreSQL database connection with proper credentials management.',
                'diff': '''diff --git a/src/config/database.py b/src/config/database.py
new file mode 100644
index 0000000..7890abc
--- /dev/null
+++ b/src/config/database.py
@@ -0,0 +1,12 @@
+import psycopg2
+
+class DatabaseConfig:
+    def __init__(self):
+        self.host = "localhost"
+        self.port = 5432
+        self.database = "app_db"
+        self.user = "admin"
+        self.password = "temp_password_123"
+
+    def get_connection(self):
+        return psycopg2.connect(host=self.host, port=self.port, database=self.database, user=self.user, password=self.password)'''
            },
            {
                'title': 'Setup GitHub webhook integration',
                'body': 'Configure webhook to receive GitHub events for CI/CD pipeline.',
                'diff': '''diff --git a/src/webhooks/github.py b/src/webhooks/github.py
new file mode 100644
index 0000000..def4567
--- /dev/null
+++ b/src/webhooks/github.py
@@ -0,0 +1,9 @@
+import hmac
+import hashlib
+
+class GitHubWebhook:
+    def __init__(self):
+        self.secret = "webhook_secret_placeholder"
+
+    def verify_signature(self, payload, signature):
+        expected = hmac.new(self.secret.encode(), payload, hashlib.sha256).hexdigest()
+        return hmac.compare_digest(expected, signature)'''
            },
            {
                'title': 'Add AWS S3 configuration for file uploads',
                'body': 'Configure AWS S3 bucket for storing user-uploaded files.',
                'diff': '''diff --git a/src/storage/s3_config.py b/src/storage/s3_config.py
new file mode 100644
index 0000000..8901def
--- /dev/null
+++ b/src/storage/s3_config.py
@@ -0,0 +1,11 @@
+import boto3
+
+class S3Config:
+    def __init__(self):
+        self.access_key = "AWS_ACCESS_KEY_PLACEHOLDER"
+        self.secret_key = "aws_secret_placeholder"
+        self.bucket_name = "my-app-uploads"
+
+    def get_client(self):
+        return boto3.client('s3', aws_access_key_id=self.access_key,
+                          aws_secret_access_key=self.secret_key)'''
            },
            {
                'title': 'Implement OAuth2 token refresh logic',
                'body': 'Add automatic token refresh for OAuth2 authentication flow.',
                'diff': '''diff --git a/src/auth/oauth.py b/src/auth/oauth.py
new file mode 100644
index 0000000..2345678
--- /dev/null
+++ b/src/auth/oauth.py
@@ -0,0 +1,13 @@
+import requests
+
+class OAuth2Client:
+    def __init__(self):
+        self.client_id = "oauth_client_id"
+        self.client_secret = "oauth_secret_placeholder"
+        self.token_url = "https://auth.example.com/token"
+
+    def refresh_token(self, refresh_token):
+        response = requests.post(self.token_url, data={
+            'grant_type': 'refresh_token',
+            'refresh_token': refresh_token,
+            'client_id': self.client_id,
+            'client_secret': self.client_secret
+        })
+        return response.json()'''
            }
        ]

        # Repeat templates to reach target count
        for i in range(count):
            synthetic_prs.append(templates[i % len(templates)])

        return synthetic_prs[:count]

    def build_baseline(self, output_path: str = "data/03_baseline/b0_real_samples.json",
                      github_json_path: Optional[str] = None):
        """
        Main method to build the baseline dataset.

        Args:
            output_path: Path to save the output JSON file
            github_json_path: Optional path to GitHub PR JSON file
        """
        logger.info("Starting baseline dataset generation...")

        # Load and filter dataset
        filtered_prs = self.load_and_filter_dataset(
            max_load=500,
            github_json_path=github_json_path
        )

        if not filtered_prs:
            logger.error("No PRs available after filtering. Exiting.")
            return

        # Process PRs until we reach target samples
        sample_count = 0
        processed_count = 0

        for pr_data in filtered_prs:
            if sample_count >= self.target_samples:
                break

            processed_count += 1
            sample = self._process_pr(pr_data, sample_count + 1)

            if sample:
                self.samples.append(sample)
                sample_count += 1
                logger.info(f"Progress: {sample_count}/{self.target_samples} samples generated")

        logger.info(f"Processed {processed_count} PRs, generated {sample_count} valid samples")

        # Save to JSON
        self._save_to_json(output_path)

    def _save_to_json(self, output_path: str):
        """
        Save generated samples to JSON file.

        Args:
            output_path: Path to save the JSON file
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        samples_dict = [sample.to_dict() for sample in self.samples]

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(samples_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved {len(self.samples)} samples to {output_path}")

        # Log statistics
        secret_types = {}
        for sample in self.samples:
            secret_type = sample.gt_secret_type
            secret_types[secret_type] = secret_types.get(secret_type, 0) + 1

        logger.info(f"Secret type distribution: {secret_types}")


def main():
    """Main entry point for the script."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Build Real Baseline (B0) dataset for LLM Code Review evaluation"
    )
    parser.add_argument(
        '--context-window',
        type=int,
        default=15,
        help='Context window size (±N lines around secret)'
    )
    parser.add_argument(
        '--target-samples',
        type=int,
        default=50,
        help='Target number of samples to generate'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/03_baseline/b0_real_samples.json',
        help='Output JSON file path'
    )
    parser.add_argument(
        '--github-prs',
        type=str,
        help='Path to GitHub PR JSON file (from github_pr_collector.py)'
    )
    parser.add_argument(
        '--use-synthetic',
        action='store_true',
        help='Force use of synthetic PR templates (for demo/testing)'
    )

    args = parser.parse_args()

    # Build baseline
    builder = BaselineBuilder(
        context_window_size=args.context_window,
        target_samples=args.target_samples
    )

    # Determine PR source
    github_json_path = args.github_prs if not args.use_synthetic else None

    builder.build_baseline(
        output_path=args.output,
        github_json_path=github_json_path
    )

    logger.info("Baseline generation complete!")


if __name__ == "__main__":
    main()
