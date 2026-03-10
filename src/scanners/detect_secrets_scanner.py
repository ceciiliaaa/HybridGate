"""
Detect-Secrets Scanner Integration

Wrapper for the detect-secrets secret scanner CLI tool.
Uses plugin-based detection with entropy analysis and keyword matching.

Design: Extracts added lines from diff, writes to temp file with
original extension, then scans with detect-secrets for accurate detection.

Why detect-secrets instead of TruffleHog:
- TruffleHog prioritizes verifiable/service-specific secrets
- detect-secrets is more broadly applicable for generic hardcoded secrets
- detect-secrets uses heuristics (entropy, keywords) that work better
  for synthetic and diverse secret samples
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

from .base import ScannerClient, ScanResult, SecretFinding

logger = logging.getLogger(__name__)


class DetectSecretsScanner(ScannerClient):
    """
    Detect-secrets scanner implementation.

    Uses plugin-based detection with entropy analysis and keyword matching.
    Requires detect-secrets CLI: pip install detect-secrets
    """

    def __init__(self):
        """Initialize detect-secrets scanner."""
        self._version = None

    @property
    def name(self) -> str:
        return "detect-secrets"

    def is_available(self) -> bool:
        """Check if detect-secrets is installed."""
        try:
            result = subprocess.run(
                ["detect-secrets", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._version = result.stdout.strip() or result.stderr.strip()
                return True
            return False
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_version(self) -> Optional[str]:
        """Get detect-secrets version."""
        if self._version is None:
            self.is_available()
        return self._version

    def scan(self, code_diff: str, file_path: Optional[str] = None) -> ScanResult:
        """
        Scan code diff for secrets using detect-secrets.

        Process:
        1. Extract added lines from unified diff
        2. Write to temp file with original filename/extension
        3. Run detect-secrets on temp file
        4. Map line numbers back to original

        Args:
            code_diff: Unified diff content to scan
            file_path: Optional file path hint

        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                scanner_name=self.name,
                scanner_hit=False,
                error="detect-secrets not installed. Run: pip install detect-secrets"
            )

        # Extract added content from diff using base class method
        extracted = self.extract_added_content_from_diff(code_diff)

        # Override file path if provided
        if file_path:
            extracted.original_file_path = file_path

        if not extracted.content.strip():
            return ScanResult(
                scanner_name=self.name,
                scanner_hit=False,
                error="No content to scan after extracting from diff"
            )

        # Create temp file with proper extension
        temp_dir = None
        try:
            temp_file, temp_dir = self.create_temp_file_for_scanning(extracted)

            # Build detect-secrets command
            # --all-files: scan all files (not just git-tracked)
            # Use "." as path and cwd=temp_dir to avoid path resolution issues
            cmd = [
                "detect-secrets",
                "scan",
                ".",
                "--all-files"
            ]

            # Run detect-secrets from temp_dir (required for proper scanning)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=temp_dir
            )

            # Parse JSON output
            findings = []
            raw_output = {}

            if result.stdout.strip():
                try:
                    raw_output = json.loads(result.stdout)
                    results_dict = raw_output.get("results", {})

                    # Iterate over all files in results
                    for file_key, file_findings in results_dict.items():
                        for finding_data in file_findings:
                            # Get scanner-reported line
                            scanner_line = finding_data.get("line_number", 0)

                            # Map to target file line number
                            target_line = self.map_scanner_line_to_target(
                                scanner_line,
                                extracted.line_mapping
                            ) or scanner_line

                            # Normalize secret type
                            raw_type = finding_data.get("type", "unknown")
                            secret_type = self._normalize_detect_secrets_type(raw_type)

                            findings.append(SecretFinding(
                                secret_type=secret_type,
                                file_path=extracted.original_file_path,
                                line_number=target_line,
                                match="[REDACTED]",  # detect-secrets hashes secrets
                                confidence=0.9 if finding_data.get("is_verified") else 0.7,
                                rule_id=raw_type,
                                entropy=None  # detect-secrets doesn't expose entropy value
                            ))

                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse detect-secrets JSON: {e}")

            # Build result
            scanner_hit = len(findings) > 0
            primary_finding = findings[0] if findings else None

            return ScanResult(
                scanner_name=self.name,
                scanner_hit=scanner_hit,
                findings=findings,
                secret_type=primary_finding.secret_type if primary_finding else None,
                location_line=primary_finding.line_number if primary_finding else None,
                confidence=primary_finding.confidence if primary_finding else 0.0,
                raw_output=raw_output
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.name,
                scanner_hit=False,
                error="detect-secrets scan timed out"
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name,
                scanner_hit=False,
                error=f"detect-secrets scan failed: {str(e)}"
            )
        finally:
            # Cleanup temp directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _normalize_detect_secrets_type(self, raw_type: str) -> str:
        """
        Normalize detect-secrets type to standard categories.

        Args:
            raw_type: Raw type from detect-secrets (e.g., "Secret Keyword", "AWS Access Key")

        Returns:
            Normalized type: token, api_key, password, private_key, connection_string
        """
        raw_lower = raw_type.lower()

        # API keys
        if any(x in raw_lower for x in ["aws", "azure", "api key", "artifactory",
                                         "cloudant", "ibm", "mailchimp", "npm",
                                         "openai", "pypi", "sendgrid", "slack",
                                         "softlayer", "square", "stripe", "telegram",
                                         "twilio", "discord", "github", "gitlab"]):
            return "api_key"

        # Tokens
        if any(x in raw_lower for x in ["token", "jwt", "bearer"]):
            return "token"

        # Passwords
        if any(x in raw_lower for x in ["password", "secret keyword", "basic auth"]):
            return "password"

        # Private keys
        if "private key" in raw_lower:
            return "private_key"

        # High entropy strings (generic)
        if any(x in raw_lower for x in ["entropy", "base64", "hex"]):
            return "token"

        # Connection strings
        if any(x in raw_lower for x in ["connection", "database", "uri"]):
            return "connection_string"

        return "unknown"
