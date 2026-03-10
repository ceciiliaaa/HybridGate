"""
Gitleaks Scanner Integration

Wrapper for the Gitleaks secret scanner CLI tool.
Top-performing scanner by Recall (88%) according to SecretBench benchmark.

Design: Extracts added lines from diff, writes to temp file with
original extension, then scans with Gitleaks for accurate detection.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

from .base import ScannerClient, ScanResult, SecretFinding

logger = logging.getLogger(__name__)


class GitleaksScanner(ScannerClient):
    """
    Gitleaks scanner implementation.

    Uses regex pattern matching to detect secrets.
    Requires gitleaks CLI: brew install gitleaks
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize Gitleaks scanner.

        Args:
            config_path: Optional path to custom gitleaks config file
        """
        self.config_path = config_path
        self._version = None

    @property
    def name(self) -> str:
        return "gitleaks"

    def is_available(self) -> bool:
        """Check if gitleaks is installed."""
        try:
            result = subprocess.run(
                ["gitleaks", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._version = result.stdout.strip()
                return True
            return False
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_version(self) -> Optional[str]:
        """Get gitleaks version."""
        if self._version is None:
            self.is_available()
        return self._version

    def scan(self, code_diff: str, file_path: Optional[str] = None) -> ScanResult:
        """
        Scan code diff for secrets using gitleaks.

        Process:
        1. Extract added lines from unified diff
        2. Write to temp file with original filename/extension
        3. Run gitleaks on temp file
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
                error="Gitleaks not installed. Run: brew install gitleaks"
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
        report_file = None
        try:
            temp_file, temp_dir = self.create_temp_file_for_scanning(extracted)

            # Create temp file for report (gitleaks can't write to /dev/stdout)
            import tempfile
            report_fd, report_file = tempfile.mkstemp(suffix='.json')
            os.close(report_fd)

            # Build gitleaks command
            cmd = [
                "gitleaks",
                "detect",
                "--source", temp_dir,
                "--report-format", "json",
                "--report-path", report_file,
                "--no-git",
                "--verbose"
            ]

            if self.config_path:
                cmd.extend(["--config", self.config_path])

            # Run gitleaks
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse output from report file
            findings = []
            raw_output = {}

            # Read report file
            report_content = ""
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    report_content = f.read()

            # Gitleaks returns exit code 1 if secrets found, 0 if none
            if report_content.strip():
                try:
                    raw_output = json.loads(report_content)
                    if isinstance(raw_output, list):
                        for finding in raw_output:
                            # Get scanner-reported line
                            scanner_line = finding.get("StartLine", 0)

                            # Map to target file line number
                            target_line = self.map_scanner_line_to_target(
                                scanner_line,
                                extracted.line_mapping
                            ) or scanner_line

                            secret_type = self.normalize_secret_type(
                                finding.get("RuleID", "unknown")
                            )

                            findings.append(SecretFinding(
                                secret_type=secret_type,
                                file_path=extracted.original_file_path,
                                line_number=target_line,
                                match=finding.get("Match", "")[:50] + "...",
                                confidence=1.0,
                                rule_id=finding.get("RuleID"),
                                entropy=finding.get("Entropy")
                            ))
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse gitleaks JSON: {result.stdout[:200]}")

            # Build result
            scanner_hit = len(findings) > 0
            primary_finding = findings[0] if findings else None

            return ScanResult(
                scanner_name=self.name,
                scanner_hit=scanner_hit,
                findings=findings,
                secret_type=primary_finding.secret_type if primary_finding else None,
                location_line=primary_finding.line_number if primary_finding else None,
                confidence=1.0 if scanner_hit else 0.0,
                raw_output={"findings": raw_output} if raw_output else {}
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.name,
                scanner_hit=False,
                error="Gitleaks scan timed out"
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name,
                scanner_hit=False,
                error=f"Gitleaks scan failed: {str(e)}"
            )
        finally:
            # Cleanup temp directory and report file
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            if report_file and os.path.exists(report_file):
                os.remove(report_file)
