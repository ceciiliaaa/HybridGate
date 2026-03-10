"""
Base classes for secret scanners.

Defines abstract interface and data structures for scanner implementations.

Design Decision - Diff Extraction:
- Classic scanners (Gitleaks, TruffleHog) are designed to scan source files
- Scanning raw unified diff format causes false positives/negatives
- We extract only ADDED lines from the diff
- Write to temp file with original filename/extension for accurate detection
- Maintain line mapping for traceability back to original diff
"""

import os
import re
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple


@dataclass
class SecretFinding:
    """Represents a single secret finding from a scanner."""
    secret_type: str
    file_path: str
    line_number: int
    match: str  # The matched string (may be redacted)
    confidence: float = 1.0
    rule_id: Optional[str] = None
    entropy: Optional[float] = None


@dataclass
class ScanResult:
    """Result from a scanner run on a code diff."""
    scanner_name: str
    scanner_hit: bool
    findings: List[SecretFinding] = field(default_factory=list)
    secret_type: Optional[str] = None  # Primary secret type if hit
    location_line: Optional[int] = None  # Primary location if hit
    confidence: float = 0.0
    raw_output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner_name": self.scanner_name,
            "scanner_hit": self.scanner_hit,
            "secret_type": self.secret_type,
            "location_line": self.location_line,
            "confidence": self.confidence,
            "finding_count": self.finding_count,
            "findings": [
                {
                    "secret_type": f.secret_type,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "rule_id": f.rule_id,
                    "confidence": f.confidence
                }
                for f in self.findings
            ],
            "error": self.error
        }


@dataclass
class ExtractedContent:
    """
    Content extracted from a diff for scanning.

    Attributes:
        content: The actual code content (added lines only)
        original_file_path: Original file path from diff header
        line_mapping: Maps extracted line index (0-based) to target file line number
    """
    content: str
    original_file_path: str
    line_mapping: Dict[int, int]


class ScannerClient(ABC):
    """Abstract base class for secret scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the scanner name."""
        pass

    @abstractmethod
    def scan(self, code_diff: str, file_path: Optional[str] = None) -> ScanResult:
        """
        Scan a code diff for secrets.

        Args:
            code_diff: The unified diff content to scan
            file_path: Optional file path hint for context

        Returns:
            ScanResult with findings
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the scanner is installed and available."""
        pass

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file directly.

        Args:
            file_path: Path to the file to scan

        Returns:
            ScanResult with findings
        """
        with open(file_path, 'r') as f:
            content = f.read()
        return self.scan(content, file_path)

    @staticmethod
    def extract_added_content_from_diff(
        diff: str,
        include_context: bool = True
    ) -> ExtractedContent:
        """
        Extract added lines from a unified diff.

        This creates content suitable for scanning with Gitleaks/TruffleHog.
        Only added lines (and optionally context) are included.

        Args:
            diff: Unified diff content
            include_context: Whether to include unchanged context lines

        Returns:
            ExtractedContent with code and line mapping
        """
        added_lines = []
        line_mapping = {}  # extracted_idx -> target_line_number
        original_file_path = "unknown.txt"

        target_line_number = 0  # Current line in the "after" file

        for line in diff.split('\n'):
            # Extract file path from diff header
            if line.startswith('+++ b/'):
                original_file_path = line[6:]
                continue
            if line.startswith('+++ '):
                original_file_path = line[4:]
                continue

            # Skip other diff headers
            if line.startswith('diff --git') or line.startswith('index '):
                continue
            if line.startswith('---'):
                continue

            # Parse hunk header to get target line number
            if line.startswith('@@'):
                match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
                if match:
                    target_line_number = int(match.group(1)) - 1
                continue

            # Added lines - what we're scanning for secrets
            if line.startswith('+') and not line.startswith('+++'):
                target_line_number += 1
                content = line[1:]  # Remove + prefix
                extracted_idx = len(added_lines)
                added_lines.append(content)
                line_mapping[extracted_idx] = target_line_number
                continue

            # Context lines (unchanged)
            if line.startswith(' ') and include_context:
                target_line_number += 1
                content = line[1:]  # Remove space prefix
                extracted_idx = len(added_lines)
                added_lines.append(content)
                line_mapping[extracted_idx] = target_line_number
                continue

            # Removed lines - skip (not in target file)
            if line.startswith('-') and not line.startswith('---'):
                continue

        return ExtractedContent(
            content='\n'.join(added_lines),
            original_file_path=original_file_path,
            line_mapping=line_mapping
        )

    @staticmethod
    def create_temp_file_for_scanning(
        extracted: ExtractedContent,
        temp_dir: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Create a temporary file with extracted content for scanning.

        Preserves original file extension for scanner accuracy.
        Creates subdirectory structure if present in original path.

        Args:
            extracted: ExtractedContent from diff extraction
            temp_dir: Optional temp directory path

        Returns:
            Tuple of (temp_file_path, temp_dir_path)
        """
        if temp_dir is None:
            temp_dir = tempfile.mkdtemp(prefix="scanner_")

        # Get file extension from original path
        original_path = Path(extracted.original_file_path)
        suffix = original_path.suffix or '.txt'
        filename = original_path.name or f"scan_target{suffix}"

        # Create subdirectories if needed
        if '/' in extracted.original_file_path:
            parent_dirs = str(Path(extracted.original_file_path).parent)
            full_parent = os.path.join(temp_dir, parent_dirs)
            os.makedirs(full_parent, exist_ok=True)
            temp_file_path = os.path.join(full_parent, filename)
        else:
            temp_file_path = os.path.join(temp_dir, filename)

        with open(temp_file_path, 'w', encoding='utf-8') as f:
            f.write(extracted.content)

        return temp_file_path, temp_dir

    @staticmethod
    def map_scanner_line_to_target(
        scanner_line: int,
        line_mapping: Dict[int, int]
    ) -> Optional[int]:
        """
        Map scanner-reported line to target file line number.

        Args:
            scanner_line: Line number from scanner (1-indexed)
            line_mapping: Mapping from extracted to target lines

        Returns:
            Target file line number or None
        """
        extracted_idx = scanner_line - 1  # Convert to 0-indexed
        return line_mapping.get(extracted_idx)

    @staticmethod
    def normalize_secret_type(raw_type: str) -> str:
        """
        Normalize scanner-specific secret types to standard categories.

        Maps various scanner-specific rule names to:
        - api_key
        - token
        - password
        - private_key
        - connection_string
        - unknown
        """
        raw_lower = raw_type.lower()

        # API Keys
        if any(x in raw_lower for x in ['api_key', 'apikey', 'api-key', 'stripe', 'sendgrid', 'twilio', 'aws_access']):
            return 'api_key'

        # Tokens
        if any(x in raw_lower for x in ['token', 'bearer', 'jwt', 'oauth', 'github', 'gitlab', 'slack']):
            return 'token'

        # Passwords
        if any(x in raw_lower for x in ['password', 'passwd', 'pwd', 'secret_key', 'django']):
            return 'password'

        # Private Keys
        if any(x in raw_lower for x in ['private_key', 'privatekey', 'rsa', 'ssh', 'pem', 'certificate']):
            return 'private_key'

        # Connection Strings
        if any(x in raw_lower for x in ['connection', 'database_url', 'mongodb', 'postgres', 'mysql', 'redis']):
            return 'connection_string'

        return 'unknown'
