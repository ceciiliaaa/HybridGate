"""
Scanner Module for HybridGate Framework

Classic secret scanners (Gitleaks, detect-secrets) for deterministic baseline detection.

Scanner Selection Rationale:
- Gitleaks: Regex-based, high recall for common patterns (SecretBench: 88% recall)
- detect-secrets: Plugin-based with entropy analysis and keyword matching,
  broadly applicable for generic hardcoded secrets

Note: TruffleHog was evaluated but excluded because it prioritizes
verifiable/service-specific secrets, resulting in low coverage (7%)
on generic/synthetic secret samples.
"""

from .base import ScannerClient, ScanResult, SecretFinding, ExtractedContent
from .gitleaks_scanner import GitleaksScanner
from .detect_secrets_scanner import DetectSecretsScanner

__all__ = [
    'ScannerClient',
    'ScanResult',
    'SecretFinding',
    'ExtractedContent',
    'GitleaksScanner',
    'DetectSecretsScanner'
]
