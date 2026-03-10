"""Data collection modules for baseline and manipulation dataset generation."""

from .build_real_baseline import BaselineBuilder, DiffParser, SecretGenerator
from .github_pr_collector import GitHubPRCollector
from .inject_secrets_llm import SecretInjector, RealBaselineBuilder
from .build_synthetic_baseline import LLMSyntheticGenerator, SyntheticBaselineBuilder
from .hybrid_baseline_builder import HybridBaselineBuilder
from .negative_control_builder import NegativeControlBuilder

__all__ = [
    'BaselineBuilder',
    'DiffParser',
    'SecretGenerator',
    'GitHubPRCollector',
    'SecretInjector',
    'RealBaselineBuilder',
    'LLMSyntheticGenerator',
    'SyntheticBaselineBuilder',
    'HybridBaselineBuilder',
    'NegativeControlBuilder',
]
