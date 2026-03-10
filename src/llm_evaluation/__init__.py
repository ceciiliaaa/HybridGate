"""
LLM Evaluation Module for HybridGate Framework

Provides evaluation pipelines for testing LLM-based code reviewers:
- Basic evaluation (run_evaluation.py)
- Hybrid evaluation with scanners and policies (hybrid_evaluation.py)
"""

from .run_evaluation import (
    LLMClient,
    OpenAIClient,
    AnthropicClient,
    EvaluationRunner,
    extract_json,
    number_lines
)

__all__ = [
    'LLMClient',
    'OpenAIClient',
    'AnthropicClient',
    'EvaluationRunner',
    'extract_json',
    'number_lines'
]
