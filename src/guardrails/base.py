"""
Base classes for Guardrails.

Defines abstract interface and data structures for guardrail implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class GuardrailConfig:
    """Configuration for a guardrail."""
    name: str
    enabled: bool = True
    strict_mode: bool = False


@dataclass
class GuardrailResult:
    """Result from guardrail validation."""
    guardrail_name: str
    is_valid: bool
    violations: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guardrail_name": self.guardrail_name,
            "is_valid": self.is_valid,
            "violations": self.violations,
            "warnings": self.warnings,
            "metadata": self.metadata
        }


class Guardrail(ABC):
    """Abstract base class for guardrails."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the guardrail name."""
        pass

    @abstractmethod
    def get_prompt(self) -> str:
        """Return the prompt text to inject into LLM system message."""
        pass

    @abstractmethod
    def validate_output(self, llm_output: dict) -> bool:
        """
        Validate LLM output against this guardrail.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            True if output passes guardrail, False otherwise
        """
        pass

    def get_config(self) -> GuardrailConfig:
        """Return default configuration for this guardrail."""
        return GuardrailConfig(name=self.name)
