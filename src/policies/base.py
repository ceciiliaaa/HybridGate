"""
Base classes for Hybrid Gate Policies.

Defines the decision types and abstract interface for policy implementations.

Design Decisions:
- llm_decision can be: "BLOCK", "PASS", "REVIEW", "NOT_INVOKED"
- NOT_INVOKED is used when LLM was not called (e.g., P3 cost-optimized)
- This avoids redundant llm_invoked boolean fields
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any


class PolicyDecision(Enum):
    """Possible gate decisions."""
    PASS = "PASS"      # Allow the PR to proceed
    BLOCK = "BLOCK"    # Block the PR, requires secret removal
    REVIEW = "REVIEW"  # Flag for human security review


class LLMDecision(Enum):
    """Possible LLM reviewer decisions."""
    BLOCK = "BLOCK"          # LLM detected secret
    PASS = "PASS"            # LLM found no secret
    REVIEW = "REVIEW"        # LLM uncertain, needs human review
    NOT_INVOKED = "NOT_INVOKED"  # LLM was not called (cost optimization)


@dataclass
class PolicyResult:
    """Result from a policy decision."""
    policy_name: str
    decision: PolicyDecision
    scanner_hit: bool
    llm_hit: bool
    llm_decision: str  # LLMDecision value as string
    reasoning: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "decision": self.decision.value,
            "scanner_hit": self.scanner_hit,
            "llm_hit": self.llm_hit,
            "llm_decision": self.llm_decision,
            "reasoning": self.reasoning,
            "metadata": self.metadata
        }


class Policy(ABC):
    """Abstract base class for gate policies."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the policy name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a description of the policy logic."""
        pass

    @abstractmethod
    def decide(self, scanner_hit: bool, llm_hit: bool,
               llm_decision: Optional[str] = None, **kwargs) -> PolicyDecision:
        """
        Make a gate decision based on scanner and LLM results.

        Args:
            scanner_hit: Whether classic scanner detected a secret
            llm_hit: Whether LLM detected a secret (pred_has_secret=True)
            llm_decision: LLM's decision string (BLOCK/PASS/REVIEW/NOT_INVOKED)
            **kwargs: Additional context (varies by policy)

        Returns:
            PolicyDecision (PASS, BLOCK, or REVIEW)
        """
        pass

    def get_full_result(self, scanner_hit: bool, llm_hit: bool,
                        llm_decision: Optional[str] = None, **kwargs) -> PolicyResult:
        """
        Get full policy result with reasoning.

        Args:
            scanner_hit: Whether classic scanner detected a secret
            llm_hit: Whether LLM detected a secret
            llm_decision: LLM's decision string
            **kwargs: Additional context

        Returns:
            PolicyResult with decision and reasoning
        """
        decision = self.decide(scanner_hit, llm_hit, llm_decision, **kwargs)

        return PolicyResult(
            policy_name=self.name,
            decision=decision,
            scanner_hit=scanner_hit,
            llm_hit=llm_hit,
            llm_decision=llm_decision or LLMDecision.NOT_INVOKED.value,
            reasoning=self._get_reasoning(scanner_hit, llm_hit, decision, llm_decision, **kwargs),
            metadata=kwargs
        )

    def _get_reasoning(self, scanner_hit: bool, llm_hit: bool,
                       decision: PolicyDecision,
                       llm_decision: Optional[str] = None, **kwargs) -> str:
        """Generate reasoning for the decision."""
        return f"{self.name}: scanner={scanner_hit}, llm={llm_hit}, llm_decision={llm_decision} -> {decision.value}"
