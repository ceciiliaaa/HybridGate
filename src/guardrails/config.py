"""
Guardrail Configuration for HybridGate Framework

Manages which guardrails are active. Allows baseline runs without G4/G5
for reproducibility of previous experiments.

Design decision:
- Default: G1, G2, G3 enabled (for backward compatibility)
- G4, G5 disabled by default (opt-in for new experiments)
"""

from dataclasses import dataclass, field
from typing import Set


@dataclass
class GuardrailSettings:
    """
    Configuration for guardrail activation.

    Attributes:
        active_guardrails: Set of guardrail names that are enabled

    Default Configuration:
    - G1, G2, G3: Enabled (backward compatible baseline)
    - G4, G5: Disabled (opt-in for new experiments)
    """
    active_guardrails: Set[str] = field(default_factory=lambda: {"G1", "G2", "G3"})

    def is_enabled(self, guardrail: str) -> bool:
        """Check if a specific guardrail is enabled."""
        return guardrail.upper() in self.active_guardrails

    def enable(self, guardrail: str) -> None:
        """Enable a guardrail."""
        self.active_guardrails.add(guardrail.upper())

    def disable(self, guardrail: str) -> None:
        """Disable a guardrail."""
        self.active_guardrails.discard(guardrail.upper())

    def enable_all(self) -> None:
        """Enable all guardrails including G4 and G5."""
        self.active_guardrails = {"G1", "G2", "G3", "G4", "G5"}

    def enable_g4_g5(self) -> None:
        """Enable G4 and G5 in addition to existing guardrails."""
        self.active_guardrails.add("G4")
        self.active_guardrails.add("G5")

    @classmethod
    def baseline(cls) -> "GuardrailSettings":
        """Create baseline config (G1, G2, G3 only) for backward compatibility."""
        return cls(active_guardrails={"G1", "G2", "G3"})

    @classmethod
    def full(cls) -> "GuardrailSettings":
        """Create full config with all guardrails enabled."""
        return cls(active_guardrails={"G1", "G2", "G3", "G4", "G5"})


# Global default settings (can be overridden per evaluation run)
DEFAULT_SETTINGS = GuardrailSettings()
