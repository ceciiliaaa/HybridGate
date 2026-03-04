"""Manipulation and perturbation modules for adversarial sample generation."""

from .perturbation_engine import (
    PerturbationEngine,
    PerturbationStrategy,
    Sample,
    E1A_DirectInstructionOverride,
    E1B_BenignFraming,
    E1C_AuthorityClaim,
    E2A_InCodeFramingComment,
    E2B_AuthorityInCodeComment,
    E3A_StringConcatenation,
    E3B_SplitAcrossVariables,
)

__all__ = [
    'PerturbationEngine',
    'PerturbationStrategy',
    'Sample',
    'E1A_DirectInstructionOverride',
    'E1B_BenignFraming',
    'E1C_AuthorityClaim',
    'E2A_InCodeFramingComment',
    'E2B_AuthorityInCodeComment',
    'E3A_StringConcatenation',
    'E3B_SplitAcrossVariables',
]
