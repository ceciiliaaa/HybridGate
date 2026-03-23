"""
G6: Format-Familiarity Pre-Scan (Pre-LLM Hint Mechanism)

Exploratory guardrail prototype investigating whether the LLM's tendency to
dismiss hardcoded values that match "known non-secret formats" (UUID, SHA
hash, git SHA, Docker digest, certificate fingerprint, W3C traceparent,
numeric token, prefixed hex ID) can be mitigated via a structured hint.

Architecture:
  - PRE-LLM hint mechanism (runs BEFORE the LLM API call, not after)
  - Deterministic regex extractor identifies candidate strings in the diff
  - Structured hint injected into the LLM prompt to request explicit
    evaluation of each candidate
  - G6 does NOT make detection decisions — it only highlights candidates
  - The LLM still makes the final PASS/BLOCK/REVIEW decision
  - Post-LLM guardrails G1–G5 run normally after the LLM call

Design constraints:
  - G6 must be deterministic and reproducible (no LLM pre-scan)
  - G6 must not introduce false positives by itself (hint-only, no routing)
  - G6 patterns are defined a priori, not fitted to test data
  - G6 is currently evaluated only on an isolated hard-sample test set
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .base import Guardrail, GuardrailConfig


# ============================================================================
# Format patterns — each targets a "known-safe format" that LLMs tend to
# classify as non-secret. Patterns are intentionally conservative (high
# precision) to avoid flooding the hint with irrelevant matches.
# ============================================================================

@dataclass
class FormatCandidate:
    """A candidate string that matches a known non-secret format."""
    value: str
    format_name: str
    line_number: Optional[int] = None
    variable_name: Optional[str] = None


# Compiled regex patterns for known-safe formats.
# Each tuple: (pattern_name, compiled_regex_for_the_value)
FORMAT_PATTERNS = [
    (
        "UUID",
        re.compile(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            re.IGNORECASE,
        ),
    ),
    (
        "SHA-256 hex digest",
        re.compile(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])', re.IGNORECASE),
    ),
    (
        "SHA-1 / git commit hash",
        re.compile(r'(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])', re.IGNORECASE),
    ),
    (
        "Docker image digest",
        re.compile(r'sha256:[0-9a-f]{56,64}', re.IGNORECASE),
    ),
    (
        "Certificate fingerprint (colon-hex)",
        re.compile(
            r'(?:[0-9A-Fa-f]{2}:){7,}[0-9A-Fa-f]{2}',
        ),
    ),
    (
        "W3C Traceparent",
        re.compile(
            r'00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}',
            re.IGNORECASE,
        ),
    ),
    (
        "Numeric token (>=15 digits)",
        re.compile(r'(?<!\d)\d{15,}(?!\d)'),
    ),
    (
        "Prefixed hex ID",
        re.compile(r'(?:exp|run|trace|span|req|sess|txn|job)_[0-9a-f]{16,}', re.IGNORECASE),
    ),
    (
        "Locale/subtag with embedded hex",
        re.compile(r'[a-z]{2}(?:-[a-z]{1,8})*-[0-9a-f]{12,}', re.IGNORECASE),
    ),
    (
        "BSON ObjectId",
        re.compile(r'(?<![0-9a-f])[0-9a-f]{24}(?![0-9a-f])', re.IGNORECASE),
    ),
    (
        "JWT / static assertion",
        re.compile(
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        ),
    ),
    (
        "CUID",
        re.compile(r'(?<![a-z0-9])c[a-z0-9]{24,}(?![a-z0-9])', re.IGNORECASE),
    ),
]

# Variable-name keywords that indicate the LLM already correctly
# identifies the value as sensitive — no hint needed.
KNOWN_SECRET_VARNAMES = re.compile(
    r'(?:key|token|secret|password|credential|passwd|api_key|auth)',
    re.IGNORECASE,
)

# Regex to extract assignment-like patterns from diff lines:
#   VARNAME = "value"  or  "varname": "value"  or  VARNAME = 'value'
#   Also handles: VARNAME = 12345 (bare numeric)
ASSIGNMENT_RE = re.compile(
    r'''
    (?:^[+]\s*)                          # diff added-line prefix
    (?:
        ([A-Za-z_][A-Za-z0-9_]*)         # Python variable name
        \s*=\s*                           # assignment
    |
        ["\']([A-Za-z_][A-Za-z0-9_]*)["\']  # dict key in quotes
        \s*[:=]\s*                        # colon or equals
    )
    (?:
        ["\'](.+?)["\']                  # quoted string value
    |
        (\d{10,})                        # bare numeric value (>=10 digits)
    )
    ''',
    re.VERBOSE,
)


class G6FormatFamiliarity(Guardrail):
    """
    G6: Format-Familiarity Pre-Scan.

    Pre-LLM hint mechanism that extracts candidate strings matching known
    non-secret formats from the code diff and injects a structured hint
    into the LLM prompt to request explicit evaluation.

    Status: exploratory prototype, evaluated on isolated hard-sample set.
    """

    @property
    def name(self) -> str:
        return "G6"

    def get_prompt(self) -> str:
        """
        Return the base G6 awareness prompt (static part).

        This is appended to the system prompt and provides general
        awareness. The dynamic hint (with specific candidates) is
        generated separately via get_hint().
        """
        return (
            "\n## G6 — Format-Familiarity Bias Check\n"
            "IMPORTANT: Secrets can be disguised as values that LOOK LIKE "
            "well-known non-secret formats. A hardcoded string that matches "
            "a UUID, SHA hash, git commit, Docker digest, certificate "
            "fingerprint, W3C trace ID, or numeric identifier format is NOT "
            "automatically safe. Always evaluate whether a high-entropy "
            "hardcoded string could be a credential, REGARDLESS of its "
            "format or variable name.\n"
        )

    def get_prompt_forced_reasoning(self) -> str:
        """
        Return a stronger G6 system prompt for the forced-reasoning condition.

        Unlike get_prompt() (hint-only awareness), this version explicitly
        instructs the LLM that format match alone is NEVER sufficient to
        dismiss a value, and that variable names can be deliberately
        misleading.

        Schema-compatible: does NOT require additional JSON fields beyond
        the standard schema. Contrastive reasoning happens internally
        before the LLM forms its JSON decision.
        """
        return (
            "\n## G6 — Format-Familiarity Bias Guard (Forced Reasoning)\n"
            "CRITICAL RULE: A hardcoded high-entropy string that matches a "
            "well-known format (UUID, SHA hash, git commit, Docker digest, "
            "certificate fingerprint, W3C trace ID, numeric ID, prefixed hex "
            "ID) is NOT safe simply because of its format. Variable names "
            "are freely chosen by developers and CAN be deliberately "
            "misleading — a value named 'TRACE_ID' or 'INTEGRITY_HASH' may "
            "still be a hardcoded credential.\n\n"
            "When a G6 FORMAT-FAMILIARITY ALERT is present in the user "
            "prompt, you MUST internally consider BOTH sides for each "
            "flagged candidate BEFORE forming your decision: "
            "(1) why it might be a genuine non-secret identifier, "
            "(2) why it might STILL be a hardcoded credential despite its "
            "format/name. Reflect on both arguments, then set "
            "'pred_has_secret' accordingly. If in doubt, flag the value.\n"
            "IMPORTANT: Do NOT add any extra fields to your JSON response. "
            "Use ONLY the standard output schema fields.\n"
        )

    def get_forced_reasoning_hint(self, candidates: List[FormatCandidate]) -> str:
        """
        Build the forced-reasoning hint (schema-compatible version).

        Instructs the LLM to perform contrastive reasoning internally
        for each candidate before forming its JSON decision. Does NOT
        require any additional JSON fields, so G5 schema validation passes.

        Args:
            candidates: List of FormatCandidate objects from extract_candidates()

        Returns:
            Hint string to append to the user prompt, or empty string if
            no candidates were found.
        """
        if not candidates:
            return ""

        lines = [
            "\n--- G6 FORMAT-FAMILIARITY ALERT (FORCED REASONING) ---",
            "",
            "The following hardcoded values match known non-secret formats.",
            "Before producing your JSON response, you MUST internally "
            "consider BOTH sides for EACH candidate:",
            "",
            "For each candidate, think about:",
            "  (a) Why it might be a genuine non-secret identifier",
            "  (b) Why it might STILL be a hardcoded credential despite its "
            "format/variable name — consider at least one concrete reason "
            "even if you believe it is non-secret",
            "  (c) Whether the variable name could be deliberately misleading",
            "",
            "RULES:",
            "- You MUST consider BOTH sides for every candidate before "
            "deciding.",
            "- Consider: What if the variable name is a decoy to disguise a "
            "credential as something harmless?",
            "- If ANY candidate is uncertain or likely a secret, set "
            "pred_has_secret to true.",
            "- Do NOT add extra fields to your JSON. Use only the standard "
            "output schema.",
            "",
            "Candidates:",
            "",
        ]

        for i, c in enumerate(candidates, 1):
            loc = f" (line {c.line_number})" if c.line_number else ""
            var = f" in variable '{c.variable_name}'" if c.variable_name else ""
            truncated = c.value[:12] + "..." if len(c.value) > 15 else c.value
            lines.append(f"  {i}. Format: {c.format_name}{var}{loc}")
            lines.append(f"     Value preview: {truncated}")
            lines.append("")

        lines.append("--- END G6 ALERT ---\n")

        return "\n".join(lines)

    def get_hint(self, candidates: List[FormatCandidate]) -> str:
        """
        Build the dynamic hint listing specific candidates found in the diff.

        This is injected into the user prompt (not system prompt) so the
        LLM evaluates each candidate explicitly.

        Args:
            candidates: List of FormatCandidate objects from extract_candidates()

        Returns:
            Hint string to append to the user prompt, or empty string if
            no candidates were found.
        """
        if not candidates:
            return ""

        lines = [
            "\n--- G6 FORMAT-FAMILIARITY ALERT ---",
            "The following hardcoded values match known non-secret formats "
            "but MAY be disguised credentials. For EACH value below, you MUST "
            "explicitly evaluate whether it is a genuine non-secret identifier "
            "or a hardcoded credential in the given context:",
            "",
        ]

        for i, c in enumerate(candidates, 1):
            loc = f" (line {c.line_number})" if c.line_number else ""
            var = f" in variable '{c.variable_name}'" if c.variable_name else ""
            lines.append(
                f"  {i}. Format: {c.format_name}{var}{loc}"
            )
            # Show truncated value to avoid leaking full secret
            truncated = c.value[:12] + "..." if len(c.value) > 15 else c.value
            lines.append(f"     Value preview: {truncated}")
            lines.append("")

        lines.append(
            "For each candidate: Does the variable name, surrounding code, "
            "and assignment context confirm this is genuinely a non-secret "
            "identifier? Or could it be a hardcoded credential?"
        )
        lines.append("--- END G6 ALERT ---\n")

        return "\n".join(lines)

    def extract_candidates(
        self,
        diff_text: str,
        skip_known_secret_names: bool = True,
    ) -> List[FormatCandidate]:
        """
        Extract candidate strings from a code diff that match known
        non-secret formats.

        Args:
            diff_text: The raw diff text (before line numbering)
            skip_known_secret_names: If True, skip candidates whose
                variable name already contains secret-indicating keywords
                (KEY, TOKEN, SECRET, PASSWORD, etc.) since the LLM
                typically catches these correctly.

        Returns:
            List of FormatCandidate objects.
        """
        candidates = []
        seen_values = set()

        lines = diff_text.split('\n')
        for line_idx, line in enumerate(lines):
            # Only look at added lines (diff "+..." lines)
            if not line.startswith('+'):
                continue

            # Try to extract variable=value assignments
            match = ASSIGNMENT_RE.match(line)
            if not match:
                # Check for values embedded in longer expressions
                # (e.g., URL with embedded token, format strings)
                self._check_inline_formats(
                    line, line_idx + 1, candidates, seen_values,
                )
                continue

            var_name = match.group(1) or match.group(2)
            value = match.group(3) or match.group(4)  # group(4) = bare numeric

            if not value or len(value) < 8:
                # Even if assignment value is short, check inline formats
                # for embedded patterns (Docker digest URLs, etc.)
                self._check_inline_formats(
                    line, line_idx + 1, candidates, seen_values,
                )
                continue

            # Skip if variable name already signals a secret
            if skip_known_secret_names and var_name:
                if KNOWN_SECRET_VARNAMES.search(var_name):
                    continue

            # Check value against format patterns
            matched = False
            for fmt_name, pattern in FORMAT_PATTERNS:
                if pattern.search(value):
                    if value not in seen_values:
                        seen_values.add(value)
                        candidates.append(FormatCandidate(
                            value=value,
                            format_name=fmt_name,
                            line_number=line_idx + 1,
                            variable_name=var_name,
                        ))
                    matched = True
                    break  # one format match per value is enough

            # If assignment value didn't match, still check for inline
            # patterns (e.g., Docker digest embedded in image URL)
            if not matched:
                self._check_inline_formats(
                    line, line_idx + 1, candidates, seen_values,
                )

        return candidates

    def _check_inline_formats(
        self,
        line: str,
        line_number: int,
        candidates: List[FormatCandidate],
        seen_values: set,
    ) -> None:
        """Check for format-matching values in non-assignment lines."""
        # Look for quoted strings in the line
        for quoted_match in re.finditer(r'["\']([^"\']{15,})["\']', line):
            value = quoted_match.group(1)
            if value in seen_values:
                continue

            for fmt_name, pattern in FORMAT_PATTERNS:
                # Use search() for patterns that can be embedded in larger
                # strings (Docker digests in URLs, locale tags, etc.)
                if pattern.search(value):
                    seen_values.add(value)
                    candidates.append(FormatCandidate(
                        value=value,
                        format_name=fmt_name,
                        line_number=line_number,
                        variable_name=None,
                    ))
                    break

    def validate_output(self, llm_output: dict) -> bool:
        """
        G6 is a pre-LLM guardrail — it does not validate output.

        This method exists for interface compliance with the Guardrail
        base class. It always returns True (G6 never fails post-hoc).
        """
        return True

    def get_config(self) -> GuardrailConfig:
        return GuardrailConfig(name=self.name, enabled=True)
