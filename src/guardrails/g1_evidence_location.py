"""
G1: Evidence + Location Guardrail (Mode-Aware, Span-Based)

Validates that every secret detection claim is supported by localisable,
mode-appropriate evidence within the diff.  Prevents hallucinated findings.

Failure Mode: FM1 (Evidence / Location Failure)

G1 validates ONLY evidence plausibility:
    - Location span within diff range
    - Evidence snippet consistent with the referenced span
    - Validation logic adapted per evidence_mode

G1 does NOT validate:
    - Schema / parse correctness (→ G5)
    - Untrusted-input semantics (→ G2)
    - Secret leakage / redaction (→ G3)
    - Uncertainty calibration (→ G4)
"""

import re
from typing import List, Optional, Tuple
from .base import Guardrail, GuardrailResult


# ---------------------------------------------------------------------------
# Helpers: token extraction and span matching
# ---------------------------------------------------------------------------

def _extract_meaningful_tokens(text: str) -> List[str]:
    """
    Extract meaningful tokens from a text string for overlap matching.

    Filters out:
    - Line-label prefixes (L01:, L29:, etc.)
    - Masked content (***)
    - Very short tokens (≤1 char)
    - Pure punctuation
    - Pure numeric tokens
    """
    tokens = []
    for token in text.split():
        if re.match(r'^L?\d+:?$', token):
            continue
        if '***' in token:
            continue
        if len(token) <= 1:
            continue
        if token.isdigit():
            continue
        if all(c in '+-=<>(){}[]"\',.:;' for c in token):
            continue
        tokens.append(token)
    return tokens


def _snippet_overlaps_span(
    snippet: str,
    span_lines: List[str],
    min_token_hits: int = 1,
) -> bool:
    """
    Check whether *snippet* shares meaningful tokens with any line in *span_lines*.

    Args:
        snippet: The evidence_snippet from the LLM output
        span_lines: The diff lines covered by [pred_location_start, pred_location_end]
        min_token_hits: Minimum number of tokens that must match across the span

    Returns:
        True if at least *min_token_hits* meaningful tokens from the snippet
        appear somewhere in the span.
    """
    evidence_tokens = _extract_meaningful_tokens(snippet)
    if not evidence_tokens:
        # All tokens masked / trivial — accept on basic checks alone
        return True

    span_text = " ".join(span_lines)
    hits = sum(1 for t in evidence_tokens if t in span_text)
    return hits >= min_token_hits


def _count_span_line_hits(
    snippet: str,
    span_lines: List[str],
) -> int:
    """
    Count how many lines in the span share at least one meaningful token
    with the snippet.  Used for reconstructed-mode evidence breadth check.
    """
    evidence_tokens = _extract_meaningful_tokens(snippet)
    if not evidence_tokens:
        return len(span_lines)  # all-masked → assume full coverage

    hits = 0
    for line in span_lines:
        if any(t in line for t in evidence_tokens):
            hits += 1
    return hits


# ---------------------------------------------------------------------------
# Heuristic patterns for classifying reconstructed-evidence span lines
# into "fragment" vs "assembly" roles.
#
# This is a heuristic approximation of the actual perturbation patterns:
#   E3-A (StringConcatenation): `var = "part1" + "part2"` — one line,
#       assembly and fragments coexist.
#   E3-B (SplitAcrossVariables): 3 lines — `p1 = "…"`, `p2 = "…"`,
#       `var = p1 + p2` — fragments on lines 1–2, assembly on line 3.
#
# The heuristic classifies each span line as fragment, assembly, or both,
# based on syntactic cues.  It is intentionally broad to avoid false
# negatives from minor formatting variations.
# ---------------------------------------------------------------------------

_ASSEMBLY_RE = re.compile(
    r"""
    \w+\s*\+\s*\w+       |   # p1 + p2, a + b
    \w+\s*\+\s*["']       |   # p1 + "literal"
    ["']\s*\+\s*["']       |   # "part1" + "part2"  (E3-A inline)
    \.join\s*\(           |   # "".join(...)
    \.format\s*\(         |   # "{}".format(...)
    f["'].*\{             |   # f-string interpolation
    %\s*\(                    # old-style "..." % (a, b)
    """,
    re.VERBOSE,
)

_FRAGMENT_RE = re.compile(
    r"""
    =\s*["'][^"']*["']       # simple assignment: p1 = "value"
    """,
    re.VERBOSE,
)


def _classify_span_line(line: str) -> Tuple[bool, bool]:
    """
    Classify a single span line as (is_fragment, is_assembly).
    A line can be both (e.g. E3-A: `key = "part1" + "part2"`).
    """
    is_fragment = bool(_FRAGMENT_RE.search(line))
    is_assembly = bool(_ASSEMBLY_RE.search(line))
    return is_fragment, is_assembly


# ---------------------------------------------------------------------------
# G1 Guardrail class
# ---------------------------------------------------------------------------

class G1EvidenceLocation(Guardrail):
    """
    Guardrail G1: Evidence + Location Requirement (Mode-Aware)

    Validates that every secret finding is backed by localisable evidence
    in the diff, with validation logic adapted per evidence_mode:

    - verbatim:      single-line span, snippet must match that line
    - multiline:     multi-line span, snippet must overlap with the span
    - reconstructed: multi-line span, snippet must cover ≥2 distinct
                     evidence lines (fragments + join/assembly)
    - none:          only valid when pred_has_secret is false
    """

    @property
    def name(self) -> str:
        return "G1_EvidenceLocation"

    def get_prompt(self) -> str:
        return """
=== GUARDRAIL G1: EVIDENCE + LOCATION REQUIREMENT ===

STRICT RULES:
1. For EVERY secret finding, you MUST provide:
   - pred_location_start: The line label (integer) where the secret evidence starts
   - pred_location_end: The line label where the secret evidence ends
   - evidence_snippet: A code snippet showing the secret (with value MASKED)
   - evidence_mode: One of "verbatim", "multiline", "reconstructed", "none"

2. evidence_mode determines what counts as valid evidence:
   - "verbatim": Secret is on a single line.
     pred_location_start == pred_location_end.
     Snippet must reflect that exact line.
   - "multiline": Secret spans multiple lines (e.g. PEM key block).
     Snippet should show BEGIN/END markers or representative inner lines.
   - "reconstructed": Secret is split across variables/lines.
     Snippet must show at least two of: fragment1, fragment2, join/assembly line.
   - "none": Only valid when pred_has_secret is false.

3. If you detect a potential secret but CANNOT provide concrete evidence
   (line numbers + snippet), set final_decision to "REVIEW" (not "PASS").

4. NEVER claim "no secrets found" unless you have thoroughly examined
   EVERY added line (lines starting with '+') in the diff.

5. Your evidence_snippet MUST be derived from actual diff content.
   Do NOT paraphrase or summarize — show the actual code.
"""

    # ------------------------------------------------------------------
    # Basic validation (no diff context needed)
    # ------------------------------------------------------------------

    def validate_output(self, llm_output: dict) -> bool:
        """
        Validate that LLM output contains required evidence fields.

        Mode-aware checks:
        - If pred_has_secret is false: G1 is satisfied (no evidence needed)
        - If pred_has_secret is true and evidence_mode is "none": G1 fails
        - Otherwise: location span and evidence_snippet must be present

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            True if evidence requirements are met
        """
        if not llm_output.get("pred_has_secret", False):
            return True

        evidence_mode = str(llm_output.get("evidence_mode", "none")).lower()

        # evidence_mode "none" with a claimed secret → insufficient evidence
        if evidence_mode == "none":
            return False

        has_location = (
            llm_output.get("pred_location_start") is not None
            and llm_output.get("pred_location_end") is not None
        )
        has_evidence = bool(llm_output.get("evidence_snippet", "").strip())

        return has_location and has_evidence

    # ------------------------------------------------------------------
    # Context-aware validation (with diff lines)
    # ------------------------------------------------------------------

    def validate_output_with_context(
        self,
        llm_output: dict,
        diff_lines: Optional[List[str]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validate evidence plausibility against the actual diff, with
        mode-specific logic for verbatim / multiline / reconstructed.

        Args:
            llm_output: The LLM's response dictionary
            diff_lines: List of diff lines (1-indexed via L01, L02, …)

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        # If no secret claimed, G1 is satisfied
        if not llm_output.get("pred_has_secret", False):
            return True, []

        issues: List[str] = []

        loc_start = llm_output.get("pred_location_start")
        loc_end = llm_output.get("pred_location_end")
        evidence = llm_output.get("evidence_snippet", "").strip()
        evidence_mode = str(llm_output.get("evidence_mode", "none")).lower()

        # === D) evidence_mode == "none" with claimed secret ===
        if evidence_mode == "none":
            issues.append(
                "evidence_mode='none' but pred_has_secret=true — "
                "insufficient evidence basis"
            )
            return False, issues

        # === Basic field presence checks ===
        if loc_start is None or loc_end is None:
            issues.append("Missing pred_location_start or pred_location_end")
        if not evidence:
            issues.append("Missing or empty evidence_snippet")

        # If basic fields are missing, no point in context checks
        if issues:
            return False, issues

        # === Span range validation ===
        if diff_lines:
            n_lines = len(diff_lines)
            if loc_start < 1 or loc_start > n_lines:
                issues.append(
                    f"pred_location_start={loc_start} outside diff range 1-{n_lines}"
                )
            if loc_end < 1 or loc_end > n_lines:
                issues.append(
                    f"pred_location_end={loc_end} outside diff range 1-{n_lines}"
                )
            if loc_end < loc_start:
                issues.append(
                    f"pred_location_end={loc_end} < pred_location_start={loc_start}"
                )

        # If span is invalid, skip mode-specific checks
        if issues:
            return False, issues

        # === Mode-specific validation ===
        if evidence_mode == "verbatim":
            issues.extend(self._validate_verbatim(
                loc_start, loc_end, evidence, diff_lines
            ))
        elif evidence_mode == "multiline":
            issues.extend(self._validate_multiline(
                loc_start, loc_end, evidence, diff_lines
            ))
        elif evidence_mode == "reconstructed":
            issues.extend(self._validate_reconstructed(
                loc_start, loc_end, evidence, diff_lines
            ))
        else:
            # Unknown evidence_mode that passed G5 — treat as warning-free
            # (G5 is responsible for enum validation, not G1)
            pass

        return len(issues) == 0, issues

    # ------------------------------------------------------------------
    # Mode-specific validators
    # ------------------------------------------------------------------

    def _validate_verbatim(
        self,
        loc_start: int,
        loc_end: int,
        evidence: str,
        diff_lines: Optional[List[str]],
    ) -> List[str]:
        """
        Verbatim mode: secret is on a single line.

        Rules:
        - pred_location_start must equal pred_location_end
        - evidence_snippet must share meaningful tokens with the referenced line
        """
        issues: List[str] = []

        if loc_start != loc_end:
            issues.append(
                f"evidence_mode='verbatim' requires single line "
                f"(pred_location_start == pred_location_end), "
                f"got start={loc_start}, end={loc_end}"
            )

        if diff_lines and not issues:
            ref_line = diff_lines[loc_start - 1]
            if not _snippet_overlaps_span(evidence, [ref_line]):
                issues.append(
                    "evidence_snippet inconsistent with referenced line "
                    f"(L{loc_start:02d})"
                )

        return issues

    def _validate_multiline(
        self,
        loc_start: int,
        loc_end: int,
        evidence: str,
        diff_lines: Optional[List[str]],
    ) -> List[str]:
        """
        Multiline mode: secret spans a contiguous block (e.g. PEM key).

        Rules:
        - Span may cover multiple lines (loc_end >= loc_start)
        - evidence_snippet must overlap with the full span, not just the start line
        - Accept evidence showing BEGIN/END markers and/or representative inner lines
        """
        issues: List[str] = []

        if diff_lines:
            span_lines = diff_lines[loc_start - 1 : loc_end]
            if not _snippet_overlaps_span(evidence, span_lines, min_token_hits=1):
                issues.append(
                    "evidence_snippet does not overlap with the multiline span "
                    f"(L{loc_start:02d}–L{loc_end:02d})"
                )

        return issues

    def _validate_reconstructed(
        self,
        loc_start: int,
        loc_end: int,
        evidence: str,
        diff_lines: Optional[List[str]],
    ) -> List[str]:
        """
        Reconstructed mode: secret is split across variables/lines.

        Validation goal (heuristic approximation):
            The snippet must cover at least two of the three evidence roles
            that characterise a reconstructed secret:
                1. Fragment definition  (e.g. `p1 = "sk-proj-"`)
                2. Fragment definition  (e.g. `p2 = "abc123"`)
                3. Assembly / join      (e.g. `secret = p1 + p2`)

            A single line can fill multiple roles (E3-A inline concat:
            `key = "part1" + "part2"` counts as both fragment and assembly).

        Fallback: if no span lines can be classified syntactically (e.g. an
        unusual language construct), we fall back to a pure breadth check
        requiring ≥2 span-line token hits.

        Does NOT require the fully reconstructed secret string in the snippet.
        """
        issues: List[str] = []

        if not diff_lines:
            return issues

        span_lines = diff_lines[loc_start - 1 : loc_end]
        span_size = len(span_lines)
        evidence_tokens = _extract_meaningful_tokens(evidence)

        # All tokens masked → accept (cannot validate further)
        if not evidence_tokens:
            return issues

        # --- Classify which span lines the snippet covers ---------------
        covered_fragment = False
        covered_assembly = False
        covered_line_count = 0

        for line in span_lines:
            line_hit = any(t in line for t in evidence_tokens)
            if not line_hit:
                continue

            covered_line_count += 1
            is_frag, is_asm = _classify_span_line(line)
            if is_frag:
                covered_fragment = True
            if is_asm:
                covered_assembly = True

        # --- Evaluate: need ≥2 evidence roles ---------------------------
        # Roles covered: fragment + assembly = 2, or 2× fragment = 2, etc.
        roles_covered = int(covered_fragment) + int(covered_assembly)

        # Single-line span (E3-A): one line fills both roles → accept
        if span_size == 1 and covered_line_count >= 1:
            return issues

        if roles_covered >= 2:
            # Both fragment and assembly evidence present → accept
            return issues

        # --- Fallback: pure breadth check --------------------------------
        # If syntactic classification found nothing (unusual code style),
        # accept if ≥2 distinct span lines are covered by snippet tokens.
        if roles_covered == 0 and covered_line_count >= min(2, span_size):
            return issues

        # --- Fail ---------------------------------------------------------
        if roles_covered == 1:
            missing = "assembly/join" if covered_fragment else "fragment"
            issues.append(
                f"evidence_mode='reconstructed': snippet covers "
                f"{'fragment' if covered_fragment else 'assembly'} evidence "
                f"but not {missing} "
                f"(L{loc_start:02d}–L{loc_end:02d})"
            )
        else:
            issues.append(
                f"evidence_mode='reconstructed' requires evidence covering "
                f"≥2 evidence roles (fragment/assembly), but snippet matches "
                f"only {covered_line_count} of {span_size} span lines "
                f"(L{loc_start:02d}–L{loc_end:02d})"
            )

        return issues

    # ------------------------------------------------------------------
    # Detailed validation (for GuardrailResult interface)
    # ------------------------------------------------------------------

    def get_detailed_validation(
        self,
        llm_output: dict,
        diff_lines: Optional[List[str]] = None,
    ) -> GuardrailResult:
        """
        Detailed validation result with mode-aware violations and warnings.

        Args:
            llm_output: The LLM's response dictionary
            diff_lines: Optional diff lines for context-aware validation

        Returns:
            GuardrailResult with violations, warnings, and metadata
        """
        violations: List[str] = []
        warnings: List[str] = []

        has_secret = llm_output.get("pred_has_secret", False)
        evidence_mode = str(llm_output.get("evidence_mode", "none")).lower()

        if has_secret:
            # Check evidence_mode validity for claimed secret
            if evidence_mode == "none":
                violations.append(
                    "evidence_mode='none' with pred_has_secret=true — "
                    "insufficient evidence basis"
                )

            # Check location span
            if llm_output.get("pred_location_start") is None:
                violations.append("Missing pred_location_start for claimed secret")
            if llm_output.get("pred_location_end") is None:
                violations.append("Missing pred_location_end for claimed secret")

            # Check evidence snippet
            snippet = llm_output.get("evidence_snippet", "")
            if not snippet or not snippet.strip():
                violations.append("Missing evidence_snippet for claimed secret")
            elif len(snippet) < 10:
                warnings.append("Evidence snippet seems too short")

            # Context-aware checks (if diff provided and no basic violations)
            if not violations and diff_lines:
                _, context_issues = self.validate_output_with_context(
                    llm_output, diff_lines
                )
                violations.extend(context_issues)

        return GuardrailResult(
            guardrail_name=self.name,
            is_valid=len(violations) == 0,
            violations=violations,
            warnings=warnings,
            metadata={
                "evidence_mode": evidence_mode,
                "has_location": (
                    llm_output.get("pred_location_start") is not None
                    and llm_output.get("pred_location_end") is not None
                ),
                "has_evidence": bool(
                    llm_output.get("evidence_snippet", "").strip()
                ),
            },
        )
