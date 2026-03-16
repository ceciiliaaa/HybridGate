"""
G3: Output Leakage Guardrail (Fail-Closed)

Addresses: FM3 (Secret Leakage in Output)

G3 is a fail-closed output leakage guardrail that detects, mitigates, and
routes secret leaks in the final LLM output.  It operates on ALL user-visible
string fields of the structured output — not just a single field.

Three-layer architecture:
1. DETECTION — deterministic rules check the serialised output for:
   A) Explicit secret / credential patterns (PEM, AWS, Stripe, GitHub, …)
   B) Longer unmaskierte secret-like spans (>8 consecutive non-masked chars
      with credential-like context)
   C) Echo / near-echo of sensitive candidates extracted from code_context
      or evidence_snippet
   D) Reconstructable leaks (multiple fragments that together reveal a secret)

2. MITIGATION — exactly one auto-redact attempt:
   Replace detected leak spans with '***REDACTED***'

3. FAIL-CLOSED ROUTING — if leaks persist after redaction → REVIEW

IMPORTANT: G3 does NOT access ground truth.  It works purely on the output
plus optional context inputs (code_context, evidence_snippet, …).

G3 does NOT validate:
    - Evidence quality / location (→ G1)
    - Untrusted-input influence  (→ G2)
    - Uncertainty / abstention   (→ G4)
    - Schema / parse correctness (→ G5)
"""

import json
import math
import re
from copy import deepcopy
from typing import Dict, List, Optional, Set, Tuple, Any

from .base import Guardrail, GuardrailResult


# ---------------------------------------------------------------------------
# Detection: A) Explicit secret / credential patterns
# ---------------------------------------------------------------------------

# Each tuple: (pattern_name, compiled_regex)
# These patterns target unmasked, full-length credentials.
_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # AWS access keys (always 20 chars, start with AKIA)
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),

    # AWS secret keys (40 chars base64-ish)
    ("aws_secret_key", re.compile(
        r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
    )),

    # Stripe keys (live and test)
    ("stripe_key", re.compile(r"(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{20,}")),

    # GitHub personal access tokens (classic and fine-grained)
    ("github_pat", re.compile(r"gh[pous]_[a-zA-Z0-9]{36,}")),

    # GitHub fine-grained PATs
    ("github_fine_grained", re.compile(r"github_pat_[a-zA-Z0-9_]{20,}")),

    # GitLab PATs
    ("gitlab_pat", re.compile(r"glpat-[a-zA-Z0-9\-]{20,}")),

    # Slack tokens
    ("slack_token", re.compile(r"xox[baprs]-[a-zA-Z0-9\-]{10,}")),

    # Slack webhook URLs
    ("slack_webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
    )),

    # OpenAI API keys
    ("openai_key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),

    # Google API keys
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),

    # PEM private key blocks
    ("pem_private_key", re.compile(
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
    )),

    # Generic bearer / auth tokens (long base64-like strings after known keys)
    ("bearer_token", re.compile(
        r"(?:Bearer|Authorization|token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_./+=]{32,})['\"]?"
    )),

    # Connection strings with password
    ("connection_string", re.compile(
        r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)"
        r"://[^:]+:([^@\s]{8,})@",
        re.IGNORECASE,
    )),

    # Generic password assignments (value ≥8 chars, not masked)
    ("password_assignment", re.compile(
        r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        re.IGNORECASE,
    )),

    # Generic API key assignments (value ≥16 chars)
    ("api_key_assignment", re.compile(
        r"(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
        re.IGNORECASE,
    )),

    # Heroku API key
    ("heroku_key", re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )),
]

# Mask indicators — if the matched span contains these, it's already masked
_MASK_INDICATORS = re.compile(
    r"\*{3,}|REDACTED|MASKED|<REMOVED>|\[HIDDEN\]|\.{4,}", re.IGNORECASE
)


def _detect_secret_patterns(text: str) -> List[Dict[str, Any]]:
    """
    Detect explicit secret / credential patterns in text.

    Returns a list of findings, each with:
        - pattern_name: str
        - matched_text: str
        - start: int  (position in text)
        - end: int
    """
    findings: List[Dict[str, Any]] = []
    if not text:
        return findings

    for pattern_name, regex in _SECRET_PATTERNS:
        for m in regex.finditer(text):
            matched = m.group(0)

            # Skip already-masked values
            if _MASK_INDICATORS.search(matched):
                continue

            # For patterns with capture groups, the secret is group(1)
            secret_part = m.group(1) if m.lastindex and m.lastindex >= 1 else matched
            if _MASK_INDICATORS.search(secret_part):
                continue

            findings.append({
                "pattern_name": pattern_name,
                "matched_text": matched,
                "start": m.start(),
                "end": m.end(),
            })

    return findings


# ---------------------------------------------------------------------------
# Detection: B) Longer unmaskierte secret-like spans
# ---------------------------------------------------------------------------

# High-entropy span: ≥10 consecutive non-whitespace chars that look
# credential-like (mixed case/digits/symbols, not a normal word)
_CREDENTIAL_SPAN_RE = re.compile(
    r"(?<![A-Za-z0-9_])"          # word boundary
    r"([A-Za-z0-9\-_/+=.]{10,})"  # candidate span
    r"(?![A-Za-z0-9_])"           # word boundary
)

# Common false-positive words / paths to exclude
_FP_SPAN_WORDS = {
    "evidence_snippet", "pred_has_secret", "pred_secret_type",
    "pred_location_start", "pred_location_end", "evidence_mode",
    "used_untrusted_input", "final_decision", "uncertainty_flags",
    "decision_basis", "untrusted_input_role", "untrusted_effect",
    "placeholder", "connection", "application", "environment",
    "development", "production", "configuration", "credentials",
    "certificate", "middleware", "repository", "controller",
    "dockerfile", "requirements", "dependencies",
}


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _detect_sensitive_spans(text: str, min_entropy: float = 3.0) -> List[Dict[str, Any]]:
    """
    Detect longer unmaskierte secret-like spans with credential context.

    Only fires on spans that:
    - Are ≥10 characters long
    - Have Shannon entropy ≥ min_entropy (default 3.0 bits/char)
    - Are not common English words or JSON field names
    - Are not already masked

    Returns list of findings.
    """
    findings: List[Dict[str, Any]] = []
    if not text:
        return findings

    for m in _CREDENTIAL_SPAN_RE.finditer(text):
        span = m.group(1)

        # Skip masked
        if _MASK_INDICATORS.search(span):
            continue

        # Skip common words / field names
        if span.lower() in _FP_SPAN_WORDS:
            continue

        # Skip all-lowercase plain English words (simple heuristic)
        if span.isalpha() and span.islower():
            continue

        # Skip file paths / URLs (contain slashes or dots with path-like structure)
        if span.count("/") >= 1 and "." in span:
            continue
        if span.count("/") > 2:
            continue

        # Entropy check
        entropy = _shannon_entropy(span)
        if entropy < min_entropy:
            continue

        findings.append({
            "pattern_name": "high_entropy_span",
            "matched_text": span,
            "start": m.start(1),
            "end": m.end(1),
            "entropy": round(entropy, 2),
        })

    return findings


# ---------------------------------------------------------------------------
# Detection: C) Echo / near-echo of sensitive candidates
# ---------------------------------------------------------------------------

def _extract_candidate_secrets(
    code_context: str = "",
    evidence_snippet: str = "",
    pred_secret_type: str = "",
) -> List[str]:
    """
    Heuristically extract candidate secret values from context inputs.

    These are risky literals that G3 should check the output does NOT echo.
    G3 does NOT use ground truth — it extracts candidates from the same
    inputs available to the LLM.

    Sources:
    - Quoted string literals from code_context (≥8 chars)
    - Quoted string literals from evidence_snippet (≥8 chars)
    """
    candidates: Set[str] = set()

    for source in [code_context, evidence_snippet]:
        if not source:
            continue
        # Extract single- and double-quoted strings
        for m in re.finditer(r"""['"]((?:[^'"\\]|\\.){8,})['"]""", source):
            val = m.group(1)
            # Skip obviously non-secret values
            val_lower = val.lower()
            if any(kw in val_lower for kw in [
                "example", "placeholder", "your_", "insert_",
                "todo", "fixme", "change_me", "replace_me",
            ]):
                continue
            # Skip values that are already masked
            if _MASK_INDICATORS.search(val):
                continue
            candidates.add(val)

    return list(candidates)


def _detect_candidate_echo(
    output_text: str,
    candidates: List[str],
    min_match_len: int = 8,
) -> List[Dict[str, Any]]:
    """
    Detect if the output echoes (or near-echoes) candidate secret values.

    A near-echo is a substring of the candidate (≥min_match_len chars)
    appearing unmaskiert in the output.

    Args:
        output_text: Serialised output to check
        candidates: List of candidate secret strings from context
        min_match_len: Minimum substring length to consider an echo

    Returns:
        List of echo findings.
    """
    findings: List[Dict[str, Any]] = []
    if not output_text or not candidates:
        return findings

    for candidate in candidates:
        if len(candidate) < min_match_len:
            continue

        # Check exact echo
        if candidate in output_text:
            findings.append({
                "pattern_name": "exact_echo",
                "matched_text": candidate,
                "candidate": candidate,
                "start": output_text.index(candidate),
                "end": output_text.index(candidate) + len(candidate),
            })
            continue

        # Check partial echo: sliding window over candidate
        # Only check the "hidden" portion (after first 4 visible chars)
        hidden = candidate[4:] if len(candidate) > 4 else candidate
        if len(hidden) < min_match_len:
            continue

        for length in range(len(hidden), min_match_len - 1, -1):
            found = False
            for start in range(len(hidden) - length + 1):
                substr = hidden[start:start + length]
                if substr in output_text:
                    # Verify it's not inside a masked context
                    idx = output_text.index(substr)
                    context_window = output_text[max(0, idx - 10):idx + len(substr) + 10]
                    if _MASK_INDICATORS.search(context_window):
                        continue
                    findings.append({
                        "pattern_name": "partial_echo",
                        "matched_text": substr,
                        "candidate": candidate,
                        "start": idx,
                        "end": idx + len(substr),
                        "echo_ratio": round(len(substr) / len(candidate), 2),
                    })
                    found = True
                    break
            if found:
                break

    return findings


# ---------------------------------------------------------------------------
# Detection: D) Reconstructable leaks (fragment assembly)
# ---------------------------------------------------------------------------

def _detect_reconstructed_leak(
    output_text: str,
    candidates: List[str],
    min_fragment_len: int = 4,
    min_coverage: float = 0.7,
) -> List[Dict[str, Any]]:
    """
    Detect if multiple fragments in the output can reconstruct a candidate secret.

    Checks if non-overlapping substrings of a candidate each appear in the
    output, covering ≥ min_coverage of the candidate's length.

    Args:
        output_text: Serialised output
        candidates: Candidate secret values
        min_fragment_len: Minimum fragment size to consider
        min_coverage: Fraction of candidate that must be covered by fragments

    Returns:
        List of reconstructable-leak findings.
    """
    findings: List[Dict[str, Any]] = []
    if not output_text or not candidates:
        return findings

    for candidate in candidates:
        if len(candidate) < 8:
            continue

        # Find all non-overlapping fragments of the candidate in the output
        covered = 0
        fragments_found = []
        pos = 0
        while pos < len(candidate):
            best_len = 0
            # Try longest fragment first
            for frag_len in range(len(candidate) - pos, min_fragment_len - 1, -1):
                frag = candidate[pos:pos + frag_len]
                if frag in output_text:
                    # Skip if fragment appears inside a masked zone
                    idx = output_text.index(frag)
                    ctx = output_text[max(0, idx - 5):idx + len(frag) + 5]
                    if _MASK_INDICATORS.search(ctx):
                        continue
                    best_len = frag_len
                    fragments_found.append(frag)
                    covered += frag_len
                    break
            pos += max(best_len, 1)

        coverage = covered / len(candidate) if len(candidate) > 0 else 0.0

        if coverage >= min_coverage and len(fragments_found) >= 2:
            findings.append({
                "pattern_name": "reconstructed_leak",
                "candidate": candidate,
                "fragments": fragments_found,
                "coverage": round(coverage, 2),
            })

    return findings


# ---------------------------------------------------------------------------
# Output field extraction
# ---------------------------------------------------------------------------

# Fields to scan for leaks — all user-visible string fields in the output
_OUTPUT_STRING_FIELDS = [
    "evidence_snippet",
    "pred_secret_type",
    "evidence_mode",
    "final_decision",
    "decision_basis",
    "untrusted_input_role",
    "untrusted_effect",
]


def _get_scannable_text(llm_output: dict) -> str:
    """
    Serialise all user-visible output fields into a single text for scanning.

    Scans all string-valued fields plus uncertainty_flags list items.
    Does NOT include internal metadata fields.
    """
    parts: List[str] = []

    for field in _OUTPUT_STRING_FIELDS:
        val = llm_output.get(field)
        if isinstance(val, str) and val:
            parts.append(val)

    # uncertainty_flags is a list of strings
    flags = llm_output.get("uncertainty_flags")
    if isinstance(flags, list):
        for f in flags:
            if isinstance(f, str):
                parts.append(f)

    return " ".join(parts)


def _get_full_output_text(llm_output: dict) -> str:
    """
    Full JSON serialisation of the output for comprehensive scanning.

    Used as fallback to catch leaks in any field, including unexpected ones.
    """
    return json.dumps(llm_output, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Mitigation: auto-redact
# ---------------------------------------------------------------------------

_REDACTION_PLACEHOLDER = "***REDACTED***"


def _sanitize_output(
    llm_output: dict,
    findings: List[Dict[str, Any]],
) -> dict:
    """
    Auto-redact detected leak spans in the output.

    Replaces matched text in all string fields with _REDACTION_PLACEHOLDER.
    Returns a deep copy — does not mutate the original.

    Args:
        llm_output: Original parsed output
        findings: List of leak findings from detection

    Returns:
        Sanitised copy of the output
    """
    if not findings:
        return llm_output

    sanitised = deepcopy(llm_output)

    # Collect all text spans to redact from findings
    redact_strings: Set[str] = set()
    for f in findings:
        # Standard findings: matched_text
        matched = f.get("matched_text", "")
        if matched and len(matched) >= 4:
            redact_strings.add(matched)

        # Reconstructed leak findings: individual fragments
        fragments = f.get("fragments")
        if isinstance(fragments, list):
            for frag in fragments:
                if isinstance(frag, str) and len(frag) >= 4:
                    redact_strings.add(frag)

    if not redact_strings:
        return sanitised

    # Sort by length (longest first) to avoid partial replacements
    sorted_redacts = sorted(redact_strings, key=len, reverse=True)

    def _redact_value(val: str) -> str:
        for r in sorted_redacts:
            val = val.replace(r, _REDACTION_PLACEHOLDER)
        return val

    # Redact in all string fields
    for key, val in sanitised.items():
        if isinstance(val, str):
            sanitised[key] = _redact_value(val)
        elif isinstance(val, list):
            sanitised[key] = [
                _redact_value(item) if isinstance(item, str) else item
                for item in val
            ]

    return sanitised


# ---------------------------------------------------------------------------
# Detection orchestrator
# ---------------------------------------------------------------------------

def _run_detection(
    llm_output: dict,
    guardrail_context: dict = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Run all detection layers on the output.

    Args:
        llm_output: Parsed LLM output
        guardrail_context: Optional dict with code_context, evidence_snippet, etc.

    Returns:
        Tuple of (all_findings, g3_flags)
    """
    if guardrail_context is None:
        guardrail_context = {}

    all_findings: List[Dict[str, Any]] = []
    g3_flags: List[str] = []

    # targeted_text: known string fields (for entropy-span detection, where
    #   JSON field names would cause false positives)
    # full_text: full JSON serialisation (for pattern, echo, and
    #   reconstruction checks — covers unexpected fields too)
    targeted_text = _get_scannable_text(llm_output)
    full_text = _get_full_output_text(llm_output)

    # A) Explicit secret patterns — scan full output
    pattern_findings = _detect_secret_patterns(full_text)
    if pattern_findings:
        all_findings.extend(pattern_findings)
        g3_flags.append("secret_pattern_detected")

    # B) High-entropy sensitive spans — scan targeted fields only
    #    (full JSON has too many field names that are high-entropy-ish)
    span_findings = _detect_sensitive_spans(targeted_text)
    if span_findings:
        all_findings.extend(span_findings)
        g3_flags.append("sensitive_span_detected")

    # C) Candidate echo detection
    code_context = guardrail_context.get("code_context") or ""
    evidence_snippet = llm_output.get("evidence_snippet") or ""
    pred_secret_type = llm_output.get("pred_secret_type") or ""

    candidates = _extract_candidate_secrets(
        code_context=code_context,
        evidence_snippet=evidence_snippet,
        pred_secret_type=pred_secret_type,
    )

    if candidates:
        # Check echo against the full serialised output so that leaks in
        # unexpected or newly added string fields are also caught.
        # Pattern-based checks (A) already run on full_text; echo and
        # reconstruction checks use it too for complete coverage.
        echo_findings = _detect_candidate_echo(full_text, candidates)
        if echo_findings:
            all_findings.extend(echo_findings)
            g3_flags.append("candidate_echo_detected")

        # D) Reconstructed leak detection — also on full serialised output
        reconstructed = _detect_reconstructed_leak(full_text, candidates)
        if reconstructed:
            all_findings.extend(reconstructed)
            g3_flags.append("reconstructed_leak_detected")

    # Deduplicate flags
    g3_flags = list(dict.fromkeys(g3_flags))

    return all_findings, g3_flags


# ---------------------------------------------------------------------------
# G3 Guardrail class
# ---------------------------------------------------------------------------

class G3Redaction(Guardrail):
    """
    Guardrail G3: Output Leakage (Fail-Closed)

    Addresses FM3 (Secret Leakage in Output).

    Three-layer architecture:
    1. DETECTION — pattern + span + echo + reconstruction checks
    2. MITIGATION — auto-redact once
    3. FAIL-CLOSED ROUTING — if leaks persist after redaction → REVIEW

    G3 operates on the final structured output.  It does NOT access
    ground truth — candidate secrets are heuristically extracted from
    code_context and evidence_snippet.
    """

    @property
    def name(self) -> str:
        return "G3_Redaction"

    def get_prompt(self) -> str:
        return """
=== GUARDRAIL G3: REDACTION / NEVER-ECHO POLICY ===

SECURITY RULE - SECRET MASKING:
You must NEVER output a discovered secret value in plain text.

MASKING RULES:
1. Show only the FIRST 4 CHARACTERS of any secret, followed by '***'

   Examples:
   - API key "sk_live_abc123xyz789" → "sk_l***"
   - Password "SuperSecret123!" → "Supe***"
   - Token "ghp_xxxxxxxxxxxx" → "ghp_***"

2. In evidence_snippet, you MAY show the surrounding code context,
   but the SECRET VALUE ITSELF must be masked.

   Good: evidence_snippet: "API_KEY = 'sk_l***'"
   Bad:  evidence_snippet: "API_KEY = 'sk_live_abc123xyz789'"

3. This applies to ALL output fields — evidence_snippet, decision_basis,
   untrusted_effect, and any other text you generate.
   Describe secret types and locations without quoting actual values.

RATIONALE:
- Secrets in LLM output could be logged, cached, or exposed
- Even "test" or "fake" secrets should be treated as real
- Redaction is a defense-in-depth measure
"""

    # ------------------------------------------------------------------
    # Core validation interface (backward compatible)
    # ------------------------------------------------------------------

    def validate_output(self, llm_output: dict) -> bool:
        """
        Basic validation — checks for obvious unmasked secret patterns.

        Backward-compatible interface.  For full detection + mitigation,
        use validate_with_details() instead.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            True if no obvious unmasked secrets found
        """
        full_text = _get_full_output_text(llm_output)
        findings = _detect_secret_patterns(full_text)
        return len(findings) == 0

    # ------------------------------------------------------------------
    # Full detection + mitigation + routing
    # ------------------------------------------------------------------

    def validate_with_details(
        self,
        llm_output: dict,
        guardrail_context: dict = None,
    ) -> Dict[str, Any]:
        """
        Full G3 validation with detection, mitigation, and routing.

        Three-layer process:
        1. Detect leaks in the original output
        2. If found: auto-redact once → re-check
        3. If still leaky after redaction → recommend REVIEW

        Args:
            llm_output: Parsed LLM output dictionary
            guardrail_context: Optional dict with:
                - code_context: str (diff / code for echo detection)

        Returns:
            Dictionary with:
            - g3_triggered: bool (any detection layer fired)
            - leak_detected_initial: bool
            - initial_findings: list (detection findings before mitigation)
            - mitigation_attempted: bool
            - mitigation_succeeded: bool
            - sanitised_output: dict or None (redacted output, if mitigation was attempted)
            - leak_detected_after_mitigation: bool
            - post_mitigation_findings: list
            - g3_flags: list[str]
            - recommended_decision: "REVIEW" or None
        """
        if guardrail_context is None:
            guardrail_context = {}

        # --- Layer 1: Detection ---
        initial_findings, g3_flags = _run_detection(
            llm_output, guardrail_context
        )
        leak_detected_initial = len(initial_findings) > 0

        result = {
            "g3_triggered": leak_detected_initial,
            "leak_detected_initial": leak_detected_initial,
            "initial_findings_count": len(initial_findings),
            "initial_findings": initial_findings,
            "mitigation_attempted": False,
            "mitigation_succeeded": False,
            "sanitised_output": None,
            "leak_detected_after_mitigation": False,
            "post_mitigation_findings_count": 0,
            "post_mitigation_findings": [],
            "g3_flags": g3_flags,
            "recommended_decision": None,
        }

        if not leak_detected_initial:
            return result

        # --- Layer 2: Mitigation (auto-redact once) ---
        result["mitigation_attempted"] = True

        sanitised = _sanitize_output(llm_output, initial_findings)
        result["sanitised_output"] = sanitised

        # Re-run detection on sanitised output
        post_findings, post_flags = _run_detection(
            sanitised, guardrail_context
        )
        result["leak_detected_after_mitigation"] = len(post_findings) > 0
        result["post_mitigation_findings_count"] = len(post_findings)
        result["post_mitigation_findings"] = post_findings

        if len(post_findings) == 0:
            # Mitigation succeeded — no more leaks
            result["mitigation_succeeded"] = True
            g3_flags.append("mitigation_succeeded")
        else:
            # --- Layer 3: Fail-closed → REVIEW ---
            result["mitigation_succeeded"] = False
            g3_flags.append("mitigation_failed")
            result["recommended_decision"] = "REVIEW"

        result["g3_flags"] = list(dict.fromkeys(g3_flags))

        return result

    # ------------------------------------------------------------------
    # Routing interface (for pipeline integration)
    # ------------------------------------------------------------------

    def apply_routing(
        self,
        llm_output: dict,
        original_decision: str,
        guardrail_context: dict = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Apply G3 leakage check with fail-closed routing.

        Args:
            llm_output: Parsed LLM output dictionary
            original_decision: Decision before G3 routing
            guardrail_context: Optional upstream context

        Returns:
            Tuple of (final_decision, metadata_dict)
        """
        details = self.validate_with_details(llm_output, guardrail_context)

        metadata = {
            "g3_triggered": details["g3_triggered"],
            "leak_detected_initial": details["leak_detected_initial"],
            "initial_findings_count": details["initial_findings_count"],
            "mitigation_attempted": details["mitigation_attempted"],
            "mitigation_succeeded": details["mitigation_succeeded"],
            "leak_detected_after_mitigation": details["leak_detected_after_mitigation"],
            "g3_flags": details["g3_flags"],
            "routed_by_guardrail": None,
        }

        if details["recommended_decision"] == "REVIEW":
            metadata["routed_by_guardrail"] = "G3"
            return "REVIEW", metadata

        return original_decision, metadata

    # ------------------------------------------------------------------
    # Detailed validation (GuardrailResult interface)
    # ------------------------------------------------------------------

    def get_detailed_validation(
        self,
        llm_output: dict,
        guardrail_context: dict = None,
    ) -> GuardrailResult:
        """
        Detailed validation result for diagnostics and logging.

        Args:
            llm_output: The LLM's response dictionary
            guardrail_context: Optional upstream context

        Returns:
            GuardrailResult with violations, warnings, and metadata
        """
        details = self.validate_with_details(llm_output, guardrail_context)

        violations = []
        warnings = []

        if details["leak_detected_initial"]:
            count = details["initial_findings_count"]
            violations.append(
                f"G3_LEAK: Detected {count} potential leak(s) in output"
            )

        if details["mitigation_attempted"] and not details["mitigation_succeeded"]:
            violations.append(
                "G3_MITIGATION_FAILED: Leaks persist after auto-redaction → REVIEW"
            )
        elif details["mitigation_attempted"] and details["mitigation_succeeded"]:
            warnings.append(
                "G3_MITIGATED: Leak detected and auto-redacted successfully"
            )

        return GuardrailResult(
            guardrail_name=self.name,
            is_valid=not details["g3_triggered"] or details["mitigation_succeeded"],
            violations=violations,
            warnings=warnings,
            metadata={
                "g3_triggered": details["g3_triggered"],
                "g3_flags": details["g3_flags"],
                "recommended_decision": details["recommended_decision"],
                "initial_findings_count": details["initial_findings_count"],
                "mitigation_attempted": details["mitigation_attempted"],
                "mitigation_succeeded": details["mitigation_succeeded"],
            },
        )
