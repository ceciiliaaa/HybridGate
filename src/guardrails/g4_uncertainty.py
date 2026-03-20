"""
G4: Uncertainty / Abstention Guardrail (Rule-Based, Deterministic)

Addresses: FM4 (Uncertainty Miscalibration)

G4 is a rule-based uncertainty escalation guardrail.  It checks whether
objective ambiguity signals justify routing a decision to REVIEW, rather
than trusting the LLM's self-assessed confidence.

Two-layer flag architecture:
1. **Reported flags** — the LLM self-reports uncertainty_flags[] in its
   structured output (optional field).
2. **Inferred flags** — G4 deterministically derives flags from structured
   output fields, file paths, PR metadata, scanner results, and upstream
   guardrail results (G2 issues, G5 repair status).

Five hard REVIEW rules combine flags with contextual conditions.

`confidence` is read as an optional backward-compatible field but is NOT
the primary signal and NOT required for G4 validity.

G4 does NOT validate:
    - Evidence quality / location (→ G1)
    - Untrusted-input influence  (→ G2)
    - Secret leakage / redaction (→ G3)
    - Schema / parse correctness (→ G5)
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from .base import Guardrail, GuardrailResult


# Kept for backward compatibility — not used as primary G4 signal
VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}

# ---------------------------------------------------------------------------
# Known uncertainty flags (canonical names)
# ---------------------------------------------------------------------------

KNOWN_UNCERTAINTY_FLAGS: Set[str] = {
    # Context-based ambiguity
    "placeholder_or_example_context",
    "test_or_docs_context",
    "comment_claims_dummy",

    # Evidence-structure signals
    "reconstructed_secret",
    "split_across_variables",
    "low_specificity_literal",
    "evidence_span_not_single_line",

    # Upstream / cross-guardrail signals
    "scanner_disagreement",
    "format_or_schema_repair_used",
    "g2_unreported_influence",

    # Adversarial / manipulation signals
    "decoy_like_pattern",

    # Semantic-context signals
    "auth_context_hardcoded_value",
}


# ---------------------------------------------------------------------------
# Heuristic patterns for flag inference
# ---------------------------------------------------------------------------

# File paths that indicate test / docs / example / template context
_TEST_DOCS_PATH_RE = re.compile(
    r"(?i)(?:"
    r"test[s_/]|spec[s_/]|__test__|\.test\.|_test\."
    r"|doc[s_/]|example[s_/]|sample[s_/]|template[s_/]"
    r"|fixture[s_/]|mock[s_/]|stub[s_/]|fake[s_/]"
    r"|demo[s_/]|tutorial[s_/]|snippet[s_/]"
    r"|\.md$|\.rst$|\.txt$|README"
    r")"
)

# Productive-sink patterns in file paths (counterweight to test/docs)
_PRODUCTIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"src/|lib/|app/|pkg/|cmd/|internal/"
    r"|main\.|server\.|handler\.|service\.|config\."
    r"|middleware|controller|model|repository"
    r")"
)

# Placeholder / example / dummy value patterns in evidence snippets
_PLACEHOLDER_VALUE_PATTERNS = [
    "example", "placeholder", "your_", "your-",
    "insert_", "insert-", "change_me", "changeme",
    "todo", "fixme", "replace_me", "replaceme",
    "dummy", "sample_", "sample-", "test_key", "test-key",
    "fake_", "fake-", "mock_", "mock-",
    "xxx", "yyy", "zzz",
    "000000", "123456", "abcdef", "aaaaaa",
    "my_secret", "my_key", "my_token", "my_password",
    "default_", "default-",
]

# Low-specificity generic token patterns (value looks like a generic name,
# not an actual credential)
_LOW_SPECIFICITY_PATTERNS = [
    "password", "secret", "token", "changeme",
    "example_key", "dummy_token", "test123",
    "admin", "root", "pass", "1234",
    "key_here", "secret_here", "token_here",
    "notsecret", "nosecret", "notapassword",
]

# Exculpatory claim keywords in PR text / code comments
_EXCULPATORY_KEYWORDS = [
    "dummy", "mock", "fake", "placeholder", "example",
    "sample", "not real", "not a real",
    "safe to ignore", "safe to commit", "approved exception",
    "security approved", "pre-approved", "whitelisted",
    "rotated already", "already rotated", "will be rotated",
    "temporary", "bootstrap only", "non-production",
    "will be removed", "to be replaced",
    "test only", "test-only", "testing only", "for testing",
    "development only", "dev only", "local only",
    "false positive", "not a secret", "not a key",
    "not sensitive", "no risk",
]

# Secret-context words for exculpatory claim detection
_SECRET_CONTEXT_WORDS = [
    "key", "secret", "token", "password", "credential",
    "api_key", "api key", "apikey", "private_key", "private key",
    "cert", "certificate", "connection", "auth",
]

# Decoy patterns: known adversarial framing in code (stronger signal —
# indicates deliberate manipulation, not just benign labeling)
_DECOY_CODE_RE = re.compile(
    r"(?i)(?:"
    r"#\s*(?:not?\s+a?\s*(?:real|actual)|dummy|fake|test|placeholder|safe)"
    r"|//\s*(?:not?\s+a?\s*(?:real|actual)|dummy|fake|test|placeholder|safe)"
    r"|/\*.*(?:dummy|fake|test|placeholder|safe).*\*/"
    r")"
)

# Comment-line extraction pattern (Python #, C/JS //, shell #)
_COMMENT_LINE_RE = re.compile(
    r"(?:#|//)\s*(.+?)$", re.MULTILINE
)

# Auth-sensitive path segments in code (URL construction targets)
_AUTH_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"/auth/|/oauth|/token|/session|/login|/credential"
    r"|/admin/|Authorization"
    r")"
)

# Hardcoded constant assignment: UPPER_CASE_VAR = "value" (6+ chars)
# Handles both raw diff lines (+CONST = "val") and numbered lines (L12: +CONST = "val")
_HARDCODED_CONST_RE = re.compile(
    r"""^(?:L\d+:\s*)?\+?\s*([A-Z][A-Z0-9_]*)\s*=\s*["']([^"']{6,})["']""",
    re.MULTILINE,
)

# Variable name suffixes that are clearly non-secret config
_BENIGN_VAR_SUFFIXES = {
    "_HOST", "_PORT", "_URL", "_ENDPOINT", "_PATH", "_NAME",
    "_REGION", "_BUCKET", "_DB", "_DATABASE", "_TIMEOUT",
    "_INTERVAL", "_SIZE", "_COUNT", "_MAX", "_MIN",
    "_DIR", "_HEADER", "_METHOD", "_SCHEME",
}


def _detect_exculpatory_comment_claims(code_context: str) -> bool:
    """
    Detect exculpatory claims about secrets in code comments.

    Extracts inline comments from code and checks whether they contain
    exculpatory keywords (dummy, fake, placeholder, test only, …)
    combined with secret-context words (key, token, password, …).

    This catches cases like:
        API_KEY = "sk_live_abc"  # dummy key for testing
        password = "hunter2"  # placeholder, will be rotated

    Returns True if at least one comment contains both an exculpatory
    keyword and a secret-context word.
    """
    if not code_context:
        return False

    comments = _COMMENT_LINE_RE.findall(code_context)
    if not comments:
        return False

    for comment in comments:
        comment_lower = comment.lower()
        has_secret_ctx = any(w in comment_lower for w in _SECRET_CONTEXT_WORDS)
        has_exculpatory = any(kw in comment_lower for kw in _EXCULPATORY_KEYWORDS)
        if has_exculpatory and has_secret_ctx:
            return True

    return False


# ---------------------------------------------------------------------------
# Flag inference
# ---------------------------------------------------------------------------

def _infer_flags_from_context(
    llm_output: dict,
    guardrail_context: dict = None,
) -> List[str]:
    """
    Deterministically infer uncertainty flags from structured output
    and full guardrail context.

    Args:
        llm_output: Parsed LLM output dictionary
        guardrail_context: Optional dict with:
            - file_path: str (source file path)
            - pr_title: str
            - pr_body: str
            - code_context: str (diff content)
            - scanner_hit: bool
            - schema_repaired: bool
            - g2_issues: list

    Returns:
        List of inferred flag names
    """
    if guardrail_context is None:
        guardrail_context = {}

    inferred: List[str] = []
    has_secret = llm_output.get("pred_has_secret", False)
    evidence_mode = str(llm_output.get("evidence_mode", "")).lower()
    snippet = str(llm_output.get("evidence_snippet", ""))
    loc_start = llm_output.get("pred_location_start")
    loc_end = llm_output.get("pred_location_end")

    # --- Evidence-structure signals ---

    if evidence_mode == "reconstructed":
        inferred.append("reconstructed_secret")

    if (loc_start is not None and loc_end is not None
            and loc_start != loc_end):
        inferred.append("evidence_span_not_single_line")

        # Multi-line reconstructed → likely split across variables
        if evidence_mode == "reconstructed":
            inferred.append("split_across_variables")

    # --- Placeholder / example detection from snippet ---

    if has_secret and snippet:
        snippet_lower = snippet.lower()
        if any(p in snippet_lower for p in _PLACEHOLDER_VALUE_PATTERNS):
            inferred.append("placeholder_or_example_context")

    # --- Low-specificity literal ---
    # Check if the secret value itself looks generic/low-entropy

    if has_secret and snippet:
        # Extract quoted values from snippet
        quoted = re.findall(r"['\"]([^'\"]+)['\"]", snippet)
        for val in quoted:
            val_lower = val.strip().lower()
            if any(p == val_lower or p in val_lower
                   for p in _LOW_SPECIFICITY_PATTERNS):
                inferred.append("low_specificity_literal")
                break

    # --- File-path context ---

    file_path = guardrail_context.get("file_path") or ""
    if file_path:
        if _TEST_DOCS_PATH_RE.search(file_path):
            inferred.append("test_or_docs_context")

    # --- PR metadata + code comments: exculpatory claims ---
    # comment_claims_dummy fires when PR text OR code comments contain
    # exculpatory keywords combined with secret-context words.

    pr_title = guardrail_context.get("pr_title") or ""
    pr_body = guardrail_context.get("pr_body") or ""
    pr_text = f"{pr_title} {pr_body}".lower()
    code_context = guardrail_context.get("code_context") or ""

    found_claims_dummy = False
    if pr_text.strip():
        has_secret_context = any(w in pr_text for w in _SECRET_CONTEXT_WORDS)
        has_exculpatory = any(kw in pr_text for kw in _EXCULPATORY_KEYWORDS)
        if has_exculpatory and has_secret_context:
            found_claims_dummy = True

    if not found_claims_dummy and code_context:
        if _detect_exculpatory_comment_claims(code_context):
            found_claims_dummy = True

    if found_claims_dummy:
        inferred.append("comment_claims_dummy")

    # --- Code-context: decoy patterns (adversarial framing) ---
    # decoy_like_pattern is a stronger, more adversarial signal than
    # comment_claims_dummy — it catches deliberate manipulation framing
    # like "# not a real key" without requiring secret-context words.

    if code_context and _DECOY_CODE_RE.search(code_context):
        inferred.append("decoy_like_pattern")

    # --- Auth-context with hardcoded values (FM4 semantic signal) ---
    # Detects hardcoded string constants in code that constructs URLs
    # pointing to auth/token/session/admin endpoints.  When the LLM says
    # "no secret" but the code feeds a hardcoded value into auth-sensitive
    # URL paths, this is a strong ambiguity signal.

    if not has_secret and code_context:
        if _AUTH_SENSITIVE_PATH_RE.search(code_context):
            for match in _HARDCODED_CONST_RE.finditer(code_context):
                var_name = match.group(1)
                value = match.group(2)
                # Skip clearly benign config variables
                if any(var_name.endswith(s) for s in _BENIGN_VAR_SUFFIXES):
                    continue
                # Skip values that look like URLs, hostnames, or paths
                if value.startswith(("http", "/", "localhost")):
                    continue
                if "." in value and not any(c.isdigit() for c in value):
                    continue  # likely a domain or module path
                # Value has some entropy: mixed case or alphanumeric mix
                has_upper = any(c.isupper() for c in value)
                has_lower = any(c.islower() for c in value)
                has_digit = any(c.isdigit() for c in value)
                if (has_upper and has_lower) or (has_digit and (has_upper or has_lower)):
                    inferred.append("auth_context_hardcoded_value")
                    break

    # --- Upstream guardrail signals ---

    # G5 schema repair
    if guardrail_context.get("schema_repaired"):
        inferred.append("format_or_schema_repair_used")

    # Scanner disagreement
    scanner_hit = guardrail_context.get("scanner_hit")
    if scanner_hit is not None:
        if scanner_hit and not has_secret:
            inferred.append("scanner_disagreement")
        elif not scanner_hit and has_secret:
            inferred.append("scanner_disagreement")

    # G2 unreported influence signal (soft/ambiguous — G2 warned but did
    # not hard-fail).  Hard G2_EXCULPATORY cases are already routed by G2
    # itself and should NOT be re-triggered here.
    g2_issues = guardrail_context.get("g2_issues") or []
    if any("G2_UNREPORTED" in i for i in g2_issues):
        inferred.append("g2_unreported_influence")

    # Deduplicate
    return list(dict.fromkeys(inferred))


def _has_productive_context(guardrail_context: dict) -> bool:
    """
    Check if the file path suggests a productive (non-test/docs) context.
    Used as counterweight in ambiguity rules.

    A path that also matches test/docs patterns is NOT considered productive,
    even if it contains productive-looking segments (e.g. tests/test_config.py).
    """
    file_path = guardrail_context.get("file_path") or ""
    if not file_path:
        return False
    # If it matches test/docs, it's not productive regardless
    if _TEST_DOCS_PATH_RE.search(file_path):
        return False
    return bool(_PRODUCTIVE_PATH_RE.search(file_path))


# ---------------------------------------------------------------------------
# Ambiguity context sets (for rule conditions)
# ---------------------------------------------------------------------------

# R1 core triggers: structural decoy/example/test/docs context
_R1_CORE_FLAGS = {
    "placeholder_or_example_context",
    "test_or_docs_context",
}

# Broader ambiguity set used by R2 (reconstructed + ambiguity)
_AMBIGUOUS_CONTEXT_FLAGS = {
    "placeholder_or_example_context",
    "test_or_docs_context",
    "comment_claims_dummy",
    "decoy_like_pattern",
    "low_specificity_literal",
}


# ---------------------------------------------------------------------------
# Hard REVIEW rules
# ---------------------------------------------------------------------------

def _rule_ambiguous_context(
    all_flags: Set[str],
    llm_output: dict,
    guardrail_context: dict,
) -> Optional[str]:
    """R1: Structural ambiguity (placeholder/example/test/docs) → REVIEW.

    Fires when:
    - A core ambiguity flag is present (placeholder_or_example_context
      or test_or_docs_context), AND
    - The file path does NOT clearly indicate a productive source.

    decoy_like_pattern is only added when it co-occurs with a core flag.
    low_specificity_literal and comment_claims_dummy do NOT trigger R1
    on their own — they are handled by R2/R4 respectively.

    When file_path is unknown (empty), R1 requires at least one core
    flag to be present — it does not fire solely from the absence of
    a productive path indicator.
    """
    core_present = all_flags & _R1_CORE_FLAGS
    if not core_present:
        return None

    # Don't fire if path clearly productive (src/lib/app/...)
    if _has_productive_context(guardrail_context):
        return None

    # Include decoy_like_pattern in the report if it co-occurs
    report_flags = core_present
    if "decoy_like_pattern" in all_flags:
        report_flags = report_flags | {"decoy_like_pattern"}

    flags_str = ", ".join(sorted(report_flags)[:3])
    return f"ambiguous context ({flags_str}) without productive file path"


def _rule_reconstructed_plus_ambiguity(
    all_flags: Set[str],
    llm_output: dict,
    guardrail_context: dict,
) -> Optional[str]:
    """R2: Reconstructed secret + ambiguous usage context → REVIEW.

    Reconstructed evidence is inherently harder to assess.  Combined
    with ambiguous context signals, escalation is warranted.
    """
    if "reconstructed_secret" not in all_flags:
        return None

    ambig_present = all_flags & _AMBIGUOUS_CONTEXT_FLAGS
    if not ambig_present:
        return None

    flags_str = ", ".join(sorted(ambig_present)[:3])
    return f"reconstructed_secret + ambiguous context ({flags_str})"


def _rule_scanner_neg_llm_pos_context(
    all_flags: Set[str],
    llm_output: dict,
    guardrail_context: dict,
) -> Optional[str]:
    """R3: Scanner negative + LLM positive + docs/test context → REVIEW.

    When the scanner found nothing but the LLM claims a secret,
    AND the file is in a test/docs/example path, the LLM may be
    over-interpreting a non-production artifact.
    """
    if "scanner_disagreement" not in all_flags:
        return None

    has_secret = llm_output.get("pred_has_secret", False)
    scanner_hit = (guardrail_context.get("scanner_hit") or False)

    # This rule targets: scanner negative, LLM positive
    if not (not scanner_hit and has_secret):
        return None

    # Require test/docs/example context
    context_flags = all_flags & {
        "test_or_docs_context",
        "placeholder_or_example_context",
        "decoy_like_pattern",
    }
    if not context_flags:
        return None

    flags_str = ", ".join(sorted(context_flags))
    return f"scanner_negative + llm_positive + {flags_str}"


def _rule_exculpatory_escalation(
    all_flags: Set[str],
    llm_output: dict,
    guardrail_context: dict,
) -> Optional[str]:
    """R4: Unreported exculpatory influence as ambiguity signal → REVIEW.

    G2 handles hard influence routing for G2_EXCULPATORY and G2_INFLUENCE
    cases.  G4 complements this for the softer, ambiguous cases:

    - G2_UNREPORTED: G2 detected exculpatory claims in PR text that the
      LLM did not acknowledge (warning, not hard-fail).
    - comment_claims_dummy + used_untrusted_input=false: PR text contains
      dummy/fake/test claims but the LLM denies using untrusted input.

    G4 does NOT re-trigger on G2_EXCULPATORY (already routed by G2).
    """
    # G2 issued an unreported-influence warning (soft signal)
    if "g2_unreported_influence" in all_flags:
        return "G2 flagged unreported exculpatory influence (G2_UNREPORTED)"

    # PR text has exculpatory claims + LLM denies using untrusted input
    if "comment_claims_dummy" in all_flags:
        used = llm_output.get("used_untrusted_input", False)
        if not used:
            return "PR exculpatory claims + used_untrusted_input=false"

    return None


def _rule_schema_repair(
    all_flags: Set[str],
    llm_output: dict,
    guardrail_context: dict,
) -> Optional[str]:
    """R5: G5 schema repair was needed → REVIEW.

    If the output required repair to become valid, the LLM's adherence
    to the expected format is unreliable, adding uncertainty.
    """
    if "format_or_schema_repair_used" in all_flags:
        return "G5 schema repair was required"
    return None


def _rule_auth_context_hardcoded(
    all_flags: Set[str],
    llm_output: dict,
    guardrail_context: dict,
) -> Optional[str]:
    """R6: Hardcoded value used in auth-sensitive URL context → REVIEW.

    Fires when the code contains hardcoded string constants that feed
    into URL construction targeting auth/token/session/admin endpoints,
    but the LLM classified the sample as having no secret.

    This catches "generic credential" blind spots: values like
    'prod-7xK2mP9nL' or 'corp-tenant-93kF2pLx' that look like
    config labels but are actually used as auth-critical routing
    tokens or API keys.
    """
    if "auth_context_hardcoded_value" not in all_flags:
        return None

    has_secret = llm_output.get("pred_has_secret", False)
    if has_secret:
        return None  # LLM already flagged it — no need to escalate

    return "hardcoded value in auth-sensitive URL context, LLM classified as non-secret"


# Ordered list of rules — first match triggers REVIEW
REVIEW_RULES = [
    ("R1_ambiguous_context", _rule_ambiguous_context),
    ("R2_reconstructed_plus_ambiguity", _rule_reconstructed_plus_ambiguity),
    ("R3_scanner_neg_llm_pos_context", _rule_scanner_neg_llm_pos_context),
    ("R4_exculpatory_escalation", _rule_exculpatory_escalation),
    ("R5_schema_repair", _rule_schema_repair),
    ("R6_auth_context_hardcoded", _rule_auth_context_hardcoded),
]


# ---------------------------------------------------------------------------
# G4 Guardrail class
# ---------------------------------------------------------------------------

class G4Uncertainty(Guardrail):
    """
    Guardrail G4: Uncertainty / Abstention (Rule-Based Escalation)

    Addresses FM4 (Uncertainty Miscalibration).

    Combines LLM-reported uncertainty signals with deterministically
    inferred flags from file paths, PR metadata, scanner results,
    G2 issues, and G5 repair status.

    `confidence` is optional and backward-compatible but NOT the
    primary signal.  G4 validity does not depend on confidence.

    Two-layer approach:
    1. Collect flags: reported (LLM) + inferred (deterministic)
    2. Evaluate rules: 6 hard rules that trigger REVIEW routing

    Rules:
    - R1: Ambiguous context (test/docs/placeholder/example) without
          productive file-path counterweight → REVIEW
    - R2: Reconstructed secret + ambiguous context → REVIEW
    - R3: Scanner negative + LLM positive + docs/test context → REVIEW
    - R4: Exculpatory claims (G2 signal or PR text) → REVIEW
    - R5: G5 schema repair was needed → REVIEW
    - R6: Hardcoded value in auth-sensitive URL context + LLM says
          no secret → REVIEW
    """

    @property
    def name(self) -> str:
        return "G4_Uncertainty"

    def get_prompt(self) -> str:
        return """
=== GUARDRAIL G4: UNCERTAINTY / ABSTENTION ===

You SHOULD include 'uncertainty_flags' (list of strings) when applicable:
- "placeholder_or_example_context": The value looks like a placeholder, example, or dummy
- "test_or_docs_context": The file appears to be a test or documentation file
- "comment_claims_dummy": A code comment or PR text claims the secret is fake/dummy/test
- "reconstructed_secret": The secret is split across variables or concatenated
- "split_across_variables": Specific case of secret split into multiple variables
- "low_specificity_literal": The literal is very short or low-entropy
- "scanner_disagreement": Your finding disagrees with static scanner results
- "decoy_like_pattern": The pattern resembles known manipulation/decoy strategies
- "auth_context_hardcoded_value": A hardcoded value is used in auth/token/session URL construction

You MAY include a 'confidence' field (HIGH/MEDIUM/LOW) to indicate your
overall certainty, but this is optional context — the system evaluates
uncertainty from structural signals, not just your self-assessment.

RULES:
1. Report ALL applicable uncertainty flags honestly.
2. Omitting flags does not prevent escalation — the system infers flags
   independently from your structured output, file paths, and PR metadata.
3. If the evidence is ambiguous (placeholder-like values, test files,
   exculpatory comments), report the relevant flags.

OUTPUT SCHEMA (add to existing):
{
  ...
  "uncertainty_flags": ["flag1", "flag2", ...],
  "confidence": "HIGH" | "MEDIUM" | "LOW"  // optional
}
"""

    # ------------------------------------------------------------------
    # Core validation interface
    # ------------------------------------------------------------------

    def validate_output(self, llm_output: dict) -> bool:
        """
        Validate G4 output fields.

        G4 validity does NOT depend on confidence being present.
        G4 is valid as long as we have a parseable output to evaluate.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            True (G4 is always valid on parsed output — flags are
            inferred deterministically regardless of LLM self-report)
        """
        # G4 is valid on any parsed output — confidence is optional
        return True

    def get_confidence(self, llm_output: dict) -> Optional[str]:
        """
        Extract and normalize the optional confidence value.

        Args:
            llm_output: The LLM's response dictionary

        Returns:
            Normalized confidence string (HIGH/MEDIUM/LOW) or None
        """
        confidence = llm_output.get("confidence")
        if confidence is None:
            return None
        normalized = str(confidence).upper()
        return normalized if normalized in VALID_CONFIDENCE_LEVELS else None

    # ------------------------------------------------------------------
    # Flag collection
    # ------------------------------------------------------------------

    def collect_flags(
        self,
        llm_output: dict,
        guardrail_context: dict = None,
    ) -> Tuple[Set[str], Set[str]]:
        """
        Collect uncertainty flags from both sources.

        Args:
            llm_output: Parsed LLM output dictionary
            guardrail_context: Optional upstream guardrail context

        Returns:
            Tuple of (reported_flags, inferred_flags)
        """
        # Reported flags from LLM output
        raw_reported = llm_output.get("uncertainty_flags", [])
        if not isinstance(raw_reported, list):
            raw_reported = []
        reported = {str(f).lower().strip() for f in raw_reported if f}

        # Inferred flags from deterministic analysis
        inferred_list = _infer_flags_from_context(llm_output, guardrail_context)
        inferred = set(inferred_list)

        return reported, inferred

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def evaluate_rules(
        self,
        llm_output: dict,
        all_flags: Set[str],
        guardrail_context: dict = None,
    ) -> Optional[Tuple[str, str]]:
        """
        Evaluate hard REVIEW rules against collected flags and context.

        Args:
            llm_output: Parsed LLM output dictionary
            all_flags: Union of reported + inferred flags
            guardrail_context: Full context for rule evaluation

        Returns:
            Tuple of (rule_name, reason) if a rule fires, None otherwise
        """
        if guardrail_context is None:
            guardrail_context = {}

        for rule_name, rule_fn in REVIEW_RULES:
            reason = rule_fn(all_flags, llm_output, guardrail_context)
            if reason is not None:
                return (rule_name, reason)

        return None

    # ------------------------------------------------------------------
    # Primary validation with details
    # ------------------------------------------------------------------

    def validate_with_details(
        self,
        llm_output: dict,
        guardrail_context: dict = None,
    ) -> Dict:
        """
        Full G4 validation with flag inference and rule evaluation.

        Args:
            llm_output: Parsed LLM output dictionary
            guardrail_context: Optional dict with:
                - file_path: str
                - pr_title: str
                - pr_body: str
                - code_context: str
                - scanner_hit: bool
                - schema_repaired: bool
                - g2_issues: list

        Returns:
            Dictionary with:
            - g4_valid: bool (always True on parsed output)
            - should_review: bool (any REVIEW rule fired)
            - triggered_rule: str or None
            - trigger_reason: str or None
            - reported_flags: list (LLM-reported)
            - inferred_flags: list (deterministically inferred)
            - all_flags: list (union)
            - confidence: str or None (optional, backward-compat)
        """
        if guardrail_context is None:
            guardrail_context = {}

        reported, inferred = self.collect_flags(llm_output, guardrail_context)
        all_flags = reported | inferred

        confidence = self.get_confidence(llm_output)

        # Evaluate rules
        rule_result = self.evaluate_rules(
            llm_output, all_flags, guardrail_context
        )

        should_review = rule_result is not None
        triggered_rule = rule_result[0] if rule_result else None
        trigger_reason = rule_result[1] if rule_result else None

        return {
            "g4_valid": True,
            "should_review": should_review,
            "triggered_rule": triggered_rule,
            "trigger_reason": trigger_reason,
            "reported_flags": sorted(reported),
            "inferred_flags": sorted(inferred),
            "all_flags": sorted(all_flags),
            "confidence": confidence,
        }

    # ------------------------------------------------------------------
    # Backward-compatible routing interface
    # ------------------------------------------------------------------

    def should_route_to_review(
        self,
        llm_output: dict,
        guardrail_context: dict = None,
    ) -> bool:
        """
        Determine if the output should be routed to REVIEW.

        Args:
            llm_output: The LLM's response dictionary
            guardrail_context: Optional upstream context

        Returns:
            True if any REVIEW rule fires
        """
        result = self.validate_with_details(llm_output, guardrail_context)
        return result["should_review"]

    def apply_routing(
        self,
        llm_output: dict,
        original_decision: str,
        guardrail_context: dict = None,
    ) -> Tuple[str, dict]:
        """
        Apply G4 uncertainty routing to the decision.

        Args:
            llm_output: The LLM's response dictionary
            original_decision: Decision before G4 routing
            guardrail_context: Optional upstream context

        Returns:
            Tuple of (final_decision, metadata_dict)
        """
        result = self.validate_with_details(llm_output, guardrail_context)

        metadata = {
            "confidence": result["confidence"],
            "original_decision": original_decision,
            "routed_by_guardrail": None,
            "triggered_rule": result["triggered_rule"],
            "trigger_reason": result["trigger_reason"],
            "reported_flags": result["reported_flags"],
            "inferred_flags": result["inferred_flags"],
            "all_flags": result["all_flags"],
        }

        if result["should_review"]:
            metadata["routed_by_guardrail"] = "G4"
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
        result = self.validate_with_details(llm_output, guardrail_context)

        violations = []
        warnings = []

        # Triggered rule is a violation (→ REVIEW)
        if result["triggered_rule"]:
            violations.append(
                f"G4_{result['triggered_rule']}: {result['trigger_reason']}"
            )

        # Inferred flags not reported by LLM are warnings
        reported_set = set(result["reported_flags"])
        for flag in result["inferred_flags"]:
            if flag not in reported_set:
                warnings.append(
                    f"G4_UNREPORTED: flag '{flag}' inferred but not "
                    f"self-reported by LLM"
                )

        return GuardrailResult(
            guardrail_name=self.name,
            is_valid=True,  # G4 is always valid on parsed output
            violations=violations,
            warnings=warnings,
            metadata={
                "confidence": result["confidence"],
                "would_route_to_review": result["should_review"],
                "triggered_rule": result["triggered_rule"],
                "reported_flags": result["reported_flags"],
                "inferred_flags": result["inferred_flags"],
                "all_flags": result["all_flags"],
            },
        )
