"""
Statistical Tests for HybridGate Framework

Implements statistical significance tests for comparing detection methods:
- McNemar Test: For comparing paired binary classifiers
"""

from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
import math


@dataclass
class ContingencyTable:
    """2x2 contingency table for McNemar test."""
    a: int = 0  # Both correct
    b: int = 0  # Method 1 correct, Method 2 wrong
    c: int = 0  # Method 1 wrong, Method 2 correct
    d: int = 0  # Both wrong

    @property
    def total(self) -> int:
        return self.a + self.b + self.c + self.d

    @property
    def n_discordant(self) -> int:
        """Total discordant pairs (b + c)."""
        return self.b + self.c

    def to_dict(self) -> Dict[str, int]:
        return {
            "both_correct": self.a,
            "only_method1_correct": self.b,
            "only_method2_correct": self.c,
            "both_wrong": self.d,
            "total": self.total,
            "discordant_pairs": self.n_discordant
        }


def compute_contingency_table(
    results: List[Dict[str, Any]],
    method1_key: str,
    method2_key: str,
    gt_key: str = "gt_has_secret"
) -> ContingencyTable:
    """
    Build contingency table for McNemar test.

    Compares two binary classifiers on the same samples.

    Args:
        results: List of result dictionaries
        method1_key: Key for method 1 predictions (e.g., "llm_baseline_hit")
        method2_key: Key for method 2 predictions (e.g., "llm_guardrail_hit")
        gt_key: Key for ground truth

    Returns:
        ContingencyTable instance
    """
    ct = ContingencyTable()

    for r in results:
        gt = r.get(gt_key, False)
        pred1 = r.get(method1_key, False)
        pred2 = r.get(method2_key, False)

        # Correct = (predicted secret AND has secret) OR (predicted no secret AND no secret)
        correct1 = (pred1 == gt)
        correct2 = (pred2 == gt)

        if correct1 and correct2:
            ct.a += 1
        elif correct1 and not correct2:
            ct.b += 1
        elif not correct1 and correct2:
            ct.c += 1
        else:
            ct.d += 1

    return ct


def run_mcnemar_test(ct: ContingencyTable) -> Dict[str, Any]:
    """
    Perform McNemar test for paired binary data.

    Tests whether the marginal probabilities of the two methods differ.
    Null hypothesis: The two methods have the same error rate.

    Uses exact binomial test for small samples (b+c < 25) and
    chi-squared approximation for larger samples.

    Args:
        ct: ContingencyTable with comparison data

    Returns:
        Dictionary with test statistic, p-value, and interpretation
    """
    b, c = ct.b, ct.c
    n = b + c  # Discordant pairs

    if n == 0:
        return {
            "test": "mcnemar",
            "statistic": 0.0,
            "p_value": 1.0,
            "n_discordant": 0,
            "method": "no_discordant_pairs",
            "significant_at_005": False,
            "significant_at_001": False,
            "interpretation": "No discordant pairs - methods have identical performance"
        }

    # For small samples, use exact binomial test
    if n < 25:
        # Two-sided exact test
        # P-value = 2 * min(P(X >= b), P(X <= b)) where X ~ Binom(n, 0.5)
        p_value = _exact_binomial_pvalue(b, n)
        method = "exact_binomial"
    else:
        # Chi-squared approximation with continuity correction
        statistic = ((abs(b - c) - 1) ** 2) / (b + c)
        p_value = _chi2_survival(statistic, df=1)
        method = "chi_squared"

    # Calculate test statistic (without continuity correction for reporting)
    statistic = ((b - c) ** 2) / (b + c) if n > 0 else 0.0

    return {
        "test": "mcnemar",
        "statistic": round(statistic, 4),
        "p_value": round(p_value, 6),
        "n_discordant": n,
        "b": b,
        "c": c,
        "method": method,
        "significant_at_005": p_value < 0.05,
        "significant_at_001": p_value < 0.01,
        "interpretation": _interpret_mcnemar(b, c, p_value)
    }


def _exact_binomial_pvalue(k: int, n: int, p: float = 0.5) -> float:
    """
    Compute two-sided p-value for binomial test.

    Args:
        k: Observed successes
        n: Total trials
        p: Null hypothesis probability

    Returns:
        Two-sided p-value
    """
    if n == 0:
        return 1.0

    # Compute binomial PMF for all values
    pmf = []
    for i in range(n + 1):
        pmf.append(_binomial_pmf(i, n, p))

    # Two-sided: sum probabilities <= P(X = k)
    threshold = pmf[k]
    p_value = sum(prob for prob in pmf if prob <= threshold + 1e-10)

    return min(p_value, 1.0)


def _binomial_pmf(k: int, n: int, p: float) -> float:
    """Compute binomial probability mass function."""
    if k < 0 or k > n:
        return 0.0

    # Use log to avoid overflow
    log_coef = _log_binomial_coef(n, k)
    log_prob = log_coef + k * math.log(p) + (n - k) * math.log(1 - p)

    return math.exp(log_prob)


def _log_binomial_coef(n: int, k: int) -> float:
    """Compute log of binomial coefficient."""
    if k < 0 or k > n:
        return float('-inf')
    if k == 0 or k == n:
        return 0.0

    # log(n! / (k! * (n-k)!)) = log(n!) - log(k!) - log((n-k)!)
    return _log_factorial(n) - _log_factorial(k) - _log_factorial(n - k)


def _log_factorial(n: int) -> float:
    """Compute log factorial using Stirling's approximation for large n."""
    if n <= 1:
        return 0.0
    if n < 20:
        return math.log(math.factorial(n))

    # Stirling's approximation
    return n * math.log(n) - n + 0.5 * math.log(2 * math.pi * n)


def _chi2_survival(x: float, df: int = 1) -> float:
    """
    Compute survival function (1 - CDF) of chi-squared distribution.

    Approximation for df=1 (standard case for McNemar).
    """
    if x <= 0:
        return 1.0

    if df == 1:
        # For df=1: P(X > x) = 2 * (1 - Phi(sqrt(x)))
        # Using error function approximation
        z = math.sqrt(x)
        return 2 * (1 - _normal_cdf(z))

    # General case (approximation)
    return _incomplete_gamma_complement(df / 2, x / 2)


def _normal_cdf(z: float) -> float:
    """Approximate standard normal CDF."""
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


def _incomplete_gamma_complement(a: float, x: float) -> float:
    """
    Approximate upper incomplete gamma function ratio (regularized).

    Q(a, x) = 1 - P(a, x) = Gamma(a, x) / Gamma(a)
    """
    if x < 0 or a <= 0:
        return 0.0
    if x == 0:
        return 1.0

    # Simple approximation using continued fraction
    # Good enough for our purposes
    if x < a + 1:
        # Use series expansion for P(a, x) then compute 1 - P
        return 1.0 - _gamma_series(a, x)
    else:
        # Use continued fraction for Q(a, x)
        return _gamma_continued_fraction(a, x)


def _gamma_series(a: float, x: float) -> float:
    """Compute lower incomplete gamma ratio using series."""
    if x == 0:
        return 0.0

    ap = a
    sum_val = 1.0 / a
    delta = sum_val

    for _ in range(100):
        ap += 1
        delta *= x / ap
        sum_val += delta
        if abs(delta) < abs(sum_val) * 1e-10:
            break

    return sum_val * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_continued_fraction(a: float, x: float) -> float:
    """Compute upper incomplete gamma ratio using continued fraction."""
    b = x + 1 - a
    c = 1.0 / 1e-30
    d = 1.0 / b
    h = d

    for i in range(1, 100):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        if abs(d) < 1e-30:
            d = 1e-30
        c = b + an / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-10:
            break

    return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _interpret_mcnemar(b: int, c: int, p_value: float) -> str:
    """Generate human-readable interpretation of McNemar test."""
    if p_value >= 0.05:
        return "No significant difference between methods (p >= 0.05)"

    if b > c:
        diff = "Method 1 performs better"
    else:
        diff = "Method 2 performs better"

    if p_value < 0.001:
        strength = "highly significant"
    elif p_value < 0.01:
        strength = "very significant"
    else:
        strength = "significant"

    return f"{diff} ({strength}, p = {p_value:.4f})"


def interpret_mcnemar_result(result: Dict[str, Any]) -> str:
    """
    Generate detailed interpretation of McNemar test result.

    Args:
        result: Result dictionary from run_mcnemar_test

    Returns:
        Multi-line interpretation string
    """
    lines = [
        "=== McNemar Test Results ===",
        f"Test statistic: {result['statistic']:.4f}",
        f"P-value: {result['p_value']:.6f}",
        f"Method: {result['method']}",
        f"Discordant pairs: {result['n_discordant']}",
        f"  - Only Method 1 correct: {result['b']}",
        f"  - Only Method 2 correct: {result['c']}",
        "",
        f"Significant at α=0.05: {'Yes' if result['significant_at_005'] else 'No'}",
        f"Significant at α=0.01: {'Yes' if result['significant_at_001'] else 'No'}",
        "",
        f"Interpretation: {result['interpretation']}"
    ]
    return "\n".join(lines)


def compare_detectors_mcnemar(
    results: List[Dict[str, Any]],
    method1_key: str,
    method2_key: str,
    method1_name: str = "Method 1",
    method2_name: str = "Method 2"
) -> Dict[str, Any]:
    """
    Compare two detection methods using McNemar test.

    Args:
        results: List of result dictionaries
        method1_key: Key for method 1 hit field
        method2_key: Key for method 2 hit field
        method1_name: Display name for method 1
        method2_name: Display name for method 2

    Returns:
        Comprehensive comparison results
    """
    ct = compute_contingency_table(results, method1_key, method2_key)
    test_result = run_mcnemar_test(ct)

    return {
        "comparison": f"{method1_name} vs {method2_name}",
        "method1": method1_name,
        "method2": method2_name,
        "contingency_table": ct.to_dict(),
        "mcnemar_test": test_result,
        "summary": {
            "both_correct_pct": round(ct.a / ct.total * 100, 1) if ct.total > 0 else 0,
            "both_wrong_pct": round(ct.d / ct.total * 100, 1) if ct.total > 0 else 0,
            "method1_only_correct_pct": round(ct.b / ct.total * 100, 1) if ct.total > 0 else 0,
            "method2_only_correct_pct": round(ct.c / ct.total * 100, 1) if ct.total > 0 else 0
        }
    }
