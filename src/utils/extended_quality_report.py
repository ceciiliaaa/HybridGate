"""
Extended Dataset Quality Report for B2 Analysis

Comprehensive quality metrics including:
- Secret diversity and realism
- Context diversity (REAL)
- Suspicious pattern detection
- Comparison across dataset versions

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import Counter
from dataclasses import dataclass, asdict


@dataclass
class ExtendedQualityMetrics:
    """Extended quality metrics for dataset analysis."""
    # Basic metrics
    total_samples: int
    positive_samples: int
    negative_samples: int

    # Secret diversity
    unique_secrets: int
    unique_secret_ratio: float
    duplicate_rate: float
    duplicate_groups: List[Tuple[str, int]]

    # Secret type distribution
    secret_type_distribution: Dict[str, int]

    # Context diversity (for REAL samples)
    unique_pr_titles: int
    unique_file_paths: int
    unique_context_families: int
    context_diversity_score: float

    # Pattern analysis
    repeating_pattern_count: int
    placeholder_pattern_count: int
    suspicious_secrets: List[str]

    # Per-type analysis
    secrets_per_type: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict:
        return asdict(self)


def detect_repeating_patterns(secret: str, min_length: int = 4, min_repeats: int = 2) -> bool:
    """Detect if a secret has obvious repeating substrings."""
    if len(secret) < min_length * min_repeats:
        return False

    for i in range(len(secret) - min_length + 1):
        chunk = secret[i:i + min_length]
        if chunk.isalnum() and secret.count(chunk) >= min_repeats:
            # Check if it's not just the secret itself (e.g., short secrets)
            if len(chunk) * secret.count(chunk) > len(secret) * 0.3:
                return True
    return False


def detect_placeholder_patterns(secret: str) -> bool:
    """Detect if a secret looks like a placeholder."""
    placeholder_patterns = [
        r'EXAMPLE',
        r'PLACEHOLDER',
        r'YOUR_.*_HERE',
        r'xxxxxxxx',
        r'XXXXXXXX',
        r'00000000',
        r'12345678',
        r'abcdefgh',
        r'test_?key',
        r'dummy',
        r'sample',
        r'_fake_',
    ]
    secret_upper = secret.upper()
    return any(re.search(pattern, secret_upper, re.IGNORECASE) for pattern in placeholder_patterns)


def analyze_secrets_by_type(samples: List[Dict]) -> Dict[str, Dict[str, Any]]:
    """Analyze secrets grouped by type."""
    by_type: Dict[str, List[str]] = {}

    for s in samples:
        if s.get('gt_has_secret') and s.get('gt_secret_value'):
            stype = s.get('gt_secret_type', 'unknown')
            if stype not in by_type:
                by_type[stype] = []
            by_type[stype].append(s['gt_secret_value'])

    result = {}
    for stype, secrets in by_type.items():
        unique = len(set(secrets))
        repeating = sum(1 for s in secrets if detect_repeating_patterns(s))
        placeholder = sum(1 for s in secrets if detect_placeholder_patterns(s))

        result[stype] = {
            'count': len(secrets),
            'unique': unique,
            'unique_ratio': unique / len(secrets) if secrets else 0,
            'repeating_patterns': repeating,
            'placeholder_patterns': placeholder,
            'avg_length': sum(len(s) for s in secrets) / len(secrets) if secrets else 0,
        }

    return result


def analyze_dataset(samples: List[Dict], dataset_name: str = "") -> ExtendedQualityMetrics:
    """
    Perform comprehensive analysis of a dataset.

    Args:
        samples: List of sample dictionaries
        dataset_name: Name for logging

    Returns:
        ExtendedQualityMetrics instance
    """
    total = len(samples)
    positive = sum(1 for s in samples if s.get('gt_has_secret', False))
    negative = total - positive

    # Secret analysis
    secrets = [s.get('gt_secret_value') for s in samples if s.get('gt_secret_value')]
    unique_secrets = len(set(secrets))
    unique_ratio = unique_secrets / len(secrets) if secrets else 0
    duplicate_rate = 1 - unique_ratio

    # Duplicate groups
    secret_counts = Counter(secrets)
    duplicate_groups = [(s[:30] + '...' if len(s) > 30 else s, c)
                        for s, c in secret_counts.most_common()
                        if c > 1]

    # Secret type distribution
    secret_types = Counter(s.get('gt_secret_type') for s in samples if s.get('gt_has_secret'))

    # Context diversity
    pr_titles = [s.get('pr_title', '') for s in samples]
    file_paths = [s.get('gt_file_path', '') for s in samples]
    context_families = [s.get('context_family', 'unknown') for s in samples]

    unique_titles = len(set(pr_titles))
    unique_paths = len(set(file_paths))
    unique_families = len(set(f for f in context_families if f != 'unknown'))

    # Context diversity score (weighted average)
    title_diversity = unique_titles / total if total else 0
    path_diversity = unique_paths / total if total else 0
    context_diversity = (title_diversity + path_diversity) / 2

    # Pattern analysis
    repeating_count = sum(1 for s in secrets if detect_repeating_patterns(s))
    placeholder_count = sum(1 for s in secrets if detect_placeholder_patterns(s))

    suspicious = []
    for s in secrets:
        if detect_repeating_patterns(s):
            suspicious.append(f"REPEAT: {s[:40]}...")
        elif detect_placeholder_patterns(s):
            suspicious.append(f"PLACEHOLDER: {s[:40]}...")

    # Per-type analysis
    secrets_per_type = analyze_secrets_by_type(samples)

    return ExtendedQualityMetrics(
        total_samples=total,
        positive_samples=positive,
        negative_samples=negative,
        unique_secrets=unique_secrets,
        unique_secret_ratio=round(unique_ratio, 4),
        duplicate_rate=round(duplicate_rate, 4),
        duplicate_groups=duplicate_groups[:10],
        secret_type_distribution=dict(secret_types),
        unique_pr_titles=unique_titles,
        unique_file_paths=unique_paths,
        unique_context_families=unique_families,
        context_diversity_score=round(context_diversity, 4),
        repeating_pattern_count=repeating_count,
        placeholder_pattern_count=placeholder_count,
        suspicious_secrets=suspicious[:10],
        secrets_per_type=secrets_per_type
    )


def print_comparison_report(metrics_list: List[Tuple[str, ExtendedQualityMetrics]]):
    """Print a comparison report across multiple datasets."""
    print("\n" + "=" * 80)
    print(" DATASET QUALITY COMPARISON REPORT")
    print("=" * 80)

    # Header
    headers = ["Metric"] + [name for name, _ in metrics_list]
    col_width = max(20, max(len(h) for h in headers) + 2)

    print("\n" + "-" * 80)
    print("".join(h.ljust(col_width) for h in headers))
    print("-" * 80)

    def row(label: str, values: List[Any], fmt: str = "{}"):
        print(label.ljust(col_width) + "".join(fmt.format(v).ljust(col_width) for v in values))

    # Basic metrics
    row("Total samples", [m.total_samples for _, m in metrics_list])
    row("Positive samples", [m.positive_samples for _, m in metrics_list])
    row("Negative samples", [m.negative_samples for _, m in metrics_list])

    print()
    print("--- SECRET DIVERSITY ---")
    row("Unique secrets", [m.unique_secrets for _, m in metrics_list])
    row("Unique ratio", [f"{m.unique_secret_ratio*100:.1f}%" for _, m in metrics_list], "{}")
    row("Duplicate rate", [f"{m.duplicate_rate*100:.1f}%" for _, m in metrics_list], "{}")

    print()
    print("--- CONTEXT DIVERSITY ---")
    row("Unique PR titles", [m.unique_pr_titles for _, m in metrics_list])
    row("Unique file paths", [m.unique_file_paths for _, m in metrics_list])
    row("Context families", [m.unique_context_families for _, m in metrics_list])
    row("Context diversity", [f"{m.context_diversity_score*100:.1f}%" for _, m in metrics_list], "{}")

    print()
    print("--- PATTERN QUALITY ---")
    row("Repeating patterns", [m.repeating_pattern_count for _, m in metrics_list])
    row("Placeholder patterns", [m.placeholder_pattern_count for _, m in metrics_list])

    print()
    print("--- SECRET TYPES ---")
    all_types = set()
    for _, m in metrics_list:
        all_types.update(m.secret_type_distribution.keys())

    for stype in sorted(all_types):
        if stype:
            counts = [m.secret_type_distribution.get(stype, 0) for _, m in metrics_list]
            row(f"  {stype}", counts)

    print("-" * 80)

    # Quality assessment
    print("\n--- QUALITY ASSESSMENT ---")
    for name, m in metrics_list:
        issues = []
        if m.duplicate_rate > 0.5:
            issues.append("HIGH DUPLICATE RATE")
        if m.context_diversity_score < 0.2:
            issues.append("LOW CONTEXT DIVERSITY")
        if m.repeating_pattern_count > 5:
            issues.append("REPEATING PATTERNS")
        if m.placeholder_pattern_count > 0:
            issues.append("PLACEHOLDER SECRETS")

        status = "GOOD" if not issues else f"ISSUES: {', '.join(issues)}"
        print(f"  {name}: {status}")

    print("=" * 80 + "\n")


def load_and_analyze(file_path: str) -> Tuple[str, ExtendedQualityMetrics]:
    """Load a dataset and return analysis."""
    with open(file_path, 'r') as f:
        samples = json.load(f)
    name = Path(file_path).stem
    return name, analyze_dataset(samples, name)


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Extended quality report for baseline datasets"
    )
    parser.add_argument(
        '--inputs',
        nargs='+',
        required=True,
        help='Input dataset JSON files to analyze'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output JSON file for metrics'
    )

    args = parser.parse_args()

    # Analyze all inputs
    analyses = [load_and_analyze(f) for f in args.inputs]

    # Print comparison report
    print_comparison_report(analyses)

    # Save to JSON if requested
    if args.output:
        output_data = {name: m.to_dict() for name, m in analyses}
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"Saved metrics to {args.output}")


if __name__ == '__main__':
    main()
