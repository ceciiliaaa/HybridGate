"""
Dataset Quality Report for HybridGate Framework

Generates comprehensive quality metrics for baseline datasets:
- Unique secret count and duplicate rate
- Secret type distribution
- Code context diversity
- Comparison between dataset versions

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import Counter
from dataclasses import dataclass, asdict


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class QualityMetrics:
    """Quality metrics for a dataset."""
    total_samples: int
    positive_samples: int
    negative_samples: int
    unique_secrets: int
    duplicate_rate: float
    secret_type_distribution: Dict[str, int]
    unique_code_contexts: int
    context_diversity_score: float
    duplicate_groups: List[Tuple[str, int]]  # (secret, count) for duplicates

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_content_hash(content: str) -> str:
    """Compute hash of content for deduplication."""
    return hashlib.md5(content.encode()).hexdigest()[:16]


def analyze_dataset(samples: List[Dict]) -> QualityMetrics:
    """
    Analyze a dataset and compute quality metrics.

    Args:
        samples: List of sample dictionaries

    Returns:
        QualityMetrics instance
    """
    total = len(samples)
    positive = sum(1 for s in samples if s.get('gt_has_secret', False))
    negative = total - positive

    # Analyze secrets
    secrets = [s.get('gt_secret_value') for s in samples if s.get('gt_secret_value')]
    unique_secrets = len(set(secrets))

    # Count duplicates
    secret_counts = Counter(secrets)
    duplicate_groups = [(secret[:20] + '...' if len(secret) > 20 else secret, count)
                        for secret, count in secret_counts.most_common()
                        if count > 1]

    # Duplicate rate
    if secrets:
        duplicate_rate = 1.0 - (unique_secrets / len(secrets))
    else:
        duplicate_rate = 0.0

    # Secret type distribution
    secret_types = Counter(s.get('gt_secret_type') for s in samples if s.get('gt_has_secret'))

    # Code context diversity
    code_hashes = [compute_content_hash(s.get('code_context', '')) for s in samples]
    unique_contexts = len(set(code_hashes))
    context_diversity = unique_contexts / total if total > 0 else 0.0

    return QualityMetrics(
        total_samples=total,
        positive_samples=positive,
        negative_samples=negative,
        unique_secrets=unique_secrets,
        duplicate_rate=round(duplicate_rate, 4),
        secret_type_distribution=dict(secret_types),
        unique_code_contexts=unique_contexts,
        context_diversity_score=round(context_diversity, 4),
        duplicate_groups=duplicate_groups
    )


def load_dataset(file_path: str) -> List[Dict]:
    """Load a dataset from JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        return []


def print_quality_report(metrics: QualityMetrics, name: str):
    """Print formatted quality report."""
    print(f"\n{'='*60}")
    print(f" Quality Report: {name}")
    print(f"{'='*60}")
    print(f"  Total Samples:      {metrics.total_samples}")
    print(f"  Positive (secrets): {metrics.positive_samples}")
    print(f"  Negative (clean):   {metrics.negative_samples}")
    print(f"")
    print(f"  Unique Secrets:     {metrics.unique_secrets}")
    print(f"  Duplicate Rate:     {metrics.duplicate_rate*100:.1f}%")
    print(f"")
    print(f"  Secret Type Distribution:")
    for stype, count in sorted(metrics.secret_type_distribution.items()):
        pct = count / metrics.positive_samples * 100 if metrics.positive_samples > 0 else 0
        print(f"    - {stype}: {count} ({pct:.1f}%)")
    print(f"")
    print(f"  Unique Code Contexts: {metrics.unique_code_contexts}")
    print(f"  Context Diversity:    {metrics.context_diversity_score*100:.1f}%")

    if metrics.duplicate_groups:
        print(f"")
        print(f"  Most Duplicated Secrets:")
        for secret, count in metrics.duplicate_groups[:5]:
            print(f"    - '{secret}': {count}x")
    print(f"{'='*60}\n")


def compare_datasets(old_metrics: QualityMetrics, new_metrics: QualityMetrics,
                     old_name: str, new_name: str):
    """Print comparison between two dataset versions."""
    print(f"\n{'='*60}")
    print(f" Comparison: {old_name} → {new_name}")
    print(f"{'='*60}")

    def fmt_change(old_val, new_val, higher_better=True):
        diff = new_val - old_val
        if diff > 0:
            symbol = "↑" if higher_better else "↓"
            color = "+" if higher_better else "-"
        elif diff < 0:
            symbol = "↓" if higher_better else "↑"
            color = "-" if higher_better else "+"
        else:
            return "→ (no change)"
        return f"{symbol} {color}{abs(diff):.1f}"

    print(f"")
    print(f"  Metric                    {old_name:>12}  {new_name:>12}  Change")
    print(f"  {'-'*54}")
    print(f"  Unique Secrets            {old_metrics.unique_secrets:>12}  {new_metrics.unique_secrets:>12}  {fmt_change(old_metrics.unique_secrets, new_metrics.unique_secrets)}")
    print(f"  Duplicate Rate            {old_metrics.duplicate_rate*100:>11.1f}%  {new_metrics.duplicate_rate*100:>11.1f}%  {fmt_change(old_metrics.duplicate_rate*100, new_metrics.duplicate_rate*100, higher_better=False)}")
    print(f"  Secret Types              {len(old_metrics.secret_type_distribution):>12}  {len(new_metrics.secret_type_distribution):>12}  {fmt_change(len(old_metrics.secret_type_distribution), len(new_metrics.secret_type_distribution))}")
    print(f"  Context Diversity         {old_metrics.context_diversity_score*100:>11.1f}%  {new_metrics.context_diversity_score*100:>11.1f}%  {fmt_change(old_metrics.context_diversity_score*100, new_metrics.context_diversity_score*100)}")
    print(f"{'='*60}\n")

    # Overall assessment
    improvements = 0
    if new_metrics.unique_secrets > old_metrics.unique_secrets:
        improvements += 1
    if new_metrics.duplicate_rate < old_metrics.duplicate_rate:
        improvements += 1
    if len(new_metrics.secret_type_distribution) > len(old_metrics.secret_type_distribution):
        improvements += 1
    if new_metrics.context_diversity_score > old_metrics.context_diversity_score:
        improvements += 1

    if improvements >= 3:
        print("  Assessment: SIGNIFICANT IMPROVEMENT")
    elif improvements >= 2:
        print("  Assessment: MODERATE IMPROVEMENT")
    elif improvements >= 1:
        print("  Assessment: MINOR IMPROVEMENT")
    else:
        print("  Assessment: NO IMPROVEMENT (or regression)")
    print("")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate quality report for baseline datasets"
    )
    parser.add_argument(
        '--input',
        type=str,
        help='Input dataset JSON file'
    )
    parser.add_argument(
        '--compare',
        nargs=2,
        metavar=('OLD', 'NEW'),
        help='Compare two dataset versions'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output JSON file for metrics'
    )

    args = parser.parse_args()

    if args.compare:
        # Compare two datasets
        old_path, new_path = args.compare
        old_samples = load_dataset(old_path)
        new_samples = load_dataset(new_path)

        if not old_samples or not new_samples:
            return 1

        old_metrics = analyze_dataset(old_samples)
        new_metrics = analyze_dataset(new_samples)

        old_name = Path(old_path).stem
        new_name = Path(new_path).stem

        print_quality_report(old_metrics, old_name)
        print_quality_report(new_metrics, new_name)
        compare_datasets(old_metrics, new_metrics, old_name, new_name)

        if args.output:
            output_data = {
                old_name: old_metrics.to_dict(),
                new_name: new_metrics.to_dict()
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            logger.info(f"Saved metrics to {args.output}")

    elif args.input:
        # Single dataset report
        samples = load_dataset(args.input)
        if not samples:
            return 1

        metrics = analyze_dataset(samples)
        print_quality_report(metrics, Path(args.input).stem)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(metrics.to_dict(), f, indent=2)
            logger.info(f"Saved metrics to {args.output}")
    else:
        parser.print_help()
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
