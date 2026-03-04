"""
Inspection utility for perturbation samples.

This module provides tools to inspect and compare baseline and perturbed samples,
making it easy to verify that manipulations were applied correctly.
"""

import json
import logging
from typing import List, Dict, Optional
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PerturbationInspector:
    """Inspector for analyzing perturbation datasets."""

    def __init__(self, samples_path: str):
        """
        Initialize the inspector.

        Args:
            samples_path: Path to the experiment samples JSON file
        """
        self.samples_path = samples_path
        self.samples = self._load_samples()
        self.samples_by_id = self._index_samples()

    def _load_samples(self) -> List[Dict]:
        """Load samples from JSON file."""
        with open(self.samples_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _index_samples(self) -> Dict[str, List[Dict]]:
        """Index samples by base ID."""
        indexed = defaultdict(list)

        for sample in self.samples:
            # Extract base ID (e.g., 'REAL_001' from 'REAL_001_E1-A')
            base_id = '_'.join(sample['sample_id'].split('_')[:2])
            indexed[base_id].append(sample)

        return indexed

    def get_sample_family(self, base_id: str) -> List[Dict]:
        """
        Get all variants (B0 + perturbations) for a base sample.

        Args:
            base_id: Base sample ID (e.g., 'REAL_001')

        Returns:
            List of all samples with this base ID
        """
        return self.samples_by_id.get(base_id, [])

    def compare_variants(self, base_id: str):
        """
        Compare all variants of a sample.

        Args:
            base_id: Base sample ID to compare
        """
        family = self.get_sample_family(base_id)

        if not family:
            logger.error(f"No samples found with base ID: {base_id}")
            return

        # Sort by condition
        family = sorted(family, key=lambda s: s['condition'])

        logger.info(f"\n{'='*80}")
        logger.info(f"Sample Family: {base_id}")
        logger.info(f"Total Variants: {len(family)}")
        logger.info(f"{'='*80}\n")

        # Find baseline
        baseline = next((s for s in family if s['condition'] == 'B0'), None)

        if baseline:
            logger.info("--- BASELINE (B0) ---")
            self._print_sample_summary(baseline)
            logger.info("")

        # Print each perturbation
        for sample in family:
            if sample['condition'] == 'B0':
                continue

            logger.info(f"--- {sample['condition']} ---")
            self._print_sample_summary(sample)

            # Show differences from baseline
            if baseline:
                self._print_diff(baseline, sample)

            logger.info("")

    def _print_sample_summary(self, sample: Dict):
        """Print a summary of a sample."""
        logger.info(f"ID: {sample['sample_id']}")
        logger.info(f"Condition: {sample['condition']}")
        logger.info(f"Secret Type: {sample['gt_secret_type']}")
        logger.info(f"Line: {sample['gt_line_start']}")

    def _print_diff(self, baseline: Dict, perturbed: Dict):
        """Print differences between baseline and perturbed sample."""
        logger.info("Changes from baseline:")

        # Check PR body
        if baseline['pr_body'] != perturbed['pr_body']:
            logger.info("  ✓ PR Body modified:")
            added = perturbed['pr_body'][len(baseline['pr_body']):]
            logger.info(f"    Added: {repr(added[:100])}")

        # Check code context
        if baseline['code_context'] != perturbed['code_context']:
            logger.info("  ✓ Code Context modified")

        # Check line number
        if baseline['gt_line_start'] != perturbed['gt_line_start']:
            logger.info(f"  ✓ Line number changed: {baseline['gt_line_start']} → {perturbed['gt_line_start']}")

    def print_statistics(self):
        """Print overall statistics about the dataset."""
        from collections import Counter

        conditions = [s['condition'] for s in self.samples]
        secret_types = [s['gt_secret_type'] for s in self.samples]

        logger.info("\n" + "="*80)
        logger.info("DATASET STATISTICS")
        logger.info("="*80)
        logger.info(f"Total Samples: {len(self.samples)}")
        logger.info(f"Unique Base Samples: {len(self.samples_by_id)}")
        logger.info("")
        logger.info("Condition Distribution:")
        for condition, count in sorted(Counter(conditions).items()):
            logger.info(f"  {condition}: {count}")
        logger.info("")
        logger.info("Secret Type Distribution:")
        for stype, count in sorted(Counter(secret_types).items()):
            logger.info(f"  {stype}: {count}")
        logger.info("="*80 + "\n")

    def validate_perturbations(self) -> Dict[str, List[str]]:
        """
        Validate that perturbations were applied correctly.

        Returns:
            Dictionary of validation issues by condition
        """
        issues = defaultdict(list)

        for base_id, family in self.samples_by_id.items():
            baseline = next((s for s in family if s['condition'] == 'B0'), None)

            if not baseline:
                issues['GENERAL'].append(f"No baseline found for {base_id}")
                continue

            for sample in family:
                condition = sample['condition']

                if condition == 'B0':
                    continue

                # Validate E1 conditions (PR body should change, code should not)
                if condition.startswith('E1'):
                    if baseline['pr_body'] == sample['pr_body']:
                        issues[condition].append(f"{sample['sample_id']}: PR body not modified")
                    if baseline['code_context'] != sample['code_context']:
                        issues[condition].append(f"{sample['sample_id']}: Code should not change in E1")

                # Validate E2 conditions (code should change, PR body should not)
                elif condition.startswith('E2'):
                    if baseline['code_context'] == sample['code_context']:
                        issues[condition].append(f"{sample['sample_id']}: Code context not modified")
                    if baseline['pr_body'] != sample['pr_body']:
                        issues[condition].append(f"{sample['sample_id']}: PR body should not change in E2")

                # Validate E3 conditions (code should change, PR body should not)
                elif condition.startswith('E3'):
                    if baseline['code_context'] == sample['code_context']:
                        issues[condition].append(f"{sample['sample_id']}: Code context not modified")
                    if baseline['pr_body'] != sample['pr_body']:
                        issues[condition].append(f"{sample['sample_id']}: PR body should not change in E3")

        return dict(issues)

    def print_validation_results(self):
        """Print validation results."""
        issues = self.validate_perturbations()

        logger.info("\n" + "="*80)
        logger.info("VALIDATION RESULTS")
        logger.info("="*80)

        if not issues:
            logger.info("✓ All perturbations passed validation!")
        else:
            logger.warning(f"Found issues in {len(issues)} condition(s):")
            for condition, condition_issues in sorted(issues.items()):
                logger.warning(f"\n{condition}:")
                for issue in condition_issues[:5]:  # Show first 5
                    logger.warning(f"  - {issue}")
                if len(condition_issues) > 5:
                    logger.warning(f"  ... and {len(condition_issues) - 5} more")

        logger.info("="*80 + "\n")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Inspect and validate perturbation samples"
    )
    parser.add_argument(
        'file',
        help='Path to experiment samples JSON file'
    )
    parser.add_argument(
        '--compare',
        help='Compare all variants of a specific base ID (e.g., REAL_001)'
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Run validation checks'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Print dataset statistics'
    )

    args = parser.parse_args()

    inspector = PerturbationInspector(args.file)

    if args.stats:
        inspector.print_statistics()

    if args.compare:
        inspector.compare_variants(args.compare)

    if args.validate:
        inspector.print_validation_results()

    # If no specific action, print stats and validate
    if not (args.stats or args.compare or args.validate):
        inspector.print_statistics()
        inspector.print_validation_results()


if __name__ == '__main__':
    main()
