"""
Baseline Merge Utility

Merges multiple baseline JSON files into a single combined dataset.
Validates schema consistency and handles ID conflicts.

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
from pathlib import Path
from typing import List, Dict
from collections import Counter


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BaselineMerger:
    """Merges and validates baseline datasets."""

    REQUIRED_FIELDS = {
        'sample_id', 'gt_has_secret', 'gt_secret_type', 'gt_file_path',
        'gt_line_start', 'condition', 'pr_title', 'pr_body', 'code_context'
    }

    def __init__(self):
        """Initialize the merger."""
        self.samples: List[Dict] = []

    def load_baseline(self, file_path: str) -> List[Dict]:
        """
        Load a baseline JSON file.

        Args:
            file_path: Path to baseline JSON

        Returns:
            List of sample dictionaries
        """
        logger.info(f"Loading baseline from {file_path}...")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                samples = json.load(f)

            if not isinstance(samples, list):
                logger.error(f"File {file_path} does not contain a JSON array")
                return []

            logger.info(f"✓ Loaded {len(samples)} samples from {file_path}")
            return samples

        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
            return []

    def validate_sample(self, sample: Dict, source: str, index: int) -> List[str]:
        """
        Validate a single sample.

        Args:
            sample: Sample dictionary
            source: Source file name for error messages
            index: Sample index

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        missing_fields = self.REQUIRED_FIELDS - set(sample.keys())
        if missing_fields:
            errors.append(
                f"{source}[{index}]: Missing fields: {missing_fields}"
            )

        # Check field types
        if 'gt_has_secret' in sample and not isinstance(sample['gt_has_secret'], bool):
            errors.append(f"{source}[{index}]: gt_has_secret must be boolean")

        if 'gt_line_start' in sample and not isinstance(sample['gt_line_start'], int):
            errors.append(f"{source}[{index}]: gt_line_start must be integer")

        return errors

    def merge(self, input_paths: List[str], validate: bool = True) -> bool:
        """
        Merge multiple baseline files.

        Args:
            input_paths: List of input file paths
            validate: Whether to validate samples

        Returns:
            True if merge successful
        """
        logger.info(f"Merging {len(input_paths)} baseline files...")

        all_errors = []
        sample_ids = []

        for input_path in input_paths:
            samples = self.load_baseline(input_path)

            if not samples:
                logger.warning(f"Skipping empty file: {input_path}")
                continue

            source_name = Path(input_path).name

            # Validate if requested
            if validate:
                for i, sample in enumerate(samples):
                    errors = self.validate_sample(sample, source_name, i)
                    all_errors.extend(errors)
                    sample_ids.append(sample.get('sample_id', f'UNKNOWN_{i}'))

            self.samples.extend(samples)

        # Check for validation errors
        if all_errors:
            logger.error(f"Validation failed with {len(all_errors)} errors:")
            for error in all_errors[:10]:  # Show first 10
                logger.error(f"  - {error}")
            if len(all_errors) > 10:
                logger.error(f"  ... and {len(all_errors) - 10} more")
            return False

        # Check for duplicate IDs
        id_counts = Counter(sample_ids)
        duplicates = [sid for sid, count in id_counts.items() if count > 1]
        if duplicates:
            logger.warning(f"Found {len(duplicates)} duplicate sample IDs: {duplicates[:5]}")
            logger.warning("Consider renaming samples to ensure uniqueness")

        logger.info(f"✓ Merged {len(self.samples)} total samples")
        return True

    def save(self, output_path: str):
        """
        Save merged baseline to JSON.

        Args:
            output_path: Output file path
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.samples, f, indent=2, ensure_ascii=False)

        logger.info(f"✓ Saved {len(self.samples)} samples to {output_path}")

        # Log statistics
        self._log_statistics()

    def _log_statistics(self):
        """Log statistics about the merged dataset."""
        conditions = Counter(s.get('condition') for s in self.samples)
        secret_types = Counter(s.get('gt_secret_type') for s in self.samples)

        # Detect data sources by ID prefix
        sources = Counter()
        for sample in self.samples:
            sid = sample.get('sample_id', '')
            if sid.startswith('REAL_'):
                sources['Hybrid/Real'] += 1
            elif sid.startswith('SYNTH_'):
                sources['Synthetic'] += 1
            else:
                sources['Unknown'] += 1

        logger.info("\n--- Merged Dataset Statistics ---")
        logger.info(f"Total samples: {len(self.samples)}")
        logger.info(f"Data sources: {dict(sources)}")
        logger.info(f"Conditions: {dict(conditions)}")
        logger.info(f"Secret types: {dict(secret_types)}")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Merge multiple baseline JSON files"
    )
    parser.add_argument(
        '--inputs',
        nargs='+',
        required=True,
        help='Input baseline JSON files to merge'
    )
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Output merged JSON file path'
    )
    parser.add_argument(
        '--no-validate',
        action='store_true',
        help='Skip validation checks'
    )

    args = parser.parse_args()

    # Merge baselines
    merger = BaselineMerger()

    success = merger.merge(
        input_paths=args.inputs,
        validate=not args.no_validate
    )

    if not success:
        logger.error("Merge failed due to validation errors")
        return 1

    # Save merged dataset
    merger.save(args.output)

    logger.info("Merge complete!")
    return 0


if __name__ == '__main__':
    exit(main())
