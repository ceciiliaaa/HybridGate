"""
Validation utilities for ground truth samples.

This module provides functions to validate the schema and quality of generated samples.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SampleValidator:
    """Validates ground truth samples against the required schema."""

    REQUIRED_FIELDS = {
        'sample_id': str,
        'gt_has_secret': bool,
        'gt_secret_type': str,
        'gt_file_path': str,
        'gt_line_start': int,
        'condition': str,
        'pr_title': str,
        'pr_body': str,
        'code_context': str
    }

    VALID_CONDITIONS = {'B0', 'E1', 'E2', 'E3'}
    VALID_SECRET_TYPES = {'token', 'api_key', 'password', 'private_key', 'connection_string', 'other'}

    @staticmethod
    def validate_sample(sample: Dict, sample_index: int) -> List[str]:
        """
        Validate a single sample against the schema.

        Args:
            sample: Sample dictionary to validate
            sample_index: Index of the sample (for error reporting)

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Check required fields
        for field, expected_type in SampleValidator.REQUIRED_FIELDS.items():
            if field not in sample:
                errors.append(f"Sample {sample_index}: Missing required field '{field}'")
            elif not isinstance(sample[field], expected_type):
                errors.append(
                    f"Sample {sample_index}: Field '{field}' has type {type(sample[field]).__name__}, "
                    f"expected {expected_type.__name__}"
                )

        # Validate condition
        if sample.get('condition') not in SampleValidator.VALID_CONDITIONS:
            errors.append(
                f"Sample {sample_index}: Invalid condition '{sample.get('condition')}', "
                f"must be one of {SampleValidator.VALID_CONDITIONS}"
            )

        # Validate secret_type
        if sample.get('gt_secret_type') not in SampleValidator.VALID_SECRET_TYPES:
            errors.append(
                f"Sample {sample_index}: Invalid secret_type '{sample.get('gt_secret_type')}', "
                f"must be one of {SampleValidator.VALID_SECRET_TYPES}"
            )

        # Validate line number
        if sample.get('gt_line_start', 0) < 1:
            errors.append(f"Sample {sample_index}: Line number must be >= 1")

        # Check for empty strings
        string_fields = ['sample_id', 'gt_file_path', 'pr_title', 'code_context']
        for field in string_fields:
            if field in sample and not sample[field].strip():
                errors.append(f"Sample {sample_index}: Field '{field}' cannot be empty")

        return errors

    @staticmethod
    def validate_dataset(samples: List[Dict]) -> Dict:
        """
        Validate an entire dataset.

        Args:
            samples: List of sample dictionaries

        Returns:
            Dictionary with validation results and statistics
        """
        all_errors = []
        sample_ids = []

        for i, sample in enumerate(samples):
            errors = SampleValidator.validate_sample(sample, i)
            all_errors.extend(errors)
            sample_ids.append(sample.get('sample_id', f'UNKNOWN_{i}'))

        # Check for duplicate IDs
        id_counts = Counter(sample_ids)
        duplicates = [sid for sid, count in id_counts.items() if count > 1]
        if duplicates:
            all_errors.append(f"Duplicate sample IDs found: {duplicates}")

        # Gather statistics
        stats = {
            'total_samples': len(samples),
            'valid_samples': len(samples) - len([e for e in all_errors if 'Sample' in e]),
            'errors': all_errors,
            'secret_type_distribution': Counter(s.get('gt_secret_type') for s in samples),
            'condition_distribution': Counter(s.get('condition') for s in samples),
            'avg_context_length': sum(len(s.get('code_context', '')) for s in samples) / len(samples) if samples else 0
        }

        return stats


def load_and_validate(file_path: str) -> Dict:
    """
    Load a samples JSON file and validate it.

    Args:
        file_path: Path to the JSON file

    Returns:
        Validation results dictionary
    """
    logger.info(f"Loading samples from {file_path}...")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            samples = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load file: {e}")
        return {'errors': [f"Failed to load file: {e}"]}

    if not isinstance(samples, list):
        return {'errors': ["File must contain a JSON array of samples"]}

    logger.info(f"Loaded {len(samples)} samples. Validating...")

    results = SampleValidator.validate_dataset(samples)

    # Log results
    if results['errors']:
        logger.warning(f"Validation found {len(results['errors'])} errors:")
        for error in results['errors'][:10]:  # Show first 10 errors
            logger.warning(f"  - {error}")
        if len(results['errors']) > 10:
            logger.warning(f"  ... and {len(results['errors']) - 10} more errors")
    else:
        logger.info("✓ All samples passed validation!")

    logger.info("\n--- Statistics ---")
    logger.info(f"Total samples: {results['total_samples']}")
    logger.info(f"Valid samples: {results['valid_samples']}")
    logger.info(f"Secret type distribution: {dict(results['secret_type_distribution'])}")
    logger.info(f"Condition distribution: {dict(results['condition_distribution'])}")
    logger.info(f"Average context length: {results['avg_context_length']:.0f} characters")

    return results


def inspect_sample(file_path: str, sample_id: str):
    """
    Inspect a specific sample by ID.

    Args:
        file_path: Path to the JSON file
        sample_id: ID of the sample to inspect
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        samples = json.load(f)

    sample = next((s for s in samples if s.get('sample_id') == sample_id), None)

    if not sample:
        logger.error(f"Sample '{sample_id}' not found")
        return

    logger.info(f"\n--- Sample: {sample_id} ---")
    logger.info(f"Condition: {sample.get('condition')}")
    logger.info(f"Has Secret: {sample.get('gt_has_secret')}")
    logger.info(f"Secret Type: {sample.get('gt_secret_type')}")
    logger.info(f"File: {sample.get('gt_file_path')}")
    logger.info(f"Line: {sample.get('gt_line_start')}")
    logger.info(f"\nPR Title: {sample.get('pr_title')}")
    logger.info(f"PR Body: {sample.get('pr_body')[:100]}...")
    logger.info(f"\nCode Context:\n{sample.get('code_context')}")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Validate ground truth samples")
    parser.add_argument('file', help='Path to samples JSON file')
    parser.add_argument('--inspect', help='Inspect specific sample by ID')

    args = parser.parse_args()

    if args.inspect:
        inspect_sample(args.file, args.inspect)
    else:
        results = load_and_validate(args.file)

        if results['errors']:
            exit(1)


if __name__ == '__main__':
    main()
