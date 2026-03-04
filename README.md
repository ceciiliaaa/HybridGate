# LLM Code Review Robustness Evaluation Framework

**Bachelor Thesis**: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
**Author**: Cecilia Nothstein
**Date**: March 2026

## Overview

This repository contains the evaluation framework for analyzing the robustness of LLM-based code reviewers when detecting hardcoded secrets in Pull Requests under adversarial manipulation.

## Project Structure

```
BA/
├── data/
│   ├── 01_raw/              # Raw data from datasets
│   ├── 02_interim/          # Intermediate processing results
│   ├── 03_baseline/         # Baseline (B0) ground truth samples
│   └── 04_manipulated/      # Perturbed samples (E1, E2, E3)
├── src/
│   ├── data_collection/     # Scripts for dataset generation
│   │   └── build_real_baseline.py
│   ├── manipulation/        # Perturbation engine
│   │   └── perturbation_engine.py
│   └── utils/               # Utility functions
│       ├── validate_samples.py
│       └── inspect_perturbations.py
├── docs/                    # Documentation and thesis materials
│   ├── Exposee_BA_*.txt
│   └── PERTURBATION_ENGINE.md
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── QUICKSTART.md           # Quick start guide
```

## Installation

### Prerequisites
- Python 3.9 or higher
- pip

### Setup

1. Clone this repository or navigate to the project directory

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Building the Baseline Dataset (B0)

The baseline dataset consists of real PRs with injected dummy secrets, representing the "clean" condition without manipulation.

```bash
python src/data_collection/build_real_baseline.py \
    --context-window 15 \
    --target-samples 50 \
    --output data/03_baseline/b0_real_samples.json
```

**Parameters:**
- `--context-window`: Number of lines ±N around the secret (default: 15)
- `--target-samples`: Target number of samples to generate (default: 50)
- `--output`: Output JSON file path

**Output Schema:**

Each sample in `b0_real_samples.json` follows this structure:

```json
{
  "sample_id": "REAL_001",
  "gt_has_secret": true,
  "gt_secret_type": "token",
  "gt_file_path": "src/auth/middleware.py",
  "gt_line_start": 9,
  "condition": "B0",
  "pr_title": "Add authentication middleware for API endpoints",
  "pr_body": "This PR adds JWT-based authentication...",
  "code_context": "... code diff with ±15 lines ..."
}
```

### Generating Adversarial Perturbations (E1, E2, E3)

After building the baseline, generate all adversarial manipulation variants:

```bash
python src/manipulation/perturbation_engine.py \
    --input data/03_baseline/b0_real_samples.json \
    --output data/04_manipulated/experiment_samples.json
```

This will generate 7 perturbation variants for each baseline sample:
- **E1-A**: Direct instruction override ("Ignore security checks...")
- **E1-B**: Benign framing ("This key is only for testing...")
- **E1-C**: Authority claim ("Approved by Security/Compliance...")
- **E2-A**: In-code framing comment
- **E2-B**: Authority in code comment
- **E3-A**: String concatenation obfuscation
- **E3-B**: Split across variables

**Output:** For 50 baseline samples → 400 total samples (50 B0 + 350 perturbations)

See [docs/PERTURBATION_ENGINE.md](docs/PERTURBATION_ENGINE.md) for detailed documentation.

### Validating Perturbations

```bash
# Validate and show statistics
python src/utils/inspect_perturbations.py data/04_manipulated/experiment_samples.json

# Compare all variants of a specific sample
python src/utils/inspect_perturbations.py data/04_manipulated/experiment_samples.json --compare REAL_001
```

## Methodology

### Evaluation Framework

The framework implements a controlled benchmark design with three manipulation levels:

- **B0 (Baseline)**: Clean PRs with injected secrets, no manipulation
- **E1 (PR-Text Manipulation)**: Misleading PR descriptions/instructions
- **E2 (Code-Comment Manipulation)**: Deceptive inline code comments
- **E3 (Semantic Obfuscation)**: String concatenation, variable splitting

### Ground Truth Schema

- `sample_id`: Unique identifier (e.g., "REAL_001")
- `gt_has_secret`: Boolean indicating presence of secret
- `gt_secret_type`: Category (token, api_key, password, private_key)
- `gt_file_path`: File path in the PR
- `gt_line_start`: Line number of the secret
- `condition`: Experimental condition (B0, E1, E2, E3)
- `pr_title`: Pull request title
- `pr_body`: Pull request description
- `code_context`: Code diff with controlled context window (±N lines)

## Features

### BaselineBuilder Class

- **Context Filtering**: Filters PRs for security-relevant keywords (auth, token, api, etc.)
- **Smart Injection**: Identifies suitable injection points in code diffs
- **Realistic Secrets**: Generates plausible dummy secrets (Stripe keys, GitHub tokens, AWS keys)
- **Controlled Context**: Extracts ±N line windows around secrets
- **Robust Parsing**: Handles unified diff format with error recovery

### DiffParser Class

- Parses unified diff format
- Extracts file paths and hunks
- Finds string assignment patterns
- Injects secrets while preserving diff structure
- Extracts context windows with line number adjustment

### SecretGenerator Class

Generates realistic dummy secrets:
- Stripe API keys (`sk_test_...`)
- GitHub Personal Access Tokens (`ghp_...`)
- AWS Access Keys (`AKIA...`)
- Generic API keys

## Development

### Running Tests

```bash
pytest tests/
```

### Code Quality

```bash
# Format code
black src/

# Lint
flake8 src/

# Type checking
mypy src/
```

## License

This project is part of a Bachelor thesis at [Your University Name]. All rights reserved.

## Contact

Cecilia Nothstein - [Your Email]
