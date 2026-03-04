# Quick Start Guide

## Installation

1. **Create and activate virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## Generate Baseline Data (B0)

Generate 50 baseline samples with real PRs and injected secrets:

```bash
python src/data_collection/build_real_baseline.py \
    --context-window 15 \
    --target-samples 50 \
    --output data/03_baseline/b0_real_samples.json
```

### Parameters:
- `--context-window N`: Number of lines ±N around the secret (default: 15)
- `--target-samples N`: Target number of samples to generate (default: 50)
- `--output PATH`: Output JSON file path

## Validate Generated Data

Validate the schema and quality of generated samples:

```bash
python src/utils/validate_samples.py data/03_baseline/b0_real_samples.json
```

Inspect a specific sample:

```bash
python src/utils/validate_samples.py data/03_baseline/b0_real_samples.json --inspect REAL_001
```

## Understanding the Output

Each sample in the JSON output follows this schema:

```json
{
  "sample_id": "REAL_001",           // Unique identifier
  "gt_has_secret": true,              // Ground truth: secret present
  "gt_secret_type": "token",          // Type: token, api_key, password, etc.
  "gt_file_path": "src/auth/middleware.py",  // File path in PR
  "gt_line_start": 9,                 // Line number of secret
  "condition": "B0",                  // Experimental condition (B0=Baseline)
  "pr_title": "Add authentication...", // PR title
  "pr_body": "This PR adds...",       // PR description
  "code_context": "... code diff ..." // Code snippet with ±N lines
}
```

## What's Next?

After generating the baseline (B0), you can:

1. **Create manipulation variants** (E1, E2, E3) based on the baseline
2. **Implement LLM reviewer** evaluation pipeline
3. **Run experiments** with different models
4. **Calculate robustness metrics** (Precision, Recall, F1, FNR)
5. **Perform failure analysis** on misclassifications

## Project Structure

```
BA/
├── data/
│   ├── 01_raw/              # Raw data from datasets
│   ├── 02_interim/          # Intermediate processing
│   └── 03_baseline/         # Baseline samples (B0)
├── src/
│   ├── data_collection/     # Dataset generation scripts
│   │   └── build_real_baseline.py
│   └── utils/               # Validation and utilities
│       └── validate_samples.py
├── requirements.txt         # Python dependencies
├── README.md               # Full documentation
└── QUICKSTART.md          # This file
```

## Common Issues

### Dataset Loading Fails
If the HuggingFace dataset fails to load, the script automatically falls back to synthetic PR generation. This is normal and provides realistic samples for testing.

### No Injection Points Found
If many PRs are skipped, it means they don't have suitable string assignments for secret injection. The script will continue processing until it reaches the target number of samples.

## Support

For issues or questions about the evaluation framework, please refer to the main [README.md](README.md) or the thesis documentation in the `docs/` folder.
