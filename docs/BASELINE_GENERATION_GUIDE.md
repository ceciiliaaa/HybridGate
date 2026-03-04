# Baseline Generation Guide - 50/50 Hybrid/Synthetic Approach

## Overview

Das Framework generiert 100 Baseline-Samples für robuste statistische Auswertung:
- **50 Hybrid-Samples**: Echte GitHub PR-Metadaten + deterministische Code-Patterns
- **50 Synthetic-Samples**: LLM-generierte PRs (einmalig erstellt, dann frozen)

**Total: 100 Baseline → 800 Experiment-Samples** (×8 conditions)

## Prerequisites

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API Keys

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and add your keys
nano .env
```

Required:
- `OPENAI_API_KEY`: For synthetic PR generation (get from https://platform.openai.com/api-keys)

Optional:
- `GITHUB_TOKEN`: For higher rate limits when collecting PRs (get from https://github.com/settings/tokens)

## Complete Workflow

### Step 1: Collect GitHub PR Metadata (for Hybrid)

```bash
# Collect 100 real PRs from GitHub
python src/data_collection/github_pr_collector.py \
    --count 100 \
    --output data/01_raw/github_prs.json
```

**What this does:**
- Searches 8 popular Python repositories
- Filters for security-relevant PRs (auth, token, api keywords)
- Downloads PR title, body, and diff
- Rate limit: 60/hour (unauth) or 5000/hour (with token)

**Output:** `data/01_raw/github_prs.json`

### Step 2a: Generate Hybrid Baseline (50 samples)

```bash
# Generate 50 hybrid samples
python src/data_collection/hybrid_baseline_builder.py \
    --github-prs data/01_raw/github_prs.json \
    --target-samples 50 \
    --output data/03_baseline/b0_hybrid_samples.json
```

**What this does:**
- Uses real GitHub PR titles and descriptions
- Injects deterministic, realistic code patterns
- 8 different Python patterns (Stripe, AWS, OAuth, JWT, etc.)
- 100% success rate (guaranteed injection points)

**Output:** `data/03_baseline/b0_hybrid_samples.json` (50 samples)

### Step 2b: Generate Synthetic Baseline (50 samples)

```bash
# Generate 50 LLM-synthetic samples
python src/data_collection/build_synthetic_baseline.py \
    --scenarios config/synthetic_scenarios.json \
    --target-samples 50 \
    --output data/03_baseline/b0_synthetic_samples.json
```

**What this does:**
- Uses OpenAI GPT-4o-mini to generate complete PRs
- 15 diverse scenarios (Stripe, AWS, MongoDB, SendGrid, etc.)
- Generates title, body, and realistic diff with hardcoded secret
- Each sample is unique and realistic

**Cost estimate:** ~$0.50-1.00 for 50 samples

**Output:** `data/03_baseline/b0_synthetic_samples.json` (50 samples)

**⚠️ IMPORTANT:** Once generated, these samples are **frozen**. The synthetic baseline is deterministic from this point forward.

### Step 3: Merge Baselines

```bash
# Combine hybrid and synthetic baselines
python src/utils/merge_baselines.py \
    --inputs data/03_baseline/b0_hybrid_samples.json \
             data/03_baseline/b0_synthetic_samples.json \
    --output data/03_baseline/b0_combined_samples.json
```

**What this does:**
- Validates schema consistency
- Checks for duplicate IDs
- Merges into single dataset
- Logs statistics

**Output:** `data/03_baseline/b0_combined_samples.json` (100 samples)

### Step 4: Validate Combined Baseline

```bash
# Validate the merged baseline
python src/utils/validate_samples.py \
    data/03_baseline/b0_combined_samples.json
```

**Expected output:**
```
✓ All samples passed validation!
Total samples: 100
Valid samples: 100
Secret type distribution: {...}
Condition distribution: {'B0': 100}
```

### Step 5: Generate Perturbations

```bash
# Generate all 7 perturbation variants
python src/manipulation/perturbation_engine.py \
    --input data/03_baseline/b0_combined_samples.json \
    --output data/04_manipulated/experiment_samples.json
```

**What this does:**
- Generates E1-A, E1-B, E1-C (PR-text manipulation)
- Generates E2-A, E2-B (code-comment manipulation)
- Generates E3-A, E3-B (semantic obfuscation)
- Validates all perturbations

**Output:** `data/04_manipulated/experiment_samples.json` (800 samples)

### Step 6: Validate Experiment Dataset

```bash
# Validate perturbations
python src/utils/inspect_perturbations.py \
    data/04_manipulated/experiment_samples.json \
    --validate
```

**Expected output:**
```
Total Samples: 800
Condition Distribution:
  B0: 100
  E1-A: 100, E1-B: 100, E1-C: 100
  E2-A: 100, E2-B: 100
  E3-A: 100, E3-B: 100

✓ All perturbations passed validation!
```

## Quick Start (Testing)

For quick testing with small sample sizes:

```bash
# 1. Collect 20 PRs
python src/data_collection/github_pr_collector.py \
    --count 20 \
    --output data/01_raw/github_prs_test.json

# 2. Generate 5 hybrid + 5 synthetic
python src/data_collection/hybrid_baseline_builder.py \
    --github-prs data/01_raw/github_prs_test.json \
    --target-samples 5 \
    --output data/03_baseline/b0_hybrid_test.json

python src/data_collection/build_synthetic_baseline.py \
    --target-samples 5 \
    --output data/03_baseline/b0_synthetic_test.json

# 3. Merge and validate
python src/utils/merge_baselines.py \
    --inputs data/03_baseline/b0_hybrid_test.json \
             data/03_baseline/b0_synthetic_test.json \
    --output data/03_baseline/b0_combined_test.json

python src/utils/validate_samples.py \
    data/03_baseline/b0_combined_test.json
```

## Data Quality Checks

### Check Hybrid Samples

```python
import json

with open('data/03_baseline/b0_hybrid_samples.json') as f:
    samples = json.load(f)

print(f"Hybrid samples: {len(samples)}")
print(f"Sample IDs: {[s['sample_id'] for s in samples[:3]]}")
print(f"PR sources: {len(set(s['pr_title'] for s in samples))} unique titles")
```

### Check Synthetic Samples

```python
import json

with open('data/03_baseline/b0_synthetic_samples.json') as f:
    samples = json.load(f)

print(f"Synthetic samples: {len(samples)}")
print(f"Sample IDs: {[s['sample_id'] for s in samples[:3]]}")
print(f"Scenarios used: {len(set(s['pr_title'] for s in samples))} unique")
```

### Inspect Specific Sample

```bash
python src/utils/validate_samples.py \
    data/03_baseline/b0_combined_samples.json \
    --inspect SYNTH_001
```

## Synthetic Scenarios

The synthetic generator uses 15 diverse scenarios defined in `config/synthetic_scenarios.json`:

1. **Stripe Payment Integration** - Token
2. **AWS S3 Upload** - API Key
3. **GitHub Webhook** - Token
4. **PostgreSQL Database** - Password
5. **OAuth2 Client** - Token
6. **SMTP Email Service** - Password
7. **JWT Authentication** - Token
8. **Redis Cache** - Password
9. **Slack Notifications** - Token
10. **Twilio SMS** - API Key
11. **MongoDB Connection** - Connection String
12. **SendGrid Email** - API Key
13. **Cloudinary Media** - API Key
14. **API Gateway Auth** - API Key
15. **Elasticsearch** - Password

Each scenario generates a unique, realistic PR with:
- Context-appropriate title
- Descriptive body
- Valid unified diff format
- Realistic hardcoded secret

## Cost Estimation

### OpenAI API Costs (GPT-4o-mini)

```
Input: ~500 tokens per request
Output: ~400 tokens per request
Total: ~900 tokens per sample

50 samples × 900 tokens = 45,000 tokens
Cost: ~$0.007 per 1k tokens (input) + ~$0.028 per 1k tokens (output)
Total: ~$1.50 for 50 samples
```

### GitHub API (Free Tier)

```
Unauthenticated: 60 requests/hour
Authenticated: 5,000 requests/hour

Collecting 100 PRs: ~15 API calls
Well within free tier
```

## Troubleshooting

### "OPENAI_API_KEY not found"

```bash
# Check if .env exists
cat .env

# If not, copy example and edit
cp .env.example .env
nano .env  # Add your API key
```

### "Rate limit exceeded" (GitHub)

```bash
# Add GitHub token to .env
echo "GITHUB_TOKEN=your-token-here" >> .env

# Or wait 1 hour for rate limit reset
```

### "No injection points found" (Hybrid)

This shouldn't happen with hybrid approach, but if it does:
```bash
# Use pure synthetic instead
python src/data_collection/build_synthetic_baseline.py \
    --target-samples 100 \
    --output data/03_baseline/b0_synthetic_only.json
```

### "Invalid diff format" (Synthetic)

The LLM occasionally generates invalid diffs. The script automatically skips these and continues. If you see many failures:

1. Check your OpenAI API key is valid
2. Try increasing temperature: `--model gpt-4o` (better quality, higher cost)
3. Regenerate failed samples

## Output Schema

All baselines follow the same schema:

```json
{
  "sample_id": "SYNTH_001" or "REAL_001",
  "gt_has_secret": true,
  "gt_secret_type": "token|api_key|password|connection_string",
  "gt_file_path": "src/path/to/file.py",
  "gt_line_start": 42,
  "condition": "B0",
  "pr_title": "Add feature XYZ",
  "pr_body": "This PR implements...",
  "code_context": "diff --git a/... [unified diff]"
}
```

## Best Practices

1. **Generate synthetic baseline ONCE**
   - Synthetic samples should be frozen after initial generation
   - Commit to git for full reproducibility
   - Don't regenerate unless necessary

2. **Version control**
   ```bash
   # Add baselines to git (they're deterministic now)
   git add data/03_baseline/b0_synthetic_samples.json
   git commit -m "Add frozen synthetic baseline (50 samples)"
   ```

3. **Document generation**
   - Record date, model version, costs
   - Keep generation logs
   - Note any failed generations

4. **Test first**
   - Always test with 5-10 samples before full run
   - Validate output quality
   - Check API costs

## Next Steps

After generating 800 experiment samples:

1. **Implement LLM Evaluator**
   - Design prompt templates for code review
   - Integrate model APIs (Claude, GPT-4)
   - Parse and validate model outputs

2. **Run Experiments**
   - Evaluate all 800 samples
   - Calculate metrics per condition
   - Measure robustness-delta

3. **Analysis**
   - Statistical tests
   - Failure classification
   - Thesis writing

## Summary

This workflow provides:
- ✅ 100 baseline samples (50 hybrid + 50 synthetic)
- ✅ 800 total experiment samples (8 conditions)
- ✅ Full reproducibility
- ✅ Scientific validity
- ✅ Cost-effective (~$2 total)
- ✅ Robust statistical power

Perfect foundation for your Bachelor thesis! 🎓
