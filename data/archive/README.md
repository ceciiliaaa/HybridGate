# Dataset Archive

Archived dataset versions. Current version is always in `data/03_baseline/`.

**SAFETY POLICY: Data is NEVER deleted. All versions are preserved in this archive.**

## Structure

```
data/
├── 03_baseline/          # Active version (generic names)
│   ├── all_150_samples.json
│   ├── real_samples.json
│   ├── synthetic_samples.json
│   ├── negative_controls.json
│   ├── manifest.json     # Contains version info
│   └── quality_report.json
│
└── archive/              # Historical versions
    ├── b0/               # Original (deprecated)
    ├── b1/               # Fixed secrets (deprecated)
    └── b2/               # (after next archive)
```

## Usage

```bash
# Show status
python -m src.utils.archive_dataset --status

# Archive current and prepare new version
python -m src.utils.archive_dataset --prepare-new --description "Description of changes"

# Only archive (without preparing new)
python -m src.utils.archive_dataset --archive --description "Why archived"
```

---

## Version History

### b0/ (2026-03-03)
**Status:** Deprecated - Critical issues

- REAL: Only 3 unique secrets (94% duplicates)
- Root cause: `generate_secret()` defaulted to `stripe_key`
- Unique secrets: 38/100 (38%)

### b1/ (2026-03-10)
**Status:** Deprecated - Partial fix

- Fixed secret category rotation
- REAL unique secrets: 3 → 50
- Remaining issue: All 50 REAL samples collapsed to same template
- Context diversity: 0.01

### Current: b2 (in data/03_baseline/)
**Status:** Active

- 15 diverse context families
- 100% unique secrets in REAL
- Context diversity: 0.593
- See `data/03_baseline/manifest.json` for details
