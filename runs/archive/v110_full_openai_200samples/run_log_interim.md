# v110 Run — Interim Status

**Snapshot:** 2026-03-15 13:58 UTC
**Status:** Running (92/200 samples completed)

## Progress

| Metric | Value |
|--------|-------|
| Samples completed | 92/200 (46%) |
| API errors | 0 |
| Retries | 0 |
| Warnings | 0 |
| Avg time/sample | ~15-20 sec |
| Estimated finish | ~25-30 min remaining |

## Samples Processed So Far

- REAL_001 through REAL_050 (50 samples)
- SYNTH_001 through SYNTH_042 (42 samples)
- Total: 92 B0 (baseline) samples

## Not Yet Processed

- SYNTH_043 through SYNTH_050 (8 remaining SYNTH baseline)
- NEG_CLEAN_001 through NEG_CLEAN_025 (25 samples)
- NEG_DECOY_001 through NEG_DECOY_025 (25 samples)
- All 50 perturbation samples (E1-B, E2-A, E3-A, E3-B)

## Observations

- 0% error rate so far (was 0% in v100 frozen run too)
- No timeout issues (120s client timeout active)
- First run attempt hung at SYNTH_009 (no client timeout); this 2nd run has the fix
- All API calls returning HTTP 200

## Note

Actual prediction data (TP/FP/TN/FN) is not available until results.json is written at run completion. This interim report only covers operational metrics from the process log.
