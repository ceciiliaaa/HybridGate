# Changelog

Development history of the HybridGate artifact. Entries before 11 May 2026 cover
the work described in the thesis. Entries after it cover the artifact only, and
the places where it has since moved away from the written specification are
listed in the README under "Where implementation and thesis diverge".

---

## [2026-09-06] Artifact cleanup and policy redesign

### Policy layer

- **P2 Contextual-Veto** and **P3 Risk-Weighted** replace the earlier P2 Consensus
  and P3 Escalation, which did not model the guardrail signals and therefore
  collapsed onto the same scanner and LLM inputs as P1.
- Shared fail-closed pre-policy rule for all three: a G5 schema that is still
  invalid after repair, or a G3 leak that persists after mitigation, forces
  REVIEW.
- The P2 veto condition was reduced during implementation. The specified
  `not R` term was dropped because G4 fires on every `NEG_DECOY` sample, which
  would have disabled the veto entirely, and `not C` was added instead.
- `src/scripts/run_policy_comparison_v2.py` re-simulates all three policies on
  the frozen guardrail outputs, so policy changes no longer need a paid re-run.
  `runs/policy_results/policy_comparison_v2.json` is the authoritative source for
  every policy figure.

### Metrics

- FM6 added to the Prevalence, Intervention and Residual analysis. The failure
  mode was implemented as G6 but had never appeared in the PRI tables.
- `policy_resimulation_hook` implemented instead of returning `None`, so the
  policy rows in the metric outputs come from current code rather than from
  values stored at evaluation time.

### Dataset and runs

- The 250-sample benchmark `all_250_samples_extreme.json` is now tracked. It had
  been excluded by a `.gitignore` rule while its superseded predecessors were
  committed, which made a clean clone unreproducible.
- `SYNTH_017`, `SYNTH_040` and `NEG_DECOY_008` in the v140 run were replaced by
  their v130 counterparts, in which the same samples produced `schema_valid=false`
  and were routed by G5. Without this, FM5 had no positive instance for OpenAI and
  could not be compared across providers. Alert-level metrics are unchanged.

### Infrastructure

- CI added in `.github/workflows/tests.yml`. Two jobs: the 128 unit tests on
  Python 3.10 and 3.12, and a reproduction job that regenerates all 26 evaluation
  tables from the frozen model output and diffs them against the committed
  versions. The reproduction job deliberately performs no `pip install`, because
  the entire chain from `results.json` to the published tables is standard library
  only.
- `requirements.txt` reduced from 26 declared packages to the 6 the code actually
  imports. It had pulled `torch` and `transformers`, roughly 2 GB, for a project
  that imports neither. Test and lint tooling moved to `requirements-dev.txt`.
- `ANTHROPIC_API_KEY` added to `.env.example`. It was required by
  `run_evaluation.py` but never documented.
- Removed from the working tree, all recoverable from git history: `Archiv/`,
  `QUICKSTART.md` (documented a workflow whose input files no longer exist),
  `docs/EVALUATION_RESULTS.md` (superseded by the cross-provider synthesis) and an
  undocumented variant run.
- README rewritten as a description of the research artifact, with the thesis
  figures in English.

---

## [2026-04-16] G6 to G4 coupling and the Anthropic run (v150)

- **G4 rule R7**: G6 finds a format-familiar candidate before the model call and
  the LLM still reports no secret, so with a corroborating signal the decision
  escalates to REVIEW. Recovers 19 of 20 FM6 false negatives in the Anthropic run
  with no false escalations.
- `get_g6_prescan()` replaces `get_g6_hint()`, and the prescan metadata flows into
  the G4 context.
- Alert-level fields `llm_guardrail_raw_hit` and `llm_guardrail_alert_hit` added,
  which separates the alert-level view from the raw model prediction.
- **Claude Opus 4.6 evaluated** on the identical 250 samples, turning the study
  into a cross-provider comparison. Notable: G2 never fires on Anthropic (0 of
  250, against 10 of 250 on OpenAI), and baseline evidence leakage is 28.0%
  against 52.4%.

## [2026-03-23] G6 forced reasoning and the 250-sample run (v140)

- G6 integrated as a forced-reasoning step ahead of the model call.
- Evaluation extended from 200 to 250 samples.
- Old runs, data and debug scripts archived.

## [2026-03-20] G4 rule R6 and the G6 guardrail (v130)

- **G4 rule R6**: a hardcoded value in an authentication-sensitive URL context
  where the model reported no secret escalates to REVIEW. Catches generic
  credentials such as `prod-7xK2mP9nL` that look like config labels.
- **G6 Format-Familiarity** added as the sixth guardrail, addressing FM6.

## [2026-03-16] Final run v121, and the G5 bug that invalidated v120

- **Bug**: G5 rejected the `confidence` field that G4 requires, which misrouted
  166 of 200 samples and produced a guardrail recall of 2%.
- **Fix**: `("confidence", str, False)` added to `OPTIONAL_FIELDS` in
  `g5_schema_validation.py`. The test that asserted the wrong behaviour was
  inverted.
- v120 is retained unchanged at `runs/archive/v120_final_extreme_openai/` next to
  its corrected successor.
- Results at alert level: scanner recall 84.0%, LLM baseline 99.3%, guardrails
  100%. A data leakage audit found nothing that affected the results.

## [2026-03-15] Guardrail hardening G1 to G5, 200 samples

- **G3 rewritten** as a fail-closed three-layer design (detect, redact once,
  REVIEW), with 16 regex patterns, entropy spans, candidate echo detection and
  reconstructed leak detection over the full JSON serialisation.
- **G4 added**: rule-based uncertainty escalation with rules R1 to R4 over flags
  inferred from file path, PR metadata, code context and scanner results.
- **G5 added**: schema validation with a repair step.
- **G1 extended** with diff context validation, **G2** with
  `validate_with_details()` for the G4 integration.
- Pipeline order fixed as G5, G2, G4, G1, G3.
- Extreme perturbation dataset built: 150 positive and 50 negative samples, with
  50 hardened positives revised by hand.

## [2026-03-10] Dataset versioning, and two dataset defects found and fixed

- **Archive system** (`src/utils/archive_dataset.py`) with automatic version
  detection and an integrity check before any deletion. Data is archived, never
  deleted.
- **B0 defect**: only 3 unique secrets across 50 real samples, a 94% duplicate
  rate, because `generate_secret()` defaulted to `stripe_key`. Fixed by
  `generate_unique_secret()` with per-sample suffixes and 6 new secret categories.
- **B1 defect**: all 50 real samples collapsed onto a single template, with
  repeating hex patterns in the secrets and a context diversity score of 0.01.
  Fixed by 15 context families, each with its own PR template and file path, and a
  realistic secret generator without repeating patterns. Diversity rose to 0.593.

## [2026-03-10] HybridGate modules

Guardrails G1 to G5, policies P1 to P3, scanner wrappers for gitleaks and
detect-secrets behind a shared abstract base class, and the metrics layer with
model metrics, gate metrics and McNemar tests.

## [2026-03-03] Initial setup

Project structure, B0 baseline with 50 real, 50 synthetic and 50 negative
samples, evaluation framework, GitHub pull request collector.

---

## Conventions

**Dataset versioning.** The active version lives in `data/03_baseline/` under
generic filenames, superseded versions in `data/archive/bX/`. The manifest records
the version, its metrics and the command that regenerates it.

**Runs.** Superseded runs stay in `runs/archive/`, including the invalid ones,
because a run that was wrong is evidence too.

**Safety policy.** Data is archived, not deleted. For code and documentation, git
history is the archive.

**Commits.** English, short summary followed by the reasoning. Work done with
assistance from Claude Code carries a `Co-Authored-By` trailer, consistent with
the AI usage declaration in the thesis.
