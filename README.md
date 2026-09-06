# HybridGate

**A hybrid pre-merge gate for detecting hardcoded secrets in pull requests, hardened by six guardrails**

> Bachelor thesis by **Cecilia Nothstein**<br>
> DHBW Stuttgart, Business Information Systems<br>
> Written in cooperation with **Mercedes-Benz Group AG** @ AI Security Engineering

Conventional secret scanners miss about a third of hardcoded credentials, 63 of 200
in this benchmark, because a value's sensitivity comes from how it is used rather
than from how it looks. An LLM reviewer can read that context, and it brings six
failure modes of its own:

![Pull request whose title and description claim the key is a placeholder, while the diff adds a live Stripe key](docs/figures/pr-exculpatory-metadata.png)

*Title and description assert a harmless test value. The diff adds a production
Stripe key. Both go into the same prompt, and nothing in a transformer separates
authoritative code evidence from the contributor's free text.*

This repository is the artifact of a Design Science Research thesis asking where
those failure modes limit an LLM reviewer, and how far a deterministic layer
around it can make LLM-assisted review more reliable and more controllable
inside a DevSecOps pre-merge gate.

> **RQ** What limits emerge when LLM-assisted code review is used to detect
> hardcoded secrets in pull requests, and to what extent can they be secured
> through targeted measures for operational DevSecOps use?
>
> **SRQ 1** Which typical failure modes occur when LLM-assisted code review is used
> to detect hardcoded secrets in pull requests?<br>
> **SRQ 2** To what extent can the identified failure modes be reduced by suitable
> guardrail measures?<br>
> **SRQ 3** What follows for the design of a practically viable deployment of
> LLM-assisted code review in a DevSecOps context?

The short answer: the limit is not the ability to detect, but the **operational
reliability of the findings**. Guardrails raise operational recall from 0.870 to 0.990
(OpenAI) and from 0.835 to 0.995 (Anthropic), and they remove 100% of observed
secret leakage from the model's own output. A large part of that gain is
escalation to human review rather than better classification. An unhardened LLM
reviewer is therefore not a replacement for a classic scanner. It is a
context-sensitive addition inside a controlled architecture.

---

## Two stages

![HybridGate architecture: a pull request enters both the conventional scanners and the guardrail-wrapped LLM reviewer, and both signals meet in the policy engine](docs/figures/hybridgate-architecture.png)

Stage 1 hardens the LLM reviewer against six failure modes. Stage 2 merges the
cleaned output with the scanner signal into a deterministic gate decision, without
a second model call. The two stages are independently configurable, which is the
central design claim: technical detection quality and organisational risk appetite
are separate concerns.

G6 is the only guardrail that runs before the model call. Format-driven
misjudgements are formed during inference, so a purely downstream check could
detect them but no longer correct them. G6 is deliberately not an autonomous
blocker. It feeds G4 through rule R7 as an ambiguity signal.

---

## Where the failure modes come from

They are not invented, and not read off the runs. They come from a systematic
literature review (vom Brocke et al. for search, Webster and Watson for synthesis):

![Literature search from research question through search string construction and database search to the final analysis corpus of 79 studies](docs/figures/slr-overview.png)

*The 79 studies were condensed into 17 failure-mode clusters and reduced to 6
evaluation failure modes. `docs/figures/slr-prisma-flowchart.png` gives the same
process as a PRISMA diagram, with the exclusion counts and reasons at each stage:
179 duplicates, 312 excluded on title and abstract, 56 excluded on full text.*

The reduction from 17 to 6 uses Hevner's three DSR requirements as explicit
selection criteria (problem relevance, artifact addressability, evaluability),
documented per cluster including every exclusion. The resulting set was then
validated against the **OWASP Top 10 for LLM Applications 2025**. All six map onto
OWASP risk classes, which grounds the taxonomy in a practice reference independent
of the literature corpus.

The corpus itself justifies the work. Only **4 of 79 studies** (5.1%) address
secret detection as their primary task, while 44 (55.7%) address general
vulnerability detection. Vulnerability detection reasons over abstract weakness
classes, whereas secret detection needs character-sequence-level, context-sensitive
judgement. That transfer is nowhere systematically demonstrated.

Four mitigation principles were synthesised from the same corpus (Evidence and
Verifiability, Context Governance, Output Hardening and Schema Validation,
Uncertainty-Aware Evaluation), and each guardrail derives from one of them.

| | Failure mode | Guardrail | Mechanism | OpenAI | Anthropic |
|---|---|---|---|---|---|
| **FM1** | Evidence and localization failure | G1 | TF-IDF-weighted match of snippet against the diff hunk | 2.4% | 1.6% |
| **FM2** | Untrusted-input influence | G2 | Detects exculpatory claims in PR title and body | 4.0% | 0.0% |
| **FM3** | Secret leakage in output | G3 | Regex, taint tracking, entropy filter (4.0 bit/char), then redaction | 90.4% | 74.8% |
| **FM4** | Uncertainty miscalibration | G4 | 13 uncertainty flags, 7 hard rules, escalation to REVIEW | 41.6% | 40.8% |
| **FM5** | Schema and output failure | G5 | Deterministic validation against the output schema, with repair | 1.2% | 0.8% |
| **FM6** | Format-familiarity misdirection | G6 | Pre-call hint injection for UUID, SHA-256 and digest formats | 12.0% | 12.0% |

Trigger rates over 250 samples. Two of them matter more than the aggregate scores.

**G2 never fires on Anthropic (0/250).** Prompt-injection susceptibility is not
comparable between the two providers. A guardrail suite tuned on one carries dead
weight on the other.

**G3 works constantly.** Raw baseline output reproduced the secret in cleartext in
52.4% (OpenAI) and 28.0% (Anthropic) of samples. After redaction: **0 in both
runs**. Detection metrics are blind to this. A reviewer that finds every secret and
prints it into a CI log has not solved the problem.

---

## Benchmark dataset

250 samples, 200 positive and 50 negative. Built as a **diagnostic instrument**
rather than as a representative sample of production repositories. It exists to
provoke and measure the six failure modes under controlled conditions. Croft et al.
report label errors in about 71% of common vulnerability datasets, so ground truth
here was built manually against explicit criteria, then independently reviewed by
two computer science master's students, with disagreements resolved through
adjudication.

![Dataset construction: data sources, quality assurance chain, and the final 250 sample corpus](docs/figures/dataset-construction.png)

The figure counts samples by construction stage. Inside the data file they carry
`sample_id` prefixes, which group them differently. Both views describe the same
250 samples:

| Group | n | Ground truth | Construction |
|---|---|---|---|
| `REAL_*` | 75 | secret | Real public PR diffs, dummy secret injected (50 baseline, 25 perturbed) |
| `SYNTH_*` | 75 | secret | Generated diffs across 15 context families (50 baseline, 25 perturbed) |
| `NEG_CLEAN_*` | 25 | clean | Clean diffs, no secret candidate |
| `NEG_DECOY_*` | 25 | clean | Secret-shaped values that are not credentials |
| `HARD_*` | 50 | mixed | Hand-written format stress cases (FM4a, FM4b, G6) |

The figure's 100 stress cases are the 25 perturbed `REAL_*`, the 25 perturbed
`SYNTH_*` and the 50 `HARD_*` samples taken together, which is why it shows 50
real and 50 synthetic where the table shows 75 of each.

A value is labelled a secret only if it is not reconstructable without the original
context, opens a security-relevant access vector on disclosure, and is hardcoded as
a literal in the diff. A finding counts as a true positive only with the correct
file path and a line within ±3 lines of the annotation, or an `evidence_snippet`
that unambiguously contains the annotated range. Correct binary classification
without verifiable localisation counts as a partial hit and is not scored as a true
positive.

Secret types: token 91, api\_key 63, password 30, private\_key 10,
connection\_string 6. Perturbation conditions, with 150 samples left unperturbed as
the within-dataset control: `E1-B` encoding 8, `E2-A` splitting 8, `E3-A`
misleading name 18, `E3-B` comment override 17, `E4-F` high-risk file 8, `E4-G`
critical category 8, `E4-H` hint injection 9, `E4-I` ambiguous format 24.

The `NEG_DECOY` group carries the most weight. Without values that look like
secrets but are not, a recall-maximising system scores well by flagging everything.

---

## Results

![Evaluation pipeline: the benchmark dataset runs through scanner baseline, LLM baseline, guardrail reviewer and policy engine, producing detection and operational metrics](docs/figures/evaluation-pipeline.png)

*SRQ 1 to SRQ 3 are the three sub-research questions stated above. The paired pre
and post comparison runs on the identical 250 samples, first without and then with
the guardrail layer.*

Alert-level scoring: BLOCK and REVIEW both count as detection, since REVIEW routes
to a human. A secret counts as missed only when it passes the gate as PASS.
Accuracy is deliberately not reported, because at an 80% positive rate constant
positive classification would already score high.

Two domain metrics carry the interpretation, because the error costs are
asymmetric. An escaped secret can become a credential leak, whereas a falsely
blocked pull request costs developer time. LER is the leak-escape rate (FN / GT⁺)
and FBR the false-block rate (FP / GT⁻).

### Baseline and guardrail effect

| System | Provider | Precision | Recall | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| Scanner only | | **0.932** | 0.685 | 0.790 | 137 | 10 | 40 | 63 |
| LLM baseline | OpenAI | 0.879 | 0.870 | 0.874 | 174 | 24 | 26 | 26 |
| LLM baseline | Anthropic | **0.982** | 0.835 | 0.903 | 167 | 3 | 47 | 33 |
| LLM and guardrails | OpenAI | 0.884 | 0.990 | 0.934 | 198 | 26 | 24 | 2 |
| LLM and guardrails | Anthropic | 0.884 | **0.995** | **0.936** | 199 | 26 | 24 | 1 |

The scanner has the best precision and the worst recall. Its misses are
type-specific. `private_key` and `connection_string` are caught completely
(R = 1.000), `token` (0.626) and `api_key` (0.681) are not, which are exactly the
types that lack stable format signatures. Those 63 misses are what motivates an LLM
layer at all.

The guardrail layer costs Anthropic **9.8 precision points** and gains **16.0
recall points**. The cause is identifiable: G4 escalates correct scanner
true-negatives into REVIEW, which alert-level scoring counts as false positives. On
OpenAI the same layer gains 0.5 precision points, because its baseline precision was
already low enough that the escalations cost nothing. A guardrail suite is not
provider-neutral, and a single averaged number would have hidden that.

### Gate logic

Signal variables, in the notation of the thesis:

| Symbol | Meaning |
|---|---|
| S | scanner hit (`scanner_hit`) |
| L_B, L_R | guardrail decision is BLOCK or REVIEW (`final_decision`) |
| P̂ | raw LLM judgment (`pred_has_secret`), written `pred` below |
| R | aggregated review signal from G1, G2, G4 and an ignored G6 hint |
| Q | G6 format signal (`g6_hint_injected`) |
| F | high-risk file path (`.env`, `config/`, `auth/`) |
| C | critical secret type (`private_key`, `connection_string`) |
| H | hard fail: G5 schema still invalid, or a G3 leak persisting after mitigation |

All three policies share a fail-closed pre-policy rule, which the figure below
does not show: `H ⇒ REVIEW`. Output that could not be validated or sanitised is
not eligible for an automatic decision, and separating technical hard fails from
epistemic review signals keeps G4's uncertainty output from dominating the
detection logic.

![The three gate policies as decision functions over the signal variables](docs/figures/gate-policies.png)

*The logic as implemented in this repository, which is what every number below was
produced from. The thesis prints the P2 veto and the P3 score differently, see
[Where implementation and thesis diverge](#where-implementation-and-thesis-diverge).*

In P3 a BLOCK always requires a detection signal, so context alone can never block.

### Policy results

| Policy | Provider | BLOCK / REVIEW / PASS | LER | FBR | F1 |
|---|---|---|---|---|---|
| **P1** Safety-Net | OpenAI | 198 / 28 / 24 | **0.0%** | 46.0% | 0.939 |
| **P1** Safety-Net | Anthropic | 162 / 64 / 24 | **0.0%** | 26.0% | 0.939 |
| **P2** Contextual-Veto | OpenAI | 124 / 101 / 25 | 0.5% | 14.0% | 0.936 |
| **P2** Contextual-Veto | Anthropic | 120 / 98 / 32 | 1.5% | **4.0%** | **0.943** |
| **P3** Risk-Weighted | OpenAI | 162 / 55 / 33 | 3.5% | 28.0% | 0.926 |
| **P3** Risk-Weighted | Anthropic | 132 / 73 / 45 | 6.0% | 14.0% | 0.928 |

The F1 spread across all six configurations is **0.017**. F1 alone cannot separate
these policies, because the difference lives entirely in the error profile.

P1 reaches LER = 0 on both providers and pays up to 46% false blocks for it. P2
achieves the best F1 and the lowest false-block rate, and it leaks. On Anthropic its
veto fires 8 times: 5 correct rejections of scanner false positives on decoy
samples, and 3 real secrets released (`HARD_9_G6_SHA_SRI`, `SYNTH_030`,
`HARD_2_FM4a_GENERIC_ADMIN_KEY`). P3 leaks most, 12 samples, every one a case where
scanner and LLM both fail so the score never reaches the gate. Its separation is
nonetheless real: 97.2% of the BLOCK band (σ ≥ 4) contains an actual secret, against
26.1% in the PASS band (σ ≤ 1).

P1 fits a regulated release branch, P2 a high-throughput feature branch with review
capacity available, P3 an audit context where thresholds must be recalibrated
without touching the guardrail architecture. The choice is an organisational one
about error costs, not a technical optimisation.

### External plausibility check

The benchmark is built along the failure modes it measures, which risks
construction-artifact sensitivity. The effects could come from the dataset rather
than from the mitigations. To probe this, the pipeline was run against **30 public
merged pull requests** from open-source repositories (SuiteCRM, rancher, immich,
mastodon, envoy, keycloak, bitcoin, go-ethereum and others), selected by stratified
purposive sampling into 12 clear positives, 10 ambiguous cases and 8 negative
decoys.

| System | Precision | Recall | F1 |
|---|---|---|---|
| Scanner | 0.667 | 0.667 | 0.667 |
| LLM baseline (OpenAI) | 0.667 | 0.667 | 0.667 |
| LLM baseline (Anthropic) | **1.000** | 0.500 | 0.667 |
| LLM and guardrails (OpenAI) | 0.500 | **0.833** | 0.625 |
| LLM and guardrails (Anthropic) | 0.556 | **0.833** | 0.667 |

The directional finding holds. Guardrails raise operational recall by 33.3 points on
Anthropic and 16.6 points on OpenAI, consistent in magnitude with the main
evaluation. But the check also produces a result that **contradicts** the main
evaluation. Externally the raw LLM reviewer shows no advantage over the scanner at
all, with an Anthropic baseline recall of 0.500 below the scanner's 0.667. The LLM's
value here appears only after guardrail hardening. That is a genuine limit on how
far the main benchmark's LLM advantage generalises, and it is reported rather than
smoothed over.

---

## Where implementation and thesis diverge

The thesis was submitted on 11 May 2026 and the code kept moving. Four places where
the written specification and this repository do not match:

| Location | Thesis | This repository |
|---|---|---|
| G4 score, Eq. 4.1 | σ_u = Σ w_i · f_i with threshold θ_u, alongside the hard rules | Not implemented. Only the seven ordered rules in [`REVIEW_RULES`](src/guardrails/g4_uncertainty.py#L654) |
| G4 flags, App. 4/6 | 9 uncertainty flags | 13, in [`KNOWN_UNCERTAINTY_FLAGS`](src/guardrails/g4_uncertainty.py#L41) |
| P2 veto, Eq. 4.4 | S ∧ ¬P̂ ∧ ¬R ∧ ¬F | S ∧ ¬P̂ ∧ ¬F ∧ ¬C |
| P3 score, Eq. 4.5 | σ = 2S + 2L_B + 𝟙(L_R ∨ R) + F | σ = 2S + 2L_B + 𝟙(L_R ∨ R) + Q + F + C |

The P2 deviation was deliberate. G4 fires on every `NEG_DECOY` sample, so keeping
¬R would have disabled the veto entirely. All reported policy figures come from the
implementation, re-simulated on the frozen guardrail outputs, not from the formulas
as printed in the thesis.

Two further design decisions did not survive contact with the data. **G6 does not
generalise**: detection with hint is 93.3% on OpenAI against 33.3% on Anthropic, and
corrected for base rates the Anthropic gain is 0.6 points, within noise. And an
intermediate evaluation run was **invalidated by a schema incompatibility**: G5
rejected the `confidence` field that G4 requires, which misrouted 166 of 200 samples
and produced a guardrail recall of 2%. The run passed without raising an error,
which is why the pipeline now validates that field explicitly. It is retained for
provenance at `runs/archive/v120_final_extreme_openai/`, next to its corrected
successor, and excluded from every reported result.

---

## Limitations

The dataset is semi-synthetic, and 100 of 250 samples are stress cases constructed
along the very failure modes being measured. The external check addresses this
partially, not fully. The guardrail layer was evaluated as a bundle with all six
active, so activation rates are diagnostic indicators rather than causal effect
measurements, and no ablation study was run. The 200:50 positive ratio departs from
real base rates, so absolute false-positive rates do not transfer to production.
Policy weights and thresholds are conservative heuristics, not statistically
optimised. Two providers with one model each are not a survey of LLM behaviour, and
open-source or security-fine-tuned models were not included. Latency, inference cost
and human-in-the-loop review load were not measured. FM5 is evaluated on three
samples substituted from an earlier run, disclosed in the run summary and in the
commit that introduced them. Results hold for hardcoded secrets and do not
generalise to other weakness classes.

---

## Reproducing

Everything downstream of the API calls is pure standard library. The guardrails,
the policies and the whole metrics chain import nothing outside it, so the
published tables regenerate on a bare Python 3.10 or newer with no installation
at all:

```bash
# Regenerate every evaluation table from the frozen model output
python -m src.metrics.compute_all \
    --results runs/v150_anthropic_opus46_full/results.json \
    --outdir  /tmp/regenerated
diff -r /tmp/regenerated runs/v150_anthropic_opus46_full/evaluation_outputs

# Re-simulate all three policies on the frozen guardrail outputs
python -m src.scripts.run_policy_comparison_v2

# Guardrail and policy tests
pip install pytest && pytest tests/ -q
```

All 26 output files come back **byte for byte** identical. CI checks exactly
this on every push, in `.github/workflows/tests.yml`, and deliberately runs the
reproduction job without a `pip install` so that a new dependency creeping into
the metrics chain breaks the build.

Running a fresh evaluation against the provider APIs does need dependencies and
keys:

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add OPENAI_API_KEY / ANTHROPIC_API_KEY
```

A full evaluation run then looks like this:

```bash
python -m src.llm_evaluation.run_evaluation \
    --model anthropic \
    --input data/03_baseline/all_250_samples_extreme.json \
    --output-dir data/05_results
```

---

## Repository layout

```
src/
  data_collection/    dataset builders (real, synthetic, negative controls)
  manipulation/       perturbation engine (E1 to E4)
  scanners/           gitleaks and detect-secrets wrappers
  llm_evaluation/     provider clients, baseline and guardrail runs
  guardrails/         G1 to G6
  policies/           P1 to P3, plus the superseded p2_consensus and
                      p3_escalation. The latter is not dead: its
                      compute_policy_tags is still called during evaluation
  metrics/            model, gate, failure-mode (PRI) and statistical metrics
  scripts/            policy re-simulation, imported by metrics/compute_all.py
scripts/              standalone tooling, run directly and imported by nothing
runs/
  v140_full_g6_250samples/    OpenAI run (GPT-5 mini), 250 samples
  v150_anthropic_opus46_full/ Anthropic run (Claude Opus 4.6), same dataset
  policy_results/             authoritative policy comparison
  scanner_baseline/           scanner-only reference
  archive/                    the superseded runs the documentation cites:
                              v120 invalid, v121 its fix, v130 the source of the
                              three substituted FM5 samples
scripts/
  plausibilitaetspruefung.py  collects the real PRs for the external check
tests/                        128 tests over G3, G4, G5, routing, policy REVIEW
docs/
  ARTIFACT_ARCHITECTURE.md    technical description of the artifact
  PERTURBATION_ENGINE.md      manipulation strategies
  SLR_FM_MetricsMapping.csv   literature-to-metric mapping from the SLR
  figures/                    thesis figures, English labels
```

Beyond the five figures embedded above, `docs/figures/` also holds
`slr-prisma-flowchart.png` (the literature search as a PRISMA diagram with
exclusion counts) and `pull-request-anatomy.png` (the parts of a pull request that
the reviewer receives).

Start with **`runs/thesis_evaluation_summary_alert_only.md`**. It names, for every
figure, which file is authoritative and which is superseded.

Datasets are versioned rather than overwritten (`data/archive/b0`, `b1`, and so on),
with provenance in `manifest.json`. Superseded runs stay in `runs/archive/`,
including the broken ones. `CHANGELOG.md` records what changed between versions and
why.

All secrets in the dataset are generated dummies. No real credentials are committed
to this repository.

---

## Contact

If you work on LLM reliability, secret detection or DevSecOps tooling, I would be
glad to talk about the method, the results, or the places where this still breaks.

Cecilia Nothstein · <Cecilia.Nothstein@gmail.com>

Bachelor thesis, DHBW Stuttgart, 2026. Code and data are released for review of the
thesis. Please get in touch before reuse.
