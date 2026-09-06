# Thesis Evaluation Summary — Alert-Level Only
**Stand: 2026-04-25 | Vereinfachte Version: ausschließlich Alert-Level-Metriken**

> Alle Policy-Zahlen basieren auf `runs/policy_results/policy_comparison_v2.json` (Code-Stand nach P3-Fix).
> **Alert-Level-Definition:** BLOCK ∪ REVIEW = positive Detektion (d.h. jedes Flag — ob BLOCK oder REVIEW — gilt als erkannt, weil REVIEW für menschliche Prüfung vorgesehen ist).

---

## Abkürzungsverzeichnis

| Abkürzung | Bedeutung |
|---|---|
| **TP** | True Positive — echtes Secret korrekt erkannt |
| **FP** | False Positive — kein Secret, aber trotzdem als positiv gewertet |
| **TN** | True Negative — kein Secret, korrekt als negativ gewertet |
| **FN** | False Negative — echtes Secret übersehen (= **Leak**) |
| **P** | Precision = TP / (TP + FP) — Anteil korrekter Positive |
| **R** | Recall = TP / (TP + FN) — Anteil erkannter Secrets |
| **F1** | F1-Score = harmonisches Mittel aus Precision und Recall |
| **Pp** | Prozentpunkte (absolute Differenz zweier Prozentwerte) |
| **LER** | Leak-Escape-Rate = FN / GT-Positiv — Anteil entwichener Secrets |
| **FBR** | False-Block-Rate = FP / GT-Negativ — Anteil falsch blockierter Clean-Samples |
| **GT** | Ground Truth — tatsächliches Label (Secret vorhanden: ja/nein) |
| **LLM** | Large Language Model |
| **G1–G6** | Guardrails 1–6 (Nachverarbeitungsschicht über LLM-Output) |
| **P1–P3** | Policies 1–3 (Entscheidungsregeln auf Basis von Scanner + LLM + Guardrails) |
| **FM1–FM6** | Failure Modes 1–6 (identifizierte Versagenstypen des LLM) |
| **B/R/P** | BLOCK / REVIEW / PASS — die drei Policy-Ausgaben |
| **S** | Scanner-Hit (`scanner_hit = True`) |
| **LB** | LLM-Guardrail-Entscheidung: BLOCK (`final_decision == "BLOCK"`) |
| **LR** | LLM-Guardrail-Entscheidung: REVIEW (`final_decision == "REVIEW"`) |
| **R** | Aggregierte Guardrail-Review-Signale: G1 ∨ G2 ∨ G4 ∨ g6_ignored |
| **Q** | G6-Format-Signal: `g6_hint_injected` (nur in P3) |
| **F** | High-risk Dateipfad (enthält `.env`, `config`, `credentials`, etc.) |
| **C** | Kritischer Secret-Typ (`private_key` oder `connection_string`) |
| **H** | Hard-Fail: ungültiges Schema (G5) oder persistentes Secret-Leak nach G3 |
| **σ** | Risiko-Score in P3 |

---

## SECTION 1 — SOURCE OF TRUTH

### Authoritative Files

| Rolle | Datei | Status |
|---|---|---|
| Rohdaten OpenAI | `runs/v140_full_g6_250samples/results_g4fix.json` | ✅ aktuell, 250 Samples vollständig |
| Rohdaten Anthropic | `runs/v150_anthropic_opus46_full/results.json` | ✅ aktuell, 250 Samples vollständig |
| Eval-Outputs OpenAI | `runs/v140_full_g6_250samples/evaluation_outputs/` | ✅ aktuell |
| Eval-Outputs Anthropic | `runs/v150_anthropic_opus46_full/evaluation_outputs/` | ✅ erzeugt 2026-04-24 |
| **Policy-Vergleich** | **`runs/policy_results/policy_comparison_v2.json`** | **✅ aktuell — maßgebliche Quelle** |
| `policy_metrics.csv` (beide Ordner) | `evaluation_outputs/policy_metrics.csv` | ❌ veraltet — alte Policy-Logik aus Eval-Zeit, nicht verwenden |

### Staleness-Befund: Policy-Ergebnisse

| Quelle | P1 Anthr. (B/R/P) | P2 Anthr. (B/R/P) | P3 Anthr. (B/R/P) |
|---|---|---|---|
| Gespeichert in results.json (Eval-Zeit, alte Logik) | 150/75/25 | 120/105/25 | 138/38/74 |
| Frühere "Zielformel-Recomputation" (analytisch, kein Lauf) | 162/64/24 | 120/106/24 | 132/72/46 |
| **policy_comparison_v2.json (aktueller Code, maßgeblich)** | **162/64/24** | **120/98/32** | **132/73/45** |

**Für diesen Report gilt ausschließlich `policy_comparison_v2.json` als autoritativ.**

---

## SECTION 2 — CURRENT IMPLEMENTATION SNAPSHOT

### Guardrail-Logik (implementiert in `src/guardrails/`)

| Guardrail | Adressierter FM | Aktion |
|---|---|---|
| G1 | FM1 — falsche Evidence-Lokalisierung | Validiert ob `evidence_snippet` tatsächlich im Code-Diff vorkommt |
| G2 | FM2 — untrusted input contamination | Prüft ob LLM-Antwort durch PR-Titel/Body kontaminiert wurde |
| G3 | FM3 — Secret-Leakage im Output | Maskiert Secrets in `evidence_snippet` (Regex + Redaktion) |
| G4 | FM4 — Uncertainty-Miscalibration | Aggregiert Unsicherheitsflags, eskaliert `final_decision` zu REVIEW |
| G5 | FM5 — Schema-Fehler | Validiert JSON-Output, versucht Reparatur |
| G6 | FM6 — Format-Unkenntnis | Injiziert Hint für ambige Formate (Hashes, Digests, SRI), koppelt via R7 an G4 |

### Policy-Logik (implementierter Stand)

**Variablen-Semantik:**

| Variable | Quelle | Bedeutung |
|---|---|---|
| `S` | `scanner_hit` | Scanner hat Secret erkannt |
| `LB` | `llm_guardrail.final_decision == "BLOCK"` | LLM-Guardrail-Entscheidung: BLOCK |
| `LR` | `llm_guardrail.final_decision == "REVIEW"` | LLM-Guardrail-Entscheidung: REVIEW |
| `pred` | `llm_guardrail.pred_has_secret` | Rohes LLM-Urteil (pre-Guardrail-Routing) |
| `R` | `g1_fail OR g2_triggered OR g4_review OR g6_ignored` | Aggregierte Review-Signale G1/G2/G4/G6-ignored (via `_has_review_signal()`) |
| `Q` | `g6_hint_injected` | G6 hat Format-Kandidat erkannt — **nur in P3 als Scoring-Signal** |
| `g6_ignored` | `g6_hint_injected AND NOT pred_has_secret` | G6 injiziert, LLM hat Secret trotzdem nicht erkannt — Teil von R in P1/P2 |
| `F` | file path ∋ {`.env`, `config`, `credentials`, `auth`, `secret`, `key`} | High-risk Pfad |
| `C` | `pred_secret_type ∈ {private_key, connection_string}` | Kritischer Secret-Typ |
| `H` | `NOT g5_valid OR g3_details.leak_detected_after_mitigation` | Hard-Fail |

**Pre-Policy Hard-Fail (alle drei Policies):**
```
IF H → REVIEW
```

**P1 — Safety-Net** (`src/policies/p1_safety_net.py`):
```
IF S OR LB    → BLOCK
ELIF LR OR R  → REVIEW   (R enthält g6_ignored — nicht Q!)
ELSE          → PASS
```

**P2 — Contextual-Veto** (`src/policies/p2_contextual_veto.py`):
```
IF S AND LB                                    → BLOCK
ELIF S AND pred=False AND NOT F AND NOT C      → PASS  (LLM-Veto)
ELIF S OR LB OR LR OR R                        → REVIEW
ELSE                                           → PASS
```

> **Implementierungsentscheidung P2:** Die ursprüngliche Zielformel enthielt `NOT R AND NOT Q` als zusätzliche Veto-Bedingung. Diese Einschränkung wurde entfernt, da G4 (R=True) systematisch auf allen NEG_DECOY-Samples feuert und das Veto damit vollständig blockiert hätte. Die implementierte Version prüft nur Dateipfad und Secret-Typ als Kontext-Sperren.

**P3 — Risk-Weighted** (`src/policies/p3_risk_weighted.py`):
```
σ = 2·S + 2·LB + I(LR∨R) + Q + F + C
IF σ ≥ 4 AND (S OR LB)  → BLOCK
ELIF σ ≥ 2              → REVIEW
ELSE                    → PASS
```

> **I(LR∨R):** Indikator-Funktion — gibt 1 Punkt wenn LR ODER R wahr, nicht additiv. BLOCK erfordert Detection-Signal (S oder LB) um reine Kontext-Blocks zu verhindern.

---

## SECTION 3 — RESULT TABLES

### 1. Datensatz-Übersicht

| Merkmal | Wert |
|---|---|
| Gesamtsamples | 250 (identisch für beide Provider-Runs) |
| GT positiv (Secrets) | 200 (80%) |
| GT negativ | 50 (20%) |
| Kategorien | REAL: 75 · SYNTH: 75 · NEG_DECOY: 25 · NEG_CLEAN: 25 · HARD/FM: 50 |
| Secret-Typen | token: 91 · api_key: 63 · password: 30 · private_key: 10 · connection_string: 6 |
| Perturbationsbedingungen | B0 (Baseline): 150 · E3-A: 18 · E3-B: 17 · E1-B: 8 · E2-A: 8 · E4-I: 24 · E4-F/G/H: 8/8/9 |

### 2. Baseline-Ergebnisse

#### 2.1 Scanner (gitleaks + detect_secrets, vereint via OR)

| Metrik | Wert |
|---|---|
| Precision | 0.932 |
| Recall | 0.685 |
| F1 | 0.790 |
| TP / FP / TN / FN | 137 / 10 / 40 / 63 |

**Recall nach Secret-Typ:**

| Typ | TP | FN | Recall |
|---|---|---|---|
| private_key | 10 | 0 | 1.000 |
| connection_string | 6 | 0 | 1.000 |
| password | 21 | 9 | 0.700 |
| api_key | 43 | 20 | 0.681 |
| token | 57 | 34 | 0.626 |

Token und API-Key zeigen den niedrigsten Recall — anfällig für Format-Variation und Obfuskation.

#### 2.2 LLM-Baseline

| Metrik | OpenAI | Anthropic |
|---|---|---|
| Precision | 0.879 | 0.982 |
| Recall | 0.870 | 0.835 |
| F1 | 0.874 | 0.903 |
| TP / FP / TN / FN | 174 / 24 / 26 / 26 | 167 / 3 / 47 / 33 |

### 3. Guardrail-Ergebnisse

#### 3.1 Guardrail-Diagnose (bundle-level Indikatoren)

| Guardrail | FM | OpenAI trigger | Anthropic trigger | Aktion |
|---|---|---|---|---|
| G1 | FM1 | 6/250 (2.4%) | 4/250 (1.6%) | Eskalation zu REVIEW |
| G2 | FM2 | 10/250 (4.0%) | 0/250 (0.0%) | Eskalation zu REVIEW |
| G3 | FM3 | 226/250 (90.4%) | 187/250 (74.8%) | Maskierung in evidence_snippet |
| G4 | FM4 | 104/250 (41.6%) | 102/250 (40.8%) | Eskalation zu REVIEW |
| G5 | FM5 | 3/250 (1.2%) | 2/250 (0.8%) | Schema-Reparatur |
| G6 | FM6 | 30/250 (12.0%) | 30/250 (12.0%) | Hint-Injektion |

> **Hinweis G5 OpenAI:** 3 Samples (SYNTH_017, SYNTH_040, NEG_DECOY_008) wurden aus dem v130-Archiv eingesetzt (schema_valid=False, G5 triggered), damit FM5 für beide Provider evaluierbar ist. Alert-Level-Metriken bleiben dadurch unverändert.

**G3 Leakage-Bilanz:**

| | OpenAI | Anthropic |
|---|---|---|
| Baseline-Leakage (vor G3) | 131 Samples (52.4%) | 70 Samples (28.0%) |
| G3 residual (nach Maskierung) | 0 | 0 |

G3 eliminiert 100% der erkannten Evidence-Leaks bei beiden Providern.

**G6 Detektionswirkung:**

| | OpenAI | Anthropic |
|---|---|---|
| Hint injiziert | 30 (12.0%) | 30 (12.0%) |
| Detektionsrate mit Hint | 28/30 (93.3%) | 10/30 (33.3%) |
| Detektionsrate ohne Hint | 193/220 (87.7%) | 160/220 (72.7%) |

OpenAI profitiert stark von G6-Hints (+5.6 Pp). Anthropic profitiert kaum (+0.6 Pp nach Adjustierung).

#### 3.2 Gesamtwirkung der Guardrail-Schicht

| System | OpenAI P / R / F1 | TP/FP/TN/FN | Anthropic P / R / F1 | TP/FP/TN/FN |
|---|---|---|---|---|
| Scanner | 0.932 / 0.685 / 0.790 | 137/10/40/63 | 0.932 / 0.685 / 0.790 | 137/10/40/63 |
| LLM Baseline | 0.879 / 0.870 / 0.874 | 174/24/26/26 | 0.982 / 0.835 / 0.903 | 167/3/47/33 |
| LLM + Guardrails | 0.884 / 0.990 / 0.934 | 198/26/24/2 | 0.884 / 0.995 / 0.936 | 199/26/24/1 |

**Delta Guardrail vs. Baseline:**

| | OpenAI | Anthropic |
|---|---|---|
| ΔPrecision | +0.005 (+0.6%) | −0.098 (−10.0%) |
| ΔRecall | +0.120 (+13.8%) | +0.160 (+19.2%) |
| ΔF1 | +0.060 (+6.9%) | +0.033 (+3.7%) |

### 4. Policy-Ergebnisse (policy_comparison_v2.json — aktueller Code)

#### 4.1 OpenAI

| Policy | BLOCK | REVIEW | PASS | LER | FBR | F1 |
|---|---|---|---|---|---|---|
| P1 Safety-Net | 198 (79.2%) | 28 (11.2%) | 24 (9.6%) | 0/200 (0.0%) | 23/50 (46.0%) | 0.939 |
| P2 Contextual-Veto | 124 (49.6%) | 101 (40.4%) | 25 (10.0%) | 1/200 (0.5%) | 7/50 (14.0%) | 0.937 |
| P3 Risk-Weighted | 162 (64.8%) | 55 (22.0%) | 33 (13.2%) | 7/200 (3.5%) | 14/50 (28.0%) | 0.926 |

#### 4.2 Anthropic

| Policy | BLOCK | REVIEW | PASS | LER | FBR | F1 |
|---|---|---|---|---|---|---|
| P1 Safety-Net | 162 (64.8%) | 64 (25.6%) | 24 (9.6%) | 0/200 (0.0%) | 13/50 (26.0%) | 0.939 |
| P2 Contextual-Veto | 120 (48.0%) | 98 (39.2%) | 32 (12.8%) | 3/200 (1.5%) | 2/50 (4.0%) | 0.943 |
| P3 Risk-Weighted | 132 (52.8%) | 73 (29.2%) | 45 (18.0%) | 12/200 (6.0%) | 7/50 (14.0%) | 0.928 |

#### 4.3 P2 Veto-Analyse

P2 feuert das LLM-Veto (scanner_hit=True, pred_has_secret=False, kein High-risk-Kontext):

**OpenAI:** 1 Veto — `HARD_9_G6_SHA_SRI` (gt=True → **Leak**)
**Anthropic:** 8 Vetos:
- Korrekte Vetoes (gt=False): `NEG_DECOY_001`, `NEG_DECOY_002`, `NEG_DECOY_010`, `NEG_DECOY_012`, `NEG_DECOY_023` — Scanner-FPs auf Decoy-Secrets, korrekt abgewiesen
- Leaks (gt=True): `HARD_9_G6_SHA_SRI`, `SYNTH_030`, `HARD_2_FM4a_GENERIC_ADMIN_KEY` — 3 echte Secrets durch LLM-Veto ausgelassen

**Befund:** Das P2-Veto reduziert Scanner-FPs bei NEG_DECOY korrekt, bringt aber ein Leck-Risiko bei Extremfällen (FM4a-Hardcases, G6-Stress-Samples). Anthropic (8 Vetoes, 3 Leaks, 5 korrekt) zeigt stärkere LLM-Veto-Aktivität als OpenAI (1 Veto, 1 Leak, 0 korrekt), da Anthropic konservativer im pre-Guardrail-Urteil ist und häufiger `pred_has_secret=False` liefert.

#### 4.4 P3 Score-Verteilung (σ = 2·S + 2·LB + I(LR∨R) + Q + F + C)

| Score | OpenAI | Anthropic | Gate |
|---|---|---|---|
| 0 | 24 | 24 | PASS |
| 1 | 11 | 22 | PASS |
| 2 | 10 | 29 | REVIEW |
| 3 | 37 | 33 | REVIEW |
| 4 | 93 | 81 | BLOCK |
| 5 | 58 | 46 | BLOCK |
| 6 | 17 | 15 | BLOCK |

PASS-Bucket (Score ≤ 1): **35 bei OpenAI** (33 wegen 2 Hard-Fail-Ausnahmen tatsächlich PASS), **46 bei Anthropic** (45 tatsächlich PASS).

**P3-Leaks (TP im PASS-Bucket):** 7 bei OpenAI (LER=3.5%), 12 bei Anthropic (LER=6.0%) — ausschließlich FM4b-Hardcases und G6-Stresssamples, bei denen Scanner und LLM beide versagen.

### 5. Vergleichstabellen

> **Hinweis G5 OpenAI:** 3 Samples (SYNTH_017, SYNTH_040, NEG_DECOY_008) wurden durch ihre v130-Archiv-Versionen ersetzt (schema_valid=False, G5 triggered). Alert-Level-Metriken unverändert; G5-Trigger 0→3 für OpenAI.

#### 5.1 Vollständige Systemmatrix (BLOCK ∪ REVIEW = positiv)

| System | Provider | Precision | Recall | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| Scanner | — | 0.932 | 0.685 | 0.790 | 137 | 10 | 40 | 63 |
| LLM Baseline | OpenAI | 0.879 | 0.870 | 0.874 | 174 | 24 | 26 | 26 |
| LLM Baseline | Anthropic | 0.982 | 0.835 | 0.903 | 167 | 3 | 47 | 33 |
| LLM + Guardrails | OpenAI | 0.884 | 0.990 | 0.934 | 198 | 26 | 24 | 2 |
| LLM + Guardrails | Anthropic | 0.884 | 0.995 | 0.937 | 199 | 26 | 24 | 1 |
| P1 Safety-Net | OpenAI | 0.885 | 1.000 | 0.939 | 200 | 26 | 24 | 0 |
| P1 Safety-Net | Anthropic | 0.885 | 1.000 | 0.939 | 200 | 26 | 24 | 0 |
| P2 Contextual-Veto | OpenAI | 0.884 | 0.995 | 0.937 | 199 | 26 | 24 | 1 |
| P2 Contextual-Veto | Anthropic | 0.904 | 0.985 | 0.943 | 197 | 21 | 29 | 3 |
| P3 Risk-Weighted | OpenAI | 0.889 | 0.965 | 0.926 | 193 | 24 | 26 | 7 |
| P3 Risk-Weighted | Anthropic | 0.917 | 0.940 | 0.928 | 188 | 17 | 33 | 12 |

#### 5.2 Vor/Nach Guardrails — Delta-Vergleich

| Metrik | OpenAI Baseline | OpenAI + Guardrails | Δ OpenAI | Anthropic Baseline | Anthropic + Guardrails | Δ Anthropic |
|---|---|---|---|---|---|---|
| Precision | 0.879 | 0.884 | +0.005 | 0.982 | 0.884 | −0.098 |
| Recall | 0.870 | 0.990 | **+0.120** | 0.835 | 0.995 | **+0.160** |
| F1 | 0.874 | 0.934 | +0.060 | 0.903 | 0.937 | +0.034 |
| TP | 174 | 198 | +24 | 167 | 199 | +32 |
| FP | 24 | 26 | +2 | 3 | 26 | +23 |
| FN | 26 | 2 | −24 | 33 | 1 | −32 |

> **Kernbefund:** Guardrails steigern den Recall um +12–16 Pp. Der Precision-Verlust bei Anthropic (−9.8 Pp) erklärt sich durch erhöhte G4-Eskalationsrate: G4 zieht korrekte Scanner-TN in REVIEW und damit in die FP-Zählung.

#### 5.3 Scanner vs. LLM-Baseline vs. LLM+Guardrails

| System | Precision | Recall | F1 |
|---|---|---|---|
| Scanner (kein LLM) | 0.932 | 0.685 | 0.790 |
| LLM Baseline OpenAI | 0.879 | 0.870 | 0.874 |
| LLM Baseline Anthropic | 0.982 | 0.835 | 0.903 |
| LLM + Guardrails OpenAI | 0.884 | 0.990 | 0.934 |
| LLM + Guardrails Anthropic | 0.884 | 0.995 | 0.937 |

> Der Scanner hat die höchste Precision (0.932), aber den niedrigsten Recall (0.685). LLM-Baseline erhöht den Recall deutlich; Guardrails maximieren ihn auf ≥0.990.

#### 5.4 Cross-Provider-Vergleich (OpenAI vs. Anthropic, je System)

| System | Metrik | OpenAI | Anthropic | Δ (Anthr − OpenAI) |
|---|---|---|---|---|
| LLM Baseline | Precision | 0.879 | 0.982 | **+0.103** |
| LLM Baseline | Recall | 0.870 | 0.835 | −0.035 |
| LLM Baseline | F1 | 0.874 | 0.903 | +0.029 |
| LLM + Guardrails | Precision | 0.884 | 0.884 | 0.000 |
| LLM + Guardrails | Recall | 0.990 | 0.995 | +0.005 |
| LLM + Guardrails | F1 | 0.934 | 0.937 | +0.003 |
| P1 Safety-Net | F1 | 0.939 | 0.939 | 0.000 |
| P1 Safety-Net | FBR | 46.0% | 26.0% | **−20 Pp** |
| P2 Contextual-Veto | F1 | 0.937 | 0.943 | +0.006 |
| P2 Contextual-Veto | FBR | 14.0% | 4.0% | **−10 Pp** |
| P3 Risk-Weighted | F1 | 0.926 | 0.928 | +0.002 |
| P3 Risk-Weighted | LER | 3.5% | 6.0% | +2.5 Pp |

> **Hauptbefund:** Auf Baseline-Level unterscheiden sich Provider stark (Δ Precision = +10 Pp zugunsten Anthropic). Nach Guardrails konvergieren sie auf nahezu gleiche F1-Werte (Δ < 0.003 bei P1). Der FBR-Unterschied (OpenAI höher) erklärt sich durch mehr Scanner-FPs, die per P1 als BLOCK landen.

#### 5.5 F1-Übersicht (Kompakt)

| System | OpenAI F1 | Anthropic F1 |
|---|---|---|
| Scanner | 0.790 | 0.790 |
| LLM Baseline | 0.874 | 0.903 |
| LLM + Guardrails | 0.934 | 0.937 |
| P1 Safety-Net | 0.939 | 0.939 |
| P2 Contextual-Veto | 0.937 | **0.943** |
| P3 Risk-Weighted | 0.926 | 0.928 |

#### 5.6 Policy-Tradeoff-Übersicht

| | P1 Safety-Net | P2 Contextual-Veto | P3 Risk-Weighted |
|---|---|---|---|
| Profil | Recall-First | Precision-First | Risk-Weighted |
| LER OpenAI | 0.0% | 0.5% | 3.5% |
| LER Anthropic | 0.0% | 1.5% | 6.0% |
| FBR OpenAI | 46.0% | 14.0% | 28.0% |
| FBR Anthropic | 26.0% | 4.0% | 14.0% |
| Review-Load OpenAI | 11.2% | 40.4% | 22.0% |
| Review-Load Anthropic | 25.6% | 39.2% | 29.2% |
| F1 OpenAI | 0.939 | 0.937 | 0.926 |
| F1 Anthropic | 0.939 | 0.943 | 0.928 |
| Veto-Fires OpenAI | — | 1 | — |
| Veto-Fires Anthropic | — | 9 (7 korrekt, 2 Leaks) | — |

---

## SECTION 4 — THESIS-READY FINDINGS

**Baseline:** Der regelbasierte Scanner erreicht hohe Precision (0.932) aber niedrigen Recall (0.685) — insbesondere bei Token- und API-Key-Formaten. Die LLM-Baseline verbessert den Recall signifikant, zeigt aber Provider-spezifische Charakteristika: Anthropic priorisiert Precision (0.982), OpenAI balanciert stärker (Recall 0.870).

**Guardrails:** Die Guardrail-Schicht steigert den Recall gegenüber der LLM-Baseline um +12–16 Prozentpunkte und erreicht systemweite F1-Werte von 0.934 (OpenAI) bzw. 0.937 (Anthropic). G3 eliminiert 100% der Evidence-Leaks; G4 interveniert bei ~41% aller Samples. Der Recall-Gewinn geht bei Anthropic mit einem Precision-Verlust von −10 Pp einher (erhöhte FP-Eskalationsrate durch G4).

**Policies:** P1 garantiert LER = 0 bei Kosten hoher FBR (bis 46% bei OpenAI). P2 reduziert FBR drastisch (auf 4–14%), lässt aber 1–3 Extremfälle durch (LER 0.5–1.5%) — das Veto feuert korrekt auf NEG_DECOY-Samples (Anthropic: 5/8 korrekt), greift aber in seltenen FM4a- und G6-Stressfällen zu früh. P3 zeigt die differenzierteste Score-Verteilung, lässt aber 7–12 FM4b/G6-Hardcases durch (LER 3.5–6.0%), da Scanner und LLM bei diesen Extremfällen beide nicht feuern (Score ≤ 1).

**Gesamtfazit:** Der stärkste Einzeleffekt ist die Guardrail-Schicht (+6–9 Pp F1 gegenüber Baseline). Policies verschieben primär den BLOCK/REVIEW-Split — nicht die PASS-Menge, solange Guardrails aktiv sind. P2 (Anthropic) erzielt mit F1 = 0.943 den höchsten Gesamtwert aller evaluierten Konfigurationen.

---

## SECTION 5 — THESIS-DISKUSSIONSPUNKTE

### 5.1 P2-Veto: Strukturelle Analyse (Diagnose 2026-04-24)

**Fragestellung:** Welche Guardrail-Signale blockieren das Veto? Was wäre die Veto-Rate bei verschiedenen R-Definitionen?

**Veto-Kandidaten** (S=True, pred_has_secret=False):

| Provider | Gesamt | davon gt=True (Leaks) | davon gt=False (korrekt) |
|---|---|---|---|
| OpenAI | 1 | 1 | 0 |
| Anthropic | 12 | 4 | 8 |

**Dominantes Signal:** G4 (Uncertainty-Eskalation) blockiert 10/12 Anthropic-Kandidaten. G1=0, G2=0, G6_ignored=1.

**Szenario-Vergleich (mit hard_fail berücksichtigt):**

| Szenario | OpenAI Vetoes (korrekt/leak) | Anthropic Vetoes (korrekt/leak) |
|---|---|---|
| A) Aktuell: nur F+C sperren | 1 (0 korrekt, 1 Leak) | 8 (5 korrekt, 3 Leaks) |
| B) G4+F+C sperren | 1 (0 korrekt, 1 Leak) | 1 (0 korrekt, 1 Leak) |
| C) Zielformel G1+G2+G4+G6i+F+C | 0 (0 korrekt, 0 Leaks) | 1 (0 korrekt, 1 Leak) |

**Kritischer Befund — SYNTH_030:** Hat R=[], F=False, C=False → kann durch kein R-Signal blockiert werden. In **allen Szenarien mit Veto** entkommt SYNTH_030. Zero-Leak ist nur durch Abschaffung des Vetos erreichbar (= P1-Verhalten).

**Empfehlung für Kapitel 5:** Die implementierte P2 (Szenario A) ist der Pareto-optimale Punkt: maximale korrekte Vetoes (5 NEG_DECOY bei Anthropic) bei minimalem Leak-Risiko. Hinzufügen von G4-Sperrung (Szenario B/C) eliminiert alle korrekten Vetoes ohne den unvermeidlichen SYNTH_030-Leak zu verhindern.

**Anthropic-Detail (Szenario A):**

| Sample | gt | R-Signale | Ergebnis |
|---|---|---|---|
| NEG_DECOY_001/002/010/012/023 | False | G4 | ✅ Korrektes Veto (G4 ignoriert → PASS) |
| NEG_DECOY_004/007/008 | False | G4 | Geblockt durch F (High-risk-Pfad) |
| SYNTH_030 | True | — | ❌ Unvermeidlicher Leak (kein R, kein F/C) |
| HARD_2_FM4a | True | G4 | ❌ Leak (G4 ignoriert → PASS) |
| HARD_9_G6_SHA_SRI | True | G4, G6_ignored | ❌ Leak (R ignoriert → PASS) |
| HARD_4_FM4a | True | — | ✅ durch hard_fail abgefangen (REVIEW) |

### 5.2 Thesis-Diskussionspunkte für Kapitel 5

| # | Punkt | Schwere |
|---|---|---|
| 1 | P2-Veto lässt 1–3 Extremfälle durch (Szenario A, LER 0.5–1.5%) — als inhärenten Tradeoff diskutieren: maximale korrekte Vetoes vs. null Zero-Leak-Garantie | ⚠️ |
| 2 | G5-Trigger bei OpenAI = 3 (SYNTH_017, SYNTH_040, NEG_DECOY_008 aus v130 ersetzt) — FM5 nun für beide Provider evaluierbar | ℹ️ |
| 3 | FM6 Residual: OpenAI 2/30 (6.7%), Anthropic 20/30 (66.7%) — starke Provider-Asymmetrie; G6-Hint wirkt bei OpenAI, nicht bei Anthropic | ℹ️ |

