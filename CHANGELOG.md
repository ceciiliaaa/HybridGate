# Changelog - HybridGate BA Projekt

Dokumentation aller wichtigen Änderungen am Projekt.

---

## [2026-03-16] Final Evaluation Run v121 (Extreme Dataset, G5-Fix)

### Evaluation
- **Run v121** (`runs/v121_final_extreme_openai_g5fix/`): Finaler Evaluation-Run auf extreme Perturbation-Dataset (200 Samples)
- Drei Modi verglichen: Scanner (Gitleaks + detect-secrets), LLM Baseline, LLM + Guardrails (G1–G5)
- Ergebnisse: Scanner Recall=84.0%, LLM Baseline Recall=100%, Guardrails Recall=100%
- Data Leakage Audit durchgeführt — keine ergebnisrelevante Leakage

### G5-Fix (v120 → v121)
- **Bug:** G5 lehnte `confidence`-Feld ab (G4 fordert es, G5 kannte es nicht) → 166/200 falsche REVIEW-Routings
- **Fix:** `("confidence", str, False)` in `OPTIONAL_FIELDS` von `g5_schema_validation.py` hinzugefügt
- Testfix: `test_g5_confidence_field_rejected` → `test_g5_confidence_field_accepted`

### Run v120 (broken, archiviert)
- Identisch zu v121, aber mit G5-Bug — Guardrail-Recall nur 2%
- Archiviert als Referenz unter `runs/v120_final_extreme_openai/`

---

## [2026-03-15] G1–G5 Guardrail Hardening & 200-Sample Evaluation

### Guardrail-Refactoring
- **G3 Rewrite:** Fail-closed 3-Schicht-Architektur (Detect → Redact once → REVIEW)
  - 16 Regex-Patterns, Entropy-Spans, Candidate Echo, Reconstructed Leak Detection
  - Scannt vollständige JSON-Serialisierung
- **G4 Neu:** Regelbasierte Uncertainty Escalation mit Confidence + Context-Flags
  - Rules: R1 (ambiguous context), R2 (reconstructed + ambiguity), R3 (scanner disagreement), R4 (exculpatory escalation)
  - Inferred Flags aus File-Path, PR-Metadata, Code-Kontext, Scanner-Ergebnissen
- **G5 Neu:** Schema Validation mit Repair-Mechanismus
  - Required/Optional Fields, Type-Checking, Enum-Validation
  - Auto-Repair für häufige Fehler (String→Bool, fehlende Felder)
- **G1 Erweitert:** Evidence Validation mit Diff-Kontext (`validate_output_with_context`)
- **G2 Erweitert:** `validate_with_details()` für G4-Integration
- **Pipeline-Order:** G5 → G2 → G4 → G1 → G3 (`apply_guardrails_with_routing()`)

### Dataset
- **Extreme Perturbation Dataset** (`all_200_samples_extreme.json`): 150 positive + 50 negative Samples
- Perturbation Engine v2: E1-B, E2-A, E3-A, E3-B Strategien mit intensivierten Manipulationen
- 50 hardened positive Samples (`hardened_positive_samples.json`) manuell überarbeitet

### Run v110 (200 Samples, Standard-Perturbation)
- `runs/v110_full_openai_200samples/`: 200 Samples mit Standard-Dataset, G1–G5
- G2 Consistency-Fix angewandt

---

## [2026-03-10] Dataset Versioning & Archive System

### Hinzugefügt
- **Archiv-System** (`src/utils/archive_dataset.py`)
  - Automatische Versionserkennung (b0 → b1 → b2 → ...)
  - Safety-Policy: Daten werden NIE gelöscht, immer archiviert
  - `verify_archived()` prüft Archiv-Integrität vor Löschung
  - CLI: `python -m src.utils.archive_dataset --status`

- **Generische Dateinamen** in `data/03_baseline/`
  - Keine Version-Prefixes mehr (war: `b2_all_samples.json`)
  - Version in `manifest.json` dokumentiert
  - Skripte referenzieren immer gleichen Pfad

### Geändert
- **Ordnerstruktur**:
  ```
  data/
  ├── 03_baseline/     # Aktive Version (generisch)
  └── archive/
      ├── b0/          # Original (deprecated)
      └── b1/          # Fixed secrets (deprecated)
  ```

### Dokumentation
- `data/archive/README.md` mit Version History

---

## [2026-03-10] B2 Dataset - Diverse Contexts & Realistic Secrets

### Problem (B1)
- Alle 50 REAL-Samples kollabierten zu einem Template
- Secrets hatten wiederholende Hex-Muster (`66f0514866f05148...`)
- Context Diversity Score: 0.01

### Lösung
- **15 Context Families** erstellt (jwt_auth, stripe_payment, aws_s3, ...)
- **RealisticSecretGenerator** ohne wiederholende Muster
- Jede Familie hat eigenes PR-Template und Dateipfad

### Ergebnis (B2)
| Metrik | B1 | B2 |
|--------|----|----|
| Unique Secrets (REAL) | 50 | 50 |
| Unique PR Titles | 1 | 15 |
| Unique File Paths | 1 | 15 |
| Context Diversity | 0.01 | 0.593 |
| Repeating Patterns | 28 | 5 |

### Dateien
- `src/data_collection/build_b2_baseline.py` (NEU)
- `src/utils/extended_quality_report.py` (NEU)

---

## [2026-03-10] B1 Dataset - Fixed Secret Diversity

### Problem (B0)
- Nur 3 unique Secrets für 50 REAL-Samples (94% Duplikate)
- Root Cause: `generate_secret()` defaultete zu `stripe_key`

### Lösung
- `generate_unique_secret()` Methode hinzugefügt
- Dynamische Suffix-Generierung per Sample
- 6 neue Secret-Kategorien (slack_webhook, twilio_sid, ...)

### Ergebnis (B1)
| Metrik | B0 | B1 |
|--------|----|----|
| REAL Unique Secrets | 3 | 50 |
| REAL Duplicate Rate | 94% | 0% |
| Gesamt Unique | 38 | 86 |

### Dateien
- `src/data_collection/build_real_baseline.py` (MODIFIED)

---

## [2026-03-10] HybridGate Module

### Guardrails (`src/guardrails/`)
| Guardrail | Funktion |
|-----------|----------|
| G1 | Evidence + Location Pflicht |
| G2 | Untrusted Input Policy (PR-Text ignorieren) |
| G3 | Secret Redaction (nie Klartext ausgeben) |
| G4 | Uncertainty Handling |
| G5 | Schema Validation |

### Policies (`src/policies/`)
| Policy | Logik |
|--------|-------|
| P1 Safety-Net | OR: Scanner ODER LLM Hit → BLOCK |
| P2 Consensus | AND: Scanner UND LLM Hit → BLOCK |
| P3 Escalation | Conditional LLM based on risk |

### Scanner (`src/scanners/`)
- Gitleaks Wrapper
- detect-secrets Wrapper
- Abstract Base Class für neue Scanner

### Metriken (`src/metrics/`)
- Model Metrics (Precision, Recall, F1)
- Gate Metrics (Leak-Escape-Rate, False-Block-Rate)
- Statistical Tests (McNemar)

---

## [2026-03-09] Evaluation Results

### Getestete Modelle
- GPT-4o
- Claude
- GPT-4o-mini

### Scanner Baseline
- detect-secrets

### Ergebnisse
Siehe `data/05_results/hybrid_evaluation_*.json`

---

## [2026-03-03] Initial Setup

### Erstellt
- Projekt-Struktur
- B0 Baseline (REAL, SYNTH, NEG je 50 Samples)
- Evaluation Framework
- GitHub PR Collector

---

## Konventionen

### Dataset Versioning
- Aktive Version: `data/03_baseline/` (generische Namen)
- Archiv: `data/archive/bX/` (X = Versionsnummer)
- Manifest enthält Version, Metriken, Regeneration-Command

### Commit Messages
- Englisch
- Kurze Summary + Details
- Co-Authored-By: Claude Opus 4.6

### Safety Policy
- **NIEMALS Daten löschen**
- Immer zuerst archivieren
- `archive_dataset.py` für Versionswechsel nutzen
