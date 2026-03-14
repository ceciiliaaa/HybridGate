# Real Data Collection Guide

## Overview

Das Framework unterstützt drei Ansätze für die Baseline-Generierung:

1. **Synthetic** (Demo/Testing): Komplett synthetische PR-Templates
2. **GitHub** (Echt, aber eingeschränkt): Echte GitHub PRs, benötigt passende Injection Points
3. **Hybrid** (Empfohlen): Echte PR-Metadaten + synthetische Code-Snippets

## Empfohlener Workflow: Hybrid-Ansatz

Der **Hybrid-Ansatz** kombiniert das Beste aus beiden Welten:
- ✅ Realistische PR-Titel und Beschreibungen von echten GitHub PRs
- ✅ Garantierte Injection Points durch synthetische Code-Snippets
- ✅ Reproduzierbare Baseline-Generierung
- ✅ Skalierbar und zuverlässig

### Schritt 1: GitHub PR-Metadaten sammeln

```bash
# Option A: Ohne Token (60 requests/hour)
python src/data_collection/github_pr_collector.py \
    --count 100 \
    --output data/01_raw/github_prs.json

# Option B: Mit GitHub Token (5000 requests/hour)
export GITHUB_TOKEN="your_token_here"
python src/data_collection/github_pr_collector.py \
    --count 100 \
    --output data/01_raw/github_prs.json
```

**GitHub Token erstellen:**
1. Gehe zu https://github.com/settings/tokens
2. "Generate new token (classic)"
3. Scope: Nur "public_repo" (read access)
4. Token kopieren und als Environment Variable setzen

### Schritt 2: Baseline mit Hybrid-Ansatz generieren

```bash
python src/data_collection/hybrid_baseline_builder.py \
    --github-prs data/01_raw/github_prs.json \
    --target-samples 50 \
    --output data/03_baseline/b0_real_samples.json
```

**Ergebnis:**
- 50 Baseline-Samples
- Echte PR-Titel und -Beschreibungen
- Synthetische, aber realistische Code-Snippets mit Secrets
- 100% Erfolgsrate (kein Risiko fehlender Injection Points)

### Schritt 3: Validierung

```bash
python src/utils/validate_samples.py data/03_baseline/b0_real_samples.json
```

### Schritt 4: Perturbationen generieren

```bash
python src/manipulation/perturbation_engine.py \
    --input data/03_baseline/b0_real_samples.json \
    --output data/04_manipulated/experiment_samples.json
```

## Alternative Ansätze

### Ansatz 1: Rein Synthetisch (für schnelles Testing)

```bash
python src/data_collection/build_real_baseline.py \
    --use-synthetic \
    --target-samples 10 \
    --output data/03_baseline/b0_synthetic.json
```

**Vorteile:**
- Sehr schnell
- Keine API-Calls nötig
- Gut für Tests

**Nachteile:**
- Keine echten PR-Daten
- Limitierte Varianz

### Ansatz 2: Pure GitHub (experimentell)

```bash
# Erst PRs sammeln
python src/data_collection/github_pr_collector.py \
    --count 200 \
    --output data/01_raw/github_prs.json

# Dann Baseline generieren
python src/data_collection/build_real_baseline.py \
    --github-prs data/01_raw/github_prs.json \
    --target-samples 50 \
    --output data/03_baseline/b0_github.json
```

**Vorteile:**
- 100% echte Diffs
- Maximale Authentizität

**Nachteile:**
- Niedrige Success-Rate (~5-10%)
- Benötigt viele PRs für wenige Samples
- Nicht alle PRs haben passende Injection Points

## Code-Snippet-Patterns (Hybrid-Ansatz)

Der Hybrid-Builder nutzt 8 realistische Python-Code-Patterns:

1. **Stripe API Config** - `stripe.api_key = "..."`
2. **AWS Config Class** - `self.access_key = "..."`
3. **GitHub Webhook** - `WEBHOOK_SECRET = "..."`
4. **Settings File** - `API_KEY = "..."`
5. **Database Connection** - `password="..."`
6. **OAuth2 Client** - `CLIENT_SECRET = "..."`
7. **Email Config** - `EMAIL_HOST_PASSWORD = "..."`
8. **JWT Utils** - `SECRET_KEY = "..."`

Jedes Pattern:
- Ist realistisch und kommt in echten Projekten vor
- Hat einen klaren Injection Point
- Folgt Python-Best-Practices (außer dem hardcoded Secret)
- Ist im unified diff Format

## GitHub PR Collector

### Features

- **Intelligente Repository-Auswahl**: 8 populäre Python-Repositories
  - django/django
  - pallets/flask
  - psf/requests
  - encode/django-rest-framework
  - boto/boto3
  - stripe/stripe-python
  - googleapis/google-api-python-client
  - tweepy/tweepy

- **Security-Keyword-Filterung**: Automatische Filterung für relevante PRs
  - auth, login, api, token, credential
  - config, setup, webhook, secret, database
  - password, key, security, oauth

- **Rate Limit Management**: Automatisches Warten bei niedrigem Limit

- **Vollständige Metadaten**:
  - PR Nummer, Titel, Body
  - Diff/Patch
  - Repository, Author
  - URLs

### CLI-Optionen

```bash
python src/data_collection/github_pr_collector.py --help

Options:
  --token TOKEN          GitHub token (oder GITHUB_TOKEN env var)
  --output PATH          Output JSON Pfad (default: data/01_raw/github_prs.json)
  --count N              Ziel-Anzahl PRs (default: 100)
  --max-per-repo N       Max PRs pro Repository (default: 20)
```

### Rate Limits

| Modus | Limit | Empfehlung |
|-------|-------|-----------|
| Unauthenticated | 60/hour | Für Tests ok |
| Authenticated | 5000/hour | Empfohlen für Production |

## Vergleich der Ansätze

| Kriterium | Synthetic | GitHub | Hybrid (Empfohlen) |
|-----------|-----------|--------|-------------------|
| Echte PR-Metadaten | ❌ | ✅ | ✅ |
| Echte Code-Diffs | ❌ | ✅ | ❌ |
| Garantierte Injection Points | ✅ | ❌ | ✅ |
| Erfolgsrate | 100% | ~5-10% | 100% |
| API-Calls nötig | ❌ | ✅ | ✅ |
| Skalierbarkeit | ✅ | ❌ | ✅ |
| Reproduzierbarkeit | ✅ | ❌ | ✅ |
| Wissenschaftliche Validität | ❌ | ✅ | ✅ |

## Best Practices

### Für Thesis-Experimente

1. **Nutze Hybrid-Ansatz** für die Hauptexperimente
   - Sammle 100+ GitHub PRs einmalig
   - Generiere 50 Baseline-Samples
   - Gut dokumentierbar und reproduzierbar

2. **Token verwenden** für größere Datenmengen
   - Erstelle Read-Only Token
   - Nutze Environment Variable
   - Nicht ins Git committen!

3. **Validiere immer** die generierten Samples
   - `validate_samples.py` ausführen
   - Stichproben manuell prüfen
   - Inter-Rater-Reliabilität für Subset

### Für schnelle Tests

1. Nutze `--use-synthetic` Flag
2. Kleine `--target-samples` (5-10)
3. Teste Pipeline-Komponenten einzeln

## Troubleshooting

### "Rate limit exceeded"
```bash
# Warte 60 Minuten oder nutze Token
export GITHUB_TOKEN="your_token"
python src/data_collection/github_pr_collector.py ...
```

### "No injection points found"
```bash
# Nutze Hybrid-Ansatz statt Pure GitHub
python src/data_collection/hybrid_baseline_builder.py \
    --github-prs data/01_raw/github_prs.json ...
```

### "GitHub PR file not found"
```bash
# Sammle erst PRs
python src/data_collection/github_pr_collector.py \
    --count 50 \
    --output data/01_raw/github_prs.json
```

## Output-Struktur

Alle drei Ansätze produzieren identisches Output-Format:

```json
{
  "sample_id": "REAL_001",
  "gt_has_secret": true,
  "gt_secret_type": "token",
  "gt_file_path": "src/payments/stripe_config.py",
  "gt_line_start": 3,
  "condition": "B0",
  "pr_title": "Add Stripe payment integration",
  "pr_body": "This PR integrates Stripe for payment processing...",
  "code_context": "diff --git a/... [unified diff]"
}
```

## Zusammenfassung

**Für deine Bachelorarbeit empfehle ich:**

1. ✅ **Hybrid-Ansatz verwenden**
2. ✅ 100 GitHub PRs sammeln (einmalig)
3. ✅ 50-100 Baseline-Samples generieren
4. ✅ GitHub Token nutzen (höhere Rate Limits)
5. ✅ Alles dokumentieren und versionieren

Das gibt dir:
- Wissenschaftlich valide Daten (echte PR-Kontexte)
- Reproduzierbare Ergebnisse
- Skalierbare Pipeline
- Keine Probleme mit fehlenden Injection Points
