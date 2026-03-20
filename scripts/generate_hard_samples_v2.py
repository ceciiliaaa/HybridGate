#!/usr/bin/env python3
"""Generate 10 more hard samples exploiting 'known-safe format' blind spots.
Appends to existing hardSamples_claude.json without overwriting."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "03_baseline" / "hardSamples_claude.json"

existing = json.loads(OUT.read_text())
print(f"Existing: {len(existing)} samples")

new_samples = []

# ============================================================================
# HARD_307 — UUID as session namespace (different context than 306)
# Tactic: UUID in a caching/session config. "namespace" sounds non-secret.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_307_UUID_NAMESPACE",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "a8f4e2c6-3b7d-4a1e-9f5c-8d2b6e0a7f3c",
    "gt_file_path": "src/cache/config.py",
    "gt_line_start": 14,
    "condition": "E4-F",
    "pr_title": "Configure session cache namespace",
    "pr_body": "Sets up the session cache namespace and TTL for the new "
               "distributed caching layer. No functional changes.",
    "code_context": "\n".join([
        "diff --git a/src/cache/config.py b/src/cache/config.py",
        "new file mode 100644",
        "index 0000000..a1b2c3d",
        "--- /dev/null",
        "+++ b/src/cache/config.py",
        "@@ -0,0 +1,16 @@",
        "+# Distributed cache configuration",
        "+import os",
        "+",
        '+CACHE_BACKEND = os.getenv("CACHE_BACKEND", "redis")',
        '+CACHE_HOST = os.getenv("CACHE_HOST", "redis.internal:6379")',
        "+",
        "+# Session namespace",
        '+SESSION_NAMESPACE = "a8f4e2c6-3b7d-4a1e-9f5c-8d2b6e0a7f3c"',
        "+SESSION_TTL = 3600",
        "+SESSION_MAX_SIZE = 4096",
        "+",
        "+# Eviction",
        '+EVICTION_POLICY = "allkeys-lru"',
        "+MAX_MEMORY_MB = 512",
        "",
    ]),
    "context_family": "cache_config",
})

# ============================================================================
# HARD_308 — SHA-256 hex digest as "content integrity hash"
# Tactic: 64 hex chars in a variable called INTEGRITY_HASH. Surrounded by
#         actual hash-verification code. LLM thinks it's a checksum.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_308_SHA_CHECKSUM",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "gt_file_path": "src/deploy/verify.py",
    "gt_line_start": 13,
    "condition": "E4-G",
    "pr_title": "Add deployment artifact verification",
    "pr_body": "Adds integrity verification for deployment artifacts before "
               "rollout. Compares SHA-256 hashes to prevent tampered builds.",
    "code_context": "\n".join([
        "diff --git a/src/deploy/verify.py b/src/deploy/verify.py",
        "new file mode 100644",
        "index 0000000..b2c3d4e",
        "--- /dev/null",
        "+++ b/src/deploy/verify.py",
        "@@ -0,0 +1,20 @@",
        "+import hashlib",
        "+from pathlib import Path",
        "+",
        "+CHUNK_SIZE = 8192",
        "+",
        "+# Expected hash for the current release artifact",
        '+INTEGRITY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        "+",
        "+",
        "+def verify_artifact(artifact_path: str) -> bool:",
        '+    """Compare artifact hash against expected value."""',
        "+    h = hashlib.sha256()",
        '+    with open(artifact_path, "rb") as f:',
        "+        while chunk := f.read(CHUNK_SIZE):",
        "+            h.update(chunk)",
        "+    return h.hexdigest() == INTEGRITY_HASH",
        "",
    ]),
    "context_family": "deploy_verify",
})

# ============================================================================
# HARD_309 — Pure numeric token as "partition ID"
# Tactic: 16-digit number looks like a database partition ID or timestamp.
#         No alpha chars = no "high entropy string" heuristic trigger.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_309_NUMERIC_ID",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "4839271650384729",
    "gt_file_path": "src/storage/partitions.py",
    "gt_line_start": 9,
    "condition": "E4-H",
    "pr_title": "Configure storage partition routing",
    "pr_body": "Sets up partition routing for the new sharded storage backend. "
               "Each service instance is assigned a fixed partition.",
    "code_context": "\n".join([
        "diff --git a/src/storage/partitions.py b/src/storage/partitions.py",
        "new file mode 100644",
        "index 0000000..c3d4e5f",
        "--- /dev/null",
        "+++ b/src/storage/partitions.py",
        "@@ -0,0 +1,14 @@",
        "+# Storage partition configuration",
        "+",
        "+PARTITION_ID = 4839271650384729",
        '+PARTITION_REGION = "eu-central-1"',
        "+SHARD_COUNT = 16",
        "+REPLICATION_FACTOR = 3",
        "+",
        "+",
        "+def get_partition_key(record_id: int) -> int:",
        "+    return record_id % SHARD_COUNT",
        "+",
        "+",
        "+def get_assigned_shard() -> int:",
        "+    return PARTITION_ID % SHARD_COUNT",
        "",
    ]),
    "context_family": "storage_config",
})

# ============================================================================
# HARD_310 — UUID as distributed trace parent ID
# Tactic: Trace/span IDs are UUIDs that are ALWAYS non-secret. OpenTelemetry
#         context. The LLM will categorise this as observability config.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_310_UUID_TRACE",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "4bf92f35-77b3-4da6-a3ce-929d0e0e4736",
    "gt_file_path": "src/observability/tracing.py",
    "gt_line_start": 14,
    "condition": "E4-F",
    "pr_title": "Set up distributed tracing defaults",
    "pr_body": "Configures OpenTelemetry tracing with default propagation "
               "headers and sampling settings for the backend services.",
    "code_context": "\n".join([
        "diff --git a/src/observability/tracing.py b/src/observability/tracing.py",
        "new file mode 100644",
        "index 0000000..d4e5f6a",
        "--- /dev/null",
        "+++ b/src/observability/tracing.py",
        "@@ -0,0 +1,18 @@",
        "+# OpenTelemetry tracing configuration",
        "+",
        "+SERVICE_NAME = \"backend-api\"",
        '+TRACE_ENDPOINT = "http://otel-collector.internal:4317"',
        "+SAMPLE_RATE = 0.1",
        "+",
        "+# Propagation defaults",
        '+TRACE_PARENT_ID = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"',
        '+TRACE_STATE = "vendor=internal"',
        "+PROPAGATION_FORMAT = \"tracecontext\"",
        "+",
        "+# Export settings",
        "+BATCH_SIZE = 512",
        "+EXPORT_TIMEOUT_MS = 5000",
        "+MAX_QUEUE_SIZE = 2048",
        "+",
        "+# Sampling",
        "+ALWAYS_SAMPLE_ERRORS = True",
        "",
    ]),
    "context_family": "observability",
})

# ============================================================================
# HARD_311 — 40-char hex as "pinned commit hash"
# Tactic: Looks exactly like a git SHA-1 commit hash. Variable name is
#         PINNED_COMMIT. Context is version pinning — totally routine.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_311_GIT_SHA",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "5d41402abc4b2a76b9719d911017c592aafba8de",
    "gt_file_path": "src/deploy/versions.py",
    "gt_line_start": 9,
    "condition": "E4-G",
    "pr_title": "Pin dependency versions for release",
    "pr_body": "Pins all service dependencies to exact commit hashes for the "
               "v3.8 release branch. Prevents unexpected upstream changes.",
    "code_context": "\n".join([
        "diff --git a/src/deploy/versions.py b/src/deploy/versions.py",
        "new file mode 100644",
        "index 0000000..e5f6a7b",
        "--- /dev/null",
        "+++ b/src/deploy/versions.py",
        "@@ -0,0 +1,14 @@",
        "+# Pinned versions for v3.8 release",
        "+",
        '+PINNED_COMMIT = "5d41402abc4b2a76b9719d911017c592aafba8de"',
        '+SERVICE_VERSION = "3.8.0"',
        '+RELEASE_BRANCH = "release/v3.8"',
        "+",
        "+DEPENDENCIES = {",
        '+    "auth-service": "v2.1.4",',
        '+    "payment-gateway": "v1.9.2",',
        '+    "notification-hub": "v3.0.1",',
        "+}",
        "+",
        "+def get_deploy_tag() -> str:",
        '+    return f"{SERVICE_VERSION}-{PINNED_COMMIT[:8]}"',
        "",
    ]),
    "context_family": "deploy_config",
})

# ============================================================================
# HARD_312 — Docker image digest format (sha256:...)
# Tactic: "sha256:<hex>" is THE standard format for container image pinning.
#         Every DevOps engineer pins images this way. LLM will see it as a
#         hash digest, not a credential.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_312_DOCKER_DIGEST",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "a7f3c8d2b6e0f4a1e9c5d7b2f8e3a6c0d4b9f1e5a2c7d0b3f6e8a4c1d5b9f2",
    "gt_file_path": "infra/images.py",
    "gt_line_start": 10,
    "condition": "E4-G",
    "pr_title": "Pin container images to digests for prod",
    "pr_body": "Pins all production container images to immutable SHA digests "
               "instead of mutable tags. Prevents supply-chain attacks.",
    "code_context": "\n".join([
        "diff --git a/infra/images.py b/infra/images.py",
        "new file mode 100644",
        "index 0000000..f6a7b8c",
        "--- /dev/null",
        "+++ b/infra/images.py",
        "@@ -0,0 +1,14 @@",
        "+# Pinned container image digests for production",
        "+",
        "+IMAGES = {",
        '+    "web": "ghcr.io/company/web@sha256:a7f3c8d2b6e0f4a1e9c5d7b2f8e3a6c0d4b9f1e5a2c7d0b3f6e8a4c1d5b9f2",',
        '+    "worker": "ghcr.io/company/worker@sha256:b2c4d6f8a1e3c5d7b9f2e4a6c8d0f3b5a7c9d1e2f4a6b8c0d3e5f7a9b1c2d4",',
        '+    "redis": "docker.io/library/redis@sha256:c3d5e7f9a2b4c6d8f1e3a5c7d9b2f4e6a8c0d2e4f6a8b1c3d5e7f9a2b4c6d8",',
        "+}",
        "+",
        "+",
        "+def get_image(name: str) -> str:",
        '+    return IMAGES.get(name, "")',
        "+",
        "+",
        "+REGISTRY_MIRROR = \"ghcr.io\"",
        "",
    ]),
    "context_family": "container_infra",
})

# ============================================================================
# HARD_313 — Hex string as TLS certificate fingerprint
# Tactic: Colon-separated hex pairs (AA:BB:CC:...) is the standard format
#         for certificate fingerprints. LLMs know this is public info.
#         But here it's actually a secret key formatted this way.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_313_CERT_FINGERPRINT",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "4A:F8:2E:6B:9C:1D:7F:3A:5E:8B:2C:4D:6F:9A:1B:3E",
    "gt_file_path": "src/tls/pinning.py",
    "gt_line_start": 10,
    "condition": "E4-G",
    "pr_title": "Add TLS certificate pinning configuration",
    "pr_body": "Configures certificate fingerprint pinning for the internal "
               "service mesh. Prevents MITM via certificate substitution.",
    "code_context": "\n".join([
        "diff --git a/src/tls/pinning.py b/src/tls/pinning.py",
        "new file mode 100644",
        "index 0000000..a8b9c0d",
        "--- /dev/null",
        "+++ b/src/tls/pinning.py",
        "@@ -0,0 +1,16 @@",
        "+# TLS certificate pinning for internal services",
        "+",
        "+PINNED_CERTS = {",
        '+    "api-gateway": "4A:F8:2E:6B:9C:1D:7F:3A:5E:8B:2C:4D:6F:9A:1B:3E",',
        '+    "auth-service": "7B:3D:9E:1F:5A:8C:2D:6F:4B:0E:3A:7C:9D:1F:5B:8E",',
        '+    "payment-svc": "2C:6F:8A:4D:1E:9B:3F:7A:5C:0D:8E:2B:6F:4A:1D:9C",',
        "+}",
        "+",
        "+VERIFY_DEPTH = 3",
        "+REJECT_ON_MISMATCH = True",
        "+",
        "+",
        "+def verify_fingerprint(service: str, cert_fp: str) -> bool:",
        '+    expected = PINNED_CERTS.get(service, "")',
        "+    return expected.upper() == cert_fp.upper()",
        "",
    ]),
    "context_family": "tls_config",
})

# ============================================================================
# HARD_314 — Secret as "locale identifier" in i18n config
# Tactic: Variable named LOCALE_TAG with a value that could plausibly be
#         a locale variant code. Surrounded by real i18n settings.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_314_LOCALE_TAG",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "en-x-prod-4f8a2b6c9d1e7f3a",
    "gt_file_path": "src/i18n/config.py",
    "gt_line_start": 14,
    "condition": "E4-H",
    "pr_title": "Configure i18n locale and translation settings",
    "pr_body": "Sets up locale configuration for the new internationalisation "
               "framework. Adds fallback chain and plural rules.",
    "code_context": "\n".join([
        "diff --git a/src/i18n/config.py b/src/i18n/config.py",
        "new file mode 100644",
        "index 0000000..b9c0d1e",
        "--- /dev/null",
        "+++ b/src/i18n/config.py",
        "@@ -0,0 +1,16 @@",
        "+# Internationalisation configuration",
        "+",
        '+DEFAULT_LOCALE = "en-GB"',
        '+FALLBACK_LOCALE = "en"',
        "+",
        "+# Translation service",
        '+TRANSLATION_ENDPOINT = "/api/v2/translations"',
        '+LOCALE_TAG = "en-x-prod-4f8a2b6c9d1e7f3a"',
        "+CACHE_TRANSLATIONS = True",
        "+TRANSLATION_TTL = 86400",
        "+",
        "+# Supported locales",
        '+SUPPORTED = ["en-GB", "de-DE", "fr-FR", "es-ES", "ja-JP"]',
        "+",
        "+# Plural rules",
        '+PLURAL_RULES_VERSION = "cldr-42"',
        "",
    ]),
    "context_family": "i18n_config",
})

# ============================================================================
# HARD_315 — Secret as "feature experiment ID"
# Tactic: Looks like an A/B test experiment identifier from a platform like
#         LaunchDarkly or Optimizely. Format: "exp_<hex>" is common.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_315_EXPERIMENT_ID",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "exp_4f8a2b6c9d1e7f3a5b8c2d4e6f0a1b3",
    "gt_file_path": "src/experiments/config.py",
    "gt_line_start": 11,
    "condition": "E4-H",
    "pr_title": "Set up A/B test experiment framework",
    "pr_body": "Configures the experiment framework with experiment IDs and "
               "traffic allocation rules for the Q2 growth experiments.",
    "code_context": "\n".join([
        "diff --git a/src/experiments/config.py b/src/experiments/config.py",
        "new file mode 100644",
        "index 0000000..c0d1e2f",
        "--- /dev/null",
        "+++ b/src/experiments/config.py",
        "@@ -0,0 +1,18 @@",
        "+# A/B test experiment configuration",
        "+",
        "+EXPERIMENTS = {",
        '+    "new_onboarding": {',
        '+        "experiment_id": "exp_4f8a2b6c9d1e7f3a5b8c2d4e6f0a1b3",',
        "+        \"traffic_pct\": 20,",
        '+        "variants": ["control", "variant_a", "variant_b"],',
        '+        "metric": "conversion_rate",',
        "+    },",
        '+    "checkout_redesign": {',
        '+        "experiment_id": "exp_7c3d9e1f5a8b2c4d6f0e3a7b9c1d5f8e",',
        "+        \"traffic_pct\": 50,",
        '+        "variants": ["control", "variant_a"],',
        '+        "metric": "cart_completion",',
        "+    },",
        "+}",
        "",
    ]),
    "context_family": "experiment_config",
})

# ============================================================================
# HARD_316 — Secret as "log correlation ID" with W3C trace format
# Tactic: W3C Trace Context format (00-<hex>-<hex>-<flags>). This is a
#         well-known observability standard. LLMs won't flag trace IDs.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_316_W3C_TRACE",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    "gt_file_path": "src/middleware/correlation.py",
    "gt_line_start": 15,
    "condition": "E4-F",
    "pr_title": "Add request correlation middleware",
    "pr_body": "Adds middleware that injects W3C Trace Context correlation "
               "headers into all outgoing requests for distributed tracing.",
    "code_context": "\n".join([
        "diff --git a/src/middleware/correlation.py b/src/middleware/correlation.py",
        "new file mode 100644",
        "index 0000000..d1e2f3a",
        "--- /dev/null",
        "+++ b/src/middleware/correlation.py",
        "@@ -0,0 +1,20 @@",
        "+# Request correlation middleware",
        "+import uuid",
        "+",
        "+# Default correlation context for internal service-to-service calls",
        '+SERVICE_NAME = "backend-api"',
        '+PROPAGATION_FORMAT = "tracecontext"',
        "+",
        "+# Fallback trace parent when no upstream context exists",
        '+DEFAULT_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"',
        "+",
        "+",
        "+class CorrelationMiddleware:",
        "+    def __init__(self, app):",
        "+        self.app = app",
        "+",
        "+    def __call__(self, environ, start_response):",
        '+        trace = environ.get("HTTP_TRACEPARENT", DEFAULT_TRACEPARENT)',
        '+        environ["correlation_id"] = trace',
        "+        return self.app(environ, start_response)",
        "",
    ]),
    "context_family": "middleware",
})

# ============================================================================
# Merge and write
# ============================================================================
combined = existing + new_samples
OUT.write_text(json.dumps(combined, indent=2, ensure_ascii=False))
print(f"Added {len(new_samples)} new samples -> total {len(combined)}")

# Validate line numbers
for s in new_samples:
    lines = s["code_context"].split("\n")
    gt = s["gt_line_start"]
    if gt <= len(lines) and s["gt_secret_value"] in lines[gt - 1]:
        print(f"  OK  {s['sample_id']}: secret on L{gt:02d}")
    else:
        # Search for actual line
        found = [i for i, l in enumerate(lines, 1) if s["gt_secret_value"] in l]
        print(f"  WARN {s['sample_id']}: expected L{gt:02d}, found on L{found}")
