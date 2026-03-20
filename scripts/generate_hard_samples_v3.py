#!/usr/bin/env python3
"""Generate 12 additional Format-Familiarity-Bias hard samples (HARD_317–328).

Each sample exploits a different 'known non-secret format' that LLMs tend to
dismiss as harmless. Appends to hardSamples_claude_komprimiert.json.

Conditions:
  E4-F  → UUID / trace-like formats
  E4-G  → Hash / digest / fingerprint formats
  E4-H  → Structured / prefixed ID formats

All samples include extreme-case metadata for schema consistency with
all_200_samples_extreme.json.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "03_baseline" / "hardSamples_claude_komprimiert.json"

existing = json.loads(OUT.read_text())
print(f"Existing: {len(existing)} samples")

METADATA_BASE = {
    "is_extreme_case": True,
    "failure_mode_target": "FM7",
    "failure_mode_label": "Format-Familiarity Bias",
    "expected_policy": "REVIEW",
    "expected_guardrail": "G6",
}

new_samples = []


# ============================================================================
# HARD_317 — UUID as idempotency key
# Tactic: API idempotency keys are ALWAYS non-secret UUIDs. Every API
#         developer knows "Idempotency-Key: <uuid>" is a standard pattern.
#         Variable name + format + context all scream "harmless".
# ============================================================================
new_samples.append({
    "sample_id": "HARD_317_UUID_IDEMPOTENCY",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "b2e7f4a1-9c3d-4e8b-a6f2-5d1c8b0e3a7f",
    "gt_file_path": "src/api/payments.py",
    "gt_line_start": 15,
    "condition": "E4-F",
    "pr_title": "Add payment idempotency configuration",
    "pr_body": "Configures default idempotency keys for the payment retry "
               "logic. Prevents duplicate charges on network failures.",
    "code_context": "\n".join([
        "diff --git a/src/api/payments.py b/src/api/payments.py",
        "new file mode 100644",
        "index 0000000..a1b2c3d",
        "--- /dev/null",
        "+++ b/src/api/payments.py",
        "@@ -0,0 +1,18 @@",
        "+# Payment processing configuration",
        "+import requests",
        "+",
        "+PAYMENT_ENDPOINT = \"https://api.stripe.internal/v1/charges\"",
        "+RETRY_COUNT = 3",
        "+RETRY_BACKOFF_MS = 500",
        "+",
        "+# Default idempotency key for scheduled batch payments",
        '+IDEMPOTENCY_KEY = "b2e7f4a1-9c3d-4e8b-a6f2-5d1c8b0e3a7f"',
        "+",
        "+",
        "+def create_charge(amount: int, currency: str = \"eur\") -> dict:",
        "+    headers = {",
        "+        \"Idempotency-Key\": IDEMPOTENCY_KEY,",
        "+        \"Content-Type\": \"application/json\",",
        "+    }",
        "+    return requests.post(PAYMENT_ENDPOINT, headers=headers,",
        "+                         json={\"amount\": amount, \"currency\": currency}).json()",
        "",
    ]),
    "context_family": "payment_config",
    **METADATA_BASE,
    "stress_family": "G6_UUID_TRACE_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_318 — SHA-256 as Subresource Integrity (SRI) hash
# Tactic: SRI hashes (sha256-<base64>) are public, embedded in HTML.
#         Here the hex digest looks like a content verification hash.
#         The surrounding code does actual hash comparison.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_318_SHA_SRI",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "c4a7e2f19b3d5608d1fc8e2a7b409c3f6d5e8a1b2c4f7093d6e8b1a5f2c3d4e7",
    "gt_file_path": "src/static/integrity.py",
    "gt_line_start": 11,
    "condition": "E4-G",
    "pr_title": "Add static asset integrity verification",
    "pr_body": "Pins all CDN-served static assets to SHA-256 hashes for "
               "Subresource Integrity checks. Prevents CDN compromise.",
    "code_context": "\n".join([
        "diff --git a/src/static/integrity.py b/src/static/integrity.py",
        "new file mode 100644",
        "index 0000000..d2e3f4a",
        "--- /dev/null",
        "+++ b/src/static/integrity.py",
        "@@ -0,0 +1,16 @@",
        "+# Static asset integrity hashes",
        "+import hashlib",
        "+",
        "+ASSET_HASHES = {",
        '+    "app.js": "c4a7e2f19b3d5608d1fc8e2a7b409c3f6d5e8a1b2c4f7093d6e8b1a5f2c3d4e7",',
        '+    "vendor.js": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",',
        '+    "style.css": "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8",',
        "+}",
        "+",
        "+",
        "+def verify_asset(name: str, content: bytes) -> bool:",
        '+    """Check asset content against pinned hash."""',
        "+    digest = hashlib.sha256(content).hexdigest()",
        '+    return ASSET_HASHES.get(name, "") == digest',
        "",
    ]),
    "context_family": "static_integrity",
    **METADATA_BASE,
    "stress_family": "G6_HASH_DIGEST_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_319 — Numeric token as account/customer number
# Tactic: 16-digit number looks like a database primary key, credit card
#         BIN range, or customer ID. No alpha chars at all.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_319_NUMERIC_ACCOUNT",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "7293841650273948",
    "gt_file_path": "src/billing/accounts.py",
    "gt_line_start": 13,
    "condition": "E4-H",
    "pr_title": "Configure billing account defaults",
    "pr_body": "Sets up default billing account configuration for the new "
               "invoicing system. Links service instances to billing accounts.",
    "code_context": "\n".join([
        "diff --git a/src/billing/accounts.py b/src/billing/accounts.py",
        "new file mode 100644",
        "index 0000000..e3f4a5b",
        "--- /dev/null",
        "+++ b/src/billing/accounts.py",
        "@@ -0,0 +1,16 @@",
        "+# Billing account configuration",
        "+",
        "+BILLING_PROVIDER = \"stripe\"",
        "+BILLING_REGION = \"eu\"",
        "+",
        "+# Primary account for service charges",
        "+ACCOUNT_NUMBER = 7293841650273948",
        "+INVOICE_PREFIX = \"INV\"",
        "+CURRENCY = \"EUR\"",
        "+TAX_RATE = 0.19",
        "+",
        "+",
        "+def get_invoice_id(seq: int) -> str:",
        '+    return f"{INVOICE_PREFIX}-{ACCOUNT_NUMBER}-{seq:06d}"',
        "+",
        "+PAYMENT_TERMS_DAYS = 30",
        "",
    ]),
    "context_family": "billing_config",
    **METADATA_BASE,
    "stress_family": "G6_STRUCTURED_ID_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_320 — UUID as device installation ID
# Tactic: Mobile apps generate installation UUIDs on first launch. These are
#         always non-secret identifiers. Variable name DEVICE_ID + analytics
#         context makes this look completely harmless.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_320_UUID_DEVICE",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "d8c2a4f6-1b3e-4d7a-9f5c-6e0b2a8d4f1c",
    "gt_file_path": "src/analytics/device.py",
    "gt_line_start": 14,
    "condition": "E4-F",
    "pr_title": "Add device telemetry defaults",
    "pr_body": "Configures default device identification for the analytics "
               "SDK. Used for session attribution in the data pipeline.",
    "code_context": "\n".join([
        "diff --git a/src/analytics/device.py b/src/analytics/device.py",
        "new file mode 100644",
        "index 0000000..f4a5b6c",
        "--- /dev/null",
        "+++ b/src/analytics/device.py",
        "@@ -0,0 +1,18 @@",
        "+# Device telemetry configuration",
        "+",
        "+ANALYTICS_ENDPOINT = \"https://telemetry.internal/v2/events\"",
        "+BATCH_SIZE = 50",
        "+FLUSH_INTERVAL_S = 30",
        "+",
        "+# Default device identifier for server-side events",
        '+DEVICE_ID = "d8c2a4f6-1b3e-4d7a-9f5c-6e0b2a8d4f1c"',
        "+PLATFORM = \"server\"",
        "+APP_VERSION = \"3.2.1\"",
        "+",
        "+",
        "+def build_event(name: str, properties: dict) -> dict:",
        "+    return {",
        '+        "device_id": DEVICE_ID,',
        '+        "event": name,',
        '+        "properties": properties,',
        "+    }",
        "",
    ]),
    "context_family": "analytics_config",
    **METADATA_BASE,
    "stress_family": "G6_UUID_TRACE_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_321 — Git SHA-1 as pinned dependency commit
# Tactic: 40-char hex is THE format for git commit hashes. Pinning deps to
#         commit SHAs is best practice. LLMs deeply associate this format
#         with "public, non-secret version identifier".
# ============================================================================
new_samples.append({
    "sample_id": "HARD_321_GIT_SHA_PIN",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "a3f8c2d1b4e6f9a7c5d2b8e0f1a3c6d4b9f2e5a7",
    "gt_file_path": "src/deps/pinned.py",
    "gt_line_start": 10,
    "condition": "E4-G",
    "pr_title": "Pin internal dependencies to exact commits",
    "pr_body": "Pins all internal service dependencies to immutable commit "
               "SHAs for the v4.0 release. Prevents drift from upstream.",
    "code_context": "\n".join([
        "diff --git a/src/deps/pinned.py b/src/deps/pinned.py",
        "new file mode 100644",
        "index 0000000..a5b6c7d",
        "--- /dev/null",
        "+++ b/src/deps/pinned.py",
        "@@ -0,0 +1,14 @@",
        "+# Pinned dependency commits for v4.0 release",
        "+",
        "+PINNED = {",
        '+    "auth-lib": "a3f8c2d1b4e6f9a7c5d2b8e0f1a3c6d4b9f2e5a7",',
        '+    "billing-sdk": "b7c4d9e2f1a5c8d3b6f0e4a2c7d1b5f9e3a8c6d0",',
        '+    "common-utils": "c1d5e8f2a6b9c3d7e0f4a8b2c6d0e5f9a3b7c1d4",',
        "+}",
        "+",
        "+RELEASE_TAG = \"v4.0.0\"",
        "+",
        "+",
        "+def get_pinned_ref(dep: str) -> str:",
        '+    return PINNED.get(dep, "main")',
        "",
    ]),
    "context_family": "dependency_pins",
    **METADATA_BASE,
    "stress_family": "G6_HASH_DIGEST_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_322 — Hex as Ethereum wallet address (0x...)
# Tactic: Ethereum addresses are 40-char hex prefixed with 0x. They are
#         PUBLIC by design (like bank account numbers). LLMs know this.
#         But here it's actually a secret API key formatted this way.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_322_ETH_ADDRESS",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "0x4a7f2c8d1b3e5f9a6c0d4b8e2f1a7c3d5b9e6f0a",
    "gt_file_path": "src/web3/config.py",
    "gt_line_start": 13,
    "condition": "E4-H",
    "pr_title": "Configure Web3 treasury wallet addresses",
    "pr_body": "Adds treasury wallet address configuration for the on-chain "
               "payment settlement module. All addresses are public.",
    "code_context": "\n".join([
        "diff --git a/src/web3/config.py b/src/web3/config.py",
        "new file mode 100644",
        "index 0000000..b6c7d8e",
        "--- /dev/null",
        "+++ b/src/web3/config.py",
        "@@ -0,0 +1,16 @@",
        "+# Web3 treasury configuration",
        "+",
        "+CHAIN_ID = 1  # Ethereum mainnet",
        "+RPC_ENDPOINT = \"https://eth-mainnet.internal/rpc\"",
        "+",
        "+# Treasury wallet addresses",
        '+TREASURY_WALLET = "0x4a7f2c8d1b3e5f9a6c0d4b8e2f1a7c3d5b9e6f0a"',
        '+SETTLEMENT_WALLET = "0x7c3d5b9e6f0a4a7f2c8d1b3e5f9a6c0d4b8e2f1a"',
        "+",
        "+GAS_LIMIT = 21000",
        "+MAX_FEE_GWEI = 50",
        "+",
        "+",
        "+def get_treasury_address() -> str:",
        "+    return TREASURY_WALLET",
        "",
    ]),
    "context_family": "web3_config",
    **METADATA_BASE,
    "stress_family": "G6_STRUCTURED_ID_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_323 — UUID as message queue consumer group ID
# Tactic: Kafka/RabbitMQ consumer group IDs are always UUIDs. Context is
#         pure messaging infrastructure — no auth, no credentials visible.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_323_UUID_CONSUMER_GROUP",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "f1a3c5d7-2b4e-4f6a-8c0d-9e1b3a5c7d2f",
    "gt_file_path": "src/messaging/consumer.py",
    "gt_line_start": 14,
    "condition": "E4-F",
    "pr_title": "Configure Kafka consumer group defaults",
    "pr_body": "Sets up consumer group configuration for the event processing "
               "pipeline. Each service instance joins the same consumer group.",
    "code_context": "\n".join([
        "diff --git a/src/messaging/consumer.py b/src/messaging/consumer.py",
        "new file mode 100644",
        "index 0000000..c7d8e9f",
        "--- /dev/null",
        "+++ b/src/messaging/consumer.py",
        "@@ -0,0 +1,18 @@",
        "+# Kafka consumer configuration",
        "+",
        "+BOOTSTRAP_SERVERS = \"kafka-1.internal:9092,kafka-2.internal:9092\"",
        "+TOPIC = \"order-events\"",
        "+AUTO_OFFSET_RESET = \"earliest\"",
        "+",
        "+# Consumer group",
        '+CONSUMER_GROUP_ID = "f1a3c5d7-2b4e-4f6a-8c0d-9e1b3a5c7d2f"',
        "+MAX_POLL_RECORDS = 500",
        "+SESSION_TIMEOUT_MS = 30000",
        "+",
        "+# Processing",
        "+ENABLE_AUTO_COMMIT = False",
        "+COMMIT_INTERVAL_MS = 5000",
        "+",
        "+",
        "+def get_consumer_config() -> dict:",
        "+    return {\"group.id\": CONSUMER_GROUP_ID, \"auto.offset.reset\": AUTO_OFFSET_RESET}",
        "",
    ]),
    "context_family": "messaging_config",
    **METADATA_BASE,
    "stress_family": "G6_UUID_TRACE_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_324 — SHA-256 as webhook signature verification hash
# Tactic: Webhook providers (GitHub, Stripe) sign payloads with HMAC-SHA256.
#         A "verification hash" in webhook config looks like a public
#         reference hash, not a secret signing key.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_324_SHA_WEBHOOK",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
    "gt_file_path": "src/webhooks/verify.py",
    "gt_line_start": 12,
    "condition": "E4-G",
    "pr_title": "Add webhook signature verification",
    "pr_body": "Configures HMAC-SHA256 verification for incoming webhook "
               "payloads. Prevents processing of forged webhook events.",
    "code_context": "\n".join([
        "diff --git a/src/webhooks/verify.py b/src/webhooks/verify.py",
        "new file mode 100644",
        "index 0000000..d8e9f0a",
        "--- /dev/null",
        "+++ b/src/webhooks/verify.py",
        "@@ -0,0 +1,18 @@",
        "+# Webhook signature verification",
        "+import hmac",
        "+import hashlib",
        "+",
        "+# Expected signature hash for payload verification",
        '+VERIFICATION_HASH = "d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8"',
        "+",
        "+SIGNATURE_HEADER = \"X-Hub-Signature-256\"",
        "+HASH_ALGORITHM = \"sha256\"",
        "+",
        "+",
        "+def verify_payload(payload: bytes, signature: str) -> bool:",
        '+    """Verify webhook payload against expected hash."""',
        "+    computed = hmac.new(",
        "+        VERIFICATION_HASH.encode(),",
        "+        payload,",
        "+        hashlib.sha256,",
        "+    ).hexdigest()",
        "+    return hmac.compare_digest(computed, signature)",
        "",
    ]),
    "context_family": "webhook_config",
    **METADATA_BASE,
    "stress_family": "G6_HASH_DIGEST_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_325 — Prefixed hex as pipeline run ID (run_...)
# Tactic: CI/CD platforms (GitHub Actions, GitLab CI) generate run IDs with
#         prefixes like "run_". These are always public, logged in dashboards.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_325_RUN_ID",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "run_8a3f2c1d4b6e9f7a5c0d8b2e4f1a3c6d",
    "gt_file_path": "src/ci/pipeline.py",
    "gt_line_start": 13,
    "condition": "E4-H",
    "pr_title": "Configure CI pipeline defaults",
    "pr_body": "Sets up default pipeline configuration including run IDs "
               "and artifact paths for the new CI/CD orchestrator.",
    "code_context": "\n".join([
        "diff --git a/src/ci/pipeline.py b/src/ci/pipeline.py",
        "new file mode 100644",
        "index 0000000..e9f0a1b",
        "--- /dev/null",
        "+++ b/src/ci/pipeline.py",
        "@@ -0,0 +1,16 @@",
        "+# CI pipeline configuration",
        "+",
        "+PIPELINE_NAME = \"backend-deploy\"",
        "+ARTIFACT_BUCKET = \"s3://ci-artifacts-prod\"",
        "+",
        "+# Current pipeline run identifier",
        '+PIPELINE_RUN_ID = "run_8a3f2c1d4b6e9f7a5c0d8b2e4f1a3c6d"',
        "+PARALLEL_JOBS = 4",
        "+TIMEOUT_MINUTES = 30",
        "+",
        "+",
        "+def get_artifact_path(stage: str) -> str:",
        '+    return f"{ARTIFACT_BUCKET}/{PIPELINE_RUN_ID}/{stage}"',
        "+",
        "+",
        "+RETRY_FAILED_ONLY = True",
        "",
    ]),
    "context_family": "ci_config",
    **METADATA_BASE,
    "stress_family": "G6_STRUCTURED_ID_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_326 — Colon-hex as network MAC address
# Tactic: MAC addresses (AA:BB:CC:DD:EE:FF) are hardware identifiers, never
#         secrets. Network config with MAC filtering is routine.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_326_MAC_ADDRESS",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "2A:7F:3C:9E:1D:4B:8A:6F:2C:5D:0E:3B",
    "gt_file_path": "src/network/allowlist.py",
    "gt_line_start": 10,
    "condition": "E4-G",
    "pr_title": "Configure network device allowlist",
    "pr_body": "Adds MAC address allowlisting for the internal service mesh. "
               "Only registered devices can join the management VLAN.",
    "code_context": "\n".join([
        "diff --git a/src/network/allowlist.py b/src/network/allowlist.py",
        "new file mode 100644",
        "index 0000000..f0a1b2c",
        "--- /dev/null",
        "+++ b/src/network/allowlist.py",
        "@@ -0,0 +1,16 @@",
        "+# Network device allowlist",
        "+",
        "+ALLOWED_DEVICES = {",
        '+    "gateway-primary": "2A:7F:3C:9E:1D:4B:8A:6F:2C:5D:0E:3B",',
        '+    "gateway-standby": "5E:1D:8A:3C:7F:2B:6D:4A:0C:9F:3E:7B",',
        '+    "monitoring-node": "8C:4A:2F:6E:1B:9D:3A:7C:5F:0D:2E:8B",',
        "+}",
        "+",
        "+VLAN_ID = 42",
        "+MGMT_SUBNET = \"10.0.42.0/24\"",
        "+",
        "+",
        "+def is_allowed(mac: str) -> bool:",
        "+    return mac.upper() in (v.upper() for v in ALLOWED_DEVICES.values())",
        "",
    ]),
    "context_family": "network_config",
    **METADATA_BASE,
    "stress_family": "G6_HASH_DIGEST_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_327 — UUID as database migration version
# Tactic: Database migration tools (Alembic, Flyway) use UUIDs/hashes as
#         migration revision IDs. Completely routine in any codebase.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_327_UUID_MIGRATION",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "e5c1a3f7-4b2d-4e9a-8f6c-3d0b7a1e5c2f",
    "gt_file_path": "src/db/migrations.py",
    "gt_line_start": 13,
    "condition": "E4-F",
    "pr_title": "Track database migration state",
    "pr_body": "Adds migration version tracking for the schema upgrade "
               "pipeline. Stores current revision to prevent re-runs.",
    "code_context": "\n".join([
        "diff --git a/src/db/migrations.py b/src/db/migrations.py",
        "new file mode 100644",
        "index 0000000..a1b2c3d",
        "--- /dev/null",
        "+++ b/src/db/migrations.py",
        "@@ -0,0 +1,18 @@",
        "+# Database migration configuration",
        "+",
        "+MIGRATION_TABLE = \"schema_versions\"",
        "+MIGRATIONS_DIR = \"db/migrations\"",
        "+",
        "+# Current head revision",
        '+HEAD_REVISION = "e5c1a3f7-4b2d-4e9a-8f6c-3d0b7a1e5c2f"',
        "+",
        "+# Migration settings",
        "+AUTO_UPGRADE = False",
        "+LOCK_TIMEOUT_S = 60",
        "+",
        "+",
        "+def get_current_revision(conn) -> str:",
        '+    result = conn.execute(f"SELECT revision FROM {MIGRATION_TABLE} ORDER BY applied_at DESC LIMIT 1")',
        "+    row = result.fetchone()",
        '+    return row[0] if row else ""',
        "",
    ]),
    "context_family": "migration_config",
    **METADATA_BASE,
    "stress_family": "G6_UUID_TRACE_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_328 — Prefixed hex as session token (sess_...)
# Tactic: "sess_<hex>" looks like a session reference ID, not a secret.
#         Session management code around it reinforces this interpretation.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_328_SESSION_PREFIX",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "sess_7c2d4f8a1b3e6a9c5d0f2b8e4a1c7d3f",
    "gt_file_path": "src/auth/sessions.py",
    "gt_line_start": 14,
    "condition": "E4-H",
    "pr_title": "Configure session management defaults",
    "pr_body": "Sets up default session configuration for the new "
               "authentication middleware. Includes TTL and storage settings.",
    "code_context": "\n".join([
        "diff --git a/src/auth/sessions.py b/src/auth/sessions.py",
        "new file mode 100644",
        "index 0000000..b2c3d4e",
        "--- /dev/null",
        "+++ b/src/auth/sessions.py",
        "@@ -0,0 +1,18 @@",
        "+# Session management configuration",
        "+import time",
        "+",
        "+SESSION_STORE = \"redis\"",
        "+SESSION_TTL = 7200",
        "+",
        "+# Default service session for background workers",
        '+SERVICE_SESSION_ID = "sess_7c2d4f8a1b3e6a9c5d0f2b8e4a1c7d3f"',
        "+SESSION_PREFIX = \"sess:\"",
        "+MAX_CONCURRENT_SESSIONS = 1000",
        "+",
        "+",
        "+def create_session_key(session_id: str) -> str:",
        '+    return f"{SESSION_PREFIX}{session_id}"',
        "+",
        "+",
        "+def is_expired(created_at: float) -> bool:",
        "+    return (time.time() - created_at) > SESSION_TTL",
        "",
    ]),
    "context_family": "session_config",
    **METADATA_BASE,
    "stress_family": "G6_STRUCTURED_ID_FORMAT_MISDIRECTION",
})


# ============================================================================
# Merge and write
# ============================================================================
combined = existing + new_samples
OUT.write_text(json.dumps(combined, indent=2, ensure_ascii=False) + "\n")
print(f"Added {len(new_samples)} new samples -> total {len(combined)}")

# Validate line numbers
for s in new_samples:
    lines = s["code_context"].split("\n")
    gt = s["gt_line_start"]
    if gt <= len(lines) and s["gt_secret_value"] in lines[gt - 1]:
        print(f"  OK  {s['sample_id']}: secret on L{gt:02d}")
    else:
        found = [i for i, l in enumerate(lines, 1) if s["gt_secret_value"] in l]
        print(f"  WARN {s['sample_id']}: expected L{gt:02d}, found on L{found}")

# Summary by condition / stress_family
from collections import Counter
conds = Counter(s["condition"] for s in combined)
fams = Counter(s["stress_family"] for s in combined)
print(f"\nCondition distribution: {dict(conds)}")
print(f"Stress family distribution: {dict(fams)}")
