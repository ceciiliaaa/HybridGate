#!/usr/bin/env python3
"""Generate 8 additional Format-Familiarity-Bias hard samples (HARD_329–336).

Each sample exploits a DIFFERENT 'known non-secret format' than v1–v3.
Appends to hardSamples_claude_komprimiert.json.

New formats (not yet covered by 301–328):
  - Base64 digest (44-char, SHA-256-as-base64)
  - BSON ObjectId (24-hex MongoDB document ID)
  - JWT-format string (three dot-separated base64 segments)
  - X.509 certificate serial (colon-separated hex pairs)
  - IPv6 address (public network identifier)
  - Base32-encoded seed (uppercase A-Z2-7)
  - SSH key fingerprint (SHA256: + base64)
  - CUID / compact unique ID (cuid-style alphanumeric)

Conditions:
  E4-F  → UUID / trace-like formats (JWT, Base32, CUID-ish)
  E4-G  → Hash / digest / fingerprint formats (Base64, X.509, SSH)
  E4-H  → Structured / prefixed ID formats (ObjectId, IPv6)
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
# HARD_329 — Base64 as content integrity digest
# Tactic: 44-char base64 is the standard encoding of SHA-256 hash (32 bytes
#         → 44 base64 chars). Content integrity hashes are NEVER secret.
#         Variable INTEGRITY_DIGEST + verify_content() makes this look like
#         a file verification hash, not a credential.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_329_BASE64_DIGEST",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "K7mR2xP9wF4jL6nQ8tY1vB5hG3cA0sEdR7kM2wX9",
    "gt_file_path": "src/cdn/integrity.py",
    "gt_line_start": 12,
    "condition": "E4-G",
    "pr_title": "Add CDN content integrity verification",
    "pr_body": "Pins CDN-served assets to base64-encoded SHA-256 digests. "
               "Prevents serving corrupted or tampered static files.",
    "code_context": "\n".join([
        "diff --git a/src/cdn/integrity.py b/src/cdn/integrity.py",
        "new file mode 100644",
        "index 0000000..a3b4c5d",
        "--- /dev/null",
        "+++ b/src/cdn/integrity.py",
        "@@ -0,0 +1,16 @@",
        "+# CDN content integrity verification",
        "+import base64",
        "+import hashlib",
        "+",
        "+# Base64-encoded SHA-256 digest for content verification",
        '+INTEGRITY_DIGEST = "K7mR2xP9wF4jL6nQ8tY1vB5hG3cA0sEdR7kM2wX9"',
        "+CDN_BASE_URL = \"https://cdn.internal/static\"",
        "+CACHE_CONTROL = \"public, max-age=31536000\"",
        "+",
        "+",
        "+def verify_content(content: bytes) -> bool:",
        '+    """Check content against pinned integrity digest."""',
        "+    digest = base64.b64encode(hashlib.sha256(content).digest()).decode()",
        "+    return digest == INTEGRITY_DIGEST",
        "",
    ]),
    "context_family": "cdn_integrity",
    **METADATA_BASE,
    "stress_family": "G6_HASH_DIGEST_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_330 — BSON ObjectId as MongoDB document reference
# Tactic: 24-hex-char strings are MongoDB ObjectIds — THE standard format
#         for document identifiers. They contain timestamp + machine + counter,
#         never credentials. Variable ROOT_DOCUMENT_ID in a database config
#         context makes this unquestionable.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_330_BSON_OBJECTID",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "5f8a3c1d4b2e7f9a6c0d3e8b",
    "gt_file_path": "src/db/document_store.py",
    "gt_line_start": 14,
    "condition": "E4-H",
    "pr_title": "Configure MongoDB document store defaults",
    "pr_body": "Sets up the default document store configuration including "
               "root collection references and index settings.",
    "code_context": "\n".join([
        "diff --git a/src/db/document_store.py b/src/db/document_store.py",
        "new file mode 100644",
        "index 0000000..c4d5e6f",
        "--- /dev/null",
        "+++ b/src/db/document_store.py",
        "@@ -0,0 +1,18 @@",
        "+# MongoDB document store configuration",
        "+from pymongo import MongoClient",
        "+",
        "+MONGO_URI = \"mongodb://docstore.internal:27017\"",
        "+DATABASE = \"app_data\"",
        "+",
        "+# Root document for tenant configuration tree",
        '+ROOT_DOCUMENT_ID = "5f8a3c1d4b2e7f9a6c0d3e8b"',
        "+COLLECTION = \"tenant_config\"",
        "+MAX_POOL_SIZE = 50",
        "+",
        "+",
        "+def get_root_document(client: MongoClient) -> dict:",
        "+    db = client[DATABASE]",
        "+    from bson import ObjectId",
        "+    return db[COLLECTION].find_one({\"_id\": ObjectId(ROOT_DOCUMENT_ID)})",
        "",
    ]),
    "context_family": "document_store",
    **METADATA_BASE,
    "stress_family": "G6_STRUCTURED_ID_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_331 — JWT-format string as static service assertion
# Tactic: JWTs (header.payload.signature) are THE format for web auth tokens.
#         LLMs are trained that JWTs are "tokens" but a hardcoded JWT in config
#         labelled SERVICE_ASSERTION looks like a template/example.
#         The surrounding code uses it with "grant_type": "jwt-bearer" — a
#         well-known OAuth flow where assertions are pre-built.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_331_JWT_STATIC",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdmMtYWNjb3VudCIsImlzcyI6ImludGVybmFsIn0.dG9rZW5fc2lnbmF0dXJlX3ZhbHVl",
    "gt_file_path": "src/auth/service_account.py",
    "gt_line_start": 14,
    "condition": "E4-F",
    "pr_title": "Configure service account JWT assertion",
    "pr_body": "Sets up the JWT assertion for service-to-service auth using "
               "the jwt-bearer grant type. Used by background workers.",
    "code_context": "\n".join([
        "diff --git a/src/auth/service_account.py b/src/auth/service_account.py",
        "new file mode 100644",
        "index 0000000..d5e6f7a",
        "--- /dev/null",
        "+++ b/src/auth/service_account.py",
        "@@ -0,0 +1,20 @@",
        "+# Service account authentication",
        "+import requests",
        "+",
        "+TOKEN_ENDPOINT = \"https://auth.internal/oauth/token\"",
        "+GRANT_TYPE = \"urn:ietf:params:oauth:grant-type:jwt-bearer\"",
        "+",
        "+# Pre-built assertion for the background-worker service account",
        '+SERVICE_ASSERTION = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdmMtYWNjb3VudCIsImlzcyI6ImludGVybmFsIn0.dG9rZW5fc2lnbmF0dXJlX3ZhbHVl"',
        "+SCOPE = \"internal.read internal.write\"",
        "+",
        "+",
        "+def get_access_token() -> str:",
        '+    """Exchange JWT assertion for access token."""',
        "+    resp = requests.post(TOKEN_ENDPOINT, data={",
        '+        "grant_type": GRANT_TYPE,',
        '+        "assertion": SERVICE_ASSERTION,',
        '+        "scope": SCOPE,',
        "+    })",
        "+    return resp.json()[\"access_token\"]",
        "",
    ]),
    "context_family": "service_auth",
    **METADATA_BASE,
    "stress_family": "G6_UUID_TRACE_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_332 — X.509 certificate serial as licence key
# Tactic: X.509 serial numbers are colon-separated hex pairs, and they are
#         PUBLIC information (in every TLS certificate). Variable CERT_SERIAL
#         in a PKI config module is 100% routine. But here it's actually the
#         licence activation key for the software.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_332_X509_SERIAL",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "0A:3B:7C:2D:9E:4F:1A:8B:5C:6D:3E:0F:7A:2B:9C:4D:1E:8F:5A:6B",
    "gt_file_path": "src/pki/certificates.py",
    "gt_line_start": 13,
    "condition": "E4-G",
    "pr_title": "Add PKI certificate chain configuration",
    "pr_body": "Configures the certificate chain for mutual TLS between "
               "internal services. Serial numbers pinned for chain validation.",
    "code_context": "\n".join([
        "diff --git a/src/pki/certificates.py b/src/pki/certificates.py",
        "new file mode 100644",
        "index 0000000..e6f7a8b",
        "--- /dev/null",
        "+++ b/src/pki/certificates.py",
        "@@ -0,0 +1,18 @@",
        "+# PKI certificate configuration",
        "+",
        "+CA_BUNDLE_PATH = \"/etc/ssl/certs/internal-ca.pem\"",
        "+VERIFY_CHAIN = True",
        "+",
        "+# Pinned intermediate CA serial for chain validation",
        '+CERT_SERIAL = "0A:3B:7C:2D:9E:4F:1A:8B:5C:6D:3E:0F:7A:2B:9C:4D:1E:8F:5A:6B"',
        "+CERT_ISSUER = \"CN=Internal CA, O=Company\"",
        "+MIN_KEY_SIZE = 2048",
        "+",
        "+# TLS settings",
        "+PROTOCOL_VERSION = \"TLSv1.3\"",
        "+CIPHER_SUITES = \"TLS_AES_256_GCM_SHA384\"",
        "+",
        "+",
        "+def validate_serial(cert_serial: str) -> bool:",
        "+    return cert_serial.upper() == CERT_SERIAL.upper()",
        "",
    ]),
    "context_family": "pki_config",
    **METADATA_BASE,
    "stress_family": "G6_HASH_DIGEST_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_333 — IPv6 address as service mesh node identifier
# Tactic: IPv6 addresses (8 groups of 4 hex separated by colons) are ALWAYS
#         public network identifiers. Service mesh node addressing is routine.
#         But here the "address" is actually a 128-bit secret key encoded
#         as an IPv6 literal.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_333_IPV6_NODE",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "2001:0db8:3c4d:5e6f:7a8b:9c0d:1e2f:3a4b",
    "gt_file_path": "src/mesh/addressing.py",
    "gt_line_start": 13,
    "condition": "E4-H",
    "pr_title": "Configure service mesh node addressing",
    "pr_body": "Assigns static IPv6 addresses to core mesh nodes for "
               "deterministic routing in the service discovery layer.",
    "code_context": "\n".join([
        "diff --git a/src/mesh/addressing.py b/src/mesh/addressing.py",
        "new file mode 100644",
        "index 0000000..f7a8b9c",
        "--- /dev/null",
        "+++ b/src/mesh/addressing.py",
        "@@ -0,0 +1,18 @@",
        "+# Service mesh node addressing",
        "+",
        "+MESH_NETWORK = \"2001:0db8:3c4d::/48\"",
        "+CONTROL_PLANE = \"[::1]:9901\"",
        "+",
        "+# Static node addresses for core services",
        '+PRIMARY_NODE = "2001:0db8:3c4d:5e6f:7a8b:9c0d:1e2f:3a4b"',
        '+REPLICA_NODE = "2001:0db8:3c4d:5e6f:8b9c:0d1e:2f3a:4b5c"',
        "+",
        "+HEALTH_CHECK_PORT = 8443",
        "+GOSSIP_INTERVAL_MS = 1000",
        "+",
        "+",
        "+def get_node_endpoint(node_addr: str, port: int) -> str:",
        '+    return f"https://[{node_addr}]:{port}"',
        "+",
        "+",
        "+MAX_MEMBERSHIP_SIZE = 128",
        "",
    ]),
    "context_family": "mesh_config",
    **METADATA_BASE,
    "stress_family": "G6_STRUCTURED_ID_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_334 — Base32 as TOTP configuration seed
# Tactic: Base32-encoded strings (uppercase A-Z, digits 2-7) are the standard
#         encoding for TOTP shared secrets (RFC 6238). They look like encoded
#         configuration constants. Variable name OTP_ISSUER_SEED sounds like a
#         non-secret seed/identifier for the TOTP issuer, not a shared secret.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_334_BASE32_SEED",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "JBSWY3DPEHPK3PXP4GZMRC2JLFNUQSKB",
    "gt_file_path": "src/auth/totp_config.py",
    "gt_line_start": 14,
    "condition": "E4-F",
    "pr_title": "Configure TOTP issuer parameters",
    "pr_body": "Sets up TOTP configuration for the admin 2FA module. "
               "Defines issuer label, algorithm, and encoding defaults.",
    "code_context": "\n".join([
        "diff --git a/src/auth/totp_config.py b/src/auth/totp_config.py",
        "new file mode 100644",
        "index 0000000..a8b9c0d",
        "--- /dev/null",
        "+++ b/src/auth/totp_config.py",
        "@@ -0,0 +1,18 @@",
        "+# TOTP two-factor authentication configuration",
        "+",
        "+ISSUER = \"InternalAdmin\"",
        "+ALGORITHM = \"SHA1\"",
        "+DIGITS = 6",
        "+",
        "+# Issuer-level seed for deterministic provisioning",
        '+OTP_ISSUER_SEED = "JBSWY3DPEHPK3PXP4GZMRC2JLFNUQSKB"',
        "+PERIOD = 30",
        "+ENCODING = \"base32\"",
        "+",
        "+",
        "+def get_provisioning_uri(account: str) -> str:",
        '+    return (f"otpauth://totp/{ISSUER}:{account}"',
        '+            f"?secret={OTP_ISSUER_SEED}&issuer={ISSUER}"',
        '+            f"&algorithm={ALGORITHM}&digits={DIGITS}&period={PERIOD}")',
        "",
    ]),
    "context_family": "totp_config",
    **METADATA_BASE,
    "stress_family": "G6_UUID_TRACE_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_335 — SSH key fingerprint as host verification key
# Tactic: SSH host key fingerprints (SHA256:<base64>) are PUBLIC information —
#         they appear in known_hosts, ssh-keyscan output, and GitHub docs.
#         A variable KNOWN_HOST_FINGERPRINT is expected to contain exactly this.
#         But here it is actually a symmetric signing key.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_335_SSH_FINGERPRINT",
    "gt_has_secret": True,
    "gt_secret_type": "token",
    "gt_secret_value": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
    "gt_file_path": "src/deploy/host_verify.py",
    "gt_line_start": 13,
    "condition": "E4-G",
    "pr_title": "Pin deployment host SSH fingerprints",
    "pr_body": "Pins SSH host key fingerprints for the production deployment "
               "targets. Prevents MITM during automated deployments.",
    "code_context": "\n".join([
        "diff --git a/src/deploy/host_verify.py b/src/deploy/host_verify.py",
        "new file mode 100644",
        "index 0000000..b9c0d1e",
        "--- /dev/null",
        "+++ b/src/deploy/host_verify.py",
        "@@ -0,0 +1,18 @@",
        "+# Deployment host SSH fingerprint verification",
        "+import subprocess",
        "+",
        "+DEPLOY_HOSTS = [\"deploy-1.internal\", \"deploy-2.internal\"]",
        "+",
        "+# Pinned host key fingerprints",
        '+KNOWN_HOST_FINGERPRINT = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"',
        '+BACKUP_HOST_FINGERPRINT = "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"',
        "+",
        "+",
        "+def verify_host(host: str) -> bool:",
        '+    """Verify SSH host key fingerprint before deployment."""',
        "+    result = subprocess.run(",
        '+        ["ssh-keyscan", "-t", "rsa", host],',
        "+        capture_output=True, text=True,",
        "+    )",
        "+    return KNOWN_HOST_FINGERPRINT in result.stdout",
        "",
    ]),
    "context_family": "deploy_config",
    **METADATA_BASE,
    "stress_family": "G6_HASH_DIGEST_FORMAT_MISDIRECTION",
})


# ============================================================================
# HARD_336 — CUID-style compact ID as correlation reference
# Tactic: CUIDs (collision-resistant unique IDs) look like compact alphanumeric
#         identifiers (e.g., "cl9..." or "cuid_..."). They are always non-secret
#         reference IDs used for logging and tracing. Variable CORRELATION_REF
#         in a logging module is perfectly harmless-looking.
# ============================================================================
new_samples.append({
    "sample_id": "HARD_336_CUID_REF",
    "gt_has_secret": True,
    "gt_secret_type": "api_key",
    "gt_secret_value": "cl9zk4r7x0002qf8d3a1v5m7n",
    "gt_file_path": "src/observability/correlation.py",
    "gt_line_start": 14,
    "condition": "E4-H",
    "pr_title": "Add request correlation ID configuration",
    "pr_body": "Configures default correlation IDs for the distributed tracing "
               "pipeline. Used for log aggregation across services.",
    "code_context": "\n".join([
        "diff --git a/src/observability/correlation.py b/src/observability/correlation.py",
        "new file mode 100644",
        "index 0000000..c0d1e2f",
        "--- /dev/null",
        "+++ b/src/observability/correlation.py",
        "@@ -0,0 +1,18 @@",
        "+# Request correlation ID configuration",
        "+import uuid",
        "+",
        "+HEADER_NAME = \"X-Correlation-Id\"",
        "+PROPAGATE_HEADERS = True",
        "+",
        "+# Default correlation reference for batch/cron jobs",
        '+CORRELATION_REF = "cl9zk4r7x0002qf8d3a1v5m7n"',
        "+LOG_CORRELATION = True",
        "+TRACE_SAMPLE_RATE = 0.1",
        "+",
        "+",
        "+def get_correlation_id(request_headers: dict) -> str:",
        '+    """Extract or generate correlation ID."""',
        "+    return request_headers.get(HEADER_NAME, CORRELATION_REF)",
        "+",
        "+",
        "+EXPORT_FORMAT = \"jaeger\"",
        "",
    ]),
    "context_family": "observability_config",
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
