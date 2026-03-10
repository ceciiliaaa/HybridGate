"""
B2 Baseline Builder - Improved Dataset Generation

Addresses b1 quality issues:
1. Realistic secret formats (no repeating patterns)
2. Diverse context templates (12+ families)
3. Semantic matching between secret type and context

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
import random
import string
import hashlib
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class GroundTruthSample:
    """Ground truth schema for a baseline sample."""
    sample_id: str
    gt_has_secret: bool
    gt_secret_type: Optional[str]
    gt_secret_value: Optional[str]
    gt_file_path: str
    gt_line_start: Optional[int]
    condition: str
    pr_title: str
    pr_body: str
    code_context: str
    context_family: str  # NEW: Track which template family was used

    def to_dict(self) -> Dict:
        return asdict(self)


class RealisticSecretGenerator:
    """
    Generates realistic-looking secrets without obvious patterns.

    Key improvements over b1:
    - No repeating hex blocks
    - Proper character sets per type
    - Realistic lengths and formats
    - No placeholder-like strings for positives
    """

    @staticmethod
    def _random_hex(length: int) -> str:
        """Generate random hex string without repeating patterns."""
        chars = '0123456789abcdef'
        result = ''.join(random.choice(chars) for _ in range(length))
        # Ensure no 4+ char repetition
        while any(result[i:i+4] in result[i+4:] for i in range(len(result)-7)):
            result = ''.join(random.choice(chars) for _ in range(length))
        return result

    @staticmethod
    def _random_base64(length: int) -> str:
        """Generate random base64-like string."""
        chars = string.ascii_letters + string.digits + '+/'
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def _random_alphanumeric(length: int, upper: bool = False) -> str:
        """Generate random alphanumeric string."""
        chars = string.ascii_uppercase + string.digits if upper else string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    @classmethod
    def generate_stripe_key(cls) -> Tuple[str, str]:
        """Generate realistic Stripe API key."""
        # sk_live_[24 random alphanumeric]
        prefix = random.choice(['sk_live_', 'sk_test_', 'rk_live_', 'rk_test_'])
        body = cls._random_alphanumeric(24)
        return f"{prefix}{body}", "api_key"

    @classmethod
    def generate_github_token(cls) -> Tuple[str, str]:
        """Generate realistic GitHub token (classic or fine-grained)."""
        prefix = random.choice(['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'])
        body = cls._random_alphanumeric(36)
        return f"{prefix}{body}", "token"

    @classmethod
    def generate_aws_access_key(cls) -> Tuple[str, str]:
        """Generate realistic AWS Access Key ID."""
        # AKIA[16 uppercase alphanumeric]
        prefix = random.choice(['AKIA', 'ABIA', 'ACCA', 'AGPA', 'AIDA', 'AROA', 'ASCA', 'ASIA'])
        body = cls._random_alphanumeric(16, upper=True)
        return f"{prefix}{body}", "api_key"

    @classmethod
    def generate_aws_secret_key(cls) -> Tuple[str, str]:
        """Generate realistic AWS Secret Access Key."""
        # 40 character base64-like
        body = cls._random_base64(40)
        return body, "api_key"

    @classmethod
    def generate_openai_key(cls) -> Tuple[str, str]:
        """Generate realistic OpenAI API key."""
        # sk-proj-[48 alphanumeric with underscores]
        prefix = random.choice(['sk-proj-', 'sk-', 'sk-org-'])
        body = cls._random_alphanumeric(48)
        return f"{prefix}{body}", "api_key"

    @classmethod
    def generate_slack_webhook(cls) -> Tuple[str, str]:
        """Generate realistic Slack webhook URL."""
        workspace_id = 'T' + cls._random_alphanumeric(10, upper=True)
        bot_id = 'B' + cls._random_alphanumeric(10, upper=True)
        token = cls._random_alphanumeric(24)
        return f"https://hooks.slack.com/services/{workspace_id}/{bot_id}/{token}", "token"

    @classmethod
    def generate_sendgrid_key(cls) -> Tuple[str, str]:
        """Generate realistic SendGrid API key."""
        # SG.[22 chars].[43 chars]
        part1 = cls._random_alphanumeric(22)
        part2 = cls._random_alphanumeric(43)
        return f"SG.{part1}.{part2}", "api_key"

    @classmethod
    def generate_twilio_sid(cls) -> Tuple[str, str]:
        """Generate realistic Twilio Account SID."""
        # AC[32 hex chars]
        body = cls._random_hex(32)
        return f"AC{body}", "api_key"

    @classmethod
    def generate_twilio_auth_token(cls) -> Tuple[str, str]:
        """Generate realistic Twilio Auth Token."""
        # 32 hex chars
        return cls._random_hex(32), "token"

    @classmethod
    def generate_jwt_secret(cls) -> Tuple[str, str]:
        """Generate realistic JWT signing secret."""
        # Random 32-64 byte secret
        length = random.randint(32, 64)
        return cls._random_base64(length), "token"

    @classmethod
    def generate_database_password(cls) -> Tuple[str, str]:
        """Generate realistic database password."""
        # Mix of chars, numbers, special
        length = random.randint(16, 24)
        chars = string.ascii_letters + string.digits + '!@#$%^&*'
        pwd = ''.join(random.choice(chars) for _ in range(length))
        return pwd, "password"

    @classmethod
    def generate_connection_string(cls) -> Tuple[str, str]:
        """Generate realistic database connection string."""
        user = random.choice(['admin', 'dbuser', 'app_user', 'service'])
        pwd = cls._random_alphanumeric(16)
        host = random.choice(['db.prod.internal', 'postgres.cluster.local', 'mysql-primary.svc'])
        port = random.choice(['5432', '3306', '27017'])
        db = random.choice(['production', 'main_db', 'app_data'])
        proto = random.choice(['postgresql', 'mysql', 'mongodb'])
        return f"{proto}://{user}:{pwd}@{host}:{port}/{db}", "connection_string"

    @classmethod
    def generate_private_key(cls) -> Tuple[str, str]:
        """Generate realistic RSA private key snippet."""
        # Generate a realistic-looking but fake PEM body
        key_type = random.choice([
            ('RSA PRIVATE KEY', 64),
            ('PRIVATE KEY', 64),
            ('EC PRIVATE KEY', 48),
            ('OPENSSH PRIVATE KEY', 70)
        ])
        header = f"-----BEGIN {key_type[0]}-----"
        footer = f"-----END {key_type[0]}-----"
        # Generate multiple lines of base64-like content
        lines = []
        for _ in range(random.randint(20, 28)):
            lines.append(cls._random_base64(key_type[1]))
        body = '\n'.join(lines)
        return f"{header}\n{body}\n{footer}", "private_key"

    @classmethod
    def generate_firebase_key(cls) -> Tuple[str, str]:
        """Generate realistic Firebase API key."""
        # AIza[35 alphanumeric]
        body = cls._random_alphanumeric(35)
        return f"AIza{body}", "api_key"

    @classmethod
    def generate_docker_registry_token(cls) -> Tuple[str, str]:
        """Generate realistic Docker registry token."""
        body = cls._random_base64(48)
        return body, "token"

    @classmethod
    def generate(cls, secret_type: str = None) -> Tuple[str, str, str]:
        """
        Generate a random realistic secret.

        Args:
            secret_type: Optional specific type to generate

        Returns:
            Tuple of (secret_value, secret_type, secret_category)
        """
        generators = {
            'stripe': cls.generate_stripe_key,
            'github': cls.generate_github_token,
            'aws_access': cls.generate_aws_access_key,
            'aws_secret': cls.generate_aws_secret_key,
            'openai': cls.generate_openai_key,
            'slack': cls.generate_slack_webhook,
            'sendgrid': cls.generate_sendgrid_key,
            'twilio_sid': cls.generate_twilio_sid,
            'twilio_auth': cls.generate_twilio_auth_token,
            'jwt': cls.generate_jwt_secret,
            'database_pwd': cls.generate_database_password,
            'connection_string': cls.generate_connection_string,
            'private_key': cls.generate_private_key,
            'firebase': cls.generate_firebase_key,
            'docker': cls.generate_docker_registry_token,
        }

        if secret_type and secret_type in generators:
            secret, stype = generators[secret_type]()
            return secret, stype, secret_type

        category = random.choice(list(generators.keys()))
        secret, stype = generators[category]()
        return secret, stype, category


class ContextTemplateFamily:
    """
    Diverse context templates for REAL samples.

    Each family has:
    - Unique file path pattern
    - Unique PR title/body
    - Unique code structure
    - Appropriate secret type mapping
    """

    FAMILIES = [
        # Family 1: JWT Authentication Middleware
        {
            'id': 'jwt_auth',
            'title': 'Add JWT authentication middleware',
            'body': 'Implements JWT-based authentication for API routes.',
            'file_path': 'src/middleware/auth.py',
            'secret_types': ['jwt', 'openai'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,15 @@
+import jwt
+from functools import wraps
+from flask import request, jsonify
+
+class JWTAuth:
+    def __init__(self):
+        self.secret_key = "{secret}"
+
+    def verify_token(self, token: str) -> dict:
+        try:
+            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
+            return payload
+        except jwt.InvalidTokenError:
+            return None
'''
        },

        # Family 2: Stripe Payment Integration
        {
            'id': 'stripe_payment',
            'title': 'Configure Stripe payment processing',
            'body': 'Sets up Stripe SDK for handling customer payments.',
            'file_path': 'src/payments/stripe_client.py',
            'secret_types': ['stripe'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,18 @@
+import stripe
+from dataclasses import dataclass
+
+@dataclass
+class StripeClient:
+    api_key: str = "{secret}"
+
+    def __post_init__(self):
+        stripe.api_key = self.api_key
+
+    def create_charge(self, amount: int, currency: str = "usd"):
+        return stripe.Charge.create(
+            amount=amount,
+            currency=currency
+        )
+
+client = StripeClient()
'''
        },

        # Family 3: AWS S3 Storage
        {
            'id': 'aws_s3',
            'title': 'Add AWS S3 file storage configuration',
            'body': 'Configures S3 bucket access for file uploads and downloads.',
            'file_path': 'src/storage/s3_handler.py',
            'secret_types': ['aws_access', 'aws_secret'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,16 @@
+import boto3
+from botocore.config import Config
+
+class S3Handler:
+    def __init__(self):
+        self.access_key = "{secret}"
+        self.bucket = "app-uploads-prod"
+
+    def get_client(self):
+        return boto3.client(
+            's3',
+            aws_access_key_id=self.access_key,
+            region_name='us-east-1'
+        )
'''
        },

        # Family 4: PostgreSQL Database Connection
        {
            'id': 'postgres_db',
            'title': 'Add PostgreSQL database configuration',
            'body': 'Sets up database connection pool for production environment.',
            'file_path': 'src/database/connection.py',
            'secret_types': ['database_pwd', 'connection_string'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,14 @@
+import psycopg2
+from psycopg2 import pool
+
+class DatabasePool:
+    def __init__(self):
+        self.connection_string = "{secret}"
+        self.pool = psycopg2.pool.ThreadedConnectionPool(
+            minconn=5,
+            maxconn=20,
+            dsn=self.connection_string
+        )
+
+    def get_connection(self):
+        return self.pool.getconn()
'''
        },

        # Family 5: Slack Notification Service
        {
            'id': 'slack_notify',
            'title': 'Implement Slack notification service',
            'body': 'Adds webhook integration for sending alerts to Slack channels.',
            'file_path': 'src/notifications/slack.py',
            'secret_types': ['slack'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,15 @@
+import requests
+import json
+
+class SlackNotifier:
+    def __init__(self):
+        self.webhook_url = "{secret}"
+
+    def send_message(self, message: str, channel: str = None):
+        payload = {{"text": message}}
+        if channel:
+            payload["channel"] = channel
+        return requests.post(
+            self.webhook_url,
+            json=payload
+        )
'''
        },

        # Family 6: SendGrid Email Service
        {
            'id': 'sendgrid_email',
            'title': 'Configure SendGrid email integration',
            'body': 'Sets up transactional email sending via SendGrid API.',
            'file_path': 'src/email/sendgrid_client.py',
            'secret_types': ['sendgrid'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,16 @@
+from sendgrid import SendGridAPIClient
+from sendgrid.helpers.mail import Mail
+
+class EmailService:
+    def __init__(self):
+        self.api_key = "{secret}"
+        self.client = SendGridAPIClient(self.api_key)
+
+    def send_email(self, to_email: str, subject: str, content: str):
+        message = Mail(
+            from_email='noreply@app.com',
+            to_emails=to_email,
+            subject=subject,
+            html_content=content
+        )
+        return self.client.send(message)
'''
        },

        # Family 7: GitHub API Integration
        {
            'id': 'github_api',
            'title': 'Add GitHub API client for repository access',
            'body': 'Implements GitHub REST API client for CI/CD automation.',
            'file_path': 'src/integrations/github_client.py',
            'secret_types': ['github'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,17 @@
+import requests
+
+class GitHubClient:
+    BASE_URL = "https://api.github.com"
+
+    def __init__(self):
+        self.token = "{secret}"
+        self.headers = {{
+            "Authorization": f"token {{self.token}}",
+            "Accept": "application/vnd.github.v3+json"
+        }}
+
+    def get_repo(self, owner: str, repo: str):
+        url = f"{{self.BASE_URL}}/repos/{{owner}}/{{repo}}"
+        response = requests.get(url, headers=self.headers)
+        return response.json()
'''
        },

        # Family 8: Twilio SMS Service
        {
            'id': 'twilio_sms',
            'title': 'Implement Twilio SMS notification service',
            'body': 'Adds SMS sending capability via Twilio API.',
            'file_path': 'src/notifications/sms.py',
            'secret_types': ['twilio_sid', 'twilio_auth'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,16 @@
+from twilio.rest import Client
+
+class SMSService:
+    def __init__(self):
+        self.account_sid = "{secret}"
+        self.from_number = "+15551234567"
+
+    def send_sms(self, to_number: str, message: str):
+        client = Client(self.account_sid, self.auth_token)
+        return client.messages.create(
+            body=message,
+            from_=self.from_number,
+            to=to_number
+        )
'''
        },

        # Family 9: Redis Cache Configuration
        {
            'id': 'redis_cache',
            'title': 'Configure Redis caching layer',
            'body': 'Sets up Redis connection for application caching.',
            'file_path': 'src/cache/redis_client.py',
            'secret_types': ['database_pwd'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,14 @@
+import redis
+
+class RedisCache:
+    def __init__(self):
+        self.password = "{secret}"
+        self.client = redis.Redis(
+            host='redis.internal',
+            port=6379,
+            password=self.password,
+            decode_responses=True
+        )
+
+    def get(self, key: str):
+        return self.client.get(key)
'''
        },

        # Family 10: Docker Registry Authentication
        {
            'id': 'docker_registry',
            'title': 'Add Docker registry authentication',
            'body': 'Configures private Docker registry access for deployments.',
            'file_path': 'scripts/docker_auth.py',
            'secret_types': ['docker'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,14 @@
+import docker
+import base64
+
+class DockerAuth:
+    def __init__(self):
+        self.registry_token = "{secret}"
+        self.registry_url = "registry.company.io"
+
+    def login(self):
+        client = docker.from_env()
+        client.login(
+            registry=self.registry_url,
+            password=self.registry_token
+        )
'''
        },

        # Family 11: Firebase Admin SDK
        {
            'id': 'firebase_admin',
            'title': 'Initialize Firebase Admin SDK',
            'body': 'Sets up Firebase for push notifications and analytics.',
            'file_path': 'src/firebase/admin.py',
            'secret_types': ['firebase'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,15 @@
+import firebase_admin
+from firebase_admin import credentials, messaging
+
+class FirebaseAdmin:
+    def __init__(self):
+        self.api_key = "{secret}"
+        cred = credentials.Certificate({{
+            "type": "service_account",
+            "project_id": "my-app-prod",
+            "private_key_id": self.api_key
+        }})
+        firebase_admin.initialize_app(cred)
+
+    def send_notification(self, token: str, title: str, body: str):
+        message = messaging.Message(notification=messaging.Notification(title=title, body=body), token=token)
'''
        },

        # Family 12: OpenAI API Client
        {
            'id': 'openai_api',
            'title': 'Add OpenAI API integration',
            'body': 'Implements OpenAI client for LLM-powered features.',
            'file_path': 'src/ai/openai_client.py',
            'secret_types': ['openai'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,16 @@
+from openai import OpenAI
+
+class AIClient:
+    def __init__(self):
+        self.api_key = "{secret}"
+        self.client = OpenAI(api_key=self.api_key)
+
+    def complete(self, prompt: str, model: str = "gpt-4"):
+        response = self.client.chat.completions.create(
+            model=model,
+            messages=[{{"role": "user", "content": prompt}}]
+        )
+        return response.choices[0].message.content
'''
        },

        # Family 13: SSH/Deployment Key
        {
            'id': 'ssh_deploy',
            'title': 'Add deployment SSH key configuration',
            'body': 'Configures SSH key for automated server deployments.',
            'file_path': 'deploy/ssh_config.py',
            'secret_types': ['private_key'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,14 @@
+import paramiko
+from io import StringIO
+
+class SSHDeployer:
+    def __init__(self):
+        self.private_key = """{secret}"""
+
+    def connect(self, host: str, user: str = "deploy"):
+        key = paramiko.RSAKey.from_private_key(StringIO(self.private_key))
+        client = paramiko.SSHClient()
+        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
+        client.connect(host, username=user, pkey=key)
+        return client
'''
        },

        # Family 14: OAuth2 Client
        {
            'id': 'oauth2_client',
            'title': 'Implement OAuth2 client for third-party auth',
            'body': 'Adds OAuth2 authentication flow for social login.',
            'file_path': 'src/auth/oauth2.py',
            'secret_types': ['jwt', 'github'],
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,17 @@
+import requests
+from urllib.parse import urlencode
+
+class OAuth2Client:
+    def __init__(self):
+        self.client_secret = "{secret}"
+        self.client_id = "app-client-id"
+        self.token_url = "https://oauth.provider.com/token"
+
+    def exchange_code(self, code: str):
+        data = {{
+            "grant_type": "authorization_code",
+            "code": code,
+            "client_id": self.client_id,
+            "client_secret": self.client_secret
+        }}
+        return requests.post(self.token_url, data=data).json()
'''
        },

        # Family 15: Monitoring/Alerting (DataDog)
        {
            'id': 'datadog_monitoring',
            'title': 'Configure DataDog monitoring integration',
            'body': 'Sets up application monitoring and alerting via DataDog.',
            'file_path': 'src/monitoring/datadog.py',
            'secret_types': ['stripe', 'sendgrid'],  # Similar format
            'template': '''diff --git a/{file_path} b/{file_path}
new file mode 100644
index 0000000..{hash1}
--- /dev/null
+++ b/{file_path}
@@ -0,0 +1,15 @@
+from datadog import initialize, statsd
+
+class DataDogClient:
+    def __init__(self):
+        self.api_key = "{secret}"
+        initialize(api_key=self.api_key)
+
+    def increment(self, metric: str, tags: list = None):
+        statsd.increment(metric, tags=tags)
+
+    def gauge(self, metric: str, value: float, tags: list = None):
+        statsd.gauge(metric, value, tags=tags)
'''
        },
    ]

    @classmethod
    def get_random_family(cls) -> Dict:
        """Get a random context family."""
        return random.choice(cls.FAMILIES)

    @classmethod
    def get_family_by_id(cls, family_id: str) -> Optional[Dict]:
        """Get a specific family by ID."""
        for family in cls.FAMILIES:
            if family['id'] == family_id:
                return family
        return None

    @classmethod
    def get_distributed_families(cls, count: int) -> List[Dict]:
        """
        Get families with even distribution.
        Ensures all families are used before repeating.
        """
        families = []
        available = cls.FAMILIES.copy()
        random.shuffle(available)

        for i in range(count):
            if not available:
                available = cls.FAMILIES.copy()
                random.shuffle(available)
            families.append(available.pop())

        return families


class B2BaselineBuilder:
    """
    Builds the improved b2 baseline dataset.

    Improvements over b1:
    - Uses RealisticSecretGenerator for realistic secrets
    - Uses ContextTemplateFamily for diverse contexts
    - Ensures semantic matching between secrets and contexts
    """

    def __init__(self, target_samples: int = 50, seed: int = None):
        self.target_samples = target_samples
        self.seed = seed
        self.samples: List[GroundTruthSample] = []

        if seed is not None:
            random.seed(seed)
            logger.info(f"Random seed set to {seed}")

        logger.info(f"Initialized B2BaselineBuilder with target_samples={target_samples}, seed={seed}")

    def build(self) -> List[GroundTruthSample]:
        """Build the b2 baseline dataset."""
        logger.info(f"Building {self.target_samples} b2 samples...")

        # Get evenly distributed families
        families = ContextTemplateFamily.get_distributed_families(self.target_samples)

        for i, family in enumerate(families):
            sample = self._create_sample(i + 1, family)
            self.samples.append(sample)

            if (i + 1) % 10 == 0:
                logger.info(f"Progress: {i + 1}/{self.target_samples}")

        logger.info(f"Generated {len(self.samples)} samples")
        return self.samples

    def _create_sample(self, index: int, family: Dict) -> GroundTruthSample:
        """Create a single sample from a family template."""
        # Generate secret matching the family's secret types
        secret_category = random.choice(family['secret_types'])
        secret, secret_type, _ = RealisticSecretGenerator.generate(secret_category)

        # Generate unique hash for diff
        hash1 = RealisticSecretGenerator._random_hex(7)

        # Format the diff template
        diff = family['template'].format(
            file_path=family['file_path'],
            secret=secret,
            hash1=hash1
        )

        # Find line number of secret
        lines = diff.split('\n')
        secret_line = 1
        for i, line in enumerate(lines):
            if secret in line and line.startswith('+'):
                # Count actual code lines
                code_lines = [l for l in lines[:i+1] if l.startswith('+') and not l.startswith('+++')]
                secret_line = len(code_lines)
                break

        return GroundTruthSample(
            sample_id=f"REAL_{index:03d}",
            gt_has_secret=True,
            gt_secret_type=secret_type,
            gt_secret_value=secret,
            gt_file_path=family['file_path'],
            gt_line_start=secret_line,
            condition="B0",
            pr_title=family['title'],
            pr_body=family['body'],
            code_context=diff,
            context_family=family['id']
        )

    def save(self, output_path: str):
        """Save samples to JSON file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        samples_dict = [s.to_dict() for s in self.samples]

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(samples_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved {len(self.samples)} samples to {output_path}")

        # Log statistics
        self._log_statistics()

    def _log_statistics(self):
        """Log statistics about generated dataset."""
        from collections import Counter

        secret_types = Counter(s.gt_secret_type for s in self.samples)
        families = Counter(s.context_family for s in self.samples)
        unique_secrets = len(set(s.gt_secret_value for s in self.samples))

        logger.info("\n--- B2 Dataset Statistics ---")
        logger.info(f"Total samples: {len(self.samples)}")
        logger.info(f"Unique secrets: {unique_secrets} ({unique_secrets/len(self.samples)*100:.1f}%)")
        logger.info(f"Secret types: {dict(secret_types)}")
        logger.info(f"Context families: {dict(families)}")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Build B2 Baseline dataset with improved diversity"
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/03_baseline/b2_real_samples.json',
        help='Output JSON file path'
    )
    parser.add_argument(
        '--target-samples',
        type=int,
        default=50,
        help='Number of samples to generate'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Random seed for reproducibility'
    )

    args = parser.parse_args()

    builder = B2BaselineBuilder(
        target_samples=args.target_samples,
        seed=args.seed
    )
    builder.build()
    builder.save(args.output)

    logger.info("B2 baseline generation complete!")


if __name__ == "__main__":
    main()
