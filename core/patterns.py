"""
core/patterns.py
Exhaustive regex patterns for secret/credential detection.
Covers AI providers, cloud, SSH/PKI, payments, databases,
auth tokens, communication platforms, and generic secrets.

Each pattern is a dict:
    name        – human-readable label shown in reports
    regex       – compiled re.Pattern
    severity    – CRITICAL | HIGH | MEDIUM | LOW
    description – one-line explanation
"""

import re
from dataclasses import dataclass


@dataclass
class SecretPattern:
    name: str
    regex: re.Pattern
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    description: str


def _p(name: str, pattern: str, severity: str, description: str) -> SecretPattern:
    return SecretPattern(
        name=name,
        regex=re.compile(pattern, re.IGNORECASE | re.MULTILINE),
        severity=severity,
        description=description,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 🤖  AI / LLM PROVIDERS
# ─────────────────────────────────────────────────────────────────────────────
AI_PATTERNS: list[SecretPattern] = [
    _p("OpenAI API Key (Modern)",
       r"sk-[a-zA-Z0-9]*T3BlbkFJ[a-zA-Z0-9]{20,}",
       "CRITICAL",
       "OpenAI modern API key"),

    _p("OpenAI API Key (Legacy)",
       r"sk-[a-zA-Z0-9]{48}",
       "CRITICAL",
       "OpenAI legacy 48-char API key"),

    _p("OpenAI Project Key",
       r"sk-proj-[a-zA-Z0-9_\-]{50,}",
       "CRITICAL",
       "OpenAI project-scoped key"),

    _p("OpenAI Service Account",
       r"sk-svcacct-[a-zA-Z0-9_\-]{50,}",
       "CRITICAL",
       "OpenAI service account key"),

    _p("Anthropic API Key",
       r"sk-ant-api0[0-9]-[a-zA-Z0-9_\-]{93,}",
       "CRITICAL",
       "Anthropic Claude API key"),

    _p("Anthropic OAuth Token",
       r"sk-ant-oat01-[a-zA-Z0-9_\-]{40,}",
       "CRITICAL",
       "Anthropic OAuth token"),

    _p("Google Gemini / AI Studio Key",
       r"AIza[0-9A-Za-z_\-]{35}",
       "CRITICAL",
       "Google AI / Firebase / Gemini API key"),

    _p("HuggingFace User Access Token",
       r"hf_[a-zA-Z0-9]{34,}",
       "HIGH",
       "HuggingFace user or org token"),

    _p("HuggingFace Org API Token",
       r"api_org_[a-zA-Z0-9]{34,}",
       "HIGH",
       "HuggingFace organization API token"),

    _p("Cohere API Key",
       r"(?i)(cohere[_\-\s]*(?:api[_\-\s]*)?key|co_)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9]{40})",
       "CRITICAL",
       "Cohere API key (context-matched)"),

    _p("Mistral AI API Key",
       r"(?i)mistral[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*[\"']?([a-zA-Z0-9]{32,})",
       "CRITICAL",
       "Mistral AI API key"),

    _p("Groq API Key",
       r"gsk_[a-zA-Z0-9]{52}",
       "CRITICAL",
       "Groq cloud API key"),

    _p("Replicate API Token",
       r"r8_[a-zA-Z0-9]{40}",
       "HIGH",
       "Replicate.com API token"),

    _p("Perplexity API Key",
       r"pplx-[a-zA-Z0-9]{48}",
       "HIGH",
       "Perplexity AI API key"),

    _p("Together AI API Key",
       r"(?i)together[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*[\"']?([a-zA-Z0-9]{64})",
       "HIGH",
       "Together AI API key"),

    _p("AI21 Studio API Key",
       r"(?i)ai21[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*[\"']?([a-zA-Z0-9]{32,})",
       "HIGH",
       "AI21 Studio API key"),

    _p("Stability AI Key",
       r"sk-[a-zA-Z0-9]{32,}(?=.*stability)",
       "HIGH",
       "Stability AI API key"),

    _p("ElevenLabs API Key",
       r"(?i)elevenlabs[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*[\"']?([a-zA-Z0-9]{32,})",
       "HIGH",
       "ElevenLabs voice API key"),

    _p("OpenRouter API Key",
       r"sk-or-[a-zA-Z0-9\-_]{40,}",
       "HIGH",
       "OpenRouter API key"),

    _p("Deepseek API Key",
       r"sk-[a-zA-Z0-9]{32}(?=.*deepseek)",
       "HIGH",
       "Deepseek API key"),
]


# ─────────────────────────────────────────────────────────────────────────────
# ☁️  CLOUD PROVIDERS
# ─────────────────────────────────────────────────────────────────────────────
CLOUD_PATTERNS: list[SecretPattern] = [
    # AWS
    _p("AWS Access Key ID",
       r"AKIA[0-9A-Z]{16}",
       "CRITICAL",
       "AWS IAM access key ID"),

    _p("AWS Secret Access Key",
       r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key\s*[:=]\s*[\"']?([0-9a-zA-Z/+]{40})",
       "CRITICAL",
       "AWS secret access key"),

    _p("AWS Session Token",
       r"(?i)aws[_\-\s]*session[_\-\s]*token\s*[:=]\s*[\"']?([a-zA-Z0-9/+=]{100,})",
       "CRITICAL",
       "AWS temporary session token"),

    _p("AWS MWS Auth Token",
       r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
       "CRITICAL",
       "Amazon MWS auth token"),

    # GCP
    _p("GCP Service Account JSON",
       r'"type"\s*:\s*"service_account"',
       "CRITICAL",
       "Google Cloud service account JSON"),

    _p("GCP OAuth2 Client Secret",
       r"(?i)client_secret\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{24,})",
       "HIGH",
       "GCP OAuth2 client secret"),

    # Azure
    _p("Azure Client Secret",
       r"(?i)azure[_\-\s]*client[_\-\s]*secret\s*[:=]\s*[\"']?([a-zA-Z0-9~._\-]{34,})",
       "CRITICAL",
       "Azure AD client secret"),

    _p("Azure Storage Connection String",
       r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
       "CRITICAL",
       "Azure Blob Storage connection string"),

    _p("Azure Storage Account Key",
       r"(?i)azure[_\-\s]*storage[_\-\s]*(?:account[_\-\s]*)?key\s*[:=]\s*[\"']?([a-zA-Z0-9+/=]{86,}==)",
       "CRITICAL",
       "Azure storage account key"),

    _p("Azure SAS Token",
       r"(?i)sig=[a-zA-Z0-9%]{40,}",
       "HIGH",
       "Azure Shared Access Signature token"),

    # DigitalOcean
    _p("DigitalOcean Personal Access Token",
       r"dop_v1_[a-zA-Z0-9]{64}",
       "CRITICAL",
       "DigitalOcean PAT"),

    _p("DigitalOcean OAuth Token",
       r"doo_v1_[a-zA-Z0-9]{64}",
       "CRITICAL",
       "DigitalOcean OAuth token"),

    _p("DigitalOcean Refresh Token",
       r"dor_v1_[a-zA-Z0-9]{64}",
       "HIGH",
       "DigitalOcean refresh token"),

    # Cloudflare
    _p("Cloudflare API Token",
       r"(?i)cloudflare[_\-\s]*(?:api[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{40})",
       "CRITICAL",
       "Cloudflare scoped API token"),

    _p("Cloudflare Global API Key",
       r"(?i)cloudflare[_\-\s]*(?:global[_\-\s]*)?api[_\-\s]*key\s*[:=]\s*[\"']?([a-f0-9]{37})",
       "CRITICAL",
       "Cloudflare global API key"),

    # Heroku
    _p("Heroku API Key",
       r"(?i)heroku[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*[\"']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
       "CRITICAL",
       "Heroku platform API key"),

    # Linode / Akamai Cloud
    _p("Linode API Token",
       r"(?i)linode[_\-\s]*(?:api[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9]{64})",
       "HIGH",
       "Linode personal access token"),

    # Vercel
    _p("Vercel API Token",
       r"(?i)vercel[_\-\s]*(?:api[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9]{24,})",
       "HIGH",
       "Vercel deployment token"),

    # Netlify
    _p("Netlify Access Token",
       r"(?i)netlify[_\-\s]*(?:access[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{40,})",
       "HIGH",
       "Netlify personal access token"),

    # Render
    _p("Render API Key",
       r"rnd_[a-zA-Z0-9]{32,}",
       "HIGH",
       "Render.com API key"),

    # Railway
    _p("Railway API Token",
       r"(?i)railway[_\-\s]*(?:api[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{32,})",
       "HIGH",
       "Railway.app API token"),

    # Fly.io
    _p("Fly.io Auth Token",
       r"fo1_[a-zA-Z0-9_\-]{40,}",
       "HIGH",
       "Fly.io auth token"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 🔑  SSH & PRIVATE KEYS / CERTIFICATES
# ─────────────────────────────────────────────────────────────────────────────
SSH_KEY_PATTERNS: list[SecretPattern] = [
    _p("RSA Private Key",
       r"-----BEGIN RSA PRIVATE KEY-----",
       "CRITICAL",
       "PEM-encoded RSA private key"),

    _p("OpenSSH Private Key",
       r"-----BEGIN OPENSSH PRIVATE KEY-----",
       "CRITICAL",
       "OpenSSH private key (Ed25519/ECDSA/RSA)"),

    _p("EC Private Key",
       r"-----BEGIN EC PRIVATE KEY-----",
       "CRITICAL",
       "Elliptic Curve private key"),

    _p("DSA Private Key",
       r"-----BEGIN DSA PRIVATE KEY-----",
       "CRITICAL",
       "DSA private key"),

    _p("PKCS#8 Private Key",
       r"-----BEGIN PRIVATE KEY-----",
       "CRITICAL",
       "PKCS#8 unencrypted private key"),

    _p("PKCS#8 Encrypted Private Key",
       r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
       "CRITICAL",
       "PKCS#8 encrypted private key"),

    _p("PGP Private Key Block",
       r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
       "CRITICAL",
       "PGP/GPG private key block"),

    _p("PuTTY Private Key",
       r"PuTTY-User-Key-File-[0-9]:",
       "CRITICAL",
       "PuTTY PPK private key file"),

    _p("SSH2 Encrypted Private Key",
       r"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
       "CRITICAL",
       "SSH2 RFC4716 encrypted private key"),

    _p("PKCS#12 / PFX Certificate",
       r"(?i)\.(pfx|p12)\b",
       "CRITICAL",
       "PKCS#12 certificate bundle (may contain private key)"),

    _p("X.509 Private Key",
       r"-----BEGIN CERTIFICATE-----",
       "MEDIUM",
       "X.509 certificate (check if private key accompanies it)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 💳  PAYMENT PROVIDERS
# ─────────────────────────────────────────────────────────────────────────────
PAYMENT_PATTERNS: list[SecretPattern] = [
    _p("Stripe Secret Key (Live)",
       r"sk_live_[0-9a-zA-Z]{24,}",
       "CRITICAL",
       "Stripe live secret key — full API access"),

    _p("Stripe Secret Key (Test)",
       r"sk_test_[0-9a-zA-Z]{24,}",
       "HIGH",
       "Stripe test secret key"),

    _p("Stripe Restricted Key",
       r"rk_live_[0-9a-zA-Z]{24,}",
       "CRITICAL",
       "Stripe restricted live key"),

    _p("Stripe Webhook Secret",
       r"whsec_[a-zA-Z0-9]{32,}",
       "HIGH",
       "Stripe webhook signing secret"),

    _p("PayPal Client Secret",
       r"(?i)paypal[_\-\s]*(?:client[_\-\s]*)?secret\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{80,})",
       "CRITICAL",
       "PayPal REST API client secret"),

    _p("Square Access Token",
       r"EAAA[a-zA-Z0-9]{60,}",
       "CRITICAL",
       "Square production access token"),

    _p("Square OAuth Secret",
       r"sq0csp-[a-zA-Z0-9_\-]{43}",
       "CRITICAL",
       "Square OAuth application secret"),

    _p("Square Application ID",
       r"sq0idp-[a-zA-Z0-9_\-]{22}",
       "MEDIUM",
       "Square application ID"),

    _p("Braintree Access Token",
       r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}",
       "CRITICAL",
       "Braintree production access token"),

    _p("Braintree Tokenization Key",
       r"production_[a-z0-9]{8}_[a-z0-9]{16}",
       "HIGH",
       "Braintree tokenization key"),

    _p("Razorpay Key Secret",
       r"rzp_live_[a-zA-Z0-9]{14,}",
       "CRITICAL",
       "Razorpay live secret key"),

    _p("Razorpay Test Key",
       r"rzp_test_[a-zA-Z0-9]{14,}",
       "MEDIUM",
       "Razorpay test secret key"),

    _p("Paystack Secret Key",
       r"sk_live_[a-zA-Z0-9]{40,}",
       "CRITICAL",
       "Paystack live secret key"),

    _p("Flutterwave Secret Key",
       r"FLWSECK_TEST-[a-zA-Z0-9]{32}|FLWSECK-[a-zA-Z0-9]{32}",
       "CRITICAL",
       "Flutterwave secret key"),

    _p("Adyen API Key",
       r"AQE[a-zA-Z0-9+/=]{60,}",
       "CRITICAL",
       "Adyen payment API key"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 🗄️  DATABASES
# ─────────────────────────────────────────────────────────────────────────────
DATABASE_PATTERNS: list[SecretPattern] = [
    _p("PostgreSQL Connection URI",
       r"postgres(?:ql)?://[^:]+:[^@\s]+@[^\s/]+(?:/\S*)?",
       "CRITICAL",
       "PostgreSQL connection string with credentials"),

    _p("MySQL Connection URI",
       r"mysql(?:2)?://[^:]+:[^@\s]+@[^\s/]+(?:/\S*)?",
       "CRITICAL",
       "MySQL connection string with credentials"),

    _p("MongoDB URI",
       r"mongodb(?:\+srv)?://[^:]+:[^@\s]+@[^\s/]+",
       "CRITICAL",
       "MongoDB connection string with credentials"),

    _p("MongoDB Atlas Cluster URI",
       r"mongodb\+srv://[^:]+:[^@\s]+@[a-z0-9\-]+\.mongodb\.net",
       "CRITICAL",
       "MongoDB Atlas SRV connection string"),

    _p("Redis URI (with password)",
       r"redis://:[^@\s]+@[^\s]+",
       "CRITICAL",
       "Redis URL with password"),

    _p("Redis Sentinel / Cluster URI",
       r"rediss?://[^:]+:[^@\s]+@[^\s]+",
       "CRITICAL",
       "Redis secure connection string"),

    _p("Elasticsearch URL (with credentials)",
       r"https?://[^:]+:[^@\s]+@[a-z0-9\-\.]+:9200",
       "CRITICAL",
       "Elasticsearch connection with auth"),

    _p("Microsoft SQL Server URI",
       r"mssql(?:\+pyodbc)?://[^:]+:[^@\s]+@[^\s/]+",
       "CRITICAL",
       "MSSQL connection string"),

    _p("Oracle JDBC Connection",
       r"jdbc:oracle:thin:[^/\s]*/[^\s@]+@[^\s]+",
       "CRITICAL",
       "Oracle JDBC connection string"),

    _p("CassandraDB URI",
       r"cassandra://[^:]+:[^@\s]+@[^\s]+",
       "CRITICAL",
       "Cassandra connection string"),

    _p("CouchDB URI",
       r"couchdb://[^:]+:[^@\s]+@[^\s]+",
       "HIGH",
       "CouchDB connection string"),

    _p("Neo4j Bolt URI",
       r"bolt://[^:]+:[^@\s]+@[^\s]+",
       "CRITICAL",
       "Neo4j Bolt connection string"),

    _p("InfluxDB URI",
       r"influxdb://[^:]+:[^@\s]+@[^\s]+",
       "HIGH",
       "InfluxDB connection string"),

    _p("RabbitMQ AMQP URI",
       r"amqps?://[^:]+:[^@\s]+@[^\s]+",
       "CRITICAL",
       "RabbitMQ AMQP connection string"),

    _p("Firebase Realtime Database URL",
       r"https://[a-z0-9\-]+\.firebaseio\.com",
       "MEDIUM",
       "Firebase Realtime DB URL (check with config)"),

    _p("Firebase Config Object",
       r'"databaseURL"\s*:\s*"https://[a-z0-9\-]+\.firebaseio\.com"',
       "HIGH",
       "Firebase config with database URL"),

    _p("Firebase Admin SDK Credential",
       r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----',
       "CRITICAL",
       "Firebase Admin SDK private key in JSON"),

    _p("Supabase Service Role Key",
       r"(?i)supabase[_\-\s]*(?:service[_\-\s]*role[_\-\s]*)?key\s*[:=]\s*[\"']?(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)",
       "CRITICAL",
       "Supabase service role JWT"),

    _p("Supabase Anon Key",
       r"(?i)supabase[_\-\s]*anon[_\-\s]*key\s*[:=]\s*[\"']?(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)",
       "MEDIUM",
       "Supabase anonymous/public JWT"),

    _p("PlanetScale Connection String",
       r"mysql://[^:]+:[^@\s]+@[a-z0-9\-]+\.connect\.psdb\.cloud",
       "CRITICAL",
       "PlanetScale MySQL connection string"),

    _p("Neon Database URI",
       r"postgres(?:ql)?://[^:]+:[^@\s]+@[a-z0-9\-]+\.neon\.tech",
       "CRITICAL",
       "Neon serverless Postgres URI"),

    _p("Turso Database URL",
       r"libsql://[a-z0-9\-]+\.turso\.io",
       "MEDIUM",
       "Turso edge database URL"),

    _p("Upstash Redis URL",
       r"rediss?://[^:]+:[^@\s]+@[a-z0-9\-]+\.upstash\.io",
       "CRITICAL",
       "Upstash Redis connection string"),

    _p("Database Password (generic)",
       r"""(?i)(?:db|database)[_\-\s]*(?:pass(?:word)?|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]""",
       "HIGH",
       "Generic database password in config"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 🔐  AUTH TOKENS & VCS
# ─────────────────────────────────────────────────────────────────────────────
AUTH_PATTERNS: list[SecretPattern] = [
    _p("GitHub Personal Access Token (Classic)",
       r"ghp_[a-zA-Z0-9]{36}",
       "CRITICAL",
       "GitHub classic PAT — full scope possible"),

    _p("GitHub Personal Access Token (Fine-Grained)",
       r"github_pat_[a-zA-Z0-9_]{82}",
       "CRITICAL",
       "GitHub fine-grained PAT"),

    _p("GitHub OAuth App Token",
       r"gho_[a-zA-Z0-9]{36}",
       "CRITICAL",
       "GitHub OAuth access token"),

    _p("GitHub GitHub Actions Token",
       r"ghs_[a-zA-Z0-9]{36}",
       "HIGH",
       "GitHub Actions installation token"),

    _p("GitHub Refresh Token",
       r"ghr_[a-zA-Z0-9]{76}",
       "HIGH",
       "GitHub refresh token"),

    _p("GitLab Personal Access Token",
       r"glpat-[a-zA-Z0-9\-_]{20}",
       "CRITICAL",
       "GitLab PAT"),

    _p("GitLab CI Job Token",
       r"glcbt-[a-zA-Z0-9]{20}",
       "HIGH",
       "GitLab CI/CD job token"),

    _p("GitLab Runner Token",
       r"glrt-[a-zA-Z0-9_\-]{20}",
       "HIGH",
       "GitLab runner registration token"),

    _p("Bitbucket App Password",
       r"(?i)bitbucket[_\-\s]*(?:app[_\-\s]*)?password\s*[:=]\s*[\"']?([a-zA-Z0-9]{20,})",
       "HIGH",
       "Bitbucket app password"),

    _p("NPM Access Token",
       r"npm_[a-zA-Z0-9]{36}",
       "HIGH",
       "NPM publish/read token"),

    _p("PyPI API Token",
       r"pypi-[a-zA-Z0-9_\-]{32,}",
       "HIGH",
       "PyPI package upload token"),

    _p("JWT Token",
       r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
       "MEDIUM",
       "JSON Web Token (check signing secret)"),

    _p("JWT Secret (in config)",
       r"""(?i)jwt[_\-\s]*secret\s*[:=]\s*['"]([^'"]{16,})['"]""",
       "CRITICAL",
       "JWT signing secret in config"),

    _p("HashiCorp Vault Token",
       r"hvs\.[a-zA-Z0-9]{24,}",
       "CRITICAL",
       "HashiCorp Vault service token"),

    _p("PostHog Project API Key",
       r"phc_[a-zA-Z0-9]{43}",
       "MEDIUM",
       "PostHog project API key"),

    _p("PostHog Personal API Key",
       r"phs_[a-zA-Z0-9]{43}",
       "HIGH",
       "PostHog personal API key"),

    _p("Sentry Auth Token",
       r"sntrys_[a-zA-Z0-9_]{64,}",
       "HIGH",
       "Sentry.io auth token"),

    _p("Datadog API Key",
       r"(?i)datadog[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*[\"']?([a-f0-9]{32})",
       "HIGH",
       "Datadog API key"),

    _p("New Relic License Key",
       r"NRAK-[A-Z0-9]{27}",
       "HIGH",
       "New Relic license key"),

    _p("Doppler Service Token",
       r"dp\.st\.[a-zA-Z0-9_]{40,}",
       "CRITICAL",
       "Doppler service token"),

    _p("Infisical API Key",
       r"inf_[a-zA-Z0-9]{32,}",
       "HIGH",
       "Infisical secrets manager key"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 💬  COMMUNICATION & SOCIAL PLATFORMS
# ─────────────────────────────────────────────────────────────────────────────
COMMUNICATION_PATTERNS: list[SecretPattern] = [
    _p("Twilio Account SID",
       r"AC[0-9a-fA-F]{32}",
       "HIGH",
       "Twilio account SID"),

    _p("Twilio Auth Token",
       r"(?i)twilio[_\-\s]*auth[_\-\s]*token\s*[:=]\s*[\"']?([0-9a-fA-F]{32})",
       "CRITICAL",
       "Twilio auth token"),

    _p("SendGrid API Key",
       r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
       "CRITICAL",
       "SendGrid email API key"),

    _p("Mailgun API Key",
       r"key-[0-9a-zA-Z]{32}",
       "HIGH",
       "Mailgun API key"),

    _p("Mailchimp API Key",
       r"[0-9a-f]{32}-us[0-9]{1,2}",
       "HIGH",
       "Mailchimp API key"),

    _p("Postmark Server Token",
       r"(?i)postmark[_\-\s]*(?:server[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9\-]{36})",
       "HIGH",
       "Postmark server token"),

    _p("Slack Bot Token",
       r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
       "CRITICAL",
       "Slack bot OAuth token"),

    _p("Slack User Token",
       r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}",
       "CRITICAL",
       "Slack user OAuth token"),

    _p("Slack App-Level Token",
       r"xapp-[0-9]-[A-Z0-9]{10}-[0-9]+-[a-f0-9]{64}",
       "HIGH",
       "Slack app-level token"),

    _p("Slack Webhook URL",
       r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
       "HIGH",
       "Slack incoming webhook URL"),

    _p("Discord Bot Token",
       r"[MNO][a-zA-Z0-9]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27,}",
       "CRITICAL",
       "Discord bot token"),

    _p("Discord Webhook URL",
       r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+",
       "HIGH",
       "Discord webhook URL"),

    _p("Discord Client Secret",
       r"(?i)discord[_\-\s]*client[_\-\s]*secret\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{32})",
       "CRITICAL",
       "Discord application client secret"),

    _p("Telegram Bot Token",
       r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}",
       "HIGH",
       "Telegram bot API token"),

    _p("Facebook App Secret",
       r"(?i)facebook[_\-\s]*(?:app[_\-\s]*)?secret\s*[:=]\s*[\"']?([a-f0-9]{32})",
       "CRITICAL",
       "Facebook/Meta app secret"),

    _p("Twitter / X Bearer Token",
       r"AAAA[a-zA-Z0-9%]{80,}",
       "HIGH",
       "Twitter/X API Bearer token"),

    _p("Twitter / X API Secret",
       r"(?i)twitter[_\-\s]*(?:api[_\-\s]*)?secret\s*[:=]\s*[\"']?([a-zA-Z0-9]{50})",
       "HIGH",
       "Twitter/X API consumer secret"),

    _p("Instagram Access Token",
       r"IGQV[a-zA-Z0-9_\-]{100,}",
       "HIGH",
       "Instagram Graph API access token"),

    _p("LinkedIn Client Secret",
       r"(?i)linkedin[_\-\s]*client[_\-\s]*secret\s*[:=]\s*[\"']?([a-zA-Z0-9]{16})",
       "HIGH",
       "LinkedIn OAuth client secret"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 📦  PACKAGE REGISTRIES & CI/CD
# ─────────────────────────────────────────────────────────────────────────────
DEVOPS_PATTERNS: list[SecretPattern] = [
    _p("Docker Hub Token",
       r"(?i)dockerhub[_\-\s]*(?:access[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{25,})",
       "HIGH",
       "Docker Hub personal access token"),

    _p("CircleCI API Token",
       r"(?i)circleci[_\-\s]*(?:api[_\-\s]*)?token\s*[:=]\s*[\"']?([a-f0-9]{40})",
       "HIGH",
       "CircleCI personal API token"),

    _p("Travis CI API Token",
       r"(?i)travis[_\-\s]*(?:api[_\-\s]*)?token\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{22})",
       "HIGH",
       "Travis CI API token"),

    _p("Jenkins API Token",
       r"(?i)jenkins[_\-\s]*(?:api[_\-\s]*)?token\s*[:=]\s*[\"']?([a-f0-9]{32,})",
       "HIGH",
       "Jenkins user API token"),

    _p("Terraform Cloud Token",
       r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{60,}",
       "CRITICAL",
       "Terraform Cloud / Atlas token"),

    _p("Ansible Vault Password",
       r"\$ANSIBLE_VAULT;[0-9]+\.[0-9]+;AES256",
       "CRITICAL",
       "Ansible Vault encrypted secret"),

    _p("Pulumi Access Token",
       r"pul-[a-zA-Z0-9]{40}",
       "HIGH",
       "Pulumi cloud access token"),

    _p("JFrog API Key",
       r"(?i)jfrog[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*[\"']?([a-zA-Z0-9]{73})",
       "HIGH",
       "JFrog Artifactory API key"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 🌐  GENERIC / CATCH-ALL SECRETS
# ─────────────────────────────────────────────────────────────────────────────
GENERIC_PATTERNS: list[SecretPattern] = [
    _p("Generic API Key Assignment",
       r"""(?i)api[_\-\s]*key\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]""",
       "MEDIUM",
       "Generic API key in config or code"),

    _p("Generic Secret Assignment",
       r"""(?i)(?:secret|private[_\-\s]*key)\s*[:=]\s*['"]([a-zA-Z0-9_\-\/+]{16,})['"]""",
       "MEDIUM",
       "Generic secret value in code"),

    _p("Generic Password Assignment",
       r"""(?i)password\s*[:=]\s*['"]([^'"]{8,})['"]""",
       "MEDIUM",
       "Generic password in code"),

    _p("Generic Token Assignment",
       r"""(?i)token\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]""",
       "LOW",
       "Generic token variable"),

    _p("Private Key PEM Content",
       r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----[\s\S]{50,}-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----",
       "CRITICAL",
       "Full PEM private key block"),

    _p(".env File Secret Line",
       r"""^(?!#)[A-Z][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL)\s*=\s*.{8,}""",
       "HIGH",
       "Secret-looking .env variable"),

    _p("Base64 Encoded Secret (long)",
       r"(?<![a-zA-Z0-9+/])[a-zA-Z0-9+/]{60,}={0,2}(?![a-zA-Z0-9+/=])",
       "LOW",
       "Long Base64 string (possible encoded credential)"),

    _p("URL with Embedded Credentials",
       r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+:[^@\s]{6,}@[^\s/]+",
       "CRITICAL",
       "URL with username:password embedded"),

    _p("Bearer Token in Code",
       r"""(?i)authorization\s*[:=]\s*['"]?bearer\s+([a-zA-Z0-9_\-\.]{20,})['"]?""",
       "HIGH",
       "Hardcoded Bearer auth header"),

    _p("Basic Auth in Code",
       r"""(?i)authorization\s*[:=]\s*['"]?basic\s+([a-zA-Z0-9+/=]{20,})['"]?""",
       "HIGH",
       "Hardcoded Basic auth header"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 📋  MASTER LIST (all patterns combined)
# ─────────────────────────────────────────────────────────────────────────────
ALL_PATTERNS: list[SecretPattern] = (
    AI_PATTERNS
    + CLOUD_PATTERNS
    + SSH_KEY_PATTERNS
    + PAYMENT_PATTERNS
    + DATABASE_PATTERNS
    + AUTH_PATTERNS
    + COMMUNICATION_PATTERNS
    + DEVOPS_PATTERNS
    + GENERIC_PATTERNS
)


# ─────────────────────────────────────────────────────────────────────────────
# 🔴  HIGH-RISK FILENAMES (always prioritised for scanning)
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_FILENAMES: set[str] = {
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.backup", ".env.example",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_rsa.pub",  # sometimes paired with private key leak
    "credentials", "credentials.json", "credentials.yaml",
    "secrets.json", "secrets.yaml", "secrets.toml",
    "config.json", "config.yaml", "config.toml",
    "settings.py", "settings.json",
    "firebase.json", "google-services.json", "GoogleService-Info.plist",
    "serviceAccount.json", "service-account.json",
    "keystore.jks", "keystore.p12",
    "wp-config.php", "database.php", "database.yml",
    ".aws/credentials", ".aws/config",
    ".netrc", ".npmrc", ".pypirc", ".gem/credentials",
    "terraform.tfvars", "terraform.tfstate",
    "docker-compose.yml", "docker-compose.yaml",  # may contain env secrets
}

SENSITIVE_EXTENSIONS: set[str] = {
    ".pem", ".key", ".p12", ".pfx", ".ppk", ".jks",
    ".env", ".secret", ".secrets", ".credential", ".credentials",
}
