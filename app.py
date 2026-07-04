"""
Subscription & Licensing Platform
Complete Flask Application with Wix Integration, Stripe Integration, OTP Auth, 
License Management, Discord Integration & ThinkHuge VPS Auto-Provisioning

ACCOUNT SLOT LOGIC:
- Each UNIQUE MT5 account number = 1 slot
- Multiple EAs on same MT5 account share 1 slot
- Slot freed only when ALL EAs on that account are removed
- Heartbeat auto-cleanup for crashed EAs (fully automatic)

FIXED: Proper MT5 account tracking with unique account_number
FIXED: Unlimited validations (max_validations=None skips the check)
FIXED: Heartbeats no longer increment validation_count
FIXED: Cancellation = stop auto-renewal, user keeps full access until paid period ends
ADDED: Language toggle support (English/Nederlands)
ADDED: "Need Help?" Contact Us support section
ADDED: ThinkHuge VPS auto-provisioning on payment (Basic plan for all levels)
ADDED: VPS auto-termination on membership expiry
ADDED: VPS details sent after license generation (correct language)
ADDED: VPS details display on user dashboard
FIXED: ThinkHuge API calls were being blocked by Cloudflare with
       "Error 1010: browser_signature_banned" because urllib's default
       User-Agent ("Python-urllib/3.x") is flagged as a bot by Cloudflare's
       bot-management rules. All ThinkHuge requests now send a real
       browser-like User-Agent (and related headers) to pass the check.
ADDED: Background retry/backfill sweep that automatically re-attempts VPS
       provisioning for any paid, active user who doesn't yet have a VPS
       (e.g. because a previous provisioning attempt failed).
"""

import os
import re
import json
import hashlib
import secrets
import logging
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, flash, send_from_directory, abort, make_response,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user,
)
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv

try:
    import stripe
except ImportError:
    stripe = None

load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///licensing.db")
    if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp-relay.brevo.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "noreply@tradingengine.nl")

    WIX_WEBHOOK_SECRET = os.getenv("WIX_WEBHOOK_SECRET", "")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
    DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "")
    DISCORD_ROLE_ID = os.getenv("DISCORD_ROLE_ID", "")
    DISCORD_INVITE_LINK = os.getenv("DISCORD_INVITE_LINK", "")
    DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
    DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
    DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "")

    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
    RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "memory://")

    APP_URL = os.getenv("APP_URL", "http://localhost:5000")
    OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", 10))
    ADMIN_OTP_EXPIRY_MINUTES = 5
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
    LICENSE_EXPIRY_DAYS = int(os.getenv("LICENSE_EXPIRY_DAYS", 365))
    DEFAULT_SUBSCRIPTION_DURATION_DAYS = int(os.getenv("DEFAULT_SUBSCRIPTION_DURATION_DAYS", 365))
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))

    HEARTBEAT_TIMEOUT_MINUTES = int(os.getenv("HEARTBEAT_TIMEOUT_MINUTES", 10))

    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    LANGUAGES = {
        'en': 'English',
        'nl': 'Nederlands'
    }

    # ThinkHuge VPS API Configuration
    # Base URL + "/servers", "/users", "/locations", "/os_templates", "/plans"
    # map to their documented "/v1/..." paths (confirmed against ThinkHuge's
    # Partners Portal OpenAPI export).
    FOREXVPS_API_URL = os.getenv("FOREXVPS_API_URL", "https://api.partners.thinkhuge.net/api/v1")
    FOREXVPS_API_KEY = os.getenv("FOREXVPS_API_KEY", "")

    # Plan *names* to search for per membership level (matched against
    # GET /v1/plans "name" field to resolve the numeric plan_id ThinkHuge
    # actually requires). Override with an exact numeric ID via
    # FOREXVPS_PLAN_ID_LEVEL{n} if you already know it, to skip the lookup.
    FOREXVPS_PLANS = {
        1: os.getenv("FOREXVPS_PLAN_LEVEL1", "Basic"),
        2: os.getenv("FOREXVPS_PLAN_LEVEL2", "Basic"),
        3: os.getenv("FOREXVPS_PLAN_LEVEL3", "Basic"),
    }
    FOREXVPS_PLAN_ID_OVERRIDES = {
        1: os.getenv("FOREXVPS_PLAN_ID_LEVEL1", "").strip() or None,
        2: os.getenv("FOREXVPS_PLAN_ID_LEVEL2", "").strip() or None,
        3: os.getenv("FOREXVPS_PLAN_ID_LEVEL3", "").strip() or None,
    }

    # Location (data center) to provision in. If FOREXVPS_LOCATION_ID is set,
    # it's used directly (no API lookup). Otherwise we search GET /v1/locations
    # by name using FOREXVPS_LOCATION_SEARCH, falling back to the first
    # location returned if the search string is empty or matches nothing.
    FOREXVPS_LOCATION_ID = os.getenv("FOREXVPS_LOCATION_ID", "").strip() or None
    FOREXVPS_LOCATION_SEARCH = os.getenv("FOREXVPS_LOCATION_SEARCH", "").strip()

    # OS template to install. Same override pattern as location.
    # os_template_id is a string/UUID per ThinkHuge's schema, not an integer.
    FOREXVPS_OS_TEMPLATE_ID = os.getenv("FOREXVPS_OS_TEMPLATE_ID", "").strip() or None
    FOREXVPS_OS_TEMPLATE_SEARCH = os.getenv("FOREXVPS_OS_TEMPLATE_SEARCH", "Windows 2022").strip()

    # How often (seconds) the background job retries provisioning for users
    # who paid but don't have a VPS yet (e.g. a previous attempt was blocked
    # by Cloudflare, ThinkHuge was briefly down, etc.) and how often it polls
    # servers that are still provisioning (no IP/password yet).
    FOREXVPS_RETRY_INTERVAL_SECONDS = int(os.getenv("FOREXVPS_RETRY_INTERVAL_SECONDS", 600))
    # Give up automatic retries after this many minutes so we don't hammer a
    # permanently failing account forever; visible to admins via vps_status.
    FOREXVPS_RETRY_MAX_AGE_MINUTES = int(os.getenv("FOREXVPS_RETRY_MAX_AGE_MINUTES", 1440))

    @staticmethod
    def is_railway():
        return bool(os.getenv("RAILWAY_STATIC_URL"))


app = Flask(__name__)
app.config.from_object(Config)

if Config.is_railway():
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "user_login"
login_manager.login_message = "Log in om deze pagina te bekijken."
CORS(app, supports_credentials=True)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=Config.RATELIMIT_STORAGE_URL
)

try:
    if Config.ENCRYPTION_KEY:
        encryption_key = Config.ENCRYPTION_KEY.encode() if isinstance(Config.ENCRYPTION_KEY, str) else Config.ENCRYPTION_KEY
        cipher_suite = Fernet(encryption_key)
    else:
        encryption_key = Fernet.generate_key()
        cipher_suite = Fernet(encryption_key)
except Exception:
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)

Path(Config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

logger.info("=" * 80)
logger.info("APPLICATION STARTING - MT5 ACCOUNT SLOT TRACKING + THINKHUGE VPS")
logger.info("=" * 80)


# ============================================================================
# LANGUAGE HELPER
# ============================================================================

def get_user_language():
    """Get the user's preferred language"""
    if 'language' in session:
        return session['language']
    if current_user.is_authenticated and hasattr(current_user, 'language_preference'):
        if current_user.language_preference in Config.LANGUAGES:
            return current_user.language_preference
    browser_lang = request.accept_languages.best_match(Config.LANGUAGES.keys()) if request else 'en'
    return browser_lang or 'en'


@app.context_processor
def inject_globals():
    """Make variables available to all templates"""
    return {
        'current_language': get_user_language(),
        'supported_languages': Config.LANGUAGES
    }


# ============================================================================
# MODELS
# ============================================================================


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    wix_contact_id = db.Column(db.String(100), nullable=True)
    wix_payment_id = db.Column(db.String(100), unique=True, nullable=True)
    wix_order_id = db.Column(db.String(100), nullable=True)
    membership_status = db.Column(db.String(20), default="pending", index=True)
    membership_start = db.Column(db.DateTime, nullable=True)
    membership_end = db.Column(db.DateTime, nullable=True)
    subscription_duration_days = db.Column(db.Integer, nullable=True)
    plan_name = db.Column(db.String(100), nullable=True)
    plan_price = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    subscription_type = db.Column(db.String(50), nullable=True)
    discord_user_id = db.Column(db.String(100), nullable=True)
    discord_joined = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    language_preference = db.Column(db.String(5), default='en')

    # ThinkHuge VPS fields
    vps_id = db.Column(db.String(100), nullable=True)
    vps_status = db.Column(db.String(20), nullable=True)
    vps_ip = db.Column(db.String(50), nullable=True)
    vps_username = db.Column(db.String(50), nullable=True)
    vps_password = db.Column(db.String(200), nullable=True)
    vps_plan = db.Column(db.String(50), nullable=True)
    vps_created_at = db.Column(db.DateTime, nullable=True)
    vps_terminated_at = db.Column(db.DateTime, nullable=True)
    vps_last_attempt_at = db.Column(db.DateTime, nullable=True)
    vps_last_error = db.Column(db.String(300), nullable=True)
    # The ThinkHuge "User" record UUID this customer maps to (ThinkHuge
    # requires servers to be created under a ThinkHuge user_id, separate
    # from this app's own user id). Looked up/created once and cached here.
    thinkhuge_user_id = db.Column(db.String(100), nullable=True)

    otp_tokens = db.relationship("OTPToken", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    licenses = db.relationship("License", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def is_membership_active(self):
        """Check if membership is currently active (not expired).
        Both 'active' and 'cancelled' status allow access until membership_end."""
        if self.membership_status not in ["active", "cancelled"]:
            return False
        if self.membership_end and self.membership_end < datetime.utcnow():
            self.membership_status = "expired"
            db.session.commit()
            return False
        return True

    def get_active_license(self):
        return self.licenses.filter_by(status="active").first()

    def get_full_name(self):
        if self.first_name and self.last_name: return f"{self.first_name} {self.last_name}"
        elif self.first_name: return self.first_name
        return self.email

    def get_plan_level(self):
        if not self.plan_name:
            return 1
        match = re.search(r'level\s*(\d+)', self.plan_name.lower())
        if match:
            return int(match.group(1))
        plan_lower = self.plan_name.lower()
        if any(word in plan_lower for word in ['starter', 'basic', 'beginner', 'standard']):
            return 1
        elif any(word in plan_lower for word in ['pro', 'advanced', 'intermediate', 'monthly']):
            return 2
        elif any(word in plan_lower for word in ['elite', 'vip', 'premium', 'expert']):
            return 3
        return 1

    def get_membership_duration_display(self):
        if not self.subscription_duration_days: return "Default"
        if self.subscription_type == "lifetime": return "Lifetime"
        if self.subscription_duration_days >= 365: return f"{self.subscription_duration_days / 365:.0f} Year"
        if self.subscription_duration_days >= 30: return f"{self.subscription_duration_days / 30:.0f} Month"
        return f"{self.subscription_duration_days} Days"

    def get_subscription_type_display(self, lang='en'):
        if not self.subscription_type:
            return "Standaard" if lang == 'nl' else "Standard"
        translations = {
            'lifetime': {'en': 'Lifetime', 'nl': 'Levenslang'},
            'monthly': {'en': 'Monthly', 'nl': 'Maandelijks'},
            'yearly': {'en': 'Yearly', 'nl': 'Jaarlijks'},
            'standard': {'en': 'Standard', 'nl': 'Standaard'}
        }
        return translations.get(self.subscription_type.lower(), {}).get(lang, self.subscription_type.title())

    def get_status_display(self, lang='en'):
        translations = {
            'active': {'en': 'ACTIVE', 'nl': 'ACTIEF'},
            'cancelled': {'en': 'CANCELLED', 'nl': 'GEANNULEERD'},
            'expired': {'en': 'EXPIRED', 'nl': 'VERLOPEN'},
            'pending': {'en': 'PENDING', 'nl': 'IN AFWACHTING'},
            'revoked': {'en': 'REVOKED', 'nl': 'INGETROKKEN'}
        }
        return translations.get(self.membership_status, {}).get(lang, self.membership_status.upper())

    def to_dict(self):
        return {
            "id": self.id, "email": self.email, "first_name": self.first_name,
            "last_name": self.last_name, "full_name": self.get_full_name(),
            "plan_level": self.get_plan_level(), "membership_status": self.membership_status,
            "plan_name": self.plan_name, "subscription_type": self.subscription_type,
            "is_active": self.is_membership_active(),
            "language_preference": self.language_preference
        }


class OTPToken(db.Model):
    __tablename__ = "otp_tokens"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)
    purpose = db.Column(db.String(50), default="login")

    def is_valid(self):
        return not self.used and self.expires_at > datetime.utcnow() and self.attempts < 3


class License(db.Model):
    __tablename__ = "licenses"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    license_key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    machine_id = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), default="active", index=True)
    license_type = db.Column(db.String(50), default="standard")
    max_accounts = db.Column(db.Integer, default=2)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_validated = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    validation_count = db.Column(db.Integer, default=0)
    max_validations = db.Column(db.Integer, nullable=True, default=None)
    ea_version = db.Column(db.String(20), nullable=True)

    accounts = db.relationship("LicenseAccount", backref="license", lazy="dynamic", cascade="all, delete-orphan")

    def is_valid(self):
        if self.status != "active":
            return False
        if self.expires_at < datetime.utcnow():
            self.status = "expired"
            db.session.commit()
            return False
        if self.max_validations is not None and self.validation_count >= self.max_validations:
            return False
        return True

    def mask_license_key(self):
        if len(self.license_key) > 8:
            return f"{self.license_key[:4]}...{self.license_key[-4:]}"
        return self.license_key


class LicenseAccount(db.Model):
    """
    Represents ONE MT5 account slot under a license.
    Multiple EAs on the same MT5 account share ONE slot.
    Slot count = number of LicenseAccount rows for the license.
    """
    __tablename__ = "license_accounts"
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    activated_at = db.Column(db.DateTime, default=datetime.utcnow)

    sessions = db.relationship("EASession", backref="license_account", lazy="dynamic", cascade="all, delete-orphan")


class EASession(db.Model):
    """
    Represents ONE EA instance running on an MT5 account.
    Multiple EASessions can exist per LicenseAccount.
    Slot freed only when ALL EASessions for an account are removed.
    """
    __tablename__ = "ea_sessions"
    id = db.Column(db.Integer, primary_key=True)
    license_account_id = db.Column(db.Integer, db.ForeignKey("license_accounts.id"), nullable=False)
    session_id = db.Column(db.String(100), nullable=False, index=True)
    symbol = db.Column(db.String(20), nullable=True)
    magic_number = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("license_account_id", "session_id", name="uq_account_session"),
    )


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    wix_order_id = db.Column(db.String(100), unique=True, nullable=True)
    wix_payment_id = db.Column(db.String(100), nullable=True)
    plan_name = db.Column(db.String(200), nullable=True)
    plan_price = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    total_amount = db.Column(db.Float, nullable=True)
    subscription_type = db.Column(db.String(50), nullable=True)
    subscription_duration_days = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default="completed")
    payment_status = db.Column(db.String(20), default="paid")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    raw_data = db.Column(db.Text, nullable=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref="audit_logs")


class EAFile(db.Model):
    __tablename__ = "ea_files"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    description = db.Column(db.Text, nullable=True)
    changelog = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_beta = db.Column(db.Boolean, default=False)
    plan_level = db.Column(db.Integer, default=1)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    download_count = db.Column(db.Integer, default=0)
    checksum = db.Column(db.String(64), nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class Setting(db.Model):
    __tablename__ = "settings"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================================================
# THINKHUGE VPS API CLIENT
# ============================================================================

class ForexVPSClient:
    """
    Client for ThinkHuge.net API.

    NOTE ON THE CLOUDFLARE 403 FIX:
    ThinkHuge's API sits behind Cloudflare, and Cloudflare's bot-management
    rules will return "Error 1010: browser_signature_banned" for requests
    whose User-Agent looks like a script (urllib's default is literally
    "Python-urllib/3.x", which is a textbook bot signature). That 403 is
    what was silently preventing every VPS from being provisioned. The fix
    is simply to send headers that look like a normal browser request.
    """

    # A realistic desktop browser User-Agent. Cloudflare mainly cares that
    # this doesn't look like a bare script/HTTP-library default.
    BROWSER_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self):
        self.api_url = Config.FOREXVPS_API_URL.rstrip('/')
        self.api_key = Config.FOREXVPS_API_KEY
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': self.BROWSER_USER_AGENT,
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }

    def is_configured(self):
        """Check if ThinkHuge API is configured"""
        return bool(self.api_key)

    def _request(self, path, method="GET", payload=None, timeout=120):
        """Shared request helper so every call gets the same anti-Cloudflare headers."""
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            headers=self.headers,
            method=method
        )
        return urllib.request.urlopen(req, timeout=timeout)

    @staticmethod
    def _error_detail(e):
        """Extract ThinkHuge's JSON error body (message + per-field errors) from an HTTPError."""
        try:
            body = e.read().decode()
        except Exception:
            return str(e)
        try:
            parsed = json.loads(body)
            msg = parsed.get("message", body)
            errors = parsed.get("errors")
            if errors:
                msg += " | " + json.dumps(errors)
            return msg
        except Exception:
            return body

    # ------------------------------------------------------------------
    # Lookup helpers (Location / OsTemplate / Plan / User)
    #
    # ThinkHuge's /v1/servers endpoint requires numeric/UUID IDs, not the
    # names our config historically stored. These helpers resolve real IDs
    # by calling ThinkHuge's list endpoints and matching by name, with
    # in-memory caching (values rarely change) and env-var overrides so an
    # admin who already knows the exact ID can skip the lookup entirely.
    # ------------------------------------------------------------------

    def _list(self, path, search=None, per_page=100):
        query = f"?per_page={per_page}"
        if search:
            query += f"&filter[search]={urllib.parse.quote(search)}"
        response = self._request(f"{path}{query}", method="GET", timeout=30)
        result = json.loads(response.read())
        return result.get("data", [])

    def list_locations(self, search=None):
        return self._list("/locations", search=search)

    def list_os_templates(self, search=None):
        return self._list("/os_templates", search=search)

    def list_plans(self, search=None):
        return self._list("/plans", search=search)

    def find_location_id(self):
        if Config.FOREXVPS_LOCATION_ID:
            return Config.FOREXVPS_LOCATION_ID
        if getattr(self, "_location_id_cache", None):
            return self._location_id_cache
        locations = self.list_locations(search=Config.FOREXVPS_LOCATION_SEARCH or None)
        if not locations:
            # Search matched nothing - fall back to the unfiltered list.
            locations = self.list_locations()
        if not locations:
            raise ValueError("No ThinkHuge locations available from /v1/locations")
        self._location_id_cache = locations[0]["id"]
        logger.info(f"[ThinkHuge] Resolved location_id={self._location_id_cache} ({locations[0].get('name')})")
        return self._location_id_cache

    def find_os_template_id(self):
        if Config.FOREXVPS_OS_TEMPLATE_ID:
            return Config.FOREXVPS_OS_TEMPLATE_ID
        if getattr(self, "_os_template_id_cache", None):
            return self._os_template_id_cache
        templates = self.list_os_templates(search=Config.FOREXVPS_OS_TEMPLATE_SEARCH or None)
        if not templates:
            templates = self.list_os_templates()
        if not templates:
            raise ValueError("No ThinkHuge OS templates available from /v1/os_templates")
        self._os_template_id_cache = templates[0]["id"]
        logger.info(f"[ThinkHuge] Resolved os_template_id={self._os_template_id_cache} ({templates[0].get('name')})")
        return self._os_template_id_cache

    def find_plan_id(self, plan_level):
        override = Config.FOREXVPS_PLAN_ID_OVERRIDES.get(plan_level)
        if override:
            return override
        cache = getattr(self, "_plan_id_cache", None) or {}
        if plan_level in cache:
            return cache[plan_level]
        search_name = Config.FOREXVPS_PLANS.get(plan_level, "Basic")
        plans = self.list_plans(search=search_name)
        if not plans:
            plans = self.list_plans()
        if not plans:
            raise ValueError("No ThinkHuge plans available from /v1/plans")
        plan_id = plans[0]["id"]
        cache[plan_level] = plan_id
        self._plan_id_cache = cache
        logger.info(f"[ThinkHuge] Resolved plan_id={plan_id} for level={plan_level} ({plans[0].get('name')})")
        return plan_id

    def get_or_create_user_id(self, email, name=""):
        """
        ThinkHuge servers are created under a ThinkHuge User record, which
        is a different concept from this app's own User model. Look up an
        existing ThinkHuge user by email first (GET /v1/users?filter[email]=),
        and only create one (POST /v1/users) if none exists yet.
        """
        query = f"?filter[email]={urllib.parse.quote(email)}"
        response = self._request(f"/users{query}", method="GET", timeout=30)
        result = json.loads(response.read())
        existing = result.get("data", [])
        if existing:
            return existing[0]["id"]

        # No documented request body for POST /v1/users in ThinkHuge's spec -
        # send the fields UserResource exposes as user-settable and let any
        # 422 tell us precisely what's still missing (same as /servers did).
        username = re.sub(r'[^a-zA-Z0-9_.-]', '', email.split('@')[0])[:30] or f"user{secrets.token_hex(4)}"
        payload = {
            "username": username,
            "name": name or username,
            "email": email,
        }
        response = self._request("/users", method="POST", payload=payload, timeout=30)
        result = json.loads(response.read())
        return result["data"]["id"]

    def create_server(self, user_id, location_id, os_template_id, plan_id, hostname):
        payload = {
            "user_id": user_id,
            "location_id": location_id,
            "os_template_id": os_template_id,
            "plan_id": plan_id,
            "hostname": hostname[:50],
        }
        response = self._request("/servers", method="POST", payload=payload, timeout=120)
        result = json.loads(response.read())
        return result["data"]

    def get_server(self, server_id):
        response = self._request(f"/servers/{server_id}", method="GET", timeout=30)
        result = json.loads(response.read())
        return result["data"]

    def reset_password(self, server_id):
        """POST /v1/servers/{server}/reset-password -> {"password": "..."} (no 'data' wrapper)."""
        response = self._request(f"/servers/{server_id}/reset-password", method="POST", timeout=60)
        result = json.loads(response.read())
        return result["password"]

    def create_vps(self, plan_level, email, name="", hostname=""):
        """
        Create a new VPS server for a client.

        Orchestrates the full ThinkHuge flow: resolve/create the ThinkHuge
        user, resolve location/os_template/plan IDs, then create the server.
        Provisioning is asynchronous on ThinkHuge's side - primary_ip_address
        may still be null in the response, in which case the caller should
        treat this as "pending" and poll get_server() later rather than
        expecting a password immediately (there's no password in the create
        response at all - it must be fetched via reset_password()).

        Returns a dict describing the outcome; never raises.
        """
        if not self.is_configured():
            logger.warning("[ThinkHuge] API not configured, skipping VPS creation")
            return {"success": False, "error": "API not configured"}

        try:
            logger.info(f"[ThinkHuge] Resolving user/location/os_template/plan for {email}")
            user_id = self.get_or_create_user_id(email, name)
            location_id = self.find_location_id()
            os_template_id = self.find_os_template_id()
            plan_id = self.find_plan_id(plan_level)

            logger.info(
                f"[ThinkHuge] Creating server: email={email} user_id={user_id} "
                f"location_id={location_id} os_template_id={os_template_id} plan_id={plan_id}"
            )

            server = self.create_server(
                user_id=user_id,
                location_id=location_id,
                os_template_id=os_template_id,
                plan_id=plan_id,
                hostname=hostname or f"te-{email.split('@')[0]}",
            )

            server_id = server.get("id")
            ip = server.get("primary_ip_address")
            provision_status = server.get("provision_status", "pending")

            password = None
            if ip:
                # Server appears ready already - fetch its password now.
                try:
                    password = self.reset_password(server_id)
                except Exception as e:
                    logger.warning(f"[ThinkHuge] Server {server_id} has an IP but password fetch failed: {e}")

            return {
                "success": True,
                "server_id": server_id,
                "user_id": user_id,
                "ip": ip,
                "username": "Administrator",
                "password": password,
                "status": provision_status,
                "ready": bool(ip and password),
            }

        except urllib.error.HTTPError as e:
            error_detail = self._error_detail(e)
            logger.error(f"[ThinkHuge] API error creating VPS: {e.code} - {error_detail}")
            return {"success": False, "error": f"API error: {e.code} - {error_detail}"}
        except Exception as e:
            logger.error(f"[ThinkHuge] Error creating VPS: {e}")
            return {"success": False, "error": str(e)}

    def terminate_vps(self, server_id):
        """Terminate/delete a VPS server"""
        if not self.is_configured():
            return {"success": False, "error": "API not configured"}

        try:
            logger.info(f"[ThinkHuge] Terminating VPS: {server_id}")

            self._request(f"/servers/{server_id}", method="DELETE", timeout=30)

            logger.info(f"[ThinkHuge] VPS termination successful: {server_id}")
            return {"success": True}

        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.warning(f"[ThinkHuge] VPS {server_id} already terminated")
                return {"success": True}
            logger.error(f"[ThinkHuge] Error terminating VPS {server_id}: {e.code}")
            return {"success": False, "error": f"API error: {e.code}"}
        except Exception as e:
            logger.error(f"[ThinkHuge] Error terminating VPS {server_id}: {e}")
            return {"success": False, "error": str(e)}


forexvps_client = ForexVPSClient()


# ============================================================================
# HELPERS
# ============================================================================

def encrypt_data(data):
    if not data:
        return None
    try: return cipher_suite.encrypt(data.encode()).decode()
    except: return data

def decrypt_data(data):
    if not data:
        return None
    try: return cipher_suite.decrypt(data.encode()).decode()
    except: return data

def generate_license_key():
    return "-".join([secrets.token_hex(2).upper() for _ in range(3)])

def generate_otp():
    return "".join([str(secrets.randbelow(10)) for _ in range(6)])

def parse_duration_to_days(duration_str):
    if not duration_str:
        return Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS, "one_time"
    d = duration_str.lower().strip()
    if "month" in d or "maand" in d:
        m = re.findall(r'\d+', d)
        return (int(m[0]) * 30 if m else 30), "monthly"
    elif "year" in d or "jaar" in d:
        y = re.findall(r'\d+', d)
        return (int(y[0]) * 365 if y else 365), "yearly"
    elif "lifetime" in d or "levenslang" in d or "annulering" in d:
        return 36500, "lifetime"
    return Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS, "one_time"

def parse_wix_date(date_str):
    if not date_str: return None
    if "annulering" in date_str.lower(): return None
    for fmt in ["%d-%m-%Y", "%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y", "%m-%d-%Y"]:
        try: return datetime.strptime(date_str.strip(), fmt)
        except: continue
    return None

def send_email_async(subject, recipients, body, html_body=None):
    def send():
        try:
            with app.app_context():
                msg = Message(subject=subject, recipients=recipients, body=body, html=html_body)
                mail.send(msg)
                logger.info(f"[EMAIL] Sent to {recipients}: {subject}")
        except Exception as e:
            logger.error(f"[EMAIL] Failed: {e}")
    threading.Thread(target=send).start()

def log_audit(user_id, action, details=None, ip_address=None):
    try:
        log = AuditLog(
            user_id=user_id, action=action, details=details,
            ip_address=ip_address or (request.remote_addr if request else "system")
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"[AUDIT] Failed: {e}")

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"ex4", "ex5", "dll", "zip"}

def get_max_accounts_for_level(plan_level):
    """Determine max MT5 accounts based on plan level"""
    if plan_level <= 1:
        return 2
    elif plan_level == 2:
        return 4
    elif plan_level == 3:
        return 8
    else:
        return 10

def get_plan_level_display(plan_level):
    level_names = {1: "LVL 1", 2: "LVL 2", 3: "LVL 3", 4: "PREMIUM"}
    return level_names.get(plan_level, f"LVL {plan_level}")

def format_date_dutch(date_obj):
    """Format a date in Dutch: '31 oktober 2026'"""
    if not date_obj:
        return "N/B"
    months_nl = [
        "januari", "februari", "maart", "april", "mei", "juni",
        "juli", "augustus", "september", "oktober", "november", "december"
    ]
    return f"{date_obj.day} {months_nl[date_obj.month - 1]} {date_obj.year}"

def format_date_english(date_obj):
    """Format a date in English: 'October 31, 2026'"""
    if not date_obj:
        return "N/A"
    return date_obj.strftime("%B %d, %Y")


# ============================================================================
# VPS PROVISIONING FUNCTIONS
# ============================================================================

def provision_vps_for_user(user, plan_level):
    """
    Provision a VPS for a user based on their plan level.
    Creates the VPS but does NOT send the welcome email.
    The welcome email is sent after license generation when language is known
    (and only once the VPS is actually ready - see send_vps_welcome_email callers).

    Returns True if a VPS now exists and is ready (has IP + password).
    Returns False if provisioning failed OR if the server was created but is
    still provisioning on ThinkHuge's side (status will be 'provisioning' and
    the background poll_pending_vps_servers() job will finish setting it up).

    Every attempt (success or failure) stamps vps_last_attempt_at so the
    background retry sweep knows when it last tried and can back off /
    give up appropriately. Failures also record vps_last_error for admins.
    """
    if not forexvps_client.is_configured():
        logger.info(f"[ThinkHuge] Skipping VPS provisioning - API not configured")
        return False

    if user.vps_id and user.vps_status == 'active':
        logger.info(f"[ThinkHuge] User {user.email} already has active VPS: {user.vps_id}")
        return True

    if user.vps_id and user.vps_status == 'provisioning':
        # Already created, just not ready yet - let the poller handle it.
        logger.info(f"[ThinkHuge] User {user.email} VPS {user.vps_id} already provisioning, not re-creating")
        return False

    vps_plan_name = Config.FOREXVPS_PLANS.get(plan_level, "Basic")

    logger.info(f"[ThinkHuge] Provisioning VPS for {user.email} | plan={vps_plan_name} | level={plan_level}")

    result = forexvps_client.create_vps(
        plan_level=plan_level,
        email=user.email,
        name=user.get_full_name(),
        hostname=f"te-{user.id}",
    )

    user.vps_last_attempt_at = datetime.utcnow()

    if not result.get('success'):
        error_msg = str(result.get('error'))[:300]
        user.vps_last_error = error_msg
        db.session.commit()
        logger.error(f"[ThinkHuge] ❌ Failed to provision VPS for {user.email}: {result.get('error')}")
        return False

    user.vps_id = result.get('server_id')
    user.thinkhuge_user_id = result.get('user_id') or user.thinkhuge_user_id
    user.vps_plan = vps_plan_name
    user.vps_created_at = datetime.utcnow()
    user.vps_last_error = None

    if result.get('ready'):
        user.vps_status = 'active'
        user.vps_ip = result.get('ip')
        user.vps_username = result.get('username')
        user.vps_password = encrypt_data(result.get('password', ''))
        db.session.commit()
        logger.info(f"[ThinkHuge] ✅ VPS provisioned and ready for {user.email}: {user.vps_id} | IP: {user.vps_ip}")
        return True
    else:
        # Server created but ThinkHuge is still provisioning it (no IP yet).
        # poll_pending_vps_servers() will pick this up and finish the job.
        user.vps_status = 'provisioning'
        db.session.commit()
        logger.info(
            f"[ThinkHuge] ⏳ VPS creation started for {user.email}: {user.vps_id} "
            f"(status={result.get('status')}) - still provisioning, will poll for IP/password"
        )
        return False


def poll_pending_vps_servers():
    """
    Check on servers that were created but hadn't finished provisioning yet
    (no primary_ip_address / password at creation time). Once ThinkHuge
    reports an IP, fetch the password and mark the VPS active - then send
    the welcome email if the user already has a license (mirroring the
    normal post-license-generation flow).
    """
    if not forexvps_client.is_configured():
        return

    try:
        pending_users = User.query.filter(
            User.vps_status == 'provisioning',
            User.vps_id.isnot(None),
        ).all()

        if not pending_users:
            return

        logger.info(f"[ThinkHuge] 🔎 Polling {len(pending_users)} pending VPS server(s)")

        for user in pending_users:
            try:
                server = forexvps_client.get_server(user.vps_id)
                ip = server.get("primary_ip_address")

                if not ip:
                    logger.info(f"[ThinkHuge] {user.email}: server {user.vps_id} still has no IP yet")
                    continue

                password = forexvps_client.reset_password(user.vps_id)

                user.vps_ip = ip
                user.vps_username = "Administrator"
                user.vps_password = encrypt_data(password)
                user.vps_status = 'active'
                user.vps_last_error = None
                db.session.commit()

                logger.info(f"[ThinkHuge] ✅ VPS now ready for {user.email}: {user.vps_id} | IP: {ip}")

                if user.get_active_license():
                    send_vps_welcome_email(user)

            except urllib.error.HTTPError as e:
                logger.warning(f"[ThinkHuge] Poll failed for {user.email} ({user.vps_id}): {e.code}")
            except Exception as e:
                logger.warning(f"[ThinkHuge] Poll error for {user.email} ({user.vps_id}): {e}")

    except Exception as e:
        logger.error(f"[ThinkHuge] Error in poll_pending_vps_servers: {e}")
        db.session.rollback()


def send_vps_welcome_email(user):
    """
    Send VPS login details to user.
    Called after license generation when user's language preference is known.
    """
    lang = get_user_language()
    vps_password = decrypt_data(user.vps_password)
    
    if lang == 'nl':
        subject = "Je Forex VPS is klaar! - Trading Engine"
        body_plain = f"""
Beste {user.first_name or 'handelaar'},

Je Forex VPS is succesvol aangemaakt en klaar voor gebruik!

=== VPS LOGIN GEGEVENS ===
IP Adres: {user.vps_ip or 'Wordt binnen enkele minuten verzonden'}
Gebruikersnaam: {user.vps_username or 'Wordt binnen enkele minuten verzonden'}
Wachtwoord: {vps_password or 'Wordt binnen enkele minuten verzonden'}

=== BELANGRIJKE INFORMATIE ===
• De VPS is 24/7 actief zolang je abonnement loopt
• Je kunt direct inloggen via Windows Remote Desktop (RDP)
• Installeer MetaTrader en je Expert Advisors op de VPS
• Bij vragen, neem contact op via support@tradingengine.nl

Je VPS blijft actief zolang je abonnement loopt.

Met vriendelijke groet,
Het Trading Engine Team
"""
        body_html = f"""
<div style="font-family: 'Inter', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2 style="color: #0b121a;">🎉 Je Forex VPS is klaar!</h2>
    <p>Beste <strong>{user.first_name or 'handelaar'}</strong>,</p>
    <p>Je Forex VPS is succesvol aangemaakt en klaar voor gebruik!</p>
    
    <div style="background-color: #f7f9fc; border: 1px solid #e6eaef; border-radius: 12px; padding: 16px; margin: 20px 0;">
        <h3 style="margin: 0 0 10px; color: #0b121a;">🔐 VPS Login Gegevens</h3>
        <p style="margin: 4px 0;"><strong>IP Adres:</strong> <code>{user.vps_ip or 'Wordt binnen enkele minuten verzonden'}</code></p>
        <p style="margin: 4px 0;"><strong>Gebruikersnaam:</strong> <code>{user.vps_username or 'Wordt binnen enkele minuten verzonden'}</code></p>
        <p style="margin: 4px 0;"><strong>Wachtwoord:</strong> <code>{vps_password or 'Wordt binnen enkele minuten verzonden'}</code></p>
    </div>
    
    <div style="background-color: #ecfdf5; border: 1px solid #d1fae5; border-radius: 8px; padding: 12px; margin: 16px 0;">
        <p style="margin: 4px 0;">✅ De VPS is 24/7 actief zolang je abonnement loopt</p>
        <p style="margin: 4px 0;">✅ Log in via Windows Remote Desktop (RDP)</p>
        <p style="margin: 4px 0;">✅ Installeer MetaTrader en je Expert Advisors</p>
    </div>
    
    <p style="color: #5b6f7e; margin-top: 30px;">
        Met vriendelijke groet,<br>
        <strong style="color: #0b121a;">Het Trading Engine Team</strong>
    </p>
</div>"""
    else:
        subject = "Your Forex VPS is Ready! - Trading Engine"
        body_plain = f"""
Dear {user.first_name or 'trader'},

Your Forex VPS has been successfully created and is ready to use!

=== VPS LOGIN DETAILS ===
IP Address: {user.vps_ip or 'Will be sent within minutes'}
Username: {user.vps_username or 'Will be sent within minutes'}
Password: {vps_password or 'Will be sent within minutes'}

=== IMPORTANT INFORMATION ===
• The VPS runs 24/7 as long as your subscription is active
• You can log in immediately via Windows Remote Desktop (RDP)
• Install MetaTrader and your Expert Advisors on the VPS
• For questions, contact support@tradingengine.nl

Your VPS will remain active as long as your subscription is active.

Best regards,
The Trading Engine Team
"""
        body_html = f"""
<div style="font-family: 'Inter', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2 style="color: #0b121a;">🎉 Your Forex VPS is Ready!</h2>
    <p>Dear <strong>{user.first_name or 'trader'}</strong>,</p>
    <p>Your Forex VPS has been successfully created and is ready to use!</p>
    
    <div style="background-color: #f7f9fc; border: 1px solid #e6eaef; border-radius: 12px; padding: 16px; margin: 20px 0;">
        <h3 style="margin: 0 0 10px; color: #0b121a;">🔐 VPS Login Details</h3>
        <p style="margin: 4px 0;"><strong>IP Address:</strong> <code>{user.vps_ip or 'Will be sent within minutes'}</code></p>
        <p style="margin: 4px 0;"><strong>Username:</strong> <code>{user.vps_username or 'Will be sent within minutes'}</code></p>
        <p style="margin: 4px 0;"><strong>Password:</strong> <code>{vps_password or 'Will be sent within minutes'}</code></p>
    </div>
    
    <div style="background-color: #ecfdf5; border: 1px solid #d1fae5; border-radius: 8px; padding: 12px; margin: 16px 0;">
        <p style="margin: 4px 0;">✅ The VPS runs 24/7 as long as your subscription is active</p>
        <p style="margin: 4px 0;">✅ Log in via Windows Remote Desktop (RDP)</p>
        <p style="margin: 4px 0;">✅ Install MetaTrader and your Expert Advisors</p>
    </div>
    
    <p style="color: #5b6f7e; margin-top: 30px;">
        Best regards,<br>
        <strong style="color: #0b121a;">The Trading Engine Team</strong>
    </p>
</div>"""
    
    send_email_async(subject, [user.email], body_plain, body_html)
    logger.info(f"[ThinkHuge] 📧 VPS welcome email sent to {user.email} in {lang}")


def send_vps_termination_email(user):
    """Send VPS termination notification to user"""
    lang = user.language_preference or 'en'
    
    if lang == 'nl':
        subject = "Je Forex VPS is beëindigd - Trading Engine"
        body_plain = f"""
Beste {user.first_name or 'handelaar'},

Je Forex VPS is beëindigd omdat je abonnement is verlopen.

Als je een nieuw abonnement afsluit, wordt er automatisch een nieuwe VPS voor je aangemaakt.

Met vriendelijke groet,
Het Trading Engine Team
"""
    else:
        subject = "Your Forex VPS has been terminated - Trading Engine"
        body_plain = f"""
Dear {user.first_name or 'trader'},

Your Forex VPS has been terminated because your subscription has expired.

If you sign up for a new subscription, a new VPS will be automatically created for you.

Best regards,
The Trading Engine Team
"""
    
    send_email_async(subject, [user.email], body_plain)
    logger.info(f"[ThinkHuge] 📧 VPS termination email sent to {user.email}")


def retry_pending_vps_provisioning():
    """
    Background safety net: find paid, active/cancelled users who still
    don't have an active VPS (e.g. their original provisioning attempt hit
    the Cloudflare browser_signature_banned 403, or ThinkHuge was briefly
    unavailable) and retry provisioning for them.

    Skips users who were only just attempted (to respect
    FOREXVPS_RETRY_INTERVAL_SECONDS) and gives up permanently after
    FOREXVPS_RETRY_MAX_AGE_MINUTES since their membership started, logging
    a warning so admins can investigate accounts that keep failing.
    """
    if not forexvps_client.is_configured():
        return

    try:
        retry_cutoff = datetime.utcnow() - timedelta(seconds=Config.FOREXVPS_RETRY_INTERVAL_SECONDS)

        candidates = User.query.filter(
            User.membership_status.in_(["active", "cancelled"]),
            User.is_admin == False,
            User.vps_id.is_(None),
            User.vps_status.notin_(['terminated', 'provisioning']),
            db.or_(User.vps_last_attempt_at.is_(None), User.vps_last_attempt_at < retry_cutoff),
        ).all()

        if not candidates:
            return

        logger.info(f"[ThinkHuge] 🔁 Retry sweep: {len(candidates)} user(s) missing an active VPS")

        for user in candidates:
            if user.membership_start:
                age_minutes = (datetime.utcnow() - user.membership_start).total_seconds() / 60
                if age_minutes > Config.FOREXVPS_RETRY_MAX_AGE_MINUTES:
                    logger.warning(
                        f"[ThinkHuge] ⚠️ Giving up auto-retry for {user.email} "
                        f"(pending {age_minutes:.0f}min, last_error={user.vps_last_error}). "
                        f"Needs manual admin attention."
                    )
                    continue

            plan_level = user.get_plan_level()
            success = provision_vps_for_user(user, plan_level)

            if success:
                logger.info(f"[ThinkHuge] ✅ Retry succeeded for {user.email}")
                # If the user already has a generated license, send VPS
                # details now since the original post-license-generation
                # email would have found no VPS to report.
                if user.get_active_license():
                    send_vps_welcome_email(user)
            elif user.vps_status == 'provisioning':
                logger.info(f"[ThinkHuge] Retry created server for {user.email}, now provisioning (will poll for IP)")
            else:
                logger.warning(f"[ThinkHuge] Retry still failing for {user.email}: {user.vps_last_error}")

    except Exception as e:
        logger.error(f"[ThinkHuge] Error in retry_pending_vps_provisioning: {e}")
        db.session.rollback()


# ============================================================================
# AUTO-CLEANUP (includes VPS cleanup)
# ============================================================================

def cleanup_expired_vps():
    """Terminate VPS for users whose membership has expired"""
    try:
        expired_users = User.query.filter(
            User.membership_end < datetime.utcnow(),
            User.membership_status.in_(['expired', 'cancelled']),
            User.vps_id.isnot(None),
            User.vps_status == 'active'
        ).all()
        
        for user in expired_users:
            logger.info(f"[ThinkHuge] Terminating VPS for expired membership: {user.email} (ended {user.membership_end})")
            
            result = forexvps_client.terminate_vps(user.vps_id)
            
            if result.get('success'):
                user.vps_status = 'terminated'
                user.vps_terminated_at = datetime.utcnow()
                db.session.commit()
                
                send_vps_termination_email(user)
                
                logger.info(f"[ThinkHuge] ✅ VPS terminated for {user.email}")
            else:
                logger.error(f"[ThinkHuge] ❌ Failed to terminate VPS for {user.email}: {result.get('error')}")
    
    except Exception as e:
        logger.error(f"[ThinkHuge] Error in cleanup_expired_vps: {e}")
        db.session.rollback()


def cleanup_stale_sessions():
    """Remove EA sessions with no heartbeat. Frees account slots automatically. Also cleans up expired VPS."""
    try:
        threshold = datetime.utcnow() - timedelta(minutes=Config.HEARTBEAT_TIMEOUT_MINUTES)

        stale_sessions = EASession.query.filter(
            EASession.last_seen < threshold
        ).all()

        cleaned = 0
        freed = 0

        for ea_session in stale_sessions:
            account = ea_session.license_account
            acct_num = account.account_number if account else "unknown"
            inactive_mins = (datetime.utcnow() - ea_session.last_seen).total_seconds() / 60

            logger.info(f"🧹 Auto-clean: session={ea_session.session_id[:8]}... account={acct_num} inactive={inactive_mins:.0f}min")

            db.session.delete(ea_session)
            cleaned += 1

            if account and account.sessions.count() <= 1:
                logger.info(f"🔓 Slot freed: MT5 account={acct_num}")
                db.session.delete(account)
                freed += 1

        if cleaned > 0:
            db.session.commit()
            logger.info(f"✅ Auto-cleanup: {cleaned} sessions removed, {freed} slots freed")

    except Exception as e:
        logger.error(f"Auto-cleanup error: {e}")
        db.session.rollback()
    
    # Also clean up expired VPS
    cleanup_expired_vps()

    # Finish provisioning for servers that were created but weren't ready yet
    poll_pending_vps_servers()

    # Retry provisioning (from scratch) for anyone still missing a VPS entirely
    retry_pending_vps_provisioning()


def start_auto_cleanup():
    def job():
        while True:
            time.sleep(300)
            with app.app_context():
                cleanup_stale_sessions()

    threading.Thread(target=job, daemon=True).start()
    logger.info(f"🔄 Auto-cleanup started (timeout: {Config.HEARTBEAT_TIMEOUT_MINUTES}min)")


# ============================================================================
# DATABASE MIGRATION
# ============================================================================

def run_migrations():
    try:
        with app.app_context():
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()

            if 'ea_sessions' not in existing_tables:
                logger.info("Creating ea_sessions table...")
                db.session.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS ea_sessions (
                        id SERIAL PRIMARY KEY,
                        license_account_id INTEGER NOT NULL REFERENCES license_accounts(id) ON DELETE CASCADE,
                        session_id VARCHAR(100) NOT NULL,
                        symbol VARCHAR(20),
                        magic_number INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT uq_account_session UNIQUE (license_account_id, session_id)
                    )
                """))
                db.session.execute(db.text("""
                    CREATE INDEX IF NOT EXISTS idx_ea_sessions_session_id ON ea_sessions(session_id)
                """))
                db.session.execute(db.text("""
                    CREATE INDEX IF NOT EXISTS idx_ea_sessions_license_account_id ON ea_sessions(license_account_id)
                """))
                db.session.commit()
                logger.info("✅ ea_sessions table created")

            # Add language_preference column if it doesn't exist
            columns = [col['name'] for col in inspector.get_columns('users')]
            if 'language_preference' not in columns:
                logger.info("Adding language_preference column to users table...")
                db.session.execute(db.text("""
                    ALTER TABLE users ADD COLUMN language_preference VARCHAR(5) DEFAULT 'en'
                """))
                db.session.commit()
                logger.info("✅ language_preference column added")

            # Add ThinkHuge VPS columns if they don't exist
            vps_columns = [
                'vps_id', 'vps_status', 'vps_ip', 'vps_username', 'vps_password',
                'vps_plan', 'vps_created_at', 'vps_terminated_at',
                'vps_last_attempt_at', 'vps_last_error', 'thinkhuge_user_id',
            ]
            for col_name in vps_columns:
                if col_name not in columns:
                    if col_name in ('vps_id', 'vps_password', 'thinkhuge_user_id'):
                        col_type = 'VARCHAR(100)'
                    elif col_name == 'vps_last_error':
                        col_type = 'VARCHAR(300)'
                    elif col_name in ('vps_ip', 'vps_username', 'vps_plan', 'vps_status'):
                        col_type = 'VARCHAR(50)'
                    else:
                        col_type = 'TIMESTAMP'
                    logger.info(f"Adding {col_name} column to users table...")
                    db.session.execute(db.text(f"""
                        ALTER TABLE users ADD COLUMN {col_name} {col_type}
                    """))
                    db.session.commit()
                    logger.info(f"✅ {col_name} column added")

            # Fix existing licenses with invalid max_accounts
            bad_licenses = License.query.filter(
                (License.max_accounts == None) | (License.max_accounts <= 0)
            ).all()

            for lic in bad_licenses:
                user = lic.user
                if user:
                    user_level = user.get_plan_level()
                    correct_max = get_max_accounts_for_level(user_level)
                    logger.warning(f"FIXING license {lic.mask_license_key()}: max_accounts {lic.max_accounts} → {correct_max}")
                    lic.max_accounts = correct_max

            if bad_licenses:
                db.session.commit()
                logger.info(f"✅ Fixed {len(bad_licenses)} licenses")

            # Remove validation limits from all existing licenses on every startup
            capped_licenses = License.query.filter(
                License.max_validations != None
            ).all()

            if capped_licenses:
                for lic in capped_licenses:
                    lic.max_validations = None
                    lic.validation_count = 0
                db.session.commit()
                logger.info(f"✅ Removed validation limits from {len(capped_licenses)} existing licenses")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        db.session.rollback()


# ============================================================================
# DECORATORS
# ============================================================================

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash("Admin toegang vereist.", "error")
            abort(403)
        return f(*args, **kwargs)
    return decorated

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Niet gevonden"}), 404
    return render_template("errors/404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    logger.error(f"500 Error: {e}", exc_info=True)
    if request.path.startswith("/api/"):
        return jsonify({"error": "Server fout"}), 500
    return render_template("errors/500.html"), 500


# ============================================================================
# ROUTES - MAIN
# ============================================================================

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard") if current_user.is_admin else url_for("user_dashboard"))
    return redirect(url_for("user_login"))

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_licenses": License.query.filter_by(status="active").count(),
        "active_accounts": LicenseAccount.query.count(),
        "active_sessions": EASession.query.count(),
        "active_vps": User.query.filter_by(vps_status='active').count()
    })


# ============================================================================
# LANGUAGE ROUTES
# ============================================================================

@app.route("/set-language/<lang>")
def set_language(lang):
    """Set the user's preferred language via URL"""
    if lang in Config.LANGUAGES:
        session['language'] = lang
        if current_user.is_authenticated:
            current_user.language_preference = lang
            db.session.commit()
        logger.info(f"[LANG] Language set to: {lang}")
    return redirect(request.referrer or url_for('index'))


@app.route("/api/set-language", methods=["POST"])
def api_set_language():
    """API endpoint to set language preference"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Invalid request"}), 400
            
        lang = data.get('language', 'en')
        
        if lang in Config.LANGUAGES:
            session['language'] = lang
            if current_user.is_authenticated:
                current_user.language_preference = lang
                db.session.commit()
            
            logger.info(f"[LANG] API language set to: {lang}")
            return jsonify({"success": True, "language": lang})
        
        return jsonify({"success": False, "error": "Invalid language"}), 400
    except Exception as e:
        logger.error(f"[LANG] Error setting language: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


# ============================================================================
# LOGIN ROUTES
# ============================================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard") if current_user.is_admin else url_for("user_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        try:
            email = validate_email(email).email
        except EmailNotValidError:
            flash("Ongeldig e-mailadres.", "error")
            return render_template("user/login.html")

        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
        if email == admin_email:
            session["admin_email"] = email
            return redirect(url_for("admin_password"))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Geen account gevonden. Schaf eerst een abonnement aan.", "error")
            return render_template("user/login.html")

        if not user.email_verified:
            flash("Account niet actief. Voltooi eerst je aankoop.", "error")
            return render_template("user/login.html")

        if user.locked_until and user.locked_until > datetime.utcnow():
            flash("Account vergrendeld. Probeer later opnieuw.", "error")
            return render_template("user/login.html")

        try:
            OTPToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(
                user_id=user.id, token=otp,
                expires_at=datetime.utcnow() + timedelta(minutes=Config.OTP_EXPIRY_MINUTES),
                purpose="login"
            )
            db.session.add(otp_token)
            db.session.commit()

            send_email_async(
                "Jouw OTP Code - Trading Engine",
                [email],
                f"Jouw OTP code is: {otp}\n\nDeze code is {Config.OTP_EXPIRY_MINUTES} minuten geldig.",
                f"<h3>Jouw OTP Code</h3><p><strong>{otp}</strong></p><p>Deze code is {Config.OTP_EXPIRY_MINUTES} minuten geldig.</p>"
            )

            session["pending_email"] = email
            flash("OTP code is verzonden naar je e-mail.", "success")
            return redirect(url_for("verify_otp"))
        except Exception as e:
            logger.error(f"[LOGIN] OTP error: {e}", exc_info=True)
            flash("Kon OTP niet verzenden. Probeer opnieuw.", "error")

    return render_template("user/login.html")


@app.route("/admin-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_password():
    admin_email = session.get("admin_email") or os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
    admin_user = User.query.filter_by(email=admin_email).first()

    if admin_user and admin_user.locked_until and admin_user.locked_until > datetime.utcnow():
        session.pop("admin_email", None)
        flash("Admin account vergrendeld.", "error")
        return redirect(url_for("user_login"))

    if request.method == "POST":
        if request.form.get("password") == os.getenv("ADMIN_PASSWORD", "admin123").strip():
            if not admin_user:
                admin_user = User(
                    email=admin_email, first_name="Admin", is_admin=True, email_verified=True,
                    membership_status="active", membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin", subscription_type="lifetime", subscription_duration_days=36500
                )
                db.session.add(admin_user)
            else:
                admin_user.login_attempts = 0
                admin_user.locked_until = None
                admin_user.is_admin = True
            db.session.commit()

            OTPToken.query.filter_by(user_id=admin_user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(
                user_id=admin_user.id, token=otp,
                expires_at=datetime.utcnow() + timedelta(minutes=Config.ADMIN_OTP_EXPIRY_MINUTES),
                purpose="admin"
            )
            db.session.add(otp_token)
            db.session.commit()
            send_email_async("Admin OTP Code", [admin_email], f"Jouw admin OTP code is: {otp}")

            session["pending_email"] = admin_email
            session["is_admin_login"] = True
            session.pop("admin_email", None)
            flash("OTP code verzonden.", "success")
            return redirect(url_for("verify_otp"))
        else:
            if admin_user:
                admin_user.login_attempts += 1
                if admin_user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                    admin_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    flash("Account vergrendeld voor 30 minuten.", "error")
                else:
                    flash(f"Onjuist wachtwoord. Nog {Config.MAX_LOGIN_ATTEMPTS - admin_user.login_attempts} pogingen.", "error")
                db.session.commit()
            else:
                flash("Ongeldig wachtwoord.", "error")

    return render_template("admin/password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("user_login"))

    is_admin = session.get("is_admin_login", False)

    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()
        if len(otp_code) != 6:
            flash("Ongeldige OTP code.", "error")
            return render_template("user/verify_otp.html", email=email, is_admin=is_admin)

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Gebruiker niet gevonden.", "error")
            return redirect(url_for("user_login"))

        otp_token = OTPToken.query.filter_by(user_id=user.id, used=False).order_by(OTPToken.created_at.desc()).first()
        if not otp_token:
            flash("Geen OTP code gevonden. Vraag een nieuwe aan.", "error")
            return render_template("user/verify_otp.html", email=email, is_admin=is_admin)

        if otp_token.attempts >= 3:
            otp_token.used = True
            db.session.commit()
            flash("Te veel pogingen. Vraag een nieuwe OTP aan.", "error")
            return render_template("user/verify_otp.html", email=email, is_admin=is_admin)

        if otp_token.token == otp_code:
            if not otp_token.is_valid():
                flash("OTP code is verlopen.", "error")
                return render_template("user/verify_otp.html", email=email, is_admin=is_admin)

            otp_token.used = True
            user.email_verified = True
            user.login_attempts = 0
            user.last_login = datetime.utcnow()
            user.locked_until = None
            db.session.commit()

            login_user(user, remember=True)
            session.pop("pending_email", None)
            session.pop("is_admin_login", None)

            log_audit(user.id, "login", f"{'Admin' if user.is_admin else 'Gebruiker'} login", request.remote_addr)

            flash(f"Welkom terug, {user.first_name or 'daar'}!", "success")
            return redirect(url_for("admin_dashboard") if user.is_admin else url_for("user_dashboard"))
        else:
            otp_token.attempts += 1
            user.login_attempts += 1
            if user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                flash("Account vergrendeld voor 30 minuten.", "error")
            else:
                flash("Ongeldige OTP code.", "error")
            db.session.commit()

    return render_template("user/verify_otp.html", email=email, is_admin=is_admin)


@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        log_audit(current_user.id, "logout", request.remote_addr)
    logout_user()
    session.clear()
    resp = make_response(redirect(url_for("user_login")))
    resp.delete_cookie("session")
    resp.delete_cookie("remember_token")
    flash("Je bent uitgelogd.", "success")
    return resp


# ============================================================================
# USER DASHBOARD
# ============================================================================

@app.route("/dashboard")
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    user = current_user
    license = user.get_active_license()
    user_level = user.get_plan_level()

    ea_files = EAFile.query.filter(
        EAFile.is_active == True,
        EAFile.plan_level <= user_level
    ).order_by(EAFile.upload_date.desc()).all()

    all_ea_count = EAFile.query.filter_by(is_active=True).count()

    default_max = get_max_accounts_for_level(user_level)

    license_accounts = []
    account_count = 0
    max_accounts = default_max

    if license:
        license_accounts = [
            {
                "account": a.account_number,
                "activated": a.activated_at,
                "sessions": a.sessions.count()
            }
            for a in license.accounts
        ]
        account_count = len(license_accounts)

        if license.max_accounts and license.max_accounts > 0:
            max_accounts = license.max_accounts
        else:
            license.max_accounts = default_max
            db.session.commit()
            max_accounts = default_max

    # Calculate days remaining for membership
    days_remaining = None
    if user.membership_end and user.membership_status in ["active", "cancelled"]:
        delta = user.membership_end - datetime.utcnow()
        days_remaining = max(0, delta.days)

    # Decrypt VPS password for display
    vps_password_decrypted = None
    if user.vps_id and user.vps_password:
        try:
            vps_password_decrypted = decrypt_data(user.vps_password)
        except:
            vps_password_decrypted = None

    return render_template(
        "user/dashboard.html",
        user=user,
        license=license,
        ea_files=ea_files,
        all_ea_count=all_ea_count,
        user_level=user_level,
        plan_level_display=get_plan_level_display(user_level),
        discord_invite=Config.DISCORD_INVITE_LINK,
        now=datetime.utcnow(),
        license_accounts=license_accounts,
        account_count=account_count,
        max_accounts=max_accounts,
        days_remaining=days_remaining,
        membership_end_date=user.membership_end,
        current_language=get_user_language(),
        vps_password_decrypted=vps_password_decrypted
    )


# ============================================================================
# GENERATE LICENSE (with VPS details email after generation)
# ============================================================================

@app.route("/generate-license", methods=["POST"])
@login_required
@limiter.limit("3 per day")
def generate_license():
    logger.info(f"[LICENSE GEN] User: {current_user.email}")
    lang = get_user_language()

    if not current_user.is_membership_active():
        return jsonify({
            "error": "Actief abonnement vereist" if lang == 'nl' else "Active membership required",
            "debug": {
                "status": current_user.membership_status,
                "end_date": current_user.membership_end.isoformat() if current_user.membership_end else None
            }
        }), 403

    if current_user.get_active_license():
        return jsonify({"error": "Je hebt al een actieve licentie" if lang == 'nl' else "You already have an active license"}), 400

    try:
        test_mode = Setting.query.filter_by(key="test_mode").first()
        is_test = test_mode and test_mode.value == "on"

        key = generate_license_key()
        days = 1 if is_test else (current_user.subscription_duration_days or Config.LICENSE_EXPIRY_DAYS)
        license_type = "test" if is_test else (current_user.subscription_type or "standard")
        user_level = current_user.get_plan_level()
        max_accounts = get_max_accounts_for_level(user_level)

        lic = License(
            user_id=current_user.id,
            license_key=key,
            expires_at=datetime.utcnow() + timedelta(days=days),
            ea_version="1.0.0",
            license_type=license_type,
            max_accounts=max_accounts,
            max_validations=None,
            validation_count=0,
        )

        db.session.add(lic)
        db.session.commit()

        logger.info(f"[LICENSE GEN] ✅ {lic.mask_license_key()} | max_acc={max_accounts} | level={user_level} | unlimited validations")

        log_audit(
            current_user.id, "license_generated",
            f"{lic.mask_license_key()} | level={user_level} | max_acc={max_accounts}",
            request.remote_addr
        )

        # Send license key email in user's selected language
        if lang == 'nl':
            send_email_async(
                "Jouw Licentiesleutel - Trading Engine",
                [current_user.email],
                f"Licentiesleutel: {key}\nVerloopt: {format_date_dutch(lic.expires_at)}\nMax MT5 Accounts: {max_accounts}\n\nBewaar deze sleutel veilig.",
                f"<h3>Jouw Licentiesleutel</h3><p><strong>{key}</strong></p><p>Verloopt: {format_date_dutch(lic.expires_at)}</p><p>Max MT5 Accounts: {max_accounts}</p><p>Bewaar deze sleutel veilig.</p>"
            )
        else:
            send_email_async(
                "Your License Key - Trading Engine",
                [current_user.email],
                f"License Key: {key}\nExpires: {format_date_english(lic.expires_at)}\nMax MT5 Accounts: {max_accounts}\n\nKeep this key safe.",
                f"<h3>Your License Key</h3><p><strong>{key}</strong></p><p>Expires: {format_date_english(lic.expires_at)}</p><p>Max MT5 Accounts: {max_accounts}</p><p>Keep this key safe.</p>"
            )

        # If there's no VPS yet, try once more synchronously right now -
        # this catches the common case where the original webhook attempt
        # failed (e.g. the Cloudflare 403) and the background retry sweep
        # hasn't run yet. Doesn't block the response either way.
        if not (current_user.vps_id and current_user.vps_status == 'active'):
            provision_vps_for_user(current_user, current_user.get_plan_level())

        # NOW SEND VPS DETAILS (if VPS exists)
        # User has already selected language on dashboard, so we use the correct language
        if current_user.vps_id and current_user.vps_status == 'active':
            send_vps_welcome_email(current_user)
            logger.info(f"[LICENSE GEN] 📧 VPS details sent to {current_user.email} in {lang}")
        else:
            logger.info(f"[LICENSE GEN] No active VPS for {current_user.email}, skipping VPS email")

        return jsonify({
            "success": True,
            "license_key": key,
            "masked_key": lic.mask_license_key(),
            "expires_at": lic.expires_at.isoformat(),
            "max_accounts": max_accounts
        })

    except Exception as e:
        logger.error(f"[LICENSE GEN] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": "Kon licentie niet genereren" if lang == 'nl' else "Failed to generate license"}), 500


# ============================================================================
# CANCEL MEMBERSHIP (FIXED - Stop auto-renewal, keep full access)
# ============================================================================

@app.route("/cancel-membership", methods=["POST"])
@login_required
@limiter.limit("5 per day")
def cancel_membership():
    """
    Cancel auto-renewal of membership.
    User keeps FULL access until their paid period ends.
    Licenses are NOT revoked - they remain active until membership_end.
    VPS is NOT terminated until membership_end passes.
    """
    if current_user.is_admin:
        return jsonify({"error": "Admin accounts cannot be cancelled this way"}), 400

    lang = get_user_language()

    try:
        user = current_user
        membership_end_date = user.membership_end

        if user.membership_status == "cancelled":
            msg = "Je abonnement is al geannuleerd." if lang == 'nl' else "Your membership is already cancelled."
            return jsonify({"error": msg}), 400

        if user.membership_status != "active":
            msg = "Alleen actieve abonnementen kunnen worden geannuleerd." if lang == 'nl' else "Only active memberships can be cancelled."
            return jsonify({"error": msg}), 400

        if not membership_end_date:
            membership_end_date = datetime.utcnow()

        # Change status to cancelled (stops auto-renewal)
        # Keep membership_end date as-is - user retains access until then
        # IMPORTANT: Do NOT revoke licenses or terminate VPS!
        user.membership_status = "cancelled"
        
        db.session.commit()

        formatted_date_nl = format_date_dutch(membership_end_date) if membership_end_date else "de eerstvolgende verlengdatum"
        formatted_date_en = format_date_english(membership_end_date) if membership_end_date else "the next renewal date"

        active_license_count = License.query.filter_by(
            user_id=user.id,
            status="active"
        ).count()

        if lang == 'nl':
            email_subject = "Bevestiging van je annulering - Trading Engine"
            email_body_plain = (
                f"Beste {user.first_name or 'handelaar'},\n\n"
                f"Je abonnement is succesvol geannuleerd. Dit betekent dat je abonnement "
                f"niet automatisch wordt verlengd.\n\n"
                f"Je behoudt volledige toegang tot alle functies van Trading Engine tot {formatted_date_nl}. "
                f"Je licenties blijven actief, je VPS blijft draaien en je kunt je Expert Advisors blijven gebruiken.\n\n"
                f"Na {formatted_date_nl} verloopt je toegang en wordt je VPS automatisch beëindigd.\n\n"
                f"Mocht je van gedachten veranderen, dan kun je altijd een nieuw abonnement afsluiten.\n\n"
                f"Bedankt dat je deel uitmaakt van Trading Engine!\n\n"
                f"Met vriendelijke groet,\n"
                f"Het Trading Engine Team"
            )
            email_body_html = f"""
            <div style="font-family: 'Inter', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #0b121a;">Bevestiging van je annulering</h2>
                <p>Beste <strong>{user.first_name or 'handelaar'}</strong>,</p>
                
                <p>Je abonnement is <strong>succesvol geannuleerd</strong>. Dit betekent dat je abonnement niet automatisch wordt verlengd.</p>
                
                <div style="background-color: #ecfdf5; border: 1px solid #d1fae5; border-radius: 12px; padding: 16px; margin: 20px 0;">
                    <p style="margin: 0; font-size: 15px; color: #065f46;">
                        ✅ <strong>Je behoudt volledige toegang tot {formatted_date_nl}</strong>
                    </p>
                    <p style="margin: 8px 0 0; font-size: 14px; color: #047857;">
                        • Je licenties blijven actief<br>
                        • Je VPS blijft draaien<br>
                        • Je kunt je Expert Advisors blijven gebruiken<br>
                        • Je hebt toegang tot alle downloadbare bestanden
                    </p>
                </div>
                
                <p style="color: #5b6f7e;">Na {formatted_date_nl} verloopt je toegang en wordt je VPS automatisch beëindigd. Mocht je van gedachten veranderen, dan kun je altijd een nieuw abonnement afsluiten.</p>
                
                <p style="color: #5b6f7e; margin-top: 30px;">
                    Met vriendelijke groet,<br>
                    <strong style="color: #0b121a;">Het Trading Engine Team</strong>
                </p>
                
                <hr style="border: none; border-top: 1px solid #e6eaef; margin: 20px 0;">
                <p style="font-size: 12px; color: #96a6b5;">
                    Als je deze annulering niet zelf hebt aangevraagd, neem dan direct contact met ons op via Discord.
                </p>
            </div>
            """
        else:
            email_subject = "Cancellation Confirmation - Trading Engine"
            email_body_plain = (
                f"Dear {user.first_name or 'trader'},\n\n"
                f"Your membership has been successfully cancelled. This means your subscription "
                f"will not auto-renew.\n\n"
                f"You will retain full access to all Trading Engine features until {formatted_date_en}. "
                f"Your licenses remain active, your VPS continues running, and you can continue using your Expert Advisors.\n\n"
                f"After {formatted_date_en}, your access will expire and your VPS will be automatically terminated.\n\n"
                f"If you change your mind, you can always sign up for a new subscription.\n\n"
                f"Thank you for being part of Trading Engine!\n\n"
                f"Best regards,\n"
                f"The Trading Engine Team"
            )
            email_body_html = f"""
            <div style="font-family: 'Inter', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #0b121a;">Cancellation Confirmation</h2>
                <p>Dear <strong>{user.first_name or 'trader'}</strong>,</p>
                
                <p>Your membership has been <strong>successfully cancelled</strong>. This means your subscription will not auto-renew.</p>
                
                <div style="background-color: #ecfdf5; border: 1px solid #d1fae5; border-radius: 12px; padding: 16px; margin: 20px 0;">
                    <p style="margin: 0; font-size: 15px; color: #065f46;">
                        ✅ <strong>You retain full access until {formatted_date_en}</strong>
                    </p>
                    <p style="margin: 8px 0 0; font-size: 14px; color: #047857;">
                        • Your licenses remain active<br>
                        • Your VPS continues running<br>
                        • You can continue using your Expert Advisors<br>
                        • You have access to all downloadable files
                    </p>
                </div>
                
                <p style="color: #5b6f7e;">After {formatted_date_en}, your access will expire and your VPS will be automatically terminated. If you change your mind, you can always sign up for a new subscription.</p>
                
                <p style="color: #5b6f7e; margin-top: 30px;">
                    Best regards,<br>
                    <strong style="color: #0b121a;">The Trading Engine Team</strong>
                </p>
                
                <hr style="border: none; border-top: 1px solid #e6eaef; margin: 20px 0;">
                <p style="font-size: 12px; color: #96a6b5;">
                    If you did not request this cancellation, please contact us immediately via Discord.
                </p>
            </div>
            """

        send_email_async(email_subject, [user.email], email_body_plain, email_body_html)

        log_audit(
            user.id,
            "membership_cancelled",
            f"User cancelled auto-renewal | Access until: {formatted_date_en} | {active_license_count} active licenses retained | VPS retained until expiry",
            request.remote_addr
        )

        logger.info(f"[CANCEL] User {user.email} cancelled auto-renewal. Access until {formatted_date_en}")

        success_msg = (
            f"Je abonnement is geannuleerd. Je behoudt volledige toegang tot {formatted_date_nl}." 
            if lang == 'nl' else 
            f"Membership cancelled. You retain full access until {formatted_date_en}."
        )

        return jsonify({
            "success": True,
            "message": success_msg,
            "end_date_nl": formatted_date_nl,
            "end_date_en": formatted_date_en,
            "licenses_retained": active_license_count
        })

    except Exception as e:
        logger.error(f"[CANCEL] Error cancelling membership: {e}", exc_info=True)
        db.session.rollback()
        error_msg = "Kon abonnement niet annuleren. Probeer opnieuw." if lang == 'nl' else "Failed to cancel membership. Please try again."
        return jsonify({"error": error_msg}), 500


# ============================================================================
# DOWNLOAD EA
# ============================================================================

@app.route("/download-ea/<int:file_id>")
@login_required
def download_ea(file_id):
    if not current_user.is_membership_active():
        flash("Actief abonnement vereist.", "error")
        return redirect(url_for("user_dashboard"))

    ea = db.session.get(EAFile, file_id)
    if not ea or not ea.is_active:
        flash("EA niet gevonden.", "error")
        return redirect(url_for("user_dashboard"))

    if ea.plan_level > current_user.get_plan_level():
        flash("Vereist een hoger plan niveau.", "error")
        return redirect(url_for("user_dashboard"))

    file_path = os.path.join(Config.UPLOAD_FOLDER, ea.file_path)
    if not os.path.exists(file_path):
        flash("Bestand ontbreekt. Neem contact op met support.", "error")
        return redirect(url_for("user_dashboard"))

    ea.download_count += 1
    db.session.commit()
    log_audit(current_user.id, "ea_download", ea.filename, request.remote_addr)

    return send_from_directory(
        Config.UPLOAD_FOLDER, ea.file_path,
        as_attachment=True, download_name=ea.filename
    )


# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    total_users = User.query.filter_by(is_admin=False).count()
    active_users = User.query.filter(
        User.membership_status.in_(["active", "cancelled"]),
        User.is_admin == False
    ).count()
    total_licenses = License.query.count()
    active_licenses = License.query.filter_by(status="active").count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    total_downloads = db.session.query(db.func.sum(EAFile.download_count)).scalar() or 0
    active_vps = User.query.filter_by(vps_status='active').count()

    recent_users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).limit(10).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    recent_licenses = License.query.order_by(License.created_at.desc()).limit(10).all()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    ea_files = EAFile.query.order_by(EAFile.upload_date.desc()).all()

    subscription_stats = db.session.query(
        User.subscription_type,
        db.func.count(User.id),
        db.func.sum(User.plan_price)
    ).filter(User.is_admin == False).group_by(User.subscription_type).all()

    test_mode = Setting.query.filter_by(key="test_mode").first()
    is_test_mode = test_mode.value == "on" if test_mode else False

    problematic_licenses = License.query.filter(
        (License.max_accounts == None) | (License.max_accounts <= 0)
    ).all()

    # Users who paid but still don't have a working VPS - surfaced for admins
    vps_pending_users = User.query.filter(
        User.membership_status.in_(["active", "cancelled"]),
        User.is_admin == False,
        db.or_(User.vps_id.is_(None), User.vps_status != 'active'),
        User.vps_status != 'terminated',
    ).order_by(User.membership_start.desc()).all()

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        active_users=active_users,
        total_licenses=total_licenses,
        active_licenses=active_licenses,
        total_orders=total_orders,
        total_revenue=total_revenue,
        total_downloads=total_downloads,
        active_vps=active_vps,
        recent_users=recent_users,
        recent_orders=recent_orders,
        recent_licenses=recent_licenses,
        recent_logs=recent_logs,
        ea_files=ea_files,
        subscription_stats=subscription_stats,
        now=datetime.utcnow(),
        is_test_mode=is_test_mode,
        problematic_licenses=problematic_licenses,
        vps_pending_users=vps_pending_users
    )


@app.route("/admin/fix-all-licenses", methods=["POST"])
@admin_required
def fix_all_licenses():
    bad_licenses = License.query.filter(
        (License.max_accounts == None) | (License.max_accounts <= 0)
    ).all()

    fixed = 0
    for lic in bad_licenses:
        user = lic.user
        if user:
            user_level = user.get_plan_level()
            correct_max = get_max_accounts_for_level(user_level)
            logger.info(f"[FIX] License {lic.mask_license_key()}: {lic.max_accounts} → {correct_max}")
            lic.max_accounts = correct_max
            fixed += 1

    db.session.commit()
    flash(f"{fixed} licenties hersteld", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/retry-vps/<int:user_id>", methods=["POST"])
@admin_required
def admin_retry_vps(user_id):
    """Manually re-trigger VPS provisioning for a single user (e.g. right after
    fixing configuration or confirming ThinkHuge/Cloudflare access is restored)."""
    user = db.session.get(User, user_id)
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_dashboard"))

    success = provision_vps_for_user(user, user.get_plan_level())
    if success:
        if user.get_active_license():
            send_vps_welcome_email(user)
        flash(f"VPS succesvol aangemaakt voor {user.email}.", "success")
    elif user.vps_status == 'provisioning':
        flash(f"VPS wordt aangemaakt voor {user.email} (ThinkHuge is nog bezig, IP volgt automatisch).", "success")
    else:
        flash(f"VPS aanmaken mislukt voor {user.email}: {user.vps_last_error}", "error")

    return redirect(request.referrer or url_for("admin_dashboard"))


@app.route("/admin/toggle-test-mode", methods=["POST"])
@admin_required
def toggle_test_mode():
    setting = Setting.query.filter_by(key="test_mode").first()
    if not setting:
        setting = Setting(key="test_mode", value="off")
        db.session.add(setting)
    setting.value = "on" if setting.value == "off" else "off"
    db.session.commit()
    log_audit(current_user.id, "test_mode_toggle", f"Test mode: {setting.value}", request.remote_addr)
    return jsonify({"status": "success", "test_mode": setting.value})


@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users, now=datetime.utcnow())


@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_users"))

    orders = user.orders.order_by(Order.created_at.desc()).all()
    licenses = user.licenses.order_by(License.created_at.desc()).all()
    
    # Decrypt VPS password for admin display
    vps_password = decrypt_data(user.vps_password) if user.vps_password else None

    return render_template(
        "admin/user_detail.html",
        user=user, orders=orders, licenses=licenses,
        vps_password=vps_password,
        now=datetime.utcnow()
    )


@app.route("/admin/orders")
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    return render_template("admin/orders.html", orders=orders, total_revenue=total_revenue)


@app.route("/admin/revoke-license/<int:license_id>", methods=["POST"])
@admin_required
def revoke_license(license_id):
    lic = db.session.get(License, license_id)
    if lic:
        lic.status = "revoked"
        lic.revoked_at = datetime.utcnow()
        db.session.commit()
        flash("Licentie ingetrokken.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/revoke-membership/<int:user_id>", methods=["POST"])
@admin_required
def revoke_membership(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.membership_status = "revoked"
        user.membership_end = datetime.utcnow()
        License.query.filter_by(user_id=user.id, status="active").update(
            {"status": "revoked", "revoked_at": datetime.utcnow()}
        )
        # Also terminate VPS if admin revokes
        if user.vps_id and user.vps_status == 'active':
            forexvps_client.terminate_vps(user.vps_id)
            user.vps_status = 'terminated'
            user.vps_terminated_at = datetime.utcnow()
        db.session.commit()
        flash("Abonnement ingetrokken.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/reactivate-membership/<int:user_id>", methods=["POST"])
@admin_required
def reactivate_membership(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.membership_status = "active"
        user.membership_start = datetime.utcnow()
        user.membership_end = datetime.utcnow() + timedelta(days=user.subscription_duration_days or 30)
        db.session.commit()
        log_audit(current_user.id, "membership_reactivated", f"Geactiveerd: {user.email}", request.remote_addr)
        flash("Abonnement opnieuw geactiveerd.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/extend-membership/<int:user_id>", methods=["POST"])
@admin_required
def extend_membership(user_id):
    user = db.session.get(User, user_id)
    if user:
        days = int(request.form.get("days", 30))
        if user.membership_end and user.membership_end > datetime.utcnow():
            user.membership_end += timedelta(days=days)
        else:
            user.membership_start = datetime.utcnow()
            user.membership_end = datetime.utcnow() + timedelta(days=days)
        user.membership_status = "active"
        db.session.commit()
        flash(f"Verlengd met {days} dagen.", "success")
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/upload-ea", methods=["POST"])
@admin_required
def upload_ea():
    if "file" not in request.files:
        flash("Geen bestand.", "error")
        return redirect(url_for("admin_dashboard"))

    file = request.files["file"]
    if file.filename == "" or not allowed_file(file.filename):
        flash("Ongeldig bestandstype.", "error")
        return redirect(url_for("admin_dashboard"))

    filename = secure_filename(file.filename)
    saved = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file_path = os.path.join(Config.UPLOAD_FOLDER, saved)
    file.save(file_path)

    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha.update(block)

    ea = EAFile(
        filename=filename, file_path=saved,
        version=request.form.get("version", "1.0.0"),
        file_size=os.path.getsize(file_path),
        description=request.form.get("description", ""),
        changelog=request.form.get("changelog", ""),
        is_beta=request.form.get("is_beta") == "on",
        plan_level=int(request.form.get("plan_level", 1)),
        checksum=sha.hexdigest(),
        uploaded_by=current_user.id
    )
    db.session.add(ea)
    db.session.commit()
    flash(f"EA geüpload (Level {ea.plan_level}).", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-ea/<int:ea_id>", methods=["POST"])
@admin_required
def delete_ea(ea_id):
    ea = db.session.get(EAFile, ea_id)
    if ea:
        file_path = os.path.join(Config.UPLOAD_FOLDER, ea.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
        name = ea.filename
        db.session.delete(ea)
        db.session.commit()
        flash(f"'{name}' verwijderd.", "success")
    return redirect(url_for("admin_dashboard"))


# ============================================================================
# API - LICENSE VALIDATION (FIXED - MT5 ACCOUNT TRACKING)
# ============================================================================

@app.route("/api/validate-license", methods=["POST"])
@limiter.limit("60 per minute")
def api_validate_license():
    """
    Called by EA on init and periodically (heartbeat).

    ACCOUNT SLOT LOGIC:
    - Each UNIQUE MT5 account number = 1 slot
    - Multiple EAs on same MT5 account share 1 slot
    - Slot freed only when ALL EAs on that account are removed

    FIX: Heartbeat calls do NOT increment validation_count.
         Only genuinely new sessions (new EA or new account) increment it.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"valid": False, "error": "Ongeldig verzoek"}), 400

        license_key = data.get("license_key", "").strip()
        account_number = data.get("account_number", "").strip()
        machine_id = data.get("machine_id", "").strip()
        session_id = data.get("session_id", "").strip()
        symbol = data.get("symbol", "").strip() or None

        try:
            magic_number = int(data.get("magic_number")) if data.get("magic_number") is not None else None
        except (TypeError, ValueError):
            magic_number = None

        if not license_key:
            return jsonify({"valid": False, "error": "Licentiesleutel vereist"}), 400

        unique_account_id = account_number if account_number else machine_id

        if not unique_account_id:
            return jsonify({"valid": False, "error": "account_number of machine_id vereist"}), 400

        if not session_id:
            return jsonify({"valid": False, "error": "session_id vereist"}), 400

        logger.info(f"[VALIDATE] License: {license_key[:10]}... | MT5 Account: {unique_account_id} | EA: {session_id[:8]}...")

        lic = License.query.filter_by(license_key=license_key).first()
        if not lic:
            logger.warning(f"[VALIDATE] License not found")
            return jsonify({"valid": False, "error": "Licentie niet gevonden"}), 404

        if not lic.is_valid():
            logger.warning(f"[VALIDATE] License invalid: {lic.mask_license_key()} status={lic.status}")
            return jsonify({"valid": False, "error": "Licentie niet actief of verlopen"}), 403

        account = LicenseAccount.query.filter_by(
            license_id=lic.id,
            account_number=unique_account_id
        ).first()

        if account:
            existing_session = EASession.query.filter_by(
                license_account_id=account.id,
                session_id=session_id
            ).first()

            if existing_session:
                existing_session.last_seen = datetime.utcnow()
                existing_session.symbol = symbol or existing_session.symbol
                existing_session.magic_number = magic_number if magic_number is not None else existing_session.magic_number
                logger.debug(f"[VALIDATE] 💓 Heartbeat: MT5={unique_account_id} EA={session_id[:8]}...")
            else:
                db.session.add(EASession(
                    license_account_id=account.id,
                    session_id=session_id,
                    symbol=symbol,
                    magic_number=magic_number,
                ))
                lic.validation_count += 1
                logger.info(f"[VALIDATE] ➕ New EA on existing MT5={unique_account_id} | Total EAs: {account.sessions.count() + 1}")

            lic.last_validated = datetime.utcnow()
            db.session.commit()

            total_slots = lic.accounts.count()

            return jsonify({
                "valid": True,
                "expires_at": lic.expires_at.isoformat(),
                "user_email": lic.user.email,
                "accounts_used": total_slots,
                "accounts_max": lic.max_accounts,
                "accounts_remaining": lic.max_accounts - total_slots,
                "sessions_on_this_account": account.sessions.count(),
            })

        total_slots = lic.accounts.count()

        logger.info(f"[VALIDATE] New MT5 account: {unique_account_id} | Slots: {total_slots}/{lic.max_accounts}")

        if total_slots >= lic.max_accounts:
            logger.warning(f"[VALIDATE] 🚫 MAX SLOTS: {total_slots}/{lic.max_accounts}")
            return jsonify({
                "valid": False,
                "error": f"Maximum {lic.max_accounts} MT5 accounts bereikt. Momenteel {total_slots} in gebruik.",
                "accounts_used": total_slots,
                "accounts_max": lic.max_accounts,
                "accounts_remaining": 0,
            }), 403

        new_account = LicenseAccount(
            license_id=lic.id,
            account_number=unique_account_id
        )
        db.session.add(new_account)
        db.session.flush()

        db.session.add(EASession(
            license_account_id=new_account.id,
            session_id=session_id,
            symbol=symbol,
            magic_number=magic_number,
        ))

        lic.last_validated = datetime.utcnow()
        lic.validation_count += 1
        db.session.commit()

        new_total = lic.accounts.count()

        logger.info(f"[VALIDATE] ✅ NEW SLOT: MT5={unique_account_id} | Total: {new_total}/{lic.max_accounts}")

        return jsonify({
            "valid": True,
            "expires_at": lic.expires_at.isoformat(),
            "user_email": lic.user.email,
            "accounts_used": new_total,
            "accounts_max": lic.max_accounts,
            "accounts_remaining": lic.max_accounts - new_total,
            "sessions_on_this_account": 1,
        })

    except Exception as e:
        logger.error(f"[VALIDATE] ❌ Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"valid": False, "error": "Server fout"}), 500


@app.route("/api/release-license", methods=["POST"])
@limiter.limit("30 per minute")
def api_release_license():
    """
    Called by EA when removed from chart.
    Releases only THIS EA session.
    Slot freed only when ALL EAs on that MT5 account are removed.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Ongeldig verzoek"}), 400

        license_key = data.get("license_key", "").strip()
        account_number = data.get("account_number", "").strip()
        machine_id = data.get("machine_id", "").strip()
        session_id = data.get("session_id", "").strip()

        unique_account_id = account_number if account_number else machine_id

        if not license_key or not unique_account_id or not session_id:
            return jsonify({
                "success": False,
                "error": "license_key, account_number (of machine_id), en session_id vereist"
            }), 400

        lic = License.query.filter_by(license_key=license_key).first()
        if not lic:
            return jsonify({"success": False, "error": "Licentie niet gevonden"}), 404

        account = LicenseAccount.query.filter_by(
            license_id=lic.id,
            account_number=unique_account_id
        ).first()

        if not account:
            logger.info(f"[RELEASE] No slot for: {unique_account_id}")
            return jsonify({
                "success": True, "session_released": False, "slot_freed": False,
                "message": "Geen actieve slot voor dit account",
                "accounts_used": lic.accounts.count(),
                "accounts_max": lic.max_accounts,
                "accounts_remaining": lic.max_accounts - lic.accounts.count(),
            })

        ea_session = EASession.query.filter_by(
            license_account_id=account.id,
            session_id=session_id
        ).first()

        if not ea_session:
            logger.info(f"[RELEASE] Session not found: {session_id[:8]}... on {unique_account_id}")
            return jsonify({
                "success": True, "session_released": False, "slot_freed": False,
                "message": "Sessie niet gevonden",
                "sessions_remaining": account.sessions.count(),
                "accounts_used": lic.accounts.count(),
                "accounts_max": lic.max_accounts,
                "accounts_remaining": lic.max_accounts - lic.accounts.count(),
            })

        db.session.delete(ea_session)
        db.session.flush()

        remaining_sessions = account.sessions.count()
        slot_freed = False

        if remaining_sessions == 0:
            db.session.delete(account)
            slot_freed = True
            logger.info(f"[RELEASE] 🔓 SLOT FREED: MT5={unique_account_id}")
        else:
            logger.info(f"[RELEASE] 🗑️ EA removed: MT5={unique_account_id} | {remaining_sessions} EAs still running")

        db.session.commit()

        log_audit(
            lic.user_id, "ea_session_released",
            f"{lic.mask_license_key()} | MT5={unique_account_id} | Session={session_id[:8]}... | Slot freed={slot_freed}",
            request.remote_addr,
        )

        return jsonify({
            "success": True,
            "session_released": True,
            "slot_freed": slot_freed,
            "sessions_remaining_on_account": remaining_sessions,
            "accounts_used": lic.accounts.count(),
            "accounts_max": lic.max_accounts,
            "accounts_remaining": lic.max_accounts - lic.accounts.count(),
        })

    except Exception as e:
        logger.error(f"[RELEASE] ❌ Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"success": False, "error": "Server fout"}), 500


@app.route("/api/user/info")
@login_required
def api_user_info():
    return jsonify(current_user.to_dict())


# ============================================================================
# WIX WEBHOOK (with VPS provisioning)
# ============================================================================

@app.route("/webhook/wix/payment", methods=["POST"])
@limiter.limit("60 per minute")
def wix_payment_webhook():
    try:
        if request.is_json:
            raw = request.get_json()
        else:
            raw = request.form.to_dict() or request.get_json(force=True, silent=True) or {}

        data = raw.get("data", raw)

        if data.get("eventType") != "Plan ordered":
            return jsonify({"status": "ignored"}), 200

        email = data.get("contact_email", "").strip().lower()
        if not email:
            return jsonify({"error": "Email vereist"}), 400

        first_name = data.get("contact_first_name", "")
        last_name = data.get("contact_last_name", "")
        plan_name = data.get("plan_name", "")
        plan_duration = data.get("plan_duration", "")
        plan_start = data.get("plan_start_date", "")
        plan_end = data.get("plan_end_date", "")
        order_id = data.get("order_id", "")
        contact_id = data.get("contact_id", "")

        try:
            plan_price = float(data.get("plan_price_amount", 0))
        except:
            plan_price = 0.0

        currency = data.get("plan_price_currency", "EUR")

        duration_days, subscription_type = parse_duration_to_days(plan_duration)

        if subscription_type == "one_time" and plan_name:
            pl = plan_name.lower()
            if "monthly" in pl or "maand" in pl:
                duration_days, subscription_type = 30, "monthly"
            elif "yearly" in pl or "jaar" in pl:
                duration_days, subscription_type = 365, "yearly"
            elif "lifetime" in pl or "levenslang" in pl:
                duration_days, subscription_type = 36500, "lifetime"

        membership_start = parse_wix_date(plan_start) or datetime.utcnow()
        membership_end = parse_wix_date(plan_end) or (membership_start + timedelta(days=duration_days))

        user = User.query.filter_by(email=email).first()
        is_new = False

        if not user:
            user = User(
                email=email, first_name=first_name, last_name=last_name,
                wix_contact_id=contact_id, wix_order_id=order_id, wix_payment_id=order_id,
                email_verified=True, membership_status="active",
                membership_start=membership_start, membership_end=membership_end,
                plan_name=plan_name, plan_price=plan_price, currency=currency,
                subscription_type=subscription_type, subscription_duration_days=duration_days
            )
            db.session.add(user)
            db.session.flush()
            is_new = True
        else:
            user.first_name = first_name or user.first_name
            user.last_name = last_name or user.last_name
            user.wix_contact_id = contact_id or user.wix_contact_id
            user.wix_order_id = order_id or user.wix_order_id
            user.wix_payment_id = order_id or user.wix_payment_id
            user.email_verified = True
            user.membership_status = "active"
            user.membership_start = membership_start
            user.membership_end = membership_end
            user.plan_name = plan_name or user.plan_name
            user.plan_price = plan_price if plan_price > 0 else user.plan_price
            user.currency = currency or user.currency
            user.subscription_type = subscription_type
            user.subscription_duration_days = duration_days
            db.session.flush()

        if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
            order = Order(
                user_id=user.id, wix_order_id=order_id, wix_payment_id=order_id,
                plan_name=plan_name, plan_price=plan_price, currency=currency,
                total_amount=plan_price, subscription_type=subscription_type,
                subscription_duration_days=duration_days, status="completed",
                payment_status="paid", ip_address=request.remote_addr,
                raw_data=json.dumps(data)
            )
            db.session.add(order)

        db.session.commit()

        # Provision VPS for the user (creates VPS but does NOT send welcome email)
        plan_level = user.get_plan_level()
        provision_vps_for_user(user, plan_level)

        send_email_async(
            "Welkom bij Trading Engine! 🎉",
            [email],
            f"Je {plan_name} abonnement is nu actief. Log in op {Config.APP_URL}/login",
            f"<h3>Hoi {first_name or 'daar'}!</h3><p>Je {plan_name} abonnement is actief.</p><p>Log in op {Config.APP_URL}/login</p>"
        )

        log_audit(
            user.id, "wix_plan_ordered",
            f"{'Nieuw' if is_new else 'Bijgewerkt'} | {plan_name} | {subscription_type}",
            request.remote_addr
        )

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"[WIX WEBHOOK] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# STRIPE WEBHOOK (with VPS provisioning)
# ============================================================================

@app.route("/webhook/stripe/payment", methods=["POST"])
@limiter.limit("60 per minute")
def stripe_payment_webhook():
    try:
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get("Stripe-Signature")

        if Config.STRIPE_WEBHOOK_SECRET:
            if stripe is None:
                logger.error("[STRIPE] Stripe library not installed")
                return jsonify({"error": "Stripe not configured"}), 500
            try:
                event = stripe.Webhook.construct_event(
                    payload, sig_header, Config.STRIPE_WEBHOOK_SECRET
                )
            except stripe.error.SignatureVerificationError as e:
                logger.warning(f"[STRIPE] Invalid signature: {e}")
                return jsonify({"error": "Ongeldige handtekening"}), 400
            except Exception as e:
                logger.error(f"[STRIPE] Webhook error: {e}")
                return jsonify({"error": "Webhook fout"}), 400
        else:
            event = json.loads(payload)

        event_type = event["type"]
        logger.info(f"[STRIPE] Event: {event_type}")

        if event_type == "checkout.session.completed":
            session_data = event["data"]["object"]._to_dict_recursive()
            customer_details = session_data.get("customer_details") or {}
            email = customer_details.get("email", "").strip().lower()
            name = customer_details.get("name", "")
            first_name = name.split()[0] if name else ""
            last_name = " ".join(name.split()[1:]) if name else ""
            phone = customer_details.get("phone", "")
            country = (customer_details.get("address") or {}).get("country", "")

            metadata = session_data.get("metadata") or {}
            plan_name = metadata.get("plan_name", "Onbekend Plan")
            plan_duration = metadata.get("plan_duration", "")
            amount_total = (session_data.get("amount_total") or 0) / 100
            currency = (session_data.get("currency") or "eur").upper()
            order_id = session_data.get("id", "")

            if not email:
                return jsonify({"error": "Email vereist"}), 400

            duration_days, subscription_type = parse_duration_to_days(plan_duration)

            if subscription_type == "one_time" and plan_name:
                pl = plan_name.lower()
                if "monthly" in pl or "maand" in pl:
                    duration_days, subscription_type = 30, "monthly"
                elif "yearly" in pl or "jaar" in pl:
                    duration_days, subscription_type = 365, "yearly"
                elif "lifetime" in pl:
                    duration_days, subscription_type = 36500, "lifetime"

            membership_start = datetime.utcnow()
            membership_end = membership_start + timedelta(days=duration_days)

            user = User.query.filter_by(email=email).first()
            is_new = False

            if not user:
                user = User(
                    email=email, first_name=first_name, last_name=last_name,
                    phone=phone, country=country, wix_order_id=order_id,
                    wix_payment_id=order_id, email_verified=True,
                    membership_status="active", membership_start=membership_start,
                    membership_end=membership_end, plan_name=plan_name,
                    plan_price=amount_total, currency=currency,
                    subscription_type=subscription_type,
                    subscription_duration_days=duration_days
                )
                db.session.add(user)
                db.session.flush()
                is_new = True
            else:
                user.first_name = first_name or user.first_name
                user.last_name = last_name or user.last_name
                user.phone = phone or user.phone
                user.country = country or user.country
                user.wix_order_id = order_id or user.wix_order_id
                user.wix_payment_id = order_id or user.wix_payment_id
                user.email_verified = True
                user.membership_status = "active"
                user.membership_start = membership_start
                user.membership_end = membership_end
                user.plan_name = plan_name or user.plan_name
                user.plan_price = amount_total if amount_total > 0 else user.plan_price
                user.currency = currency or user.currency
                user.subscription_type = subscription_type
                user.subscription_duration_days = duration_days
                db.session.flush()

            if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
                order = Order(
                    user_id=user.id, wix_order_id=order_id, wix_payment_id=order_id,
                    plan_name=plan_name, plan_price=amount_total, currency=currency,
                    total_amount=amount_total, subscription_type=subscription_type,
                    subscription_duration_days=duration_days, status="completed",
                    payment_status="paid", ip_address=request.remote_addr,
                    raw_data=json.dumps(session_data)
                )
                db.session.add(order)

            db.session.commit()

            # Provision VPS for the user (creates VPS but does NOT send welcome email)
            plan_level = user.get_plan_level()
            provision_vps_for_user(user, plan_level)

            send_email_async(
                "Welkom bij Trading Engine! 🎉",
                [email],
                f"Je {plan_name} abonnement is nu actief. Log in op {Config.APP_URL}/login",
                f"<h3>Hoi {first_name or 'daar'}!</h3><p>Je {plan_name} abonnement is actief.</p><p>Log in op {Config.APP_URL}/login</p>"
            )

            log_audit(
                user.id, "stripe_payment",
                f"{'Nieuw' if is_new else 'Bijgewerkt'} | {plan_name} | {subscription_type}",
                request.remote_addr
            )

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"[STRIPE] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# DISCORD
# ============================================================================

def assign_discord_role(discord_id):
    try:
        role_url = f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{discord_id}/roles/{Config.DISCORD_ROLE_ID}"
        role_req = urllib.request.Request(role_url, method="PUT")
        role_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
        role_req.add_header("Content-Type", "application/json")
        urllib.request.urlopen(role_req)
        return True
    except Exception as e:
        logger.error(f"[DISCORD] Role assignment failed: {e}")
        return False


@app.route("/connect-discord")
@login_required
def connect_discord():
    if not current_user.is_membership_active():
        flash("Actief abonnement vereist.", "error")
        return redirect(url_for("user_dashboard"))

    if not Config.DISCORD_CLIENT_ID:
        flash("Discord niet geconfigureerd.", "error")
        return redirect(url_for("user_dashboard"))

    params = urllib.parse.urlencode({
        "client_id": Config.DISCORD_CLIENT_ID,
        "redirect_uri": Config.DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds.join"
    })

    return redirect(f"https://discord.com/oauth2/authorize?{params}")


@app.route("/discord/callback")
@login_required
def discord_callback():
    code = request.args.get("code")
    if not code:
        flash("Discord verbinding geannuleerd.", "error")
        return redirect(url_for("user_dashboard"))

    try:
        token_data = urllib.parse.urlencode({
            "client_id": Config.DISCORD_CLIENT_ID,
            "client_secret": Config.DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": Config.DISCORD_REDIRECT_URI
        }).encode()

        token_req = urllib.request.Request(
            "https://discord.com/api/oauth2/token",
            data=token_data,
            method="POST"
        )
        token_req.add_header("Content-Type", "application/x-www-form-urlencoded")
        token_json = json.loads(urllib.request.urlopen(token_req).read())
        access_token = token_json["access_token"]

        user_req = urllib.request.Request("https://discord.com/api/users/@me")
        user_req.add_header("Authorization", f"Bearer {access_token}")
        discord_user = json.loads(urllib.request.urlopen(user_req).read())
        discord_id = discord_user["id"]

        join_data = json.dumps({"access_token": access_token}).encode()
        join_req = urllib.request.Request(
            f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{discord_id}",
            data=join_data,
            method="PUT"
        )
        join_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
        join_req.add_header("Content-Type", "application/json")

        try:
            urllib.request.urlopen(join_req)
        except:
            pass

        assign_discord_role(discord_id)

        current_user.discord_user_id = discord_id
        current_user.discord_joined = True
        db.session.commit()

        flash("Discord verbonden! 🎉", "success")

    except Exception as e:
        logger.error(f"[DISCORD] OAuth failed: {e}", exc_info=True)
        flash("Discord verbinding mislukt.", "error")

    return redirect(url_for("user_dashboard"))


# ============================================================================
# AUTO-INIT DB
# ============================================================================

@app.before_request
def auto_init_db():
    try:
        db.session.execute(db.text("SELECT 1 FROM users LIMIT 1"))
    except Exception:
        try:
            db.create_all()
            logger.info("✅ DB created!")

            admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
            if not User.query.filter_by(email=admin_email).first():
                admin = User(
                    email=admin_email, first_name="Admin", is_admin=True,
                    email_verified=True, membership_status="active",
                    membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin", subscription_type="lifetime",
                    subscription_duration_days=36500
                )
                db.session.add(admin)
                db.session.commit()
        except Exception as e:
            logger.error(f"DB init failed: {e}")


# ============================================================================
# STARTUP
# ============================================================================

with app.app_context():
    run_migrations()

start_auto_cleanup()

logger.info("=" * 80)
logger.info("APPLICATION STARTUP COMPLETE - MT5 ACCOUNT SLOT TRACKING + THINKHUGE VPS READY")
logger.info("=" * 80)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
