"""
Subscription & Licensing Platform
Complete Flask Application with Wix Integration, Stripe Integration, OTP Auth, 
License Management, Discord Integration & ThinkHuge VPS Auto-Provisioning
+ Trading Journal with MT5 Sync Agent Integration
+ MT5 Connector Indicator Management

ACCOUNT SLOT LOGIC:
- Each UNIQUE MT5 account number = 1 slot
- Multiple EAs on same MT5 account share 1 slot
- Slot freed only when ALL EAs on that account are removed
- Heartbeat auto-cleanup for crashed EAs (fully automatic)

FIXED: Proper MT5 account tracking with unique account_number
FIXED: Unlimited validations (max_validations=None skips the check)
FIXED: Heartbeats no longer increment validation_count
FIXED: Cancellation = stop auto-renewal, user keeps full access until paid period ends
FIXED: Cancellation now actually cancels the Stripe subscription (cancel_at_period_end),
       instead of only flipping a local status flag. Previously Stripe kept billing and
       auto-renewing because it was never told to stop, and the next renewal webhook
       would silently re-activate the membership and push membership_end forward again.
ADDED: stripe_subscription_id / stripe_customer_id columns to track the real Stripe
       subscription so it can be cancelled at the source.
ADDED: Stripe customer.subscription.deleted webhook handler for audit-log visibility
       when a cancelled subscription's paid period actually ends at Stripe.
ADDED: Language toggle support (English/Nederlands)
ADDED: "Need Help?" Contact Us support section
ADDED: ThinkHuge VPS auto-provisioning on payment (Basic plan for all levels)
ADDED: VPS auto-termination on membership expiry
ADDED: VPS details display on user dashboard and admin user-detail page
ADDED: VPS RDP port support - IP displayed with port for easy copy-paste
FIXED: ThinkHuge API calls were being blocked by Cloudflare with
       "Error 1010: browser_signature_banned" because urllib's default
       User-Agent ("Python-urllib/3.x") is flagged as a bot by Cloudflare's
       bot-management rules. All ThinkHuge requests now send a real
       browser-like User-Agent (and related headers) to pass the check.
FIXED: Discord OAuth token exchange / API calls (discord_callback,
       assign_discord_role) were failing with a bare "HTTP Error 403: Forbidden"
       for the same reason as the ThinkHuge issue above - Cloudflare fronts
       discord.com too and blocks urllib's default User-Agent. All Discord API
       requests (token exchange, /users/@me, guild join, role assignment) now
       send a browser-like User-Agent. HTTPError responses are also now logged
       with their actual body instead of just the status code.
ADDED: Background retry/backfill sweep that automatically re-attempts VPS
       provisioning for any paid, active user who doesn't yet have a VPS
       (e.g. because a previous provisioning attempt failed).
ADDED: Debug VPS endpoint for admins to diagnose VPS issues
REMOVED: Automatic VPS "credentials ready" / "VPS terminated" emails. VPS
       login details are already visible on the user dashboard and in the
       admin user-detail page, so no email is sent for VPS lifecycle events
       anymore. (License key emails and welcome/cancellation emails are
       unaffected.)
ADDED: Admin can reactivate a CANCELLED membership (not just a revoked one).
       Reactivating a cancelled membership resumes auto-renewal at Stripe
       (cancel_at_period_end=False) and keeps the existing paid period intact.
       Reactivating a revoked membership still grants a fresh paid period,
       same as before.
ADDED: Trading Journal with MT5 Sync Agent integration
ADDED: Journal account management with auto-detection of broker/server/currency
ADDED: One-click sync agent download with pre-embedded token
ADDED: Live dashboard auto-refresh every 60 seconds
ADDED: Calendar view with daily P/L
ADDED: Trade filtering, sorting, and search
ADDED: Weekly P/L chart
ADDED: Comprehensive trade statistics (win rate, profit factor, drawdown, etc.)
ADDED: MT5 Connector Indicator management for admin dashboard
ADDED: MT5 Connector Indicator download on journal page for manual traders
"""

import os
import re
import json
import gzip
import zlib
import hashlib
import secrets
import logging
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import statistics
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from collections import defaultdict

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
    """Application configuration loaded from environment variables."""
    
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///licensing.db")
    if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email configuration (Brevo SMTP)
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp-relay.brevo.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "noreply@tradingengine.nl")

    # Webhook secrets
    WIX_WEBHOOK_SECRET = os.getenv("WIX_WEBHOOK_SECRET", "")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    STRIPE_API_KEY = os.getenv("STRIPE_API_KEY", os.getenv("STRIPE_SECRET_KEY", ""))
    
    # Discord configuration
    DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
    DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "")
    DISCORD_ROLE_ID = os.getenv("DISCORD_ROLE_ID", "")
    DISCORD_INVITE_LINK = os.getenv("DISCORD_INVITE_LINK", "")
    DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
    DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
    DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "")

    # Encryption
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "memory://")

    # Application URLs and settings
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

    # Language support
    LANGUAGES = {
        'en': 'English',
        'nl': 'Nederlands'
    }

    # ThinkHuge VPS API Configuration
    FOREXVPS_API_URL = os.getenv("FOREXVPS_API_URL", "https://api.partners.thinkhuge.net/api/v1")
    FOREXVPS_API_KEY = os.getenv("FOREXVPS_API_KEY", "")

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

    FOREXVPS_LOCATION_ID = os.getenv("FOREXVPS_LOCATION_ID", "").strip() or None
    FOREXVPS_LOCATION_SEARCH = os.getenv("FOREXVPS_LOCATION_SEARCH", "").strip()

    FOREXVPS_OS_TEMPLATE_ID = os.getenv("FOREXVPS_OS_TEMPLATE_ID", "").strip() or None
    FOREXVPS_OS_TEMPLATE_SEARCH = os.getenv("FOREXVPS_OS_TEMPLATE_SEARCH", "Windows 2022").strip()

    FOREXVPS_DEFAULT_RDP_PORT = os.getenv("FOREXVPS_DEFAULT_RDP_PORT", "42014")

    FOREXVPS_RETRY_INTERVAL_SECONDS = int(os.getenv("FOREXVPS_RETRY_INTERVAL_SECONDS", 600))
    FOREXVPS_RETRY_MAX_AGE_MINUTES = int(os.getenv("FOREXVPS_RETRY_MAX_AGE_MINUTES", 1440))

    @staticmethod
    def is_railway():
        """Check if running on Railway.app."""
        return bool(os.getenv("RAILWAY_STATIC_URL"))


# ============================================================================
# APPLICATION INITIALIZATION
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Stripe
if stripe is not None and Config.STRIPE_API_KEY:
    stripe.api_key = Config.STRIPE_API_KEY

# Railway-specific proxy configuration
if Config.is_railway():
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "user_login"
login_manager.login_message = "Log in om deze pagina te bekijken."
CORS(app, supports_credentials=True)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=Config.RATELIMIT_STORAGE_URL
)

# Logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================================
# SHARED HTTP CONSTANTS
# ============================================================================

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DISCORD_BROWSER_USER_AGENT = BROWSER_USER_AGENT

# ============================================================================
# ENCRYPTION SETUP
# ============================================================================

try:
    if Config.ENCRYPTION_KEY:
        encryption_key = Config.ENCRYPTION_KEY.encode() if isinstance(Config.ENCRYPTION_KEY, str) else Config.ENCRYPTION_KEY
        cipher_suite = Fernet(encryption_key)
    else:
        logger.warning("=" * 80)
        logger.warning("⚠️  ENCRYPTION_KEY is not set - using a RANDOM, EPHEMERAL key for this process.")
        logger.warning("⚠️  VPS passwords (and anything else encrypted) will NOT be decryptable")
        logger.warning("⚠️  by other workers or after the next restart. Set a persistent")
        logger.warning("⚠️  ENCRYPTION_KEY env var: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
        logger.warning("=" * 80)
        encryption_key = Fernet.generate_key()
        cipher_suite = Fernet(encryption_key)
except Exception:
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)

# Ensure upload directory exists
Path(Config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

logger.info("=" * 80)
logger.info("APPLICATION STARTING - MT5 ACCOUNT SLOT TRACKING + THINKHUGE VPS + TRADING JOURNAL + CONNECTOR INDICATOR")
logger.info("=" * 80)


# ============================================================================
# LANGUAGE HELPER
# ============================================================================

def get_user_language():
    """Get the user's preferred language from session, user preference, or browser."""
    if 'language' in session:
        return session['language']
    if current_user.is_authenticated and hasattr(current_user, 'language_preference'):
        if current_user.language_preference in Config.LANGUAGES:
            return current_user.language_preference
    browser_lang = request.accept_languages.best_match(Config.LANGUAGES.keys()) if request else 'en'
    return browser_lang or 'en'


@app.context_processor
def inject_globals():
    """Make language variables available to all templates."""
    return {
        'current_language': get_user_language(),
        'supported_languages': Config.LANGUAGES
    }


# ============================================================================
# MODELS
# ============================================================================


class User(UserMixin, db.Model):
    """User model for authentication, membership, and VPS tracking."""
    
    __tablename__ = "users"
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Contact information
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    
    # Account status
    email_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Wix integration
    wix_contact_id = db.Column(db.String(100), nullable=True)
    wix_payment_id = db.Column(db.String(100), unique=True, nullable=True)
    wix_order_id = db.Column(db.String(100), nullable=True)
    
    # Stripe integration
    stripe_subscription_id = db.Column(db.String(100), nullable=True)
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    
    # Membership
    membership_status = db.Column(db.String(20), default="pending", index=True)
    membership_start = db.Column(db.DateTime, nullable=True)
    membership_end = db.Column(db.DateTime, nullable=True)
    subscription_duration_days = db.Column(db.Integer, nullable=True)
    plan_name = db.Column(db.String(100), nullable=True)
    plan_price = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    subscription_type = db.Column(db.String(50), nullable=True)
    
    # Discord
    discord_user_id = db.Column(db.String(100), nullable=True)
    discord_joined = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Security
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Preferences
    language_preference = db.Column(db.String(5), default='en')

    # ThinkHuge VPS fields
    vps_id = db.Column(db.String(100), nullable=True)
    vps_status = db.Column(db.String(20), nullable=True)
    vps_ip = db.Column(db.String(50), nullable=True)
    vps_port = db.Column(db.String(10), nullable=True)
    vps_username = db.Column(db.String(50), nullable=True)
    vps_password = db.Column(db.String(200), nullable=True)
    vps_plan = db.Column(db.String(50), nullable=True)
    vps_created_at = db.Column(db.DateTime, nullable=True)
    vps_terminated_at = db.Column(db.DateTime, nullable=True)
    vps_last_attempt_at = db.Column(db.DateTime, nullable=True)
    vps_last_error = db.Column(db.String(300), nullable=True)
    thinkhuge_user_id = db.Column(db.String(100), nullable=True)

    # Relationships
    otp_tokens = db.relationship("OTPToken", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    licenses = db.relationship("License", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    journal_accounts = db.relationship("JournalAccount", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def is_membership_active(self):
        """Check if the user's membership is currently active."""
        if self.membership_status not in ["active", "cancelled"]:
            return False
        if self.membership_end and self.membership_end < datetime.utcnow():
            self.membership_status = "expired"
            db.session.commit()
            return False
        return True

    def get_active_license(self):
        """Get the user's active license, if any."""
        return self.licenses.filter_by(status="active").first()

    def get_full_name(self):
        """Get the user's full name or fall back to email."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        return self.email

    def get_plan_level(self):
        """Determine the user's plan level based on plan name."""
        if not self.plan_name:
            return 1
        
        # Check for explicit level number
        match = re.search(r'level\s*(\d+)', self.plan_name.lower())
        if match:
            return int(match.group(1))
        
        # Infer from plan name keywords
        plan_lower = self.plan_name.lower()
        if any(word in plan_lower for word in ['starter', 'basic', 'beginner', 'standard']):
            return 1
        elif any(word in plan_lower for word in ['pro', 'advanced', 'intermediate', 'monthly']):
            return 2
        elif any(word in plan_lower for word in ['elite', 'vip', 'premium', 'expert']):
            return 3
        
        return 1

    def get_subscription_type_display(self, lang='en'):
        """Get a human-readable subscription type."""
        if not self.subscription_type:
            return "Standaard" if lang == 'nl' else "Standard"
        
        translations = {
            'lifetime': {'en': 'Lifetime', 'nl': 'Levenslang'},
            'monthly': {'en': 'Monthly', 'nl': 'Maandelijks'},
            'yearly': {'en': 'Yearly', 'nl': 'Jaarlijks'},
            'standard': {'en': 'Standard', 'nl': 'Standaard'}
        }
        return translations.get(self.subscription_type.lower(), {}).get(
            lang, self.subscription_type.title()
        )

    def get_status_display(self, lang='en'):
        """Get a human-readable membership status."""
        translations = {
            'active': {'en': 'ACTIVE', 'nl': 'ACTIEF'},
            'cancelled': {'en': 'CANCELLED', 'nl': 'GEANNULEERD'},
            'expired': {'en': 'EXPIRED', 'nl': 'VERLOPEN'},
            'pending': {'en': 'PENDING', 'nl': 'IN AFWACHTING'},
            'revoked': {'en': 'REVOKED', 'nl': 'INGETROKKEN'}
        }
        return translations.get(self.membership_status, {}).get(
            lang, self.membership_status.upper()
        )

    def to_dict(self):
        """Serialize user to dictionary."""
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.get_full_name(),
            "plan_level": self.get_plan_level(),
            "membership_status": self.membership_status,
            "plan_name": self.plan_name,
            "subscription_type": self.subscription_type,
            "is_active": self.is_membership_active(),
            "language_preference": self.language_preference
        }


class OTPToken(db.Model):
    """One-time password token for login authentication."""
    
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
        """Check if token is still valid."""
        return not self.used and self.expires_at > datetime.utcnow() and self.attempts < 3


class License(db.Model):
    """License key for EA activation."""
    
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

    accounts = db.relationship(
        "LicenseAccount", backref="license", lazy="dynamic", cascade="all, delete-orphan"
    )

    def is_valid(self):
        """Check if license is currently valid."""
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
        """Mask the license key for display."""
        if len(self.license_key) > 8:
            return f"{self.license_key[:4]}...{self.license_key[-4:]}"
        return self.license_key


class LicenseAccount(db.Model):
    """MT5 account linked to a license."""
    
    __tablename__ = "license_accounts"
    
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    activated_at = db.Column(db.DateTime, default=datetime.utcnow)

    sessions = db.relationship(
        "EASession", backref="license_account", lazy="dynamic", cascade="all, delete-orphan"
    )


class EASession(db.Model):
    """Active EA session tracking."""
    
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
    """Order/payment record."""
    
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
    """Audit trail for security events."""
    
    __tablename__ = "audit_logs"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref="audit_logs")


class EAFile(db.Model):
    """Expert Advisor file for download."""
    
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


class MT5ConnectorIndicator(db.Model):
    """Store the MT5 Connector Indicator file for journal download."""
    __tablename__ = 'mt5_connector_indicator'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    download_count = db.Column(db.Integer, default=0)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)


class Setting(db.Model):
    """Application settings key-value store."""
    
    __tablename__ = "settings"
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class JournalAccount(db.Model):
    """Trading journal account linked to an MT5 login."""
    
    __tablename__ = "journal_accounts"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    # Basic info - name is user-defined, rest auto-detected by sync agent
    name = db.Column(db.String(100), nullable=False)
    broker = db.Column(db.String(100), nullable=True)
    prop_firm = db.Column(db.String(100), nullable=True)
    mt5_login = db.Column(db.String(50), nullable=False)
    mt5_server = db.Column(db.String(100), nullable=True)
    currency = db.Column(db.String(10), default="USD")
    starting_balance = db.Column(db.Float, default=0.0)

    # Live balance/equity updated by sync agent
    current_balance = db.Column(db.Float, nullable=True)
    current_equity = db.Column(db.Float, nullable=True)

    # Sync agent configuration
    sync_token = db.Column(db.String(64), unique=True, nullable=False)
    auto_sync = db.Column(db.Boolean, default=True)
    sync_requested_at = db.Column(db.DateTime, nullable=True)
    last_synced_at = db.Column(db.DateTime, nullable=True)
    last_sync_error = db.Column(db.String(300), nullable=True)

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    archived = db.Column(db.Boolean, default=False)

    # Relationships
    trades = db.relationship(
        "JournalTrade", backref="account", lazy="dynamic",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        db.UniqueConstraint("user_id", "mt5_login", name="uq_user_mt5_login"),
    )


class JournalTrade(db.Model):
    """Individual trade record in the trading journal."""
    
    __tablename__ = "journal_trades"
    
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey("journal_accounts.id"), nullable=False, index=True)

    # Trade identification
    mt5_ticket = db.Column(db.String(50), nullable=False)
    symbol = db.Column(db.String(20), nullable=False)
    trade_type = db.Column(db.String(10), nullable=False)  # 'buy' or 'sell'
    volume = db.Column(db.Float, nullable=False)

    # Price levels
    entry_price = db.Column(db.Float, nullable=True)
    sl = db.Column(db.Float, nullable=True)
    tp = db.Column(db.Float, nullable=True)
    exit_price = db.Column(db.Float, nullable=True)

    # Timing
    open_time = db.Column(db.DateTime, nullable=True)
    close_time = db.Column(db.DateTime, nullable=False, index=True)

    # Results
    profit = db.Column(db.Float, nullable=False, default=0.0)
    pips = db.Column(db.Float, nullable=True)
    magic_number = db.Column(db.Integer, nullable=True)
    comment = db.Column(db.String(200), nullable=True)

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("account_id", "mt5_ticket", name="uq_account_ticket"),
    )

    def duration_seconds(self):
        """Calculate trade duration in seconds."""
        if self.open_time and self.close_time:
            return int((self.close_time - self.open_time).total_seconds())
        return None

    def duration_display(self):
        """Format duration as human-readable string."""
        secs = self.duration_seconds()
        if secs is None:
            return "—"
        h, rem = divmod(secs, 3600)
        m, _ = divmod(rem, 60)
        return f"{h}h {m}m" if h else f"{m}m"


# ============================================================================
# THINKHUGE VPS API CLIENT
# ============================================================================

class ForexVPSClient:
    """
    Client for ThinkHuge.net VPS provisioning API.
    Handles server creation, management, and termination.
    """

    BROWSER_USER_AGENT = BROWSER_USER_AGENT

    def __init__(self):
        self.api_url = Config.FOREXVPS_API_URL.rstrip('/')
        self.api_key = Config.FOREXVPS_API_KEY
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': self.BROWSER_USER_AGENT,
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

    def is_configured(self):
        """Check if the VPS API is properly configured."""
        return bool(self.api_key)

    def _request(self, path, method="GET", payload=None, timeout=120):
        """Make an HTTP request to the ThinkHuge API."""
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            headers=self.headers,
            method=method
        )
        return urllib.request.urlopen(req, timeout=timeout)

    @staticmethod
    def _read_json(response):
        """Read and parse JSON response, handling gzip/deflate encoding."""
        raw = response.read()
        encoding = (response.headers.get("Content-Encoding") or "").lower()
        if encoding == "gzip":
            raw = gzip.decompress(raw)
        elif encoding == "deflate":
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        return json.loads(raw.decode("utf-8"))

    @staticmethod
    def _error_detail(e):
        """Extract error details from HTTPError response."""
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

    def _list(self, path, search=None, per_page=100):
        """List resources with optional search filter."""
        query = f"?per_page={per_page}"
        if search:
            query += f"&filter[search]={urllib.parse.quote(search)}"
        response = self._request(f"{path}{query}", method="GET", timeout=30)
        result = self._read_json(response)
        return result.get("data", [])

    def list_locations(self, search=None):
        """List available VPS locations."""
        return self._list("/locations", search=search)

    def list_os_templates(self, search=None):
        """List available OS templates."""
        return self._list("/os_templates", search=search)

    def list_plans(self, search=None):
        """List available VPS plans."""
        return self._list("/plans", search=search)

    def find_location_id(self):
        """Find the best location ID, using cache or config override."""
        if Config.FOREXVPS_LOCATION_ID:
            return Config.FOREXVPS_LOCATION_ID
        if getattr(self, "_location_id_cache", None):
            return self._location_id_cache
        locations = self.list_locations(search=Config.FOREXVPS_LOCATION_SEARCH or None)
        if not locations:
            locations = self.list_locations()
        if not locations:
            raise ValueError("No ThinkHuge locations available from /v1/locations")
        self._location_id_cache = locations[0]["id"]
        logger.info(f"[ThinkHuge] Resolved location_id={self._location_id_cache} ({locations[0].get('name')})")
        return self._location_id_cache

    def find_os_template_id(self):
        """Find the best OS template ID."""
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
        """Find the best plan ID for a given plan level."""
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
        """Get existing ThinkHuge user ID or create a new one."""
        query = f"?filter[email]={urllib.parse.quote(email)}"
        response = self._request(f"/users{query}", method="GET", timeout=30)
        result = self._read_json(response)
        existing = result.get("data", [])
        if existing:
            return existing[0]["id"]

        username = re.sub(r'[^a-zA-Z0-9_.-]', '', email.split('@')[0])[:30] or f"user{secrets.token_hex(4)}"
        payload = {
            "username": username,
            "name": name or username,
            "email": email,
        }
        response = self._request("/users", method="POST", payload=payload, timeout=30)
        result = self._read_json(response)
        return result["data"]["id"]

    def create_server(self, user_id, location_id, os_template_id, plan_id, hostname):
        """Create a new VPS server."""
        payload = {
            "user_id": user_id,
            "location_id": location_id,
            "os_template_id": os_template_id,
            "plan_id": plan_id,
            "hostname": hostname[:50],
        }
        response = self._request("/servers", method="POST", payload=payload, timeout=120)
        result = self._read_json(response)
        return result["data"]

    def get_server(self, server_id):
        """Get server details by ID."""
        response = self._request(f"/servers/{server_id}", method="GET", timeout=30)
        result = self._read_json(response)
        return result["data"]

    def reset_password(self, server_id):
        """Reset the server password and return the new one."""
        response = self._request(f"/servers/{server_id}/reset-password", method="POST", payload={}, timeout=60)
        result = self._read_json(response)
        return result["password"]

    def create_vps(self, plan_level, email, name="", hostname=""):
        """Provision a complete VPS for a user."""
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
                try:
                    password = self.reset_password(server_id)
                except urllib.error.HTTPError as e:
                    logger.warning(
                        f"[ThinkHuge] Server {server_id} has an IP but password fetch failed: "
                        f"{e.code} - {self._error_detail(e)}"
                    )
                except Exception as e:
                    logger.warning(f"[ThinkHuge] Server {server_id} has an IP but password fetch failed: {e}")

            return {
                "success": True,
                "server_id": server_id,
                "user_id": user_id,
                "ip": ip,
                "username": "trader",
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
        """Terminate a VPS server."""
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


# Initialize the VPS client
forexvps_client = ForexVPSClient()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def encrypt_data(data):
    """Encrypt sensitive data using Fernet symmetric encryption."""
    if not data:
        return None
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception:
        return data


def decrypt_data(data):
    """Decrypt data that was encrypted with encrypt_data."""
    if not data:
        return None
    try:
        return cipher_suite.decrypt(data.encode()).decode()
    except Exception:
        logger.warning("[decrypt_data] Failed to decrypt a stored value - key may have changed since it was encrypted")
        return None


def generate_license_key():
    """Generate a unique license key in format XXXX-XXXX-XXXX."""
    return "-".join([secrets.token_hex(2).upper() for _ in range(3)])


def generate_otp():
    """Generate a 6-digit OTP code."""
    return "".join([str(secrets.randbelow(10)) for _ in range(6)])


def parse_duration_to_days(duration_str):
    """Parse a duration string into days and subscription type."""
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
    """Parse a date string from Wix in various formats."""
    if not date_str:
        return None
    if "annulering" in date_str.lower():
        return None
    
    for fmt in ["%d-%m-%Y", "%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y", "%m-%d-%Y"]:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return None


def send_email_async(subject, recipients, body, html_body=None):
    """Send an email asynchronously in a background thread."""
    def send():
        try:
            with app.app_context():
                msg = Message(
                    subject=subject,
                    recipients=recipients,
                    body=body,
                    html=html_body
                )
                mail.send(msg)
                logger.info(f"[EMAIL] Sent to {recipients}: {subject}")
        except Exception as e:
            logger.error(f"[EMAIL] Failed: {e}")
    
    threading.Thread(target=send).start()


def log_audit(user_id, action, details=None, ip_address=None):
    """Log an audit event to the database."""
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address or (request.remote_addr if request else "system")
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"[AUDIT] Failed: {e}")


def allowed_file(filename):
    """Check if a file has an allowed extension for EA uploads."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"ex4", "ex5", "dll", "zip"}


def get_max_accounts_for_level(plan_level):
    """Get the maximum number of MT5 accounts allowed for a plan level."""
    if plan_level <= 1:
        return 2
    elif plan_level == 2:
        return 4
    elif plan_level == 3:
        return 8
    else:
        return 10


def get_plan_level_display(plan_level):
    """Get a human-readable plan level display string."""
    level_names = {1: "LVL 1", 2: "LVL 2", 3: "LVL 3", 4: "PREMIUM"}
    return level_names.get(plan_level, f"LVL {plan_level}")


def format_date_dutch(date_obj):
    """Format a date in Dutch format."""
    if not date_obj:
        return "N/B"
    months_nl = [
        "januari", "februari", "maart", "april", "mei", "juni",
        "juli", "augustus", "september", "oktober", "november", "december"
    ]
    return f"{date_obj.day} {months_nl[date_obj.month - 1]} {date_obj.year}"


def format_date_english(date_obj):
    """Format a date in English format."""
    if not date_obj:
        return "N/A"
    return date_obj.strftime("%B %d, %Y")


# ============================================================================
# JOURNAL HELPER FUNCTIONS
# ============================================================================

def compute_journal_stats(trades):
    """
    Compute aggregate statistics from a list of JournalTrade objects.
    
    Args:
        trades: List of JournalTrade objects
        
    Returns:
        Dictionary with comprehensive trade statistics
    """
    if not trades:
        return {
            "total_trades": 0,
            "wins": 0,
            "losses": 0,
            "breakeven": 0,
            "win_rate": 0.0,
            "profit_factor": 0.0,
            "expectancy": 0.0,
            "net_profit": 0.0,
            "avg_win": 0.0,
            "avg_loss": 0.0,
            "largest_win": 0.0,
            "largest_loss": 0.0,
            "gross_profit": 0.0,
            "gross_loss": 0.0,
            "avg_rr": 0.0,
            "longest_win_streak": 0,
            "longest_loss_streak": 0,
            "avg_duration_seconds": 0,
        }

    # Categorize trades
    wins = [t for t in trades if t.profit > 0]
    losses = [t for t in trades if t.profit < 0]
    breakeven = [t for t in trades if t.profit == 0]

    # Profit calculations
    gross_profit = sum(t.profit for t in wins)
    gross_loss = abs(sum(t.profit for t in losses))
    net_profit = sum(t.profit for t in trades)

    # Win rate
    win_rate = (len(wins) / len(trades)) * 100 if trades else 0.0

    # Profit factor
    if gross_loss > 0:
        profit_factor = gross_profit / gross_loss
    elif gross_profit > 0:
        profit_factor = gross_profit
    else:
        profit_factor = 0.0

    # Expectancy
    expectancy = net_profit / len(trades) if trades else 0.0

    # Average win/loss
    avg_win = (gross_profit / len(wins)) if wins else 0.0
    avg_loss = (-gross_loss / len(losses)) if losses else 0.0
    avg_rr = abs(avg_win / avg_loss) if avg_loss else 0.0

    # Win/loss streaks
    ordered = sorted(trades, key=lambda t: t.close_time)
    longest_win_streak = 0
    longest_loss_streak = 0
    cur_win = 0
    cur_loss = 0
    
    for t in ordered:
        if t.profit > 0:
            cur_win += 1
            cur_loss = 0
            longest_win_streak = max(longest_win_streak, cur_win)
        elif t.profit < 0:
            cur_loss += 1
            cur_win = 0
            longest_loss_streak = max(longest_loss_streak, cur_loss)
        else:
            cur_win = 0
            cur_loss = 0

    # Average duration
    durations = [t.duration_seconds() for t in trades if t.duration_seconds() is not None]
    avg_duration = int(statistics.mean(durations)) if durations else 0

    return {
        "total_trades": len(trades),
        "wins": len(wins),
        "losses": len(losses),
        "breakeven": len(breakeven),
        "win_rate": round(win_rate, 2),
        "profit_factor": round(profit_factor, 2),
        "expectancy": round(expectancy, 2),
        "net_profit": round(net_profit, 2),
        "avg_win": round(avg_win, 2),
        "avg_loss": round(avg_loss, 2),
        "largest_win": round(max((t.profit for t in trades), default=0.0), 2),
        "largest_loss": round(min((t.profit for t in trades), default=0.0), 2),
        "gross_profit": round(gross_profit, 2),
        "gross_loss": round(gross_loss, 2),
        "avg_rr": round(avg_rr, 2),
        "longest_win_streak": longest_win_streak,
        "longest_loss_streak": longest_loss_streak,
        "avg_duration_seconds": avg_duration,
    }


def journal_daily_pl_map(trades):
    """
    Create a dictionary mapping dates to daily profit/loss totals.
    
    Args:
        trades: List of JournalTrade objects
        
    Returns:
        Dictionary with date strings as keys and P/L floats as values
    """
    out = defaultdict(float)
    for t in trades:
        out[t.close_time.strftime("%Y-%m-%d")] += t.profit
    return dict(out)


def journal_max_drawdown(trades, starting_balance):
    """
    Calculate maximum drawdown from a list of trades.
    
    Args:
        trades: List of JournalTrade objects sorted by close_time
        starting_balance: Initial account balance
        
    Returns:
        Tuple of (max_drawdown_amount, max_drawdown_percentage)
    """
    ordered = sorted(trades, key=lambda t: t.close_time)
    equity = starting_balance
    peak = starting_balance
    max_dd = 0.0
    max_dd_pct = 0.0
    
    for t in ordered:
        equity += t.profit
        peak = max(peak, equity)
        dd = peak - equity
        dd_pct = (dd / peak * 100) if peak > 0 else 0
        max_dd = max(max_dd, dd)
        max_dd_pct = max(max_dd_pct, dd_pct)
    
    return round(max_dd, 2), round(max_dd_pct, 2)


def get_selected_journal_account(requested_id=None):
    """
    Resolve which JournalAccount is currently active for the logged-in user.
    
    Priority:
    1. Explicitly requested account_id
    2. Last used account_id from session
    3. First available account
    
    Args:
        requested_id: Optional account ID to select
        
    Returns:
        JournalAccount object or None
    """
    account = None
    
    if requested_id:
        account = JournalAccount.query.filter_by(
            id=requested_id, user_id=current_user.id, archived=False
        ).first()
    
    if not account:
        last_id = session.get("journal_account_id")
        if last_id:
            account = JournalAccount.query.filter_by(
                id=last_id, user_id=current_user.id, archived=False
            ).first()
    
    if not account:
        account = JournalAccount.query.filter_by(
            user_id=current_user.id, archived=False
        ).order_by(JournalAccount.created_at).first()
    
    if account:
        session["journal_account_id"] = account.id
    
    return account


# ============================================================================
# VPS PROVISIONING FUNCTIONS
# ============================================================================

def try_complete_pending_vps(user):
    """
    Check if a provisioning VPS has become ready and update user record.
    
    Args:
        user: User object with vps_status='provisioning'
        
    Returns:
        True if VPS is now ready, False otherwise
    """
    if not user.vps_id:
        return False

    try:
        server = forexvps_client.get_server(user.vps_id)
        ip = server.get("primary_ip_address")

        if not ip:
            logger.info(f"[ThinkHuge] {user.email}: server {user.vps_id} still has no IP yet")
            return False

        password = forexvps_client.reset_password(user.vps_id)
        rdp_port = server.get("rdp_port") or server.get("port") or Config.FOREXVPS_DEFAULT_RDP_PORT

        user.vps_ip = ip
        user.vps_port = str(rdp_port)
        user.vps_username = "trader"
        user.vps_password = encrypt_data(password)
        user.vps_status = 'active'
        user.vps_last_error = None
        db.session.commit()

        logger.info(f"[ThinkHuge] VPS now ready for {user.email}: {user.vps_id} | IP: {ip}:{rdp_port}")
        return True

    except urllib.error.HTTPError as e:
        detail = forexvps_client._error_detail(e)
        logger.warning(f"[ThinkHuge] Completion check failed for {user.email} ({user.vps_id}): {e.code} - {detail}")
        user.vps_last_error = f"{e.code} - {detail}"[:300]
        db.session.commit()
        return False
    except Exception as e:
        logger.warning(f"[ThinkHuge] Completion check error for {user.email} ({user.vps_id}): {e}")
        user.vps_last_error = str(e)[:300]
        db.session.commit()
        return False


def provision_vps_for_user(user, plan_level):
    """
    Provision a VPS for a user if they don't already have one.
    
    Args:
        user: User object
        plan_level: Integer plan level (1, 2, or 3)
        
    Returns:
        True if VPS is active, False otherwise
    """
    if not forexvps_client.is_configured():
        logger.info(f"[ThinkHuge] Skipping VPS provisioning - API not configured")
        return False

    # Already has active VPS
    if user.vps_id and user.vps_status == 'active':
        logger.info(f"[ThinkHuge] User {user.email} already has active VPS: {user.vps_id}")
        return True

    # VPS is provisioning - check if ready
    if user.vps_id and user.vps_status == 'provisioning':
        user.vps_last_attempt_at = datetime.utcnow()
        db.session.commit()
        logger.info(f"[ThinkHuge] User {user.email} VPS {user.vps_id} already provisioning, checking if ready")
        return try_complete_pending_vps(user)

    # Create new VPS
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
        logger.error(f"[ThinkHuge] Failed to provision VPS for {user.email}: {result.get('error')}")
        return False

    user.vps_id = result.get('server_id')
    user.thinkhuge_user_id = result.get('user_id') or user.thinkhuge_user_id
    user.vps_plan = vps_plan_name
    user.vps_created_at = datetime.utcnow()
    user.vps_last_error = None

    if result.get('ready'):
        user.vps_status = 'active'
        user.vps_ip = result.get('ip')
        user.vps_port = Config.FOREXVPS_DEFAULT_RDP_PORT
        user.vps_username = result.get('username')
        user.vps_password = encrypt_data(result.get('password', ''))
        db.session.commit()
        logger.info(f"[ThinkHuge] VPS provisioned and ready for {user.email}: {user.vps_id} | IP: {user.vps_ip}:{user.vps_port}")
        return True
    else:
        user.vps_status = 'provisioning'
        db.session.commit()
        logger.info(
            f"[ThinkHuge] VPS creation started for {user.email}: {user.vps_id} "
            f"(status={result.get('status')}) - still provisioning"
        )
        return False


def poll_pending_vps_servers():
    """Poll all provisioning VPS servers to check if they're ready."""
    if not forexvps_client.is_configured():
        return

    try:
        pending_users = User.query.filter(
            User.vps_status == 'provisioning',
            User.vps_id.isnot(None),
        ).all()

        if not pending_users:
            return

        logger.info(f"[ThinkHuge] Polling {len(pending_users)} pending VPS server(s)")

        for user in pending_users:
            try_complete_pending_vps(user)

    except Exception as e:
        logger.error(f"[ThinkHuge] Error in poll_pending_vps_servers: {e}")
        db.session.rollback()


def retry_pending_vps_provisioning():
    """Retry VPS provisioning for users who don't have one yet."""
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

        logger.info(f"[ThinkHuge] Retry sweep: {len(candidates)} user(s) missing an active VPS")

        for user in candidates:
            if user.membership_start:
                age_minutes = (datetime.utcnow() - user.membership_start).total_seconds() / 60
                if age_minutes > Config.FOREXVPS_RETRY_MAX_AGE_MINUTES:
                    logger.warning(
                        f"[ThinkHuge] Giving up auto-retry for {user.email} "
                        f"(pending {age_minutes:.0f}min, last_error={user.vps_last_error}). "
                        f"Needs manual admin attention."
                    )
                    continue

            plan_level = user.get_plan_level()
            success = provision_vps_for_user(user, plan_level)

            if success:
                logger.info(f"[ThinkHuge] Retry succeeded for {user.email}")
            elif user.vps_status == 'provisioning':
                logger.info(f"[ThinkHuge] Retry created server for {user.email}, now provisioning")
            else:
                logger.warning(f"[ThinkHuge] Retry still failing for {user.email}: {user.vps_last_error}")

    except Exception as e:
        logger.error(f"[ThinkHuge] Error in retry_pending_vps_provisioning: {e}")
        db.session.rollback()


# ============================================================================
# AUTO-CLEANUP FUNCTIONS
# ============================================================================

def cleanup_expired_vps():
    """Terminate VPS for users with expired memberships."""
    try:
        expired_users = User.query.filter(
            User.membership_end < datetime.utcnow(),
            User.membership_status.in_(['expired', 'cancelled']),
            User.vps_id.isnot(None),
            User.vps_status == 'active'
        ).all()

        for user in expired_users:
            logger.info(f"[ThinkHuge] Terminating VPS for expired membership: {user.email}")

            result = forexvps_client.terminate_vps(user.vps_id)

            if result.get('success'):
                user.vps_status = 'terminated'
                user.vps_terminated_at = datetime.utcnow()
                db.session.commit()
                logger.info(f"[ThinkHuge] VPS terminated for {user.email}")
            else:
                logger.error(f"[ThinkHuge] Failed to terminate VPS for {user.email}: {result.get('error')}")

    except Exception as e:
        logger.error(f"[ThinkHuge] Error in cleanup_expired_vps: {e}")
        db.session.rollback()


def cleanup_stale_sessions():
    """Remove stale EA sessions that haven't sent a heartbeat."""
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

            logger.info(f"Auto-clean: session={ea_session.session_id[:8]}... account={acct_num} inactive={inactive_mins:.0f}min")

            db.session.delete(ea_session)
            cleaned += 1

            if account and account.sessions.count() <= 1:
                logger.info(f"Slot freed: MT5 account={acct_num}")
                db.session.delete(account)
                freed += 1

        if cleaned > 0:
            db.session.commit()
            logger.info(f"Auto-cleanup: {cleaned} sessions removed, {freed} slots freed")

    except Exception as e:
        logger.error(f"Auto-cleanup error: {e}")
        db.session.rollback()

    # Also run VPS cleanup
    cleanup_expired_vps()
    poll_pending_vps_servers()
    retry_pending_vps_provisioning()


def start_auto_cleanup():
    """Start the background auto-cleanup thread."""
    def job():
        while True:
            time.sleep(300)  # Run every 5 minutes
            with app.app_context():
                cleanup_stale_sessions()

    threading.Thread(target=job, daemon=True).start()
    logger.info(f"Auto-cleanup started (timeout: {Config.HEARTBEAT_TIMEOUT_MINUTES}min)")


# ============================================================================
# DATABASE MIGRATIONS
# ============================================================================

def run_migrations():
    """Run database migrations to ensure all tables and columns exist."""
    try:
        with app.app_context():
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()

            # Create ea_sessions table if missing
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
                logger.info("ea_sessions table created")

            # Create journal_accounts table if missing
            if 'journal_accounts' not in existing_tables:
                logger.info("Creating journal_accounts table...")
                db.session.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS journal_accounts (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        name VARCHAR(100) NOT NULL,
                        broker VARCHAR(100),
                        prop_firm VARCHAR(100),
                        mt5_login VARCHAR(50) NOT NULL,
                        mt5_server VARCHAR(100),
                        currency VARCHAR(10) DEFAULT 'USD',
                        starting_balance FLOAT DEFAULT 0.0,
                        current_balance FLOAT,
                        current_equity FLOAT,
                        sync_token VARCHAR(64) UNIQUE NOT NULL,
                        auto_sync BOOLEAN DEFAULT TRUE,
                        sync_requested_at TIMESTAMP,
                        last_synced_at TIMESTAMP,
                        last_sync_error VARCHAR(300),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        archived BOOLEAN DEFAULT FALSE,
                        CONSTRAINT uq_user_mt5_login UNIQUE (user_id, mt5_login)
                    )
                """))
                db.session.commit()
                logger.info("journal_accounts table created")

            # Create journal_trades table if missing
            if 'journal_trades' not in existing_tables:
                logger.info("Creating journal_trades table...")
                db.session.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS journal_trades (
                        id SERIAL PRIMARY KEY,
                        account_id INTEGER NOT NULL REFERENCES journal_accounts(id) ON DELETE CASCADE,
                        mt5_ticket VARCHAR(50) NOT NULL,
                        symbol VARCHAR(20) NOT NULL,
                        trade_type VARCHAR(10) NOT NULL,
                        volume FLOAT NOT NULL,
                        entry_price FLOAT,
                        sl FLOAT,
                        tp FLOAT,
                        exit_price FLOAT,
                        open_time TIMESTAMP,
                        close_time TIMESTAMP NOT NULL,
                        profit FLOAT NOT NULL DEFAULT 0.0,
                        pips FLOAT,
                        magic_number INTEGER,
                        comment VARCHAR(200),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT uq_account_ticket UNIQUE (account_id, mt5_ticket)
                    )
                """))
                db.session.commit()
                logger.info("journal_trades table created")

            # Create mt5_connector_indicator table if missing
            if 'mt5_connector_indicator' not in existing_tables:
                logger.info("Creating mt5_connector_indicator table...")
                db.session.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS mt5_connector_indicator (
                        id SERIAL PRIMARY KEY,
                        filename VARCHAR(255) NOT NULL,
                        file_path VARCHAR(500) NOT NULL,
                        version VARCHAR(50) NOT NULL,
                        description TEXT,
                        download_count INTEGER DEFAULT 0,
                        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        uploaded_by INTEGER REFERENCES users(id)
                    )
                """))
                db.session.commit()
                logger.info("mt5_connector_indicator table created")

            # Add missing columns to users table
            columns = [col['name'] for col in inspector.get_columns('users')]
            
            if 'language_preference' not in columns:
                db.session.execute(db.text("""
                    ALTER TABLE users ADD COLUMN language_preference VARCHAR(5) DEFAULT 'en'
                """))
                db.session.commit()
                logger.info("language_preference column added")

            # VPS columns
            vps_columns = [
                'vps_id', 'vps_status', 'vps_ip', 'vps_port', 'vps_username', 'vps_password',
                'vps_plan', 'vps_created_at', 'vps_terminated_at',
                'vps_last_attempt_at', 'vps_last_error', 'thinkhuge_user_id',
            ]
            for col_name in vps_columns:
                if col_name not in columns:
                    if col_name in ('vps_id', 'vps_password', 'thinkhuge_user_id'):
                        col_type = 'VARCHAR(100)'
                    elif col_name == 'vps_last_error':
                        col_type = 'VARCHAR(300)'
                    elif col_name in ('vps_ip', 'vps_username', 'vps_plan', 'vps_status', 'vps_port'):
                        col_type = 'VARCHAR(50)'
                    else:
                        col_type = 'TIMESTAMP'
                    logger.info(f"Adding {col_name} column to users table...")
                    db.session.execute(db.text(f"""
                        ALTER TABLE users ADD COLUMN {col_name} {col_type}
                    """))
                    db.session.commit()
                    logger.info(f"{col_name} column added")

            # Stripe columns
            stripe_columns = ['stripe_subscription_id', 'stripe_customer_id']
            for col_name in stripe_columns:
                if col_name not in columns:
                    logger.info(f"Adding {col_name} column to users table...")
                    db.session.execute(db.text(f"""
                        ALTER TABLE users ADD COLUMN {col_name} VARCHAR(100)
                    """))
                    db.session.commit()
                    logger.info(f"{col_name} column added")

            # Fix bad licenses (max_accounts null or <= 0)
            bad_licenses = License.query.filter(
                (License.max_accounts == None) | (License.max_accounts <= 0)
            ).all()

            for lic in bad_licenses:
                user = lic.user
                if user:
                    user_level = user.get_plan_level()
                    correct_max = get_max_accounts_for_level(user_level)
                    logger.warning(f"FIXING license {lic.mask_license_key()}: max_accounts {lic.max_accounts} -> {correct_max}")
                    lic.max_accounts = correct_max

            if bad_licenses:
                db.session.commit()
                logger.info(f"Fixed {len(bad_licenses)} licenses")

            # Remove validation limits
            capped_licenses = License.query.filter(
                License.max_validations != None
            ).all()

            if capped_licenses:
                for lic in capped_licenses:
                    lic.max_validations = None
                    lic.validation_count = 0
                db.session.commit()
                logger.info(f"Removed validation limits from {len(capped_licenses)} existing licenses")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        db.session.rollback()


# ============================================================================
# DECORATORS
# ============================================================================

def admin_required(f):
    """Decorator to require admin access for a route."""
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
    """Load a user by ID for Flask-Login."""
    return db.session.get(User, int(user_id))


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    if request.path.startswith("/api/"):
        return jsonify({"error": "Niet gevonden"}), 404
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    db.session.rollback()
    logger.error(f"500 Error: {e}", exc_info=True)
    if request.path.startswith("/api/"):
        return jsonify({"error": "Server fout"}), 500
    return render_template("errors/500.html"), 500


# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.route("/")
def index():
    """Redirect to appropriate dashboard based on auth status."""
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard") if current_user.is_admin else url_for("user_dashboard"))
    return redirect(url_for("user_login"))


@app.route("/health")
def health():
    """Health check endpoint with key metrics."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_licenses": License.query.filter_by(status="active").count(),
        "active_accounts": LicenseAccount.query.count(),
        "active_sessions": EASession.query.count(),
        "active_vps": User.query.filter_by(vps_status='active').count(),
        "journal_accounts": JournalAccount.query.filter_by(archived=False).count(),
        "journal_trades": JournalTrade.query.count()
    })


# ============================================================================
# LANGUAGE ROUTES
# ============================================================================

@app.route("/set-language/<lang>")
def set_language(lang):
    """Set the user's language preference via URL."""
    if lang in Config.LANGUAGES:
        session['language'] = lang
        if current_user.is_authenticated:
            current_user.language_preference = lang
            db.session.commit()
        logger.info(f"[LANG] Language set to: {lang}")
    return redirect(request.referrer or url_for('index'))


@app.route("/api/set-language", methods=["POST"])
def api_set_language():
    """Set the user's language preference via API."""
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
    """User login with email OTP authentication."""
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard") if current_user.is_admin else url_for("user_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        try:
            email = validate_email(email).email
        except EmailNotValidError:
            flash("Ongeldig e-mailadres.", "error")
            return render_template("user/login.html")

        # Check if this is the admin email
        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
        if email == admin_email:
            session["admin_email"] = email
            return redirect(url_for("admin_password"))

        # Find user
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

        # Generate and send OTP
        try:
            OTPToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(
                user_id=user.id,
                token=otp,
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
    """Admin password verification before OTP."""
    admin_email = session.get("admin_email") or os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
    admin_user = User.query.filter_by(email=admin_email).first()

    if admin_user and admin_user.locked_until and admin_user.locked_until > datetime.utcnow():
        session.pop("admin_email", None)
        flash("Admin account vergrendeld.", "error")
        return redirect(url_for("user_login"))

    if request.method == "POST":
        if request.form.get("password") == os.getenv("ADMIN_PASSWORD", "admin123").strip():
            # Create or update admin user
            if not admin_user:
                admin_user = User(
                    email=admin_email,
                    first_name="Admin",
                    is_admin=True,
                    email_verified=True,
                    membership_status="active",
                    membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin",
                    subscription_type="lifetime",
                    subscription_duration_days=36500
                )
                db.session.add(admin_user)
            else:
                admin_user.login_attempts = 0
                admin_user.locked_until = None
                admin_user.is_admin = True
            db.session.commit()

            # Generate admin OTP
            OTPToken.query.filter_by(user_id=admin_user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(
                user_id=admin_user.id,
                token=otp,
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
    """Verify OTP code and log the user in."""
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

        otp_token = OTPToken.query.filter_by(
            user_id=user.id, used=False
        ).order_by(OTPToken.created_at.desc()).first()
        
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

            # Successful verification
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
    """Log out the current user."""
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
    """Main user dashboard with membership, license, EA, VPS, and Discord info."""
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    user = current_user
    license = user.get_active_license()
    user_level = user.get_plan_level()

    # Get available EA files for user's plan level
    ea_files = EAFile.query.filter(
        EAFile.is_active == True,
        EAFile.plan_level <= user_level
    ).order_by(EAFile.upload_date.desc()).all()

    all_ea_count = EAFile.query.filter_by(is_active=True).count()

    # License account tracking
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

    # Days remaining
    days_remaining = None
    if user.membership_end and user.membership_status in ["active", "cancelled"]:
        delta = user.membership_end - datetime.utcnow()
        days_remaining = max(0, delta.days)

    # VPS password
    vps_password_decrypted = None
    if user.vps_id and user.vps_password:
        try:
            vps_password_decrypted = decrypt_data(user.vps_password)
        except Exception:
            vps_password_decrypted = None

    # Get connector indicator info
    connector = MT5ConnectorIndicator.query.first()

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
        vps_password_decrypted=vps_password_decrypted,
        vps_default_port=Config.FOREXVPS_DEFAULT_RDP_PORT,
        indicator_download_url=url_for('download_connector') if connector else None,
        indicator_version=connector.version if connector else '1.0',
        webrequest_url=Config.APP_URL
    )

# ============================================================================
# GENERATE LICENSE
# ============================================================================

@app.route("/generate-license", methods=["POST"])
@login_required
@limiter.limit("3 per day")
def generate_license():
    """Generate a new license key for the user."""
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
        return jsonify({
            "error": "Je hebt al een actieve licentie" if lang == 'nl' else "You already have an active license"
        }), 400

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

        logger.info(
            f"[LICENSE GEN] {lic.mask_license_key()} | max_acc={max_accounts} | "
            f"level={user_level} | unlimited validations"
        )

        log_audit(
            current_user.id,
            "license_generated",
            f"{lic.mask_license_key()} | level={user_level} | max_acc={max_accounts}",
            request.remote_addr
        )

        # Send license email
        if lang == 'nl':
            send_email_async(
                "Jouw Licentiesleutel - Trading Engine",
                [current_user.email],
                f"Licentiesleutel: {key}\nVerloopt: {format_date_dutch(lic.expires_at)}\nMax MT5 Accounts: {max_accounts}",
                f"<h3>Jouw Licentiesleutel</h3><p><strong>{key}</strong></p><p>Verloopt: {format_date_dutch(lic.expires_at)}</p>"
            )
        else:
            send_email_async(
                "Your License Key - Trading Engine",
                [current_user.email],
                f"License Key: {key}\nExpires: {format_date_english(lic.expires_at)}\nMax MT5 Accounts: {max_accounts}",
                f"<h3>Your License Key</h3><p><strong>{key}</strong></p><p>Expires: {format_date_english(lic.expires_at)}</p>"
            )

        # Provision VPS if needed
        if not (current_user.vps_id and current_user.vps_status == 'active'):
            provision_vps_for_user(current_user, current_user.get_plan_level())

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
        return jsonify({
            "error": "Kon licentie niet genereren" if lang == 'nl' else "Failed to generate license"
        }), 500


# ============================================================================
# CANCEL MEMBERSHIP
# ============================================================================

@app.route("/cancel-membership", methods=["POST"])
@login_required
@limiter.limit("5 per day")
def cancel_membership():
    """Cancel membership auto-renewal at Stripe while preserving access until period end."""
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

        # Cancel at Stripe
        if user.stripe_subscription_id:
            if stripe is None:
                logger.error("[CANCEL] Stripe library not installed")
                return jsonify({"error": "Configuration error"}), 500
            try:
                stripe.Subscription.modify(
                    user.stripe_subscription_id,
                    cancel_at_period_end=True,
                )
                logger.info(f"[CANCEL] Stripe subscription {user.stripe_subscription_id} set to cancel_at_period_end for {user.email}")
            except stripe.error.InvalidRequestError as e:
                logger.warning(f"[CANCEL] Stripe subscription could not be modified: {e}")
            except Exception as e:
                logger.error(f"[CANCEL] Stripe API error: {e}")
                db.session.rollback()
                return jsonify({"error": "Failed to cancel with payment provider"}), 502

        user.membership_status = "cancelled"
        db.session.commit()

        # Send confirmation email
        formatted_date_nl = format_date_dutch(membership_end_date) if membership_end_date else "de eerstvolgende verlengdatum"
        formatted_date_en = format_date_english(membership_end_date) if membership_end_date else "the next renewal date"

        send_email_async(
            "Bevestiging van je opzegging",
            [user.email],
            f"Je opzegging is succesvol verwerkt. Je membership blijft actief tot {formatted_date_nl}.",
            f"<h3>Bevestiging van je opzegging</h3><p>Je membership blijft actief tot <strong>{formatted_date_nl}</strong>.</p>"
        )

        log_audit(user.id, "membership_cancelled", f"Access until: {formatted_date_en}", request.remote_addr)
        logger.info(f"[CANCEL] User {user.email} cancelled auto-renewal. Access until {formatted_date_en}")

        success_msg = (
            f"Je abonnement is geannuleerd. Je behoudt volledige toegang tot {formatted_date_nl}."
            if lang == 'nl'
            else f"Membership cancelled. You retain full access until {formatted_date_en}."
        )

        return jsonify({"success": True, "message": success_msg})

    except Exception as e:
        logger.error(f"[CANCEL] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": "Failed to cancel membership"}), 500


# ============================================================================
# DOWNLOAD EA
# ============================================================================

@app.route("/download-ea/<int:file_id>")
@login_required
def download_ea(file_id):
    """Download an Expert Advisor file."""
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

@app.route("/download-connector")
def download_connector():
    """Download MT5 Journal Sync Service (increment counter)."""
    connector = MT5ConnectorIndicator.query.first()
    if not connector:
        flash('Geen sync service beschikbaar.', 'error')
        return redirect(url_for('user_dashboard'))
    
    connector.download_count = (connector.download_count or 0) + 1
    db.session.commit()
    
    full_path = os.path.join(app.root_path, connector.file_path)
    
    if not os.path.exists(full_path):
        flash('Service bestand niet gevonden op server.', 'error')
        return redirect(url_for('user_dashboard'))
    
    return send_from_directory(
        os.path.join(app.root_path, 'static', 'downloads'),
        connector.filename,
        as_attachment=True,
        download_name=connector.filename
    )

# ============================================================================
# TRADING JOURNAL ROUTES
# ============================================================================

@app.route("/journal")
@login_required
def journal_page():
    """Single-page Trading Journal with tabs: Dashboard, Trades, Calendar, Accounts."""
    if not current_user.is_membership_active():
        flash("Actief abonnement vereist.", "error")
        return redirect(url_for("user_dashboard"))
    
    accounts = JournalAccount.query.filter_by(
        user_id=current_user.id, archived=False
    ).order_by(JournalAccount.created_at).all()
    
    requested_id = request.args.get("account_id", type=int)
    account = get_selected_journal_account(requested_id)
    
    # Get connector info for download
    connector = MT5ConnectorIndicator.query.first()
    
    if not account:
        return render_template(
            "user/journal.html",
            user=current_user, accounts=accounts, account=None,
            active_tab="accounts", current_language=get_user_language(),
            now=datetime.utcnow(),
            indicator_download_url=url_for('download_connector') if connector else None,
            indicator_version=connector.version if connector else '1.0',
            webrequest_url=Config.APP_URL
        )
    
    now = datetime.utcnow()
    all_trades = account.trades.order_by(JournalTrade.close_time.asc()).all()
    
    week_start = datetime(now.year, now.month, now.day) - timedelta(days=now.weekday())
    week_trades = [t for t in all_trades if t.close_time >= week_start]
    month_start = datetime(now.year, now.month, 1)
    month_trades = [t for t in all_trades if t.close_time >= month_start]
    
    overall = compute_journal_stats(all_trades)
    week_stats = compute_journal_stats(week_trades)
    month_stats = compute_journal_stats(month_trades)
    
    starting_balance = account.starting_balance or 0.0
    total_return_pct = (overall["net_profit"] / starting_balance * 100) if starting_balance else 0.0
    max_dd, max_dd_pct = journal_max_drawdown(all_trades, starting_balance)
    active_days = len({t.close_time.strftime("%Y-%m-%d") for t in all_trades})
    
    # Calendar
    month_param = request.args.get("month")
    if month_param:
        try: cal_year, cal_month = [int(x) for x in month_param.split("-")]
        except: cal_year, cal_month = now.year, now.month
    else:
        cal_year, cal_month = now.year, now.month
    
    cal_start = datetime(cal_year, cal_month, 1)
    cal_end = datetime(cal_year + (1 if cal_month == 12 else 0), 1 if cal_month == 12 else cal_month + 1, 1)
    cal_trades = [t for t in all_trades if cal_start <= t.close_time < cal_end]
    cal_daily_pl = journal_daily_pl_map(cal_trades)
    
    weekly_bars = []
    week_pl = journal_daily_pl_map(week_trades)
    for i in range(7):
        d = week_start + timedelta(days=i)
        key = d.strftime("%Y-%m-%d")
        weekly_bars.append({"label": d.strftime("%a"), "date": key, "pl": round(week_pl.get(key, 0.0), 2)})
    
    # Trade filters
    symbol = request.args.get("jsymbol", "").strip().upper()
    trade_type = request.args.get("jtype", "").strip().lower()
    start = request.args.get("jstart")
    end = request.args.get("jend")
    q = request.args.get("jq", "").strip()
    
    query = account.trades
    if symbol: query = query.filter(JournalTrade.symbol == symbol)
    if trade_type in ("buy", "sell"): query = query.filter(JournalTrade.trade_type == trade_type)
    if start:
        try: query = query.filter(JournalTrade.close_time >= datetime.strptime(start, "%Y-%m-%d"))
        except: pass
    if end:
        try: query = query.filter(JournalTrade.close_time < datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1))
        except: pass
    if q: query = query.filter(JournalTrade.symbol.ilike(f"%{q}%"))
    
    sort = request.args.get("jsort", "close_time")
    direction = request.args.get("jdir", "desc")
    sort_col = getattr(JournalTrade, sort, JournalTrade.close_time)
    query = query.order_by(sort_col.desc() if direction == "desc" else sort_col.asc())
    
    trades = query.limit(500).all()
    symbols = sorted({t.symbol for t in account.trades.all()})
    active_tab = request.args.get("tab", "dashboard")
    
    return render_template(
        "user/journal.html",
        user=current_user, accounts=accounts, account=account,
        active_tab=active_tab, overall=overall, week_stats=week_stats,
        month_stats=month_stats, total_return_pct=round(total_return_pct, 2),
        max_dd=max_dd, max_dd_pct=max_dd_pct, active_days=active_days,
        current_balance=account.current_balance if account.current_balance is not None else starting_balance,
        current_equity=account.current_equity if account.current_equity is not None else starting_balance,
        cal_year=cal_year, cal_month=cal_month, cal_daily_pl=cal_daily_pl,
        cal_first_weekday=cal_start.weekday(), cal_days_in_month=(cal_end - cal_start).days,
        weekly_bars=weekly_bars, recent_trades=list(reversed(all_trades))[:8],
        trades=trades, symbols=symbols, sort=sort, direction=direction,
        filters={"symbol": symbol, "type": trade_type, "q": q, "start": start or "", "end": end or ""},
        month_names=['','January','February','March','April','May','June','July','August','September','October','November','December'],
        current_language=get_user_language(), now=now,
        indicator_download_url=url_for('download_connector') if connector else None,
        indicator_version=connector.version if connector else '1.0',
        webrequest_url=Config.APP_URL
    )

@app.route("/journal/account/new", methods=["POST"])
@login_required
def journal_account_new():
    """Create a new journal account. EA auto-fills broker/server/currency/balance."""
    name = request.form.get("name", "").strip()
    mt5_login = request.form.get("mt5_login", "").strip()

    if not name:
        name = f"MT5-{mt5_login}" if mt5_login else "MT5 Account"

    if not mt5_login:
        flash("MT5 login number is required.", "error")
        return redirect(url_for("journal_page", tab="accounts"))

    if JournalAccount.query.filter_by(user_id=current_user.id, mt5_login=mt5_login).first():
        flash("You already have an account linked to that MT5 login number.", "error")
        return redirect(url_for("journal_page", tab="accounts"))

    account = JournalAccount(
        user_id=current_user.id,
        name=name,
        mt5_login=mt5_login,
        sync_token=secrets.token_hex(24),
    )
    db.session.add(account)
    db.session.commit()

    session["journal_account_id"] = account.id
    flash(f"'{name}' connected! Your EA will auto-sync trades and account details.", "success")
    return redirect(url_for("journal_page", account_id=account.id, tab="accounts"))


@app.route("/journal/account/<int:account_id>/delete", methods=["POST"])
@login_required
def journal_account_delete(account_id):
    """Delete a journal account and all its trades."""
    account = JournalAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()
    name = account.name
    db.session.delete(account)
    db.session.commit()
    if session.get("journal_account_id") == account_id:
        session.pop("journal_account_id", None)
    flash(f"'{name}' and all its trade history deleted.", "success")
    return redirect(url_for("journal_page", tab="accounts"))


@app.route("/journal/api/day/<int:account_id>/<day>")
@login_required
def journal_api_day(account_id, day):
    """Get trades for a specific day (for calendar click)."""
    account = JournalAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()
    try: d = datetime.strptime(day, "%Y-%m-%d")
    except: return jsonify({"error": "Invalid date"}), 400
    
    next_d = d + timedelta(days=1)
    trades = account.trades.filter(
        JournalTrade.close_time >= d, JournalTrade.close_time < next_d
    ).order_by(JournalTrade.close_time).all()
    
    stats = compute_journal_stats(trades)
    return jsonify({
        "date": day, "stats": stats,
        "trades": [{
            "symbol": t.symbol, "type": t.trade_type, "volume": t.volume,
            "entry": t.entry_price, "sl": t.sl, "tp": t.tp, "exit": t.exit_price,
            "profit": t.profit, "pips": t.pips,
            "open_time": t.open_time.strftime("%H:%M") if t.open_time else None,
            "close_time": t.close_time.strftime("%H:%M"),
            "duration": t.duration_display(), "magic": t.magic_number,
        } for t in trades]
    })


@app.route("/journal/api/ingest", methods=["POST"])
def journal_api_ingest():
    """
    Called by the MT5 Journal Sync Service via WebRequest.
    Matches trades by MT5 login number.
    """
    mt5_login = request.headers.get("X-MT5-Login", "").strip()

    if not mt5_login:
        return jsonify({"success": False, "error": "Missing MT5 login"}), 400

    # Find any journal account with this MT5 login
    account = JournalAccount.query.filter_by(mt5_login=mt5_login).first()

    if not account:
        return jsonify({
            "success": False, 
            "error": "No journal account found for this MT5 login. Add it on the journal page first."
        }), 404

    data = request.get_json(silent=True) or {}

    # Auto-detect account metadata
    account_info = data.get("account_info", {})
    if account_info:
        if account_info.get("broker"):
            account.broker = account_info["broker"]
        if account_info.get("server"):
            account.mt5_server = account_info["server"]
        if account_info.get("currency"):
            account.currency = account_info["currency"]
        if account_info.get("balance") and (account.starting_balance is None or account.starting_balance == 0.0):
            account.starting_balance = account_info["balance"]

    # Import trades
    trades_payload = data.get("trades", [])
    imported = 0
    skipped = 0

    for tr in trades_payload:
        try:
            ticket = str(tr["ticket"])
        except KeyError:
            continue

        if JournalTrade.query.filter_by(account_id=account.id, mt5_ticket=ticket).first():
            skipped += 1
            continue

        close_time = None
        close_str = str(tr.get("close_time", "")).replace("T", " ")[:19]
        for fmt in ["%Y.%m.%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
            try:
                close_time = datetime.strptime(close_str, fmt)
                break
            except ValueError:
                continue

        if not close_time:
            continue

        open_time = None
        if tr.get("open_time"):
            open_str = str(tr["open_time"]).replace("T", " ")[:19]
            for fmt in ["%Y.%m.%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                try:
                    open_time = datetime.strptime(open_str, fmt)
                    break
                except ValueError:
                    continue

        db.session.add(JournalTrade(
            account_id=account.id,
            mt5_ticket=ticket,
            symbol=tr.get("symbol", "UNKNOWN"),
            trade_type=(tr.get("type") or "buy").lower(),
            volume=float(tr.get("volume") or 0),
            entry_price=tr.get("entry_price"),
            sl=tr.get("sl"),
            tp=tr.get("tp"),
            exit_price=tr.get("exit_price"),
            open_time=open_time,
            close_time=close_time,
            profit=float(tr.get("profit") or 0),
            pips=tr.get("pips"),
            magic_number=tr.get("magic_number"),
            comment=tr.get("comment"),
        ))
        imported += 1

    if "balance" in data:
        account.current_balance = data["balance"]
    if "equity" in data:
        account.current_equity = data["equity"]

    account.last_synced_at = datetime.utcnow()
    account.last_sync_error = None
    db.session.commit()

    return jsonify({
        "success": True,
        "imported": imported,
        "skipped": skipped,
        "balance": account.current_balance,
        "equity": account.current_equity
    })


@app.route("/journal/api/dashboard-data/<int:account_id>")
@login_required
def journal_api_dashboard_data(account_id):
    """Returns live dashboard data for AJAX auto-refresh every 60 seconds."""
    account = JournalAccount.query.filter_by(
        id=account_id, user_id=current_user.id
    ).first_or_404()
    
    now = datetime.utcnow()
    all_trades = account.trades.order_by(JournalTrade.close_time.asc()).all()
    
    week_start = datetime(now.year, now.month, now.day) - timedelta(days=now.weekday())
    week_trades = [t for t in all_trades if t.close_time >= week_start]
    
    overall = compute_journal_stats(all_trades)
    week_stats = compute_journal_stats(week_trades)
    
    starting_balance = account.starting_balance or 0.0
    
    week_pl = journal_daily_pl_map(week_trades)
    weekly_bars = []
    for i in range(7):
        d = week_start + timedelta(days=i)
        key = d.strftime("%Y-%m-%d")
        weekly_bars.append({
            "label": d.strftime("%a"),
            "date": key,
            "pl": round(week_pl.get(key, 0.0), 2)
        })
    
    recent_trades = list(reversed(all_trades))[:8]
    
    return jsonify({
        "success": True,
        "balance": account.current_balance if account.current_balance is not None else starting_balance,
        "equity": account.current_equity if account.current_equity is not None else starting_balance,
        "last_synced_at": account.last_synced_at.strftime('%d %b %H:%M') if account.last_synced_at else 'never',
        "overall": overall,
        "week_stats": week_stats,
        "weekly_bars": weekly_bars,
        "recent_trades": [{
            "close_time": t.close_time.isoformat(),
            "symbol": t.symbol,
            "trade_type": t.trade_type,
            "volume": t.volume,
            "entry_price": t.entry_price,
            "exit_price": t.exit_price,
            "profit": t.profit,
            "pips": t.pips,
            "duration": t.duration_display()
        } for t in recent_trades]
    })


@app.route("/journal/cleanup-bad-trades-once/<int:account_id>")
@login_required
def journal_cleanup_bad_trades_once(account_id):
    """
    TEMPORARY: One-off cleanup of corrupted trade rows (empty symbol or
    zero volume) left over from before the EA's DEAL_TYPE filter fix.
    """
    account = JournalAccount.query.filter_by(
        id=account_id, user_id=current_user.id
    ).first_or_404()

    deleted = JournalTrade.query.filter(
        JournalTrade.account_id == account.id,
        db.or_(
            JournalTrade.symbol == "",
            JournalTrade.symbol.is_(None),
            JournalTrade.volume == 0,
        ),
    ).delete(synchronize_session=False)

    db.session.commit()

    return jsonify({
        "account_id": account.id,
        "account_name": account.name,
        "deleted": deleted
    })


# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Admin dashboard with system statistics."""
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
    journal_accounts = JournalAccount.query.filter_by(archived=False).count()
    journal_trades = JournalTrade.query.count()

    recent_users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).limit(10).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    recent_licenses = License.query.order_by(License.created_at.desc()).limit(10).all()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    ea_files = EAFile.query.order_by(EAFile.upload_date.desc()).all()
    connector_indicator = MT5ConnectorIndicator.query.first()

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
        journal_accounts=journal_accounts,
        journal_trades=journal_trades,
        recent_users=recent_users,
        recent_orders=recent_orders,
        recent_licenses=recent_licenses,
        recent_logs=recent_logs,
        ea_files=ea_files,
        connector_indicator=connector_indicator,
        subscription_stats=subscription_stats,
        now=datetime.utcnow(),
        is_test_mode=is_test_mode,
        problematic_licenses=problematic_licenses,
        vps_pending_users=vps_pending_users
    )

@app.route("/admin/fix-all-licenses", methods=["POST"])
@admin_required
def fix_all_licenses():
    """Fix all licenses with invalid max_accounts values."""
    bad_licenses = License.query.filter(
        (License.max_accounts == None) | (License.max_accounts <= 0)
    ).all()

    fixed = 0
    for lic in bad_licenses:
        user = lic.user
        if user:
            user_level = user.get_plan_level()
            correct_max = get_max_accounts_for_level(user_level)
            logger.info(f"[FIX] License {lic.mask_license_key()}: {lic.max_accounts} -> {correct_max}")
            lic.max_accounts = correct_max
            fixed += 1

    db.session.commit()
    flash(f"{fixed} licenties hersteld", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/retry-vps/<int:user_id>", methods=["POST"])
@admin_required
def admin_retry_vps(user_id):
    """Retry VPS provisioning for a specific user."""
    user = db.session.get(User, user_id)
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_dashboard"))

    success = provision_vps_for_user(user, user.get_plan_level())
    if success:
        flash(f"VPS succesvol aangemaakt voor {user.email}.", "success")
    elif user.vps_status == 'provisioning':
        flash(f"VPS wordt aangemaakt voor {user.email} (ThinkHuge is nog bezig).", "success")
    else:
        flash(f"VPS aanmaken mislukt voor {user.email}: {user.vps_last_error}", "error")

    return redirect(request.referrer or url_for("admin_dashboard"))


@app.route("/admin/reset-vps-password/<int:user_id>", methods=["POST"])
@admin_required
def admin_reset_vps_password(user_id):
    """Reset VPS password for a user."""
    user = db.session.get(User, user_id)
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_dashboard"))

    if not user.vps_id:
        flash(f"{user.email} heeft nog geen VPS server.", "error")
        return redirect(request.referrer or url_for("admin_dashboard"))

    try:
        password = forexvps_client.reset_password(user.vps_id)
        user.vps_password = encrypt_data(password)
        user.vps_last_error = None
        db.session.commit()
        flash(f"Nieuw VPS wachtwoord opgehaald voor {user.email}.", "success")
    except Exception as e:
        user.vps_last_error = str(e)[:300]
        db.session.commit()
        flash(f"Wachtwoord ophalen mislukt voor {user.email}: {e}", "error")

    return redirect(request.referrer or url_for("admin_dashboard"))


@app.route("/admin/toggle-test-mode", methods=["POST"])
@admin_required
def toggle_test_mode():
    """Toggle test mode on/off."""
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
    """List all non-admin users."""
    users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users, now=datetime.utcnow())


@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    """View detailed information about a specific user."""
    user = db.session.get(User, user_id)
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_users"))

    orders = user.orders.order_by(Order.created_at.desc()).all()
    licenses = user.licenses.order_by(License.created_at.desc()).all()
    journal_accounts = user.journal_accounts.filter_by(archived=False).order_by(JournalAccount.created_at).all()

    vps_password = decrypt_data(user.vps_password) if user.vps_password else None

    return render_template(
        "admin/user_detail.html",
        user=user,
        orders=orders,
        licenses=licenses,
        journal_accounts=journal_accounts,
        vps_password=vps_password,
        now=datetime.utcnow()
    )


@app.route("/admin/orders")
@admin_required
def admin_orders():
    """List all orders."""
    orders = Order.query.order_by(Order.created_at.desc()).all()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    return render_template("admin/orders.html", orders=orders, total_revenue=total_revenue)


@app.route("/admin/revoke-license/<int:license_id>", methods=["POST"])
@admin_required
def revoke_license(license_id):
    """Revoke a specific license."""
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
    """Revoke a user's membership and terminate their VPS."""
    user = db.session.get(User, user_id)
    if user:
        user.membership_status = "revoked"
        user.membership_end = datetime.utcnow()
        License.query.filter_by(user_id=user.id, status="active").update(
            {"status": "revoked", "revoked_at": datetime.utcnow()}
        )
        if user.vps_id and user.vps_status == 'active':
            forexvps_client.terminate_vps(user.vps_id)
            user.vps_status = 'terminated'
            user.vps_terminated_at = datetime.utcnow()
        db.session.commit()
        flash("Abonnement ingetrokken.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Permanently delete a user and all associated data."""
    user = db.session.get(User, user_id)
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_users"))

    if user.is_admin:
        flash("Admin accounts kunnen niet worden verwijderd.", "error")
        return redirect(url_for("admin_users"))

    confirm_email = request.form.get("confirm_email", "").strip().lower()
    if confirm_email != user.email.lower():
        flash("Bevestigingsemail komt niet overeen.", "error")
        return redirect(request.referrer or url_for("admin_users"))

    email_for_log = user.email
    id_for_log = user.id

    try:
        if user.vps_id and user.vps_status not in ("terminated", None):
            forexvps_client.terminate_vps(user.vps_id)

        if user.stripe_subscription_id and stripe is not None:
            try:
                stripe.Subscription.delete(user.stripe_subscription_id)
            except Exception:
                pass

        EAFile.query.filter_by(uploaded_by=user.id).update({"uploaded_by": None})
        AuditLog.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()

        logger.info(f"[DELETE USER] Permanently deleted {email_for_log} (id={id_for_log})")
        log_audit(None, "user_deleted", f"Permanently deleted: {email_for_log} (was id={id_for_log})", request.remote_addr)
        flash(f"{email_for_log} is permanent verwijderd.", "success")

    except Exception as e:
        logger.error(f"[DELETE USER] Error deleting {email_for_log}: {e}", exc_info=True)
        db.session.rollback()
        flash(f"Verwijderen mislukt: {e}", "error")

    return redirect(url_for("admin_users"))


@app.route("/admin/reactivate-membership/<int:user_id>", methods=["POST"])
@admin_required
def reactivate_membership(user_id):
    """
    Reactivate a cancelled or revoked membership.
    For cancelled: resumes Stripe auto-renewal.
    For revoked: grants a fresh paid period.
    """
    user = db.session.get(User, user_id)
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_users"))

    previous_status = user.membership_status

    if previous_status == "cancelled":
        if user.stripe_subscription_id and stripe is not None:
            try:
                stripe.Subscription.modify(user.stripe_subscription_id, cancel_at_period_end=False)
                logger.info(f"[REACTIVATE] Stripe subscription {user.stripe_subscription_id} auto-renewal resumed for {user.email}")
            except Exception as e:
                logger.error(f"[REACTIVATE] Stripe error: {e}")

        user.membership_status = "active"
        if not user.membership_end or user.membership_end < datetime.utcnow():
            user.membership_end = datetime.utcnow() + timedelta(days=user.subscription_duration_days or 30)
        db.session.commit()
        flash(f"Abonnement van {user.email} is hervat (auto-renewal weer actief).", "success")
    else:
        user.membership_status = "active"
        user.membership_start = datetime.utcnow()
        user.membership_end = datetime.utcnow() + timedelta(days=user.subscription_duration_days or 30)
        db.session.commit()
        flash(f"Abonnement opnieuw geactiveerd voor {user.email}.", "success")

    log_audit(current_user.id, "membership_reactivated", f"Reactivated: {user.email} (was {previous_status})", request.remote_addr)
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/extend-membership/<int:user_id>", methods=["POST"])
@admin_required
def extend_membership(user_id):
    """Extend a user's membership by a number of days."""
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
    """Upload a new Expert Advisor file."""
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
        filename=filename,
        file_path=saved,
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
    """Delete an Expert Advisor file."""
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
# MT5 CONNECTOR INDICATOR MANAGEMENT
# ============================================================================

@app.route("/admin/upload-connector", methods=["POST"])
@admin_required
def admin_upload_connector():
    """Upload or update MT5 Journal Sync Service."""
    if 'file' not in request.files:
        flash('Geen bestand geselecteerd.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    file = request.files['file']
    version = request.form.get('version', '').strip()
    description = request.form.get('description', '').strip()
    
    if not file.filename:
        flash('Geen bestand geselecteerd.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if not version:
        flash('Versie is verplicht.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    allowed_extensions = {'.ex5', '.ex4'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        flash('Alleen .ex5 en .ex4 bestanden zijn toegestaan.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        downloads_dir = os.path.join(app.root_path, 'static', 'downloads')
        os.makedirs(downloads_dir, exist_ok=True)
        
        # Always use fixed filename
        fixed_filename = "MT5JournalSync" + file_ext
        
        # Delete all old database records
        old_connectors = MT5ConnectorIndicator.query.all()
        for old in old_connectors:
            old_path = os.path.join(app.root_path, old.file_path)
            if os.path.exists(old_path):
                os.remove(old_path)
            db.session.delete(old)
        
        # Clean downloads folder of any old MT5 files
        for f in os.listdir(downloads_dir):
            if f.startswith('MT5') and (f.endswith('.ex5') or f.endswith('.ex4')):
                try:
                    os.remove(os.path.join(downloads_dir, f))
                except:
                    pass
        
        # Save with fixed filename
        file_path = os.path.join('static', 'downloads', fixed_filename)
        full_path = os.path.join(app.root_path, file_path)
        file.save(full_path)
        
        # Create fresh record
        connector = MT5ConnectorIndicator(
            filename=fixed_filename,
            file_path=file_path,
            version=version,
            description=description,
            uploaded_by=current_user.id
        )
        db.session.add(connector)
        
        log_audit(
            current_user.id,
            'upload_connector',
            f'MT5 Journal Sync Service v{version} ({fixed_filename})',
            request.remote_addr
        )
        db.session.commit()
        
        flash(f'MT5 Journal Sync Service v{version} geüpload!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f'Upload error: {e}')
        flash(f'Fout: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))


@app.route("/admin/delete-connector", methods=["POST"])
@admin_required
def admin_delete_connector():
    """Delete MT5 Journal Sync Service."""
    connector = MT5ConnectorIndicator.query.first()
    if not connector:
        flash('Geen sync service gevonden.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Delete physical file
        full_path = os.path.join(app.root_path, connector.file_path)
        if os.path.exists(full_path):
            os.remove(full_path)
        
        # Log activity
        log_audit(
            current_user.id,
            'delete_connector',
            f'MT5 Journal Sync Service v{connector.version} verwijderd',
            request.remote_addr
        )
        
        # Delete database record
        db.session.delete(connector)
        db.session.commit()
        
        flash('MT5 Journal Sync Service verwijderd.', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f'Delete error: {str(e)}')
        flash(f'Fout bij verwijderen: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

# ============================================================================
# API - LICENSE VALIDATION
# ============================================================================

@app.route("/api/validate-license", methods=["POST"])
@limiter.limit("60 per minute")
def api_validate_license():
    """Validate a license key for EA activation."""
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

        lic = License.query.filter_by(license_key=license_key).first()
        if not lic:
            return jsonify({"valid": False, "error": "Licentie niet gevonden"}), 404
        if not lic.is_valid():
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
            else:
                db.session.add(EASession(
                    license_account_id=account.id,
                    session_id=session_id,
                    symbol=symbol,
                    magic_number=magic_number,
                ))
                lic.validation_count += 1

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
        if total_slots >= lic.max_accounts:
            return jsonify({
                "valid": False,
                "error": f"Maximum {lic.max_accounts} MT5 accounts bereikt.",
                "accounts_used": total_slots,
                "accounts_max": lic.max_accounts,
                "accounts_remaining": 0,
            }), 403

        new_account = LicenseAccount(license_id=lic.id, account_number=unique_account_id)
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
        logger.error(f"[VALIDATE] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"valid": False, "error": "Server fout"}), 500


@app.route("/api/release-license", methods=["POST"])
@limiter.limit("30 per minute")
def api_release_license():
    """Release a license slot for an MT5 account."""
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
            return jsonify({"success": False, "error": "Vereiste velden ontbreken"}), 400

        lic = License.query.filter_by(license_key=license_key).first()
        if not lic:
            return jsonify({"success": False, "error": "Licentie niet gevonden"}), 404

        account = LicenseAccount.query.filter_by(
            license_id=lic.id,
            account_number=unique_account_id
        ).first()

        if not account:
            return jsonify({
                "success": True,
                "session_released": False,
                "slot_freed": False,
                "accounts_used": lic.accounts.count(),
                "accounts_max": lic.max_accounts,
                "accounts_remaining": lic.max_accounts - lic.accounts.count(),
            })

        ea_session = EASession.query.filter_by(
            license_account_id=account.id,
            session_id=session_id
        ).first()

        if not ea_session:
            return jsonify({
                "success": True,
                "session_released": False,
                "slot_freed": False,
                "sessions_remaining": account.sessions.count(),
            })

        db.session.delete(ea_session)
        db.session.flush()

        remaining_sessions = account.sessions.count()
        slot_freed = False

        if remaining_sessions == 0:
            db.session.delete(account)
            slot_freed = True

        db.session.commit()

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
        logger.error(f"[RELEASE] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"success": False, "error": "Server fout"}), 500


@app.route("/api/user/info")
@login_required
def api_user_info():
    """Get current user info as JSON."""
    return jsonify(current_user.to_dict())


# ============================================================================
# WIX WEBHOOK
# ============================================================================

@app.route("/webhook/wix/payment", methods=["POST"])
@limiter.limit("60 per minute")
def wix_payment_webhook():
    """Handle Wix payment webhooks for new plan orders."""
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
        except (ValueError, TypeError):
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
                email=email,
                first_name=first_name,
                last_name=last_name,
                wix_contact_id=contact_id,
                wix_order_id=order_id,
                wix_payment_id=order_id,
                email_verified=True,
                membership_status="active",
                membership_start=membership_start,
                membership_end=membership_end,
                plan_name=plan_name,
                plan_price=plan_price,
                currency=currency,
                subscription_type=subscription_type,
                subscription_duration_days=duration_days
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
                user_id=user.id,
                wix_order_id=order_id,
                wix_payment_id=order_id,
                plan_name=plan_name,
                plan_price=plan_price,
                currency=currency,
                total_amount=plan_price,
                subscription_type=subscription_type,
                subscription_duration_days=duration_days,
                status="completed",
                payment_status="paid",
                ip_address=request.remote_addr,
                raw_data=json.dumps(data)
            )
            db.session.add(order)

        db.session.commit()

        plan_level = user.get_plan_level()
        provision_vps_for_user(user, plan_level)

        send_email_async(
            "Welkom bij Trading Engine! 🎉",
            [email],
            f"Je {plan_name} abonnement is nu actief. Log in op {Config.APP_URL}/login",
            f"<h3>Hoi {first_name or 'daar'}!</h3><p>Je {plan_name} abonnement is actief.</p><p>Log in op {Config.APP_URL}/login</p>"
        )

        log_audit(
            user.id,
            "wix_plan_ordered",
            f"{'Nieuw' if is_new else 'Bijgewerkt'} | {plan_name} | {subscription_type}",
            request.remote_addr
        )

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"[WIX WEBHOOK] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# STRIPE WEBHOOK
# ============================================================================

@app.route("/webhook/stripe/payment", methods=["POST"])
@limiter.limit("60 per minute")
def stripe_payment_webhook():
    """Handle Stripe payment webhooks."""
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

            metadata = session_data.get("metadata") or {}
            plan_name = metadata.get("plan_name", "Onbekend Plan")
            plan_duration = metadata.get("plan_duration", "")
            amount_total = (session_data.get("amount_total") or 0) / 100
            order_id = session_data.get("id", "")
            stripe_subscription_id = session_data.get("subscription")
            stripe_customer_id = session_data.get("customer")

            if email:
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

                if not user:
                    user = User(
                        email=email,
                        first_name=first_name,
                        email_verified=True,
                        membership_status="active",
                        membership_start=membership_start,
                        membership_end=membership_end,
                        plan_name=plan_name,
                        plan_price=amount_total,
                        currency=(session_data.get("currency") or "eur").upper(),
                        subscription_type=subscription_type,
                        subscription_duration_days=duration_days,
                        stripe_subscription_id=stripe_subscription_id,
                        stripe_customer_id=stripe_customer_id,
                    )
                    db.session.add(user)
                else:
                    user.membership_status = "active"
                    user.membership_start = membership_start
                    user.membership_end = membership_end
                    user.stripe_subscription_id = stripe_subscription_id or user.stripe_subscription_id
                    user.stripe_customer_id = stripe_customer_id or user.stripe_customer_id

                if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
                    order = Order(
                        user_id=user.id,
                        wix_order_id=order_id,
                        plan_name=plan_name,
                        plan_price=amount_total,
                        total_amount=amount_total,
                        subscription_type=subscription_type,
                        subscription_duration_days=duration_days,
                        status="completed",
                        payment_status="paid",
                        ip_address=request.remote_addr,
                        raw_data=json.dumps(session_data)
                    )
                    db.session.add(order)

                db.session.commit()

                plan_level = user.get_plan_level()
                provision_vps_for_user(user, plan_level)

                send_email_async(
                    "Welkom bij Trading Engine! 🎉",
                    [email],
                    f"Je {plan_name} abonnement is nu actief.",
                    f"<h3>Hoi {first_name or 'daar'}!</h3><p>Je {plan_name} abonnement is actief.</p>"
                )

                log_audit(
                    user.id,
                    "stripe_payment",
                    f"{plan_name} | {subscription_type} | sub_id={stripe_subscription_id}",
                    request.remote_addr
                )

        elif event_type == "customer.subscription.deleted":
            sub = event["data"]["object"]._to_dict_recursive()
            sub_id = sub.get("id")
            user = User.query.filter_by(stripe_subscription_id=sub_id).first()
            if user:
                logger.info(f"[STRIPE] Subscription {sub_id} deleted at Stripe for {user.email}")
                log_audit(user.id, "stripe_subscription_deleted", f"sub_id={sub_id}", request.remote_addr)

        elif event_type == "customer.subscription.updated":
            sub = event["data"]["object"]._to_dict_recursive()
            sub_id = sub.get("id")
            cancel_at_period_end = sub.get("cancel_at_period_end")
            user = User.query.filter_by(stripe_subscription_id=sub_id).first()
            if user:
                logger.info(
                    f"[STRIPE] Subscription {sub_id} updated for {user.email}: "
                    f"cancel_at_period_end={cancel_at_period_end}"
                )

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"[STRIPE] Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# DISCORD INTEGRATION
# ============================================================================

def assign_discord_role(discord_id):
    """Assign the configured Discord role to a user."""
    try:
        role_url = f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{discord_id}/roles/{Config.DISCORD_ROLE_ID}"
        role_req = urllib.request.Request(role_url, method="PUT")
        role_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
        role_req.add_header("Content-Type", "application/json")
        role_req.add_header("User-Agent", DISCORD_BROWSER_USER_AGENT)
        urllib.request.urlopen(role_req)
        return True
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()
        except Exception:
            detail = ""
        logger.error(f"[DISCORD] Role assignment failed: {e.code} - {detail}")
        return False
    except Exception as e:
        logger.error(f"[DISCORD] Role assignment failed: {e}")
        return False


@app.route("/connect-discord")
@login_required
def connect_discord():
    """Initiate Discord OAuth connection."""
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
    """Handle Discord OAuth callback."""
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
        token_req.add_header("User-Agent", DISCORD_BROWSER_USER_AGENT)
        token_json = json.loads(urllib.request.urlopen(token_req).read())
        access_token = token_json["access_token"]

        user_req = urllib.request.Request("https://discord.com/api/users/@me")
        user_req.add_header("Authorization", f"Bearer {access_token}")
        user_req.add_header("User-Agent", DISCORD_BROWSER_USER_AGENT)
        discord_user = json.loads(urllib.request.urlopen(user_req).read())
        discord_id = discord_user["id"]

        # Join guild
        join_data = json.dumps({"access_token": access_token}).encode()
        join_req = urllib.request.Request(
            f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{discord_id}",
            data=join_data,
            method="PUT"
        )
        join_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
        join_req.add_header("Content-Type", "application/json")
        join_req.add_header("User-Agent", DISCORD_BROWSER_USER_AGENT)

        try:
            urllib.request.urlopen(join_req)
        except urllib.error.HTTPError as join_err:
            try:
                join_detail = join_err.read().decode()
            except Exception:
                join_detail = ""
            logger.warning(f"[DISCORD] Guild join failed for {discord_id}: {join_err.code} - {join_detail}")
        except Exception as join_err:
            logger.warning(f"[DISCORD] Guild join failed for {discord_id}: {join_err}")

        assign_discord_role(discord_id)

        current_user.discord_user_id = discord_id
        current_user.discord_joined = True
        db.session.commit()

        flash("Discord verbonden! 🎉", "success")

    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode()
        except Exception:
            error_body = ""
        logger.error(f"[DISCORD] OAuth failed: {e.code} - {error_body}", exc_info=True)
        flash("Discord verbinding mislukt.", "error")
    except Exception as e:
        logger.error(f"[DISCORD] OAuth failed: {e}", exc_info=True)
        flash("Discord verbinding mislukt.", "error")

    return redirect(url_for("user_dashboard"))


# ============================================================================
# AUTO-INIT DATABASE
# ============================================================================

@app.before_request
def auto_init_db():
    """Auto-initialize the database on first request."""
    try:
        db.session.execute(db.text("SELECT 1 FROM users LIMIT 1"))
    except Exception:
        try:
            db.create_all()
            logger.info("Database created!")

            admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
            if not User.query.filter_by(email=admin_email).first():
                admin = User(
                    email=admin_email,
                    first_name="Admin",
                    is_admin=True,
                    email_verified=True,
                    membership_status="active",
                    membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin",
                    subscription_type="lifetime",
                    subscription_duration_days=36500
                )
                db.session.add(admin)
                db.session.commit()
                logger.info("Admin user created")
        except Exception as e:
            logger.error(f"DB init failed: {e}")


# ============================================================================
# APPLICATION STARTUP
# ============================================================================

with app.app_context():
    run_migrations()

start_auto_cleanup()

logger.info("=" * 80)
logger.info("APPLICATION STARTUP COMPLETE - ALL SYSTEMS READY")
logger.info("=" * 80)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
