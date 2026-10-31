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
ADDED: Self-service "Reset VPS Password" endpoint (/vps/reset-password) so a
       logged-in user can rotate their own VPS password on demand, in
       addition to the existing admin-only reset endpoint.
UPDATED: All outgoing emails are now written in Dutch only (single-language
       copy, no more English branches), to keep tone and wording consistent
       across every notification the platform sends. This includes the
       "Members Platform is ready" login-invite email, which is kept and
       still sent alongside the welcome/purchase-confirmation email on
       every Wix plan-order and Stripe checkout.
ADDED: WWA (WealthWave Affiliation / Cellxpert) broker tracking integration
       - BrokerAccount model, WWA API client, member UID-check endpoint,
       postback receivers for registration/FTD/qualified-CPA/commission/lead
       events, and an admin Broker Tracker dashboard.
FIXED: Stripe API version 2026-04-22.dahlia (and potentially other versions)
       moved the Invoice object's subscription reference off the top-level
       "subscription" field and into parent.subscription_details.subscription.
       The invoice.paid renewal handler was still reading only the old
       top-level field, which came back None on every renewal invoice under
       the new schema. That caused User.query.filter_by(stripe_subscription_id=None)
       to run - silently matching nothing (renewal never applied) or, worse,
       incorrectly matching some unrelated user whose stripe_subscription_id
       happened to be NULL in the database. Added extract_subscription_id(),
       which checks the new nested location first and falls back to the old
       top-level field, so renewals keep working across this and future API
       version changes. Also added explicit error logging (instead of a
       silent no-op) when no subscription ID can be resolved at all, so this
       class of failure is never silent again.
CHANGED: Access for Stripe-managed subscribers now FOLLOWS STRIPE'S SUBSCRIPTION
       STATUS instead of a local date timeline. Previously membership_end and
       license.expires_at were plain dates, so a license could expire while
       Stripe was still collecting the payment (slow SEPA debits that take
       days to settle, or card retries during the dunning window), locking the
       customer out and letting cleanup_expired_vps() terminate their VPS.
       - New users.stripe_subscription_status column (auto-migrated, backfilled).
       - User.has_active_access() is the single access check. For Stripe-managed
         users: active / trialing / past_due = access (past_due means Stripe is
         still retrying); canceled / unpaid / incomplete* / paused = no access.
         Admin "revoked" always wins. Wix / lifetime / admin-granted users keep
         the old date-based behaviour.
       - User.is_membership_active(), License.is_valid() and
         cleanup_expired_vps() all use that one check.
       - customer.subscription.updated keeps the stored status in sync;
         customer.subscription.deleted is the real expiry (expires membership +
         license, VPS cleanup then terminates the server).
       - invoice.payment_failed logs + sends a Dutch "betaling mislukt" email.
       - invoice.paid no longer restores access for a subscription that Stripe
         has already cancelled (the invoice status is left "past-due" by the
         Stripe dunning settings, so an old invoice can be paid later).
       - Background reconciliation sweep re-reads subscriptions from Stripe so a
         missed webhook can never leave someone with permanent (or no) access.
       - /api/validate-license returns a rolling expires_at for Stripe-managed
         users so an EA that compares that date locally doesn't shut down
         while Stripe is still collecting.
       - Admin extend / reactivate on a dead Stripe subscription now detaches it
         (status "admin_override") so the admin's manual grant actually works.
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
    # How often (seconds) the background sweep re-reads non-settled Stripe
    # subscriptions from Stripe to correct any missed webhooks, and how many
    # subscriptions it checks per run.
    STRIPE_RECONCILE_INTERVAL_SECONDS = int(os.getenv("STRIPE_RECONCILE_INTERVAL_SECONDS", 900))
    STRIPE_RECONCILE_BATCH_SIZE = int(os.getenv("STRIPE_RECONCILE_BATCH_SIZE", 50))
    # /api/validate-license reports expires_at as at least "now + this many
    # days" for Stripe-managed users with active access, so an EA comparing
    # that date locally keeps running while Stripe is still collecting.
    STRIPE_EA_EXPIRY_BUFFER_DAYS = int(os.getenv("STRIPE_EA_EXPIRY_BUFFER_DAYS", 3))

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

    # Show the VPS management section on the members dashboard. Off by default:
    # the ThinkHuge partnership has ended and clients now buy their VPS directly
    # from ForexVPS. Set SHOW_VPS_SECTION=true to show it again.
    SHOW_VPS_SECTION = os.getenv("SHOW_VPS_SECTION", "false").lower() == "true"

    FOREXVPS_RETRY_INTERVAL_SECONDS = int(os.getenv("FOREXVPS_RETRY_INTERVAL_SECONDS", 600))
    FOREXVPS_RETRY_MAX_AGE_MINUTES = int(os.getenv("FOREXVPS_RETRY_MAX_AGE_MINUTES", 1440))

    # WWA (WealthWave Affiliation / Cellxpert) API configuration
    WWA_API_URL = os.getenv("WWA_API_URL", "https://go.wealthwaveaffiliation.com/api/")
    WWA_AFFILIATE_ID = os.getenv("WWA_AFFILIATE_ID", "")
    WWA_API_KEY = os.getenv("WWA_API_KEY", "")
    # Optional shared secret you invent yourself and append as a query param
    # (&secret=xxxx) on every postback URL registered in WWA's dashboard, so
    # postback requests can be verified as genuinely coming from WWA.
    WWA_POSTBACK_SECRET = os.getenv("WWA_POSTBACK_SECRET", "")

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
# Default to INFO rather than DEBUG so routine noise (e.g. every quiet EA
# heartbeat sync) doesn't flood the log stream and bury real events.
# Set LOG_LEVEL=DEBUG in the environment if you need full verbosity while
# troubleshooting - no code change required.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
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

# --- Stripe subscription statuses and what they mean for access -------------
# "past_due" means Stripe is STILL TRYING to collect (card retries, or a SEPA
# debit that failed and is being retried), so the customer keeps access until
# Stripe actually cancels the subscription (customer.subscription.deleted).
STRIPE_ACCESS_STATUSES = frozenset({"active", "trialing", "past_due"})
# Every status Stripe can report for a subscription. A user is only treated as
# "Stripe-managed" when the stored status is one of these.
STRIPE_KNOWN_STATUSES = frozenset({
    "active", "trialing", "past_due", "unpaid", "canceled",
    "incomplete", "incomplete_expired", "paused",
})
# Sentinel stored when an admin manually grants time on a subscription that
# Stripe has already ended. It is NOT a Stripe status, so the user falls back to
# date-based access and the reconciliation sweep leaves them alone.
STRIPE_STATUS_ADMIN_OVERRIDE = "admin_override"


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
    # Mirror of Stripe's subscription.status (active / past_due / canceled ...).
    # For Stripe-managed users THIS decides access, not membership_end.
    stripe_subscription_status = db.Column(db.String(30), nullable=True)

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
    # Set the first (and only) time the "VPS ready" email is actually sent for
    # the CURRENT vps_id. Used as an atomic claim to prevent duplicate emails
    # when multiple worker processes/threads notice readiness at once.
    vps_ready_email_sent_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    otp_tokens = db.relationship("OTPToken", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    licenses = db.relationship("License", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    journal_accounts = db.relationship("JournalAccount", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def is_stripe_managed(self):
        """True when Stripe's subscription status is the source of truth for access."""
        return bool(
            self.stripe_subscription_id
            and self.stripe_subscription_status in STRIPE_KNOWN_STATUSES
        )

    def has_active_access(self):
        """
        THE single access check (membership, licenses, VPS all use this).

        - Admin "revoked" and never-paid "pending" always mean no access.
        - Stripe-managed users: access follows Stripe's subscription status.
          active / trialing / past_due (Stripe still retrying) = access;
          canceled / unpaid / incomplete* / paused = no access. Local dates and
          the local "expired" flag are ignored - Stripe decides.
        - Everyone else (Wix, lifetime, admin-granted): date-based, as before.

        Pure read - no database writes. is_membership_active() adds the
        local-status self-healing on top of this.
        """
        status = self.membership_status
        if not status or status in ("revoked", "pending"):
            return False

        if self.is_stripe_managed():
            return self.stripe_subscription_status in STRIPE_ACCESS_STATUSES

        if status not in ("active", "cancelled"):
            return False
        if self.membership_end and self.membership_end < datetime.utcnow():
            return False
        return True

    def is_membership_active(self):
        """Check if the user's membership is currently active."""
        has_access = self.has_active_access()
        try:
            if has_access:
                # Heal a local "expired" flag set by the old date-based logic
                # while Stripe still says the subscription is alive.
                if self.membership_status == "expired" and self.is_stripe_managed():
                    self.membership_status = "active"
                    db.session.commit()
            elif self.membership_status in ("active", "cancelled"):
                self.membership_status = "expired"
                db.session.commit()
        except Exception as e:
            logger.error(f"[ACCESS] Could not sync membership_status for user {self.id}: {e}")
            db.session.rollback()
        return has_access

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

    def _is_latest_license_of_user(self):
        """True if this is the user's newest non-revoked license."""
        latest = (
            License.query.filter(License.user_id == self.user_id, License.status != "revoked")
            .order_by(License.created_at.desc(), License.id.desc())
            .first()
        )
        return bool(latest and latest.id == self.id)

    def is_valid(self):
        """
        Check if license is currently valid.

        For Stripe-managed users validity follows the user's Stripe-driven
        access (see User.has_active_access) instead of this row's expires_at,
        so a license stays valid while Stripe is still collecting payment and
        is restored automatically if an older run of the date-based logic had
        marked it "expired". Everyone else keeps the date-based behaviour.
        """
        user = self.user
        if user is not None and user.is_stripe_managed():
            if self.status not in ("active", "expired"):
                return False  # revoked (admin) always wins
            if not user.has_active_access():
                if self.status == "active":
                    self.status = "expired"
                    db.session.commit()
                return False
            if self.status == "expired":
                # Only the newest license is revived, so old keys the user
                # replaced can't be brought back to life by validating them.
                if not self._is_latest_license_of_user():
                    return False
                self.status = "active"
                db.session.commit()
        else:
            if self.status != "active":
                return False
            if self.expires_at < datetime.utcnow():
                self.status = "expired"
                db.session.commit()
                return False

        if self.max_validations is not None and self.validation_count >= self.max_validations:
            return False
        return True

    def effective_expires_at(self):
        """
        The expires_at reported to the EA. For Stripe-managed users with live
        access it is a rolling date (never earlier than now + buffer), because
        the stored date is not what decides access for them. The EA keeps
        re-validating, and the server is what actually enforces access.
        """
        user = self.user
        if user is not None and user.is_stripe_managed() and user.has_active_access():
            floor = datetime.utcnow() + timedelta(days=Config.STRIPE_EA_EXPIRY_BUFFER_DAYS)
            if not self.expires_at or self.expires_at < floor:
                return floor
        return self.expires_at

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


class BrokerAccount(db.Model):
    """A member's broker/UID entry, tracked for WWA attribution + CPA."""

    __tablename__ = "broker_accounts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    broker = db.Column(db.String(100), nullable=False)
    uid = db.Column(db.String(100), nullable=False, index=True)

    # Attribution: whether WWA's `registrations` lookup found this UID
    # attributed to our affiliate account.
    attribution_status = db.Column(db.String(20), default="pending")  # pending | confirmed | not_attributed
    registration_status = db.Column(db.String(50), nullable=True)     # raw WWA "Status" field, e.g. "New"
    registration_date = db.Column(db.DateTime, nullable=True)
    country = db.Column(db.String(10), nullable=True)

    # Deposit / volume (populated from registrations lookup and/or FTD postback)
    deposit_amount = db.Column(db.Float, default=0.0)
    deposit_date = db.Column(db.DateTime, nullable=True)
    required_deposit = db.Column(db.Float, default=1000.0)   # your own CPA terms per broker

    volume_lots = db.Column(db.Float, default=0.0)
    required_volume_lots = db.Column(db.Float, default=1.0)  # your own CPA terms per broker

    # CPA / commission - populated primarily via postbacks
    cpa_status = db.Column(db.String(20), default="pending")       # pending | in_progress | qualified
    commission_amount = db.Column(db.Float, default=0.0)
    commission_status = db.Column(db.String(20), default="pending")  # pending | paid

    # Bookkeeping
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_check_error = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("broker_accounts", lazy="dynamic"))

    __table_args__ = (
        db.UniqueConstraint("user_id", "broker", "uid", name="uq_user_broker_uid"),
    )

    def progress_pct(self):
        """Volume progress toward the CPA volume requirement, capped at 100."""
        if not self.required_volume_lots:
            return 0
        pct = (self.volume_lots / self.required_volume_lots) * 100
        return min(100, round(pct))

    def deposit_met(self):
        return (self.deposit_amount or 0) >= (self.required_deposit or 0)


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
# WWA (WEALTHWAVE AFFILIATION / CELLXPERT) API CLIENT
# ============================================================================

class WWAClient:
    """
    Client for the WWA / Cellxpert Affiliate API (pull side).
    Postbacks (push side) are handled separately by the webhook routes
    below - this client is only for on-demand lookups, e.g. checking a
    UID's attribution/registration status when a member submits it.
    """

    def __init__(self, base_url, affiliate_id, api_key, user_agent):
        self.base_url = base_url
        self.affiliate_id = affiliate_id
        self.api_key = api_key
        self.user_agent = user_agent

    def is_configured(self):
        return bool(self.affiliate_id and self.api_key)

    def _get(self, params, timeout=30):
        query = urllib.parse.urlencode(params)
        url = f"{self.base_url}?{query}"
        req = urllib.request.Request(url, method="GET")
        req.add_header("affiliateid", str(self.affiliate_id))
        req.add_header("x-api-key", self.api_key)
        req.add_header("User-Agent", self.user_agent)
        return urllib.request.urlopen(req, timeout=timeout)

    def get_registration(self, uid):
        """
        Look up a single UID via the `registrations` command.
        Returns the registration dict if found, or None if the UID isn't
        attributed to this affiliate account (or doesn't exist yet).

        Raises urllib.error.HTTPError / URLError / ValueError on failure -
        callers should catch these and treat as "couldn't verify right now"
        rather than "not attributed", since a network/API failure is not
        the same as a confirmed non-match.
        """
        params = {"command": "registrations", "userid": uid, "json": 1}
        response = self._get(params)
        raw = response.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        regs = data.get("registrations") or []
        if not regs:
            return None
        return regs[0]


# Initialize the WWA client
wwa_client = WWAClient(
    base_url=Config.WWA_API_URL,
    affiliate_id=Config.WWA_AFFILIATE_ID,
    api_key=Config.WWA_API_KEY,
    user_agent=BROWSER_USER_AGENT,
)


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


def extract_subscription_id(stripe_object):
    """
    Get the subscription ID referenced by a Stripe Invoice (or similarly
    shaped) object, robust to API version changes.

    As of Stripe API version 2026-04-22.dahlia, the Invoice object no
    longer has a top-level "subscription" field. The reference moved to:
        invoice["parent"]["subscription_details"]["subscription"]

    Older API versions (and possibly future ones) put/put back a plain
    top-level "subscription" field, so this checks the new nested location
    first and falls back to the legacy top-level field, rather than
    assuming either one is guaranteed to exist. Returns None if neither
    location has a value - callers must handle that explicitly instead of
    passing None into a database lookup, since filtering on a NULL column
    can silently match an unrelated record.
    """
    if not stripe_object:
        return None

    # Newest known location (API version 2026-04-22.dahlia and later)
    parent = stripe_object.get("parent") or {}
    subscription_details = parent.get("subscription_details") or {}
    sub_id = subscription_details.get("subscription")
    if sub_id:
        return sub_id

    # Legacy top-level field (pre-dahlia API versions)
    sub_id = stripe_object.get("subscription")
    if sub_id:
        return sub_id

    return None


def get_invoice_period_end(invoice):
    """
    Extract the exact billing period end for a paid invoice's subscription
    line item, straight from Stripe's own invoice payload - no extra API
    call needed, since Stripe already includes it.

    This exists because locally computing membership_end/license.expires_at
    as "+N days" (e.g. +30) drifts from Stripe's real, calendar-based
    billing cycles - a monthly subscription that started on the 14th of a
    31-day month renews on the 14th of the next month, which is 31 days
    later, not 30. That one-to-three-day gap made membership_end/expires_at
    fall due a day or two before Stripe's own invoice/renewal actually
    fires, which is exactly what caused License/membership rows to show as
    "expired" while the real Stripe subscription was still current and
    about to renew on schedule.

    Using Stripe's own period end instead of a local approximation removes
    this drift entirely, for every renewal, going forward.

    Returns None if the invoice doesn't have a usable line item/period -
    callers must fall back to a duration-based calculation in that case,
    never assume this always succeeds.
    """
    try:
        lines = (invoice.get("lines") or {}).get("data") or []
        if not lines:
            return None
        period = lines[0].get("period") or {}
        end_ts = period.get("end")
        if not end_ts:
            return None
        return datetime.utcfromtimestamp(end_ts)
    except Exception as e:
        logger.warning(f"[STRIPE] Could not read period end from invoice: {e}")
        return None


def get_subscription_period_end(subscription_id):
    """
    Fetch the exact current period end for a subscription directly from
    Stripe, so a brand-new user's initial membership_end lines up with
    Stripe's real billing cycle instead of an approximate flat-duration
    window computed locally (see get_invoice_period_end for why that drift
    matters).

    Checks both known locations for this field, since Stripe has been
    moving "current_period_end" off the Subscription object itself and
    onto each Subscription Item (to support multiple differently-billed
    items per subscription) - the same kind of schema relocation that
    broke the invoice.paid handler, so this is written defensively against
    it happening here too.

    Returns None (caller must fall back to a duration-based calculation) if
    Stripe isn't configured, no subscription_id was given, or the API call
    fails for any reason - this must never raise and break checkout
    processing.
    """
    if not subscription_id or stripe is None or not Config.STRIPE_API_KEY:
        return None
    try:
        sub_dict = fetch_stripe_subscription(subscription_id)
        if sub_dict:
            return subscription_period_end_from_dict(sub_dict)
    except Exception as e:
        logger.warning(f"[STRIPE] Could not retrieve period end for subscription {subscription_id}: {e}")
    return None


def subscription_period_end_from_dict(sub_dict):
    """
    Read current_period_end from a Subscription dict, checking both the
    subscription itself and its first item (Stripe moved it onto items).
    Returns a naive UTC datetime, or None.
    """
    try:
        period_end = sub_dict.get("current_period_end")
        if not period_end:
            items = (sub_dict.get("items") or {}).get("data") or []
            if items:
                period_end = items[0].get("current_period_end")
        if period_end:
            return datetime.utcfromtimestamp(period_end)
    except Exception as e:
        logger.warning(f"[STRIPE] Could not read period end from subscription: {e}")
    return None


# ============================================================================
# STRIPE SUBSCRIPTION STATE SYNC
# One place that pushes Stripe's subscription state onto our User/License rows.
# Used by the webhooks AND the background reconciliation sweep, so both always
# reach the same conclusion.
# ============================================================================

def fetch_stripe_subscription(subscription_id):
    """
    Retrieve a subscription from Stripe as a plain dict.

    Returns None if Stripe isn't configured. Returns {"id": ..., "status":
    "canceled", "_missing": True} if Stripe says the subscription doesn't
    exist at all. Any other API failure RAISES, so callers never mistake a
    network error for a cancellation.
    """
    if not subscription_id or stripe is None or not Config.STRIPE_API_KEY:
        return None
    try:
        sub = stripe.Subscription.retrieve(subscription_id)
    except Exception as e:
        if getattr(e, "code", None) == "resource_missing" or "No such subscription" in str(e):
            return {"id": subscription_id, "status": "canceled", "_missing": True}
        raise
    return sub.to_dict() if hasattr(sub, "to_dict") else dict(sub)


def _latest_license_for(user):
    """The user's newest non-revoked license (the one renewals act on)."""
    return user.licenses.filter(License.status != "revoked").order_by(
        License.created_at.desc()
    ).first()


def detach_dead_stripe_subscription(user):
    """
    Call before an admin (or Wix/lifetime purchase) manually grants time to a
    user whose Stripe subscription has already ended. Without this, the Stripe
    status (canceled etc.) would still override the grant. Marks the user as
    date-based. A live subscription is left untouched. Caller commits.
    """
    if user.is_stripe_managed() and user.stripe_subscription_status not in STRIPE_ACCESS_STATUSES:
        logger.info(
            f"[STRIPE] Detaching ended subscription {user.stripe_subscription_id} "
            f"(status={user.stripe_subscription_status}) from {user.email}: manual grant"
        )
        user.stripe_subscription_status = STRIPE_STATUS_ADMIN_OVERRIDE
        return True
    return False


def apply_stripe_subscription_state(user, sub, source="webhook", preserve_future_grants=False):
    """
    Apply a Stripe Subscription (dict) to our rows. Idempotent.

    - Stores the status (which is what grants/denies access).
    - Access statuses: heals a stale local "expired" flag/license, syncs the
      cancel-at-period-end flag, and (active/trialing only) extends the dates
      to Stripe's current period end. Dates are never shortened here.
    - Non-access statuses (canceled, unpaid, ...): expires membership + license
      (the VPS cleanup then terminates the server).
    Admin "revoked" is never touched. Returns the status. Caller does not need
    to commit; this commits.

    preserve_future_grants (used by the one-time migration backfill only): if
    Stripe reports the subscription ended but the user still has well over a
    day of paid-through time locally, that time came from somewhere other than
    this subscription (an older Stripe link plus a later Wix/lifetime/admin
    grant). Don't lock them out on first sync - keep them date-based instead.
    """
    status = (sub or {}).get("status")
    if not status:
        return None

    previous = user.stripe_subscription_status

    # canceled / incomplete_expired are terminal in Stripe (a subscription can
    # never come back). Webhooks can arrive out of order, so a late "past_due"
    # or "active" update must not resurrect a subscription we already saw end.
    if previous in ("canceled", "incomplete_expired") and status != previous:
        logger.info(
            f"[STRIPE] Ignoring {source} status '{status}' for {user.email}: "
            f"subscription already {previous}"
        )
        return previous

    now = datetime.utcnow()

    if (
        preserve_future_grants
        and status not in STRIPE_ACCESS_STATUSES
        and user.membership_status in ("active", "cancelled")
        and user.membership_end
        and user.membership_end > now + timedelta(days=1)
    ):
        logger.warning(
            f"[STRIPE] {user.email}: Stripe says {status} but local access runs until "
            f"{user.membership_end}; keeping date-based access (manual grant / other source)"
        )
        user.stripe_subscription_status = STRIPE_STATUS_ADMIN_OVERRIDE
        db.session.commit()
        return STRIPE_STATUS_ADMIN_OVERRIDE

    user.stripe_subscription_status = status

    if user.membership_status == "revoked":
        db.session.commit()
        return status

    if status in STRIPE_ACCESS_STATUSES:
        cancel_at_period_end = bool(sub.get("cancel_at_period_end"))

        # Mirror cancel-at-period-end (user cancelled in Stripe's portal etc.)
        if user.membership_status in ("active", "expired"):
            user.membership_status = "cancelled" if cancel_at_period_end else "active"
        elif user.membership_status == "cancelled" and not cancel_at_period_end:
            user.membership_status = "active"

        period_end = subscription_period_end_from_dict(sub)
        extend_dates = status in ("active", "trialing") and period_end
        if extend_dates and (not user.membership_end or period_end > user.membership_end):
            user.membership_end = period_end

        lic = _latest_license_for(user)
        if lic:
            if lic.status == "expired":
                lic.status = "active"
            if extend_dates and (not lic.expires_at or period_end > lic.expires_at):
                lic.expires_at = period_end
    else:
        if user.membership_status in ("active", "cancelled"):
            user.membership_status = "expired"
        if not user.membership_end or user.membership_end > now:
            user.membership_end = now
        lic = _latest_license_for(user)
        if lic and lic.status == "active":
            lic.status = "expired"
            if not lic.expires_at or lic.expires_at > now:
                lic.expires_at = now

    db.session.commit()

    if previous != status:
        logger.info(f"[STRIPE] {user.email}: subscription status {previous} -> {status} ({source})")
        log_audit(
            user.id,
            "stripe_status_changed",
            f"{previous or 'none'} -> {status} | sub={user.stripe_subscription_id} | via={source}",
            "system",
        )
    return status


def refresh_user_from_stripe(user, source="reconcile"):
    """Re-read the user's subscription from Stripe and apply it. Never raises."""
    if not user.stripe_subscription_id:
        return None
    try:
        sub = fetch_stripe_subscription(user.stripe_subscription_id)
        if not sub:
            return None
        return apply_stripe_subscription_state(
            user, sub, source=source, preserve_future_grants=(source == "migration")
        )
    except Exception as e:
        logger.warning(f"[STRIPE] Could not refresh {user.email} from Stripe ({source}): {e}")
        db.session.rollback()
        return None


_last_stripe_reconcile = 0.0


def reconcile_stripe_subscriptions(force=False):
    """
    Safety net for missed webhooks: re-read subscriptions from Stripe whose
    local state may be stale, and correct any drift.

    Candidates (terminal "canceled" and admin-override users are skipped):
      - no stored status yet (backfill for existing subscribers)
      - past_due / unpaid / incomplete / paused (waiting for a Stripe outcome)
      - "active" but membership_end has already passed (a renewal webhook
        probably didn't arrive - e.g. a SEPA debit still settling)
    Throttled to Config.STRIPE_RECONCILE_INTERVAL_SECONDS per process.
    """
    global _last_stripe_reconcile
    if stripe is None or not Config.STRIPE_API_KEY:
        return
    now_ts = time.time()
    if not force and now_ts - _last_stripe_reconcile < Config.STRIPE_RECONCILE_INTERVAL_SECONDS:
        return
    _last_stripe_reconcile = now_ts

    try:
        now = datetime.utcnow()
        candidates = User.query.filter(
            User.stripe_subscription_id.isnot(None),
            User.membership_status != "revoked",
            db.or_(
                User.stripe_subscription_status.is_(None),
                User.stripe_subscription_status.in_(
                    ["past_due", "unpaid", "incomplete", "paused", "trialing"]
                ),
                db.and_(
                    User.stripe_subscription_status == "active",
                    User.membership_end.isnot(None),
                    User.membership_end < now,
                ),
            ),
        ).limit(Config.STRIPE_RECONCILE_BATCH_SIZE).all()

        if not candidates:
            return

        logger.info(f"[STRIPE] Reconcile: checking {len(candidates)} subscription(s)")
        for user in candidates:
            refresh_user_from_stripe(user, source="reconcile")

    except Exception as e:
        logger.error(f"[STRIPE] Error in reconcile_stripe_subscriptions: {e}")
        db.session.rollback()


def record_stripe_renewal_order(user, invoice):
    """
    Record a PAID Stripe renewal invoice as an Order, so renewals show up in
    Total Revenue, the Orders list and the user's order history (before this,
    only the first checkout created an Order, so every renewal was invisible).

    Idempotent: the invoice id is stored as the order's unique id, so webhook
    redeliveries and the one-time backfill can never double count. Zero-amount
    invoices (credits/trials) are not revenue and are skipped.
    Returns the new Order, or None if skipped / already recorded.
    """
    invoice_id = invoice.get("id")
    if not invoice_id:
        return None
    try:
        # Date the order by when Stripe actually collected the money (for SEPA
        # that is the settlement day), not by when we happened to record it.
        paid_at = None
        try:
            paid_ts = (invoice.get("status_transitions") or {}).get("paid_at")
            if paid_ts:
                paid_at = datetime.utcfromtimestamp(paid_ts)
        except Exception:
            paid_at = None

        existing = Order.query.filter_by(wix_order_id=invoice_id).first()
        if existing:
            # Correct the date of an order recorded earlier with the wrong day
            if (
                paid_at
                and existing.ip_address == "stripe"
                and existing.created_at
                and abs((existing.created_at - paid_at).total_seconds()) > 3600
            ):
                existing.created_at = paid_at
                db.session.commit()
                logger.info(f"[STRIPE] Corrected date of renewal order {invoice_id} to {paid_at}")
            return None
        amount = (invoice.get("amount_paid") or 0) / 100
        if amount <= 0:
            return None
        order = Order(
            user_id=user.id,
            wix_order_id=invoice_id,
            plan_name=user.plan_name,
            plan_price=amount,
            currency=(invoice.get("currency") or user.currency or "eur").upper(),
            total_amount=amount,
            subscription_type=user.subscription_type,
            subscription_duration_days=user.subscription_duration_days,
            status="completed",
            payment_status="paid",
            ip_address="stripe",
            raw_data=json.dumps(invoice, default=str),
        )
        if paid_at:
            order.created_at = paid_at
        db.session.add(order)
        db.session.commit()
        logger.info(f"[STRIPE] Recorded renewal order {invoice_id} for {user.email}: {amount:.2f}")
        return order
    except Exception as e:
        # e.g. a racing duplicate hitting the unique constraint - never break the webhook
        logger.warning(f"[STRIPE] Could not record renewal order {invoice_id}: {e}")
        db.session.rollback()
        return None


def backfill_stripe_renewal_orders():
    """
    Create Orders for renewal invoices Stripe already collected before renewals
    were recorded. Only "subscription_cycle" invoices are used: the first
    invoice of a subscription is already covered by the checkout Order and
    would be double counted. Safe to run repeatedly. Returns (scanned, created).
    """
    if stripe is None or not Config.STRIPE_API_KEY:
        return (0, 0)
    scanned = created = 0
    users = User.query.filter(User.stripe_subscription_id.isnot(None)).all()
    for user in users:
        try:
            invoices = stripe.Invoice.list(
                subscription=user.stripe_subscription_id, status="paid", limit=100
            )
            for inv in invoices.auto_paging_iter():
                d = inv.to_dict() if hasattr(inv, "to_dict") else dict(inv)
                if d.get("billing_reason") != "subscription_cycle":
                    continue
                scanned += 1
                if record_stripe_renewal_order(user, d):
                    created += 1
        except Exception as e:
            logger.warning(f"[STRIPE] Renewal-order backfill failed for {user.email}: {e}")
            db.session.rollback()
    logger.info(f"[STRIPE] Renewal-order backfill: scanned={scanned} created={created}")
    return (scanned, created)


def send_payment_failed_email(user, invoice):
    """Dutch 'betaling mislukt' email while Stripe is still retrying (or after the last try)."""
    try:
        next_ts = invoice.get("next_payment_attempt")
        next_dt = datetime.utcfromtimestamp(next_ts) if next_ts else None
        name = user.first_name or "klant"
        portal = f"{Config.APP_URL.rstrip('/')}/dashboard"

        if next_dt:
            retry_nl = (
                f"We proberen de betaling automatisch opnieuw op {format_date_dutch(next_dt)}. "
                f"Je toegang blijft in de tussentijd gewoon actief."
            )
            subject = "Je betaling is mislukt - we proberen het opnieuw"
        else:
            retry_nl = (
                "Dit was de laatste automatische poging. Zonder een geslaagde betaling wordt "
                "je abonnement binnenkort beëindigd en verlies je de toegang tot je EA's en VPS."
            )
            subject = "Laatste kans: je betaling is mislukt"

        text = (
            f"Hoi {name},\n\n"
            f"Je maandelijkse betaling voor Trading Engine is helaas mislukt. {retry_nl}\n\n"
            f"Controleer of er voldoende saldo staat en of je betaalgegevens kloppen. "
            f"Kom je er niet uit? Reageer dan op deze e-mail.\n\nDashboard: {portal}"
        )
        html = (
            f"<h3>Je betaling is mislukt</h3><p>Hoi {name},</p>"
            f"<p>Je maandelijkse betaling voor Trading Engine is helaas mislukt. {retry_nl}</p>"
            f"<p>Controleer of er voldoende saldo staat en of je betaalgegevens kloppen. "
            f"Kom je er niet uit? Reageer dan op deze e-mail.</p>"
            f"<p><a href=\"{portal}\">Naar je dashboard</a></p>"
        )
        send_email_async(subject, [user.email], text, html)
    except Exception as e:
        # Never let an email problem break the webhook
        logger.error(f"[EMAIL] Failed to queue payment-failed email for {user.email}: {e}")


def send_subscription_ended_email(user):
    """Dutch email when Stripe ended the subscription because payment never succeeded."""
    try:
        name = user.first_name or "klant"
        lost = "de EA's en je VPS" if Config.SHOW_VPS_SECTION else "de EA's"
        text = (
            f"Hoi {name},\n\nOmdat we je betaling niet konden incasseren, is je abonnement bij "
            f"Trading Engine beëindigd. Je toegang tot {lost} is daarmee gestopt. "
            f"Wil je weer verder? Sluit dan een nieuw abonnement af, dan zetten we alles weer voor je klaar."
        )
        html = (
            f"<h3>Je abonnement is beëindigd</h3><p>Hoi {name},</p>"
            f"<p>Omdat we je betaling niet konden incasseren, is je abonnement bij Trading Engine "
            f"beëindigd. Je toegang tot {lost} is daarmee gestopt.</p>"
            f"<p>Wil je weer verder? Sluit dan een nieuw abonnement af, dan zetten we alles weer voor je klaar.</p>"
        )
        send_email_async("Je abonnement is beëindigd", [user.email], text, html)
    except Exception as e:
        logger.error(f"[EMAIL] Failed to queue subscription-ended email for {user.email}: {e}")


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


def send_members_platform_ready_email(user):
    """
    Send the dedicated 'your Members Platform account is ready' email with
    a clickable login button.

    This is separate and in addition to the general welcome email - the
    welcome email confirms the purchase/plan, this one is a focused
    invitation to actually log in, with a real button rather than a plain
    text URL buried in the welcome copy.

    Copy is Dutch only, in line with every other outgoing email.
    """
    try:
        login_url = f"{Config.APP_URL}/login"
        first_name = user.first_name or 'daar'

        button_style = (
            "display:inline-block;padding:12px 28px;background:#12182B;"
            "color:#ffffff;text-decoration:none;border-radius:8px;"
            "font-weight:700;font-size:14px;letter-spacing:0.02em;"
        )

        subject = "Je Trading Engine Members Platform is klaar 🚀"
        body = (
            f"Hi {first_name},\n\n"
            f"Je account voor het Trading Engine Members Platform is aangemaakt "
            f"en klaar voor gebruik.\n\n"
            f"Via onderstaande link kun je direct inloggen:\n"
            f"{login_url}\n\n"
            f"Tot snel!"
        )
        html_body = (
            f"<h3>Je Trading Engine Members Platform is klaar 🚀</h3>"
            f"<p>Hi {first_name},</p>"
            f"<p>Je account voor het Trading Engine Members Platform is aangemaakt "
            f"en klaar voor gebruik.</p>"
            f"<p>Via onderstaande link kun je direct inloggen:</p>"
            f"<p><a href=\"{login_url}\" style=\"background-color: #3FBFB3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;\">"
            f"INLOGGEN OP HET MEMBERS PLATFORM</a></p>"
        )

        send_email_async(subject, [user.email], body, html_body)
        logger.info(f"[EMAIL] Members Platform login email queued for {user.email}")

    except Exception as e:
        # Never let an email failure break the payment/membership flow
        logger.error(f"[EMAIL] Failed to queue Members Platform login email for {user.email}: {e}")


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

def claim_vps_ready_email_slot(user):
    """
    Atomically claim the right to send the "VPS ready" email for the user's
    CURRENT vps_id, using a single conditional UPDATE.

    Multiple worker processes/threads (the background poller, a direct
    provisioning call, an admin retry, etc.) can all notice a VPS became
    ready at nearly the same moment. A plain Python if-check on
    user.vps_ready_email_sent_at is NOT safe against that race, because two
    processes can both read "not sent yet" before either writes back.

    A single UPDATE ... WHERE vps_ready_email_sent_at IS NULL is atomic at
    the database level: only one caller's UPDATE can match the WHERE clause
    and affect a row, so only one caller gets rowcount == 1 back. That
    caller - and only that caller - should send the email.

    Returns True if this call won the race (send the email), False if
    someone else already claimed it (skip sending).
    """
    try:
        result = db.session.execute(
            db.text("""
                UPDATE users
                SET vps_ready_email_sent_at = :now
                WHERE id = :uid
                  AND vps_id = :vps_id
                  AND vps_ready_email_sent_at IS NULL
            """),
            {"now": datetime.utcnow(), "uid": user.id, "vps_id": user.vps_id}
        )
        db.session.commit()
        won = result.rowcount == 1
        if not won:
            logger.info(
                f"[ThinkHuge] VPS ready email for {user.email} already claimed "
                f"by another process/thread - skipping duplicate send"
            )
        return won
    except Exception as e:
        logger.error(f"[ThinkHuge] Failed to claim VPS ready email slot for {user.email}: {e}")
        db.session.rollback()
        # Fail safe: if the claim itself errors, don't send - better to miss
        # a rare edge case than to spam a duplicate email.
        return False


def send_vps_ready_email(user):
    """
    Notify the user their VPS is ready, with login details included.

    This can be called from a background thread (polling/retry sweep) as
    well as from a normal request, so it deliberately avoids anything that
    depends on Flask's request/session context (e.g. get_user_language()).

    All copy is Dutch only, regardless of the user's stored language
    preference - the platform now sends a single, consistent language for
    every email.

    Callers should call claim_vps_ready_email_slot(user) first and only
    call this function if that returns True, to avoid duplicate emails.
    """
    try:
        port = user.vps_port or Config.FOREXVPS_DEFAULT_RDP_PORT
        password = decrypt_data(user.vps_password) if user.vps_password else None
        first_name = user.first_name or 'daar'

        members_platform_url = "https://members.tradingengine.nl/dashboard"
        academy_url = "https://www.tradingengine.nl/academy"
        # Fall back to the app-wide configured invite if set, so this stays
        # in sync with the Discord button elsewhere on the dashboard; the
        # client-supplied URL is used as the default otherwise.
        discord_url = Config.DISCORD_INVITE_LINK or "https://discord.com/invite/RRpN2Am8xj"
        support_email = "support@thinkhuge.net"

        if not user.vps_ip or not password:
            logger.warning(
                f"[ThinkHuge] Skipping VPS ready email for {user.email} - "
                f"missing IP or password (ip={user.vps_ip}, has_password={bool(password)})"
            )
            return

        subject = "Je Forex VPS is klaar! 🎉"
        body = (
            f"Hi {first_name},\n\n"
            f"Goed nieuws! Je Forex VPS is aangemaakt en klaar voor gebruik.\n\n"
            f"Jouw VPS-gegevens\n"
            f"RDP-adres: {user.vps_ip}:{port}\n"
            f"Gebruikersnaam: {user.vps_username}\n"
            f"Wachtwoord: {password}\n\n"
            f"Je kunt je VPS-gegevens ook altijd terugvinden in je Members Platform: "
            f"{members_platform_url}\n\n"
            f"Hoe nu verder?\n"
            f"Ga naar de Trading Engine Academy: {academy_url}\n"
            f"Bekijk daar de Tutorials en volg daarna de Setup Guide stap voor stap "
            f"om alles correct in te stellen.\n\n"
            f"Heb je een technische vraag rondom je VPS? Dan kun je mailen naar "
            f"{support_email}\n\n"
            f"Heb je andere vragen of loop je ergens tegenaan? Stel je vraag binnen "
            f"de Discord Community: {discord_url}\n\n"
            f"Let's get the Engine Started 🚀\n\n"
            f"Dave & Josefien\n"
            f"Team Trading Engine"
        )
        html_body = (
            f"<h3>Je Forex VPS is klaar! 🎉</h3>"
            f"<p>Hi {first_name},</p>"
            f"<p>Goed nieuws! Je Forex VPS is aangemaakt en klaar voor gebruik.</p>"
            f"<p><strong>Jouw VPS-gegevens</strong><br>"
            f"RDP-adres: {user.vps_ip}:{port}<br>"
            f"Gebruikersnaam: {user.vps_username}<br>"
            f"Wachtwoord: {password}</p>"
            f"<p>Je kunt je VPS-gegevens ook altijd terugvinden in je "
            f"<a href=\"{members_platform_url}\">Members Platform</a>.</p>"
            f"<p><strong>Hoe nu verder?</strong><br>"
            f"Ga naar de <a href=\"{academy_url}\">Trading Engine Academy</a>.<br>"
            f"Bekijk daar de Tutorials en volg daarna de Setup Guide stap voor stap "
            f"om alles correct in te stellen.</p>"
            f"<p>Heb je een technische vraag rondom je VPS? Dan kun je mailen naar "
            f"<a href=\"mailto:{support_email}\">{support_email}</a></p>"
            f"<p>Heb je andere vragen of loop je ergens tegenaan? Stel je vraag binnen "
            f"de <a href=\"{discord_url}\">Discord Community</a>.</p>"
            f"<p>Let's get the Engine Started 🚀</p>"
            f"<p>Dave &amp; Josefien<br>Team Trading Engine</p>"
        )

        send_email_async(subject, [user.email], body, html_body)
        logger.info(f"[ThinkHuge] VPS ready email queued for {user.email}")

    except Exception as e:
        # Never let an email failure break VPS provisioning
        logger.error(f"[ThinkHuge] Failed to queue VPS ready email for {user.email}: {e}")


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
        if claim_vps_ready_email_slot(user):
            send_vps_ready_email(user)
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
    # New server -> reset the "ready email sent" claim so this new VPS gets
    # its own notification instead of being blocked by a prior VPS's claim.
    user.vps_ready_email_sent_at = None

    if result.get('ready'):
        user.vps_status = 'active'
        user.vps_ip = result.get('ip')
        user.vps_port = Config.FOREXVPS_DEFAULT_RDP_PORT
        user.vps_username = result.get('username')
        user.vps_password = encrypt_data(result.get('password', ''))
        db.session.commit()
        logger.info(f"[ThinkHuge] VPS provisioned and ready for {user.email}: {user.vps_id} | IP: {user.vps_ip}:{user.vps_port}")
        if claim_vps_ready_email_slot(user):
            send_vps_ready_email(user)
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
    """
    Terminate VPS for users who no longer have access.

    "No access" is decided by User.has_active_access(), the same check used
    everywhere else: for Stripe-managed users that means Stripe cancelled the
    subscription (never merely "past_due" while Stripe is still retrying, and
    never because a local date passed); for everyone else it is the date.
    """
    try:
        candidates = User.query.filter(
            User.vps_id.isnot(None),
            User.vps_status == 'active',
            User.is_admin == False,
            db.or_(
                User.stripe_subscription_id.isnot(None),
                User.membership_end < datetime.utcnow(),
                User.membership_status.in_(['expired', 'revoked']),
            ),
        ).all()

        expired_users = [u for u in candidates if not u.has_active_access()]

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

    # Correct any missed Stripe webhooks first, so the VPS cleanup below acts
    # on Stripe's real state (throttled internally)
    reconcile_stripe_subscriptions()

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

            # Create broker_accounts table if missing (WWA integration)
            if 'broker_accounts' not in existing_tables:
                logger.info("Creating broker_accounts table...")
                db.session.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS broker_accounts (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        broker VARCHAR(100) NOT NULL,
                        uid VARCHAR(100) NOT NULL,
                        attribution_status VARCHAR(20) DEFAULT 'pending',
                        registration_status VARCHAR(50),
                        registration_date TIMESTAMP,
                        country VARCHAR(10),
                        deposit_amount FLOAT DEFAULT 0.0,
                        deposit_date TIMESTAMP,
                        required_deposit FLOAT DEFAULT 1000.0,
                        volume_lots FLOAT DEFAULT 0.0,
                        required_volume_lots FLOAT DEFAULT 1.0,
                        cpa_status VARCHAR(20) DEFAULT 'pending',
                        commission_amount FLOAT DEFAULT 0.0,
                        commission_status VARCHAR(20) DEFAULT 'pending',
                        last_checked_at TIMESTAMP,
                        last_check_error VARCHAR(300),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT uq_user_broker_uid UNIQUE (user_id, broker, uid)
                    )
                """))
                db.session.execute(db.text("""
                    CREATE INDEX IF NOT EXISTS idx_broker_accounts_uid ON broker_accounts(uid)
                """))
                db.session.commit()
                logger.info("broker_accounts table created")

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
                'vps_ready_email_sent_at',
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

            # Stripe subscription status (access follows Stripe, not local dates)
            if 'stripe_subscription_status' not in columns:
                logger.info("Adding stripe_subscription_status column to users table...")
                db.session.execute(db.text("""
                    ALTER TABLE users ADD COLUMN stripe_subscription_status VARCHAR(30)
                """))
                db.session.commit()
                logger.info("stripe_subscription_status column added")

            # Backfill: existing subscribers get their status from Stripe. Users
            # whose lookup fails stay NULL (date-based until the next sweep).
            try:
                to_backfill = User.query.filter(
                    User.stripe_subscription_id.isnot(None),
                    User.stripe_subscription_status.is_(None),
                ).all()
                if to_backfill and stripe is not None and Config.STRIPE_API_KEY:
                    logger.info(f"Backfilling Stripe subscription status for {len(to_backfill)} user(s)...")
                    for u in to_backfill:
                        refresh_user_from_stripe(u, source="migration")
            except Exception as e:
                logger.error(f"Stripe status backfill failed (will retry via reconcile sweep): {e}")
                db.session.rollback()

            # One-time: record renewals Stripe already collected (they were never
            # counted as revenue). Flagged in settings so it runs once; it is
            # idempotent anyway, and /admin/backfill-renewal-orders can re-run it.
            # (v2: also corrects the date of renewal orders recorded with the
            # backfill day instead of the payment day, and fills in the missing
            # currency on older Stripe checkout orders.)
            try:
                done = Setting.query.filter_by(key="stripe_renewal_orders_backfilled_v2").first()
                if not done:
                    if stripe is not None and Config.STRIPE_API_KEY:
                        scanned, created = backfill_stripe_renewal_orders()
                        logger.info(f"Renewal-order backfill complete: {created} order(s) added")

                    fixed = 0
                    for order in Order.query.filter(
                        Order.currency.is_(None), Order.wix_order_id.like("cs_%")
                    ).all():
                        order.currency = (order.user.currency if order.user else None) or "EUR"
                        fixed += 1
                    if fixed:
                        logger.info(f"Filled in missing currency on {fixed} Stripe checkout order(s)")

                    db.session.add(Setting(key="stripe_renewal_orders_backfilled_v2", value="1"))
                    db.session.commit()
            except Exception as e:
                logger.error(f"Renewal-order backfill failed: {e}")
                db.session.rollback()

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
            send_email_async(
                "Admin OTP-code - Trading Engine",
                [admin_email],
                f"Jouw admin OTP code is: {otp}\n\nDeze code is {Config.ADMIN_OTP_EXPIRY_MINUTES} minuten geldig.",
                f"<h3>Admin OTP-code</h3><p><strong>{otp}</strong></p><p>Deze code is {Config.ADMIN_OTP_EXPIRY_MINUTES} minuten geldig.</p>"
            )

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

    # Broker accounts (WWA)
    broker_accounts = BrokerAccount.query.filter_by(user_id=user.id).all()

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
        # VPS section is hidden (we no longer provide VPS - clients buy it
        # directly from ForexVPS). Set SHOW_VPS_SECTION=true to bring it back.
        show_vps_section=Config.SHOW_VPS_SECTION,
        vps_password_decrypted=vps_password_decrypted if Config.SHOW_VPS_SECTION else None,
        vps_default_port=Config.FOREXVPS_DEFAULT_RDP_PORT,
        indicator_download_url=url_for('download_connector') if connector else None,
        indicator_version=connector.version if connector else '1.0',
        webrequest_url=Config.APP_URL,
        broker_accounts=broker_accounts
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

        # Anchor the stored date to the paid period when there is one, not to
        # "now + N days" (that mismatch is what let a license expire before the
        # billing date). For Stripe-managed users access follows Stripe anyway.
        if (
            not is_test
            and current_user.membership_end
            and current_user.membership_end > datetime.utcnow()
        ):
            license_expires_at = current_user.membership_end
        else:
            license_expires_at = datetime.utcnow() + timedelta(days=days)

        lic = License(
            user_id=current_user.id,
            license_key=key,
            expires_at=license_expires_at,
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

        # Send license email (Dutch only)
        send_email_async(
            "Jouw Licentiesleutel - Trading Engine",
            [current_user.email],
            f"Licentiesleutel: {key}\nEA Portfolio: Actief\nMax MT5 Accounts: {max_accounts}",
            f"<h3>Jouw Licentiesleutel</h3><p><strong>{key}</strong></p><p>EA Portfolio: Actief</p><p>Max MT5 Accounts: {max_accounts}</p>"
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

        # Send confirmation email (Dutch only)
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
# VPS SELF-SERVICE ROUTES
# ============================================================================

@app.route("/vps/reset-password", methods=["POST"])
@login_required
@limiter.limit("5 per day")
def user_reset_vps_password():
    """Let a user reset their own VPS password on demand."""
    lang = get_user_language()
    user = current_user

    if user.is_admin:
        msg = "Admin accounts hebben geen zelfbedienings-VPS." if lang == 'nl' else "Admin accounts don't use the self-service VPS."
        return jsonify({"success": False, "error": msg}), 400

    if not user.vps_id or user.vps_status != 'active':
        msg = "Je hebt nog geen actieve VPS." if lang == 'nl' else "You don't have an active VPS yet."
        return jsonify({"success": False, "error": msg}), 400

    try:
        password = forexvps_client.reset_password(user.vps_id)
        user.vps_password = encrypt_data(password)
        user.vps_last_error = None
        db.session.commit()

        log_audit(user.id, "vps_password_reset", f"vps_id={user.vps_id}", request.remote_addr)
        logger.info(f"[ThinkHuge] User-initiated password reset for {user.email} ({user.vps_id})")

        return jsonify({
            "success": True,
            "password": password,
            "message": "Nieuw wachtwoord ingesteld." if lang == 'nl' else "New password set."
        })
    except urllib.error.HTTPError as e:
        detail = forexvps_client._error_detail(e)
        logger.error(f"[ThinkHuge] User password reset failed for {user.email}: {e.code} - {detail}")
        user.vps_last_error = f"{e.code} - {detail}"[:300]
        db.session.commit()
        msg = "Wachtwoord resetten mislukt. Probeer later opnieuw." if lang == 'nl' else "Password reset failed. Please try again later."
        return jsonify({"success": False, "error": msg}), 502
    except Exception as e:
        logger.error(f"[ThinkHuge] User password reset error for {user.email}: {e}")
        db.session.rollback()
        msg = "Wachtwoord resetten mislukt." if lang == 'nl' else "Password reset failed."
        return jsonify({"success": False, "error": msg}), 500


# ============================================================================
# WWA BROKER TRACKER ROUTES
# ============================================================================

def _find_broker_account_by_uid(uid):
    """
    Postbacks only carry [userid] (the UID), not our internal broker name,
    so match on uid alone. If a UID is somehow registered under more than
    one broker for the same user, this takes the most recently created -
    in practice a given UID belongs to exactly one broker.
    """
    return BrokerAccount.query.filter_by(uid=uid).order_by(BrokerAccount.created_at.desc()).first()


def _check_postback_secret():
    """Optional shared-secret check if WWA_POSTBACK_SECRET is set and
    &secret=... was included in the postback URLs configured at WWA."""
    if not Config.WWA_POSTBACK_SECRET:
        return True
    return request.args.get("secret") == Config.WWA_POSTBACK_SECRET


@app.route("/broker/check-uid", methods=["POST"])
@login_required
def broker_check_uid():
    """
    Called from the member dashboard when a member enters a broker + UID.
    Looks the UID up against WWA and stores/updates a BrokerAccount row.
    """
    payload = request.get_json(silent=True) or {}
    broker = (request.form.get("broker") or payload.get("broker") or "").strip()
    uid = (request.form.get("uid") or payload.get("uid") or "").strip()

    if not broker or not uid:
        return jsonify({"success": False, "error": "Broker and UID are required"}), 400

    account = BrokerAccount.query.filter_by(
        user_id=current_user.id, broker=broker, uid=uid
    ).first()

    if not account:
        account = BrokerAccount(user_id=current_user.id, broker=broker, uid=uid)
        db.session.add(account)

    if not wwa_client.is_configured():
        account.attribution_status = "pending"
        account.last_check_error = "WWA API not configured"
        db.session.commit()
        return jsonify({"success": True, "attribution_status": "pending", "note": "WWA not configured yet"})

    try:
        reg = wwa_client.get_registration(uid)
        account.last_checked_at = datetime.utcnow()
        account.last_check_error = None

        if reg:
            account.attribution_status = "confirmed"
            account.registration_status = reg.get("Status")
            account.country = reg.get("Country")
            try:
                account.deposit_amount = float(reg.get("First_Deposit") or reg.get("Deposits") or 0)
            except (TypeError, ValueError):
                pass
            try:
                account.volume_lots = float(reg.get("Volume") or 0)
            except (TypeError, ValueError):
                pass
            reg_date = reg.get("Registration_Date")
            if reg_date:
                for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                    try:
                        account.registration_date = datetime.strptime(reg_date[:26], fmt)
                        break
                    except ValueError:
                        continue
        else:
            account.attribution_status = "not_attributed"

        db.session.commit()
        log_audit(current_user.id, "broker_uid_checked", f"{broker} | {uid} | {account.attribution_status}", request.remote_addr)

        return jsonify({
            "success": True,
            "attribution_status": account.attribution_status,
            "deposit_amount": account.deposit_amount,
            "volume_lots": account.volume_lots,
        })

    except Exception as e:
        logger.error(f"[WWA] UID check failed for {uid}: {e}")
        account.last_check_error = str(e)[:300]
        account.last_checked_at = datetime.utcnow()
        db.session.commit()
        return jsonify({
            "success": False,
            "error": "Could not verify with WWA right now - please try again shortly",
            "attribution_status": account.attribution_status,
        }), 502


@app.route("/broker/my-accounts")
@login_required
def broker_my_accounts():
    """Return the current user's broker accounts as JSON, for dashboard polling."""
    accounts = BrokerAccount.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        "accounts": [{
            "id": a.id,
            "broker": a.broker,
            "uid": a.uid,
            "attribution_status": a.attribution_status,
            "deposit_amount": a.deposit_amount,
            "required_deposit": a.required_deposit,
            "volume_lots": a.volume_lots,
            "required_volume_lots": a.required_volume_lots,
            "progress_pct": a.progress_pct(),
            "cpa_status": a.cpa_status,
            "commission_amount": a.commission_amount,
            "commission_status": a.commission_status,
        } for a in accounts]
    })


@app.route("/webhook/wwa/registration", methods=["GET", "POST"])
def wwa_postback_registration():
    """Postback receiver for WWA's Registration postback event."""
    if not _check_postback_secret():
        return jsonify({"error": "forbidden"}), 403
    uid = request.args.get("userid", "").strip()
    account = _find_broker_account_by_uid(uid)
    if account:
        account.attribution_status = "confirmed"
        account.registration_status = "New"
        account.registration_date = datetime.utcnow()
        account.country = request.args.get("isocountry") or account.country
        db.session.commit()
        logger.info(f"[WWA postback] registration for uid={uid}")
    else:
        logger.warning(f"[WWA postback] registration for unknown uid={uid}")
    return jsonify({"success": True}), 200


@app.route("/webhook/wwa/ftd", methods=["GET", "POST"])
def wwa_postback_ftd():
    """Postback receiver for WWA's FTD (first time deposit) postback event."""
    if not _check_postback_secret():
        return jsonify({"error": "forbidden"}), 403
    uid = request.args.get("userid", "").strip()
    account = _find_broker_account_by_uid(uid)
    if account:
        try:
            account.deposit_amount = float(request.args.get("transaction_sum") or account.deposit_amount)
        except (TypeError, ValueError):
            pass
        account.deposit_date = datetime.utcnow()
        db.session.commit()
        logger.info(f"[WWA postback] FTD for uid={uid} amount={account.deposit_amount}")
    else:
        logger.warning(f"[WWA postback] FTD for unknown uid={uid}")
    return jsonify({"success": True}), 200


@app.route("/webhook/wwa/qualified-cpa", methods=["GET", "POST"])
def wwa_postback_qualified_cpa():
    """Postback receiver for WWA's Qualified CPA postback event."""
    if not _check_postback_secret():
        return jsonify({"error": "forbidden"}), 403
    uid = request.args.get("userid", "").strip()
    account = _find_broker_account_by_uid(uid)
    if account:
        account.cpa_status = "qualified"
        db.session.commit()
        logger.info(f"[WWA postback] Qualified CPA for uid={uid}")
    else:
        logger.warning(f"[WWA postback] Qualified CPA for unknown uid={uid}")
    return jsonify({"success": True}), 200


@app.route("/webhook/wwa/commission", methods=["GET", "POST"])
def wwa_postback_commission():
    """Postback receiver for WWA's Commission postback event."""
    if not _check_postback_secret():
        return jsonify({"error": "forbidden"}), 403
    uid = request.args.get("userid", "").strip()
    account = _find_broker_account_by_uid(uid)
    if account:
        try:
            amount = float(request.args.get("commissionamount") or 0)
            account.commission_amount = (account.commission_amount or 0) + amount
        except (TypeError, ValueError):
            pass
        account.commission_status = "pending"  # flip to "paid" via your own payout process/admin action
        db.session.commit()
        logger.info(f"[WWA postback] Commission for uid={uid} amount={request.args.get('commissionamount')}")
    else:
        logger.warning(f"[WWA postback] Commission for unknown uid={uid}")
    return jsonify({"success": True}), 200


@app.route("/webhook/wwa/lead", methods=["GET", "POST"])
def wwa_postback_lead():
    """Postback receiver for WWA's Lead postback event."""
    if not _check_postback_secret():
        return jsonify({"error": "forbidden"}), 403
    uid = request.args.get("userid", "").strip()
    logger.info(f"[WWA postback] Lead for uid={uid} (no BrokerAccount action needed yet)")
    return jsonify({"success": True}), 200


@app.route("/admin/broker-tracker")
@admin_required
def admin_broker_tracker():
    """Admin Broker Tracker dashboard - attribution, deposits, volume, CPA, commission."""
    broker_filter = request.args.get("broker", "").strip()
    attribution_filter = request.args.get("attribution", "").strip()
    cpa_filter = request.args.get("cpa", "").strip()
    search = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 25

    query = BrokerAccount.query.join(User, BrokerAccount.user_id == User.id)

    if broker_filter:
        query = query.filter(BrokerAccount.broker == broker_filter)
    if attribution_filter:
        query = query.filter(BrokerAccount.attribution_status == attribution_filter)
    if cpa_filter:
        query = query.filter(BrokerAccount.cpa_status == cpa_filter)
    if search:
        like = f"%{search}%"
        query = query.filter(db.or_(
            User.email.ilike(like),
            User.first_name.ilike(like),
            User.last_name.ilike(like),
            BrokerAccount.uid.ilike(like),
        ))

    total = query.count()
    accounts = query.order_by(BrokerAccount.created_at.desc()) \
        .offset((page - 1) * per_page).limit(per_page).all()

    total_accounts = BrokerAccount.query.count()
    attributed_count = BrokerAccount.query.filter_by(attribution_status="confirmed").count()
    ftd_count = BrokerAccount.query.filter(BrokerAccount.deposit_amount > 0).count()
    cpa_qualified_count = BrokerAccount.query.filter_by(cpa_status="qualified").count()
    total_commission = db.session.query(db.func.sum(BrokerAccount.commission_amount)).scalar() or 0

    brokers = [b[0] for b in db.session.query(BrokerAccount.broker).distinct().all()]

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "admin/broker_tracker.html",
        accounts=accounts,
        total_accounts=total_accounts,
        attributed_count=attributed_count,
        ftd_count=ftd_count,
        cpa_qualified_count=cpa_qualified_count,
        total_commission=total_commission,
        brokers=brokers,
        broker_filter=broker_filter,
        attribution_filter=attribution_filter,
        cpa_filter=cpa_filter,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
    )


@app.route("/admin/broker-tracker/refresh/<int:account_id>", methods=["POST"])
@admin_required
def admin_broker_tracker_refresh(account_id):
    """Manually re-check a single broker account against the WWA API."""
    account = db.session.get(BrokerAccount, account_id)
    if not account:
        flash("Broker account not found.", "error")
        return redirect(url_for("admin_broker_tracker"))

    if not wwa_client.is_configured():
        flash("WWA API is not configured.", "error")
        return redirect(request.referrer or url_for("admin_broker_tracker"))

    try:
        reg = wwa_client.get_registration(account.uid)
        account.last_checked_at = datetime.utcnow()
        account.last_check_error = None
        if reg:
            account.attribution_status = "confirmed"
            account.registration_status = reg.get("Status")
            try:
                account.deposit_amount = float(reg.get("First_Deposit") or reg.get("Deposits") or account.deposit_amount)
                account.volume_lots = float(reg.get("Volume") or account.volume_lots)
            except (TypeError, ValueError):
                pass
        else:
            account.attribution_status = "not_attributed"
        db.session.commit()
        flash(f"Refreshed {account.uid} from WWA.", "success")
    except Exception as e:
        account.last_check_error = str(e)[:300]
        db.session.commit()
        flash(f"Refresh failed: {e}", "error")

    return redirect(request.referrer or url_for("admin_broker_tracker"))


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
    """Create a new journal account. Multiple users can link the same MT5 login."""
    name = request.form.get("name", "").strip()
    mt5_login = request.form.get("mt5_login", "").strip()

    if not name:
        name = f"MT5-{mt5_login}" if mt5_login else "MT5 Account"

    if not mt5_login:
        flash("MT5 login number is required.", "error")
        return redirect(url_for("journal_page", tab="accounts"))

    # REMOVED: Check for existing account with same MT5 login
    # Now multiple users can add the same MT5 login
    
    # Only check if THIS user already has this MT5 login
    existing = JournalAccount.query.filter_by(
        user_id=current_user.id, 
        mt5_login=mt5_login
    ).first()
    
    if existing:
        flash("You already have this MT5 login linked to your journal.", "error")
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
    flash(f"'{name}' connected! The sync service will auto-sync trades to all linked journals.", "success")
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
    Syncs trades to ALL journal accounts matching this MT5 login.
    """
    mt5_login = request.headers.get("X-MT5-Login", "").strip()

    if not mt5_login:
        return jsonify({"success": False, "error": "Missing MT5 login"}), 400

    # Find ALL journal accounts with this MT5 login
    accounts = JournalAccount.query.filter_by(
        mt5_login=mt5_login, 
        archived=False
    ).all()

    if not accounts:
        return jsonify({
            "success": False,
            "error": "No journal account found. Add your MT5 login on the journal page first."
        }), 404

    data = request.get_json(silent=True) or {}
    total_imported = 0
    total_skipped = 0

    for account in accounts:
        # Auto-detect account metadata for each account
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

        # Import trades for this account
        trades_payload = data.get("trades", [])
        imported = 0
        skipped = 0

        for tr in trades_payload:
            try:
                ticket = str(tr["ticket"])
            except KeyError:
                continue

            # Check if this trade already exists in THIS account
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

        # Update balance/equity for this account
        if "balance" in data:
            account.current_balance = data["balance"]
        if "equity" in data:
            account.current_equity = data["equity"]

        account.last_synced_at = datetime.utcnow()
        account.last_sync_error = None
        
        total_imported += imported
        total_skipped += skipped

    db.session.commit()

    # Only log at INFO when something actually happened. This endpoint is
    # polled repeatedly by every connected EA (often every few minutes,
    # sometimes multiple times a second across accounts) even when there
    # are zero new trades to sync - logging every single one of those
    # no-op heartbeats drowned out everything else in the app's logs.
    # A quiet, ordinary sync still gets a DEBUG line (visible if you
    # explicitly need to trace polling activity), just not at INFO.
    if total_imported > 0:
        logger.info(
            f"[JOURNAL] Sync for MT5-{mt5_login}: "
            f"{total_imported} new, {total_skipped} skipped "
            f"across {len(accounts)} account(s)"
        )
    else:
        logger.debug(
            f"[JOURNAL] Sync for MT5-{mt5_login}: "
            f"{total_imported} new, {total_skipped} skipped "
            f"across {len(accounts)} account(s)"
        )

    return jsonify({
        "success": True,
        "imported": total_imported,
        "skipped": total_skipped,
        "accounts_synced": len(accounts),
        "balance": accounts[0].current_balance if accounts else None,
        "equity": accounts[0].current_equity if accounts else None
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
    broker_accounts_count = BrokerAccount.query.count()

    recent_users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).limit(10).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    recent_licenses = License.query.order_by(License.created_at.desc()).limit(10).all()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    ea_files = EAFile.query.order_by(EAFile.upload_date.desc()).all()
    connector_indicator = MT5ConnectorIndicator.query.first()

    # Revenue per plan type = money actually collected (all orders incl. Stripe
    # renewals), not the sum of each user's plan price (which only ever showed
    # the first payment).
    subscription_stats = db.session.query(
        User.subscription_type,
        db.func.count(db.distinct(User.id)),
        db.func.sum(Order.total_amount)
    ).outerjoin(Order, Order.user_id == User.id).filter(
        User.is_admin == False
    ).group_by(User.subscription_type).all()

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
        broker_accounts_count=broker_accounts_count,
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

@app.route("/admin/backfill-renewal-orders", methods=["POST"])
@admin_required
def admin_backfill_renewal_orders():
    """Pull already-paid Stripe renewal invoices into Orders (idempotent)."""
    scanned, created = backfill_stripe_renewal_orders()
    flash(f"Stripe-verlengingen gecontroleerd: {scanned}, nieuw toegevoegd: {created}.", "success")
    return redirect(url_for("admin_dashboard"))


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
    broker_accounts = BrokerAccount.query.filter_by(user_id=user.id).order_by(BrokerAccount.created_at.desc()).all()

    vps_password = decrypt_data(user.vps_password) if user.vps_password else None

    return render_template(
        "admin/user_detail.html",
        user=user,
        orders=orders,
        licenses=licenses,
        journal_accounts=journal_accounts,
        broker_accounts=broker_accounts,
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
        # A manual grant on a subscription Stripe has already ended must not
        # be overridden by that subscription's "canceled" status.
        detach_dead_stripe_subscription(user)
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
    """Extend a user's membership AND their license key, seamlessly."""
    user = db.session.get(User, user_id)
    if user:
        days = int(request.form.get("days", 30))

        # If Stripe has already ended this user's subscription, Stripe's
        # "canceled" status would still override this manual extension, so
        # detach it (the user becomes date-based). A live subscription is
        # left alone - it already has access.
        detach_dead_stripe_subscription(user)

        # Extend membership
        if user.membership_end and user.membership_end > datetime.utcnow():
            user.membership_end += timedelta(days=days)
        else:
            user.membership_start = datetime.utcnow()
            user.membership_end = datetime.utcnow() + timedelta(days=days)
        user.membership_status = "active"

        # Extend the license key too - regardless of whether it's
        # currently active or already expired. Skip only if it was
        # deliberately revoked by an admin.
        license = user.licenses.filter(
            License.status != "revoked"
        ).order_by(License.created_at.desc()).first()

        if license:
            if license.expires_at and license.expires_at > datetime.utcnow():
                license.expires_at += timedelta(days=days)
            else:
                license.expires_at = datetime.utcnow() + timedelta(days=days)
            license.status = "active"
            flash(f"Verlengd met {days} dagen. Licentie {license.mask_license_key()} bijgewerkt.", "success")
        else:
            flash(f"Verlengd met {days} dagen. Geen licentie gevonden om te synchroniseren.", "warning")

        db.session.commit()
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
                "expires_at": lic.effective_expires_at().isoformat(),
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
            "expires_at": lic.effective_expires_at().isoformat(),
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
            # A new Wix purchase is date-based; don't let an older, ended
            # Stripe subscription's "canceled" status override it.
            detach_dead_stripe_subscription(user)
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
        send_members_platform_ready_email(user)

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
            # Checkout Session objects still carry "subscription" as a plain
            # top-level field in current Stripe API versions (this field
            # lives directly on the Session object, not nested under an
            # Invoice's "parent", so it isn't affected by the dahlia
            # Invoice schema change). Kept as a direct read intentionally -
            # see extract_subscription_id() for the Invoice-specific fix.
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

                # Prefer Stripe's own exact billing period end over a flat
                # local approximation, so a monthly subscription that
                # started on e.g. Aug 14 correctly ends Sep 14 (31 days),
                # not a hardcoded 30 days later. Falls back to the local
                # calculation if Stripe can't be reached or this isn't a
                # subscription checkout at all (e.g. lifetime one-time pay).
                exact_period_end = None
                stripe_status = None
                if stripe_subscription_id:
                    try:
                        sub_snapshot = fetch_stripe_subscription(stripe_subscription_id)
                    except Exception as e:
                        logger.warning(f"[STRIPE] Could not read new subscription {stripe_subscription_id}: {e}")
                        sub_snapshot = None
                    if sub_snapshot:
                        exact_period_end = subscription_period_end_from_dict(sub_snapshot)
                        stripe_status = sub_snapshot.get("status")
                    # A completed Checkout means Stripe accepted the order (card
                    # paid, or an async debit like SEPA is processing). Never
                    # lock a brand-new customer out just because Stripe hasn't
                    # flipped the status yet; the reconcile sweep and
                    # subscription.updated webhooks keep it accurate afterwards.
                    if stripe_status not in STRIPE_KNOWN_STATUSES or stripe_status == "incomplete":
                        stripe_status = "active"
                membership_end = exact_period_end or (membership_start + timedelta(days=duration_days))

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
                        stripe_subscription_status=stripe_status,
                    )
                    db.session.add(user)
                else:
                    user.membership_status = "active"
                    user.membership_start = membership_start
                    user.membership_end = membership_end
                    if stripe_subscription_id:
                        # New subscription replaces whatever was linked before
                        user.stripe_subscription_id = stripe_subscription_id
                        user.stripe_subscription_status = stripe_status
                    else:
                        # One-time purchase (e.g. lifetime): date-based. If an
                        # old Stripe subscription has already ended, detach it
                        # so its "canceled" status doesn't override this.
                        detach_dead_stripe_subscription(user)
                    user.stripe_customer_id = stripe_customer_id or user.stripe_customer_id

                if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
                    order = Order(
                        user_id=user.id,
                        wix_order_id=order_id,
                        plan_name=plan_name,
                        plan_price=amount_total,
                        currency=(session_data.get("currency") or "eur").upper(),
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
                send_members_platform_ready_email(user)

                log_audit(
                    user.id,
                    "stripe_payment",
                    f"{plan_name} | {subscription_type} | sub_id={stripe_subscription_id}",
                    request.remote_addr
                )

        elif event_type == "invoice.paid":
            invoice = event["data"]["object"]._to_dict_recursive()
            billing_reason = invoice.get("billing_reason")

            # "subscription_create" = the very first invoice, already handled
            # by checkout.session.completed above. Only "subscription_cycle"
            # is a genuine recurring renewal that needs extending here.
            if billing_reason != "subscription_cycle":
                logger.info(f"[STRIPE] Ignoring invoice.paid (billing_reason={billing_reason})")
            else:
                invoice_id = invoice.get("id")

                # FIXED: As of Stripe API version 2026-04-22.dahlia, invoices
                # no longer carry a top-level "subscription" field - it moved
                # to parent.subscription_details.subscription. Reading only
                # the old top-level field returned None here on every
                # renewal, which then fed straight into a
                # filter_by(stripe_subscription_id=None) lookup - silently
                # matching nothing (renewal skipped) or, worse, matching an
                # unrelated user whose stripe_subscription_id happened to be
                # NULL. extract_subscription_id() checks both locations.
                sub_id = extract_subscription_id(invoice)

                if not sub_id:
                    # Never silently fall through to a filter_by(None) query.
                    # If Stripe changes the schema again, this makes the
                    # failure loud instead of a quiet mismatch.
                    logger.error(
                        f"[STRIPE] invoice.paid ({invoice_id}) has billing_reason="
                        f"subscription_cycle but no resolvable subscription ID - "
                        f"check for another Stripe API schema change"
                    )
                else:
                    user = User.query.filter_by(stripe_subscription_id=sub_id).first()

                    if not user:
                        logger.warning(f"[STRIPE] invoice.paid for unknown subscription {sub_id}")
                    else:
                        # Idempotency guard - Stripe can redeliver the same webhook
                        already_processed = AuditLog.query.filter(
                            AuditLog.user_id == user.id,
                            AuditLog.action == "stripe_renewal",
                            AuditLog.details.like(f"%{invoice_id}%")
                        ).first()

                        # Ask Stripe for the subscription's CURRENT status. The
                        # "if all retries fail" setting leaves the invoice
                        # past-due after Stripe cancels the subscription, so an
                        # old invoice can still be paid later (e.g. via the
                        # hosted invoice link). That payment must NOT silently
                        # bring a cancelled subscription's access back.
                        live_status = user.stripe_subscription_status
                        live_sub = None
                        try:
                            live_sub = fetch_stripe_subscription(sub_id)
                            if live_sub and live_sub.get("status"):
                                live_status = live_sub.get("status")
                        except Exception as e:
                            logger.warning(f"[STRIPE] Could not confirm status of {sub_id} for invoice {invoice_id}: {e}")
                        subscription_ended = (
                            live_status in STRIPE_KNOWN_STATUSES
                            and live_status not in STRIPE_ACCESS_STATUSES
                        )

                        if already_processed:
                            logger.info(f"[STRIPE] Invoice {invoice_id} already processed for {user.email}, skipping")
                        elif subscription_ended:
                            logger.warning(
                                f"[STRIPE] Invoice {invoice_id} was paid for {user.email} but subscription "
                                f"{sub_id} is {live_status} - NOT restoring access. Needs manual review/refund."
                            )
                            if live_sub:
                                apply_stripe_subscription_state(user, live_sub, source="invoice.paid")
                            # The money was collected, so it is still recorded as revenue
                            record_stripe_renewal_order(user, invoice)
                            log_audit(
                                user.id,
                                "stripe_paid_on_ended_subscription",
                                f"invoice={invoice_id} | sub={sub_id} | status={live_status} | access NOT restored",
                                request.remote_addr
                            )
                        else:
                            days = user.subscription_duration_days or 30

                            # Prefer Stripe's own exact period end (already
                            # present in this invoice's payload) over a flat
                            # local "+N days" approximation. Stripe bills on
                            # real calendar cycles (e.g. Aug 14 -> Sep 14 is
                            # 31 days), so a flat 30-day add drifts by a day
                            # or two every cycle - which previously caused
                            # membership_end/license.expires_at to fall due
                            # BEFORE Stripe's actual renewal fired, making
                            # still-current subscribers show as "expired" a
                            # day or two early. Falls back to the old +days
                            # calculation only if this invoice has no usable
                            # period data.
                            exact_period_end = get_invoice_period_end(invoice)

                            # Extend membership - seamless whether still active or already lapsed
                            if exact_period_end:
                                user.membership_end = exact_period_end
                            elif user.membership_end and user.membership_end > datetime.utcnow():
                                user.membership_end += timedelta(days=days)
                            else:
                                user.membership_end = datetime.utcnow() + timedelta(days=days)
                            user.membership_status = "active"
                            # Paid invoice on a live subscription = Stripe says it is current.
                            user.stripe_subscription_status = (
                                live_status if live_status in STRIPE_ACCESS_STATUSES else "active"
                            )

                            # Extend/reactivate the license key the same way
                            license = user.licenses.filter(
                                License.status != "revoked"
                            ).order_by(License.created_at.desc()).first()

                            if license:
                                if exact_period_end:
                                    license.expires_at = exact_period_end
                                elif license.expires_at and license.expires_at > datetime.utcnow():
                                    license.expires_at += timedelta(days=days)
                                else:
                                    license.expires_at = datetime.utcnow() + timedelta(days=days)
                                license.status = "active"

                            db.session.commit()

                            # Count this renewal in revenue / order history
                            record_stripe_renewal_order(user, invoice)

                            log_audit(
                                user.id,
                                "stripe_renewal",
                                f"+{days}d | invoice={invoice_id} | license={license.mask_license_key() if license else 'none'}",
                                request.remote_addr
                            )
                            logger.info(f"[STRIPE] Renewed {user.email}: +{days}d, membership_end={user.membership_end}")

        elif event_type == "invoice.payment_failed":
            invoice = event["data"]["object"]._to_dict_recursive()
            invoice_id = invoice.get("id")
            sub_id = extract_subscription_id(invoice)
            user = User.query.filter_by(stripe_subscription_id=sub_id).first() if sub_id else None

            if not user:
                logger.info(f"[STRIPE] invoice.payment_failed ({invoice_id}) for unknown subscription {sub_id}")
            else:
                attempt = invoice.get("attempt_count") or 1
                has_next_attempt = bool(invoice.get("next_payment_attempt"))
                logger.warning(
                    f"[STRIPE] Payment failed for {user.email}: invoice={invoice_id} "
                    f"attempt={attempt} next_attempt={invoice.get('next_payment_attempt')}"
                )

                # Stripe moves the subscription to past_due (access is kept
                # while it retries). Re-read it so our stored status is right
                # even if the subscription.updated webhook arrives late.
                refresh_user_from_stripe(user, source="invoice.payment_failed")

                # One audit row + one email per failed attempt (idempotent on redelivery)
                marker = f"invoice={invoice_id} | attempt={attempt}"
                already_logged = AuditLog.query.filter(
                    AuditLog.user_id == user.id,
                    AuditLog.action == "stripe_payment_failed",
                    AuditLog.details.like(f"%{marker}%"),
                ).first()
                if not already_logged:
                    log_audit(
                        user.id,
                        "stripe_payment_failed",
                        f"{marker} | next_attempt={'yes' if has_next_attempt else 'no (final)'}",
                        request.remote_addr
                    )
                    # First failure, and the final one, are the useful moments to email
                    if attempt == 1 or not has_next_attempt:
                        send_payment_failed_email(user, invoice)

        elif event_type == "customer.subscription.deleted":
            sub = event["data"]["object"]._to_dict_recursive()
            sub_id = sub.get("id")
            user = User.query.filter_by(stripe_subscription_id=sub_id).first()
            if user:
                logger.info(f"[STRIPE] Subscription {sub_id} deleted at Stripe for {user.email}")
                was_revoked = user.membership_status == "revoked"
                # The REAL expiry: Stripe ended the subscription (period ended
                # after a user cancellation, or every payment retry failed).
                sub["status"] = "canceled"
                apply_stripe_subscription_state(user, sub, source="subscription.deleted")
                log_audit(user.id, "stripe_subscription_deleted", f"sub_id={sub_id}", request.remote_addr)

                reason = ((sub.get("cancellation_details") or {}).get("reason") or "")
                if reason == "payment_failed" and not was_revoked:
                    send_subscription_ended_email(user)

        elif event_type == "customer.subscription.updated":
            sub = event["data"]["object"]._to_dict_recursive()
            sub_id = sub.get("id")
            user = User.query.filter_by(stripe_subscription_id=sub_id).first()
            if user:
                logger.info(
                    f"[STRIPE] Subscription {sub_id} updated for {user.email}: "
                    f"status={sub.get('status')} cancel_at_period_end={sub.get('cancel_at_period_end')}"
                )
                # Prefer Stripe's live view over the event payload: events can be
                # delivered late or out of order, the live read can't be stale.
                live_sub = None
                try:
                    live_sub = fetch_stripe_subscription(sub_id)
                except Exception as e:
                    logger.warning(f"[STRIPE] Could not re-read {sub_id}, using event payload: {e}")
                apply_stripe_subscription_state(user, live_sub or sub, source="subscription.updated")

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
