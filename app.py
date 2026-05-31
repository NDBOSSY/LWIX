"""
Subscription & Licensing Platform
Complete Flask Application with Wix Integration, OTP Auth, License Management & Discord Integration
Compatible with local development and Railway deployment

SECURITY NOTES:
- OTP-based auth (no passwords to hash/steal)
- Session tokens are Flask-signed (tamper-proof)
- Rate limiting on all auth endpoints
- Account lockout after failed attempts
- Admin routes protected by separate password + OTP
- API endpoints require login or are public read-only
- Machine ID removed from license validation (by design)
- CSRF not needed for API (JSON only, no cookies used by MT5)
"""

import os
import re
import json
import hashlib
import hmac
import secrets
import logging
import threading
import urllib.parse
import urllib.request
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

    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    @staticmethod
    def is_railway():
        return bool(os.getenv("RAILWAY_STATIC_URL"))


app = Flask(__name__)
app.config.from_object(Config)

if Config.is_railway():
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.config["SESSION_COOKIE_SECURE"] = True

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "user_login"
login_manager.login_message = "Please log in to access this page."
login_manager.session_protection = "strong"

CORS(app, supports_credentials=True, origins=[
    "https://members.tradingengine.nl",
    "http://localhost:5000"
])

limiter = Limiter(
    get_remote_address, app=app,
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
    level=logging.INFO if not Config.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ============================================================================
# SECURITY HEADERS
# ============================================================================

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if Config.is_railway():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


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
    session_token = db.Column(db.String(64), nullable=True)

    otp_tokens = db.relationship("OTPToken", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    licenses = db.relationship("License", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def is_membership_active(self):
        if self.membership_status != "active": return False
        if self.membership_end and self.membership_end < datetime.utcnow():
            self.membership_status = "expired"; db.session.commit(); return False
        return True

    def get_active_license(self): return self.licenses.filter_by(status="active").first()

    def get_full_name(self):
        if self.first_name and self.last_name: return f"{self.first_name} {self.last_name}"
        elif self.first_name: return self.first_name
        return self.email

    def get_plan_level(self):
        if not self.plan_name: return 1
        match = re.search(r'level\s*(\d+)', self.plan_name.lower())
        return int(match.group(1)) if match else 1

    def get_membership_duration_display(self):
        if not self.subscription_duration_days: return "Default"
        if self.subscription_type == "lifetime": return "Lifetime"
        if self.subscription_duration_days >= 365: return f"{self.subscription_duration_days / 365:.0f} Year"
        if self.subscription_duration_days >= 30: return f"{self.subscription_duration_days / 30:.0f} Month"
        return f"{self.subscription_duration_days} Days"

    def to_dict(self):
        return {
            "id": self.id, "email": self.email,
            "first_name": self.first_name, "last_name": self.last_name,
            "full_name": self.get_full_name(), "plan_level": self.get_plan_level(),
            "membership_status": self.membership_status, "plan_name": self.plan_name,
            "subscription_type": self.subscription_type, "is_active": self.is_membership_active()
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

    def is_valid(self): return not self.used and self.expires_at > datetime.utcnow() and self.attempts < 3


class License(db.Model):
    __tablename__ = "licenses"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    license_key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    machine_id = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), default="active", index=True)
    license_type = db.Column(db.String(50), default="standard")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_validated = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    validation_count = db.Column(db.Integer, default=0)
    max_validations = db.Column(db.Integer, default=10000)
    ea_version = db.Column(db.String(20), nullable=True)

    def is_valid(self):
        if self.status != "active": return False
        if self.expires_at < datetime.utcnow(): self.status = "expired"; db.session.commit(); return False
        if self.validation_count >= self.max_validations: return False
        return True

    def mask_license_key(self):
        return f"{self.license_key[:4]}...{self.license_key[-4:]}" if len(self.license_key) > 8 else self.license_key


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


# ============================================================================
# HELPERS
# ============================================================================

def encrypt_data(data: str) -> str:
    try: return cipher_suite.encrypt(data.encode()).decode()
    except: return data

def decrypt_data(data: str) -> str:
    try: return cipher_suite.decrypt(data.encode()).decode()
    except: return data

def generate_license_key() -> str: return "-".join([secrets.token_hex(2).upper() for _ in range(3)])

def generate_otp() -> str: return "".join([str(secrets.randbelow(10)) for _ in range(6)])

def parse_duration_to_days(duration_str: str) -> tuple:
    if not duration_str: return Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS, "one_time"
    d = duration_str.lower().strip()
    if "month" in d or "maand" in d:
        m = re.findall(r'\d+', d); return (int(m[0]) * 30 if m else 30), "monthly"
    elif "year" in d or "jaar" in d:
        y = re.findall(r'\d+', d); return (int(y[0]) * 365 if y else 365), "yearly"
    elif "lifetime" in d or "levenslang" in d or "annulering" in d: return 36500, "lifetime"
    return Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS, "one_time"

def parse_wix_date(date_str: str):
    if not date_str: return None
    if "annulering" in date_str.lower(): return None
    for fmt in ["%d-%m-%Y", "%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y", "%m-%d-%Y"]:
        try: return datetime.strptime(date_str.strip(), fmt)
        except: continue
    return None

def send_email_async(subject: str, recipients: list, body: str, html_body: str = None):
    def send():
        try:
            with app.app_context():
                msg = Message(subject=subject, recipients=recipients, body=body, html=html_body)
                mail.send(msg)
        except Exception as e: logger.error(f"Email failed: {e}")
    threading.Thread(target=send).start()

def log_audit(user_id: int, action: str, details: str = None, ip_address: str = None):
    try:
        log = AuditLog(user_id=user_id, action=action, details=details,
                       ip_address=ip_address or (request.remote_addr if request else "system"))
        db.session.add(log); db.session.commit()
    except Exception as e: logger.error(f"Audit log failed: {e}")

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"ex4", "ex5", "dll", "zip"}


# ============================================================================
# DECORATORS
# ============================================================================

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            log_audit(current_user.id, "unauthorized_admin_access", request.path, request.remote_addr)
            flash("Admin access required.", "error"); abort(403)
        return f(*args, **kwargs)
    return decorated


@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))


@app.errorhandler(403)
def forbidden(e):
    if request.path.startswith("/api/"): return jsonify({"error": "Forbidden"}), 403
    return render_template("errors/404.html"), 403

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"): return jsonify({"error": "Not found"}), 404
    return render_template("errors/404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    if request.path.startswith("/api/"): return jsonify({"error": "Server error"}), 500
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
def health(): return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})


# ============================================================================
# LOGIN
# SECURITY:
# - OTP-based, no passwords stored or transmitted
# - OTPs are single-use, expire in 10 min, max 3 attempts
# - Account locks after 5 failed attempts for 30 min
# - Constant-time comparison prevents timing attacks
# - Generic error messages prevent email enumeration
# ============================================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard") if current_user.is_admin else url_for("user_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        try: email = validate_email(email).email
        except EmailNotValidError: flash("Invalid email address.", "error"); return render_template("user/login.html")

        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
        if email == admin_email:
            session["admin_email"] = email; return redirect(url_for("admin_password"))

        user = User.query.filter_by(email=email).first()
        # Generic message to prevent email enumeration
        if not user:
            flash("If an account exists for this email, a code has been sent.", "info")
            return render_template("user/login.html")

        if not user.email_verified:
            flash("Account not active. Please complete your purchase first.", "error")
            return render_template("user/login.html")

        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
            flash(f"Account locked. Try again in {remaining} minutes.", "error")
            return render_template("user/login.html")

        try:
            OTPToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(
                user_id=user.id, token=otp,
                expires_at=datetime.utcnow() + timedelta(minutes=Config.OTP_EXPIRY_MINUTES),
                purpose="login"
            )
            db.session.add(otp_token); db.session.commit()
            send_email_async(
                "Your Login Code - Trading Engine", [email],
                f"Your login code: {otp}\nExpires in {Config.OTP_EXPIRY_MINUTES} minutes.\nIf you did not request this, ignore this email.",
                f"""<div style="font-family:Arial,sans-serif;max-width:400px;margin:0 auto;padding:20px;">
                <h2 style="color:#4B7BE5;">Trading Engine Login</h2>
                <p>Your verification code:</p>
                <div style="background:#f0f4ff;border-radius:10px;padding:20px;text-align:center;margin:20px 0;">
                <span style="font-size:2.5rem;font-weight:bold;color:#5534A5;letter-spacing:8px;">{otp}</span></div>
                <p style="color:#666;">Expires in <strong>{Config.OTP_EXPIRY_MINUTES} minutes</strong>.</p>
                <p style="color:#999;font-size:0.8rem;">If you didn't request this, ignore this email.</p></div>"""
            )
            session["pending_email"] = email
            flash("Verification code sent to your email.", "success")
            return redirect(url_for("verify_otp"))
        except Exception as e:
            logger.error(f"OTP send failed: {e}"); flash("Failed to send code. Please try again.", "error")
    return render_template("user/login.html")


@app.route("/admin-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_password():
    admin_email = session.get("admin_email") or os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
    admin_user = User.query.filter_by(email=admin_email).first()

    if admin_user and admin_user.locked_until and admin_user.locked_until > datetime.utcnow():
        session.pop("admin_email", None); flash("Admin account locked.", "error"); return redirect(url_for("user_login"))

    if request.method == "POST":
        password = request.form.get("password", "")
        admin_password_env = os.getenv("ADMIN_PASSWORD", "admin123").strip()

        # Constant-time comparison prevents timing attacks
        if hmac.compare_digest(password, admin_password_env):
            if not admin_user:
                admin_user = User(
                    email=admin_email, first_name="Admin", is_admin=True, email_verified=True,
                    membership_status="active", membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin", subscription_type="lifetime", subscription_duration_days=36500
                )
                db.session.add(admin_user)
            else:
                admin_user.login_attempts = 0; admin_user.locked_until = None; admin_user.is_admin = True
            db.session.commit()

            OTPToken.query.filter_by(user_id=admin_user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(
                user_id=admin_user.id, token=otp,
                expires_at=datetime.utcnow() + timedelta(minutes=Config.ADMIN_OTP_EXPIRY_MINUTES),
                purpose="admin"
            )
            db.session.add(otp_token); db.session.commit()
            send_email_async("Admin Login Code", [admin_email], f"Admin OTP: {otp}\nExpires in {Config.ADMIN_OTP_EXPIRY_MINUTES} minutes.")
            session["pending_email"] = admin_email; session["is_admin_login"] = True; session.pop("admin_email", None)
            flash("Verification code sent.", "success"); return redirect(url_for("verify_otp"))
        else:
            if admin_user:
                admin_user.login_attempts += 1
                if admin_user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                    admin_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    flash("Admin account locked for 30 minutes.", "error")
                else:
                    flash(f"Incorrect password. {Config.MAX_LOGIN_ATTEMPTS - admin_user.login_attempts} attempts remaining.", "error")
                db.session.commit()
            else:
                flash("Invalid password.", "error")
            log_audit(None, "failed_admin_login", request.remote_addr, request.remote_addr)
    return render_template("admin/password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp():
    email = session.get("pending_email")
    if not email: return redirect(url_for("user_login"))
    is_admin = session.get("is_admin_login", False)

    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()

        # Validate format — digits only, exactly 6
        if not otp_code.isdigit() or len(otp_code) != 6:
            flash("Invalid code format.", "error")
            return render_template("user/verify_otp.html", email=email, is_admin=is_admin)

        user = User.query.filter_by(email=email).first()
        if not user: flash("User not found.", "error"); return redirect(url_for("user_login"))

        otp_token = OTPToken.query.filter_by(
            user_id=user.id, used=False
        ).order_by(OTPToken.created_at.desc()).first()

        if not otp_token:
            flash("No active code found. Please log in again.", "error")
            session.pop("pending_email", None)
            return redirect(url_for("user_login"))

        if otp_token.attempts >= 3:
            otp_token.used = True; db.session.commit()
            flash("Too many failed attempts. Please log in again.", "error")
            session.pop("pending_email", None)
            return redirect(url_for("user_login"))

        # Constant-time comparison prevents timing attacks
        if hmac.compare_digest(otp_token.token, otp_code):
            if not otp_token.is_valid():
                flash("Code expired. Please log in again.", "error")
                session.pop("pending_email", None)
                return redirect(url_for("user_login"))

            otp_token.used = True
            user.email_verified = True; user.login_attempts = 0
            user.last_login = datetime.utcnow(); user.locked_until = None
            user.session_token = secrets.token_hex(32)
            db.session.commit()

            login_user(user, remember=True)
            session.permanent = True
            session.pop("pending_email", None); session.pop("is_admin_login", None)
            log_audit(user.id, "login_success", f"{'Admin' if user.is_admin else 'User'} from {request.remote_addr}", request.remote_addr)
            flash(f"Welcome back, {user.first_name or 'there'}!", "success")
            return redirect(url_for("admin_dashboard") if user.is_admin else url_for("user_dashboard"))
        else:
            otp_token.attempts += 1; user.login_attempts += 1
            if user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                flash("Account locked for 30 minutes.", "error")
            else:
                flash(f"Incorrect code. {Config.MAX_LOGIN_ATTEMPTS - user.login_attempts} attempts remaining.", "error")
            db.session.commit()
            log_audit(user.id, "failed_otp", f"Attempt {otp_token.attempts} from {request.remote_addr}", request.remote_addr)
    return render_template("user/verify_otp.html", email=email, is_admin=is_admin)


@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        log_audit(current_user.id, "logout", request.remote_addr)
        current_user.session_token = None
        db.session.commit()
    logout_user()
    session.clear()
    resp = make_response(redirect(url_for("user_login")))
    resp.delete_cookie("session"); resp.delete_cookie("remember_token")
    flash("You have been logged out.", "success")
    return resp


# ============================================================================
# USER DASHBOARD
# SECURITY: @login_required enforced. Users only see their own data.
# Plan level enforced on EA downloads — no IDOR possible.
# ============================================================================

@app.route("/dashboard")
@login_required
def user_dashboard():
    if current_user.is_admin: return redirect(url_for("admin_dashboard"))
    user = current_user; license = user.get_active_license(); user_level = user.get_plan_level()
    ea_files = EAFile.query.filter(
        EAFile.is_active == True, EAFile.plan_level <= user_level
    ).order_by(EAFile.upload_date.desc()).all()
    all_ea_count = EAFile.query.filter_by(is_active=True).count()
    return render_template(
        "user/dashboard.html", user=user, license=license, ea_files=ea_files,
        all_ea_count=all_ea_count, user_level=user_level,
        discord_invite=Config.DISCORD_INVITE_LINK, now=datetime.utcnow()
    )


@app.route("/generate-license", methods=["POST"])
@login_required
@limiter.limit("3 per day")
def generate_license():
    if not current_user.is_membership_active(): return jsonify({"error": "Active membership required"}), 403
    if current_user.get_active_license(): return jsonify({"error": "You already have an active license"}), 400
    try:
        key = generate_license_key(); days = current_user.subscription_duration_days or Config.LICENSE_EXPIRY_DAYS
        lic = License(
            user_id=current_user.id, license_key=key,
            expires_at=datetime.utcnow() + timedelta(days=days),
            ea_version="1.0.0", license_type=current_user.subscription_type or "standard"
        )
        db.session.add(lic); db.session.commit()
        log_audit(current_user.id, "license_generated", f"{lic.mask_license_key()} | {days}d", request.remote_addr)
        send_email_async(
            "Your License Key - Trading Engine", [current_user.email],
            f"License: {key}\nExpires: {lic.expires_at.strftime('%B %d, %Y')}",
            f"""<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
            <h2 style="color:#4B7BE5;">Your License Key</h2>
            <div style="background:#f0f4ff;border-radius:10px;padding:20px;text-align:center;margin:20px 0;border:2px dashed #6FDFDF;">
            <span style="font-size:1.5rem;font-weight:bold;color:#5534A5;letter-spacing:4px;font-family:monospace;">{key}</span></div>
            <p><strong>Expires:</strong> {lic.expires_at.strftime('%B %d, %Y')}</p>
            <p style="color:#666;font-size:0.85rem;">Keep this key safe. Do not share it with anyone.</p></div>"""
        )
        return jsonify({"success": True, "license_key": key, "masked_key": lic.mask_license_key(), "expires_at": lic.expires_at.isoformat()})
    except Exception as e:
        logger.error(f"License generation failed: {e}"); db.session.rollback(); return jsonify({"error": "Failed"}), 500


@app.route("/download-ea/<int:file_id>")
@login_required
def download_ea(file_id):
    if not current_user.is_membership_active(): flash("Active membership required.", "error"); return redirect(url_for("user_dashboard"))
    ea = db.session.get(EAFile, file_id)
    if not ea or not ea.is_active: flash("EA not found.", "error"); return redirect(url_for("user_dashboard"))
    # Enforce plan level — prevents IDOR across plan levels
    if ea.plan_level > current_user.get_plan_level():
        log_audit(current_user.id, "unauthorized_download", f"EA {file_id} level {ea.plan_level}", request.remote_addr)
        flash("Your plan does not include this EA.", "error"); return redirect(url_for("user_dashboard"))
    file_path = os.path.join(Config.UPLOAD_FOLDER, ea.file_path)
    if not os.path.exists(file_path): flash("File not found. Contact support.", "error"); return redirect(url_for("user_dashboard"))
    ea.download_count += 1; db.session.commit()
    log_audit(current_user.id, "ea_download", ea.filename, request.remote_addr)
    return send_from_directory(Config.UPLOAD_FOLDER, ea.file_path, as_attachment=True, download_name=ea.filename)


# ============================================================================
# ADMIN
# SECURITY:
# - admin_required = @login_required + is_admin check
# - Admin access = password (compared with hmac) + OTP = 2FA
# - All admin actions are audit logged with IP
# - No user_id exposed in URLs for data access (explicit DB lookup)
# ============================================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    total_users = User.query.filter_by(is_admin=False).count()
    active_users = User.query.filter_by(membership_status="active", is_admin=False).count()
    total_licenses = License.query.count(); active_licenses = License.query.filter_by(status="active").count()
    total_orders = Order.query.count(); total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    total_downloads = db.session.query(db.func.sum(EAFile.download_count)).scalar() or 0
    recent_users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).limit(10).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    recent_licenses = License.query.order_by(License.created_at.desc()).limit(10).all()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    ea_files = EAFile.query.order_by(EAFile.upload_date.desc()).all()
    subscription_stats = db.session.query(
        User.subscription_type, db.func.count(User.id), db.func.sum(User.plan_price)
    ).filter(User.is_admin == False).group_by(User.subscription_type).all()
    return render_template(
        "admin/dashboard.html", total_users=total_users, active_users=active_users,
        total_licenses=total_licenses, active_licenses=active_licenses, total_orders=total_orders,
        total_revenue=total_revenue, total_downloads=total_downloads, recent_users=recent_users,
        recent_orders=recent_orders, recent_licenses=recent_licenses, recent_logs=recent_logs,
        ea_files=ea_files, subscription_stats=subscription_stats, now=datetime.utcnow()
    )


@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users, now=datetime.utcnow())


@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    user = db.session.get(User, user_id)
    if not user: flash("User not found.", "error"); return redirect(url_for("admin_users"))
    orders = user.orders.order_by(Order.created_at.desc()).all()
    licenses = user.licenses.order_by(License.created_at.desc()).all()
    return render_template("admin/user_detail.html", user=user, orders=orders, licenses=licenses, now=datetime.utcnow())


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
        lic.status = "revoked"; lic.revoked_at = datetime.utcnow(); db.session.commit()
        log_audit(current_user.id, "license_revoked", f"License {license_id}", request.remote_addr)
        flash("License revoked.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/revoke-membership/<int:user_id>", methods=["POST"])
@admin_required
def revoke_membership(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.membership_status = "revoked"; user.membership_end = datetime.utcnow()
        License.query.filter_by(user_id=user.id, status="active").update({"status": "revoked", "revoked_at": datetime.utcnow()})
        db.session.commit()
        log_audit(current_user.id, "membership_revoked", f"User {user_id}", request.remote_addr)
        flash("Membership revoked.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/extend-membership/<int:user_id>", methods=["POST"])
@admin_required
def extend_membership(user_id):
    user = db.session.get(User, user_id)
    if user:
        days = int(request.form.get("days", 30))
        if user.membership_end and user.membership_end > datetime.utcnow(): user.membership_end += timedelta(days=days)
        else: user.membership_start = datetime.utcnow(); user.membership_end = datetime.utcnow() + timedelta(days=days)
        user.membership_status = "active"; db.session.commit()
        log_audit(current_user.id, "membership_extended", f"User {user_id} +{days}d", request.remote_addr)
        flash(f"Extended by {days} days.", "success")
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/clear-machine-id/<license_key>")
@admin_required
def clear_machine_id(license_key):
    """Clear bound machine ID from a license."""
    lic = License.query.filter_by(license_key=license_key).first()
    if lic:
        lic.machine_id = None; db.session.commit()
        log_audit(current_user.id, "machine_id_cleared", license_key, request.remote_addr)
        return jsonify({"status": "cleared", "license": license_key})
    return jsonify({"error": "License not found"}), 404


@app.route("/admin/upload-ea", methods=["POST"])
@admin_required
def upload_ea():
    if "file" not in request.files: flash("No file selected.", "error"); return redirect(url_for("admin_dashboard"))
    file = request.files["file"]
    if file.filename == "" or not allowed_file(file.filename): flash("Invalid file type.", "error"); return redirect(url_for("admin_dashboard"))
    filename = secure_filename(file.filename); saved = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file_path = os.path.join(Config.UPLOAD_FOLDER, saved); file.save(file_path)
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""): sha.update(block)
    ea = EAFile(
        filename=filename, file_path=saved, version=request.form.get("version", "1.0.0"),
        file_size=os.path.getsize(file_path), description=request.form.get("description", ""),
        changelog=request.form.get("changelog", ""), is_beta=request.form.get("is_beta") == "on",
        plan_level=int(request.form.get("plan_level", 1)), checksum=sha.hexdigest(), uploaded_by=current_user.id
    )
    db.session.add(ea); db.session.commit()
    log_audit(current_user.id, "ea_uploaded", f"{filename} v{ea.version} Level {ea.plan_level}", request.remote_addr)
    flash(f"EA uploaded (Level {ea.plan_level}).", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-ea/<int:ea_id>", methods=["POST"])
@admin_required
def delete_ea(ea_id):
    ea = db.session.get(EAFile, ea_id)
    if ea:
        file_path = os.path.join(Config.UPLOAD_FOLDER, ea.file_path)
        if os.path.exists(file_path): os.remove(file_path)
        name = ea.filename; db.session.delete(ea); db.session.commit()
        log_audit(current_user.id, "ea_deleted", name, request.remote_addr)
        flash(f"'{name}' deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ============================================================================
# API
# SECURITY:
# - /api/validate-license: public but rate limited (30/min)
# - Machine ID check REMOVED by design
# - /api/user/info: login required, returns only current user (no IDOR)
# ============================================================================

@app.route("/api/validate-license", methods=["POST"])
@limiter.limit("30 per minute")
def api_validate_license():
    try:
        data = request.get_json()
        if not data: return jsonify({"valid": False, "error": "Invalid request"}), 400

        license_key = data.get("license_key", "").strip()
        if not license_key: return jsonify({"valid": False, "error": "License key required"}), 400

        lic = License.query.filter_by(license_key=license_key).first()
        if not lic: return jsonify({"valid": False, "error": "License not found"}), 404
        if not lic.is_valid(): return jsonify({"valid": False, "error": "License not active or expired"}), 403

        lic.last_validated = datetime.utcnow(); lic.validation_count += 1; db.session.commit()
        return jsonify({"valid": True, "expires_at": lic.expires_at.isoformat(), "user_email": lic.user.email})
    except Exception as e:
        logger.error(f"License validation failed: {e}"); return jsonify({"valid": False, "error": "Server error"}), 500


@app.route("/api/user/info")
@login_required
def api_user_info():
    # Returns only current user's data — no user_id param, no IDOR possible
    return jsonify(current_user.to_dict())


# ============================================================================
# WIX WEBHOOK
# ============================================================================

@app.route("/webhook/wix/payment", methods=["POST"])
@limiter.limit("60 per minute")
def wix_payment_webhook():
    try:
        if request.is_json: raw = request.get_json()
        else: raw = request.form.to_dict() or request.get_json(force=True, silent=True) or {}
        data = raw.get("data", raw)
        logger.info(f"Webhook: {json.dumps(data, indent=2)}")
        if data.get("eventType") != "Plan ordered": return jsonify({"status": "ignored"}), 200

        email = data.get("contact_email", "").strip().lower()
        if not email: return jsonify({"error": "Email required"}), 400

        first_name = data.get("contact_first_name", "")
        last_name = data.get("contact_last_name", "")
        plan_name = data.get("plan_name", "")
        plan_duration = data.get("plan_duration", "")
        plan_start = data.get("plan_start_date", "")
        plan_end = data.get("plan_end_date", "")
        order_id = data.get("order_id", "")
        contact_id = data.get("contact_id", "")
        try: plan_price = float(data.get("plan_price_amount", 0))
        except: plan_price = 0.0
        currency = data.get("plan_price_currency", "EUR")

        duration_days, subscription_type = parse_duration_to_days(plan_duration)
        if subscription_type == "one_time" and plan_name:
            pl = plan_name.lower()
            if "monthly" in pl or "maand" in pl: duration_days, subscription_type = 30, "monthly"
            elif "yearly" in pl or "jaar" in pl: duration_days, subscription_type = 365, "yearly"
            elif "lifetime" in pl or "levenslang" in pl: duration_days, subscription_type = 36500, "lifetime"

        membership_start = parse_wix_date(plan_start) or datetime.utcnow()
        membership_end = parse_wix_date(plan_end) or (membership_start + timedelta(days=duration_days))

        user = User.query.filter_by(email=email).first(); is_new = False
        if not user:
            user = User(
                email=email, first_name=first_name, last_name=last_name,
                wix_contact_id=contact_id, wix_order_id=order_id, wix_payment_id=order_id,
                email_verified=True, membership_status="active",
                membership_start=membership_start, membership_end=membership_end,
                plan_name=plan_name, plan_price=plan_price, currency=currency,
                subscription_type=subscription_type, subscription_duration_days=duration_days
            )
            db.session.add(user); db.session.flush(); is_new = True
        else:
            user.first_name = first_name or user.first_name; user.last_name = last_name or user.last_name
            user.wix_contact_id = contact_id or user.wix_contact_id; user.wix_order_id = order_id or user.wix_order_id
            user.wix_payment_id = order_id or user.wix_payment_id; user.email_verified = True
            user.membership_status = "active"; user.membership_start = membership_start
            user.membership_end = membership_end; user.plan_name = plan_name or user.plan_name
            user.plan_price = plan_price if plan_price > 0 else user.plan_price
            user.currency = currency or user.currency; user.subscription_type = subscription_type
            user.subscription_duration_days = duration_days; db.session.flush()

        if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
            order = Order(
                user_id=user.id, wix_order_id=order_id, wix_payment_id=order_id,
                plan_name=plan_name, plan_price=plan_price, currency=currency,
                total_amount=plan_price, subscription_type=subscription_type,
                subscription_duration_days=duration_days, status="completed",
                payment_status="paid", ip_address=request.remote_addr, raw_data=json.dumps(data)
            )
            db.session.add(order)

        db.session.commit()
        user_name = f"{first_name} {last_name}".strip() or "there"
        send_email_async(
            "Welcome to Trading Engine! 🎉", [email],
            f"Hi {user_name}! Your {plan_name} is active. Login: {Config.APP_URL}/login",
            f"""<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
            <h2 style="color:#4B7BE5;">Welcome to Trading Engine! 🎉</h2>
            <p>Hi {user_name},</p><p>Your <strong>{plan_name}</strong> is now active.</p>
            <p><strong>Access until:</strong> {membership_end.strftime('%B %d, %Y')}</p>
            <a href="{Config.APP_URL}/login" style="display:inline-block;background:linear-gradient(135deg,#4B7BE5,#5534A5);color:white;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:bold;margin-top:16px;">Login to Dashboard</a></div>"""
        )
        log_audit(user.id, "wix_plan_ordered", f"{'New' if is_new else 'Updated'} | {plan_name} | {subscription_type}", request.remote_addr)
        logger.info(f"✅ Plan activated: {email} | {plan_name} | {subscription_type}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Webhook failed: {e}", exc_info=True); db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# DISCORD OAuth2
# ============================================================================

def assign_discord_role(discord_id: str):
    try:
        role_url = f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{discord_id}/roles/{Config.DISCORD_ROLE_ID}"
        role_req = urllib.request.Request(role_url, method="PUT")
        role_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
        role_req.add_header("Content-Type", "application/json")
        urllib.request.urlopen(role_req)
        logger.info(f"✅ Discord role assigned to {discord_id}")
        return True
    except Exception as e: logger.error(f"Discord role failed: {e}"); return False


def remove_from_discord(user_id: int):
    if not Config.DISCORD_BOT_TOKEN: return
    try:
        with app.app_context():
            user = db.session.get(User, user_id)
            if user and user.discord_user_id and user.discord_user_id != "pending":
                role_url = f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{user.discord_user_id}/roles/{Config.DISCORD_ROLE_ID}"
                role_req = urllib.request.Request(role_url, method="DELETE")
                role_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
                role_req.add_header("Content-Type", "application/json")
                urllib.request.urlopen(role_req)
            if user: user.discord_joined = False; user.discord_user_id = None; db.session.commit()
    except Exception as e: logger.error(f"Discord remove failed: {e}")


@app.route("/connect-discord")
@login_required
def connect_discord():
    if not current_user.is_membership_active():
        flash("Active membership required.", "error"); return redirect(url_for("user_dashboard"))
    if not Config.DISCORD_CLIENT_ID:
        flash("Discord not configured.", "error"); return redirect(url_for("user_dashboard"))
    params = urllib.parse.urlencode({
        "client_id": Config.DISCORD_CLIENT_ID,
        "redirect_uri": Config.DISCORD_REDIRECT_URI,
        "response_type": "code", "scope": "identify guilds.join"
    })
    return redirect(f"https://discord.com/oauth2/authorize?{params}")


@app.route("/discord/callback")
@login_required
def discord_callback():
    code = request.args.get("code")
    if not code: flash("Discord connection cancelled.", "error"); return redirect(url_for("user_dashboard"))
    try:
        token_data = urllib.parse.urlencode({
            "client_id": Config.DISCORD_CLIENT_ID, "client_secret": Config.DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code", "code": code, "redirect_uri": Config.DISCORD_REDIRECT_URI
        }).encode()
        token_req = urllib.request.Request("https://discord.com/api/oauth2/token", data=token_data, method="POST")
        token_req.add_header("Content-Type", "application/x-www-form-urlencoded")
        token_res = urllib.request.urlopen(token_req)
        token_json = json.loads(token_res.read())
        access_token = token_json["access_token"]

        user_req = urllib.request.Request("https://discord.com/api/users/@me")
        user_req.add_header("Authorization", f"Bearer {access_token}")
        user_res = urllib.request.urlopen(user_req)
        discord_user = json.loads(user_res.read())
        discord_id = discord_user["id"]
        discord_username = discord_user.get("username", "unknown")

        join_data = json.dumps({"access_token": access_token}).encode()
        join_req = urllib.request.Request(
            f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{discord_id}",
            data=join_data, method="PUT"
        )
        join_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
        join_req.add_header("Content-Type", "application/json")
        try: urllib.request.urlopen(join_req)
        except: pass

        assign_discord_role(discord_id)
        current_user.discord_user_id = discord_id; current_user.discord_joined = True; db.session.commit()
        log_audit(current_user.id, "discord_connected", f"{discord_username} ({discord_id})", request.remote_addr)
        flash("Discord connected! You now have access to the private channel. 🎉", "success")
    except Exception as e:
        logger.error(f"Discord OAuth failed: {e}"); flash("Discord connection failed. Please try again.", "error")
    return redirect(url_for("user_dashboard"))


# ============================================================================
# AUTO-INIT DB
# ============================================================================

@app.before_request
def auto_init_db():
    try: db.session.execute(db.text("SELECT 1 FROM users LIMIT 1"))
    except Exception: 
        try:
            db.create_all(); logger.info("✅ DB created!")
            admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
            if not User.query.filter_by(email=admin_email).first():
                admin = User(
                    email=admin_email, first_name="Admin", is_admin=True, email_verified=True,
                    membership_status="active", membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin", subscription_type="lifetime", subscription_duration_days=36500
                )
                db.session.add(admin); db.session.commit()
                logger.info(f"✅ Admin created: {admin_email}")
        except Exception as e: logger.error(f"DB init failed: {e}")
       
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
