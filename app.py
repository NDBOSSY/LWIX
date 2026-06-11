"""
Subscription & Licensing Platform
Complete Flask Application with Wix Integration, Stripe Integration, OTP Auth, License Management & Discord Integration
"""

import os
import re
import json
import hashlib
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

    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

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
login_manager.login_message = "Please log in to access this page."
CORS(app, supports_credentials=True)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri=Config.RATELIMIT_STORAGE_URL)

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

logging.basicConfig(level=logging.INFO if not Config.DEBUG else logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


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
        return {"id": self.id, "email": self.email, "first_name": self.first_name,
                "last_name": self.last_name, "full_name": self.get_full_name(),
                "plan_level": self.get_plan_level(), "membership_status": self.membership_status,
                "plan_name": self.plan_name, "subscription_type": self.subscription_type,
                "is_active": self.is_membership_active()}


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
    max_accounts = db.Column(db.Integer, default=4)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_validated = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    validation_count = db.Column(db.Integer, default=0)
    max_validations = db.Column(db.Integer, default=10000)
    ea_version = db.Column(db.String(20), nullable=True)

    accounts = db.relationship("LicenseAccount", backref="license", lazy="dynamic", cascade="all, delete-orphan")

    def is_valid(self):
        if self.status != "active": return False
        if self.expires_at < datetime.utcnow(): self.status = "expired"; db.session.commit(); return False
        if self.validation_count >= self.max_validations: return False
        return True

    def mask_license_key(self):
        if len(self.license_key) > 8: return f"{self.license_key[:4]}...{self.license_key[-4:]}"
        return self.license_key


class LicenseAccount(db.Model):
    __tablename__ = "license_accounts"
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    activated_at = db.Column(db.DateTime, default=datetime.utcnow)


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
# HELPERS
# ============================================================================

def encrypt_data(data):
    try: return cipher_suite.encrypt(data.encode()).decode()
    except: return data

def decrypt_data(data):
    try: return cipher_suite.decrypt(data.encode()).decode()
    except: return data

def generate_license_key(): return "-".join([secrets.token_hex(2).upper() for _ in range(3)])

def generate_otp(): return "".join([str(secrets.randbelow(10)) for _ in range(6)])

def parse_duration_to_days(duration_str):
    if not duration_str: return Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS, "one_time"
    d = duration_str.lower().strip()
    if "month" in d or "maand" in d:
        m = re.findall(r'\d+', d); return (int(m[0]) * 30 if m else 30), "monthly"
    elif "year" in d or "jaar" in d:
        y = re.findall(r'\d+', d); return (int(y[0]) * 365 if y else 365), "yearly"
    elif "lifetime" in d or "levenslang" in d or "annulering" in d: return 36500, "lifetime"
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
        except Exception as e: logger.error(f"Email failed: {e}")
    threading.Thread(target=send).start()

def log_audit(user_id, action, details=None, ip_address=None):
    try:
        log = AuditLog(user_id=user_id, action=action, details=details,
                       ip_address=ip_address or (request.remote_addr if request else "system"))
        db.session.add(log); db.session.commit()
    except Exception as e: logger.error(f"Audit log failed: {e}")

def allowed_file(filename): return "." in filename and filename.rsplit(".", 1)[1].lower() in {"ex4", "ex5", "dll", "zip"}


# ============================================================================
# DECORATORS
# ============================================================================

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin: flash("Admin access required.", "error"); abort(403)
        return f(*args, **kwargs)
    return decorated

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

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
        if email == admin_email: session["admin_email"] = email; return redirect(url_for("admin_password"))
        user = User.query.filter_by(email=email).first()
        if not user: flash("No account found. Purchase a plan first.", "error"); return render_template("user/login.html")
        if not user.email_verified: flash("Account not active. Complete purchase first.", "error"); return render_template("user/login.html")
        if user.locked_until and user.locked_until > datetime.utcnow(): flash("Account locked. Try later.", "error"); return render_template("user/login.html")
        try:
            OTPToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(user_id=user.id, token=otp, expires_at=datetime.utcnow() + timedelta(minutes=Config.OTP_EXPIRY_MINUTES), purpose="login")
            db.session.add(otp_token); db.session.commit()
            send_email_async("Your OTP - Trading Engine", [email], f"OTP: {otp}", f"<h3>OTP: {otp}</h3><p>Expires in {Config.OTP_EXPIRY_MINUTES} min.</p>")
            session["pending_email"] = email; flash("OTP sent.", "success")
            return redirect(url_for("verify_otp"))
        except Exception as e: logger.error(f"OTP failed: {e}"); flash("Failed to send OTP.", "error")
    return render_template("user/login.html")


@app.route("/admin-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_password():
    admin_email = session.get("admin_email") or os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
    admin_user = User.query.filter_by(email=admin_email).first()
    if admin_user and admin_user.locked_until and admin_user.locked_until > datetime.utcnow():
        session.pop("admin_email", None); flash("Admin locked.", "error"); return redirect(url_for("user_login"))
    if request.method == "POST":
        if request.form.get("password") == os.getenv("ADMIN_PASSWORD", "admin123").strip():
            if not admin_user:
                admin_user = User(email=admin_email, first_name="Admin", is_admin=True, email_verified=True,
                                  membership_status="active", membership_start=datetime.utcnow(),
                                  membership_end=datetime.utcnow() + timedelta(days=3650),
                                  plan_name="Admin", subscription_type="lifetime", subscription_duration_days=36500)
                db.session.add(admin_user)
            else: admin_user.login_attempts = 0; admin_user.locked_until = None; admin_user.is_admin = True
            db.session.commit()
            OTPToken.query.filter_by(user_id=admin_user.id, used=False).update({"used": True})
            otp = generate_otp()
            otp_token = OTPToken(user_id=admin_user.id, token=otp, expires_at=datetime.utcnow() + timedelta(minutes=Config.ADMIN_OTP_EXPIRY_MINUTES), purpose="admin")
            db.session.add(otp_token); db.session.commit()
            send_email_async("Admin OTP", [admin_email], f"OTP: {otp}")
            session["pending_email"] = admin_email; session["is_admin_login"] = True; session.pop("admin_email", None)
            flash("OTP sent.", "success"); return redirect(url_for("verify_otp"))
        else:
            if admin_user:
                admin_user.login_attempts += 1
                if admin_user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS: admin_user.locked_until = datetime.utcnow() + timedelta(minutes=30); flash("Locked 30 min.", "error")
                else: flash(f"Wrong password. {Config.MAX_LOGIN_ATTEMPTS - admin_user.login_attempts} left.", "error")
                db.session.commit()
            else: flash("Invalid password.", "error")
    return render_template("admin/password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp():
    email = session.get("pending_email")
    if not email: return redirect(url_for("user_login"))
    is_admin = session.get("is_admin_login", False)
    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()
        if len(otp_code) != 6: flash("Invalid OTP.", "error"); return render_template("user/verify_otp.html", email=email, is_admin=is_admin)
        user = User.query.filter_by(email=email).first()
        if not user: flash("User not found.", "error"); return redirect(url_for("user_login"))
        otp_token = OTPToken.query.filter_by(user_id=user.id, used=False).order_by(OTPToken.created_at.desc()).first()
        if not otp_token: flash("No OTP. Request new.", "error"); return render_template("user/verify_otp.html", email=email, is_admin=is_admin)
        if otp_token.attempts >= 3: otp_token.used = True; db.session.commit(); flash("Too many attempts.", "error"); return render_template("user/verify_otp.html", email=email, is_admin=is_admin)
        if otp_token.token == otp_code:
            if not otp_token.is_valid(): flash("OTP expired.", "error"); return render_template("user/verify_otp.html", email=email, is_admin=is_admin)
            otp_token.used = True; user.email_verified = True; user.login_attempts = 0; user.last_login = datetime.utcnow(); user.locked_until = None
            db.session.commit()
            login_user(user, remember=True)
            session.pop("pending_email", None); session.pop("is_admin_login", None)
            log_audit(user.id, "login", f"{'Admin' if user.is_admin else 'User'} login", request.remote_addr)
            flash(f"Welcome back, {user.first_name or 'there'}!", "success")
            return redirect(url_for("admin_dashboard") if user.is_admin else url_for("user_dashboard"))
        else:
            otp_token.attempts += 1; user.login_attempts += 1
            if user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS: user.locked_until = datetime.utcnow() + timedelta(minutes=30); flash("Locked 30 min.", "error")
            else: flash("Invalid OTP.", "error")
            db.session.commit()
    return render_template("user/verify_otp.html", email=email, is_admin=is_admin)


@app.route("/logout")
def logout():
    if current_user.is_authenticated: log_audit(current_user.id, "logout", request.remote_addr)
    logout_user(); session.clear()
    resp = make_response(redirect(url_for("user_login")))
    resp.delete_cookie("session"); resp.delete_cookie("remember_token")
    flash("Logged out.", "success")
    return resp


# ============================================================================
# USER DASHBOARD
# ============================================================================

@app.route("/dashboard")
@login_required
def user_dashboard():
    if current_user.is_admin: return redirect(url_for("admin_dashboard"))
    user = current_user; license = user.get_active_license(); user_level = user.get_plan_level()
    ea_files = EAFile.query.filter(EAFile.is_active == True, EAFile.plan_level <= user_level).order_by(EAFile.upload_date.desc()).all()
    all_ea_count = EAFile.query.filter_by(is_active=True).count()
    default_max = 2 if user_level == 1 else 4
    license_accounts = []; account_count = 0; max_accounts = default_max
    if license:
        license_accounts = [{"account": a.account_number, "activated": a.activated_at} for a in license.accounts]
        account_count = len(license_accounts); max_accounts = license.max_accounts
    return render_template("user/dashboard.html", user=user, license=license, ea_files=ea_files,
                           all_ea_count=all_ea_count, user_level=user_level,
                           discord_invite=Config.DISCORD_INVITE_LINK, now=datetime.utcnow(),
                           license_accounts=license_accounts, account_count=account_count, max_accounts=max_accounts)


@app.route("/generate-license", methods=["POST"])
@login_required
@limiter.limit("3 per day")
def generate_license():
    if not current_user.is_membership_active(): return jsonify({"error": "Active membership required"}), 403
    if current_user.get_active_license(): return jsonify({"error": "Already have active license"}), 400
    try:
        test_mode = Setting.query.filter_by(key="test_mode").first()
        is_test = test_mode and test_mode.value == "on"
        key = generate_license_key()
        days = 1 if is_test else (current_user.subscription_duration_days or Config.LICENSE_EXPIRY_DAYS)
        license_type = "test" if is_test else (current_user.subscription_type or "standard")
        user_level = current_user.get_plan_level()
        max_accounts = 2 if user_level == 1 else 4
        lic = License(user_id=current_user.id, license_key=key, expires_at=datetime.utcnow() + timedelta(days=days),
                      ea_version="1.0.0", license_type=license_type, max_accounts=max_accounts)
        db.session.add(lic); db.session.commit()
        log_audit(current_user.id, "license_generated", f"{lic.mask_license_key()} | {days}d | max_acc={max_accounts} | test={is_test}", request.remote_addr)
        send_email_async("License Key", [current_user.email], f"License: {key}\nExpires: {lic.expires_at.strftime('%B %d, %Y')}")
        return jsonify({"success": True, "license_key": key, "masked_key": lic.mask_license_key(), "expires_at": lic.expires_at.isoformat()})
    except Exception as e: logger.error(f"License failed: {e}"); db.session.rollback(); return jsonify({"error": "Failed"}), 500


@app.route("/download-ea/<int:file_id>")
@login_required
def download_ea(file_id):
    if not current_user.is_membership_active(): flash("Active membership required.", "error"); return redirect(url_for("user_dashboard"))
    ea = db.session.get(EAFile, file_id)
    if not ea or not ea.is_active: flash("EA not found.", "error"); return redirect(url_for("user_dashboard"))
    if ea.plan_level > current_user.get_plan_level(): flash("Requires higher plan level.", "error"); return redirect(url_for("user_dashboard"))
    file_path = os.path.join(Config.UPLOAD_FOLDER, ea.file_path)
    if not os.path.exists(file_path): flash("File missing. Contact support.", "error"); return redirect(url_for("user_dashboard"))
    ea.download_count += 1; db.session.commit()
    log_audit(current_user.id, "ea_download", ea.filename, request.remote_addr)
    return send_from_directory(Config.UPLOAD_FOLDER, ea.file_path, as_attachment=True, download_name=ea.filename)


# ============================================================================
# ADMIN
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
    subscription_stats = db.session.query(User.subscription_type, db.func.count(User.id), db.func.sum(User.plan_price)).filter(User.is_admin == False).group_by(User.subscription_type).all()
    test_mode = Setting.query.filter_by(key="test_mode").first()
    is_test_mode = test_mode.value == "on" if test_mode else False
    return render_template("admin/dashboard.html", total_users=total_users, active_users=active_users,
                           total_licenses=total_licenses, active_licenses=active_licenses, total_orders=total_orders,
                           total_revenue=total_revenue, total_downloads=total_downloads, recent_users=recent_users,
                           recent_orders=recent_orders, recent_licenses=recent_licenses, recent_logs=recent_logs,
                           ea_files=ea_files, subscription_stats=subscription_stats, now=datetime.utcnow(),
                           is_test_mode=is_test_mode)


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
    if lic: lic.status = "revoked"; lic.revoked_at = datetime.utcnow(); db.session.commit(); flash("License revoked.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/revoke-membership/<int:user_id>", methods=["POST"])
@admin_required
def revoke_membership(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.membership_status = "revoked"; user.membership_end = datetime.utcnow()
        License.query.filter_by(user_id=user.id, status="active").update({"status": "revoked", "revoked_at": datetime.utcnow()})
        db.session.commit(); flash("Membership revoked.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/extend-membership/<int:user_id>", methods=["POST"])
@admin_required
def extend_membership(user_id):
    user = db.session.get(User, user_id)
    if user:
        days = int(request.form.get("days", 30))
        if user.membership_end and user.membership_end > datetime.utcnow(): user.membership_end += timedelta(days=days)
        else: user.membership_start = datetime.utcnow(); user.membership_end = datetime.utcnow() + timedelta(days=days)
        user.membership_status = "active"; db.session.commit(); flash(f"Extended by {days} days.", "success")
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/upload-ea", methods=["POST"])
@admin_required
def upload_ea():
    if "file" not in request.files: flash("No file.", "error"); return redirect(url_for("admin_dashboard"))
    file = request.files["file"]
    if file.filename == "" or not allowed_file(file.filename): flash("Invalid file type.", "error"); return redirect(url_for("admin_dashboard"))
    filename = secure_filename(file.filename); saved = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file_path = os.path.join(Config.UPLOAD_FOLDER, saved); file.save(file_path)
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""): sha.update(block)
    ea = EAFile(filename=filename, file_path=saved, version=request.form.get("version", "1.0.0"),
                file_size=os.path.getsize(file_path), description=request.form.get("description", ""),
                changelog=request.form.get("changelog", ""), is_beta=request.form.get("is_beta") == "on",
                plan_level=int(request.form.get("plan_level", 1)), checksum=sha.hexdigest(), uploaded_by=current_user.id)
    db.session.add(ea); db.session.commit()
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
        flash(f"'{name}' deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reset-account/<int:account_id>", methods=["POST"])
@admin_required
def reset_license_account(account_id):
    account = db.session.get(LicenseAccount, account_id)
    if account: db.session.delete(account); db.session.commit(); flash("Account slot freed.", "success")
    return redirect(request.referrer or url_for("admin_dashboard"))


# ============================================================================
# API
# ============================================================================

@app.route("/api/validate-license", methods=["POST"])
@limiter.limit("30 per minute")
def api_validate_license():
    try:
        data = request.get_json()
        if not data: return jsonify({"valid": False, "error": "Invalid request"}), 400
        license_key = data.get("license_key", "").strip()
        machine_id = data.get("machine_id", "").strip()
        if not license_key: return jsonify({"valid": False, "error": "License key required"}), 400
        lic = License.query.filter_by(license_key=license_key).first()
        if not lic: return jsonify({"valid": False, "error": "License not found"}), 404
        if not lic.is_valid(): return jsonify({"valid": False, "error": "License not active or expired"}), 403
        account_id = machine_id
        existing = LicenseAccount.query.filter_by(license_id=lic.id, account_number=account_id).first()
        if existing:
            lic.last_validated = datetime.utcnow(); lic.validation_count += 1; db.session.commit()
            return jsonify({"valid": True, "expires_at": lic.expires_at.isoformat(), "user_email": lic.user.email,
                           "accounts_used": lic.accounts.count(), "accounts_max": lic.max_accounts,
                           "accounts_remaining": lic.max_accounts - lic.accounts.count()})
        active_count = lic.accounts.count()
        if active_count >= lic.max_accounts:
            return jsonify({"valid": False, "error": f"Maximum {lic.max_accounts} accounts reached.",
                           "accounts_used": active_count, "accounts_max": lic.max_accounts}), 403
        new_account = LicenseAccount(license_id=lic.id, account_number=account_id)
        db.session.add(new_account)
        lic.last_validated = datetime.utcnow(); lic.validation_count += 1; db.session.commit()
        return jsonify({"valid": True, "expires_at": lic.expires_at.isoformat(), "user_email": lic.user.email,
                       "accounts_used": lic.accounts.count(), "accounts_max": lic.max_accounts,
                       "accounts_remaining": lic.max_accounts - lic.accounts.count()})
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return jsonify({"valid": False, "error": "Server error"}), 500


@app.route("/api/user/info")
@login_required
def api_user_info(): return jsonify(current_user.to_dict())


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
        if data.get("eventType") != "Plan ordered": return jsonify({"status": "ignored"}), 200
        email = data.get("contact_email", "").strip().lower()
        if not email: return jsonify({"error": "Email required"}), 400
        first_name = data.get("contact_first_name", ""); last_name = data.get("contact_last_name", "")
        plan_name = data.get("plan_name", ""); plan_duration = data.get("plan_duration", "")
        plan_start = data.get("plan_start_date", ""); plan_end = data.get("plan_end_date", "")
        order_id = data.get("order_id", ""); contact_id = data.get("contact_id", "")
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
            user = User(email=email, first_name=first_name, last_name=last_name, wix_contact_id=contact_id,
                        wix_order_id=order_id, wix_payment_id=order_id, email_verified=True, membership_status="active",
                        membership_start=membership_start, membership_end=membership_end, plan_name=plan_name,
                        plan_price=plan_price, currency=currency, subscription_type=subscription_type,
                        subscription_duration_days=duration_days)
            db.session.add(user); db.session.flush(); is_new = True
        else:
            user.first_name = first_name or user.first_name; user.last_name = last_name or user.last_name
            user.wix_contact_id = contact_id or user.wix_contact_id; user.wix_order_id = order_id or user.wix_order_id
            user.wix_payment_id = order_id or user.wix_payment_id; user.email_verified = True
            user.membership_status = "active"; user.membership_start = membership_start
            user.membership_end = membership_end; user.plan_name = plan_name or user.plan_name
            user.plan_price = plan_price if plan_price > 0 else user.plan_price; user.currency = currency or user.currency
            user.subscription_type = subscription_type; user.subscription_duration_days = duration_days
            db.session.flush()
        if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
            order = Order(user_id=user.id, wix_order_id=order_id, wix_payment_id=order_id, plan_name=plan_name,
                          plan_price=plan_price, currency=currency, total_amount=plan_price,
                          subscription_type=subscription_type, subscription_duration_days=duration_days,
                          status="completed", payment_status="paid", ip_address=request.remote_addr, raw_data=json.dumps(data))
            db.session.add(order)
        db.session.commit()
        send_email_async("Welcome to Trading Engine! 🎉", [email],
                         f"Your {plan_name} is active. Login at {Config.APP_URL}/login",
                         f"<h3>Hi {first_name or 'there'}!</h3><p>Plan: {plan_name}</p><p>Login: {Config.APP_URL}/login</p>")
        log_audit(user.id, "wix_plan_ordered", f"{'New' if is_new else 'Updated'} | {plan_name} | {subscription_type}", request.remote_addr)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Webhook failed: {e}", exc_info=True); db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# STRIPE WEBHOOK
# ============================================================================

@app.route("/webhook/stripe/payment", methods=["POST"])
@limiter.limit("60 per minute")
def stripe_payment_webhook():
    try:
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get("Stripe-Signature")
        if Config.STRIPE_WEBHOOK_SECRET:
            if stripe is None:
                logger.error("Stripe library not installed")
                return jsonify({"error": "Stripe not configured"}), 500
            try:
                event = stripe.Webhook.construct_event(payload, sig_header, Config.STRIPE_WEBHOOK_SECRET)
            except stripe.error.SignatureVerificationError as e:
                logger.warning(f"Stripe signature invalid: {e}")
                return jsonify({"error": "Invalid signature"}), 400
            except Exception as e:
                logger.error(f"Stripe webhook error: {e}")
                return jsonify({"error": "Webhook error"}), 400
        else:
            event = json.loads(payload)
        event_type = event["type"]
        logger.info(f"Stripe Webhook: {event_type}")
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
            plan_name = metadata.get("plan_name", "Unknown Plan")
            plan_duration = metadata.get("plan_duration", "")
            amount_total = (session_data.get("amount_total") or 0) / 100
            currency = (session_data.get("currency") or "eur").upper()
            order_id = session_data.get("id", "")
            if not email: return jsonify({"error": "Email required"}), 400
            duration_days, subscription_type = parse_duration_to_days(plan_duration)
            if subscription_type == "one_time" and plan_name:
                pl = plan_name.lower()
                if "monthly" in pl or "maand" in pl: duration_days, subscription_type = 30, "monthly"
                elif "yearly" in pl or "jaar" in pl: duration_days, subscription_type = 365, "yearly"
                elif "lifetime" in pl: duration_days, subscription_type = 36500, "lifetime"
            membership_start = datetime.utcnow()
            membership_end = membership_start + timedelta(days=duration_days)
            user = User.query.filter_by(email=email).first(); is_new = False
            if not user:
                user = User(email=email, first_name=first_name, last_name=last_name, phone=phone, country=country,
                            wix_order_id=order_id, wix_payment_id=order_id, email_verified=True, membership_status="active",
                            membership_start=membership_start, membership_end=membership_end, plan_name=plan_name,
                            plan_price=amount_total, currency=currency, subscription_type=subscription_type,
                            subscription_duration_days=duration_days)
                db.session.add(user); db.session.flush(); is_new = True
            else:
                user.first_name = first_name or user.first_name; user.last_name = last_name or user.last_name
                user.phone = phone or user.phone; user.country = country or user.country
                user.wix_order_id = order_id or user.wix_order_id; user.wix_payment_id = order_id or user.wix_payment_id
                user.email_verified = True; user.membership_status = "active"
                user.membership_start = membership_start; user.membership_end = membership_end
                user.plan_name = plan_name or user.plan_name
                user.plan_price = amount_total if amount_total > 0 else user.plan_price
                user.currency = currency or user.currency
                user.subscription_type = subscription_type; user.subscription_duration_days = duration_days
                db.session.flush()
            if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
                order = Order(user_id=user.id, wix_order_id=order_id, wix_payment_id=order_id, plan_name=plan_name,
                              plan_price=amount_total, currency=currency, total_amount=amount_total,
                              subscription_type=subscription_type, subscription_duration_days=duration_days,
                              status="completed", payment_status="paid", ip_address=request.remote_addr,
                              raw_data=json.dumps(session_data))
                db.session.add(order)
            db.session.commit()
            send_email_async("Welcome to Trading Engine! 🎉", [email],
                             f"Your {plan_name} is active. Login at {Config.APP_URL}/login",
                             f"<h3>Hi {first_name or 'there'}!</h3><p>Plan: {plan_name}</p><p>Login: {Config.APP_URL}/login</p>")
            log_audit(user.id, "stripe_payment", f"{'New' if is_new else 'Updated'} | {plan_name} | {subscription_type}", request.remote_addr)
            logger.info(f"✅ Stripe: {email} | {plan_name} | {currency} {amount_total}")
        elif event_type == "invoice.paid":
            invoice = event["data"]["object"]._to_dict_recursive()
            customer_email = invoice.get("customer_email", "").strip().lower()
            if not customer_email: return jsonify({"status": "ignored"}), 200
            lines = (invoice.get("lines") or {}).get("data", [])
            plan_name = "Unknown Plan"; duration_days = Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS; subscription_type = "one_time"
            if lines:
                first_line = lines[0]
                plan_metadata = first_line.get("metadata") or {}
                plan_name = plan_metadata.get("plan_name", first_line.get("description", "Unknown Plan"))
                period = first_line.get("period") or {}
                if period:
                    try:
                        period_start = datetime.fromtimestamp(period.get("start", datetime.utcnow().timestamp()))
                        period_end = datetime.fromtimestamp(period.get("end", datetime.utcnow().timestamp() + 2592000))
                        duration_days = max((period_end - period_start).days, 1)
                        if duration_days <= 31: subscription_type = "monthly"
                        elif duration_days <= 366: subscription_type = "yearly"
                        else: subscription_type = "lifetime"
                    except: pass
            amount_total = (invoice.get("amount_paid") or 0) / 100
            currency = (invoice.get("currency") or "eur").upper()
            order_id = invoice.get("id", "")
            user = User.query.filter_by(email=customer_email).first()
            if user:
                user.membership_status = "active"; user.membership_start = datetime.utcnow()
                user.membership_end = datetime.utcnow() + timedelta(days=duration_days)
                user.subscription_duration_days = duration_days; user.subscription_type = subscription_type
                if not Order.query.filter_by(wix_order_id=order_id).first() and order_id:
                    order = Order(user_id=user.id, wix_order_id=order_id, wix_payment_id=order_id, plan_name=plan_name,
                                  plan_price=amount_total, currency=currency, total_amount=amount_total,
                                  subscription_type=subscription_type, subscription_duration_days=duration_days,
                                  status="completed", payment_status="paid", ip_address=request.remote_addr)
                    db.session.add(order)
                db.session.commit()
                logger.info(f"✅ Stripe renewal: {customer_email} | {plan_name} | Extended to {user.membership_end}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Stripe webhook failed: {e}", exc_info=True); db.session.rollback()
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
    except Exception as e: logger.error(f"Discord role failed: {e}"); return False


@app.route("/connect-discord")
@login_required
def connect_discord():
    if not current_user.is_membership_active(): flash("Active membership required.", "error"); return redirect(url_for("user_dashboard"))
    if not Config.DISCORD_CLIENT_ID: flash("Discord not configured.", "error"); return redirect(url_for("user_dashboard"))
    params = urllib.parse.urlencode({"client_id": Config.DISCORD_CLIENT_ID, "redirect_uri": Config.DISCORD_REDIRECT_URI, "response_type": "code", "scope": "identify guilds.join"})
    return redirect(f"https://discord.com/oauth2/authorize?{params}")


@app.route("/discord/callback")
@login_required
def discord_callback():
    code = request.args.get("code")
    if not code: flash("Discord connection cancelled.", "error"); return redirect(url_for("user_dashboard"))
    try:
        token_data = urllib.parse.urlencode({"client_id": Config.DISCORD_CLIENT_ID, "client_secret": Config.DISCORD_CLIENT_SECRET, "grant_type": "authorization_code", "code": code, "redirect_uri": Config.DISCORD_REDIRECT_URI}).encode()
        token_req = urllib.request.Request("https://discord.com/api/oauth2/token", data=token_data, method="POST")
        token_req.add_header("Content-Type", "application/x-www-form-urlencoded")
        token_json = json.loads(urllib.request.urlopen(token_req).read())
        access_token = token_json["access_token"]
        user_req = urllib.request.Request("https://discord.com/api/users/@me")
        user_req.add_header("Authorization", f"Bearer {access_token}")
        discord_user = json.loads(urllib.request.urlopen(user_req).read())
        discord_id = discord_user["id"]
        join_data = json.dumps({"access_token": access_token}).encode()
        join_req = urllib.request.Request(f"https://discord.com/api/guilds/{Config.DISCORD_GUILD_ID}/members/{discord_id}", data=join_data, method="PUT")
        join_req.add_header("Authorization", f"Bot {Config.DISCORD_BOT_TOKEN}")
        join_req.add_header("Content-Type", "application/json")
        try: urllib.request.urlopen(join_req)
        except: pass
        assign_discord_role(discord_id)
        current_user.discord_user_id = discord_id; current_user.discord_joined = True; db.session.commit()
        flash("Discord connected! 🎉", "success")
    except Exception as e: logger.error(f"Discord OAuth failed: {e}"); flash("Discord connection failed.", "error")
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
                admin = User(email=admin_email, first_name="Admin", is_admin=True, email_verified=True,
                             membership_status="active", membership_start=datetime.utcnow(),
                             membership_end=datetime.utcnow() + timedelta(days=3650),
                             plan_name="Admin", subscription_type="lifetime", subscription_duration_days=36500)
                db.session.add(admin); db.session.commit()
        except Exception as e: logger.error(f"DB init failed: {e}")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
