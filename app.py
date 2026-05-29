"""
Subscription & Licensing Platform
Complete Flask Application with Wix Integration, OTP Auth, License Management & Discord Integration
Compatible with local development and Railway deployment
"""

import os
import re
import sys
import uuid
import json
import hashlib
import secrets
import logging
import threading
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

# Third-party imports
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
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
from dateutil import parser as dateparser

# Load environment variables
load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================


class Config:
    """Application configuration"""

    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))

    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///licensing.db")
    if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "noreply@yourplatform.com")

    # Wix
    WIX_WEBHOOK_SECRET = os.getenv("WIX_WEBHOOK_SECRET", "")

    # Discord
    DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
    DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "")
    DISCORD_ROLE_ID = os.getenv("DISCORD_ROLE_ID", "")
    DISCORD_INVITE_LINK = os.getenv("DISCORD_INVITE_LINK", "")

    # Encryption
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")

    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "memory://")

    # Application
    APP_URL = os.getenv("APP_URL", "http://localhost:5000")
    OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", 10))
    ADMIN_OTP_EXPIRY_MINUTES = 5
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
    LICENSE_EXPIRY_DAYS = int(os.getenv("LICENSE_EXPIRY_DAYS", 365))
    DEFAULT_SUBSCRIPTION_DURATION_DAYS = int(os.getenv("DEFAULT_SUBSCRIPTION_DURATION_DAYS", 365))
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))

    # Environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    @staticmethod
    def is_railway():
        return bool(os.getenv("RAILWAY_STATIC_URL"))


# Initialize Flask
app = Flask(__name__)
app.config.from_object(Config)

# Production settings for Railway
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
login_manager.login_message = "Please log in to access this page."
CORS(app, supports_credentials=True)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=Config.RATELIMIT_STORAGE_URL,
)

# Encryption setup
try:
    if Config.ENCRYPTION_KEY:
        encryption_key = Config.ENCRYPTION_KEY.encode() if isinstance(Config.ENCRYPTION_KEY, str) else Config.ENCRYPTION_KEY
        cipher_suite = Fernet(encryption_key)
    else:
        encryption_key = Fernet.generate_key()
        cipher_suite = Fernet(encryption_key)
        print(f"Generated new encryption key. Add to .env: ENCRYPTION_KEY={encryption_key.decode()}")
except Exception:
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)
    print(f"Generated new encryption key. Add to .env: ENCRYPTION_KEY={encryption_key.decode()}")

# Create upload folder
Path(Config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO if not Config.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MODELS
# ============================================================================


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    address_line1 = db.Column(db.String(200), nullable=True)
    address_city = db.Column(db.String(100), nullable=True)
    address_state = db.Column(db.String(100), nullable=True)
    address_zip = db.Column(db.String(20), nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    wix_contact_id = db.Column(db.String(100), nullable=True)
    wix_payment_id = db.Column(db.String(100), unique=True, nullable=True)
    wix_order_id = db.Column(db.String(100), nullable=True)
    wix_invoice_id = db.Column(db.String(100), nullable=True)
    membership_status = db.Column(db.String(20), default="pending", index=True)
    membership_start = db.Column(db.DateTime, nullable=True)
    membership_end = db.Column(db.DateTime, nullable=True)
    subscription_duration_days = db.Column(db.Integer, nullable=True)
    plan_name = db.Column(db.String(100), nullable=True)
    plan_price = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)
    subscription_type = db.Column(db.String(50), nullable=True)
    discord_user_id = db.Column(db.String(100), nullable=True)
    discord_joined = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(500), nullable=True)
    referral_source = db.Column(db.String(200), nullable=True)

    otp_tokens = db.relationship("OTPToken", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    licenses = db.relationship("License", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def is_membership_active(self):
        if self.membership_status != "active":
            return False
        if self.membership_end and self.membership_end < datetime.utcnow():
            self.membership_status = "expired"
            db.session.commit()
            return False
        return True

    def get_active_license(self):
        return self.licenses.filter_by(status="active").first()

    def get_full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        return self.email

    def get_membership_duration_display(self):
        if not self.subscription_duration_days:
            return "Default"
        if self.subscription_type == "lifetime":
            return "Lifetime"
        if self.subscription_duration_days >= 365:
            years = self.subscription_duration_days / 365
            return f"{years:.0f} Year{'s' if years > 1 else ''}"
        if self.subscription_duration_days >= 30:
            months = self.subscription_duration_days / 30
            return f"{months:.0f} Month{'s' if months > 1 else ''}"
        return f"{self.subscription_duration_days} Days"

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.get_full_name(),
            "phone": self.phone,
            "country": self.country,
            "membership_status": self.membership_status,
            "membership_start": self.membership_start.isoformat() if self.membership_start else None,
            "membership_end": self.membership_end.isoformat() if self.membership_end else None,
            "plan_name": self.plan_name,
            "plan_price": self.plan_price,
            "currency": self.currency,
            "subscription_type": self.subscription_type,
            "is_active": self.is_membership_active(),
            "created_at": self.created_at.isoformat(),
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
    machine_name = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), default="active", index=True)
    license_type = db.Column(db.String(50), default="standard")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_validated = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    validation_count = db.Column(db.Integer, default=0)
    max_validations = db.Column(db.Integer, default=10000)
    ea_version = db.Column(db.String(20), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    def is_valid(self):
        if self.status != "active":
            return False
        if self.expires_at < datetime.utcnow():
            self.status = "expired"
            db.session.commit()
            return False
        if self.validation_count >= self.max_validations:
            return False
        return True

    def mask_license_key(self):
        if len(self.license_key) > 8:
            return f"{self.license_key[:4]}...{self.license_key[-4:]}"
        return self.license_key


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    wix_order_id = db.Column(db.String(100), unique=True, nullable=True)
    wix_payment_id = db.Column(db.String(100), nullable=True)
    wix_invoice_id = db.Column(db.String(100), nullable=True)
    wix_checkout_id = db.Column(db.String(100), nullable=True)
    plan_name = db.Column(db.String(200), nullable=True)
    plan_price = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    discount_amount = db.Column(db.Float, default=0.0)
    tax_amount = db.Column(db.Float, default=0.0)
    total_amount = db.Column(db.Float, nullable=True)
    subscription_type = db.Column(db.String(50), nullable=True)
    subscription_duration_days = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default="completed")
    payment_status = db.Column(db.String(20), default="paid")
    fulfillment_status = db.Column(db.String(20), default="fulfilled")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    coupon_code = db.Column(db.String(100), nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    raw_data = db.Column(db.Text, nullable=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
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
    min_license_type = db.Column(db.String(50), default="standard")
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    download_count = db.Column(db.Integer, default=0)
    checksum = db.Column(db.String(64), nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class SubscriptionPlan(db.Model):
    __tablename__ = "subscription_plans"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default="EUR")
    duration_days = db.Column(db.Integer, nullable=False)
    subscription_type = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    features = db.Column(db.Text, nullable=True)
    max_licenses = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def encrypt_data(data: str) -> str:
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return data


def decrypt_data(encrypted_data: str) -> str:
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return encrypted_data


def generate_license_key() -> str:
    segments = [secrets.token_hex(2).upper() for _ in range(3)]
    return "-".join(segments)


def generate_otp() -> str:
    return "".join([str(secrets.randbelow(10)) for _ in range(6)])


def calculate_subscription_duration(subscription_type: str, duration_days: int = None) -> int:
    if subscription_type == "lifetime":
        return 36500
    elif subscription_type == "yearly":
        return duration_days or 365
    elif subscription_type == "monthly":
        return duration_days or 30
    else:
        return duration_days or Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS


def send_email_async(subject: str, recipients: list, body: str, html_body: str = None):
    def send():
        try:
            with app.app_context():
                msg = Message(subject=subject, recipients=recipients, body=body, html=html_body)
                mail.send(msg)
                logger.info(f"Email sent to {recipients}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            if Config.ENVIRONMENT == "development":
                print(f"\n{'='*50}")
                print(f"EMAIL TO: {recipients}")
                print(f"SUBJECT: {subject}")
                print(f"BODY: {body}")
                print(f"{'='*50}\n")

    thread = threading.Thread(target=send)
    thread.start()


def log_audit(user_id: int, action: str, details: str = None, ip_address: str = None):
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address or (request.remote_addr if request else "system"),
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log audit: {e}")


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"ex4", "ex5", "dll", "zip"}


def parse_duration_to_days(duration_str: str) -> tuple:
    """Parse Wix plan_duration string to days and subscription type"""
    if not duration_str:
        return Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS, "one_time"
    
    duration_lower = duration_str.lower()
    
    if "month" in duration_lower:
        months = re.findall(r'\d+', duration_lower)
        days = int(months[0]) * 30 if months else 30
        return days, "monthly"
    elif "year" in duration_lower:
        years = re.findall(r'\d+', duration_lower)
        days = int(years[0]) * 365 if years else 365
        return days, "yearly"
    elif "lifetime" in duration_lower:
        return 36500, "lifetime"
    else:
        return Config.DEFAULT_SUBSCRIPTION_DURATION_DAYS, "one_time"


# ============================================================================
# DECORATORS
# ============================================================================


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("Admin access required.", "error")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# USER LOADER
# ============================================================================


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ============================================================================
# ERROR HANDLERS
# ============================================================================


@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Resource not found"}), 404
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500
    return render_template("errors/500.html"), 500


# ============================================================================
# ROUTES - MAIN
# ============================================================================


@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))
    return redirect(url_for("user_login"))


@app.route("/health")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": Config.ENVIRONMENT,
    })


# ============================================================================
# ROUTES - UNIFIED LOGIN
# ============================================================================


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def user_login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            flash("Invalid email address.", "error")
            return render_template("user/login.html")

        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()

        if email == admin_email:
            session["admin_email"] = email
            return redirect(url_for("admin_password"))

        user = User.query.filter_by(email=email).first()

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash("Account temporarily locked. Please try again later.", "error")
            return render_template("user/login.html")

        if not user:
            user = User(email=email, email_verified=False, is_admin=False)
            db.session.add(user)
            db.session.commit()

        try:
            OTPToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
            otp = generate_otp()
            expires_at = datetime.utcnow() + timedelta(minutes=Config.OTP_EXPIRY_MINUTES)

            otp_token = OTPToken(user_id=user.id, token=otp, expires_at=expires_at, purpose="login")
            db.session.add(otp_token)
            db.session.commit()

            user_name = user.get_full_name() if user.first_name else "there"
            html_body = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #4B7BE5 0%, #5534A5 100%); padding: 20px; border-radius: 10px 10px 0 0;">
                    <h2 style="color: white; margin: 0;">Trading Engine Platform</h2>
                </div>
                <div style="background: white; padding: 30px; border: 1px solid #e0e0e0; border-radius: 0 0 10px 10px;">
                    <h3 style="color: #333;">Hi {user_name}! Your OTP Code</h3>
                    <p>Use the following code to verify your email:</p>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                        <h1 style="color: #4B7BE5; font-size: 36px; margin: 0; letter-spacing: 5px;">{otp}</h1>
                    </div>
                    <p style="color: #666;">This code expires in {Config.OTP_EXPIRY_MINUTES} minutes.</p>
                </div>
            </div>
            """
            send_email_async("Your OTP Code - Trading Engine", [email], f"Your OTP code is: {otp}", html_body)

            session["pending_email"] = email
            flash("OTP sent to your email.", "success")
            return redirect(url_for("verify_otp"))

        except Exception as e:
            logger.error(f"OTP generation failed: {e}")
            flash("Failed to send OTP. Please try again.", "error")

    return render_template("user/login.html")


@app.route("/admin-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_password():
    admin_email = session.get("admin_email") or os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()

    admin_user = User.query.filter_by(email=admin_email).first()
    if admin_user and admin_user.locked_until and admin_user.locked_until > datetime.utcnow():
        session.pop("admin_email", None)
        flash("Admin account locked. Try again later.", "error")
        return redirect(url_for("user_login"))

    if request.method == "POST":
        password = request.form.get("password", "")
        admin_password = os.getenv("ADMIN_PASSWORD", "admin123").strip()

        if password == admin_password:
            if not admin_user:
                admin_user = User(
                    email=admin_email, first_name="Admin", is_admin=True,
                    email_verified=True, membership_status="active",
                    membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin", subscription_type="lifetime", subscription_duration_days=36500,
                )
                db.session.add(admin_user)
            else:
                admin_user.login_attempts = 0
                admin_user.locked_until = None
                if not admin_user.is_admin:
                    admin_user.is_admin = True
            db.session.commit()

            OTPToken.query.filter_by(user_id=admin_user.id, used=False).update({"used": True})
            otp = generate_otp()
            expires_at = datetime.utcnow() + timedelta(minutes=Config.ADMIN_OTP_EXPIRY_MINUTES)
            otp_token = OTPToken(user_id=admin_user.id, token=otp, expires_at=expires_at, purpose="admin")
            db.session.add(otp_token)
            db.session.commit()

            if Config.ENVIRONMENT == "development":
                print(f"\nADMIN OTP for {admin_email}: {otp}\n")

            html_body = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #4B7BE5 0%, #5534A5 100%); padding: 20px; border-radius: 10px 10px 0 0;">
                    <h2 style="color: white; margin: 0;">Admin Verification</h2>
                </div>
                <div style="background: white; padding: 30px; border: 1px solid #e0e0e0; border-radius: 0 0 10px 10px;">
                    <h3 style="color: #333;">Admin OTP Code</h3>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                        <h1 style="color: #4B7BE5; font-size: 36px; margin: 0; letter-spacing: 5px;">{otp}</h1>
                    </div>
                    <p style="color: #EF4444;">⚠️ Expires in {Config.ADMIN_OTP_EXPIRY_MINUTES} minutes.</p>
                </div>
            </div>
            """
            send_email_async("Admin OTP - Trading Engine", [admin_email], f"Admin OTP: {otp}", html_body)

            session["pending_email"] = admin_email
            session["is_admin_login"] = True
            session.pop("admin_email", None)
            flash("Password verified. OTP sent.", "success")
            return redirect(url_for("verify_otp"))
        else:
            if admin_user:
                admin_user.login_attempts += 1
                if admin_user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                    admin_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    flash("Admin account locked for 30 minutes.", "error")
                else:
                    remaining = Config.MAX_LOGIN_ATTEMPTS - admin_user.login_attempts
                    flash(f"Invalid password. {remaining} attempts remaining.", "error")
                db.session.commit()
            else:
                flash("Invalid password.", "error")

    return render_template("admin/password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp():
    email = session.get("pending_email")
    is_admin_login = session.get("is_admin_login", False)

    if not email:
        return redirect(url_for("user_login"))

    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()

        if not otp_code or len(otp_code) != 6:
            flash("Invalid OTP code.", "error")
            return render_template("user/verify_otp.html", email=email, is_admin=is_admin_login)

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("user_login"))

        otp_token = OTPToken.query.filter_by(user_id=user.id, used=False).order_by(OTPToken.created_at.desc()).first()

        if not otp_token:
            flash("No OTP found. Please request a new one.", "error")
            return render_template("user/verify_otp.html", email=email, is_admin=is_admin_login)

        if otp_token.attempts >= 3:
            otp_token.used = True
            db.session.commit()
            flash("Too many attempts. Please request a new OTP.", "error")
            return render_template("user/verify_otp.html", email=email, is_admin=is_admin_login)

        if otp_token.token == otp_code:
            if not otp_token.is_valid():
                flash("OTP has expired. Please request a new one.", "error")
                return render_template("user/verify_otp.html", email=email, is_admin=is_admin_login)

            otp_token.used = True
            user.email_verified = True
            user.login_attempts = 0
            user.last_login = datetime.utcnow()
            user.locked_until = None

            if not user.is_admin and (not user.membership_status or user.membership_status == "pending"):
                user.membership_status = "active"
                user.membership_start = datetime.utcnow()
                user.membership_end = datetime.utcnow() + timedelta(days=Config.LICENSE_EXPIRY_DAYS)

            db.session.commit()
            login_user(user, remember=True)
            session.pop("pending_email", None)
            session.pop("is_admin_login", None)

            log_audit(user.id, "login", f"{'Admin' if user.is_admin else 'User'} login", request.remote_addr)
            flash(f"Welcome back, {user.get_full_name()}!", "success")

            if user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("user_dashboard"))
        else:
            otp_token.attempts += 1
            user.login_attempts += 1

            if user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                flash("Account locked for 30 minutes.", "error")
            else:
                flash("Invalid OTP code.", "error")
            db.session.commit()

    return render_template("user/verify_otp.html", email=email, is_admin=is_admin_login)


@app.route("/logout")
@login_required
def logout():
    log_audit(current_user.id, "logout", f"User {current_user.email} logged out", request.remote_addr)
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("user_login"))


# ============================================================================
# ROUTES - USER DASHBOARD
# ============================================================================


@app.route("/dashboard")
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    user = current_user
    license = user.get_active_license()
    orders = user.orders.order_by(Order.created_at.desc()).limit(5).all()
    ea_files = EAFile.query.filter_by(is_active=True).order_by(EAFile.upload_date.desc()).all()

    return render_template(
        "user/dashboard.html",
        user=user,
        license=license,
        orders=orders,
        ea_files=ea_files,
        discord_invite=Config.DISCORD_INVITE_LINK,
        now=datetime.utcnow(),
    )


@app.route("/generate-license", methods=["POST"])
@login_required
@limiter.limit("3 per day")
def generate_license():
    if not current_user.is_membership_active():
        return jsonify({"error": "Active membership required"}), 403

    existing_license = current_user.get_active_license()
    if existing_license:
        return jsonify({"error": "You already have an active license", "license_key": existing_license.mask_license_key()}), 400

    try:
        license_key = generate_license_key()
        duration_days = current_user.subscription_duration_days or Config.LICENSE_EXPIRY_DAYS

        license = License(
            user_id=current_user.id,
            license_key=license_key,
            expires_at=datetime.utcnow() + timedelta(days=duration_days),
            ea_version="1.0.0",
            license_type=current_user.subscription_type or "standard",
        )
        db.session.add(license)
        db.session.commit()

        threading.Thread(target=add_to_discord, args=(current_user.id,)).start()
        log_audit(current_user.id, "license_generated", f"License {license.mask_license_key()} generated | {duration_days} days", request.remote_addr)

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #4B7BE5 0%, #5534A5 100%); padding: 20px; border-radius: 10px 10px 0 0;">
                <h2 style="color: white; margin: 0;">Your License Key</h2>
            </div>
            <div style="background: white; padding: 30px; border: 1px solid #e0e0e0; border-radius: 0 0 10px 10px;">
                <h3 style="color: #3FBFB3;">Hi {current_user.get_full_name()}!</h3>
                <p>Your license key:</p>
                <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                    <h2 style="color: #4B7BE5; font-family: monospace;">{license_key}</h2>
                </div>
                <p><strong>Valid until:</strong> {license.expires_at.strftime('%B %d, %Y')}</p>
            </div>
        </div>
        """
        send_email_async("Your License Key - Trading Engine", [current_user.email], f"Your license key: {license_key}", html_body)

        return jsonify({
            "success": True,
            "license_key": license_key,
            "masked_key": license.mask_license_key(),
            "expires_at": license.expires_at.isoformat(),
        })

    except Exception as e:
        logger.error(f"License generation failed: {e}")
        db.session.rollback()
        return jsonify({"error": "Failed to generate license"}), 500


@app.route("/download-ea/<int:file_id>")
@login_required
def download_ea(file_id):
    if not current_user.is_membership_active():
        flash("Active membership required.", "error")
        return redirect(url_for("user_dashboard"))

    ea_file = db.session.get(EAFile, file_id)
    if not ea_file or not ea_file.is_active:
        abort(404)

    ea_file.download_count += 1
    db.session.commit()

    log_audit(current_user.id, "ea_download", f"Downloaded {ea_file.filename} v{ea_file.version}", request.remote_addr)
    return send_from_directory(Config.UPLOAD_FOLDER, ea_file.file_path, as_attachment=True, download_name=ea_file.filename)


# ============================================================================
# ROUTES - ADMIN
# ============================================================================


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    total_users = User.query.filter_by(is_admin=False).count()
    active_users = User.query.filter_by(membership_status="active", is_admin=False).count()
    total_licenses = License.query.count()
    active_licenses = License.query.filter_by(status="active").count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
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
        "admin/dashboard.html",
        total_users=total_users, active_users=active_users,
        total_licenses=total_licenses, active_licenses=active_licenses,
        total_orders=total_orders, total_revenue=total_revenue,
        total_downloads=total_downloads, recent_users=recent_users,
        recent_orders=recent_orders, recent_licenses=recent_licenses,
        recent_logs=recent_logs, ea_files=ea_files,
        subscription_stats=subscription_stats, now=datetime.utcnow(),
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
    if not user:
        abort(404)
    orders = user.orders.order_by(Order.created_at.desc()).all()
    licenses = user.licenses.order_by(License.created_at.desc()).all()
    audit_logs = AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.created_at.desc()).limit(50).all()
    return render_template("admin/user_detail.html", user=user, orders=orders, licenses=licenses, audit_logs=audit_logs)


@app.route("/admin/orders")
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    revenue_by_plan = db.session.query(Order.plan_name, db.func.count(Order.id), db.func.sum(Order.total_amount)).group_by(Order.plan_name).all()
    return render_template("admin/orders.html", orders=orders, total_revenue=total_revenue, revenue_by_plan=revenue_by_plan)


@app.route("/admin/revoke-license/<int:license_id>", methods=["POST"])
@admin_required
def revoke_license(license_id):
    license = db.session.get(License, license_id)
    if not license:
        abort(404)
    license.status = "revoked"
    license.revoked_at = datetime.utcnow()
    db.session.commit()
    threading.Thread(target=remove_from_discord, args=(license.user.id,)).start()
    log_audit(current_user.id, "license_revoked", f"Revoked license {license.license_key}", request.remote_addr)
    flash("License revoked.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/revoke-membership/<int:user_id>", methods=["POST"])
@admin_required
def revoke_membership(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    user.membership_status = "revoked"
    user.membership_end = datetime.utcnow()
    License.query.filter_by(user_id=user.id, status="active").update({"status": "revoked", "revoked_at": datetime.utcnow()})
    db.session.commit()
    threading.Thread(target=remove_from_discord, args=(user.id,)).start()
    log_audit(current_user.id, "membership_revoked", f"Revoked membership for {user.email}", request.remote_addr)
    flash("Membership revoked.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/extend-membership/<int:user_id>", methods=["POST"])
@admin_required
def extend_membership(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    days = int(request.form.get("days", 30))
    if user.membership_end and user.membership_end > datetime.utcnow():
        user.membership_end += timedelta(days=days)
    else:
        user.membership_start = datetime.utcnow()
        user.membership_end = datetime.utcnow() + timedelta(days=days)
    user.membership_status = "active"
    db.session.commit()
    log_audit(current_user.id, "membership_extended", f"Extended {user.email} by {days} days", request.remote_addr)
    flash(f"Membership extended by {days} days.", "success")
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/upload-ea", methods=["POST"])
@admin_required
def upload_ea():
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("admin_dashboard"))

    file = request.files["file"]
    if file.filename == "" or not allowed_file(file.filename):
        flash("Invalid file type.", "error")
        return redirect(url_for("admin_dashboard"))

    filename = secure_filename(file.filename)
    version = request.form.get("version", "1.0.0")
    description = request.form.get("description", "")
    changelog = request.form.get("changelog", "")
    is_beta = request.form.get("is_beta") == "on"

    saved_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file_path = os.path.join(Config.UPLOAD_FOLDER, saved_filename)
    file.save(file_path)

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    ea_file = EAFile(
        filename=filename, file_path=saved_filename, version=version,
        file_size=os.path.getsize(file_path), description=description,
        changelog=changelog, is_beta=is_beta, checksum=sha256_hash.hexdigest(),
        uploaded_by=current_user.id,
    )
    db.session.add(ea_file)
    db.session.commit()
    log_audit(current_user.id, "ea_upload", f"Uploaded {filename} v{version}", request.remote_addr)
    flash("EA file uploaded.", "success")
    return redirect(url_for("admin_dashboard"))


# ============================================================================
# API ROUTES
# ============================================================================


@app.route("/api/validate-license", methods=["POST"])
@limiter.limit("30 per minute")
def api_validate_license():
    try:
        data = request.get_json()
        license_key = data.get("license_key", "")
        machine_id = data.get("machine_id", "")

        if not license_key:
            return jsonify({"valid": False, "error": "License key required"}), 400

        license = License.query.filter_by(license_key=license_key).first()
        if not license:
            return jsonify({"valid": False, "error": "Invalid license key"}), 404
        if not license.is_valid():
            return jsonify({"valid": False, "error": "License not active"}), 403
        if license.machine_id and license.machine_id != machine_id:
            return jsonify({"valid": False, "error": "License bound to different machine"}), 403

        if not license.machine_id and machine_id:
            license.machine_id = encrypt_data(machine_id)

        license.last_validated = datetime.utcnow()
        license.validation_count += 1
        db.session.commit()

        return jsonify({
            "valid": True,
            "expires_at": license.expires_at.isoformat(),
            "ea_version": license.ea_version,
            "user_email": license.user.email,
            "license_type": license.license_type,
            "validation_count": license.validation_count,
        })
    except Exception as e:
        logger.error(f"License validation failed: {e}")
        return jsonify({"valid": False, "error": "Validation failed"}), 500


@app.route("/api/user/info")
@login_required
def api_user_info():
    return jsonify(current_user.to_dict())


@app.route("/api/admin/user/<int:user_id>")
@admin_required
def api_admin_user_detail(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict())


# ============================================================================
# WIX WEBHOOK - PLAN ORDERED
# ============================================================================


@app.route("/webhook/wix/payment", methods=["POST"])
@limiter.limit("60 per minute")
def wix_payment_webhook():
    """Handle Wix Plan Ordered webhook with flat fields"""
    try:
        data = request.get_json()
        logger.info(f"Wix Webhook received: {json.dumps(data, indent=2)}")

        event_type = data.get("eventType", "")

        # Only process Plan ordered events
        if event_type != "Plan ordered":
            logger.info(f"Ignoring event type: {event_type}")
            return jsonify({"status": "ignored"}), 200

        # Extract fields from Wix flat format
        email = data.get("contact_email", "").strip().lower()
        contact_id = data.get("contact_id", "")
        first_name = data.get("contact_first_name", "")
        last_name = data.get("contact_last_name", "")
        plan_name = data.get("plan_name", "Unknown Plan")
        plan_duration = data.get("plan_duration", "")
        plan_start = data.get("plan_start_date", "")
        plan_end = data.get("plan_end_date", "")
        order_id = data.get("order_id", "")

        # Price
        try:
            plan_price = float(data.get("plan_price_amount", 0))
        except:
            plan_price = 0.0
        currency = data.get("plan_price_currency", "EUR")

        if not email:
            logger.error("No email in webhook")
            return jsonify({"error": "Email required"}), 400

        # Calculate duration and subscription type
        duration_days, subscription_type = parse_duration_to_days(plan_duration)

        # Also check plan name for subscription hints
        if subscription_type == "one_time":
            plan_lower = plan_name.lower()
            if "monthly" in plan_lower:
                duration_days, subscription_type = 30, "monthly"
            elif "yearly" in plan_lower or "annual" in plan_lower:
                duration_days, subscription_type = 365, "yearly"
            elif "lifetime" in plan_lower:
                duration_days, subscription_type = 36500, "lifetime"

        # Parse dates
        try:
            membership_start = dateparser.parse(plan_start) if plan_start else datetime.utcnow()
        except:
            membership_start = datetime.utcnow()

        try:
            membership_end = dateparser.parse(plan_end) if plan_end else membership_start + timedelta(days=duration_days)
        except:
            membership_end = membership_start + timedelta(days=duration_days)

        # Find or create user
        user = User.query.filter_by(email=email).first()
        is_new_user = False

        if not user:
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                wix_contact_id=contact_id,
                wix_order_id=order_id,
                wix_payment_id=order_id,
                membership_status="active",
                membership_start=membership_start,
                membership_end=membership_end,
                plan_name=plan_name,
                plan_price=plan_price,
                currency=currency,
                subscription_type=subscription_type,
                subscription_duration_days=duration_days,
            )
            db.session.add(user)
            db.session.flush()
            is_new_user = True
        else:
            user.first_name = first_name or user.first_name
            user.last_name = last_name or user.last_name
            user.wix_contact_id = contact_id or user.wix_contact_id
            user.wix_order_id = order_id or user.wix_order_id
            user.wix_payment_id = order_id or user.wix_payment_id
            user.membership_status = "active"
            user.membership_start = membership_start
            user.membership_end = membership_end
            user.plan_name = plan_name or user.plan_name
            user.plan_price = plan_price or user.plan_price
            user.currency = currency or user.currency
            user.subscription_type = subscription_type
            user.subscription_duration_days = duration_days
            db.session.flush()

        # Save order
        existing_order = Order.query.filter_by(wix_order_id=order_id).first()
        if not existing_order and order_id:
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
                raw_data=json.dumps(data),
            )
            db.session.add(order)

        db.session.commit()

        # Send welcome email
        user_name = f"{first_name} {last_name}".strip() or "there"
        welcome_html = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #4B7BE5 0%, #5534A5 100%); padding: 20px; border-radius: 10px 10px 0 0;">
                <h2 style="color: white; margin: 0;">Welcome to Trading Engine!</h2>
            </div>
            <div style="background: white; padding: 30px; border: 1px solid #e0e0e0; border-radius: 0 0 10px 10px;">
                <h3 style="color: #3FBFB3;">Hi {user_name}! 🎉</h3>
                <p><strong>Plan:</strong> {plan_name}</p>
                <p><strong>Duration:</strong> {plan_duration}</p>
                <p><strong>Start:</strong> {membership_start.strftime('%B %d, %Y')}</p>
                <p><strong>End:</strong> {membership_end.strftime('%B %d, %Y')}</p>
                <a href="{Config.APP_URL}/login" style="display: inline-block; padding: 12px 30px; background: #4B7BE5; color: white; text-decoration: none; border-radius: 8px; margin-top: 20px;">
                    Access Dashboard →
                </a>
            </div>
        </div>
        """
        send_email_async("Welcome to Trading Engine! 🎉", [email], f"Your {plan_name} subscription is active.", welcome_html)

        log_audit(user.id, "wix_plan_ordered", f"{'New' if is_new_user else 'Existing'} | Plan: {plan_name} | Duration: {plan_duration}", request.remote_addr)
        logger.info(f"✅ Plan ordered: {email} | {plan_name} | {plan_duration}")

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"Webhook failed: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# DISCORD INTEGRATION
# ============================================================================


def add_to_discord(user_id: int):
    if not Config.DISCORD_BOT_TOKEN or not Config.DISCORD_GUILD_ID:
        return
    try:
        with app.app_context():
            user = db.session.get(User, user_id)
            if user and user.is_membership_active():
                user.discord_joined = True
                user.discord_user_id = "pending"
                db.session.commit()
                log_audit(user_id, "discord_add", f"User {user.email} added to Discord", "system")
    except Exception as e:
        logger.error(f"Failed to add user to Discord: {e}")


def remove_from_discord(user_id: int):
    if not Config.DISCORD_BOT_TOKEN:
        return
    try:
        with app.app_context():
            user = db.session.get(User, user_id)
            if user:
                user.discord_joined = False
                user.discord_user_id = None
                db.session.commit()
                log_audit(user_id, "discord_remove", f"User {user.email} removed from Discord", "system")
    except Exception as e:
        logger.error(f"Failed to remove user from Discord: {e}")


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================


@app.before_request
def auto_init_db():
    """Auto-create tables on first request if they don't exist"""
    try:
        db.session.execute(db.text("SELECT 1 FROM users LIMIT 1"))
    except Exception:
        try:
            db.create_all()
            logger.info("✅ Database tables created automatically!")
            
            # Create admin user
            admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
            admin = User.query.filter_by(email=admin_email).first()
            if not admin:
                admin = User(
                    email=admin_email, first_name="Admin", is_admin=True,
                    email_verified=True, membership_status="active",
                    membership_start=datetime.utcnow(),
                    membership_end=datetime.utcnow() + timedelta(days=3650),
                    plan_name="Admin", subscription_type="lifetime",
                    subscription_duration_days=36500,
                )
                db.session.add(admin)
                db.session.commit()
                logger.info(f"✅ Admin created: {admin_email}")
        except Exception as e:
            logger.error(f"Database init failed: {e}")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Trading Engine - Subscription & Licensing Platform")
    print("=" * 60)

    if Config.ENVIRONMENT == "development":
        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "admin123").strip()
        print(f"Admin Email: {admin_email}")
        print(f"Admin Password: {admin_password}")
    
    print("=" * 60)

    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
