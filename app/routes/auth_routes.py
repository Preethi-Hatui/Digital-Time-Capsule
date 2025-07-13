from flask import Blueprint, request, redirect, render_template, session, url_for, flash
from flask_login import login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import db, User, OTPAttempt
from app.utils.email import send_otp_email, send_notification_email
from datetime import datetime, timedelta
import pyotp
import re
import pytz
import traceback

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# ---------------------------
# Config Constants
# ---------------------------
MAX_OTP_ATTEMPTS = 3
LOCKOUT_DURATION = timedelta(hours=1)
OTP_VALIDITY = 300  # 5 minutes
SESSION_TIMEOUT = 600  # 10 minutes

IST = pytz.timezone('Asia/Kolkata')

PASSWORD_REGEX = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
)

# ---------------------------
# Utility Functions
# ---------------------------
def validate_email(email):
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', email))

def validate_password(password):
    return bool(PASSWORD_REGEX.match(password))

def get_unlock_time(utc_dt):
    utc_dt = utc_dt.replace(tzinfo=pytz.utc)
    unlock_ist = utc_dt.astimezone(IST) + LOCKOUT_DURATION
    return unlock_ist.strftime("%I:%M %p")

# ==============================
# REGISTER
# ==============================
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not all([username, email, password, confirm_password]):
            flash("All fields are required.", "warning")
            return redirect(url_for('auth.register'))

        if len(username) < 3 or len(username) > 50:
            flash("Username must be between 3 and 50 characters.", "warning")
            return redirect(url_for('auth.register'))

        if not validate_email(email):
            flash("Invalid email format.", "warning")
            return redirect(url_for('auth.register'))

        if not validate_password(password):
            flash("Password must be at least 8 characters and include uppercase, lowercase, number, and special character.", "warning")
            return redirect(url_for('auth.register'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('auth.register'))

        existing_user = User.query.filter(
            (User.email == email) | (User.username == username)
        ).first()
        if existing_user:
            flash("Email or username already exists.", "danger")
            return redirect(url_for('auth.register'))

        otp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(otp_secret, interval=OTP_VALIDITY)
        otp_code = totp.now()

        try:
            send_otp_email(email, otp_code, subject="Digital Time Capsule - Email Verification OTP")
        except Exception:
            flash("Failed to send OTP email.", "danger")
            return redirect(url_for('auth.register'))

        session.permanent = True
        session['pending_registration'] = {
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password),
            'otp_secret': otp_secret
        }
        session['otp_start_time'] = datetime.utcnow().timestamp()

        flash("OTP sent to your email. Please verify to complete registration.", "info")
        return redirect(url_for('auth.verify_registration_otp'))

    return render_template('auth/register.html')

# ==============================
# VERIFY REGISTRATION OTP
# ==============================
@auth_bp.route('/verify_registration_otp', methods=['GET', 'POST'])
def verify_registration_otp():
    pending = session.get('pending_registration')
    if not pending:
        flash("Session expired. Please register again.", "warning")
        return redirect(url_for('auth.register'))

    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        if not otp_input:
            flash("OTP is required.", "warning")
            return render_template('auth/verify_otp.html', locked=False)

        totp = pyotp.TOTP(pending['otp_secret'], interval=OTP_VALIDITY)
        is_valid = totp.verify(otp_input)

        if is_valid:
            try:
                new_user = User(
                    username=pending['username'],
                    email=pending['email'],
                    password_hash=pending['password_hash'],
                    otp_secret=pending['otp_secret']
                )
                db.session.add(new_user)
                db.session.commit()

                db.session.add(OTPAttempt(
                    user_id=new_user.id,
                    capsule_id=None,
                    success=True,
                    timestamp=datetime.utcnow(),
                    ip_address=request.remote_addr,
                    action='register'
                ))
                db.session.commit()

                try:
                    from flask import render_template_string
                    html_body = render_template_string("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                    <meta charset="UTF-8" />
                    <title>Welcome to Digital Time Capsule</title>
                    <style>
                        body {
                        background-color: #f3f4f6;
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        margin: 0;
                        padding: 0;
                        color: #333;
                        }

                        .email-container {
                        max-width: 640px;
                        margin: 50px auto;
                        background-color: #ffffff;
                        border-radius: 16px;
                        overflow: hidden;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.12);
                        }

                        .email-header {
                        background: rgba(15, 23, 42, 0.95);
                        color: #ffffff;
                        padding: 40px 30px;
                        text-align: center;
                        backdrop-filter: blur(10px);
                        }

                        .email-header h1 {
                        font-size: 26px;
                        margin: 0;
                        font-weight: 700;
                        letter-spacing: 0.5px;
                        }

                        .email-header p {
                        font-size: 14px;
                        margin-top: 10px;
                        color: #cbd5e1;
                        }

                        .email-body {
                        padding: 40px 30px;
                        text-align: center;
                        }

                        .email-body h2 {
                        font-size: 22px;
                        font-weight: 600;
                        margin-bottom: 8px;
                        }

                        .welcome-highlight {
                        background: rgba(15, 23, 42, 0.88);
                        color: #ffffff;
                        padding: 24px 20px;
                        border-radius: 14px;
                        margin: 20px auto 30px;
                        max-width: 500px;
                        font-size: 15.5px;
                        line-height: 1.6;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                        }

                        .cta-button {
                        display: inline-block;
                        background: linear-gradient(to right, #0f172a, #1e293b);
                        color: #ffffff !important;
                        text-decoration: none;
                        padding: 14px 30px;
                        border-radius: 8px;
                        font-weight: 600;
                        font-size: 15px;
                        transition: all 0.3s ease;
                        box-shadow: 0 6px 16px rgba(15, 23, 42, 0.25);
                        margin-top: 10px;
                        }

                        .cta-button:hover {
                        background: #111827;
                        box-shadow: 0 8px 22px rgba(15, 23, 42, 0.35);
                        }

                        .features {
                        margin-top: 45px;
                        text-align: center;
                        }

                        .features h3 {
                        font-size: 16px;
                        margin-bottom: 24px;
                        color: #111827;
                        }

                        .feature-block {
                        margin-bottom: 30px;
                        }

                        .feature-block i {
                        font-size: 28px;
                        color: #0f172a;
                        margin-bottom: 12px;
                        }

                        .feature-description {
                        font-size: 14.5px;
                        color: #444;
                        max-width: 500px;
                        margin: 0 auto;
                        line-height: 1.5;
                        }

                        .email-footer {
                        background-color: #f1f5f9;
                        text-align: center;
                        font-size: 12px;
                        color: #777;
                        padding: 20px;
                        border-top: 1px solid #e2e8f0;
                        border-bottom-left-radius: 16px;
                        border-bottom-right-radius: 16px;
                        }

                        .email-footer a {
                        color: #0f62fe;
                        text-decoration: none;
                        }

                        .social-icons a {
                        margin: 0 8px;
                        color: #888;
                        font-size: 15px;
                        text-decoration: none;
                        }

                        .social-icons a:hover {
                        color: #0f62fe;
                        }
                    </style>
                    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
                    </head>
                    <body>
                    <div class="email-container">

                        <!-- Header -->
                        <div class="email-header">
                        <h1><i class="fas fa-shield-alt me-2"></i>Digital Time Capsule</h1>
                        <p>Secure. Private. Future-Proof.</p>
                        </div>

                        <!-- Body -->
                        <div class="email-body">
                        <h2>Welcome, <strong>{{ username }}</strong></h2>

                        <div class="welcome-highlight">
                            Your journey with Digital Time Capsule starts now.<br>
                            You're not just storing files—you're preserving moments, thoughts, and milestones for the future.<br><br>
                            We’re honored to safeguard your digital legacy.
                        </div>

                        <a href="{{ login_url }}" class="cta-button">
                            <i class="fas fa-lock-open me-1"></i> Access Dashboard
                        </a>

                        <!-- Key Benefits -->
                        <div class="features">
                            <h3>Why users trust Digital Time Capsule</h3>

                            <div class="feature-block">
                            <i class="fas fa-lock"></i>
                            <div class="feature-description">
                                AES-256 encrypted file storage with RSA-secured keys
                            </div>
                            </div>

                            <div class="feature-block">
                            <i class="fas fa-clock"></i>
                            <div class="feature-description">
                                Time-locked access — open only when you decide
                            </div>
                            </div>

                            <div class="feature-block">
                            <i class="fas fa-shield-alt"></i>
                            <div class="feature-description">
                                Mandatory 2FA via Google Authenticator for all capsules
                            </div>
                            </div>

                            <div class="feature-block">
                            <i class="fas fa-cloud"></i>
                            <div class="feature-description">
                                Backed by AWS S3 with military-grade security
                            </div>
                            </div>

                            <div class="feature-block">
                            <i class="fas fa-user-shield"></i>
                            <div class="feature-description">
                                You have full control — only you can unlock or delete your capsules
                            </div>
                            </div>
                        </div>
                        </div>

                        <!-- Footer -->
                        <div class="email-footer">
                        &copy; {{ current_year }} Digital Time Capsule. All rights reserved.<br />
                        Need help? Contact <a href="mailto:support@digitaltimecapsule.dev">support@digitaltimecapsule.dev</a>
                        <div class="social-icons" style="margin-top: 10px;">
                            <a href="#"><i class="fab fa-twitter"></i></a>
                            <a href="#"><i class="fab fa-discord"></i></a>
                            <a href="#"><i class="fab fa-github"></i></a>
                        </div>
                        </div>

                    </div>
                    </body>
                    </html>

                    """, username=pending['username'], login_url=url_for('auth.login', _external=True), current_year=datetime.utcnow().year)

                    send_notification_email(
                        to=pending['email'],
                        subject="Welcome to Digital Time Capsule",
                        html_body=html_body
                    )

                except Exception as e:
                    print("Welcome email failed:", e)

                session.clear()
                flash("✅ Registration successful! Please log in.", "success")
                return redirect(url_for('auth.login'))

            except Exception as e:
                db.session.rollback()
                traceback.print_exc()
                flash("❌ An error occurred during registration. Please try again.", "danger")
                return redirect(url_for('auth.register'))

        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template('auth/verify_otp.html', locked=False)

# ==============================
# LOGIN
# ==============================
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials.", "danger")
            return redirect(url_for('auth.login'))

        latest_failed = OTPAttempt.query.filter_by(
            user_id=user.id, action='login', success=False
        ).order_by(OTPAttempt.timestamp.desc()).first()

        if latest_failed:
            delta = datetime.utcnow() - latest_failed.timestamp
            if delta < LOCKOUT_DURATION:
                failed_count = OTPAttempt.query.filter_by(
                    user_id=user.id, action='login', success=False
                ).filter(OTPAttempt.timestamp > latest_failed.timestamp - LOCKOUT_DURATION).count()

                if failed_count >= MAX_OTP_ATTEMPTS:
                    unlock_time = get_unlock_time(latest_failed.timestamp)
                    flash(f"Too many OTP failures. Try again after {unlock_time} IST.", "danger")
                    return redirect(url_for('auth.login'))

        totp = pyotp.TOTP(user.otp_secret, interval=OTP_VALIDITY)
        otp_code = totp.now()

        try:
            send_otp_email(user.email, otp_code, subject="Login OTP - Digital Time Capsule")
        except Exception:
            flash("Error sending OTP email. Try again later.", "danger")
            return redirect(url_for('auth.login'))

        session.permanent = True
        session['pending_login_user'] = user.id
        session['otp_start_time'] = datetime.utcnow().timestamp()
        flash("OTP sent to your email. Please verify.", "info")
        return redirect(url_for('auth.verify_otp'))

    return render_template("auth/login.html")

# ==============================
# VERIFY LOGIN OTP
# ==============================
@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    user_id = session.get('pending_login_user')
    start_time = session.get('otp_start_time')

    if not user_id or not start_time:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('auth.login'))

    if datetime.utcnow().timestamp() - start_time > SESSION_TIMEOUT:
        session.clear()
        flash("OTP session expired. Please login again.", "warning")
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        if not otp_input:
            flash("OTP is required.", "warning")
            return render_template("auth/verify_otp.html", locked=False)

        totp = pyotp.TOTP(user.otp_secret, interval=OTP_VALIDITY)
        is_valid = totp.verify(otp_input)

        db.session.add(OTPAttempt(
            user_id=user.id,
            capsule_id=None,
            success=is_valid,
            timestamp=datetime.utcnow(),
            ip_address=request.remote_addr,
            action='login'
        ))
        db.session.commit()

        if is_valid:
            session.pop('pending_login_user', None)
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for('main.dashboard'))

        failed_count = OTPAttempt.query.filter_by(
            user_id=user.id, action='login', success=False
        ).filter(OTPAttempt.timestamp > datetime.utcnow() - LOCKOUT_DURATION).count()

        if failed_count >= MAX_OTP_ATTEMPTS:
            unlock_time = get_unlock_time(datetime.utcnow())
            try:
                return render_template('emails/otp_lockout_login.html', unlock_time=unlock_time)
            except:
                html_message = f"""
                <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Account Locked - OTP Attempts Exceeded</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
</head>
<body style="margin: 0; padding: 0; background-color: #f4f6f8; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #2c3e50;">
  <div style="width: 100%; padding: 50px 0; background-color: #f4f6f8;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 0 16px rgba(0, 0, 0, 0.08); border: 1px solid #e0e0e0;">

      <!-- Header -->
      <div style="background: linear-gradient(135deg, #181818, #303030); padding: 30px 40px; text-align: center;">
        <h1 style="margin: 0; font-size: 24px; font-weight: 600; color: #ffffff;">
          <i class="fas fa-user-lock" style="margin-right: 10px;"></i> Account Locked
        </h1>
        <p style="color: #bbbbbb; font-size: 14px; margin: 8px 0 0;">Too Many OTP Attempts</p>
      </div>

      <!-- Body -->
      <div style="padding: 40px 30px; font-size: 15px; background-color: #ffffff;">

        <!-- Greeting -->
        <p style="font-size: 16px; margin-bottom: 20px; color: #2c3e50;">
          <i class="fas fa-user" style="color: #0a1f44; margin-right: 6px;"></i>
          <strong>Dear {{ current_user.username }},</strong>
        </p>

        <!-- Warning Box -->
        <div style="background-color: #fff0f0; border-left: 4px solid #d32f2f; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px;">
          <p style="margin: 0; font-size: 15px; color: #b71c1c;">
            <i class="fas fa-triangle-exclamation" style="margin-right: 8px;"></i>
            Multiple failed OTP attempts have been detected.
          </p>
        </div>

        <!-- Info -->
        <p style="color: #444; margin-bottom: 20px;">
          For your protection, your account has been temporarily locked. You can attempt login again after:
        </p>

        <!-- Unlock Time -->
        <div style="background-color: #f9f9f9; border: 2px dashed #ccc; border-radius: 8px; padding: 20px; text-align: center; max-width: 350px; margin: 0 auto 20px;">
          <div style="font-size: 16px; font-weight: bold; color: #d32f2f; margin-bottom: 6px;">
            <i class="fas fa-clock" style="margin-right: 6px;"></i> Lock Expires
          </div>
          <div style="font-size: 20px; font-weight: bold; color: #0f62fe;">
            {{ unlock_time }} IST
          </div>
        </div>

        <!-- Recommendations -->
        <div style="margin: 30px 0;">
          <p style="margin-bottom: 15px; color: #444;">
            <i class="fas fa-info-circle" style="color: #0f62fe; margin-right: 8px;"></i>
            Please wait until the unlock time before trying to log in again.
          </p>
          <p style="margin-bottom: 15px; color: #444;">
            <i class="fas fa-shield-alt" style="color: #0f62fe; margin-right: 8px;"></i>
            This is a security measure to protect against unauthorized access.
          </p>
          <p style="margin-bottom: 15px; color: #444;">
            <i class="fas fa-ban" style="color: #d32f2f; margin-right: 8px;"></i>
            Any login attempt before the unlock time will be blocked.
          </p>
        </div>

        <!-- Contact Note -->
        <div style="background-color: #f4f6f8; padding: 15px; border-radius: 8px; font-size: 13px; color: #666;">
          <i class="fas fa-headset" style="margin-right: 6px;"></i>
          If this wasn’t you, please contact our support team immediately.
        </div>

      </div>

      <!-- Footer -->
      <div style="background-color: #f0f0f0; padding: 25px 40px; text-align: center; font-size: 13px; color: #888888;">
        <p style="margin: 5px 0;">This is an automated message from <strong style="color: #222;">Digital Time Capsule</strong>.</p>
        <p style="margin: 5px 0;">&copy; {{ current_year }} Digital Time Capsule. All rights reserved.</p>
        <p style="margin: 10px 0 0;">
          <a href="#" style="color: #888; text-decoration: none; margin: 0 8px;">Security Center</a> |
          <a href="#" style="color: #888; text-decoration: none; margin: 0 8px;">Support</a> |
          <a href="#" style="color: #888; text-decoration: none; margin: 0 8px;">Privacy Policy</a>
        </p>
      </div>

    </div>
  </div>
</body>
</html>

                """
                send_notification_email(
                    user.email,
                    "Account Locked - Too Many OTP Attempts",
                    html_message,
               
                )
            session.clear()
            flash(f"Too many failed attempts. Try again after {unlock_time} IST.", "danger")
            return redirect(url_for('auth.login'))

        flash("Invalid OTP. Try again.", "danger")

    return render_template("auth/verify_otp.html", locked=False)


# ==============================
# OTP RESEND (UNLIMITED)
# ==============================
@auth_bp.route('/resend_otp')
def resend_otp():
    try:
        if 'pending_registration' in session:
            data = session['pending_registration']
            totp = pyotp.TOTP(data['otp_secret'], interval=OTP_VALIDITY)
            send_otp_email(data['email'], totp.now(), subject="Digital Time Capsule - Email Verification OTP")
            session['otp_start_time'] = datetime.utcnow().timestamp()
            flash("OTP resent to your email.", "info")
            return redirect(url_for('auth.verify_registration_otp'))

        elif 'pending_login_user' in session:
            user = User.query.get(session['pending_login_user'])
            totp = pyotp.TOTP(user.otp_secret, interval=OTP_VALIDITY)
            send_otp_email(user.email, totp.now(), subject="Login OTP - Digital Time Capsule")
            session['otp_start_time'] = datetime.utcnow().timestamp()
            flash("OTP resent to your email.", "info")
            return redirect(url_for('auth.verify_otp'))

    except Exception:
        flash("Error resending OTP. Try again later.", "danger")

    return redirect(url_for('auth.login'))

# ==============================
# LOGOUT
# ==============================
@auth_bp.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('auth.login'))
