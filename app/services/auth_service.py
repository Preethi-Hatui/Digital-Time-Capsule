from datetime import datetime, timedelta
from flask import current_app, url_for
from flask_mail import Message
from app.extensions import db, bcrypt, mail
from app.models import User, OTPAttempt
import pyotp
import pytz

IST = pytz.timezone("Asia/Kolkata")


class AuthService:
    @staticmethod
    def register_user(username: str, email: str, password: str) -> tuple[bool, str]:
        """
        Registers a new user with hashed password and TOTP secret.
        """
        try:
            if User.query.filter_by(email=email).first():
                return False, "This email is already registered."

            if User.query.filter_by(username=username).first():
                return False, "This username is already taken."

            otp_secret = pyotp.random_base32()
            password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

            new_user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                email_verified=False,
                otp_secret=otp_secret
            )

            db.session.add(new_user)
            db.session.commit()

            if not AuthService.send_verification_email(new_user):
                return True, "Registered, but verification email could not be sent."

            return True, "Registration successful. Please verify your email."

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"[AuthService] Registration error: {e}")
            return False, "Registration failed. Please try again."

    @staticmethod
    def send_verification_email(user: User) -> bool:
        """
        Sends a TOTP-based short-lived email verification link with HTML formatting.
        """
        try:
            totp = pyotp.TOTP(user.otp_secret, interval=300)  # 5 min validity
            token = totp.now()

            verify_url = url_for("auth.verify_email", token=token, _external=True)
            sender = current_app.config.get("MAIL_DEFAULT_SENDER", "noreply@example.com")

            html_body = f"""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <h3 style="color:#333;">Welcome to <strong>Digital Time Capsule</strong>, {user.username}!</h3>
                    <p>Please click the button below to verify your email address:</p>
                    <p style="text-align:center;">
                        <a href="{verify_url}" style="padding:10px 20px; background-color:#007bff; color:white; text-decoration:none; border-radius:5px;">Verify Email</a>
                    </p>
                    <p>This link is valid for 5 minutes.</p>
                    <hr>
                    <p style="font-size:12px;color:#888;">If you did not request this, you can safely ignore this email.</p>
                </body>
            </html>
            """

            msg = Message(
                subject="Verify Your Email - Digital Time Capsule",
                sender=sender,
                recipients=[user.email],
                html=html_body
            )
            mail.send(msg)
            return True

        except Exception as e:
            current_app.logger.error(f"[AuthService] Verification email send failed: {e}")
            return False

    @staticmethod
    def login_user(email: str, password: str) -> tuple[User | None, str]:
        """
        Verifies credentials and checks if email is verified.
        """
        try:
            user = User.query.filter_by(email=email).first()
            if not user:
                return None, "Invalid email or password."

            if not bcrypt.check_password_hash(user.password_hash, password):
                return None, "Invalid email or password."

            if not user.email_verified:
                return None, "Please verify your email before logging in."

            user.last_login = datetime.utcnow()
            db.session.commit()

            return user, "Login successful."

        except Exception as e:
            current_app.logger.error(f"[AuthService] Login error: {e}")
            return None, "Login failed. Please try again later."

    @staticmethod
    def can_attempt_otp(user_id: int) -> tuple[bool, str | None]:
        """
        Determines if the user can attempt OTP based on failure count and lockout duration.
        Returns (allowed: bool, retry_message: str | None)
        """
        try:
            max_attempts = current_app.config.get("MAX_OTP_ATTEMPTS", 3)
            lockout_duration = current_app.config.get("OTP_LOCKOUT_TIME", 3600)

            now = datetime.utcnow()
            cutoff = now - timedelta(seconds=lockout_duration)

            recent_attempts = OTPAttempt.query.filter(
                OTPAttempt.user_id == user_id,
                OTPAttempt.attempt_time > cutoff
            ).order_by(OTPAttempt.attempt_time.desc()).limit(max_attempts).all()

            failed_count = sum(1 for attempt in recent_attempts if not attempt.success)
            if failed_count >= max_attempts:
                last_attempt = recent_attempts[0].attempt_time
                retry_at_ist = last_attempt.replace(tzinfo=pytz.utc).astimezone(IST) + timedelta(seconds=lockout_duration)
                retry_str = retry_at_ist.strftime('%I:%M %p IST')
                return False, f"You've exceeded OTP attempts. Please try again at {retry_str}."

            return True, None

        except Exception as e:
            current_app.logger.error(f"[AuthService] OTP attempt check failed: {e}")
            return False, "Unable to verify OTP status. Try again later."

    @staticmethod
    def record_otp_attempt(user_id: int, success: bool, ip: str = None) -> bool:
        """
        Records an OTP attempt (success/failure) with IP and timestamp.
        """
        try:
            attempt = OTPAttempt(
                user_id=user_id,
                success=success,
                ip_address=ip,
                attempt_time=datetime.utcnow()
            )
            db.session.add(attempt)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"[AuthService] Failed to record OTP attempt: {e}")
            return False
