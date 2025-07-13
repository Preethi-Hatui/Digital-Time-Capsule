import base64
import pyotp
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
from flask import current_app
from flask_mail import Message
from app.models import User, OTPAttempt
from app.extensions import db, mail
from typing import Optional, Tuple


class OTPService:
    @staticmethod
    def generate_otp_secret() -> str:
        """
        Generates a base32 OTP secret for TOTP-based authentication.
        """
        return pyotp.random_base32()

    @staticmethod
    def get_otp_uri(label: str, secret: str) -> str:
        """
        Returns a provisioning URI for Google Authenticator.
        """
        issuer = current_app.config.get("OTP_ISSUER_NAME", "Digital Time Capsule")
        return pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)

    @staticmethod
    def generate_qr_code(otp_uri: str) -> str:
        """
        Returns base64-encoded PNG QR code for TOTP URI.
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode("utf-8")

    @staticmethod
    def verify_otp(user_id: int, otp_input: str, ip_address: Optional[str] = None) -> Tuple[bool, str]:
        """
        Verifies user's login OTP and handles lockout logic.
        """
        from app.services.auth_service import AuthService

        user = User.query.get(user_id)
        if not user:
            return False, "User not found."

        if not user.otp_secret:
            return False, "No OTP secret found for this user."

        if not AuthService.can_attempt_otp(user_id):
            OTPService._send_lockout_email(user)
            return False, "Too many failed OTP attempts. Try again later."

        try:
            otp_input = otp_input.strip()
            totp = pyotp.TOTP(user.otp_secret, interval=300)  # OTP valid for 5 minutes

            valid_window = current_app.config.get("OTP_VALID_WINDOW", 1)
            is_valid = totp.verify(otp_input, valid_window=valid_window)

            AuthService.record_otp_attempt(user_id, success=is_valid, ip=ip_address)

            if is_valid:
                current_app.logger.info(f"[OTPService] OTP verified for user {user.email}")
                return True, "OTP verified successfully."
            else:
                current_app.logger.warning(f"[OTPService] Invalid OTP for user {user.email}")
                return False, "Invalid OTP code."

        except Exception as e:
            current_app.logger.error(f"[OTPService] OTP verification error for user {user.email}: {e}")
            return False, "An error occurred during OTP verification."

    @staticmethod
    def verify_capsule_otp(secret: str, otp_input: str) -> Tuple[bool, str]:
        """
        Verifies capsule-specific OTP (not tied to login).
        """
        try:
            otp_input = otp_input.strip()
            totp = pyotp.TOTP(secret, interval=300)  # 300 seconds = 5 minutes

            valid_window = current_app.config.get("OTP_VALID_WINDOW", 1)
            is_valid = totp.verify(otp_input, valid_window=valid_window)

            if is_valid:
                return True, "OTP verified successfully."
            return False, "Invalid OTP code."

        except Exception as e:
            current_app.logger.error(f"[OTPService] Capsule OTP verification error: {e}")
            return False, "An error occurred during OTP verification."

    @staticmethod
    def _send_lockout_email(user: User) -> None:
        """
        Sends an email to the user when their account is locked due to OTP failures.
        """
        try:
            lockout_seconds = current_app.config.get("OTP_LOCKOUT_TIME", 3600)
            unlock_time = datetime.utcnow() + timedelta(seconds=lockout_seconds)
            formatted_unlock = unlock_time.strftime('%Y-%m-%d %H:%M:%S UTC')

            html_body = f"""
            <html>
            <head>
                <style>
                    @import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css');
                </style>
            </head>
            <body style="font-family:Arial, sans-serif; background:#f9f9f9; color:#333;">
                <div style="max-width:600px; margin:auto; background:white; border:1px solid #ddd; padding:20px;">
                    <h2 style="color:#d9534f;">
                        <i class="fa fa-lock"></i> Account Locked
                    </h2>
                    <p>Hi <strong>{user.username}</strong>,</p>
                    <p>Your account has been temporarily locked due to <strong>too many failed OTP attempts</strong>.</p>
                    <p>You may try again after:</p>
                    <div style="margin:20px 0; font-size:18px; font-weight:bold;">
                        <i class="fa fa-clock" style="margin-right:8px;"></i>{formatted_unlock}
                    </div>
                    <p>If this wasn't you, please change your password and review your activity.</p>
                    <hr style="margin-top:30px;">
                    <p style="font-size:0.9em; color:#999;">– Digital Time Capsule Team</p>
                </div>
            </body>
            </html>
            """

            msg = Message(
                subject="Account Locked: Too Many OTP Attempts",
                recipients=[user.email],
                sender=current_app.config.get("MAIL_DEFAULT_SENDER", "noreply@digitalcapsule.app"),
                html=html_body
            )
            mail.send(msg)
            current_app.logger.info(f"[OTPService] Lockout email sent to {user.email}")

        except Exception as e:
            current_app.logger.error(f"[OTPService] Failed to send lockout email to {user.email}: {e}")
