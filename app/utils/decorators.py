from functools import wraps
from datetime import datetime, timedelta
from flask import flash, redirect, url_for, request, current_app, session
from flask_login import current_user
from flask_mail import Message

from app.extensions import db, mail
from app.models import OTPAttempt
from app.config import Config


def check_otp_attempts(lockout_seconds=None):
    """
    Decorator to check OTP failures and block user after threshold.
    You can optionally override lockout_seconds for different contexts (e.g. 1h vs 24h).
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login', next=request.url))

            try:
                lockout_duration_seconds = lockout_seconds or Config.OTP_LOCKOUT_TIME
                lockout_threshold_time = datetime.utcnow() - timedelta(seconds=lockout_duration_seconds)

                # Count recent failed OTP attempts
                failed_attempts = OTPAttempt.query.filter(
                    OTPAttempt.user_id == current_user.id,
                    OTPAttempt.timestamp > lockout_threshold_time,  # Make sure models.py uses 'timestamp'
                    OTPAttempt.success.is_(False)
                ).count()

                if failed_attempts >= Config.MAX_OTP_ATTEMPTS:
                    if not session.get('lockout_notified'):
                        try:
                            unlock_time = datetime.utcnow() + timedelta(seconds=lockout_duration_seconds)
                            formatted_time = unlock_time.strftime('%Y-%m-%d %H:%M:%S UTC')

                            html_body = f"""
                            <div style="font-family:Arial, sans-serif; max-width:600px; margin:auto; border:1px solid #ddd; padding:20px;">
                                <h2 style="color:#d9534f;">Account Locked</h2>
                                <p>Hi <strong>{current_user.username}</strong>,</p>
                                <p>Your account has been temporarily locked due to <strong>{failed_attempts} failed OTP attempts</strong>.</p>
                                <p>You can try again after:</p>
                                <div style="margin:20px 0; font-size:18px; font-weight:bold; color:#333;">
                                    <i class="fa fa-clock-o" style="margin-right:8px;"></i>{formatted_time}
                                </div>
                                <p>If this wasn't you, please contact our support team immediately.</p>
                                <p style="margin-top:30px;">– Digital Time Capsule Team</p>
                            </div>
                            """

                            msg = Message(
                                subject="Account Locked Due to OTP Failures",
                                sender=current_app.config['MAIL_DEFAULT_SENDER'],
                                recipients=[current_user.email],
                                html=html_body
                            )
                            mail.send(msg)
                            session['lockout_notified'] = True

                        except Exception as e:
                            current_app.logger.error(f"[check_otp_attempts] Email send failure: {e}")

                    minutes = lockout_duration_seconds // 60
                    flash(f'Too many failed OTP attempts. Please try again in {minutes} minute(s).', 'danger')
                    return redirect(url_for('main.dashboard'))

            except Exception as e:
                current_app.logger.error(f"[check_otp_attempts] Unexpected error: {e}")
                flash('OTP validation error. Please try again.', 'warning')
                return redirect(url_for('auth.login'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator
