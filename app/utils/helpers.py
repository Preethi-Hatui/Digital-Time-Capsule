from flask import url_for, current_app
from flask_mail import Message
from app.extensions import mail

def send_verification_email(email: str, token: str) -> bool:
    """
    Sends a verification email with a secure confirmation link.

    Args:
        email (str): Recipient's email.
        token (str): Verification token (usually TOTP).

    Returns:
        bool: True if sent, False otherwise.
    """
    try:
        verification_link = url_for('auth.verify_email', token=token, _external=True)
        sender = (
            current_app.config.get('MAIL_DEFAULT_SENDER')
            or current_app.config.get('MAIL_USERNAME')
            or 'no-reply@digitalcapsule.app'
        )

        subject = "Confirm Your Email – Digital Time Capsule"

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 30px;">
            <div style="max-width: 600px; margin: auto; background-color: #fff; padding: 24px; border: 1px solid #ddd; border-radius: 8px;">
                <h2 style="color: #0275d8; margin-top: 0;">
                    <!-- [FontAwesome icon: envelope] -->
                    Email Verification
                </h2>
                <p>Hello,</p>
                <p>Thank you for signing up for <strong>Digital Time Capsule</strong>.</p>
                <p>Please confirm your email by clicking the button below:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_link}" style="background-color: #0275d8; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Verify Email
                    </a>
                </div>
                <p>This link will expire in <strong>30 minutes</strong>.</p>
                <p>If you didn’t request this, you can safely ignore this email.</p>
                <hr style="margin: 40px 0;">
                <p style="font-size: 0.9em; color: #666;">– The Digital Time Capsule Team</p>
            </div>
        </body>
        </html>
        """

        msg = Message(subject=subject, sender=sender, recipients=[email], html=html)
        mail.send(msg)

        current_app.logger.info(f"[send_verification_email] Verification email sent to {email}")
        return True

    except Exception as e:
        current_app.logger.error(f"[send_verification_email] Failed to send to {email}: {e}")
        return False
