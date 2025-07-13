from flask_mail import Message
from flask import current_app
from app.extensions import mail
from datetime import datetime, timedelta
import pytz

IST = pytz.timezone("Asia/Kolkata")


# ------------------------------
# 🔐 OTP Email Sender (OTP Code Only)
# ------------------------------
def send_otp_email(to_email: str, otp_code: str, subject: str = None) -> bool:
    """
    Sends a styled HTML OTP email with 5-minute expiry time in IST.
    Use this for login and capsule unlocking OTPs.
    """
    try:
        subject = subject or "Your One-Time Password (OTP)"
        sender = (
            current_app.config.get("MAIL_DEFAULT_SENDER")
            or current_app.config.get("MAIL_USERNAME")
            or "no-reply@digitalcapsule.app"
        )

        expiry_utc = datetime.utcnow() + timedelta(minutes=5)
        expiry_ist = expiry_utc.replace(tzinfo=pytz.utc).astimezone(IST).strftime("%Y-%m-%d %I:%M %p IST")

        html = f"""
        <html>
        <head>
            <style>
                @import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css');
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f4f6f8;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 600px;
                    margin: 30px auto;
                    background-color: #ffffff;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                    border: 1px solid #e0e0e0;
                }}
                .header {{
                    background-color: #003366;
                    color: #ffffff;
                    padding: 20px;
                    text-align: center;
                }}
                .header h2 {{
                    margin: 0;
                    font-size: 22px;
                }}
                .content {{
                    padding: 30px;
                    color: #333333;
                }}
                .otp-box {{
                    font-size: 28px;
                    font-weight: bold;
                    letter-spacing: 4px;
                    text-align: center;
                    margin: 25px 0;
                    background: #f8f9fa;
                    padding: 15px;
                    border: 1px dashed #888;
                    border-radius: 8px;
                    color: #d9534f;
                }}
                .expiry {{
                    text-align: center;
                    font-weight: bold;
                    color: #0275d8;
                    font-size: 16px;
                }}
                .footer {{
                    font-size: 13px;
                    color: #888888;
                    padding: 20px;
                    text-align: center;
                    border-top: 1px solid #e0e0e0;
                }}
                @media only screen and (max-width: 600px) {{
                    .content {{
                        padding: 20px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2><i class="fa fa-lock"></i> OTP Verification</h2>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>You or someone using your email requested an OTP for verification. Use the code below:</p>
                    <div class="otp-box">{otp_code}</div>
                    <p class="expiry">Valid until: <strong>{expiry_ist}</strong></p>
                    <p style="margin-top: 30px; color: #666666; font-size: 14px;">
                        If you didn’t request this, please ignore this message.<br>
                        Your data remains secure.
                    </p>
                </div>
                <div class="footer">
                    &copy; {datetime.now().year} Digital Time Capsule. All rights reserved.<br>
                    This is an automated email. Please do not reply.
                </div>
            </div>
        </body>
        </html>
        """

        msg = Message(subject=subject, sender=sender, recipients=[to_email], html=html)
        mail.send(msg)

        current_app.logger.info(f"[send_otp_email] Sent OTP to {to_email}")
        return True

    except Exception as e:
        current_app.logger.error(f"[send_otp_email] Failed to send OTP to {to_email}: {e}")
        return False


# ------------------------------
# 📧 General Notification Email (Custom HTML)
# ------------------------------
def send_notification_email(to: str, subject: str, html_body: str) -> bool:
    """
    Sends a professional HTML email (used for welcome, lockout, unlock alerts).
    Expects fully formatted HTML.
    """
    try:
        sender = (
            current_app.config.get("MAIL_DEFAULT_SENDER")
            or current_app.config.get("MAIL_USERNAME")
            or "no-reply@digitalcapsule.app"
        )

        if "<html" not in html_body.lower():
            html_body = f"""
            <html><body style="font-family: Arial; font-size: 14px; color: #333;">
            <h3>{subject}</h3>
            {html_body}
            <br><br><div style="font-size:12px;color:#888;">— Digital Time Capsule</div>
            </body></html>
            """

        msg = Message(subject=subject, sender=sender, recipients=[to], html=html_body)
        mail.send(msg)

        current_app.logger.info(f"[send_notification_email] Sent to {to} - Subject: {subject}")
        return True

    except Exception as e:
        current_app.logger.error(f"[send_notification_email] Failed to send to {to}: {e}")
        return False
