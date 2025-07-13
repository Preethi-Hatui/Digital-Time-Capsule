from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, session, send_file
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from app.services import OTPService, S3Service, EncryptionService
from app.models import TimeCapsule
from app.extensions import db, scheduler
from app.utils.decorators import check_otp_attempts
from app.utils.validators import validate_file
from app.utils.email import send_otp_email, send_notification_email
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import os
from io import BytesIO
import pyotp
import qrcode
import uuid
import traceback
import pytz

capsule_bp = Blueprint('capsule', __name__, url_prefix='/capsules')
IST = pytz.timezone('Asia/Kolkata')

from app.models import OTPAttempt  # Make sure this model is defined properly

def log_capsule_otp_attempt(capsule_id, user_id, ip, success, action="delete"):
    try:
        attempt = OTPAttempt(
            capsule_id=capsule_id,
            user_id=user_id,
            ip_address=ip,
            success=success,
            action=action,
            timestamp=datetime.utcnow()
        )
        db.session.add(attempt)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"[OTP Logging Error] Failed to log OTP attempt: {e}")
        db.session.rollback()


def is_valid_base64(s):
    try:
        if not s or len(s) % 4 != 0:
            return False
        base64.b64decode(s)
        return True
    except Exception:
        return False


def unlock_expired_capsules():
    from app import create_app
    app = create_app()
    with app.app_context():
        try:
            now = datetime.now(pytz.utc)
            expired_capsules = TimeCapsule.query.filter(
                TimeCapsule.unlock_datetime <= now,
                TimeCapsule.status == 'locked'
            ).all()

            base_url = app.config.get('BASE_URL', 'http://localhost:5000')  # Fallback if not set

            for capsule in expired_capsules:
                capsule.status = 'unlocked'

                send_notification_email(
                    to=capsule.user.email,
                    subject="Your Time Capsule is Unlocked",
                    html_body=f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                    <meta charset="UTF-8">
                    <title>Capsule Unlocked</title>
                    </head>
                    <body style="margin:0; padding:0; background-color:#f4f4f4; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color:#2c3e50;">
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f4f4f4; padding: 50px 0;">
                        <tr>
                        <td align="center">
                            <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color:#ffffff; border-radius:10px; box-shadow:0 0 12px rgba(0,0,0,0.08); overflow:hidden;">
                            
                            <!-- Header -->
                            <tr>
                                <td bgcolor="#1e1e1e" style="padding: 30px 40px; text-align: center;">
                                <h1 style="margin: 0; color: #ffffff; font-size: 24px;">Digital Time Capsule</h1>
                                <p style="margin: 6px 0 0; color: #aaaaaa; font-size: 14px;">Your Secure Memory Vault</p>
                                </td>
                            </tr>

                            <!-- Body -->
                            <tr>
                                <td style="padding: 40px;">
                                <h2 style="color: #2c3e50; font-size: 20px; margin-top: 0;">Capsule Unlocked</h2>

                                <p style="font-size: 15px; line-height: 1.6;">
                                    Hello <strong>{capsule.user.username}</strong>,
                                </p>

                                <p style="font-size: 15px; line-height: 1.6;">
                                    Your time capsule <strong>"{capsule.capsule_name}"</strong> has reached its unlock time and is now available for viewing.
                                </p>

                                <p style="font-size: 15px; line-height: 1.6;">
                                    Please log in to your dashboard to securely access and manage your capsule contents.
                                </p>

                                <div style="text-align: center; margin: 30px 0;">
                                    <a href="{base_url}/dashboard"
                                    style="background-color: #2980b9; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-size: 15px; display: inline-block;">
                                    Go to Dashboard
                                    </a>
                                </div>

                                <p style="font-size: 14px; color: #555555;">
                                    Need help or have questions? Contact our support team anytime at
                                    <a href="mailto:support@digitaltimecapsule.com" style="color: #2980b9; text-decoration: none;">support@digitaltimecapsule.com</a>.
                                </p>

                                <p style="font-size: 14px; color: #888888; margin-top: 40px;">
                                    — The Digital Time Capsule Team
                                </p>
                                </td>
                            </tr>

                            <!-- Footer -->
                            <tr>
                                <td bgcolor="#f0f0f0" style="text-align: center; padding: 20px 40px; font-size: 12px; color: #999999;">
                                &copy; {datetime.utcnow().year} Digital Time Capsule. All rights reserved.
                                <br>This is an automated message. Please do not reply directly to this email.
                                </td>
                            </tr>

                            </table>
                        </td>
                        </tr>
                    </table>
                    </body>
                    </html>

                    """
                )

            if expired_capsules:
                db.session.commit()
                print(f"{len(expired_capsules)} capsules auto-unlocked at {now} UTC.")
        except Exception as e:
            print(f"[Scheduler Error] {str(e)}")
            db.session.rollback()



def session_authenticated():
    if not current_user.is_authenticated:
        flash('Session expired. Please log in again.', 'warning')
        return False
    return True


@capsule_bp.route('/')
@login_required
def view_capsules():
    if not session_authenticated():
        return redirect(url_for('auth.login'))

    now_utc = datetime.now(pytz.utc)
    capsules = TimeCapsule.query.filter_by(user_id=current_user.id).order_by(TimeCapsule.unlock_datetime).all()

    for capsule in capsules:
        unlock_dt = capsule.unlock_datetime
        if unlock_dt.tzinfo is None:
            unlock_dt = pytz.utc.localize(unlock_dt)
        if unlock_dt <= now_utc and capsule.status != 'unlocked':
            capsule.status = 'unlocked'
        capsule.unlock_time_ist = unlock_dt.astimezone(IST)

    db.session.commit()
    return render_template('capsules/list.html', capsules=capsules, now=datetime.now(IST))


@capsule_bp.route('/create', methods=['GET', 'POST'])
@login_required
@check_otp_attempts()
def create():
    if not session_authenticated():
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        try:
            capsule_name = request.form.get('capsule_name', '').strip()
            description = request.form.get('description', '').strip()
            unlock_date = request.form.get('unlock_date')
            unlock_time = request.form.get('unlock_time')
            file = request.files.get('file')

            if not all([capsule_name, unlock_date, unlock_time, file]):
                flash('Please fill all required fields.', 'danger')
                return redirect(url_for('capsule.create'))

            if len(capsule_name) < 3 or len(capsule_name) > 50:
                flash('Capsule name must be 3 to 50 characters.', 'danger')
                return redirect(url_for('capsule.create'))

            if len(description) > 500:
                flash('Description must be 500 characters or less.', 'danger')
                return redirect(url_for('capsule.create'))

            is_valid_file, msg = validate_file(file)
            if not is_valid_file:
                flash(msg, 'danger')
                return redirect(url_for('capsule.create'))

            ist_now = datetime.now(IST)
            unlock_naive = datetime.strptime(f"{unlock_date} {unlock_time}", "%Y-%m-%d %H:%M")
            unlock_datetime_ist = IST.localize(unlock_naive)

            if unlock_datetime_ist.date() == ist_now.date() and unlock_datetime_ist <= ist_now + timedelta(minutes=2):
                flash('For today, unlock time must be at least 2 minutes in the future.', 'danger')
                return redirect(url_for('capsule.create'))

            if unlock_datetime_ist <= ist_now:
                flash('Unlock time must be in the future.', 'danger')
                return redirect(url_for('capsule.create'))

            unlock_datetime_utc = unlock_datetime_ist.astimezone(pytz.utc)

            temp_folder = current_app.config['TEMP_FOLDER']
            os.makedirs(temp_folder, exist_ok=True)
            temp_filename = f"{uuid.uuid4().hex}_{file.filename}"
            temp_path = os.path.join(temp_folder, temp_filename)
            file.save(temp_path)
            os.chmod(temp_path, 0o600)

            capsule_secret = pyotp.random_base32()
            totp = pyotp.TOTP(capsule_secret)
            capsule_id_str = uuid.uuid4().hex[:12]

            label = f"{capsule_id_str} | {current_user.email} - {capsule_name}"
            provisioning_url = totp.provisioning_uri(name=label, issuer_name="Digital Time Capsule")

            qr = qrcode.QRCode(box_size=6, border=4)
            qr.add_data(provisioning_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            qr_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

            session['pending_capsule'] = {
                'capsule_name': capsule_name,
                'description': description,
                'unlock_datetime': unlock_datetime_utc.isoformat(),
                'temp_path': temp_path,
                'filename': file.filename,
                'capsule_secret': capsule_secret,
                'capsule_id_str': capsule_id_str
            }

            return render_template(
                'capsules/qr_verification.html',
                qr_code=qr_b64,
                unlock_datetime_str=unlock_datetime_ist.strftime('%Y-%m-%d %H:%M'),
                capsule_name=capsule_name
            )

        except Exception:
            current_app.logger.error("Capsule creation error:\n" + traceback.format_exc())
            flash('Unexpected error occurred.', 'danger')

    return render_template('capsules/create.html')


@capsule_bp.route('/confirm', methods=['POST'])
@login_required
@check_otp_attempts()
def confirm():
    if not session_authenticated():
        return redirect(url_for('auth.login'))

    otp = request.form.get('otp')
    if not otp:
        flash('OTP is required.', 'danger')
        return redirect(url_for('capsule.create'))

    data = session.get('pending_capsule')
    if not data:
        flash('Session expired. Please start again.', 'warning')
        return redirect(url_for('capsule.create'))

    capsule_secret = data['capsule_secret']
    totp = pyotp.TOTP(capsule_secret)
    if not totp.verify(otp):
        flash('Invalid OTP. Try again quickly before it expires.', 'danger')
        return redirect(url_for('capsule.create'))

    try:
        unlock_datetime = datetime.fromisoformat(data['unlock_datetime'])
        if unlock_datetime.tzinfo is None:
            unlock_datetime = pytz.utc.localize(unlock_datetime)

        temp_path = data['temp_path']
        filename = data['filename']

        with open(temp_path, 'rb') as f:
            file_data = f.read()

        aes_key = EncryptionService.generate_aes_key()
        encrypted_data, iv = EncryptionService.encrypt_file_aes(file_data, aes_key)

        s3_service = S3Service(current_app)
        file_stream = BytesIO(encrypted_data)
        s3_key = s3_service.upload_file(file_stream, filename, current_user.id)

        public_key = serialization.load_pem_public_key(
            current_app.config['RSA_PUBLIC_KEY'].replace("\\n", "\n").encode(),
            backend=default_backend())
        encrypted_aes_key = EncryptionService.encrypt_aes_key_with_rsa(aes_key, public_key)

        capsule = TimeCapsule(
            user_id=current_user.id,
            capsule_name=data['capsule_name'],
            description=data['description'],
            unlock_datetime=unlock_datetime,
            s3_file_key=s3_key,
            aes_encrypted_key=base64.b64encode(encrypted_aes_key).decode('utf-8'),
            iv=base64.b64encode(iv).decode('utf-8'),
            capsule_otp_secret=capsule_secret,
            capsule_id=data['capsule_id_str'],
            original_filename=filename,
            status='locked',
            is_decrypted=False
        )
        db.session.add(capsule)
        db.session.commit()

        if os.path.exists(temp_path):
            os.remove(temp_path)
        session.pop('pending_capsule', None)

        flash(f'Capsule created successfully! Capsule ID: {capsule.capsule_id}', 'success')
        return redirect(url_for('main.dashboard'))

    except Exception:
        db.session.rollback()
        current_app.logger.error("Capsule confirm failed:\n" + traceback.format_exc())
        flash('Failed to save capsule.', 'danger')
        return redirect(url_for('capsule.create'))


@capsule_bp.route('/<int:capsule_id>', methods=['GET', 'POST'])
@login_required
@check_otp_attempts()
def view_capsule(capsule_id):
    if not session_authenticated():
        return redirect(url_for('auth.login'))

    capsule = TimeCapsule.query.filter_by(id=capsule_id, user_id=current_user.id).first_or_404()
    now_utc = datetime.now(pytz.utc)

    unlock_dt = capsule.unlock_datetime
    if unlock_dt.tzinfo is None:
        unlock_dt = pytz.utc.localize(unlock_dt)
    capsule.unlock_time_ist = unlock_dt.astimezone(IST)

    if capsule.status != 'unlocked' and unlock_dt <= now_utc:
        capsule.status = 'unlocked'
        db.session.commit()

    if capsule.status != 'unlocked':
        flash("This capsule is not yet unlockable. Please wait a little longer.", "warning")
        return redirect(url_for('main.dashboard'))

    if capsule.is_decrypted:
        return render_template('capsules/unlock_view.html', capsule=capsule, unlocked=True)

    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash("OTP is required to unlock.", "danger")
            return render_template('capsules/unlock_view.html', capsule=capsule, unlocked=False)

        totp = pyotp.TOTP(capsule.capsule_otp_secret)
        if not totp.verify(otp):
            flash("Invalid OTP. Please try again quickly.", "danger")
            return render_template('capsules/unlock_view.html', capsule=capsule, unlocked=False)

        try:
            if not is_valid_base64(capsule.aes_encrypted_key):
                flash("Corrupted AES key. Cannot decrypt.", "danger")
                return redirect(url_for('capsule.view_capsule', capsule_id=capsule_id))

            private_key = serialization.load_pem_private_key(
                current_app.config['RSA_PRIVATE_KEY'].replace("\\n", "\n").encode(),
                password=None,
                backend=default_backend()
            )
            aes_key = EncryptionService.decrypt_aes_key_with_rsa(
                base64.b64decode(capsule.aes_encrypted_key), private_key)

            s3_service = S3Service(current_app)
            encrypted_data = s3_service.download_file(capsule.s3_file_key)
            iv = base64.b64decode(capsule.iv)
            decrypted_data = EncryptionService.decrypt_file_aes(encrypted_data, aes_key, iv)

            file_ext = capsule.original_filename.split('.')[-1] if '.' in capsule.original_filename else 'txt'
            upload_folder = os.path.join(current_app.static_folder, 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            temp_path = os.path.join(upload_folder, f"capsule_{capsule.id}.{file_ext}")
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)

            capsule.is_decrypted = True
            db.session.commit()

            preview = None
            if file_ext in ['txt', 'log']:
                try:
                    with open(temp_path, 'r', encoding='utf-8') as f:
                        preview = f.read()
                except Exception:
                    preview = '[Preview unavailable]'

            return render_template('capsules/unlock_view.html',
                                   capsule=capsule,
                                   unlocked=True,
                                   file_extension=file_ext,
                                   preview_path=f"/static/uploads/{os.path.basename(temp_path)}",
                                   preview_content=preview)

        except Exception:
            current_app.logger.error("Unlock failed:\n" + traceback.format_exc())
            flash("Something went wrong while unlocking the file.", "danger")
            return redirect(url_for('capsule.view_capsule', capsule_id=capsule_id))

    return render_template('capsules/unlock_view.html', capsule=capsule, unlocked=False)


@capsule_bp.route('/<int:capsule_id>/delete', methods=['GET', 'POST'])
@login_required
@check_otp_attempts()
def delete(capsule_id):
    if not session_authenticated():
        return redirect(url_for('auth.login'))

    capsule = TimeCapsule.query.filter_by(id=capsule_id, user_id=current_user.id).first_or_404()

    if request.method == 'GET':
        if capsule.status != 'unlocked' or not capsule.is_decrypted:
            flash("You can only delete unlocked and decrypted capsules.", "warning")
            return redirect(url_for('capsule.view_capsules'))

        try:
            capsule.unlock_time_ist = capsule.unlock_datetime.astimezone(IST)
        except Exception:
            capsule.unlock_time_ist = capsule.unlock_datetime

        # Generate deletion OTP
        totp = pyotp.TOTP(capsule.capsule_otp_secret, interval=300)  # 5-minute interval for deletion OTP

        otp_code = totp.now()

        # HTML Email
        html = f"""
        <!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Capsule Deletion Request</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
</head>
<body style="margin:0; padding:0; background-color:#f4f6f8; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color:#2c3e50;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f4f6f8" style="padding: 50px 0;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="border-radius:12px; overflow:hidden; box-shadow:0 0 16px rgba(0,0,0,0.08); border:1px solid #e0e0e0;">

        <!-- Header -->
        <tr>
          <td bgcolor="#1e1e1e" style="padding: 30px 40px; text-align: center;">
            <h1 style="color:#ffffff; font-size:22px; font-weight:600; margin:0;">
              <i class="fas fa-trash-alt" style="color:#ffffff; font-size:20px; margin-right:8px;"></i>Capsule Deletion Request
            </h1>
            <p style="color:#cccccc; font-size:14px; margin:6px 0 0;">Action Required to Continue</p>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding: 40px 30px 20px; font-size:15px; text-align: center; color: #2c3e50;">
            <p style="margin-bottom: 15px;">
              <i class="fas fa-user" style="color:#0a1f44; margin-right:8px;"></i><strong>Dear {current_user.username}</strong>,
            </p>

            <p style="margin-bottom: 15px;">
              <i class="fas fa-info-circle" style="color:#0a1f44; margin-right:8px;"></i>You have initiated a request to permanently delete the following time capsule:
            </p>

            <!-- Info Table -->
            <table cellpadding="0" cellspacing="0" width="100%" style="max-width:500px; margin:25px auto; font-size:15px;">
              <tr>
                <td style="padding: 8px 0; color:#0a1f44; font-weight: bold; text-align:left;">
                  <i class="fas fa-file-alt" style="margin-right:8px;"></i>Capsule Name:
                </td>
                <td style="padding: 8px 0; text-align:right; color:#333;">{capsule.capsule_name}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; color:#0a1f44; font-weight: bold; text-align:left;">
                  <i class="fas fa-fingerprint" style="margin-right:8px;"></i>Capsule ID:
                </td>
                <td style="padding: 8px 0; text-align:right; color:#333;">{capsule.capsule_id}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; color:#0a1f44; font-weight: bold; text-align:left;">
                  <i class="fas fa-clock" style="margin-right:8px;"></i>Scheduled Unlock Time:
                </td>
                <td style="padding: 8px 0; text-align:right; color:#333;">{capsule.unlock_time_ist.strftime('%Y-%m-%d %I:%M %p')}</td>
              </tr>
            </table>

            <p style="margin: 20px 0 10px;">
              <i class="fas fa-key" style="color:#0a1f44; margin-right:8px;"></i>To confirm this deletion, please enter the OTP below:
            </p>

            <!-- OTP Box -->
            <div style="font-size:26px; font-weight:bold; background-color:#f9f9f9; color:#d32f2f; border:2px dashed #ccc; border-radius:8px; padding:18px 30px; margin:25px auto 10px; width: fit-content; letter-spacing:4px;">
              {otp_code}
            </div>

            <div style="color: #0f62fe; font-size: 14px; font-weight: 600; margin-top: 5px;">
                Valid for up to 5 minutes.
            </div>

            <p style="font-size:14px; color:#d32f2f; font-weight:600; margin:18px 0 0;">
              <i class="fas fa-exclamation-triangle" style="color:#d32f2f; margin-right:8px;"></i>This capsule will be <strong>permanently deleted</strong> once the OTP is verified.
            </p>

            <p style="font-size:13px; color:#555; margin-top:14px;">
              <strong>Note:</strong> OTP is valid for approximately 5 minutes. If expired, please reinitiate the deletion request.
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td bgcolor="#f0f0f0" style="padding: 25px 40px; text-align:center; font-size:13px; color:#888888;">
            <p style="margin:0;">This message was sent by <strong style="color:#222;">Digital Time Capsule</strong>. Do not reply directly to this email.</p>
            <p style="margin-top:5px;">&copy; {datetime.now().year} Digital Time Capsule. All rights reserved.</p>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
</body>
</html>


        """

        send_notification_email(
            to=current_user.email,
            subject="OTP for Capsule Deletion",
            html_body=html
        )

        flash("An OTP has been sent to your email to confirm deletion.", "info")
        return render_template('capsules/delete_confirm.html', capsule=capsule)

    # POST: Verify OTP
    otp = request.form.get('otp')
    if not otp:
        flash("OTP is required to confirm deletion.", "danger")
        return render_template('capsules/delete_confirm.html', capsule=capsule)

    totp = pyotp.TOTP(capsule.capsule_otp_secret, interval=300)

    if not totp.verify(otp, valid_window=1):  # Strict 5-minute OTP
        log_capsule_otp_attempt(
            capsule_id=capsule.id,
            user_id=current_user.id,
            success=False,
            ip=request.remote_addr,
            action='delete'
        )
        flash("Invalid OTP. Please try again before it expires.", "danger")
        return render_template('capsules/delete_confirm.html', capsule=capsule)

    # OTP Verified
    log_capsule_otp_attempt(
        capsule_id=capsule.id,
        user_id=current_user.id,
        success=True,
        ip=request.remote_addr,
        action='delete'
    )

    try:
        s3_service = S3Service(current_app)
        s3_service.delete_file(capsule.s3_file_key)

        db.session.delete(capsule)
        db.session.commit()

        flash("Capsule deleted permanently.", "success")
        return redirect(url_for('main.dashboard'))

    except Exception:
        db.session.rollback()
        current_app.logger.error(f"Capsule deletion failed for capsule ID {capsule.capsule_id}:\n" + traceback.format_exc())
        flash("Failed to delete capsule due to an internal error.", "danger")
        return redirect(url_for('capsule.view_capsule', capsule_id=capsule_id))





@capsule_bp.route('/<int:capsule_id>/download')
@login_required
@check_otp_attempts()
def download(capsule_id):
    capsule = TimeCapsule.query.filter_by(id=capsule_id, user_id=current_user.id).first_or_404()

    if not capsule.is_decrypted:
        flash("Please unlock the capsule first.", "warning")
        return redirect(url_for('capsule.view_capsule', capsule_id=capsule_id))

    try:
        ext = capsule.original_filename.split('.')[-1] if '.' in capsule.original_filename else 'txt'
        filename = f"capsule_{capsule.id}.{ext}"
        download_path = os.path.join(current_app.static_folder, 'uploads', filename)

        if os.path.exists(download_path):
            return send_file(download_path, as_attachment=True, download_name=capsule.original_filename)
        else:
            flash("Decrypted file not found. Please unlock again.", "danger")
            return redirect(url_for('capsule.view_capsule', capsule_id=capsule_id))
    except Exception:
        current_app.logger.error("Download failed:\n" + traceback.format_exc())
        flash("Error during file download.", "danger")
        return redirect(url_for('capsule.view_capsule', capsule_id=capsule_id))
