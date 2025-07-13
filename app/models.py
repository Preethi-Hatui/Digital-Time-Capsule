from datetime import datetime
from app.extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# =============================
# 👤 User Model
# =============================
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)

    # OTP & Verification
    otp_secret = db.Column(db.String(32), nullable=False)
    otp_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)

    # Flags & Controls
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    # Lockouts
    login_locked_until = db.Column(db.DateTime, nullable=True)
    capsule_locked_until = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    capsules = db.relationship(
        'TimeCapsule',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan'
    )

    otp_attempts = db.relationship(
        'OTPAttempt',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan'
    )

    # 🔐 Password Utilities
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

    def __str__(self):
        return self.username


# =============================
# ⏳ Time Capsule Model
# =============================
class TimeCapsule(db.Model):
    __tablename__ = 'time_capsules'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False
    )

    capsule_name = db.Column(db.String(100), nullable=False)
    capsule_id = db.Column(db.String(20), unique=True, nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    unlock_datetime = db.Column(db.DateTime, nullable=False)

    # Encrypted Storage
    s3_file_key = db.Column(db.String(255), nullable=False)
    aes_encrypted_key = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)
    capsule_otp_secret = db.Column(db.String(32), nullable=False)

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='locked')
    is_decrypted = db.Column(db.Boolean, default=False)

    otp_attempts = db.relationship(
        'OTPAttempt',
        backref='capsule',
        lazy=True,
        cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f"<Capsule #{self.id} - {self.capsule_name} by User {self.user_id}>"

    def __str__(self):
        return self.capsule_name

    def qr_string(self, user_email: str) -> str:
        return f"{user_email}|{self.capsule_name}|{self.id}|{self.unlock_datetime.isoformat()}"


# =============================
# 🔐 OTP Attempt Model
# =============================
class OTPAttempt(db.Model):
    __tablename__ = 'otp_attempts'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False
    )

    capsule_id = db.Column(
        db.Integer,
        db.ForeignKey('time_capsules.id', ondelete='CASCADE'),
        nullable=True
    )

    action = db.Column(db.String(50), nullable=False)  # 'login', 'unlock', 'delete', etc.

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    def __repr__(self):
        return (
            f"<OTPAttempt user_id={self.user_id}, capsule_id={self.capsule_id}, "
            f"success={self.success}, action={self.action}>"
        )
