from datetime import datetime
from flask import current_app
from app.models import TimeCapsule
from app.extensions import db
from app.services.s3_service import S3Service
from app.services.encryption_service import EncryptionService
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from io import BytesIO


class CapsuleService:
    @staticmethod
    def create_capsule(user_id, capsule_name, description, unlock_datetime, file):
        """
        Encrypts file, uploads to S3, and stores capsule metadata.
        Returns (success: bool, message: str)
        """
        try:
            s3_service = S3Service(current_app)

            file_data = file.read()
            aes_key = EncryptionService.generate_aes_key()
            encrypted_data, iv = EncryptionService.encrypt_file_aes(file_data, aes_key)

            file_stream = BytesIO(encrypted_data)
            s3_key = s3_service.upload_file(file_stream, file.filename, user_id)
            if not s3_key:
                return False, "Failed to upload file to S3."

            public_key_pem = current_app.config.get('RSA_PUBLIC_KEY')
            if not public_key_pem:
                return False, "RSA public key not configured."

            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            encrypted_aes_key = EncryptionService.encrypt_aes_key_with_rsa(aes_key, public_key)

            capsule = TimeCapsule(
                user_id=user_id,
                capsule_name=capsule_name,
                description=description,
                unlock_datetime=unlock_datetime,
                s3_file_key=s3_key,
                aes_encrypted_key=base64.b64encode(encrypted_aes_key).decode('utf-8'),
                iv=base64.b64encode(iv).decode('utf-8'),
                status='locked',
                is_decrypted=False
            )
            db.session.add(capsule)
            db.session.commit()

            return True, "Capsule created successfully."

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"[CapsuleService] Capsule creation error: {e}")
            return False, "An error occurred while creating the capsule."

    @staticmethod
    def get_user_capsules(user_id):
        """
        Returns all capsules for a user ordered by unlock datetime.
        """
        try:
            return TimeCapsule.query.filter_by(user_id=user_id).order_by(TimeCapsule.unlock_datetime).all()
        except Exception as e:
            current_app.logger.error(f"[CapsuleService] Error fetching user capsules: {e}")
            return []

    @staticmethod
    def unlock_capsule(capsule_id, user_id):
        """
        Unlocks and decrypts capsule if eligible.
        Returns (success: bool, message: str, data: bytes | None)
        """
        try:
            capsule = TimeCapsule.query.filter_by(id=capsule_id, user_id=user_id).first()
            if not capsule:
                return False, "Capsule not found.", None

            if capsule.status == 'unlocked':
                return False, "Capsule already unlocked.", None

            if capsule.unlock_datetime > datetime.utcnow():
                return False, "Capsule is not yet unlockable.", None

            s3_service = S3Service(current_app)
            private_key_pem = current_app.config.get('RSA_PRIVATE_KEY')
            if not private_key_pem:
                return False, "RSA private key not configured.", None

            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )

            encrypted_aes_key = base64.b64decode(capsule.aes_encrypted_key)
            aes_key = EncryptionService.decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

            encrypted_data = s3_service.download_file(capsule.s3_file_key)
            if not encrypted_data:
                return False, "Failed to retrieve file from storage.", None

            iv = base64.b64decode(capsule.iv)
            decrypted_data = EncryptionService.decrypt_file_aes(encrypted_data, aes_key, iv)
            if decrypted_data is None:
                return False, "File decryption failed.", None

            capsule.status = 'unlocked'
            capsule.is_decrypted = True
            db.session.commit()

            return True, "Capsule unlocked successfully.", decrypted_data

        except Exception as e:
            current_app.logger.error(f"[CapsuleService] Unlock error: {e}")
            db.session.rollback()
            return False, "Failed to unlock capsule due to internal error.", None
