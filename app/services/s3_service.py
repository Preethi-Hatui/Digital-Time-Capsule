import os
from io import BytesIO
from datetime import datetime
from typing import Union, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from werkzeug.utils import secure_filename
from flask import current_app


class S3Service:
    def __init__(self, app):
        """
        Initializes the S3 client with credentials from app config.
        """
        self.s3 = boto3.client(
            's3',
            aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
            region_name=app.config['AWS_REGION']
        )
        self.bucket_name = app.config['AWS_BUCKET_NAME']

    def upload_file(self, file_stream: Union[BytesIO, str], filename: str, user_id: int) -> Optional[str]:
        """
        Uploads a file to AWS S3 under the user's folder with a timestamp-based name.

        Args:
            file_stream: File as BytesIO stream or file path (string).
            filename: Original filename.
            user_id: ID of the user for S3 key namespacing.

        Returns:
            S3 object key (str) on success, None on failure.
        """
        try:
            safe_filename = secure_filename(filename)
            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            s3_key = f"user_{user_id}/{timestamp}_{safe_filename}"

            extra_args = {
                'ContentType': 'application/octet-stream',
                'ACL': 'private'
            }

            if isinstance(file_stream, BytesIO):
                self.s3.upload_fileobj(file_stream, self.bucket_name, s3_key, ExtraArgs=extra_args)
            elif isinstance(file_stream, str) and os.path.exists(file_stream):
                with open(file_stream, 'rb') as f:
                    self.s3.upload_fileobj(f, self.bucket_name, s3_key, ExtraArgs=extra_args)
            else:
                current_app.logger.error("[S3Service] Invalid file stream or path.")
                return None

            return s3_key

        except NoCredentialsError:
            current_app.logger.error("[S3Service] AWS credentials not found. Check your configuration.")
            return None

        except ClientError as e:
            current_app.logger.error(f"[S3Service] Upload failed: {e.response['Error']['Message']}")
            return None

        except Exception as e:
            current_app.logger.error(f"[S3Service] Unexpected upload error: {str(e)}")
            return None

    def download_file(self, s3_key: str) -> Optional[bytes]:
        """
        Downloads a file from S3 using its key.

        Args:
            s3_key: Object key in the S3 bucket.

        Returns:
            File data as bytes on success, None on failure.
        """
        try:
            with BytesIO() as buffer:
                self.s3.download_fileobj(self.bucket_name, s3_key, buffer)
                buffer.seek(0)
                return buffer.read()

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == '404':
                current_app.logger.warning(f"[S3Service] File not found: {s3_key}")
            else:
                current_app.logger.error(f"[S3Service] Download failed: {e.response['Error']['Message']}")
            return None

        except Exception as e:
            current_app.logger.error(f"[S3Service] Unexpected download error: {str(e)}")
            return None

    def delete_file(self, s3_key: str) -> bool:
        """
        Deletes a file from the S3 bucket.

        Args:
            s3_key: Object key to delete.

        Returns:
            True on success, False on failure.
        """
        try:
            self.s3.delete_object(Bucket=self.bucket_name, Key=s3_key)
            return True

        except ClientError as e:
            current_app.logger.error(f"[S3Service] Delete failed: {e.response['Error']['Message']}")
            return False

        except Exception as e:
            current_app.logger.error(f"[S3Service] Unexpected delete error: {str(e)}")
            return False
