# app/utils/s3.py

import os
import boto3
from flask import current_app
from botocore.exceptions import ClientError, NoCredentialsError


def get_s3_client():
    """
    Create and return a configured AWS S3 client using environment variables.

    Returns:
        boto3.client: A Boto3 S3 client instance.
    """
    try:
        return boto3.client(
            's3',
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_REGION")
        )
    except Exception as e:
        current_app.logger.error(f"[get_s3_client] Failed to create S3 client: {e}")
        return None


def upload_to_s3(file_path: str, s3_key: str) -> bool:
    """
    Upload a local file to AWS S3.

    Args:
        file_path (str): Local file path.
        s3_key (str): Target S3 key (e.g. 'user123/capsule.txt').

    Returns:
        bool: True if upload is successful, False otherwise.
    """
    if not os.path.isfile(file_path):
        current_app.logger.warning(f"[upload_to_s3] File not found: {file_path}")
        return False

    s3_client = get_s3_client()
    if not s3_client:
        return False

    try:
        bucket_name = (
            current_app.config.get("S3_BUCKET")
            or os.getenv("AWS_BUCKET_NAME")
        )
        s3_client.upload_file(file_path, bucket_name, s3_key)
        current_app.logger.info(f"[upload_to_s3] Uploaded {file_path} to bucket '{bucket_name}' as '{s3_key}'")
        return True

    except NoCredentialsError:
        current_app.logger.error("[upload_to_s3] AWS credentials not found.")
    except ClientError as e:
        current_app.logger.error(f"[upload_to_s3] S3 ClientError: {e.response['Error'].get('Message', str(e))}")
    except Exception as e:
        current_app.logger.error(f"[upload_to_s3] Unexpected error: {e}")
    return False


def download_from_s3(s3_key: str, local_path: str) -> bool:
    """
    Download a file from AWS S3 and save it locally.

    Args:
        s3_key (str): S3 object key.
        local_path (str): Destination path on local filesystem.

    Returns:
        bool: True if download succeeds, False otherwise.
    """
    s3_client = get_s3_client()
    if not s3_client:
        return False

    try:
        bucket_name = (
            current_app.config.get("S3_BUCKET")
            or os.getenv("AWS_BUCKET_NAME")
        )
        s3_client.download_file(bucket_name, s3_key, local_path)
        current_app.logger.info(f"[download_from_s3] Downloaded '{s3_key}' to '{local_path}'")
        return True

    except NoCredentialsError:
        current_app.logger.error("[download_from_s3] AWS credentials not found.")
    except ClientError as e:
        current_app.logger.error(f"[download_from_s3] S3 ClientError: {e.response['Error'].get('Message', str(e))}")
    except Exception as e:
        current_app.logger.error(f"[download_from_s3] Unexpected error: {e}")
    return False
