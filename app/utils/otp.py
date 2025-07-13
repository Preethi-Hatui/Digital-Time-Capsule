# app/utils/otp.py

import pyotp
import logging

logger = logging.getLogger(__name__)


def generate_totp(secret: str) -> str:
    """
    Generates a time-based one-time password (TOTP) using the provided base32 secret.

    Args:
        secret (str): The user's base32-encoded OTP secret.

    Returns:
        str: A 6-digit TOTP valid for 30 seconds (by default).

    Raises:
        ValueError: If the secret is invalid or OTP generation fails.
    """
    if not secret or not isinstance(secret, str):
        logger.warning("[OTP] Empty or invalid secret provided.")
        raise ValueError("OTP secret must be a non-empty base32 string.")

    try:
        # You may customize the interval or digits if needed in future
        totp = pyotp.TOTP(secret)
        code = totp.now()
        logger.debug(f"[OTP] Generated OTP: {code}")
        return code

    except Exception as e:
        logger.error(f"[OTP] Error generating OTP: {e}")
        raise ValueError("Failed to generate OTP") from e
