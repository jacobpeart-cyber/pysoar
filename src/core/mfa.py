"""
TOTP MFA manager for time-based one-time passwords.
Implements RFC 6238 TOTP with backup codes for account recovery.
"""

import logging
import secrets
import string
from typing import Dict, List, Optional, Tuple

import bcrypt
import pyotp

logger = logging.getLogger(__name__)


class MFAManager:
    """Manages TOTP (Time-based One-Time Password) MFA and backup codes."""

    BACKUP_CODE_LENGTH = 8
    BACKUP_CODE_COUNT = 10

    @staticmethod
    def generate_secret() -> str:
        """
        Generate a base32-encoded secret for TOTP.

        Returns:
            str: Base32-encoded random secret (compatible with authenticator apps)
        """
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(secret: str, email: str, issuer: str = "PySOAR") -> str:
        """
        Generate provisioning URI for QR code generation.

        Args:
            secret: Base32-encoded TOTP secret
            email: User email address (used as account name)
            issuer: Issuer name (default: "PySOAR")

        Returns:
            str: otpauth:// URI suitable for QR code encoding
        """
        if not secret or not email:
            logger.warning("Missing secret or email for provisioning URI")
            return ""

        try:
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name=email, issuer_name=issuer)
            return uri
        except Exception as e:
            logger.error(f"Error generating provisioning URI: {e}")
            return ""

    @staticmethod
    def verify_totp(secret: str, code: str, window: int = 1) -> bool:
        """
        Verify a TOTP code against the secret.

        Args:
            secret: Base32-encoded TOTP secret
            code: 6-digit TOTP code to verify
            window: Time window tolerance in 30-second periods (default: 1)
                    window=1 accepts current and adjacent time windows

        Returns:
            bool: True if code is valid, False otherwise
        """
        if not secret or not code:
            logger.warning("Missing secret or code for TOTP verification")
            return False

        try:
            # Validate code format (should be 6 digits)
            if not code.isdigit() or len(code) != 6:
                logger.warning(f"Invalid TOTP code format: {len(code)} digits")
                return False

            totp = pyotp.TOTP(secret)
            # verify() uses time window to account for clock skew
            is_valid = totp.verify(code, valid_window=window)
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying TOTP: {e}")
            return False

    @staticmethod
    def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> List[str]:
        """
        Generate backup codes for account recovery.

        Args:
            count: Number of codes to generate (default: 10)

        Returns:
            list: List of backup codes in format "XXXX-XXXX" (8 alphanumeric chars)
        """
        if count <= 0:
            logger.warning(f"Invalid backup code count: {count}")
            return []

        try:
            codes = []
            # Use uppercase alphanumeric (excludes ambiguous chars like 0/O, 1/I, l/1)
            charset = string.ascii_uppercase + string.digits
            # Remove ambiguous characters
            charset = charset.replace("0", "").replace("1", "").replace("I", "").replace("L", "").replace("O", "")

            for _ in range(count):
                code = "".join(secrets.choice(charset) for _ in range(MFAManager.BACKUP_CODE_LENGTH))
                codes.append(code)

            logger.info(f"Generated {count} backup codes")
            return codes
        except Exception as e:
            logger.error(f"Error generating backup codes: {e}")
            return []

    @staticmethod
    def hash_backup_codes(codes: List[str]) -> Dict[str, Dict[str, bool]]:
        """
        Hash backup codes using bcrypt for secure storage.

        Args:
            codes: List of plaintext backup codes

        Returns:
            dict: Dictionary mapping code hashes to usage status:
                  {"code_hash_1": {"used": False}, "code_hash_2": {"used": False}, ...}
        """
        if not codes or not isinstance(codes, list):
            logger.warning("Invalid codes list for hashing")
            return {}

        try:
            hashed = {}
            for code in codes:
                if not code:
                    continue
                # Hash with bcrypt (cost=12 for security, suitable for infrequent operations)
                code_hash = bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt(rounds=12))
                # Store as hex string for JSON serialization
                code_hash_hex = code_hash.hex()
                hashed[code_hash_hex] = {"used": False}

            logger.info(f"Hashed {len(hashed)} backup codes")
            return hashed
        except Exception as e:
            logger.error(f"Error hashing backup codes: {e}")
            return {}

    @staticmethod
    def verify_backup_code(code: str, hashed_codes: Dict[str, Dict[str, bool]]) -> Tuple[bool, Optional[str]]:
        """
        Verify a backup code using constant-time comparison.

        Args:
            code: Plaintext backup code to verify
            hashed_codes: Dictionary of hashed codes from hash_backup_codes()

        Returns:
            tuple: (is_valid, code_hash_key)
                - is_valid: True if code matches and hasn't been used
                - code_hash_key: The matching code hash key (for marking as used), or None
        """
        if not code or not hashed_codes:
            logger.warning("Missing code or hashed codes for verification")
            return (False, None)

        try:
            code_bytes = code.encode("utf-8")

            # Iterate through all hashed codes
            for code_hash_hex, metadata in hashed_codes.items():
                # Skip if already used
                if metadata.get("used", False):
                    continue

                try:
                    # Decode hex string back to bytes
                    code_hash_bytes = bytes.fromhex(code_hash_hex)
                    # Use constant-time comparison via bcrypt.checkpw
                    if bcrypt.checkpw(code_bytes, code_hash_bytes):
                        logger.info("Backup code verified successfully")
                        return (True, code_hash_hex)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error processing code hash: {e}")
                    continue

            logger.warning("Backup code verification failed or code already used")
            return (False, None)
        except Exception as e:
            logger.error(f"Error verifying backup code: {e}")
            return (False, None)
