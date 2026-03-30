"""
Password policy validator implementing NIST 800-63B compliance.
Focuses on length requirements and common weakness checks, not complexity rules.
"""

import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Top 20 most commonly used weak passwords (common dictionary attacks)
WEAK_PASSWORDS = {
    "password",
    "123456",
    "password123",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "1234567",
    "letmein",
    "trustno1",
    "dragon",
    "baseball",
    "111111",
    "iloveyou",
    "master",
    "sunshine",
    "ashley",
    "bailey",
    "shadow",
    "123123",
}


class PasswordValidator:
    """NIST 800-63B compliant password validator."""

    MIN_LENGTH = 12  # NIST recommendation for federal systems
    MAX_LENGTH = 128  # Reasonable upper limit

    @staticmethod
    def validate(password: str, settings: dict = None) -> Tuple[bool, List[str]]:
        """
        Validate password against NIST 800-63B requirements.

        Args:
            password: Password string to validate
            settings: Optional dict with config:
                - min_length: Override minimum length (default: 12)
                - max_length: Override maximum length (default: 128)
                - email: User email to check password != email
                - check_common: Whether to check common passwords (default: True)

        Returns:
            tuple: (is_valid, errors)
                - is_valid: True if password meets all requirements
                - errors: List of validation error messages
        """
        if settings is None:
            settings = {}

        errors = []
        min_length = settings.get("min_length", PasswordValidator.MIN_LENGTH)
        max_length = settings.get("max_length", PasswordValidator.MAX_LENGTH)
        email = settings.get("email", None)
        check_common = settings.get("check_common", True)

        if not isinstance(password, str):
            errors.append("Password must be a string")
            return (False, errors)

        if len(password) == 0:
            errors.append("Password cannot be empty")
            return (False, errors)

        # Check minimum length
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters long")

        # Check maximum length
        if len(password) > max_length:
            errors.append(f"Password must not exceed {max_length} characters")

        # Check against common weak passwords (case-insensitive)
        if check_common and password.lower() in WEAK_PASSWORDS:
            errors.append("Password is too commonly used")

        # Check password != email (case-insensitive)
        if email and password.lower() == email.lower():
            errors.append("Password must not match email address")

        is_valid = len(errors) == 0
        return (is_valid, errors)
