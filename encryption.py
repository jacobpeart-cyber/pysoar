"""
SQLAlchemy custom types for field-level encryption

Provides EncryptedType and EncryptedJSON for transparent encryption/decryption
of database columns at the ORM level.
"""

import json
import logging
from typing import Any, Optional

from sqlalchemy import String, Text, TypeDecorator
from sqlalchemy.engine import Dialect

from src.core.secrets import EncryptionService

logger = logging.getLogger(__name__)


# Global encryption service instance
_encryption_service: Optional[EncryptionService] = None


def init_encryption(master_key: Optional[str] = None) -> EncryptionService:
    """Initialize the global encryption service"""
    global _encryption_service
    _encryption_service = EncryptionService(master_key=master_key)
    return _encryption_service


def get_encryption_service() -> EncryptionService:
    """Get or initialize encryption service"""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service


class EncryptedType(TypeDecorator):
    """
    SQLAlchemy type that encrypts strings before storage and decrypts on retrieval

    Usage in models:
        from src.core.encryption import EncryptedType

        class APICredential(Base):
            __tablename__ = "api_credentials"

            id = Column(String, primary_key=True)
            api_key = Column(EncryptedType, nullable=False)
            api_secret = Column(EncryptedType, nullable=False)
    """

    impl = String
    cache_ok = True

    def __init__(self, length: int = 255):
        """Initialize encrypted type"""
        super().__init__(length=length)
        self.length = length

    def process_bind_param(
        self,
        value: Optional[str],
        dialect: Dialect,
    ) -> Optional[str]:
        """Encrypt value before storing in database"""
        if value is None:
            return None

        try:
            encryption_service = get_encryption_service()
            encrypted = encryption_service.encrypt_field(value)
            logger.debug(f"Encrypted field of length {len(value)} -> {len(encrypted)}")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def process_result_value(
        self,
        value: Optional[str],
        dialect: Dialect,
    ) -> Optional[str]:
        """Decrypt value retrieved from database"""
        if value is None:
            return None

        try:
            encryption_service = get_encryption_service()
            decrypted = encryption_service.decrypt_field(value)
            logger.debug(f"Decrypted field of length {len(value)} -> {len(decrypted)}")
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def copy(self, **kw):
        """Create a copy of this type"""
        return EncryptedType(length=self.length)


class EncryptedJSON(TypeDecorator):
    """
    SQLAlchemy type that encrypts JSON data before storage and decrypts on retrieval

    Usage in models:
        from src.core.encryption import EncryptedJSON

        class Integration(Base):
            __tablename__ = "integrations"

            id = Column(String, primary_key=True)
            credentials = Column(EncryptedJSON, nullable=False)  # Stored as encrypted JSON
    """

    impl = Text
    cache_ok = True

    def process_bind_param(
        self,
        value: Optional[Any],
        dialect: Dialect,
    ) -> Optional[str]:
        """Serialize to JSON, encrypt, and store"""
        if value is None:
            return None

        try:
            encryption_service = get_encryption_service()
            encrypted = encryption_service.encrypt_json(value)
            logger.debug(f"Encrypted JSON field")
            return encrypted
        except Exception as e:
            logger.error(f"JSON encryption failed: {e}")
            raise

    def process_result_value(
        self,
        value: Optional[str],
        dialect: Dialect,
    ) -> Optional[dict]:
        """Decrypt and deserialize JSON"""
        if value is None:
            return None

        try:
            encryption_service = get_encryption_service()
            decrypted = encryption_service.decrypt_json(value)
            logger.debug(f"Decrypted JSON field")
            return decrypted
        except Exception as e:
            logger.error(f"JSON decryption failed: {e}")
            raise

    def copy(self, **kw):
        """Create a copy of this type"""
        return EncryptedJSON()


def generate_data_key() -> str:
    """Generate a new data encryption key"""
    return EncryptionService.generate_key()


def derive_key_from_master(master_key: str, salt: str = "pysoar") -> str:
    """Derive a key from master key"""
    return EncryptionService.derive_key_from_master(master_key, salt)
