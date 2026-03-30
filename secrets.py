"""
Production Secrets Management

Provides abstract secrets backend interface with multiple implementations:
- HashiCorp Vault for enterprise secret management
- AWS Secrets Manager for cloud deployments
- Environment variables for development/testing
- Field-level encryption for credentials at rest
"""

import json
import logging
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class SecretsBackend(ABC):
    """Abstract base class for secrets storage backends"""

    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret by key"""
        pass

    @abstractmethod
    async def set_secret(self, key: str, value: str) -> None:
        """Store a secret"""
        pass

    @abstractmethod
    async def delete_secret(self, key: str) -> None:
        """Delete a secret"""
        pass

    @abstractmethod
    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secret keys, optionally filtered by prefix"""
        pass

    @abstractmethod
    async def rotate_secret(self, key: str, new_value: str) -> None:
        """Rotate a secret to a new value"""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify backend connectivity and health"""
        pass


class VaultBackend(SecretsBackend):
    """HashiCorp Vault integration for secret management"""

    def __init__(
        self,
        vault_addr: str,
        vault_token: Optional[str] = None,
        vault_role_id: Optional[str] = None,
        vault_secret_id: Optional[str] = None,
        vault_namespace: Optional[str] = None,
        kv_mount_path: str = "secret",
    ):
        """
        Initialize Vault backend

        Args:
            vault_addr: Vault server address (e.g., https://vault.example.com:8200)
            vault_token: Token for direct authentication
            vault_role_id: Role ID for AppRole authentication
            vault_secret_id: Secret ID for AppRole authentication
            vault_namespace: Vault namespace (Enterprise only)
            kv_mount_path: Path to KV v2 secrets engine mount (default: secret)
        """
        try:
            import hvac
        except ImportError:
            raise ImportError("hvac library required for Vault backend: pip install hvac")

        self.vault_addr = vault_addr
        self.kv_mount_path = kv_mount_path
        self.namespace = vault_namespace

        # Initialize client
        self.client = hvac.Client(
            url=vault_addr,
            namespace=vault_namespace,
        )

        # Authenticate
        if vault_token:
            self.client.token = vault_token
        elif vault_role_id and vault_secret_id:
            self.authenticate_approle(vault_role_id, vault_secret_id)
        else:
            self.authenticate_kubernetes()

        logger.info(f"Vault backend initialized at {vault_addr}")

    def authenticate_approle(self, role_id: str, secret_id: str) -> None:
        """Authenticate using AppRole method"""
        response = self.client.auth.approle.login(role_id, secret_id)
        self.client.token = response["auth"]["client_token"]
        logger.info("Authenticated to Vault using AppRole")

    def authenticate_kubernetes(self) -> None:
        """Authenticate using Kubernetes service account"""
        import os

        role = os.getenv("VAULT_ROLE", "pysoar")
        jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"

        try:
            with open(jwt_path) as f:
                jwt = f.read()
            response = self.client.auth.kubernetes.login(role, jwt)
            self.client.token = response["auth"]["client_token"]
            logger.info("Authenticated to Vault using Kubernetes")
        except FileNotFoundError:
            logger.warning("Kubernetes JWT not found, using existing token")

    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve secret from Vault KV v2 engine"""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=key,
                mount_point=self.kv_mount_path,
            )
            return response["data"]["data"].get("value")
        except Exception as e:
            logger.error(f"Failed to retrieve secret {key}: {e}")
            return None

    async def set_secret(self, key: str, value: str) -> None:
        """Store secret in Vault KV v2 engine"""
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=key,
                secret_data={"value": value},
                mount_point=self.kv_mount_path,
            )
            logger.info(f"Stored secret {key} in Vault")
        except Exception as e:
            logger.error(f"Failed to store secret {key}: {e}")
            raise

    async def delete_secret(self, key: str) -> None:
        """Delete secret from Vault"""
        try:
            self.client.secrets.kv.v2.delete_secret_version(
                path=key,
                mount_point=self.kv_mount_path,
            )
            logger.info(f"Deleted secret {key} from Vault")
        except Exception as e:
            logger.error(f"Failed to delete secret {key}: {e}")
            raise

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secrets in Vault"""
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path=prefix,
                mount_point=self.kv_mount_path,
            )
            return response.get("data", {}).get("keys", [])
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []

    async def rotate_secret(self, key: str, new_value: str) -> None:
        """Rotate secret with version tracking"""
        try:
            # Read current version
            current = await self.get_secret(key)

            # Store new version
            await self.set_secret(key, new_value)

            logger.info(f"Rotated secret {key}")
        except Exception as e:
            logger.error(f"Failed to rotate secret {key}: {e}")
            raise

    async def health_check(self) -> bool:
        """Check Vault health"""
        try:
            health = self.client.sys.is_initialized()
            return health
        except Exception as e:
            logger.error(f"Vault health check failed: {e}")
            return False


class AWSSecretsBackend(SecretsBackend):
    """AWS Secrets Manager integration"""

    def __init__(
        self,
        region: str = "us-east-1",
        kms_key_id: Optional[str] = None,
    ):
        """
        Initialize AWS Secrets Manager backend

        Args:
            region: AWS region
            kms_key_id: KMS key ID for encryption (optional)
        """
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "boto3 library required for AWS backend: pip install boto3"
            )

        self.region = region
        self.kms_key_id = kms_key_id
        self.client = boto3.client("secretsmanager", region_name=region)

        logger.info(f"AWS Secrets Manager backend initialized in {region}")

    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve secret from AWS Secrets Manager"""
        try:
            response = self.client.get_secret_value(SecretId=key)
            if "SecretString" in response:
                return response["SecretString"]
            else:
                return response["SecretBinary"]
        except Exception as e:
            logger.error(f"Failed to retrieve secret {key}: {e}")
            return None

    async def set_secret(self, key: str, value: str) -> None:
        """Store secret in AWS Secrets Manager"""
        try:
            kwargs = {"SecretId": key, "SecretString": value}
            if self.kms_key_id:
                kwargs["KmsKeyId"] = self.kms_key_id

            # Try to update existing secret
            try:
                self.client.update_secret(**kwargs)
            except self.client.exceptions.ResourceNotFoundException:
                # Create new secret if it doesn't exist
                self.client.create_secret(**kwargs)

            logger.info(f"Stored secret {key} in AWS Secrets Manager")
        except Exception as e:
            logger.error(f"Failed to store secret {key}: {e}")
            raise

    async def delete_secret(self, key: str) -> None:
        """Delete secret from AWS Secrets Manager"""
        try:
            self.client.delete_secret(
                SecretId=key,
                ForceDeleteWithoutRecovery=True,
            )
            logger.info(f"Deleted secret {key} from AWS Secrets Manager")
        except Exception as e:
            logger.error(f"Failed to delete secret {key}: {e}")
            raise

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secrets in AWS Secrets Manager"""
        try:
            secrets = []
            paginator = self.client.get_paginator("list_secrets")

            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    name = secret["Name"]
                    if not prefix or name.startswith(prefix):
                        secrets.append(name)

            return secrets
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []

    async def rotate_secret(self, key: str, new_value: str) -> None:
        """Rotate secret in AWS Secrets Manager"""
        try:
            await self.set_secret(key, new_value)
            logger.info(f"Rotated secret {key}")
        except Exception as e:
            logger.error(f"Failed to rotate secret {key}: {e}")
            raise

    async def health_check(self) -> bool:
        """Check AWS Secrets Manager connectivity"""
        try:
            self.client.list_secrets(MaxResults=1)
            return True
        except Exception as e:
            logger.error(f"AWS Secrets Manager health check failed: {e}")
            return False


class EnvironmentBackend(SecretsBackend):
    """Fallback backend using environment variables and .env files"""

    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize environment backend

        Args:
            env_file: Optional path to .env file to load
        """
        import os
        from dotenv import load_dotenv

        self.env_file = env_file
        self.secrets = {}

        # Load .env file if provided
        if env_file:
            load_dotenv(env_file)
            logger.warning(
                f"Using environment backend with .env file: {env_file}. "
                "NOT RECOMMENDED FOR PRODUCTION."
            )
        else:
            logger.warning(
                "Using environment backend. NOT RECOMMENDED FOR PRODUCTION."
            )

    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve secret from environment variables"""
        import os

        return os.getenv(key)

    async def set_secret(self, key: str, value: str) -> None:
        """Store secret in memory (not persistent)"""
        import os

        os.environ[key] = value
        self.secrets[key] = value
        logger.warning(f"Secret {key} stored in memory only - will be lost on restart")

    async def delete_secret(self, key: str) -> None:
        """Delete secret from environment"""
        import os

        if key in os.environ:
            del os.environ[key]
        if key in self.secrets:
            del self.secrets[key]

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secrets in environment variables"""
        import os

        return [
            key
            for key in os.environ.keys()
            if not prefix or key.startswith(prefix)
        ]

    async def health_check(self) -> bool:
        """Environment backend is always available"""
        return True


class EncryptionService:
    """Field-level encryption service using Fernet symmetric encryption"""

    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize encryption service

        Args:
            master_key: Base64-encoded master key (generated if not provided)
        """
        if master_key:
            self.key = master_key.encode()
        else:
            self.key = Fernet.generate_key()

        self.cipher = Fernet(self.key)
        logger.info("Encryption service initialized")

    def encrypt_field(self, plaintext: str) -> str:
        """Encrypt a single field value"""
        if not plaintext:
            return plaintext

        ciphertext = self.cipher.encrypt(plaintext.encode())
        return ciphertext.decode()

    def decrypt_field(self, ciphertext: str) -> str:
        """Decrypt a single field value"""
        if not ciphertext:
            return ciphertext

        try:
            plaintext = self.cipher.decrypt(ciphertext.encode())
            return plaintext.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt field: {e}")
            raise

    def encrypt_json(self, data: dict) -> str:
        """Encrypt JSON data as a single string"""
        json_str = json.dumps(data)
        return self.encrypt_field(json_str)

    def decrypt_json(self, encrypted: str) -> dict:
        """Decrypt JSON data from encrypted string"""
        json_str = self.decrypt_field(encrypted)
        return json.loads(json_str)

    def rotate_encryption_key(self, old_key: str, new_key: str) -> None:
        """Rotate to a new encryption key"""
        self.key = new_key.encode()
        self.cipher = Fernet(self.key)
        logger.info("Encryption key rotated")

    @staticmethod
    def generate_key() -> str:
        """Generate a new encryption key"""
        return Fernet.generate_key().decode()

    @staticmethod
    def derive_key_from_master(master_key: str, salt: str = "pysoar") -> str:
        """Derive a key from master key using PBKDF2"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        from cryptography.hazmat.backends import default_backend
        import base64

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
            backend=default_backend(),
        )

        derived = kdf.derive(master_key.encode())
        return base64.urlsafe_b64encode(derived).decode()


class SecretsManager:
    """Factory and manager for secrets backends with singleton pattern"""

    _instance = None
    _backend: SecretsBackend = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def initialize(
        cls,
        backend_type: str = "environment",
        **kwargs,
    ) -> None:
        """
        Initialize secrets backend

        Args:
            backend_type: 'vault', 'aws', or 'environment'
            **kwargs: Backend-specific configuration
        """
        if backend_type == "vault":
            cls._backend = VaultBackend(**kwargs)
        elif backend_type == "aws":
            cls._backend = AWSSecretsBackend(**kwargs)
        elif backend_type == "environment":
            cls._backend = EnvironmentBackend(**kwargs)
        else:
            raise ValueError(f"Unknown backend type: {backend_type}")

        logger.info(f"SecretsManager initialized with {backend_type} backend")

    @classmethod
    def get_backend(cls) -> SecretsBackend:
        """Get the active secrets backend"""
        if cls._backend is None:
            cls.initialize()
        return cls._backend

    @classmethod
    async def get_secret(cls, key: str) -> Optional[str]:
        """Retrieve a secret"""
        backend = cls.get_backend()
        return await backend.get_secret(key)

    @classmethod
    async def set_secret(cls, key: str, value: str) -> None:
        """Store a secret"""
        backend = cls.get_backend()
        return await backend.set_secret(key, value)

    @classmethod
    async def delete_secret(cls, key: str) -> None:
        """Delete a secret"""
        backend = cls.get_backend()
        return await backend.delete_secret(key)

    @classmethod
    async def list_secrets(cls, prefix: str = "") -> list[str]:
        """List secrets"""
        backend = cls.get_backend()
        return await backend.list_secrets(prefix)

    @classmethod
    async def rotate_secret(cls, key: str, new_value: str) -> None:
        """Rotate a secret"""
        backend = cls.get_backend()
        return await backend.rotate_secret(key, new_value)

    @classmethod
    async def health_check(cls) -> bool:
        """Check backend health"""
        backend = cls.get_backend()
        return await backend.health_check()


@lru_cache(maxsize=1)
def get_secrets_manager() -> SecretsManager:
    """Dependency injection function for FastAPI"""
    return SecretsManager()
