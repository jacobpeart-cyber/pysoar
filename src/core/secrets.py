"""
Production Secrets Management

Provides abstract secrets backend interface with multiple implementations:
- HashiCorp Vault for enterprise secret management
- AWS Secrets Manager for cloud deployments
- Environment variables for development/testing
- Field-level encryption for credentials at rest
"""

import base64
import json
import logging
import os
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any, Dict, Optional

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

# Environments where EncryptionService() may fall back to a generated key.
_THROWAWAY_KEY_ENVS: frozenset[str] = frozenset({"development", "test"})


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
    """Field-level encryption service using AES-256-GCM symmetric encryption"""

    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize encryption service

        Args:
            master_key: Base64-encoded master key (generated if not provided)
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if master_key:
            # Decode the base64 master key
            self.master_key = base64.b64decode(master_key.encode())
            if len(self.master_key) != 32:
                raise ValueError("Master key must be 32 bytes when decoded")
        else:
            # Design v2 section 10: a throwaway key is a development/test
            # convenience only. In every other context (production,
            # staging, migrations) refusing is the honest behaviour --
            # anything encrypted under a random key is unreadable after
            # the next restart.
            from src.core.config import settings

            if settings.app_env not in _THROWAWAY_KEY_ENVS:
                raise RuntimeError(
                    "EncryptionService requires ENCRYPTION_MASTER_KEY when "
                    f"APP_ENV={settings.app_env!r}; a generated key is only "
                    "permitted for development/test",
                )
            logger.warning(
                "ENCRYPTION_MASTER_KEY is unset: using a THROWAWAY random key "
                "(APP_ENV=%s). Every secret encrypted in this process becomes "
                "unreadable after restart. Never run this way outside dev/test.",
                settings.app_env,
            )
            self.master_key = os.urandom(32)

        self.AESGCM = AESGCM
        logger.info("Encryption service initialized with AES-256-GCM")

    def encrypt_field(self, plaintext: str) -> str:
        """Encrypt a single field value using AES-256-GCM"""
        if not plaintext:
            return plaintext

        # Generate random salt and nonce
        salt = os.urandom(16)  # 128-bit salt
        nonce = os.urandom(12)  # 12-byte nonce for GCM

        # Derive key from master key using PBKDF2
        key = self._derive_key_from_master(self.master_key, salt)

        # Encrypt with AES-256-GCM
        cipher = self.AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)

        # Combine salt + nonce + ciphertext + tag and encode
        combined = salt + nonce + ciphertext
        return base64.b64encode(combined).decode()

    def decrypt_field(self, ciphertext_b64: str) -> str:
        """Decrypt a single field value using AES-256-GCM"""
        if not ciphertext_b64:
            return ciphertext_b64

        try:
            # Decode from base64
            combined = base64.b64decode(ciphertext_b64.encode())

            # Extract components
            salt = combined[:16]  # 128-bit salt
            nonce = combined[16:28]  # 12-byte nonce
            ciphertext_and_tag = combined[28:]  # Ciphertext with tag

            # Derive key from master key
            key = self._derive_key_from_master(self.master_key, salt)

            # Decrypt with AES-256-GCM
            cipher = self.AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext_and_tag, None)

            return plaintext.decode()
        except Exception as e:
            raise ValueError(f"Failed to decrypt field: {e}")

    def encrypt_json(self, data: dict) -> str:
        """Encrypt JSON data as a single string"""
        json_str = json.dumps(data)
        return self.encrypt_field(json_str)

    def decrypt_json(self, encrypted: str) -> dict:
        """Decrypt JSON data from encrypted string"""
        json_str = self.decrypt_field(encrypted)
        return json.loads(json_str)

    def rotate_encryption_key(self, old_key: str) -> "EncryptionService":
        """Rotate to a new encryption key"""
        if old_key != base64.b64encode(self.master_key).decode():
            raise ValueError("Old key does not match current key")

        new_service = EncryptionService()
        logger.info("Encryption key rotated - new service created")
        return new_service

    @staticmethod
    def generate_key() -> str:
        """Generate a new encryption key"""
        key = os.urandom(32)
        return base64.b64encode(key).decode()

    @staticmethod
    def derive_key_from_master(master_key: str) -> str:
        """Derive a key from master key using PBKDF2"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend

        # Generate random salt
        salt = os.urandom(16)  # 128-bit salt

        # Decode master key
        master_key_bytes = base64.b64decode(master_key.encode())

        # Derive key with PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend(),
        )

        derived = kdf.derive(master_key_bytes)
        return base64.b64encode(derived).decode()

    @staticmethod
    def _derive_key_from_master(master_key_bytes: bytes, salt: bytes) -> bytes:
        """Derive a key from master key bytes using PBKDF2 with given salt"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend(),
        )

        return kdf.derive(master_key_bytes)


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


# ---------------------------------------------------------------------------
# Versioned secret envelope (design v2 §10)
#
# ``enc:v1:<b64>`` wraps the AES-256-GCM ciphertext produced by
# ``EncryptionService.encrypt_field`` so a reader can tell an encrypted secret
# from legacy plaintext without guessing. ``decrypt_secret_json`` never falls
# back to plaintext: an un-enveloped or undecryptable value raises
# ``SecretUnreadable`` so the caller surfaces an honest failure instead of
# silently using ``{}``.
# ---------------------------------------------------------------------------

SECRET_ENVELOPE_PREFIX = "enc:v1:"

# JSON keys inside ``app_settings.value`` (and any other JSON credential blob)
# whose values are secrets. Only these keys are enveloped by migration 020 and
# by the settings write paths; everything else stays readable plaintext.
SECRET_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "api_secret",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "bearer_token",
        "password",
        "passphrase",
        "private_key",
        "webhook_secret",
        "signing_secret",
        "slack_webhook_url",
        "teams_webhook_url",
        "webhook_url",
    }
)


class SecretUnreadable(Exception):
    """A stored secret cannot be read under the current master key.

    ``reason`` is one of ``not_enveloped`` (value is not an ``enc:v1:`` blob),
    ``decrypt_failed`` (wrong key or corrupted ciphertext), ``no_master_key``
    (no encryption service is configured) or ``invalid_json`` (the plaintext
    is not JSON).
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"secret_unreadable:{reason}" + (f" ({detail})" if detail else ""))


def is_enveloped(value: Any) -> bool:
    """True when ``value`` is an ``enc:v1:`` envelope string."""
    return isinstance(value, str) and value.startswith(SECRET_ENVELOPE_PREFIX)


def _resolve_service(service: Optional[EncryptionService]) -> EncryptionService:
    if service is not None:
        return service
    # Imported lazily: src.core.encryption imports this module.
    from src.core.config import settings
    from src.core.encryption import get_encryption_service

    if not settings.encryption_master_key and settings.app_env not in _THROWAWAY_KEY_ENVS:
        raise SecretUnreadable("no_master_key", "settings.encryption_master_key is unset")
    # In development/test EncryptionService() logs loudly and uses a
    # throwaway key; everywhere else the line above has already refused.
    return get_encryption_service()


def encrypt_secret_json(payload: Any, *, service: Optional[EncryptionService] = None) -> str:
    """Serialize ``payload`` to canonical JSON, encrypt it and return an ``enc:v1:`` envelope.

    ``service`` defaults to the process-wide ``EncryptionService`` initialised
    from ``settings.encryption_master_key``; pass one explicitly in migrations
    so the key used is the one being verified.
    """
    svc = _resolve_service(service)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return SECRET_ENVELOPE_PREFIX + svc.encrypt_field(raw)


def decrypt_secret_json(
    value: Optional[str],
    *,
    service: Optional[EncryptionService] = None,
    required: bool = True,
) -> Any:
    """Open an ``enc:v1:`` envelope and return the JSON payload it holds.

    With ``required=True`` (the default, used for the ``ai`` and
    ``integration:*`` sections) this raises ``SecretUnreadable`` -- never a
    fallback -- when the value is not enveloped, cannot be decrypted under the
    current key, or is not JSON.

    With ``required=False`` the pre-envelope shapes are still accepted for
    rows migration 020 has not rewritten yet (``__plaintext__:`` marker, raw
    legacy ciphertext, plain JSON) and any failure returns ``{}``. Callers
    that read credentials for an outbound call must use ``required=True``.
    """
    if not is_enveloped(value):
        if required:
            raise SecretUnreadable("not_enveloped")
        return _decrypt_legacy_shape(value)
    assert isinstance(value, str)
    ciphertext = value[len(SECRET_ENVELOPE_PREFIX):]
    try:
        svc = _resolve_service(service)
        plaintext = svc.decrypt_field(ciphertext)
    except SecretUnreadable:
        if required:
            raise
        return {}
    except ValueError as exc:
        if required:
            raise SecretUnreadable("decrypt_failed", str(exc)) from exc
        return {}
    try:
        return json.loads(plaintext)
    except json.JSONDecodeError as exc:
        if required:
            raise SecretUnreadable("invalid_json", str(exc)) from exc
        return {}


def _decrypt_legacy_shape(value: Optional[str]) -> Any:
    """Best-effort read of a pre-envelope credentials blob (``required=False`` only)."""
    if not value:
        return {}
    if value.startswith(_LEGACY_PLAINTEXT_MARKER):
        return _safe_json_dict(value[len(_LEGACY_PLAINTEXT_MARKER):])
    try:
        from src.core.encryption import get_encryption_service

        return _safe_json_dict(get_encryption_service().decrypt_field(value))
    except (ValueError, RuntimeError):
        # Legacy row written before encryption was wired: plain JSON.
        return _safe_json_dict(value)


def _safe_json_dict(raw: str) -> Any:
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if parsed is not None else {}


_LEGACY_PLAINTEXT_MARKER = "__plaintext__:"


def _encrypt_secret_json(payload: Any) -> str:
    """Compatibility writer for ``InstalledIntegration.auth_credentials_encrypted``.

    Formerly defined in ``src/api/v1/endpoints/integrations.py``; every
    install/update path now writes an ``enc:v1:`` envelope. ``None`` maps to
    ``""`` (the column is NOT NULL). There is no plaintext fallback any more:
    without a usable encryption service this raises ``SecretUnreadable``
    (``no_master_key``) instead of writing secrets in the clear.
    """
    if payload is None:
        return ""
    return encrypt_secret_json(payload)


def _decrypt_secret_json(value: Optional[str]) -> dict:
    """Compatibility reader: envelope first, legacy shapes second, ``{}`` on failure.

    Kept for the integration marketplace / SIEM pollers that predate the
    envelope. New code that needs an honest failure must call
    :func:`decrypt_secret_json` with ``required=True``.
    """
    result = decrypt_secret_json(value, required=False)
    return result if isinstance(result, dict) else {}


def envelope_secret_keys(
    value: Any,
    *,
    service: Optional[EncryptionService] = None,
    secret_keys: frozenset[str] = SECRET_KEYS,
) -> tuple[Any, int]:
    """Return a copy of ``value`` with every ``SECRET_KEYS`` member enveloped.

    Walks nested dicts/lists. Values that are already enveloped, ``None`` or
    empty strings are left untouched, which makes the operation idempotent.
    Returns ``(new_value, changed_count)``.
    """
    changed = 0

    def _walk(node: Any, key: Optional[str]) -> Any:
        nonlocal changed
        if isinstance(node, dict):
            return {k: _walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item, None) for item in node]
        if key is not None and key in secret_keys:
            if node is None or node == "" or is_enveloped(node):
                return node
            changed += 1
            return encrypt_secret_json(node, service=service)
        return node

    return _walk(value, None), changed


def open_secret_keys(
    value: Any,
    *,
    service: Optional[EncryptionService] = None,
    secret_keys: frozenset[str] = SECRET_KEYS,
) -> Any:
    """Inverse of :func:`envelope_secret_keys`: decrypt every enveloped secret key.

    Raises ``SecretUnreadable`` on the first value that cannot be opened.
    """

    def _walk(node: Any, key: Optional[str]) -> Any:
        if isinstance(node, dict):
            return {k: _walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item, None) for item in node]
        if key is not None and key in secret_keys and is_enveloped(node):
            return decrypt_secret_json(node, service=service)
        return node

    return _walk(value, None)
