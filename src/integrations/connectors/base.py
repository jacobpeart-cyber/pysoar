"""Connector protocol and base class for vendor API integrations.

Every implemented connector declares, as class attributes, the single source
of truth the catalogue, the install validation, the action rows and the docs
are built from:

* ``ACTIONS``: action name -> ``ActionSpec`` (description, JSON-schema
  ``params_schema``, one-line ``output``, ``idempotent``, ``side_effect``).
  Every key is a coroutine method of the class; ``execute_action`` dispatches
  exactly these names and nothing else.
* ``CONFIG_FIELDS`` / ``CREDENTIAL_FIELDS``: the keys the class reads from
  ``config`` / ``credentials``, as ``IntegrationConfigField``.
* ``VERIFICATION``: an honest statement of how the connector was checked.
* ``TEST_CALL``: the authenticated, read-only vendor call ``test_connection``
  makes.

Every HTTP request goes through ``get_client``, whose transport is
``PinnedTransport`` (src/integrations/netguard.py): each request's host is
resolved once, internal addresses are refused and the connection goes to the
vetted IP with TLS verification on.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, ClassVar, Dict, Optional

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.core.config import settings
from src.core.exceptions import IntegrationError
from src.core.logging import get_logger
from src.integrations.netguard import PinnedTransport
from src.schemas.integrations import IntegrationConfigField

logger = get_logger(__name__)

DEFAULT_VERIFICATION = (
    "implemented from the vendor's public API documentation; not verified against a live tenant"
)
REFUSED_INTERNAL = "refused: target resolves to an internal address"
MAX_ERROR_CHARS = 200


@dataclass(frozen=True)
class ActionSpec:
    """One executable connector action."""

    description: str
    params_schema: dict[str, Any]
    output: str
    idempotent: bool
    side_effect: bool
    action_type: str = "query"
    display_name: str = ""

    def as_catalogue(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "display_name": self.display_name or name.replace("_", " ").capitalize(),
            "description": self.description,
            "params_schema": self.params_schema,
            "output": self.output,
            "idempotent": self.idempotent,
            "side_effect": self.side_effect,
            "action_type": self.action_type,
        }


@dataclass
class ConnectionTestResult:
    """Outcome of ``test_connection``: never carries a secret."""

    status: str  # "healthy" | "unhealthy"
    detail: str
    checked: str
    http_status: Optional[int] = None

    @property
    def healthy(self) -> bool:
        return self.status == "healthy"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ConnectorHTTPError(IntegrationError):
    """The vendor answered with an HTTP error status."""

    def __init__(self, service: str, status_code: int, vendor_message: str = ""):
        self.status_code = status_code
        self.vendor_message = vendor_message
        text = f"HTTP {status_code}" + (f": {vendor_message}" if vendor_message else "")
        super().__init__(service=service, message=text, details={"status_code": status_code})


class ConnectorActionFailed(Exception):  # noqa: N818 (reads as a result, not a bug class)
    """An action did not succeed. ``message`` is already sanitised."""

    def __init__(self, message: str, http_status: Optional[int] = None, code: str = "failed"):
        self.message = message
        self.http_status = http_status
        self.code = code
        super().__init__(message)


class _Retryable(Exception):  # noqa: N818
    """Internal: a transient failure on an idempotent request."""

    def __init__(self, error: IntegrationError):
        self.error = error
        super().__init__(str(error))


def field_spec(
    name: str,
    display_name: str,
    description: str,
    *,
    required: bool = True,
    secret: bool = False,
    type: str = "string",  # noqa: A002 (the schema's own key name)
    default: Any = None,
) -> IntegrationConfigField:
    return IntegrationConfigField(
        name=name,
        type="password" if secret and type == "string" else type,
        display_name=display_name,
        description=description,
        required=required,
        default=default,
        secret=secret,
    )


def object_schema(properties: dict[str, Any], required: Optional[list[str]] = None) -> dict[str, Any]:
    """A closed JSON-schema object (unknown keys are refused)."""
    return {
        "type": "object",
        "properties": properties,
        "required": list(required or []),
        "additionalProperties": False,
    }


_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}


def validate_params(schema: dict[str, Any], params: Any) -> list[str]:
    """Check ``params`` against a connector ``params_schema``.

    ``jsonschema`` is not a dependency of this repository, so this is a small
    checker for the subset the connector schemas use: an object with
    ``required`` keys, ``additionalProperties: false``, and per-property
    ``type`` (string, integer, number, boolean, array, object), ``enum``,
    ``minimum`` / ``maximum``, ``minLength``, ``minItems`` and array ``items``
    of a single type. Returns human-readable problems naming keys, never
    values.
    """
    if not isinstance(params, dict):
        return ["parameters must be a JSON object"]
    problems: list[str] = []
    properties: dict[str, Any] = schema.get("properties") or {}
    for key in schema.get("required") or []:
        if key not in params or params[key] is None:
            problems.append(f"missing required parameter '{key}'")
    if schema.get("additionalProperties") is False:
        for key in params:
            if key not in properties:
                problems.append(f"unknown parameter '{key}'")
    for key, value in params.items():
        spec = properties.get(key)
        if spec is None or value is None:
            continue
        problems.extend(_check_value(key, spec, value))
    return problems


def _check_value(key: str, spec: dict[str, Any], value: Any) -> list[str]:
    expected = spec.get("type")
    if expected:
        types = _JSON_TYPES.get(expected, ())
        ok = isinstance(value, types) and not (expected in ("integer", "number") and isinstance(value, bool))
        if not ok:
            return [f"parameter '{key}' must be of type {expected}"]
    problems: list[str] = []
    if "enum" in spec and value not in spec["enum"]:
        problems.append(f"parameter '{key}' must be one of {spec['enum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in spec and value < spec["minimum"]:
            problems.append(f"parameter '{key}' must be >= {spec['minimum']}")
        if "maximum" in spec and value > spec["maximum"]:
            problems.append(f"parameter '{key}' must be <= {spec['maximum']}")
    if isinstance(value, str) and len(value) < int(spec.get("minLength", 0)):
        problems.append(f"parameter '{key}' must not be empty")
    if isinstance(value, list):
        if len(value) < int(spec.get("minItems", 0)):
            problems.append(f"parameter '{key}' needs at least {spec['minItems']} item(s)")
        item_type = (spec.get("items") or {}).get("type")
        if item_type:
            types = _JSON_TYPES.get(item_type, ())
            if any(not isinstance(v, types) or (item_type in ("integer", "number") and isinstance(v, bool)) for v in value):
                problems.append(f"parameter '{key}' items must be of type {item_type}")
    return problems


def sanitize_message(message: Any, secrets: Optional[list[str]] = None, limit: int = MAX_ERROR_CHARS) -> str:
    """Collapse whitespace, strip every known secret value, cap the length."""
    text = re.sub(r"\s+", " ", str(message or "")).strip()
    for secret in secrets or []:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "[redacted]")
    text = re.sub(r"(?i)(bearer|basic|token token=)\s*[A-Za-z0-9._~+/=-]{8,}", r"\1 [redacted]", text)
    return text[:limit]


class RateLimitTracker:
    """Track API rate limits"""

    def __init__(self):
        self.remaining: int = 0
        self.reset_at: Optional[datetime] = None
        self.limit: int = 0

    def update(self, remaining: int, reset_at: Optional[datetime] = None):
        """Update rate limit information"""
        self.remaining = remaining
        self.reset_at = reset_at or datetime.utcnow() + timedelta(minutes=1)
        if self.remaining == 0:
            logger.warning(f"Rate limit exhausted. Reset at {self.reset_at}")

    def is_exceeded(self) -> bool:
        """Check if rate limit is exceeded"""
        if self.remaining > 0:
            return False
        if self.reset_at and datetime.utcnow() < self.reset_at:
            return True
        return False


_RETRY_STATUSES = {429, 502, 503, 504}
_IDEMPOTENT_METHODS = {"GET", "HEAD"}


class BaseConnector(ABC):
    """Abstract base class for API connectors (see the module docstring)."""

    name: str = "base"
    base_url: str = ""
    timeout: int = 30

    ACTIONS: ClassVar[dict[str, ActionSpec]] = {}
    CONFIG_FIELDS: ClassVar[list[IntegrationConfigField]] = []
    CREDENTIAL_FIELDS: ClassVar[list[IntegrationConfigField]] = []
    VERIFICATION: ClassVar[str] = DEFAULT_VERIFICATION
    TEST_CALL: ClassVar[str] = ""

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize connector with config and credentials"""
        self.config = dict(config or {})
        self.credentials = dict(credentials or {})
        self._client: Optional[httpx.AsyncClient] = None
        self.rate_limit = RateLimitTracker()
        self._session_start = datetime.utcnow()

    # ------------------------------------------------------------------
    # Declared fields
    # ------------------------------------------------------------------

    @classmethod
    def missing_fields(cls, config: Optional[dict[str, Any]], credentials: Optional[dict[str, Any]]) -> list[str]:
        """Names of required config / credential fields that are absent or empty."""
        missing: list[str] = []
        for fields, values in ((cls.CONFIG_FIELDS, config or {}), (cls.CREDENTIAL_FIELDS, credentials or {})):
            for spec in fields:
                if spec.required and (values.get(spec.name) in (None, "") or (isinstance(values.get(spec.name), str) and not values[spec.name].strip())):
                    missing.append(spec.name)
        return missing

    @classmethod
    def invalid_fields(cls, config: Optional[dict[str, Any]], credentials: Optional[dict[str, Any]]) -> list[str]:
        """Names of present fields whose value cannot be used (format checks; values never echoed)."""
        return []

    @property
    def is_configured(self) -> bool:
        """True when every required config and credential field is present."""
        return not self.missing_fields(getattr(self, "config", {}), getattr(self, "credentials", {}))

    def _secret_values(self) -> list[str]:
        secret_names = {f.name for f in self.CREDENTIAL_FIELDS + self.CONFIG_FIELDS if f.secret}
        values = [str(v) for k, v in (getattr(self, "credentials", {}) or {}).items() if k in secret_names and v]
        token = getattr(self, "_token", None)
        if token:
            values.append(str(token))
        return values

    def sanitize(self, message: Any) -> str:
        return sanitize_message(message, self._secret_values())

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create the pinned HTTP client.

        Headers are not baked into the client: each request builds its own
        (``_request``), so a call that must not carry the vendor credential
        (an absolute callback URL, the PagerDuty Events API) can omit it.
        """
        if self._client is None or self._client.is_closed:
            # PinnedTransport resolves each request's host once, refuses
            # internal addresses and connects to the vetted IP (Host / TLS SNI
            # keep the hostname), so a tenant-supplied domain or path segment
            # cannot reach the API host's network, even via DNS rebinding.
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=float(self.timeout),
                transport=PinnedTransport(),
                follow_redirects=False,
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client"""
        client = getattr(self, "_client", None)
        if client is not None and hasattr(client, "aclose"):
            await client.aclose()
        self._client = None

    def _get_headers(self) -> Dict[str, str]:
        """Default headers; subclasses add their authentication header."""
        return {
            "Accept": "application/json",
            "User-Agent": f"PySOAR/{settings.app_name}",
        }

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json_data: Any = None,
        headers: Optional[Dict] = None,
        *,
        form_data: Optional[Dict] = None,
        content: Optional[bytes] = None,
        auth: bool = True,
    ) -> httpx.Response:
        """Send one request; retries transient failures of idempotent calls.

        Raises ``ConnectorHTTPError`` for an HTTP error status and
        ``IntegrationError`` for a refused target or a transport failure.
        """
        method = method.upper()

        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=1, max=4),
            retry=retry_if_exception_type(_Retryable),
            reraise=True,
        )
        async def _attempt() -> httpx.Response:
            try:
                return await self._send_once(method, endpoint, params, json_data, headers, form_data, content, auth)
            except IntegrationError as exc:
                transient = getattr(exc, "status_code", None) in _RETRY_STATUSES or exc.details.get("transient")
                if transient and method in _IDEMPOTENT_METHODS:
                    raise _Retryable(exc) from exc
                raise

        try:
            return await _attempt()
        except _Retryable as exc:
            raise exc.error from None

    async def _send_once(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict],
        json_data: Any,
        headers: Optional[Dict],
        form_data: Optional[Dict],
        content: Optional[bytes],
        auth: bool,
    ) -> httpx.Response:
        client = await self.get_client()
        base_headers = self._get_headers() if auth else BaseConnector._get_headers(self)
        request_headers = {**base_headers, **(headers or {})}
        start_time = time.time()
        try:
            response = await client.request(
                method=method,
                url=endpoint,
                params=params,
                json=json_data,
                data=form_data,
                content=content,
                headers=request_headers,
            )
        except httpx.ConnectError as exc:
            text = str(exc)
            if "outbound target refused" in text:
                reason = REFUSED_INTERNAL if ("internal address" in text or "blocked" in text) else "refused: " + self.sanitize(text.split("refused:", 1)[-1])
                logger.warning(f"{self.name} outbound target refused", endpoint=_path_only(endpoint))
                raise IntegrationError(self.name, reason, details={"refused": True}) from None
            raise IntegrationError(self.name, "connection failed", details={"transient": True}) from None
        except httpx.TimeoutException:
            raise IntegrationError(self.name, f"timed out after {self.timeout}s", details={"transient": True}) from None
        except httpx.RequestError as exc:
            raise IntegrationError(self.name, f"request failed: {type(exc).__name__}", details={"transient": True}) from None

        logger.info(
            f"{self.name} API call",
            method=method,
            endpoint=_path_only(endpoint),
            status=response.status_code,
            latency=f"{time.time() - start_time:.2f}s",
        )
        if response.status_code >= 400:
            vendor = self.sanitize(_vendor_error_text(response))
            raise ConnectorHTTPError(self.name, response.status_code, vendor)
        return response

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json_data: Any = None,
        headers: Optional[Dict] = None,
        *,
        form_data: Optional[Dict] = None,
        auth: bool = True,
    ) -> Any:
        """Send a request and return its decoded JSON body ({} when empty)."""
        response = await self._request(
            method, endpoint, params=params, json_data=json_data, headers=headers, form_data=form_data, auth=auth,
        )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            raise IntegrationError(self.name, f"HTTP {response.status_code}: response was not JSON") from None

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    @abstractmethod
    async def test_connection(self) -> ConnectionTestResult:
        """One authenticated read-only call (``TEST_CALL``)."""

    async def _probe(
        self,
        checked: str,
        call: Callable[[], Awaitable[Any]],
        verdict: Optional[Callable[[Any], Optional[str]]] = None,
    ) -> ConnectionTestResult:
        """Run ``call`` and translate the outcome into a ConnectionTestResult.

        ``verdict`` may inspect a 2xx body and return a failure reason (for
        APIs such as Slack's that answer 200 with ``ok: false``).
        """
        missing = self.missing_fields(self.config, self.credentials)
        if missing:
            return ConnectionTestResult("unhealthy", f"missing required fields: {', '.join(missing)}", checked)
        try:
            body = await call()
        except ConnectorHTTPError as exc:
            if exc.status_code in (401, 403):
                detail = f"authentication rejected (HTTP {exc.status_code})"
            else:
                detail = self.sanitize(str(exc.message).split(": ", 1)[-1])
            return ConnectionTestResult("unhealthy", detail, checked, exc.status_code)
        except IntegrationError as exc:
            return ConnectionTestResult("unhealthy", self.sanitize(str(exc.message).split(": ", 1)[-1]), checked)
        except ValueError as exc:
            return ConnectionTestResult("unhealthy", self.sanitize(exc), checked)
        finally:
            await self.close()
        reason = verdict(body) if verdict else None
        if reason:
            return ConnectionTestResult("unhealthy", self.sanitize(reason), checked, 200)
        return ConnectionTestResult("healthy", "authenticated read-only call succeeded", checked, 200)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def run_action(self, action_name: str, params: Optional[Dict]) -> Dict[str, Any]:
        """Run a declared action; return its output or raise ConnectorActionFailed."""
        spec = self.ACTIONS.get(action_name)
        if spec is None:
            raise ConnectorActionFailed(
                f"unknown action {action_name}; available: {sorted(self.ACTIONS)}", code="unknown_action",
            )
        params = dict(params or {})
        problems = validate_params(spec.params_schema, params)
        if problems:
            raise ConnectorActionFailed("invalid parameters: " + "; ".join(problems), code="invalid_parameters")
        missing = self.missing_fields(self.config, self.credentials)
        if missing:
            raise ConnectorActionFailed(f"integration is missing required fields: {', '.join(missing)}", code="not_configured")
        method = getattr(self, action_name)
        try:
            result = await method(**params)
        except ConnectorHTTPError as exc:
            raise ConnectorActionFailed(self.sanitize(exc.message), http_status=exc.status_code) from None
        except IntegrationError as exc:
            raise ConnectorActionFailed(self.sanitize(exc.message)) from None
        except ValueError as exc:
            raise ConnectorActionFailed(self.sanitize(exc), code="invalid_parameters") from None
        finally:
            await self.close()
        if not isinstance(result, dict):
            raise ConnectorActionFailed("connector returned no structured output")
        if result.get("error"):
            raise ConnectorActionFailed(self.sanitize(result["error"]), http_status=result.get("http_status"))
        if result.get("success") is False:
            raise ConnectorActionFailed(self.sanitize(result.get("errors") or "vendor reported failure"))
        return result

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Dispatch exactly the names in ``ACTIONS``.

        Returns the action output on success, or
        ``{"status": "failed", "error": ..., "http_status": ...}``; an unknown
        name is a failed result, never an exception.
        """
        try:
            return await self.run_action(action_name, params)
        except ConnectorActionFailed as exc:
            return {"status": "failed", "error": exc.message, "http_status": exc.http_status, "code": exc.code}

    # ------------------------------------------------------------------
    # Catalogue
    # ------------------------------------------------------------------

    @classmethod
    def catalogue_actions(cls) -> list[dict[str, Any]]:
        return [spec.as_catalogue(name) for name, spec in cls.ACTIONS.items()]

    @classmethod
    def config_schema(cls) -> dict[str, Any]:
        """JSON schema of the install payload's ``config`` and ``credentials``."""

        def _props(fields: list[IntegrationConfigField]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for f in fields:
                prop: dict[str, Any] = {
                    "type": "string" if f.type == "password" else f.type,
                    "title": f.display_name,
                    "description": f.description or "",
                }
                if f.secret:
                    prop["writeOnly"] = True
                if f.default is not None:
                    prop["default"] = f.default
                out[f.name] = prop
            return out

        return {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": _props(cls.CONFIG_FIELDS),
                    "required": [f.name for f in cls.CONFIG_FIELDS if f.required],
                },
                "credentials": {
                    "type": "object",
                    "properties": _props(cls.CREDENTIAL_FIELDS),
                    "required": [f.name for f in cls.CREDENTIAL_FIELDS if f.required],
                },
            },
        }


def path_segment(value: Any) -> str:
    """A value placed in a URL path must be one plain segment (no slash, ?, #, @, backslash, space, % or dot-segment)."""
    text = str(value or "").strip()
    if not text or any(c in text for c in ("/", "?", "#", "@", "\\", " ", "%")) or text in (".", ".."):
        raise ValueError("value is not a plain identifier")
    return text


def _path_only(endpoint: str) -> str:
    """Log the path of a request, never its query string (keys travel there)."""
    return str(endpoint).split("?", 1)[0]


def _vendor_error_text(response: httpx.Response) -> str:
    """A short vendor error message from a JSON error body, else empty."""
    try:
        body = response.json()
    except ValueError:
        return ""
    candidates: list[Any] = []
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            candidates += [err.get("message"), err.get("code")]
        else:
            candidates.append(err)
        candidates += [body.get("message"), body.get("error_description"), body.get("errorMessages")]
        errors = body.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            candidates.append(first.get("message") if isinstance(first, dict) else first)
        elif isinstance(errors, dict):
            candidates.append("; ".join(f"{k}: {v}" for k, v in list(errors.items())[:3]))
    for c in candidates:
        if isinstance(c, list):
            c = "; ".join(str(x) for x in c[:3])
        if c:
            return str(c)
    return ""


__all__ = [
    "ActionSpec",
    "BaseConnector",
    "ConnectionTestResult",
    "ConnectorActionFailed",
    "ConnectorHTTPError",
    "DEFAULT_VERIFICATION",
    "REFUSED_INTERNAL",
    "field_spec",
    "object_schema",
    "path_segment",
    "sanitize_message",
    "validate_params",
]
