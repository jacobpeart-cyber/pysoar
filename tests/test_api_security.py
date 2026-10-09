"""Tests for API security OpenAPI spec parsing and compliance header checks"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.api_security.engine import APIDiscoveryEngine
from src.api_security.models import APIEndpointInventory, AuthenticationTypeEnum
from src.api_security.tasks import _check_security_headers, _run_check


def _mock_async_client(response=None, error=None):
    """Build a mock for httpx.AsyncClient usable as an async context manager"""
    client = AsyncMock()
    if error is not None:
        client.get = AsyncMock(side_effect=error)
    else:
        client.get = AsyncMock(return_value=response)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _endpoint(**overrides):
    """Build an (unsaved) APIEndpointInventory instance for checks"""
    defaults = dict(
        service_name="orders-service",
        base_url="https://api.example.com",
        path="/api/orders",
        method="GET",
        organization_id="org-1",
    )
    defaults.update(overrides)
    return APIEndpointInventory(**defaults)


OPENAPI3_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Orders API", "version": "1.0"},
    "security": [{"bearerAuth": []}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        }
    },
    "paths": {
        "/api/orders": {
            "get": {"responses": {"200": {"description": "ok"}}},
            "post": {
                "security": [{"apiKeyAuth": []}],
                "responses": {"201": {"description": "created"}},
            },
            "parameters": [],
        },
        "/api/health": {
            "get": {"security": [], "responses": {"200": {"description": "ok"}}},
        },
    },
}

SWAGGER2_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "1.0"},
    "securityDefinitions": {
        "basic_auth": {"type": "basic"},
        "oauth": {"type": "oauth2", "flow": "implicit", "authorizationUrl": "https://x/auth"},
    },
    "paths": {
        "/legacy": {
            "delete": {"security": [{"basic_auth": []}]},
            "put": {"security": [{"oauth": []}]},
        },
    },
}

OPENAPI3_YAML_SPEC = """
openapi: 3.0.0
info:
  title: Yaml API
  version: "1.0"
paths:
  /yaml-endpoint:
    get:
      responses:
        "200":
          description: ok
"""


class TestOpenAPISpecParsing:
    """Tests for APIDiscoveryEngine._parse_openapi_spec / discover_from_openapi"""

    async def test_parse_openapi3_json_extracts_endpoints_and_auth(self):
        engine = APIDiscoveryEngine()
        response = httpx.Response(200, text=json.dumps(OPENAPI3_SPEC))

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            endpoints = await engine._parse_openapi_spec("https://api.example.com/openapi.json")

        by_key = {(e["method"], e["path"]): e for e in endpoints}
        assert set(by_key) == {
            ("GET", "/api/orders"),
            ("POST", "/api/orders"),
            ("GET", "/api/health"),
        }
        # Root-level security (bearer -> JWT)
        assert by_key[("GET", "/api/orders")]["authentication_type"] == AuthenticationTypeEnum.JWT.value
        # Operation-level security overrides root (apiKey)
        assert by_key[("POST", "/api/orders")]["authentication_type"] == AuthenticationTypeEnum.API_KEY.value
        # Explicit empty security list -> no auth
        assert by_key[("GET", "/api/health")]["authentication_type"] == AuthenticationTypeEnum.NONE.value

    async def test_parse_swagger2_security_definitions(self):
        engine = APIDiscoveryEngine()
        response = httpx.Response(200, text=json.dumps(SWAGGER2_SPEC))

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            endpoints = await engine._parse_openapi_spec("https://legacy.example.com/swagger.json")

        by_key = {(e["method"], e["path"]): e for e in endpoints}
        assert by_key[("DELETE", "/legacy")]["authentication_type"] == AuthenticationTypeEnum.BASIC.value
        assert by_key[("PUT", "/legacy")]["authentication_type"] == AuthenticationTypeEnum.OAUTH2.value

    async def test_parse_yaml_spec(self):
        engine = APIDiscoveryEngine()
        response = httpx.Response(200, text=OPENAPI3_YAML_SPEC)

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            endpoints = await engine._parse_openapi_spec("https://api.example.com/openapi.yaml")

        assert endpoints == [
            {
                "path": "/yaml-endpoint",
                "method": "GET",
                "authentication_type": AuthenticationTypeEnum.NONE.value,
            }
        ]

    async def test_discover_from_openapi_marks_endpoints_documented(self):
        engine = APIDiscoveryEngine()
        response = httpx.Response(200, text=json.dumps(OPENAPI3_SPEC))

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            result = await engine.discover_from_openapi(
                "https://api.example.com/openapi.json", "orders-service", "org-1"
            )

        assert result["documented_endpoints_count"] == 3
        assert "orders-service:GET:/api/orders" in engine.documented_endpoints
        assert all(e["is_documented"] for e in result["documented_endpoints"])
        assert all(not e["is_shadow"] for e in result["documented_endpoints"])

    async def test_fetch_failure_aborts_instead_of_fabricating(self):
        """Unreachable spec URL must NOT silently produce an empty documented set"""
        engine = APIDiscoveryEngine()

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(error=httpx.ConnectError("connection refused")),
        ):
            result = await engine.discover_from_openapi(
                "https://unreachable.example.com/openapi.json", "orders-service", "org-1"
            )

        assert result["status"] == "error"
        assert "documented_endpoints" not in result
        assert engine.documented_endpoints == set()
        assert engine.discovered_endpoints == {}

    async def test_non_2xx_response_aborts(self):
        engine = APIDiscoveryEngine()
        response = httpx.Response(404, text="not found")

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            result = await engine.discover_from_openapi(
                "https://api.example.com/openapi.json", "orders-service", "org-1"
            )

        assert result["status"] == "error"
        assert "404" in result["error"]
        assert engine.documented_endpoints == set()

    async def test_document_without_openapi_marker_aborts(self):
        engine = APIDiscoveryEngine()
        response = httpx.Response(200, text=json.dumps({"paths": {"/x": {"get": {}}}}))

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            result = await engine.discover_from_openapi(
                "https://api.example.com/openapi.json", "orders-service", "org-1"
            )

        assert result["status"] == "error"
        assert engine.documented_endpoints == set()

    async def test_unparseable_document_aborts(self):
        engine = APIDiscoveryEngine()
        response = httpx.Response(200, text="{not json and not: valid: yaml")

        with patch(
            "src.api_security.engine.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            result = await engine.discover_from_openapi(
                "https://api.example.com/openapi.json", "orders-service", "org-1"
            )

        assert result["status"] == "error"
        assert engine.documented_endpoints == set()


class TestHeaderComplianceCheck:
    """Tests for _check_security_headers in compliance tasks"""

    @pytest.fixture(autouse=True)
    def _public_targets(self, monkeypatch):
        # The check now refuses private/unresolvable targets (SSRF guard,
        # covered in tests/unit/test_ssrf_and_scan_gates.py). These tests mock
        # the HTTP client, so treat their example hostnames as public.
        monkeypatch.setattr("src.api_security.tasks.validate_url", lambda url: (True, "OK"))

    async def test_all_required_headers_present_passes(self):
        endpoint = _endpoint()
        response = httpx.Response(
            200,
            headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=63072000",
            },
        )

        with patch(
            "src.api_security.tasks.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            passed, details = await _check_security_headers(endpoint)

        assert passed is True
        assert details["missing_headers"] == []
        assert details["checked_url"] == "https://api.example.com/api/orders"

    async def test_missing_headers_fails_and_lists_them(self):
        endpoint = _endpoint()
        response = httpx.Response(200, headers={"X-Content-Type-Options": "nosniff"})

        with patch(
            "src.api_security.tasks.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            passed, details = await _check_security_headers(endpoint)

        assert passed is False
        assert set(details["missing_headers"]) == {
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        }

    async def test_hsts_not_required_over_plain_http(self):
        endpoint = _endpoint(base_url="http://internal.example.com")
        response = httpx.Response(
            200,
            headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": "default-src 'none'",
            },
        )

        with patch(
            "src.api_security.tasks.httpx.AsyncClient",
            return_value=_mock_async_client(response),
        ):
            passed, details = await _check_security_headers(endpoint)

        assert passed is True
        assert details["missing_headers"] == []

    async def test_no_resolvable_url_fails_with_reason(self):
        """No URL means no header data -- must fail, never pass by default"""
        endpoint = _endpoint(base_url="")

        passed, details = await _check_security_headers(endpoint)

        assert passed is False
        assert "no header data available" in details["reason"]

    async def test_unreachable_endpoint_fails_with_reason(self):
        endpoint = _endpoint()

        with patch(
            "src.api_security.tasks.httpx.AsyncClient",
            return_value=_mock_async_client(error=httpx.ConnectTimeout("timed out")),
        ):
            passed, details = await _check_security_headers(endpoint)

        assert passed is False
        assert "no header data available" in details["reason"]

    async def test_run_check_routes_header_check(self):
        """_run_check('header_check') uses the real check, not a hardcoded pass"""
        endpoint = _endpoint(base_url="")

        passed = await _run_check(endpoint, "header_check")

        assert passed is False
