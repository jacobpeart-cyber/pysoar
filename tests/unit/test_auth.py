"""Tests for authentication functionality"""

import pytest
from httpx import AsyncClient

from src.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
)


class TestPasswordHashing:
    """Tests for password hashing functions"""

    def test_password_hash(self):
        """Test password hashing"""
        password = "securepassword123"
        hashed = get_password_hash(password)

        assert hashed != password
        assert len(hashed) > 20

    def test_verify_correct_password(self):
        """Test verifying correct password"""
        password = "securepassword123"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True

    def test_verify_wrong_password(self):
        """Test verifying wrong password"""
        password = "securepassword123"
        hashed = get_password_hash(password)

        assert verify_password("wrongpassword", hashed) is False


class TestJWTTokens:
    """Tests for JWT token functions"""

    def test_create_access_token(self):
        """Test creating access token"""
        user_id = "test-user-id"
        token = create_access_token(subject=user_id)

        assert token is not None
        assert len(token) > 50

    def test_verify_access_token(self):
        """Test verifying access token"""
        user_id = "test-user-id"
        token = create_access_token(subject=user_id)

        verified_id = verify_token(token, token_type="access")

        assert verified_id == user_id

    def test_create_refresh_token(self):
        """Test creating refresh token"""
        user_id = "test-user-id"
        token = create_refresh_token(subject=user_id)

        assert token is not None
        assert len(token) > 50

    def test_verify_refresh_token(self):
        """Test verifying refresh token"""
        user_id = "test-user-id"
        token = create_refresh_token(subject=user_id)

        verified_id = verify_token(token, token_type="refresh")

        assert verified_id == user_id

    def test_verify_wrong_token_type(self):
        """Test verifying token with wrong type"""
        user_id = "test-user-id"
        access_token = create_access_token(subject=user_id)

        # Try to verify access token as refresh token
        verified_id = verify_token(access_token, token_type="refresh")

        assert verified_id is None

    def test_verify_invalid_token(self):
        """Test verifying invalid token"""
        verified_id = verify_token("invalid-token", token_type="access")

        assert verified_id is None


@pytest.mark.asyncio
class TestAuthEndpoints:
    """Tests for authentication API endpoints"""

    async def test_login_success(self, client: AsyncClient, test_user):
        """Test successful login"""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_wrong_password(self, client: AsyncClient, test_user):
        """Test login with wrong password"""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "wrongpassword",
            },
        )

        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Test login with non-existent user"""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "somepassword",
            },
        )

        assert response.status_code == 401

    async def test_get_current_user(self, client: AsyncClient, test_user, auth_headers):
        """Test getting current user info"""
        response = await client.get(
            "/api/v1/auth/me",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["full_name"] == "Test User"

    async def test_get_current_user_no_auth(self, client: AsyncClient):
        """Test getting current user without authentication"""
        response = await client.get("/api/v1/auth/me")

        assert response.status_code == 401
