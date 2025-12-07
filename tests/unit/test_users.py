"""Tests for User management functionality"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.core.security import get_password_hash


@pytest.mark.asyncio
class TestUserEndpoints:
    """Tests for User API endpoints"""

    async def test_list_users_admin(self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession):
        """Test listing users as admin"""
        response = await client.get(
            "/api/v1/users",
            headers=admin_auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    async def test_list_users_non_admin(self, client: AsyncClient, auth_headers):
        """Test listing users as non-admin should fail"""
        response = await client.get(
            "/api/v1/users",
            headers=auth_headers,
        )

        assert response.status_code == 403

    async def test_create_user_admin(self, client: AsyncClient, admin_auth_headers):
        """Test creating a user as admin"""
        response = await client.post(
            "/api/v1/users",
            headers=admin_auth_headers,
            json={
                "email": "newuser@example.com",
                "password": "newpassword123",
                "full_name": "New User",
                "role": "analyst",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["full_name"] == "New User"
        assert data["role"] == "analyst"

    async def test_create_user_duplicate_email(self, client: AsyncClient, admin_auth_headers, test_user):
        """Test creating user with duplicate email"""
        response = await client.post(
            "/api/v1/users",
            headers=admin_auth_headers,
            json={
                "email": "test@example.com",  # Same as test_user
                "password": "password123",
                "full_name": "Duplicate User",
            },
        )

        assert response.status_code == 400

    async def test_get_user(self, client: AsyncClient, admin_auth_headers, test_user):
        """Test getting a specific user"""
        response = await client.get(
            f"/api/v1/users/{test_user.id}",
            headers=admin_auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user.email

    async def test_update_user(self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession):
        """Test updating a user"""
        user = User(
            email="updateme@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Update Me",
            role="analyst",
            is_active=True,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        response = await client.patch(
            f"/api/v1/users/{user.id}",
            headers=admin_auth_headers,
            json={"full_name": "Updated Name"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["full_name"] == "Updated Name"

    async def test_deactivate_user(self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession):
        """Test deactivating a user"""
        user = User(
            email="deactivate@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Deactivate Me",
            role="analyst",
            is_active=True,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        response = await client.patch(
            f"/api/v1/users/{user.id}",
            headers=admin_auth_headers,
            json={"is_active": False},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False

    async def test_delete_user(self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession):
        """Test deleting a user"""
        user = User(
            email="delete@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Delete Me",
            role="analyst",
            is_active=True,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        response = await client.delete(
            f"/api/v1/users/{user.id}",
            headers=admin_auth_headers,
        )

        assert response.status_code == 204


@pytest.mark.asyncio
class TestUserRoles:
    """Tests for role-based access control"""

    async def test_analyst_cannot_create_admin(self, client: AsyncClient, auth_headers):
        """Test that analyst cannot create admin users"""
        response = await client.post(
            "/api/v1/users",
            headers=auth_headers,
            json={
                "email": "hacker@example.com",
                "password": "password123",
                "role": "admin",
            },
        )

        assert response.status_code == 403

    async def test_admin_can_change_roles(self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession):
        """Test that admin can change user roles"""
        user = User(
            email="rolechange@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Role Change",
            role="viewer",
            is_active=True,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        response = await client.patch(
            f"/api/v1/users/{user.id}",
            headers=admin_auth_headers,
            json={"role": "analyst"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "analyst"
