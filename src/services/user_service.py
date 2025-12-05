"""User service for user management operations"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import NotFoundError, ValidationError
from src.core.security import get_password_hash, verify_password
from src.models.user import User, UserRole


class UserService:
    """Service for user management"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.db.execute(
            select(User).where(func.lower(User.email) == email.lower())
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        role: str = UserRole.ANALYST.value,
        is_superuser: bool = False,
    ) -> User:
        """Create a new user"""
        # Check if email already exists
        existing = await self.get_by_email(email)
        if existing:
            raise ValidationError(f"User with email {email} already exists")

        user = User(
            email=email.lower(),
            hashed_password=get_password_hash(password),
            full_name=full_name,
            role=role,
            is_superuser=is_superuser,
            is_active=True,
        )

        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def update(
        self,
        user_id: str,
        **kwargs,
    ) -> User:
        """Update a user"""
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User", user_id)

        # Handle password update
        if "password" in kwargs:
            kwargs["hashed_password"] = get_password_hash(kwargs.pop("password"))

        # Handle email update
        if "email" in kwargs:
            kwargs["email"] = kwargs["email"].lower()
            existing = await self.get_by_email(kwargs["email"])
            if existing and existing.id != user_id:
                raise ValidationError(f"Email {kwargs['email']} is already in use")

        for key, value in kwargs.items():
            if hasattr(user, key) and value is not None:
                setattr(user, key, value)

        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def delete(self, user_id: str) -> bool:
        """Delete a user"""
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User", user_id)

        await self.db.delete(user)
        await self.db.flush()
        return True

    async def authenticate(self, email: str, password: str) -> Optional[User]:
        """Authenticate a user by email and password"""
        user = await self.get_by_email(email)
        if not user:
            return None

        if not verify_password(password, user.hashed_password):
            return None

        if not user.is_active:
            return None

        return user

    async def update_last_login(self, user_id: str) -> None:
        """Update user's last login timestamp"""
        user = await self.get_by_id(user_id)
        if user:
            user.last_login = datetime.now(timezone.utc).isoformat()
            await self.db.flush()

    async def list_users(
        self,
        page: int = 1,
        size: int = 20,
        search: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> tuple[list[User], int]:
        """List users with pagination and filtering"""
        query = select(User)

        # Apply filters
        if search:
            search_filter = f"%{search}%"
            query = query.where(
                (User.email.ilike(search_filter))
                | (User.full_name.ilike(search_filter))
            )

        if role:
            query = query.where(User.role == role)

        if is_active is not None:
            query = query.where(User.is_active == is_active)

        # Get total count
        count_result = await self.db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        # Apply pagination
        query = query.offset((page - 1) * size).limit(size)
        query = query.order_by(User.created_at.desc())

        result = await self.db.execute(query)
        users = list(result.scalars().all())

        return users, total

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> bool:
        """Change user password"""
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User", user_id)

        if not verify_password(current_password, user.hashed_password):
            raise ValidationError("Current password is incorrect")

        user.hashed_password = get_password_hash(new_password)
        await self.db.flush()
        return True
