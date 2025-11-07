"""
Authentication validation utilities
"""
from typing import Optional
from .models import CreateUser, UpdateUser, UpdatePassword
from .database_service import DatabaseService

from fastapi import HTTPException, status
import re

from . import user_queries


def validate_username_format(username: str) -> None:
    """Validate username format"""
    if not re.match(r"^\w{3,}$", username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters long and contain only letters, numbers, and underscores."
        )


def validate_email_format(email: str) -> None:
    """Validate email format"""
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format.",
        )


def validate_password_strength(password: str) -> None:
    """Validate password strength"""
    if (len(password) < 8 or 
        not re.search(r"[A-Z]", password) or 
        not re.search(r"[0-9]", password)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long, contain at least one uppercase letter and one number.",
        )


def validate_username_unique(username: str, db_service: DatabaseService) -> None:
    """Validate that username is unique (excluding current user if updating)"""
    existing_user = user_queries.get_user_by_username(username, db_service)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already taken.",
        )


def validate_email_unique(email: str, db_service: DatabaseService) -> None:
    """Validate that email is unique (excluding current user if updating)"""
    
    existing_user = user_queries.get_user_by_email(email, db_service)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered.",
        )


def validate_new_user(user: CreateUser, db_service: DatabaseService) -> None:
    """Validate all fields for new user creation"""
    validate_username_format(user.username)
    validate_email_format(user.email)
    validate_password_strength(user.password)
    validate_username_unique(user.username, db_service)
    validate_email_unique(user.email, db_service)


def validate_user_update(user_update: UpdateUser, db_service: DatabaseService) -> None:
    """Validate fields for user update"""
    if user_update.username is not None:
        validate_username_format(user_update.username)
        validate_username_unique(user_update.username, db_service)


def validate_new_password(
    current_hashed_password: str,
    pwd_context,
    password_update: Optional[UpdatePassword],
    new_password: Optional[str] = None,
    allow_same_as_current: bool = True
    ) -> None:
    """Validate password update"""
    _newPassword = new_password
    # Verify current password
    if password_update is not None:
        if not pwd_context.verify(password_update.current_password, current_hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect."
            )
        _newPassword = password_update.new_password

    if not _newPassword:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be provided."
        )

    if not allow_same_as_current and pwd_context.verify(_newPassword, current_hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password."
        )

    validate_password_strength(_newPassword)
    return None