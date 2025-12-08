"""
Verification database queries
"""
from fastapi import HTTPException, status
from datetime import datetime, timezone, timedelta
from typing import Optional

from src.models import UserInDB, VerificationCode
from src.database_service import DatabaseService
from src import user_queries

import secrets
import os



def generate_verification_code() -> str:
    """Generate a 6-digit verification code"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])


def get_verification_code_by_user_id(user_id: str, db_service: DatabaseService) -> Optional[VerificationCode]:
    """Get regular verification code for user from database"""
    result = db_service.execute_single_query(
        "SELECT * FROM verification_code WHERE user_id = %s",
        (user_id,)
    )
    if result:
        return VerificationCode(**result)
    return None


def create_verification_code(
    user: Optional[UserInDB],
    email: str,
    db_service: DatabaseService,
    ) -> str:
    """Create or update regular verification code for user"""
    if not user: user = user_queries.get_user_by_email(email, db_service)
    check_can_send_verification(user, db_service)

    new_code = generate_verification_code()
    current_time = datetime.now(timezone.utc)

    # Check if verification code already exists for this user
    existing_code = get_verification_code_by_user_id(user.id, db_service)
    if existing_code:
        # Update existing code
        db_service.execute_modification_query(
            "UPDATE verification_code SET value = %s, created_at = %s, verified_at = NULL WHERE user_id = %s",
            (new_code, current_time, user.id)
        )
    else:
        # Insert new code
        db_service.execute_modification_query(
            "INSERT INTO verification_code (user_id, value, created_at) VALUES (%s, %s, %s)",
            (user.id, new_code, current_time)
        )
    return new_code


def mark_verification_code_as_used(user_id: str, db_service: DatabaseService) -> None:
    """Mark regular verification code as used"""
    current_time = datetime.now(timezone.utc)
    db_service.execute_modification_query(
        "UPDATE verification_code SET verified_at = %s WHERE user_id = %s",
        (current_time, user_id)
    )


def check_can_send_verification(user: Optional[UserInDB], db_service: DatabaseService) -> bool:
    """Check if user can resend verification code (30 seconds cooldown)"""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    existing_code = db_service.execute_single_query(
        "SELECT created_at FROM verification_code WHERE user_id = %s",
        (user.id,)
    )

    if not existing_code:
        return None
    
    created_at = existing_code['created_at']
    
    # Check if 30 seconds has passed since last code generation
    time_diff = datetime.now(timezone.utc) - created_at.replace(tzinfo=timezone.utc)
    if time_diff <= timedelta(seconds=30):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Please wait 30 seconds before requesting another verification code.",
        )
    return None


def update_user_email_verified_status(user_id: str, db_service: DatabaseService, verified: bool = True) -> None:
    """Update user's email_verified status"""
    db_service.execute_modification_query(
        "UPDATE user SET email_verified = %s WHERE id = %s",
        (1 if verified else 0, user_id)
    )


def update_user_email(user_id: str, new_email: str, db_service: DatabaseService) -> None:
    """Update user's email and mark as verified"""
    db_service.execute_modification_query(
        "UPDATE user SET email = %s WHERE id = %s",
        (new_email, user_id)
    )
