"""
Verification database queries
"""
from datetime import datetime, timezone
from typing import Optional

from src.models import VerificationCode
from src.managers.postgres import PostgresManager


def get_verification_code_by_user_id(user_id: str, pg_manager: PostgresManager) -> Optional[VerificationCode]:
    """Get regular verification code for user from database"""
    result = pg_manager.execute_single_query(
        "SELECT * FROM verification_code WHERE user_id = %s",
        (user_id,)
    )
    if result:
        return VerificationCode(**result)
    return None


def upsert_verification_code(
    user_id: str,
    code: str,
    pg_manager: PostgresManager,
    ) -> None:
    """Create or update regular verification code for user"""
    current_time = datetime.now(timezone.utc)

    # Check if verification code already exists for this user
    existing_code = get_verification_code_by_user_id(user_id, pg_manager)
    if existing_code:
        # Update existing code
        pg_manager.execute_modification_query(
            "UPDATE verification_code SET value = %s, created_at = %s, verified_at = NULL WHERE user_id = %s",
            (code, current_time, user_id)
        )
    else:
        # Insert new code
        pg_manager.execute_modification_query(
            "INSERT INTO verification_code (user_id, value, created_at) VALUES (%s, %s, %s)",
            (user_id, code, current_time)
        )


def mark_verification_code_as_used(user_id: str, pg_manager: PostgresManager) -> None:
    """Mark regular verification code as used"""
    current_time = datetime.now(timezone.utc)
    pg_manager.execute_modification_query(
        "UPDATE verification_code SET verified_at = %s WHERE user_id = %s",
        (current_time, user_id)
    )


def update_user_email_verified_status(user_id: str, pg_manager: PostgresManager, verified: bool = True) -> None:
    """Update user's email_verified status"""
    pg_manager.execute_modification_query(
        'UPDATE "user" SET email_verified = %s WHERE id = %s',
        (verified, user_id)
    )


def update_user_email(user_id: str, new_email: str, pg_manager: PostgresManager) -> None:
    """Update user's email and mark as verified"""
    pg_manager.execute_modification_query(
        'UPDATE "user" SET email = %s WHERE id = %s',
        (new_email, user_id)
    )
