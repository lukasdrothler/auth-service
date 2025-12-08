from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException, status

from src.models import UserInDBNoPassword, UserInDB, UpdateUser
from src.database_service import DatabaseService

import logging

logger = logging.getLogger(__name__)

def get_user_by_id(user_id: str, db_service: DatabaseService) -> Optional[UserInDB]:
    """Get user by ID"""
    result = db_service.execute_single_query(
        "SELECT * FROM user WHERE id = %s", 
        (user_id,)
    )
    if result:
        return UserInDB(**result)
    return None


def get_user_by_username(username: str, db_service: DatabaseService) -> Optional[UserInDB]:
    """Get user by username"""
    result = db_service.execute_single_query(
        "SELECT * FROM user WHERE LOWER(username) = LOWER(%s)", 
        (username,)
    )
    if result:
        return UserInDB(**result)
    return None


def get_user_by_email(email: str, db_service: DatabaseService) -> Optional[UserInDB]:
    """Get user by email"""
    result = db_service.execute_single_query(
        "SELECT * FROM user WHERE LOWER(email) = LOWER(%s)", 
        (email,)
    )
    if result:
        return UserInDB(**result)
    return None


def get_user_by_username_and_email(username: str, email: str, db_service: DatabaseService) -> Optional[UserInDB]:
    """Get user by username and email"""
    result = db_service.execute_single_query(
        "SELECT * FROM user WHERE LOWER(username) = LOWER(%s) AND LOWER(email) = LOWER(%s)", 
        (username, email)
    )
    if result:
        return UserInDB(**result)
    return None


def get_user_by_stripe_customer_id(stripe_customer_id: str, db_service: DatabaseService) -> Optional[UserInDB]:
    """Get user by Stripe customer ID"""
    result = db_service.execute_single_query(
        "SELECT * FROM user WHERE stripe_customer_id = %s", 
        (stripe_customer_id,)
    )
    if result:
        return UserInDB(**result)
    return None


def get_username_by_id(user_id: str, db_service: DatabaseService) -> str:
    """Get username by user ID"""
    user = get_user_by_id(user_id, db_service)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user.username


def create_user(username: str, email: str, hashed_password: str, db_service: DatabaseService) -> None:
    """Create a new user in the database"""
    uid = generate_user_uuid(db_service)
    if uid is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate user ID",
        )
    db_service.execute_modification_query(
        "INSERT INTO user (id, username, email, hashed_password) VALUES (%s, %s, %s, %s)",
        (uid, username, email, hashed_password)
    )


def update_user_last_seen(user_id: str, db_service: DatabaseService) -> None:
    """Update user's last seen timestamp"""
    current_time = datetime.now(timezone.utc)
    db_service.execute_modification_query(
        "UPDATE user SET last_seen = %s WHERE id = %s", 
        (current_time, user_id)
    )


def update_user_password(user_id: str, hashed_password: str, db_service: DatabaseService) -> None:
    """Update user's password"""
    db_service.execute_modification_query(
        "UPDATE user SET hashed_password = %s WHERE id = %s",
        (hashed_password, user_id)
    )


def update_user_fields(user_id: str, user_update: UpdateUser, db_service: DatabaseService) -> bool:
    """Update user fields dynamically"""
    update_fields = []
    update_values = []
    
    if user_update.username is not None:
        update_fields.append("username = %s")
        update_values.append(user_update.username)
    
    if update_fields:
        update_values.append(user_id)
        query = f"UPDATE user SET {', '.join(update_fields)} WHERE id = %s"  # nosec
        db_service.execute_modification_query(query, tuple(update_values))
    
    return len(update_fields) > 0  # Return True if any fields were updated


def generate_user_uuid(db_service: DatabaseService) -> Optional[str]:
    """Generate a new UUID for a user"""
    return db_service.generate_uuid("user")


def get_user_ids_to_names(user_ids: list[str], db_service: DatabaseService) -> dict[str, str]:
    """Get user names by their IDs"""
    if not user_ids:
        return {}
    
    placeholders = ', '.join(['%s'] * len(user_ids))
    try:
        results = db_service.execute_query(
            sql = f"SELECT id, username FROM user WHERE id IN ({placeholders})",  # nosec
            params=tuple(user_ids)
            )
    except Exception as e:
        logger.error(f"Error fetching user names: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch user names"
        )

    return {result['id']: result['username'] for result in results} if results else {}


def get_all_users(db_service: DatabaseService) -> list[UserInDBNoPassword]:
    """Get all users from the database"""
    try:
        results = db_service.execute_query("SELECT * FROM user")
        return [UserInDBNoPassword(**result) for result in results] if results else []
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch users"
        )


def delete_user(user_id: str, db_service: DatabaseService) -> dict:
    """Delete a user by ID"""
    # First check if user exists
    existing_user = get_user_by_id(user_id, db_service)
    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    try:
        db_service.execute_modification_query(
            sql="DELETE FROM user WHERE id = %s",
            params=(user_id,)
        )
        return {"detail": "User deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )


def update_user_premium_level(user_id: str, new_premium_level: int, db_service: DatabaseService, stripe_customer_id: Optional[str] = None) -> dict:
    """Update user's premium level"""
    try:
        if stripe_customer_id is not None:
            db_service.execute_modification_query(
                sql="UPDATE user SET premium_level = %s, stripe_customer_id = %s WHERE id = %s",
                params=(new_premium_level, stripe_customer_id, user_id)
            )
        else:
            db_service.execute_modification_query(
                sql="UPDATE user SET premium_level = %s WHERE id = %s",
                params=(new_premium_level, user_id)
            )
        return {"detail": "User premium level updated successfully"}
    except Exception as e:
        logger.error(f"Error updating user premium level: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user premium level",
        )