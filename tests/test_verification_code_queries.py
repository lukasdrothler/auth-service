import pytest
import os

from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

from src import verification_code_queries
from src import user_queries
from src.models import UserInDB

def test_generate_verification_code():
    code = verification_code_queries.generate_verification_code()
    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isdigit()

def test_create_and_get_verification_code(db_service):
    # Setup user
    username = "verify_user"
    email = "verify@example.com"
    password = "hashed_password"
    user_queries.create_user(username, email, password, db_service)
    user = user_queries.get_user_by_username(username, db_service)
    
    # Create verification code
    code = verification_code_queries.create_verification_code(user, email, db_service)
    assert len(code) == 6
    
    # Get verification code
    stored_code = verification_code_queries.get_verification_code_by_user_id(user.id, db_service)
    assert stored_code is not None
    assert stored_code.value == code
    assert stored_code.user_id == user.id
    assert stored_code.verified_at is None

    # Update verification code (create again)
    # We need to bypass the cooldown check for this test or wait/manipulate time
    # But create_verification_code calls check_can_send_verification.
    # check_can_send_verification checks if 30 seconds has passed.
    # To test update, we can manually update the created_at to be in the past.
    
    past_time = datetime.now(timezone.utc) - timedelta(minutes=2)
    db_service.execute_modification_query(
        "UPDATE verification_code SET created_at = %s WHERE user_id = %s",
        (past_time, user.id)
    )
    
    new_code = verification_code_queries.create_verification_code(user, email, db_service)
    assert new_code != code # It's random, so likely different
    
    stored_code_updated = verification_code_queries.get_verification_code_by_user_id(user.id, db_service)
    assert stored_code_updated.value == new_code
    
    # Ensure stored_code_updated.created_at is timezone-aware for comparison
    created_at = stored_code_updated.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
        
    assert created_at > past_time

def test_mark_verification_code_as_used(db_service):
    # Setup user
    username = "used_code_user"
    email = "used@example.com"
    password = "hashed_password"
    user_queries.create_user(username, email, password, db_service)
    user = user_queries.get_user_by_username(username, db_service)
    
    # Create code
    verification_code_queries.create_verification_code(user, email, db_service)
    
    # Mark as used
    verification_code_queries.mark_verification_code_as_used(user.id, db_service)
    
    stored_code = verification_code_queries.get_verification_code_by_user_id(user.id, db_service)
    assert stored_code.verified_at is not None

def test_check_can_send_verification(db_service):
    # Setup user
    username = "cooldown_user"
    email = "cooldown@example.com"
    password = "hashed_password"
    user_queries.create_user(username, email, password, db_service)
    user = user_queries.get_user_by_username(username, db_service)
    
    # No code exists, should be fine
    assert verification_code_queries.check_can_send_verification(user, db_service) is None
    
    # Create code
    verification_code_queries.create_verification_code(user, email, db_service)
    
    # Check immediately, should fail because of the 30 seconds cooldown
    with pytest.raises(HTTPException) as excinfo:
        verification_code_queries.check_can_send_verification(user, db_service)
    assert excinfo.value.status_code == 429
    
    # Manually update created_at to be > 30 seconds ago
    past_time = datetime.now(timezone.utc) - timedelta(seconds=31)
    db_service.execute_modification_query(
        "UPDATE verification_code SET created_at = %s WHERE user_id = %s",
        (past_time, user.id)
    )
    
    # Should pass now
    assert verification_code_queries.check_can_send_verification(user, db_service) is None

def test_update_user_email_verified_status(db_service):
    # Setup user
    username = "status_user"
    email = "status@example.com"
    password = "hashed_password"
    user_queries.create_user(username, email, password, db_service)
    user = user_queries.get_user_by_username(username, db_service)
    
    assert user.email_verified is False
    
    verification_code_queries.update_user_email_verified_status(user.id, db_service, verified=True)
    
    updated_user = user_queries.get_user_by_id(user.id, db_service)
    assert updated_user.email_verified is True
    
    verification_code_queries.update_user_email_verified_status(user.id, db_service, verified=False)
    
    updated_user = user_queries.get_user_by_id(user.id, db_service)
    assert updated_user.email_verified is False

def test_update_user_email(db_service):
    # Setup user
    username = "email_update_user"
    email = "old@example.com"
    password = "hashed_password"
    user_queries.create_user(username, email, password, db_service)
    user = user_queries.get_user_by_username(username, db_service)
    
    new_email = "new@example.com"
    verification_code_queries.update_user_email(user.id, new_email, db_service)
    
    updated_user = user_queries.get_user_by_id(user.id, db_service)
    assert updated_user.email == new_email
