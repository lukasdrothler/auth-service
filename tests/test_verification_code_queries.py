import pytest

from src import verification_code_queries
from src import user_queries

def test_upsert_and_get_verification_code(db_service):
    # Setup user
    username = "verify_user"
    email = "verify@example.com"
    password = "hashed_password"
    user_queries.create_user(username, email, password, db_service)
    user = user_queries.get_user_by_username(username, db_service)
    
    code = "123456"
    
    # Create verification code
    verification_code_queries.upsert_verification_code(user.id, code, db_service)
    
    # Get verification code
    stored_code = verification_code_queries.get_verification_code_by_user_id(user.id, db_service)
    assert stored_code is not None
    assert stored_code.value == code
    assert stored_code.user_id == user.id
    assert stored_code.verified_at is None

    # Update verification code
    new_code = "654321"
    verification_code_queries.upsert_verification_code(user.id, new_code, db_service)
    
    stored_code_updated = verification_code_queries.get_verification_code_by_user_id(user.id, db_service)
    assert stored_code_updated.value == new_code
    assert stored_code_updated.value != code

def test_mark_verification_code_as_used(db_service):
    # Setup user
    username = "used_code_user"
    email = "used@example.com"
    password = "hashed_password"
    user_queries.create_user(username, email, password, db_service)
    user = user_queries.get_user_by_username(username, db_service)
    
    code = "123456"
    # Create code
    verification_code_queries.upsert_verification_code(user.id, code, db_service)
    
    # Mark as used
    verification_code_queries.mark_verification_code_as_used(user.id, db_service)
    
    stored_code = verification_code_queries.get_verification_code_by_user_id(user.id, db_service)
    assert stored_code.verified_at is not None

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
