import pytest
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

from src.managers.postgres import PostgresManager
from src.managers.auth import AuthManager
from src.models import VerifyEmailRequest, UpdateForgottenPassword, CreateUser
from src.email_verification import (
    verify_user_email_with_code,
    verify_user_email_change,
    verify_forgot_password_with_code,
    update_forgotten_password_with_code
)
from src import user_queries, verification_code_queries

# Helper to create a user and a verification code
def create_user_and_code(auth_manager: AuthManager, pg_manager: PostgresManager, username="testuser", email="test@example.com"):
    user_data = CreateUser(username=username, email=email, password="TestPassword123")
    response = auth_manager.register_new_user(user_data, pg_manager)
    user = user_queries.get_user_by_email(email, pg_manager)
    return user, response.value

def test_verify_user_email_with_code_success(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    
    request = VerifyEmailRequest(email=user.email, code=code)
    result = verify_user_email_with_code(request, pg_manager)
    
    assert result == {"detail": "Email verified successfully!"}
    
    verification_record = verification_code_queries.get_verification_code_by_user_id(user.id, pg_manager)
    assert verification_record.verified_at is not None

def test_verify_user_email_with_code_user_not_found(pg_manager: PostgresManager):
    request = VerifyEmailRequest(email="nonexistent@example.com", code="123456")
    
    with pytest.raises(HTTPException) as excinfo:
        verify_user_email_with_code(request, pg_manager)
    assert excinfo.value.status_code == 404
    assert excinfo.value.detail == "User not found"

def test_verify_user_email_with_code_no_code_found(pg_manager: PostgresManager):
    user_queries.create_user("nocode", "nocode@example.com", "pass", pg_manager)
    request = VerifyEmailRequest(email="nocode@example.com", code="123456")
    
    with pytest.raises(HTTPException) as excinfo:
        verify_user_email_with_code(request, pg_manager)
    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "No verification code found for this user"

def test_verify_user_email_with_code_invalid_code(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    request = VerifyEmailRequest(email=user.email, code="000000") # Wrong code
    
    with pytest.raises(HTTPException) as excinfo:
        verify_user_email_with_code(request, pg_manager)
    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "Invalid verification code"

def test_verify_user_email_with_code_expired(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    
    # Manually expire the code
    expired_time = datetime.now(timezone.utc) - timedelta(hours=25)
    pg_manager.execute_modification_query(
        "UPDATE verification_code SET created_at = %s WHERE user_id = %s",
        (expired_time, user.id)
    )
    
    request = VerifyEmailRequest(email=user.email, code=code)
    
    with pytest.raises(HTTPException) as excinfo:
        verify_user_email_with_code(request, pg_manager)
    assert excinfo.value.status_code == 400
    assert "expired" in excinfo.value.detail

def test_verify_user_email_change_success(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    new_email = "newemail@example.com"
    
    request = VerifyEmailRequest(email=new_email, code=code)
    result = verify_user_email_change(user, request, pg_manager)
    
    assert result == {"detail": "Email address updated successfully"}
    
    updated_user = user_queries.get_user_by_id(user.id, pg_manager)
    assert updated_user.email == new_email

def test_verify_user_email_change_invalid_format(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    request = VerifyEmailRequest(email="invalid-email", code=code)
    
    with pytest.raises(HTTPException) as excinfo:
        verify_user_email_change(user, request, pg_manager)
    assert excinfo.value.status_code == 400
    assert "Invalid email format" in excinfo.value.detail

def test_verify_user_email_change_email_taken(pg_manager: PostgresManager, auth_manager: AuthManager):
    user1, code1 = create_user_and_code(auth_manager, pg_manager, "user1", "user1@example.com")
    create_user_and_code(auth_manager, pg_manager, "user2", "user2@example.com")
    
    request = VerifyEmailRequest(email="user2@example.com", code=code1)
    
    with pytest.raises(HTTPException) as excinfo:
        verify_user_email_change(user1, request, pg_manager)
    assert excinfo.value.status_code == 409
    assert "Email is already registered" in excinfo.value.detail

def test_verify_forgot_password_with_code_success(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    request = VerifyEmailRequest(email=user.email, code=code)
    
    result = verify_forgot_password_with_code(request, pg_manager)
    assert result == {"detail": "E-Mail successfully verified. You can now reset your password."}

def test_update_forgotten_password_with_code_success(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    new_password = "NewPassword123!"
    
    update_request = UpdateForgottenPassword(
        email=user.email,
        new_password=new_password,
        verification_code=code
    )
    
    result = update_forgotten_password_with_code(update_request, auth_manager, pg_manager)
    
    assert result == {"detail": "Password updated successfully"}
    
    # Verify password was updated
    updated_user = user_queries.get_user_by_id(user.id, pg_manager)
    assert auth_manager.verify_password(new_password, updated_user.hashed_password)
    
    # Check if code is marked as used
    verification_record = verification_code_queries.get_verification_code_by_user_id(user.id, pg_manager)
    assert verification_record.verified_at is not None

def test_update_forgotten_password_with_code_invalid_code(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager)
    update_request = UpdateForgottenPassword(
        email=user.email,
        new_password="NewPassword123!",
        verification_code="wrongcode"
    )
    
    with pytest.raises(HTTPException) as excinfo:
        update_forgotten_password_with_code(update_request, auth_manager, pg_manager)
    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "Invalid verification code"
    
    # Verify password was NOT updated
    updated_user = user_queries.get_user_by_id(user.id, pg_manager)
    assert updated_user.hashed_password == user.hashed_password

def test_verify_user_email_updates_status(pg_manager: PostgresManager, auth_manager: AuthManager):
    """Test that verifying email actually updates the user's email_verified status in DB"""
    user, code = create_user_and_code(auth_manager, pg_manager, "verify_status_user", "verify_status@example.com")
    
    # Verify initial state
    assert user.email_verified is False
    
    request = VerifyEmailRequest(email=user.email, code=code)
    verify_user_email_with_code(request, pg_manager)
    
    # Fetch user again to check status
    updated_user = user_queries.get_user_by_id(user.id, pg_manager)
    assert updated_user.email_verified is True

def test_verify_user_email_change_already_used(pg_manager: PostgresManager, auth_manager: AuthManager):
    user, code = create_user_and_code(auth_manager, pg_manager, "used_code_user", "used_code@example.com")
    
    request = VerifyEmailRequest(email=user.email, code=code)
    
    # First verification should succeed
    verify_user_email_with_code(request, pg_manager)
    
    # Second verification should fail
    with pytest.raises(HTTPException) as excinfo:
        verify_user_email_with_code(request, pg_manager)
    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "Verification code has already been used."
