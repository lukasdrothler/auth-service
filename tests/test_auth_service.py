import pytest
from fastapi import HTTPException, status
import jwt
from src.models import CreateUser, UpdateUser, UpdatePassword
from src import user_queries, verification_code_queries
from datetime import datetime, timedelta, timezone

def test_password_hashing(auth_manager):
    password = "TestPassword123"
    hashed = auth_manager.get_password_hash(password)
    assert hashed != password
    assert auth_manager.verify_password(password, hashed) is True
    assert auth_manager.verify_password("wrongpassword", hashed) is False

def test_register_new_user(auth_manager, pg_manager):
    user_data = CreateUser(
        username="testuser",
        email="test@example.com",
        password="TestPassword123"
    )
    response = auth_manager.register_new_user(user_data, pg_manager)
    
    assert response.username == user_data.username
    assert response.email == user_data.email
    assert response.value is not None
    assert len(response.value) == 6

    # Verify user is in DB
    user = auth_manager.authenticate_user(user_data.username, user_data.password, pg_manager)
    assert user.username == user_data.username
    assert user.email == user_data.email

def test_authenticate_user(auth_manager, pg_manager):
    # Setup user
    user_data = CreateUser(
        username="authuser",
        email="auth@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)

    # Test valid authentication with username
    user = auth_manager.authenticate_user("authuser", "TestPassword123", pg_manager)
    assert user.username == "authuser"

    # Test valid authentication with email
    user = auth_manager.authenticate_user("auth@example.com", "TestPassword123", pg_manager)
    assert user.username == "authuser"

    # Test invalid password
    with pytest.raises(HTTPException) as exc:
        auth_manager.authenticate_user("authuser", "wrongpass", pg_manager)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

    # Test non-existent user
    with pytest.raises(HTTPException) as exc:
        auth_manager.authenticate_user("nonexistent", "pass", pg_manager)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_create_bearer_token(auth_manager, pg_manager):
    user_data = CreateUser(
        username="tokenuser",
        email="token@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("tokenuser", "TestPassword123", pg_manager)

    token = auth_manager.create_bearer_token(user, pg_manager)
    assert isinstance(token, str)
    
    # Decode and verify
    payload = jwt.decode(token, auth_manager.public_key, algorithms=[auth_manager.algorithm])
    assert payload["sub"] == user.id
    assert payload["username"] == user.username

def test_get_token_for_user(auth_manager, pg_manager):
    user_data = CreateUser(
        username="loginuser",
        email="login@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)

    # Test standard login
    token = auth_manager.get_token_for_user("loginuser", "TestPassword123", pg_manager)
    assert token.access_token is not None
    assert token.refresh_token is None

    # Test login with stay_logged_in
    token_stay = auth_manager.get_token_for_user("loginuser", "TestPassword123", pg_manager, stay_logged_in=True)
    assert token_stay.access_token is not None
    assert token_stay.refresh_token is not None

def test_refresh_access_token(auth_manager, pg_manager):
    user_data = CreateUser(
        username="refreshuser",
        email="refresh@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    
    # Get refresh token
    token = auth_manager.get_token_for_user("refreshuser", "TestPassword123", pg_manager, stay_logged_in=True)
    refresh_token = token.refresh_token

    # Use refresh token to get new access token
    new_token = auth_manager.refresh_access_token(refresh_token, pg_manager)
    assert new_token.access_token is not None

    # Test invalid refresh token
    with pytest.raises(HTTPException) as exc:
        auth_manager.refresh_access_token("invalid_token", pg_manager)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_user(auth_manager, pg_manager):
    user_data = CreateUser(
        username="currentuser",
        email="current@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("currentuser", "TestPassword123", pg_manager)
    token = auth_manager.create_bearer_token(user, pg_manager)

    fetched_user = auth_manager.get_current_user(token, pg_manager)
    assert fetched_user.id == user.id
    assert fetched_user.username == user.username

    # Test invalid token
    with pytest.raises(HTTPException) as exc:
        auth_manager.get_current_user("invalid_token", pg_manager)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_user_status_checks(auth_manager, pg_manager):
    user_data = CreateUser(
        username="statususer",
        email="status@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("statususer", "TestPassword123", pg_manager)

    # Test active user
    active_user = auth_manager.get_current_active_user(user)
    assert active_user.id == user.id

    # Test admin user (default is not admin)
    with pytest.raises(HTTPException) as exc:
        auth_manager.get_current_admin_user(user)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN

def test_update_user(auth_manager, pg_manager):
    user_data = CreateUser(
        username="updateuser",
        email="update@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("updateuser", "TestPassword123", pg_manager)

    update_data = UpdateUser(username="newusername")
    result = auth_manager.update_user(user.id, update_data, pg_manager)
    assert result["detail"] == "User information updated successfully"

    # Verify update
    updated_user = auth_manager.authenticate_user("newusername", "TestPassword123", pg_manager)
    assert updated_user.username == "newusername"

def test_update_user_no_changes(auth_manager, pg_manager):
    user_data = CreateUser(
        username="nochangeuser",
        email="nochange@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("nochangeuser", "TestPassword123", pg_manager)

    # Update with same data (or None)
    update_data = UpdateUser(username=None)
    result = auth_manager.update_user(user.id, update_data, pg_manager)
    assert result["detail"] == "No changes were made"

def test_update_password(auth_manager, pg_manager):
    user_data = CreateUser(
        username="passuser",
        email="pass@example.com",
        password="OldPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("passuser", "OldPassword123", pg_manager)

    # Update password
    pwd_update = UpdatePassword(
        current_password="OldPassword123",
        new_password="NewPassword123"
    )
    result = auth_manager.update_password(user.id, pg_manager, password_update=pwd_update)
    assert result["detail"] == "Password updated successfully"

    # Verify new password works
    new_user = auth_manager.authenticate_user("passuser", "NewPassword123", pg_manager)
    assert new_user is not None

    # Verify old password fails
    with pytest.raises(HTTPException):
        auth_manager.authenticate_user("passuser", "OldPassword123", pg_manager)

def test_update_password_direct(auth_manager, pg_manager):
    # Test updating password without current password (e.g. admin reset or forgot password flow)
    user_data = CreateUser(
        username="resetuser",
        email="reset@example.com",
        password="OldPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("resetuser", "OldPassword123", pg_manager)

    new_password = "ResetPassword123"
    result = auth_manager.update_password(user.id, pg_manager, new_password=new_password)
    assert result["detail"] == "Password updated successfully"

    # Verify new password works
    new_user = auth_manager.authenticate_user("resetuser", "ResetPassword123", pg_manager)
    assert new_user is not None

def test_get_current_active_user_disabled(auth_manager, pg_manager):
    user_data = CreateUser(
        username="disableduser",
        email="disabled@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("disableduser", "TestPassword123", pg_manager)
    
    # Manually disable user
    pg_manager.execute_modification_query(
        'UPDATE "user" SET disabled = %s WHERE id = %s',
        (True, user.id)
    )
    
    # Fetch fresh user object
    disabled_user = user_queries.get_user_by_id(user.id, pg_manager)
    
    with pytest.raises(HTTPException) as exc:
        auth_manager.get_current_active_user(disabled_user)
    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc.value.detail == "Inactive user"


def test_generate_verification_code(auth_manager):
    code = auth_manager.generate_verification_code()
    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isdigit()

def test_check_can_send_verification(auth_manager, pg_manager):
    # Setup user
    user_data = CreateUser(
        username="cooldown_user",
        email="cooldown@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("cooldown_user", "TestPassword123", pg_manager)
    
    # register_new_user already created a code, so cooldown should be active
    with pytest.raises(HTTPException) as excinfo:
        auth_manager.check_can_send_verification(user.id, pg_manager)
    assert excinfo.value.status_code == 429
    
    # Manually update created_at to be > 30 seconds ago
    past_time = datetime.now(timezone.utc) - timedelta(seconds=31)
    pg_manager.execute_modification_query(
        "UPDATE verification_code SET created_at = %s WHERE user_id = %s",
        (past_time, user.id)
    )
    
    # Should pass now
    assert auth_manager.check_can_send_verification(user.id, pg_manager) is None

def test_create_verification_code_for_user(auth_manager, pg_manager):
    # Setup user
    user_data = CreateUser(
        username="verify_code_user",
        email="verify_code@example.com",
        password="TestPassword123"
    )
    auth_manager.register_new_user(user_data, pg_manager)
    user = auth_manager.authenticate_user("verify_code_user", "TestPassword123", pg_manager)
    
    # Manually update created_at to be > 30 seconds ago to allow new code
    past_time = datetime.now(timezone.utc) - timedelta(seconds=31)
    pg_manager.execute_modification_query(
        "UPDATE verification_code SET created_at = %s WHERE user_id = %s",
        (past_time, user.id)
    )
    
    # Create new code
    new_code = auth_manager.create_verification_code_for_user(user.id, pg_manager)
    assert len(new_code) == 6
    
    # Verify in DB
    stored_code = verification_code_queries.get_verification_code_by_user_id(user.id, pg_manager)
    assert stored_code.value == new_code
