import pytest
from fastapi import HTTPException, status
import jwt
from src.models import CreateUser, UpdateUser, UpdatePassword
from src import user_queries, verification_code_queries
from datetime import datetime, timedelta, timezone

def test_password_hashing(auth_service):
    password = "TestPassword123"
    hashed = auth_service.get_password_hash(password)
    assert hashed != password
    assert auth_service.verify_password(password, hashed) is True
    assert auth_service.verify_password("wrongpassword", hashed) is False

def test_register_new_user(auth_service, db_service):
    user_data = CreateUser(
        username="testuser",
        email="test@example.com",
        password="TestPassword123"
    )
    response = auth_service.register_new_user(user_data, db_service)
    
    assert response.username == user_data.username
    assert response.email == user_data.email
    assert response.value is not None
    assert len(response.value) == 6

    # Verify user is in DB
    user = auth_service.authenticate_user(user_data.username, user_data.password, db_service)
    assert user.username == user_data.username
    assert user.email == user_data.email

def test_authenticate_user(auth_service, db_service):
    # Setup user
    user_data = CreateUser(
        username="authuser",
        email="auth@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)

    # Test valid authentication with username
    user = auth_service.authenticate_user("authuser", "TestPassword123", db_service)
    assert user.username == "authuser"

    # Test valid authentication with email
    user = auth_service.authenticate_user("auth@example.com", "TestPassword123", db_service)
    assert user.username == "authuser"

    # Test invalid password
    with pytest.raises(HTTPException) as exc:
        auth_service.authenticate_user("authuser", "wrongpass", db_service)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

    # Test non-existent user
    with pytest.raises(HTTPException) as exc:
        auth_service.authenticate_user("nonexistent", "pass", db_service)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_create_bearer_token(auth_service, db_service):
    user_data = CreateUser(
        username="tokenuser",
        email="token@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("tokenuser", "TestPassword123", db_service)

    token = auth_service.create_bearer_token(user, db_service)
    assert isinstance(token, str)
    
    # Decode and verify
    payload = jwt.decode(token, auth_service.public_key, algorithms=[auth_service.algorithm])
    assert payload["sub"] == user.id
    assert payload["username"] == user.username

def test_get_token_for_user(auth_service, db_service):
    user_data = CreateUser(
        username="loginuser",
        email="login@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)

    # Test standard login
    token = auth_service.get_token_for_user("loginuser", "TestPassword123", db_service)
    assert token.access_token is not None
    assert token.refresh_token is None

    # Test login with stay_logged_in
    token_stay = auth_service.get_token_for_user("loginuser", "TestPassword123", db_service, stay_logged_in=True)
    assert token_stay.access_token is not None
    assert token_stay.refresh_token is not None

def test_refresh_access_token(auth_service, db_service):
    user_data = CreateUser(
        username="refreshuser",
        email="refresh@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    
    # Get refresh token
    token = auth_service.get_token_for_user("refreshuser", "TestPassword123", db_service, stay_logged_in=True)
    refresh_token = token.refresh_token

    # Use refresh token to get new access token
    new_token = auth_service.refresh_access_token(refresh_token, db_service)
    assert new_token.access_token is not None

    # Test invalid refresh token
    with pytest.raises(HTTPException) as exc:
        auth_service.refresh_access_token("invalid_token", db_service)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_user(auth_service, db_service):
    user_data = CreateUser(
        username="currentuser",
        email="current@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("currentuser", "TestPassword123", db_service)
    token = auth_service.create_bearer_token(user, db_service)

    fetched_user = auth_service.get_current_user(token, db_service)
    assert fetched_user.id == user.id
    assert fetched_user.username == user.username

    # Test invalid token
    with pytest.raises(HTTPException) as exc:
        auth_service.get_current_user("invalid_token", db_service)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_user_status_checks(auth_service, db_service):
    user_data = CreateUser(
        username="statususer",
        email="status@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("statususer", "TestPassword123", db_service)

    # Test active user
    active_user = auth_service.get_current_active_user(user)
    assert active_user.id == user.id

    # Test admin user (default is not admin)
    with pytest.raises(HTTPException) as exc:
        auth_service.get_current_admin_user(user)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN

def test_update_user(auth_service, db_service):
    user_data = CreateUser(
        username="updateuser",
        email="update@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("updateuser", "TestPassword123", db_service)

    update_data = UpdateUser(username="newusername")
    result = auth_service.update_user(user.id, update_data, db_service)
    assert result["detail"] == "User information updated successfully"

    # Verify update
    updated_user = auth_service.authenticate_user("newusername", "TestPassword123", db_service)
    assert updated_user.username == "newusername"

def test_update_user_no_changes(auth_service, db_service):
    user_data = CreateUser(
        username="nochangeuser",
        email="nochange@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("nochangeuser", "TestPassword123", db_service)

    # Update with same data (or None)
    update_data = UpdateUser(username=None)
    result = auth_service.update_user(user.id, update_data, db_service)
    assert result["detail"] == "No changes were made"

def test_update_password(auth_service, db_service):
    user_data = CreateUser(
        username="passuser",
        email="pass@example.com",
        password="OldPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("passuser", "OldPassword123", db_service)

    # Update password
    pwd_update = UpdatePassword(
        current_password="OldPassword123",
        new_password="NewPassword123"
    )
    result = auth_service.update_password(user.id, db_service, password_update=pwd_update)
    assert result["detail"] == "Password updated successfully"

    # Verify new password works
    new_user = auth_service.authenticate_user("passuser", "NewPassword123", db_service)
    assert new_user is not None

    # Verify old password fails
    with pytest.raises(HTTPException):
        auth_service.authenticate_user("passuser", "OldPassword123", db_service)

def test_update_password_direct(auth_service, db_service):
    # Test updating password without current password (e.g. admin reset or forgot password flow)
    user_data = CreateUser(
        username="resetuser",
        email="reset@example.com",
        password="OldPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("resetuser", "OldPassword123", db_service)

    new_password = "ResetPassword123"
    result = auth_service.update_password(user.id, db_service, new_password=new_password)
    assert result["detail"] == "Password updated successfully"

    # Verify new password works
    new_user = auth_service.authenticate_user("resetuser", "ResetPassword123", db_service)
    assert new_user is not None

def test_get_current_active_user_disabled(auth_service, db_service):
    user_data = CreateUser(
        username="disableduser",
        email="disabled@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("disableduser", "TestPassword123", db_service)
    
    # Manually disable user
    db_service.execute_modification_query(
        "UPDATE user SET disabled = 1 WHERE id = %s",
        (user.id,)
    )
    
    # Fetch fresh user object
    disabled_user = user_queries.get_user_by_id(user.id, db_service)
    
    with pytest.raises(HTTPException) as exc:
        auth_service.get_current_active_user(disabled_user)
    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc.value.detail == "Inactive user"


def test_generate_verification_code(auth_service):
    code = auth_service.generate_verification_code()
    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isdigit()

def test_check_can_send_verification(auth_service, db_service):
    # Setup user
    user_data = CreateUser(
        username="cooldown_user",
        email="cooldown@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("cooldown_user", "TestPassword123", db_service)
    
    # register_new_user already created a code, so cooldown should be active
    with pytest.raises(HTTPException) as excinfo:
        auth_service.check_can_send_verification(user.id, db_service)
    assert excinfo.value.status_code == 429
    
    # Manually update created_at to be > 30 seconds ago
    past_time = datetime.now(timezone.utc) - timedelta(seconds=31)
    db_service.execute_modification_query(
        "UPDATE verification_code SET created_at = %s WHERE user_id = %s",
        (past_time, user.id)
    )
    
    # Should pass now
    assert auth_service.check_can_send_verification(user.id, db_service) is None

def test_create_verification_code_for_user(auth_service, db_service):
    # Setup user
    user_data = CreateUser(
        username="verify_code_user",
        email="verify_code@example.com",
        password="TestPassword123"
    )
    auth_service.register_new_user(user_data, db_service)
    user = auth_service.authenticate_user("verify_code_user", "TestPassword123", db_service)
    
    # Manually update created_at to be > 30 seconds ago to allow new code
    past_time = datetime.now(timezone.utc) - timedelta(seconds=31)
    db_service.execute_modification_query(
        "UPDATE verification_code SET created_at = %s WHERE user_id = %s",
        (past_time, user.id)
    )
    
    # Create new code
    new_code = auth_service.create_verification_code_for_user(user.id, db_service)
    assert len(new_code) == 6
    
    # Verify in DB
    stored_code = verification_code_queries.get_verification_code_by_user_id(user.id, db_service)
    assert stored_code.value == new_code
