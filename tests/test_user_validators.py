import pytest
from fastapi import HTTPException, status
from src import user_validators
from src.models import CreateUser, UpdateUser, UpdatePassword
from src import user_queries

def test_validate_username_format_valid():
    user_validators.validate_username_format("valid_user123")

def test_validate_username_format_too_short():
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_username_format("ab")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "at least 3 characters" in exc_info.value.detail

def test_validate_username_format_invalid_chars():
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_username_format("user@name")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST

def test_validate_email_format_valid():
    user_validators.validate_email_format("test@example.com")

def test_validate_email_format_invalid():
    invalid_emails = ["test", "test@", "test@example", "test@.com"]
    for email in invalid_emails:
        with pytest.raises(HTTPException) as exc_info:
            user_validators.validate_email_format(email)
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST

def test_validate_password_strength_valid():
    user_validators.validate_password_strength("Password123")

def test_validate_password_strength_too_short():
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_password_strength("Pass1")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST

def test_validate_password_strength_no_uppercase():
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_password_strength("password123")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST

def test_validate_password_strength_no_number():
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_password_strength("Password")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST

def test_validate_username_unique(postgres_service):
    # Create a user first
    user_queries.create_user("existing_user", "existing@example.com", "hashed_pw", postgres_service)
    
    # Test with existing username
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_username_unique("existing_user", postgres_service)
    assert exc_info.value.status_code == status.HTTP_409_CONFLICT

    # Test with new username
    user_validators.validate_username_unique("new_user", postgres_service)

def test_validate_email_unique(postgres_service):
    # Create a user first
    user_queries.create_user("existing_user_email", "existing_email@example.com", "hashed_pw", postgres_service)
    
    # Test with existing email
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_email_unique("existing_email@example.com", postgres_service)
    assert exc_info.value.status_code == status.HTTP_409_CONFLICT

    # Test with new email
    user_validators.validate_email_unique("new_email@example.com", postgres_service)

def test_validate_new_user(postgres_service):
    # Valid user
    valid_user = CreateUser(
        username="new_valid_user",
        email="new_valid@example.com",
        password="Password123"
    )
    user_validators.validate_new_user(valid_user, postgres_service)

    # Duplicate username
    user_queries.create_user("dup_user", "dup@example.com", "hashed_pw", postgres_service)
    invalid_user = CreateUser(
        username="dup_user",
        email="another@example.com",
        password="Password123"
    )
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_new_user(invalid_user, postgres_service)
    assert exc_info.value.status_code == status.HTTP_409_CONFLICT

def test_validate_user_update(postgres_service):
    # Create a user to conflict with
    user_queries.create_user("conflict_user", "conflict@example.com", "hashed_pw", postgres_service)
    
    # Valid update (no conflict)
    update_valid = UpdateUser(username="new_unique_name")
    user_validators.validate_user_update(update_valid, postgres_service)

    # Invalid update (conflict)
    update_conflict = UpdateUser(username="conflict_user")
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_user_update(update_conflict, postgres_service)
    assert exc_info.value.status_code == status.HTTP_409_CONFLICT

def test_validate_new_password(auth_service):
    password_hash = auth_service.password_hash
    current_password = "OldPassword123"
    current_hashed = auth_service.get_password_hash(current_password)
    
    # Valid update
    update = UpdatePassword(current_password=current_password, new_password="NewPassword123")
    user_validators.validate_new_password(current_hashed, password_hash, update)

    # Invalid current password
    update_wrong = UpdatePassword(current_password="WrongPassword", new_password="NewPassword123")
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_new_password(current_hashed, password_hash, update_wrong)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST

    # Test with allow_same_as_current=False
    update_same = UpdatePassword(current_password=current_password, new_password=current_password)
    with pytest.raises(HTTPException) as exc_info:
        user_validators.validate_new_password(current_hashed, password_hash, update_same, allow_same_as_current=False)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST