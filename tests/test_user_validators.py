import pytest
from fastapi import HTTPException, status
from src import user_validators

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