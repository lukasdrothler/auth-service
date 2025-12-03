import pytest
from src.user_queries import (
    get_user_by_email, 
    get_user_by_id, 
    get_user_by_username,
    create_user
)
from src.database_service import DatabaseService

def test_database_connection(db_service: DatabaseService):
    """Test that the database service can connect and execute queries"""
    assert db_service.db_connection_works() is True
    assert db_service.database == "auth_test"

def test_create_and_get_user(db_service: DatabaseService):
    """Test creating a user and retrieving it via queries"""
    username = "testuser"
    email = "test@example.com"
    hashed_password = "hashed_secret"
    
    # Test create_user
    create_user(username, email, hashed_password, db_service)
    
    # Test get_user_by_email
    user = get_user_by_email(email, db_service)
    assert user is not None
    assert user.username == username
    assert user.email == email
    
    # Test get_user_by_id
    user_by_id = get_user_by_id(user.id, db_service)
    assert user_by_id is not None
    assert user_by_id.email == email
    
    # Test get_user_by_username
    user_by_username = get_user_by_username(username, db_service)
    assert user_by_username is not None
    assert user_by_username.id == user.id

