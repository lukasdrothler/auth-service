import pytest
from src.user_queries import (
    get_user_by_email, 
    get_user_by_id, 
    get_user_by_username,
    create_user
)
from src.managers.postgres import PostgresManager

def test_database_connection(pg_manager: PostgresManager):
    """Test that the database service can connect and execute queries"""
    assert pg_manager.db_connection_works() is True
    assert pg_manager.db_name == "test"

def test_create_and_get_user(pg_manager: PostgresManager):
    """Test creating a user and retrieving it via queries"""
    username = "testuser"
    email = "test@example.com"
    hashed_password = "hashed_secret"
    
    # Test create_user
    create_user(username, email, hashed_password, pg_manager)
    
    # Test get_user_by_email
    user = get_user_by_email(email, pg_manager)
    assert user is not None
    assert user.username == username
    assert user.email == email
    
    # Test get_user_by_id
    user_by_id = get_user_by_id(user.id, pg_manager)
    assert user_by_id is not None
    assert user_by_id.email == email
    
    # Test get_user_by_username
    user_by_username = get_user_by_username(username, pg_manager)
    assert user_by_username is not None
    assert user_by_username.id == user.id

