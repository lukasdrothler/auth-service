import pytest
from fastapi import HTTPException
from src.services.postgres_service import PostgresService
from src.models import UpdateUser
from src.user_queries import (
    get_user_by_id,
    get_user_by_username,
    get_user_by_email,
    get_user_by_username_and_email,
    get_user_by_stripe_customer_id,
    get_username_by_id,
    create_user,
    update_user_last_seen,
    update_user_password,
    update_user_fields,
    get_user_ids_to_names,
    get_all_users,
    delete_user,
    update_user_premium_level,
)

def test_create_user(postgres_service: PostgresService):
    username = "testuser"
    email = "test@example.com"
    hashed_password = "hashedpassword123"
    
    create_user(username, email, hashed_password, postgres_service)
    
    user = get_user_by_username(username, postgres_service)
    assert user is not None
    assert user.username == username
    assert user.email == email
    assert user.hashed_password == hashed_password
    assert user.id is not None

def test_get_user_by_id(postgres_service: PostgresService):
    username = "testuser_id"
    email = "testid@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    created_user = get_user_by_username(username, postgres_service)
    
    user = get_user_by_id(created_user.id, postgres_service)
    assert user is not None
    assert user.id == created_user.id
    assert user.username == username

    assert get_user_by_id("nonexistent", postgres_service) is None

def test_get_user_by_username(postgres_service: PostgresService):
    username = "testuser_name"
    email = "testname@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    
    user = get_user_by_username(username, postgres_service)
    assert user is not None
    assert user.username == username

    # Case insensitive check
    user_upper = get_user_by_username(username.upper(), postgres_service)
    assert user_upper is not None
    assert user_upper.id == user.id

    assert get_user_by_username("nonexistent", postgres_service) is None

def test_get_user_by_email(postgres_service: PostgresService):
    username = "testuser_email"
    email = "testemail@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    
    user = get_user_by_email(email, postgres_service)
    assert user is not None
    assert user.email == email

    # Case insensitive check
    user_upper = get_user_by_email(email.upper(), postgres_service)
    assert user_upper is not None
    assert user_upper.id == user.id

    assert get_user_by_email("nonexistent@example.com", postgres_service) is None

def test_get_user_by_username_and_email(postgres_service: PostgresService):
    username = "testuser_both"
    email = "testboth@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    
    user = get_user_by_username_and_email(username, email, postgres_service)
    assert user is not None
    assert user.username == username
    assert user.email == email

    assert get_user_by_username_and_email("wrong", email, postgres_service) is None
    assert get_user_by_username_and_email(username, "wrong", postgres_service) is None

def test_get_user_by_stripe_customer_id(postgres_service: PostgresService):
    username = "testuser_stripe"
    email = "teststripe@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    user = get_user_by_username(username, postgres_service)
    
    # Manually update stripe_customer_id since create_user doesn't set it
    stripe_id = "cus_12345"
    update_user_premium_level(user.id, 1, postgres_service, stripe_customer_id=stripe_id)
    
    fetched_user = get_user_by_stripe_customer_id(stripe_id, postgres_service)
    assert fetched_user is not None
    assert fetched_user.id == user.id
    
    assert get_user_by_stripe_customer_id("nonexistent", postgres_service) is None

def test_get_username_by_id(postgres_service: PostgresService):
    username = "testuser_getname"
    email = "testgetname@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    user = get_user_by_username(username, postgres_service)
    
    fetched_username = get_username_by_id(user.id, postgres_service)
    assert fetched_username == username

    with pytest.raises(HTTPException) as excinfo:
        get_username_by_id("nonexistent", postgres_service)
    assert excinfo.value.status_code == 404

def test_update_user_last_seen(postgres_service: PostgresService):
    username = "testuser_lastseen"
    email = "testlastseen@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    user = get_user_by_username(username, postgres_service)
    
    original_last_seen = user.last_seen
    
    update_user_last_seen(user.id, postgres_service)
    
    updated_user = get_user_by_id(user.id, postgres_service)
    assert updated_user.last_seen is not None
    if original_last_seen:
        assert updated_user.last_seen > original_last_seen

def test_update_user_password(postgres_service: PostgresService):
    username = "testuser_pwd"
    email = "testpwd@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    user = get_user_by_username(username, postgres_service)
    
    new_password = "newhashedpassword456"
    update_user_password(user.id, new_password, postgres_service)
    
    updated_user = get_user_by_id(user.id, postgres_service)
    assert updated_user.hashed_password == new_password

def test_update_user_fields(postgres_service: PostgresService):
    username = "testuser_fields"
    email = "testfields@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    user = get_user_by_username(username, postgres_service)
    
    new_username = "updated_username"
    update_data = UpdateUser(username=new_username)
    
    updated = update_user_fields(user.id, update_data, postgres_service)
    assert updated is True
    
    updated_user = get_user_by_id(user.id, postgres_service)
    assert updated_user.username == new_username

    # Test no update
    update_data_empty = UpdateUser(username=None)
    updated_empty = update_user_fields(user.id, update_data_empty, postgres_service)
    assert updated_empty is False

def test_get_user_ids_to_names(postgres_service: PostgresService):
    user1_data = ("user1", "user1@example.com", "pass1")
    user2_data = ("user2", "user2@example.com", "pass2")
    
    create_user(*user1_data, postgres_service)
    create_user(*user2_data, postgres_service)
    
    user1 = get_user_by_username(user1_data[0], postgres_service)
    user2 = get_user_by_username(user2_data[0], postgres_service)
    
    mapping = get_user_ids_to_names([user1.id, user2.id], postgres_service)
    
    assert len(mapping) == 2
    assert mapping[user1.id] == user1.username
    assert mapping[user2.id] == user2.username
    
    assert get_user_ids_to_names([], postgres_service) == {}

def test_get_all_users(postgres_service: PostgresService):
    # Clear existing users first if any (though fixture should handle cleanup, 
    # but other tests might have run in same session if scope was session, 
    # but here scope is function so it should be clean)
    
    users = get_all_users(postgres_service)
    initial_count = len(users)
    
    create_user("user_all_1", "all1@example.com", "pass", postgres_service)
    create_user("user_all_2", "all2@example.com", "pass", postgres_service)
    
    users = get_all_users(postgres_service)
    assert len(users) == initial_count + 2

def test_delete_user(postgres_service: PostgresService):
    username = "testuser_delete"
    email = "testdelete@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    user = get_user_by_username(username, postgres_service)
    
    result = delete_user(user.id, postgres_service)
    assert result["detail"] == "User deleted successfully"
    
    assert get_user_by_id(user.id, postgres_service) is None
    
    with pytest.raises(HTTPException) as excinfo:
        delete_user(user.id, postgres_service)
    assert excinfo.value.status_code == 404

def test_update_user_premium_level(postgres_service: PostgresService):
    username = "testuser_premium"
    email = "testpremium@example.com"
    hashed_password = "hashedpassword123"
    create_user(username, email, hashed_password, postgres_service)
    user = get_user_by_username(username, postgres_service)
    
    # Update level only
    update_user_premium_level(user.id, 2, postgres_service)
    updated_user = get_user_by_id(user.id, postgres_service)
    assert updated_user.premium_level == 2
    
    # Update level and stripe id
    stripe_id = "cus_new"
    update_user_premium_level(user.id, 3, postgres_service, stripe_customer_id=stripe_id)
    updated_user_2 = get_user_by_id(user.id, postgres_service)
    assert updated_user_2.premium_level == 3
    assert updated_user_2.stripe_customer_id == stripe_id
