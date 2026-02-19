from src.models import CreateVerificationCodeResponse, UserInDB, CreateUser, UpdateUser, UpdatePassword, Token, TokenData
from src.managers.postgres import PostgresManager

from src import user_queries, verification_code_queries, user_validators

from datetime import datetime, timedelta, timezone
from typing import Optional
from pwdlib import PasswordHash, exceptions as pwdlib_exceptions
from jwt.exceptions import InvalidTokenError
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import jwt
import os
import logging
import secrets

logger = logging.getLogger(__name__)

class AuthManager:
    """Manager for handling authentication-related operations"""
    
    def __init__(self,
                 access_token_expire_minutes=30,
                 refresh_token_expire_days=30,
                 token_url="token",  # nosec
                 private_key_filename: str = "private_key.pem",
                 public_key_filename: str = "public_key.pem",
                 keys_dir: str = None
                 ):
        
        """Initialize the authentication configuration"""
        if keys_dir is not None:
            _rsa_keys_path = keys_dir
            logger.info(f"Using  '{_rsa_keys_path}' from provided keys_dir argument")
        elif "RSA_KEYS_DIR" in os.environ:
            _rsa_keys_path = os.environ["RSA_KEYS_DIR"]
            logger.info(f"Using  '{_rsa_keys_path}' from environment variable 'RSA_KEYS_DIR'")
        else:
            # Default to 'keys' directory at project root (parent of src/)
            _rsa_keys_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")
            logger.info(f"Using default RSA keys directory since 'RSA_KEYS_DIR' not set")
        
        ## create dir if not exists
        if not os.path.exists(_rsa_keys_path):
            os.makedirs(_rsa_keys_path)
            logger.info(f"Created RSA keys directory at '{_rsa_keys_path}'")
        
        self.algorithm = "RS256"
        private_key_path = os.path.join(_rsa_keys_path, private_key_filename)
        public_key_path = os.path.join(_rsa_keys_path, public_key_filename)
        
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            logger.info(f"No RSA keys found at {_rsa_keys_path}, with filenames {private_key_filename} and {public_key_filename}. Generating new keys..")
            
            key = rsa.generate_private_key(
                backend=default_backend(),
                public_exponent=65537,
                key_size=2048
            )
            private_key = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            public_key = key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(private_key_path, 'wb') as f:
                f.write(private_key)
            with open(public_key_path, 'wb') as f:
                f.write(public_key)

        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
        
        # Store configuration values
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.token_url = token_url

        self.password_hash = PasswordHash.recommended()
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=self.token_url)

    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return self.password_hash.verify(plain_password, hashed_password)
    

    def get_password_hash(self, password: str) -> str:
        """Hash a password"""
        return self.password_hash.hash(password)


    def create_bearer_token(self, user: UserInDB, pg_manager: PostgresManager, is_refresh: bool = False) -> str:
        """Create a JWT token"""
        data = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "email_verified": user.email_verified,
            "premium_level": user.premium_level,
            "is_admin": user.is_admin,
            "stripe_customer_id": user.stripe_customer_id,
            "disabled": user.disabled,
            "last_seen": user.last_seen.isoformat() if user.last_seen else None,
            "created_at": user.created_at.isoformat() if user.created_at else None
            }
        to_encode = data.copy()
        if is_refresh:
            expires_delta = timedelta(days=self.refresh_token_expire_days)
        else:
            expires_delta = timedelta(minutes=self.access_token_expire_minutes)
        
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.private_key, algorithm=self.algorithm)
        user_queries.update_user_last_seen(
            user_id=user.id,
            pg_manager=pg_manager
            )
        return encoded_jwt


    def authenticate_user(
            self,
            username_or_email: str,
            password: str,
            pg_manager: PostgresManager
        ) -> UserInDB:
        """Authenticate a user"""
        user = None
        user = user_queries.get_user_by_username(
            username=username_or_email,
            pg_manager=pg_manager
            )
        if not user:
            user = user_queries.get_user_by_email(
                email=username_or_email,
                pg_manager=pg_manager
                )
            if not user:
                logger.error(f"Could not find user with username or email '{username_or_email}'")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        if not user.hashed_password or user.hashed_password.strip() == "":
            raise HTTPException(
                status_code=status.HTTP_417_EXPECTATION_FAILED,
                detail="User does not have a password set"
            )

        try:
            if not self.verify_password(password, user.hashed_password):
                logger.error(f"Invalid password for user '{username_or_email}'")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        # Users with an old passlib hash. Notify them to reset their password
        except pwdlib_exceptions.UnknownHashError:
            raise HTTPException(
                status_code=status.HTTP_417_EXPECTATION_FAILED,
                detail="User has an old password hash that cannot be verified"
            )
        return user
    

    def get_token_for_user(
            self,
            username_or_email: str,
            password: str,
            pg_manager: PostgresManager,
            stay_logged_in: bool = False
            ) -> Token:
        
        user = self.authenticate_user(
            username_or_email=username_or_email,
            password=password,
            pg_manager=pg_manager
            )
        
        access_token = self.create_bearer_token(
            user=user,
            pg_manager=pg_manager
            )
        if stay_logged_in:
            refresh_token = self.create_bearer_token(
                user=user,
                pg_manager=pg_manager,
                is_refresh=True)
            return Token(access_token=access_token, refresh_token=refresh_token)
        
        return Token(access_token=access_token)
    

    def refresh_access_token(
            self,
            refresh_token: str,
            pg_manager: PostgresManager
            ) -> Token:
        """Refresh an access token using a refresh token"""
        credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
        )
        
        try:
            payload = jwt.decode(refresh_token, self.public_key, algorithms=[self.algorithm])
            user_id = payload.get("sub")
            if user_id is None:
                raise credentials_exception
            token_data = TokenData(user_id=user_id)
        except InvalidTokenError:
            raise credentials_exception
        
        # Get and validate current user
        user = user_queries.get_user_by_id(token_data.user_id, pg_manager=pg_manager)
        if user is None or user.disabled:
            raise credentials_exception
        
        access_token = self.create_bearer_token(
            user=user,
            pg_manager=pg_manager
            )
        return Token(access_token=access_token)
    
    def generate_verification_code(self) -> str:
        """Generate a 6-digit verification code"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

    def check_can_send_verification(self, user_id: str, pg_manager: PostgresManager) -> None:
        """Check if user can resend verification code (30 seconds cooldown)"""
        existing_code = verification_code_queries.get_verification_code_by_user_id(user_id, pg_manager)

        if not existing_code:
            return None
        
        created_at = existing_code.created_at
        
        # Check if 30 seconds has passed since last code generation
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
            
        time_diff = datetime.now(timezone.utc) - created_at
        if time_diff <= timedelta(seconds=30):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Please wait 30 seconds before requesting another verification code.",
            )
        return None

    def create_verification_code_for_user(self, user_id: str, pg_manager: PostgresManager) -> str:
        """Create or update regular verification code for user"""
        self.check_can_send_verification(user_id, pg_manager)
        
        new_code = self.generate_verification_code()
        
        verification_code_queries.upsert_verification_code(
            user_id=user_id,
            code=new_code,
            pg_manager=pg_manager
        )
        return new_code

    def register_new_user(self, user: CreateUser, pg_manager: PostgresManager) -> CreateVerificationCodeResponse:
        """Create a new user"""
        user_validators.validate_new_user(user, pg_manager)
        hashed_password = self.get_password_hash(user.password)
        
        user_queries.create_user(
            username=user.username,
            email=user.email,
            hashed_password=hashed_password,
            pg_manager=pg_manager,
        )
        
        created_user = user_queries.get_user_by_username(user.username, pg_manager)

        # Generate 6-digit verification code
        verification_code = self.create_verification_code_for_user(
            user_id=created_user.id,
            pg_manager=pg_manager,
        )

        return CreateVerificationCodeResponse(
            username=user.username,
            email=user.email,
            value=verification_code
        )
    
    def resend_verification_code(self, email: str, pg_manager: PostgresManager) -> CreateVerificationCodeResponse:
        """Resend verification code to user's email"""
        user = user_queries.get_user_by_email(email, pg_manager)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User with the specified email not found"
            )
        
        self.check_can_send_verification(user.id, pg_manager)
        
        # Generate new verification code
        verification_code = self.create_verification_code_for_user(
            user_id=user.id,
            pg_manager=pg_manager,
        )
        
        return CreateVerificationCodeResponse(
            username=user.username,
            email=user.email,
            value=verification_code
        )


    def get_current_user(self, token: str, pg_manager: PostgresManager) -> UserInDB:
        """Get current user from JWT token"""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        try:
            payload = jwt.decode(token, self.public_key, algorithms=[self.algorithm])
            user_id = payload.get("sub")
            if user_id is None:
                logger.error("User ID not found in token payload")
                raise credentials_exception
        except jwt.InvalidTokenError:
            raise credentials_exception
            
        user = user_queries.get_user_by_id(user_id, pg_manager=pg_manager)
        if user is None:
            logger.error(f"User with ID '{user_id}' not found")
            raise credentials_exception
        return user


    def get_current_active_user(self, current_user: UserInDB) -> UserInDB:
        """Get current active user (not disabled)"""
        if current_user.disabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        return current_user


    def get_current_admin_user(self, current_user: UserInDB) -> UserInDB:
        """Get current admin user"""
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        return current_user


    def update_user(
            self,
            user_id: str,
            user_update: UpdateUser,
            pg_manager: PostgresManager
            ) -> dict:
        """Update user information"""
        # Get current user to verify they exist
        current_user = user_queries.get_user_by_id(user_id, pg_manager=pg_manager)
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user_validators.validate_user_update(user_update, pg_manager)
        fields_updated = user_queries.update_user_fields(user_id, user_update, pg_manager=pg_manager)
        
        if not fields_updated:
            return {"detail": "No changes were made"}
        
        try:
            return {"detail": "User information updated successfully"}
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user information"
            )


    def update_password(
            self,
            user_id: str,
            pg_manager: PostgresManager,
            password_update: Optional[UpdatePassword] = None,
            new_password: Optional[str] = None
            ) -> dict:
        """Update user password"""
        # Get current user to verify they exist and get their current password
        current_user = user_queries.get_user_by_id(user_id, pg_manager=pg_manager)
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_validators.validate_new_password(
                password_update=password_update,
                current_hashed_password=current_user.hashed_password,
                new_password=new_password,
                password_hash=self.password_hash,
            )

        if password_update is not None:
            new_hashed_password = self.get_password_hash(password_update.new_password)
        elif new_password is not None:
            new_hashed_password = self.get_password_hash(new_password)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No password provided for update"
            )
        
        # Update password in database
        try:
            user_queries.update_user_password(
                user_id=user_id, 
                hashed_password=new_hashed_password, 
                pg_manager=pg_manager)
            return {"detail": "Password updated successfully"}
        except Exception as e:
            logger.error(f"Error updating password: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )