"""
Dependency injection container for FastAPI Utils
"""
from typing import Annotated, Any, Dict, Callable, Optional
from fastapi import Depends, Header
from fastapi.security import OAuth2PasswordBearer

from src.models import UserInDB
from src.database_service import DatabaseService
from src.auth_service import AuthService
from src.stripe_service import StripeService
from src.rmq_service import RabbitMQService

import os


class DependencyContainer:
    """Dependency injection container for managing service instances"""
    
    def __init__(self):
        self._factories: Dict[str, Callable] = {}
        self._singletons: Dict[str, Any] = {}
        
    def register_singleton(self, service_name: str, instance: Any) -> None:
        """Register a singleton service instance"""
        self._singletons[service_name] = instance
        
    def register_factory(self, service_name: str, factory: Callable) -> None:
        """Register a factory function for creating service instances"""
        self._factories[service_name] = factory
        
    def get(self, service_name: str) -> Any:
        """Get a service instance"""
        # Check if it's a singleton first
        if service_name in self._singletons:
            return self._singletons[service_name]
            
        # Check if there's a factory for it
        if service_name in self._factories:
            instance = self._factories[service_name]()
            # Cache as singleton after first creation
            self._singletons[service_name] = instance
            return instance
            
        raise ValueError(f"Service '{service_name}' not found in container")
    
    def clear(self) -> None:
        """Clear all registered services"""
        self._factories.clear()
        self._singletons.clear()


# Global dependency container instance
container = DependencyContainer()


def create_database_service() -> DatabaseService:
    """Factory function to create DatabaseService instance"""
    return DatabaseService()


def create_stripe_service() -> StripeService:
    """Factory function to create StripeService instance"""
    return StripeService()


def create_rmq_service() -> RabbitMQService:
    """Factory function to create RabbitMQService instance"""
    return RabbitMQService()


def create_auth_service(
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 30,
    token_url: str = "token",
    private_key_filename: str = "private_key.pem",
    public_key_filename: str = "public_key.pem"
):
    """Factory function to create AuthService instance without dependencies"""
    return AuthService(
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
        token_url=token_url,
        private_key_filename=private_key_filename,
        public_key_filename=public_key_filename
    )


def setup_dependencies(
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 30,
    token_url: str = "token",
    private_key_filename: str = "private_key.pem",
    public_key_filename: str = "public_key.pem"
) -> None:
    """Setup all dependencies in the container"""
    container.clear()
    
    # Register singleton instances
    container.register_singleton("database_service", create_database_service())
    container.register_singleton("stripe_service", create_stripe_service())
    container.register_singleton("rmq_service", create_rmq_service())

    # Register AuthService singleton instance
    container.register_singleton(
        "auth_service",
        create_auth_service(
            access_token_expire_minutes=access_token_expire_minutes,
            refresh_token_expire_days=refresh_token_expire_days,
            token_url=token_url,
            private_key_filename=private_key_filename,
            public_key_filename=public_key_filename
        )
    )


def get_rmq_service() -> RabbitMQService:
    """FastAPI dependency function to get RabbitMQService instance"""
    return container.get("rmq_service")


def get_auth_service() -> AuthService:
    """FastAPI dependency function to get AuthService instance"""
    return container.get("auth_service")


def get_database_service() -> DatabaseService:
    """FastAPI dependency function to get DatabaseService instance"""
    return container.get("database_service")


def get_stripe_service() -> StripeService:
    """FastAPI dependency function to get StripeService instance"""
    return container.get("stripe_service")


# Create OAuth2 scheme with correct token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    auth_service = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
) -> UserInDB:
    """Dependency to get current user from JWT token"""
    return auth_service.get_current_user(token, db_service=db_service)


def get_current_active_user(
    current_user: Annotated[UserInDB, Depends(get_current_user)],
    auth_service = Depends(get_auth_service),
) -> UserInDB:
    """Dependency to get current active user"""
    return auth_service.get_current_active_user(current_user)

def get_current_admin_user(
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
    auth_service = Depends(get_auth_service),
) -> UserInDB:
    """Dependency to get current admin user"""
    return auth_service.get_current_admin_user(current_user)


# Internal service authentication
def verify_internal_api_key(x_api_key: Optional[str] = Header(None)) -> bool:
    """
    Dependency to verify internal service API key.
    Returns True if the API key is valid, False otherwise.
    Set INTERNAL_API_KEY environment variable to enable this feature.
    """
    internal_api_key = os.getenv("INTERNAL_API_KEY")
    
    # If no internal API key is configured, return False (external request)
    if not internal_api_key:
        return False
    
    # Check if the provided API key matches
    if x_api_key and x_api_key == internal_api_key:
        return True
    
    return False


# Convenience type annotations for use in route handlers
CurrentUser = Annotated[UserInDB, Depends(get_current_user)]
CurrentActiveUser = Annotated[UserInDB, Depends(get_current_active_user)]
CurrentAdminUser = Annotated[UserInDB, Depends(get_current_admin_user)]
IsInternalRequest = Annotated[bool, Depends(verify_internal_api_key)]