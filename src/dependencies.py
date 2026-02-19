"""
Dependency injection container for FastAPI Utils
"""
from typing import Annotated, Any, Dict, Callable, Optional
from fastapi import Depends, Header
from fastapi.security import OAuth2PasswordBearer

from src.models import UserInDB
from src.services.postgres_service import PostgresService
from src.services.auth_service import AuthService
from src.services.rmq_service import RabbitMQService


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

def create_postgres_service() -> PostgresService:
    """Factory function to create PostgresService instance"""
    return PostgresService()


def create_rmq_service() -> RabbitMQService:
    """Factory function to create RabbitMQService instance"""
    return RabbitMQService()


def create_auth_service(
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 30,
    token_url: str = "token",  # nosec
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
    token_url: str = "token",  # nosec
    private_key_filename: str = "private_key.pem",
    public_key_filename: str = "public_key.pem"
) -> None:
    """Setup all dependencies in the container"""
    container.clear()
    
    # Register singleton instances
    container.register_singleton("postgres_service", create_postgres_service())
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


def get_postgres_service() -> PostgresService:
    """FastAPI dependency function to get PostgresService instance"""
    return container.get("postgres_service")


# Create OAuth2 scheme with correct token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    auth_service = Depends(get_auth_service),
    postgres_service: PostgresService = Depends(get_postgres_service)
) -> UserInDB:
    """Dependency to get current user from JWT token"""
    return auth_service.get_current_user(token, postgres_service=postgres_service)


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


# Convenience type annotations for use in route handlers
CurrentUser = Annotated[UserInDB, Depends(get_current_user)]
CurrentActiveUser = Annotated[UserInDB, Depends(get_current_active_user)]
CurrentAdminUser = Annotated[UserInDB, Depends(get_current_admin_user)]