"""
Dependency injection container for FastAPI Utils
"""
from typing import Annotated, Any, Dict, Callable

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer

from .models import UserInDB
from .database_service import DatabaseService
from .auth_service import AuthService


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


def get_auth_service() -> AuthService:
    """FastAPI dependency function to get AuthService instance"""
    return container.get("auth_service")


def get_database_service() -> DatabaseService:
    """FastAPI dependency function to get DatabaseService instance"""
    return container.get("database_service")


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


# Convenience type annotations for use in route handlers
CurrentUser = Annotated[UserInDB, Depends(get_current_user)]
CurrentActiveUser = Annotated[UserInDB, Depends(get_current_active_user)]
CurrentAdminUser = Annotated[UserInDB, Depends(get_current_admin_user)]