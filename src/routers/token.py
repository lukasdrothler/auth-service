from fastapi import APIRouter, Depends, Query
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated


from src.dependencies import get_auth_service, get_postgres_service
from src.services.auth_service import AuthService
from src.services.postgres_service import PostgresService
from src.models import Token, RefreshTokenRequest

router = APIRouter()

@router.post("/token", response_model=Token, tags=["tokens"])
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    auth_service: AuthService = Depends(get_auth_service),
    postgres_service: PostgresService = Depends(get_postgres_service),
    stay_logged_in: bool = Query(False, description="Whether to issue a refresh token")
) -> Token:
    return auth_service.get_token_for_user(
        username_or_email=form_data.username,
        password=form_data.password,
        postgres_service=postgres_service,
        stay_logged_in=stay_logged_in
    )


@router.post("/token/refresh", response_model=Token, tags=["tokens"])
def refresh_access_token(
    refresh_request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service),
    postgres_service: PostgresService = Depends(get_postgres_service),
) -> Token:
    return auth_service.refresh_access_token(
        refresh_token=refresh_request.refresh_token,
        postgres_service=postgres_service
    )