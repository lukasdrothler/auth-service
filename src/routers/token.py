from fastapi import APIRouter, Depends, Query
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated


from src.dependencies import get_auth_manager, get_pg_manager
from src.managers.auth import AuthManager
from src.managers.postgres import PostgresManager
from src.models import Token, RefreshTokenRequest, ErrorDetail

router = APIRouter()

@router.post(
    "/token",
    response_model=Token,
    tags=["tokens"],
    responses={
        200: {"description": "Access token (and optionally a refresh token) issued"},
        401: {"model": ErrorDetail, "description": "Incorrect username/e-mail or password"},
        417: {"model": ErrorDetail, "description": "User has no password set or has an outdated password hash"},
    },
)
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
    stay_logged_in: bool = Query(False, description="Whether to issue a refresh token")
) -> Token:
    return auth_manager.get_token_for_user(
        username_or_email=form_data.username,
        password=form_data.password,
        pg_manager=pg_manager,
        stay_logged_in=stay_logged_in
    )


@router.post(
    "/token/refresh",
    response_model=Token,
    tags=["tokens"],
    responses={
        200: {"description": "New access token issued"},
        401: {"model": ErrorDetail, "description": "Invalid, expired, or missing refresh token, or user is disabled"},
    },
)
def refresh_access_token(
    refresh_request: RefreshTokenRequest,
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
) -> Token:
    return auth_manager.refresh_access_token(
        refresh_token=refresh_request.refresh_token,
        pg_manager=pg_manager
    )