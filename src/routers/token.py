from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from jwt.exceptions import InvalidTokenError

import jwt

from src.dependencies import *
from src.models import *
from src.user_queries import *

router = APIRouter()

@router.post("/token", response_model=Token, tags=["tokens"])
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    auth_service: AuthService = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
    stay_logged_in: bool = Query(False, description="Whether to issue a refresh token")
) -> Token:
    return auth_service.get_token_for_user(
        username_or_email=form_data.username,
        password=form_data.password,
        db_service=db_service,
        stay_logged_in=stay_logged_in
    )


@router.post("/token/refresh", response_model=Token, tags=["tokens"])
async def refresh_access_token(
    refresh_request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
) -> Token:
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(refresh_request.refresh_token, auth_service.public_key, algorithms=[auth_service.algorithm])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except InvalidTokenError:
        raise credentials_exception
    
    # Get and validate current user
    user = get_user_by_id(token_data.user_id, db_service=db_service)
    if user is None or user.disabled:
        raise credentials_exception
    
    access_token = auth_service.create_bearer_token(
        user=user,
        db_service=db_service
        )
    return Token(access_token=access_token)