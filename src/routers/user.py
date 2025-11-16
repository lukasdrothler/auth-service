from fastapi import APIRouter, Depends, HTTPException, status

from src.dependencies import get_auth_service, get_database_service, CurrentActiveUser, CurrentAdminUser, IsInternalRequest
from src.models import User, CreateUser, UpdateUser, UpdatePassword, VerifyEmailRequest, CreateVerificationCodeResponse, UpdateForgottenPassword, UserInDBNoPassword
from src.user_queries import get_all_users, delete_user
from src.email_verification import verify_user_email_with_code, verify_user_email_change, verify_forgot_password_with_code, update_forgotten_password_with_code
from src.auth_service import AuthService
from src.database_service import DatabaseService

from src import verification_code_queries
from src import user_queries

router = APIRouter()

@router.get("/user/me", response_model=User, tags=["user-information"])
def read_users_me(current_user: CurrentActiveUser):
    return current_user


@router.post("/user/register", status_code=201, tags=["user-registration"])
def create_new_user(
    user: CreateUser,
    auth_service: AuthService = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
):
    auth_service.register_new_user(user=user, db_service=db_service)
    return {"detail": "User registered successfully. Please check your email for the verification code."}


@router.get("/internal/user/{user_id}/verification-code", response_model=CreateVerificationCodeResponse, tags=["user-registration"])
def get_user_verification_code(
    user_id: str,
    is_internal: IsInternalRequest,
    db_service: DatabaseService = Depends(get_database_service),
):
    if not is_internal:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires internal API key authentication"
        )

    user = user_queries.get_user_by_id(user_id, db_service)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    verification_code =  verification_code_queries.get_verification_code_by_user_id(user_id, db_service)
    if not verification_code:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Verification code not found for the specified user ID"
        )
    
    return CreateVerificationCodeResponse(
        verification_code=verification_code.value,
        username=user.username,
        email=user.email
    )
    

@router.post("/internal/user/register", response_model=CreateVerificationCodeResponse, status_code=201, tags=["user-registration"])
def create_new_user_internal(
    user: CreateUser,
    is_internal: IsInternalRequest,
    auth_service: AuthService = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
):
    if not is_internal:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires internal API key authentication"
        )
    return auth_service.register_new_user(user=user, db_service=db_service)


@router.post("/user/verify-email", status_code=200, tags=["user-registration"])
def verify_user_email(
    verify_request: VerifyEmailRequest,
    db_service: DatabaseService = Depends(get_database_service),
):
    return verify_user_email_with_code(
        verify_request=verify_request,
        db_service=db_service, 
        )
    

# @router.post("/user/resend-verification", status_code=200, tags=["user-registration"])
# def send_new_verification_code(
#     send_verification_request: SendVerificationRequest,
#     db_service: DatabaseService = Depends(get_database_service),
# ):
#     return resend_verification_code(
#         email=send_verification_request.email,
#         db_service=db_service,
#         )


@router.put("/user/me", status_code=200, tags=["user-information"])
def update_user_info(
    user_update: UpdateUser,
    current_user: CurrentActiveUser,
    auth_service: AuthService = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
):
    """Update current user's information"""
    return auth_service.update_user(
        user_id=current_user.id, 
        user_update=user_update,
        db_service=db_service,
        )


@router.put("/user/me/password", status_code=200, tags=["user-information"])
def change_user_password(
    password_update: UpdatePassword,
    current_user: CurrentActiveUser,
    auth_service: AuthService = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
):
    """Update current user's password"""
    return auth_service.update_password(
        user_id=current_user.id,
        password_update=password_update,
        db_service=db_service,
        )


# @router.post("/user/me/email/change", status_code=200, tags=["user-information"])
# def request_user_email_change(
#     send_verification_request: SendVerificationRequest,
#     current_user: CurrentActiveUser,
#     db_service: DatabaseService = Depends(get_database_service),
# ):
#     """Initiate email change process - sends verification code to new email"""
#     return send_email_change_verification(
#         user=current_user,
#         new_email=send_verification_request.email,
#         db_service=db_service,
#         )


@router.post("/user/me/email/verify", status_code=200, tags=["user-information"])
def user_email_change_verification(
    verify_request: VerifyEmailRequest,
    current_user: CurrentActiveUser,
    db_service: DatabaseService = Depends(get_database_service),
):
    """Verify email change with 6-digit code and update user's email"""
    return verify_user_email_change(
        user=current_user,
        verify_request=verify_request,
        db_service=db_service,
        )


# @router.post("/user/forgot-password/request", status_code=200, tags=["user-password-recovery"])
# def request_forgot_password(
#     send_verification_request: SendVerificationRequest,
#     db_service: DatabaseService = Depends(get_database_service),
# ):
#     return send_forgot_password_verification(
#         email=send_verification_request.email,
#         db_service=db_service,
#         )


@router.post("/user/forgot-password/verify", status_code=200, tags=["user-password-recovery"])
def forgot_password_verification(
    verify_request: VerifyEmailRequest,
    db_service: DatabaseService = Depends(get_database_service),
):
    """Verify email change with 6-digit code and update user's email"""
    return verify_forgot_password_with_code(
        verify_request=verify_request,
        db_service=db_service,
        )


@router.post("/user/forgot-password/change", status_code=200, tags=["user-password-recovery"])
def change_forgotten_password(
    update_forgotten_password: UpdateForgottenPassword,
    auth_service: AuthService = Depends(get_auth_service),
    db_service: DatabaseService = Depends(get_database_service),
):
    """Verify email change with 6-digit code and update user's email"""
    return update_forgotten_password_with_code(
        update_forgotten_password=update_forgotten_password,
        auth_service=auth_service,
        db_service=db_service,
        )


@router.post("/user/id-to-name-map", response_model=dict, tags=["user-information"])
def get_user_ids_to_name(
    user_ids: list[str],
    db_service: DatabaseService = Depends(get_database_service),
):
    """Get user names by their IDs"""
    return user_queries.get_user_ids_to_names(
        user_ids=user_ids,
        db_service=db_service,
    )


@router.get("/user/all", response_model=list[UserInDBNoPassword], tags=["user-management"])
def get_users_all(
    current_admin: CurrentAdminUser,
    db_service: DatabaseService = Depends(get_database_service),
):
    """Get all users from the database"""
    if not current_admin.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return get_all_users(db_service=db_service)


@router.delete("/user/{user_id}", status_code=200, tags=["user-management"])
def delete_user_by_id(
    current_admin: CurrentAdminUser,
    user_id: str,
    db_service: DatabaseService = Depends(get_database_service),
):
    """Delete a user by ID"""
    if not current_admin.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    
    return delete_user(
        user_id=user_id,
        db_service=db_service,
    )