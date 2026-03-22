from fastapi import APIRouter, Depends, HTTPException, status, Request

from src.managers.auth import AuthManager
from src.managers.rabbitmq import RabbitMQManager
from src.managers.postgres import PostgresManager

from src import (
    user_queries,
    email_verification,
)

from src.models import (
 SendVerificationRequest,
 User,
 CreateUser,
 UpdateUser,
 UpdatePassword,
 VerifyEmailRequest,
 UpdateForgottenPassword,
 UserInDBNoPassword,
 DetailResponse,
 ErrorDetail,
)

from src.dependencies import (
    get_auth_manager,
    get_pg_manager,
    get_rmq_manager,
    CurrentActiveUser,
    CurrentAdminUser
)

router = APIRouter()

def extract_locale_from_request(request: Request) -> str:
    """Extract the preferred language from the Accept-Language header"""
    accept_language = request.headers.get("Accept-Language", "en")
    # Split the header by comma and take the first language
    languages = [lang.strip() for lang in accept_language.split(",")]
    if languages:
        return languages[0]
    return "en"

@router.get(
    "/user/me",
    response_model=User,
    tags=["user-information"],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication token"},
        400: {"model": ErrorDetail, "description": "User account is disabled"},
    },
)
def read_users_me(current_user: CurrentActiveUser):
    return current_user


@router.post(
    "/user/register",
    status_code=201,
    response_model=DetailResponse,
    tags=["user-registration"],
    responses={
        201: {"description": "User registered successfully, verification e-mail queued"},
        400: {"model": ErrorDetail, "description": "Invalid username, e-mail format or password strength"},
        409: {"model": ErrorDetail, "description": "Username or e-mail already taken"},
    },
)
def create_new_user(
    user: CreateUser,
    request: Request,
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
    rmq_manager: RabbitMQManager = Depends(get_rmq_manager),
):
    response = auth_manager.register_new_user(user=user,pg_manager=pg_manager)

    rmq_manager.publish_verify_mail_request(
            username=response.username,
            verification_code=response.value,
            recipient=response.email,
            language=extract_locale_from_request(request)
        )

    return {"detail": "User registered successfully. E-Mail verification request added to queue."}



@router.post(
    "/user/verify-email",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-registration"],
    responses={
        200: {"description": "E-Mail verified successfully"},
        400: {"model": ErrorDetail, "description": "No verification code found, invalid code, expired code, or code already used"},
        404: {"model": ErrorDetail, "description": "User not found for the given e-mail"},
    },
)
def verify_user_email(
    verify_request: VerifyEmailRequest,
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    return email_verification.verify_user_email_with_code(
        verify_request=verify_request,
        pg_manager=pg_manager, 
        )
    

@router.post(
    "/user/resend-verification",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-registration"],
    responses={
        200: {"description": "New verification code sent"},
        400: {"model": ErrorDetail, "description": "Invalid e-mail format or e-mail is already verified"},
        404: {"model": ErrorDetail, "description": "User with the given e-mail not found"},
        429: {"model": ErrorDetail, "description": "Too many requests – please wait 30 seconds before retrying"},
    },
)
def send_new_verification_code(
    send_verification_request: SendVerificationRequest,
    request: Request,
    pg_manager: PostgresManager = Depends(get_pg_manager),
    auth_manager: AuthManager = Depends(get_auth_manager),
    rmq_manager: RabbitMQManager = Depends(get_rmq_manager),
):
    return email_verification.resend_verification_code(
        email=send_verification_request.email,
        pg_manager=pg_manager,
        auth_manager=auth_manager,
        rmq_manager=rmq_manager,
        language=extract_locale_from_request(request)
    )


@router.put(
    "/user/me",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-information"],
    responses={
        200: {"description": "User information updated successfully or no changes made"},
        400: {"model": ErrorDetail, "description": "Invalid username format, user account disabled"},
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication token"},
        404: {"model": ErrorDetail, "description": "User not found"},
        409: {"model": ErrorDetail, "description": "Username already taken"},
        500: {"model": ErrorDetail, "description": "Unexpected server error while saving changes"},
    },
)
def update_user_info(
    user_update: UpdateUser,
    current_user: CurrentActiveUser,
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Update current user's information"""
    return auth_manager.update_user(
        user_id=current_user.id, 
        user_update=user_update,
        pg_manager=pg_manager,
        )


@router.put(
    "/user/me/password",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-information"],
    responses={
        200: {"description": "Password updated successfully"},
        400: {"model": ErrorDetail, "description": "Current password incorrect, weak new password, or user account disabled"},
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication token"},
        404: {"model": ErrorDetail, "description": "User not found"},
        500: {"model": ErrorDetail, "description": "Unexpected server error while saving the new password"},
    },
)
def change_user_password(
    password_update: UpdatePassword,
    current_user: CurrentActiveUser,
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Update current user's password"""
    return auth_manager.update_password(
        user_id=current_user.id,
        password_update=password_update,
        pg_manager=pg_manager,
        )


@router.post(
    "/user/me/email/change",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-information"],
    responses={
        200: {"description": "Verification code sent to the new e-mail address"},
        400: {"model": ErrorDetail, "description": "New e-mail is the same as current, invalid format, or user account disabled"},
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication token"},
        409: {"model": ErrorDetail, "description": "New e-mail is already registered"},
        429: {"model": ErrorDetail, "description": "Too many requests – please wait 30 seconds before retrying"},
    },
)
def request_user_email_change(
    send_verification_request: SendVerificationRequest,
    current_user: CurrentActiveUser,
    request: Request,
    pg_manager: PostgresManager = Depends(get_pg_manager),
    auth_manager: AuthManager = Depends(get_auth_manager),
    rmq_manager: RabbitMQManager = Depends(get_rmq_manager),
):
    """Initiate email change process - sends verification code to new email"""
    return email_verification.send_email_change_verification(
        user=current_user,
        new_email=send_verification_request.email,
        pg_manager=pg_manager,
        auth_manager=auth_manager,
        rmq_manager=rmq_manager,
        language=extract_locale_from_request(request)
    )


@router.post(
    "/user/me/email/verify",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-information"],
    responses={
        200: {"description": "E-Mail address updated successfully"},
        400: {"model": ErrorDetail, "description": "Invalid e-mail format, no verification code found, invalid/expired/already-used code, or user account disabled"},
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication token"},
        409: {"model": ErrorDetail, "description": "New e-mail is already registered"},
    },
)
def user_email_change_verification(
    verify_request: VerifyEmailRequest,
    current_user: CurrentActiveUser,
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Verify email change with 6-digit code and update user's email"""
    return email_verification.verify_user_email_change(
        user=current_user,
        verify_request=verify_request,
        pg_manager=pg_manager,
        )


@router.post(
    "/user/forgot-password/request",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-password-recovery"],
    responses={
        200: {"description": "Verification code sent to the registered e-mail address"},
        404: {"model": ErrorDetail, "description": "User with the given e-mail not found"},
        429: {"model": ErrorDetail, "description": "Too many requests – please wait 30 seconds before retrying"},
    },
)
def request_forgot_password(
    send_verification_request: SendVerificationRequest,
    request: Request,
    pg_manager: PostgresManager = Depends(get_pg_manager),
    auth_manager: AuthManager = Depends(get_auth_manager),
    rmq_manager: RabbitMQManager = Depends(get_rmq_manager),
):
    return email_verification.send_forgot_password_verification(
        email=send_verification_request.email,
        pg_manager=pg_manager,
        auth_manager=auth_manager,
        rmq_manager=rmq_manager,
        language=extract_locale_from_request(request)
        )


@router.post(
    "/user/forgot-password/verify",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-password-recovery"],
    responses={
        200: {"description": "E-Mail verified; client may now submit a new password"},
        400: {"model": ErrorDetail, "description": "No verification code found, invalid/expired/already-used code"},
        404: {"model": ErrorDetail, "description": "User with the given e-mail not found"},
    },
)
def forgot_password_verification(
    verify_request: VerifyEmailRequest,
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Verify email change with 6-digit code and update user's email"""
    return email_verification.verify_forgot_password_with_code(
        verify_request=verify_request,
        pg_manager=pg_manager,
        )


@router.post(
    "/user/forgot-password/change",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-password-recovery"],
    responses={
        200: {"description": "Password reset successfully"},
        400: {"model": ErrorDetail, "description": "No verification code found, invalid/expired/already-used code, or weak new password"},
        404: {"model": ErrorDetail, "description": "User with the given e-mail not found"},
        500: {"model": ErrorDetail, "description": "Unexpected server error while saving the new password"},
    },
)
def change_forgotten_password(
    update_forgotten_password: UpdateForgottenPassword,
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Verify email change with 6-digit code and update user's email"""
    return email_verification.update_forgotten_password_with_code(
        update_forgotten_password=update_forgotten_password,
        auth_manager=auth_manager,
        pg_manager=pg_manager,
        )


@router.post(
    "/user/id-to-name-map",
    response_model=dict,
    tags=["user-information"],
    responses={
        200: {"description": "Map of user IDs to usernames (unknown IDs are omitted)"},
    },
)
def get_user_ids_to_name(
    user_ids: list[str],
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Get user names by their IDs"""
    return user_queries.get_user_ids_to_names(
        user_ids=user_ids,
        pg_manager=pg_manager,
    )


@router.get(
    "/user/{user_id}/username",
    tags=["user-information"],
    responses={
        200: {"description": "Username for the given user ID"},
        404: {"model": ErrorDetail, "description": "User not found"},
    },
)
def get_username_by_id_endpoint(
    user_id: str,
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Get a username by user ID"""
    return auth_manager.get_username_by_id(user_id=user_id, pg_manager=pg_manager)


@router.get(
    "/user/{username}/id",
    tags=["user-information"],
    responses={
        200: {"description": "User ID for the given username"},
        404: {"model": ErrorDetail, "description": "User not found"},
    },
)
def get_id_by_username_endpoint(
    username: str,
    auth_manager: AuthManager = Depends(get_auth_manager),
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Get a user ID by username"""
    return auth_manager.get_id_by_username(username=username, pg_manager=pg_manager)


@router.get(
    "/user/all",
    response_model=list[UserInDBNoPassword],
    tags=["user-management"],
    responses={
        200: {"description": "List of all users"},
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication token"},
        403: {"model": ErrorDetail, "description": "Admin privileges required"},
    },
)
def get_users_all(
    current_admin: CurrentAdminUser,
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Get all users from the database"""
    if not current_admin.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user_queries.get_all_users(pg_manager=pg_manager)


@router.delete(
    "/user/{user_id}",
    status_code=200,
    response_model=DetailResponse,
    tags=["user-management"],
    responses={
        200: {"description": "User deleted successfully"},
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication token"},
        403: {"model": ErrorDetail, "description": "Admin privileges required"},
        404: {"model": ErrorDetail, "description": "User not found"},
    },
)
def delete_user_by_id(
    current_admin: CurrentAdminUser,
    user_id: str,
    pg_manager: PostgresManager = Depends(get_pg_manager),
):
    """Delete a user by ID"""
    if not current_admin.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    
    return user_queries.delete_user(
        user_id=user_id,
        pg_manager=pg_manager,
    )