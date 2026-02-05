from fastapi import APIRouter, Depends, HTTPException, status

from src.services.auth_service import AuthService
from src.services.rmq_service import RabbitMQService
from src.services.postgres_service import PostgresService

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
 UserInDBNoPassword
)

from src.dependencies import (
    get_auth_service,
    get_postgres_service,
    get_rmq_service,
    CurrentActiveUser,
    CurrentAdminUser
)

router = APIRouter()

@router.get("/user/me", response_model=User, tags=["user-information"])
def read_users_me(current_user: CurrentActiveUser):
    return current_user


@router.post("/user/register", status_code=201, tags=["user-registration"])
def create_new_user(
    user: CreateUser,
    auth_service: AuthService = Depends(get_auth_service),
    postgres_service: PostgresService = Depends(get_postgres_service),
    rmq_service: RabbitMQService = Depends(get_rmq_service),
):
    response = auth_service.register_new_user(user=user,postgres_service=postgres_service)

    rmq_service.publish_verify_mail_request(
            username=response.username,
            verification_code=response.value,
            recipient=response.email
        )

    return {"detail": "User registered successfully. E-Mail verification request added to queue."}



@router.post("/user/verify-email", status_code=200, tags=["user-registration"])
def verify_user_email(
    verify_request: VerifyEmailRequest,
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    return email_verification.verify_user_email_with_code(
        verify_request=verify_request,
        postgres_service=postgres_service, 
        )
    

@router.post("/user/resend-verification", status_code=200, tags=["user-registration"])
def send_new_verification_code(
    send_verification_request: SendVerificationRequest,
    postgres_service: PostgresService = Depends(get_postgres_service),
    auth_service: AuthService = Depends(get_auth_service),
    rmq_service: RabbitMQService = Depends(get_rmq_service),
):
    return email_verification.resend_verification_code(
        email=send_verification_request.email,
        postgres_service=postgres_service,
        auth_service=auth_service,
        rmq_service=rmq_service
    )


@router.put("/user/me", status_code=200, tags=["user-information"])
def update_user_info(
    user_update: UpdateUser,
    current_user: CurrentActiveUser,
    auth_service: AuthService = Depends(get_auth_service),
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Update current user's information"""
    return auth_service.update_user(
        user_id=current_user.id, 
        user_update=user_update,
        postgres_service=postgres_service,
        )


@router.put("/user/me/password", status_code=200, tags=["user-information"])
def change_user_password(
    password_update: UpdatePassword,
    current_user: CurrentActiveUser,
    auth_service: AuthService = Depends(get_auth_service),
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Update current user's password"""
    return auth_service.update_password(
        user_id=current_user.id,
        password_update=password_update,
        postgres_service=postgres_service,
        )


@router.post("/user/me/email/change", status_code=200, tags=["user-information"])
def request_user_email_change(
    send_verification_request: SendVerificationRequest,
    current_user: CurrentActiveUser,
    postgres_service: PostgresService = Depends(get_postgres_service),
    auth_service: AuthService = Depends(get_auth_service),
    rmq_service: RabbitMQService = Depends(get_rmq_service),
):
    """Initiate email change process - sends verification code to new email"""
    return email_verification.send_email_change_verification(
        user=current_user,
        new_email=send_verification_request.email,
        postgres_service=postgres_service,
        auth_service=auth_service,
        rmq_service=rmq_service,
    )


@router.post("/user/me/email/verify", status_code=200, tags=["user-information"])
def user_email_change_verification(
    verify_request: VerifyEmailRequest,
    current_user: CurrentActiveUser,
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Verify email change with 6-digit code and update user's email"""
    return email_verification.verify_user_email_change(
        user=current_user,
        verify_request=verify_request,
        postgres_service=postgres_service,
        )


@router.post("/user/forgot-password/request", status_code=200, tags=["user-password-recovery"])
def request_forgot_password(
    send_verification_request: SendVerificationRequest,
    postgres_service: PostgresService = Depends(get_postgres_service),
    auth_service: AuthService = Depends(get_auth_service),
    rmq_service: RabbitMQService = Depends(get_rmq_service),
):
    return email_verification.send_forgot_password_verification(
        email=send_verification_request.email,
        postgres_service=postgres_service,
        auth_service=auth_service,
        rmq_service=rmq_service,
        )


@router.post("/user/forgot-password/verify", status_code=200, tags=["user-password-recovery"])
def forgot_password_verification(
    verify_request: VerifyEmailRequest,
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Verify email change with 6-digit code and update user's email"""
    return email_verification.verify_forgot_password_with_code(
        verify_request=verify_request,
        postgres_service=postgres_service,
        )


@router.post("/user/forgot-password/change", status_code=200, tags=["user-password-recovery"])
def change_forgotten_password(
    update_forgotten_password: UpdateForgottenPassword,
    auth_service: AuthService = Depends(get_auth_service),
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Verify email change with 6-digit code and update user's email"""
    return email_verification.update_forgotten_password_with_code(
        update_forgotten_password=update_forgotten_password,
        auth_service=auth_service,
        postgres_service=postgres_service,
        )


@router.post("/user/id-to-name-map", response_model=dict, tags=["user-information"])
def get_user_ids_to_name(
    user_ids: list[str],
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Get user names by their IDs"""
    return user_queries.get_user_ids_to_names(
        user_ids=user_ids,
        postgres_service=postgres_service,
    )


@router.get("/user/all", response_model=list[UserInDBNoPassword], tags=["user-management"])
def get_users_all(
    current_admin: CurrentAdminUser,
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Get all users from the database"""
    if not current_admin.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user_queries.get_all_users(postgres_service=postgres_service)


@router.delete("/user/{user_id}", status_code=200, tags=["user-management"])
def delete_user_by_id(
    current_admin: CurrentAdminUser,
    user_id: str,
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Delete a user by ID"""
    if not current_admin.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    
    return user_queries.delete_user(
        user_id=user_id,
        postgres_service=postgres_service,
    )