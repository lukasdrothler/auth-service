
from typing import Optional
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException, status

from src.services.rmq_service import RabbitMQService
from src.services.auth_service import AuthService
from src.models import UpdateForgottenPassword, UserInDB, VerifyEmailRequest
from src.services.database_service import DatabaseService
from src import user_queries, verification_code_queries, user_validators

def _check_verification_code(user: Optional[UserInDB], code: str, db_service: DatabaseService) -> UserInDB:
    """Check if verification code is valid, not used and not expired"""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    verification_record = verification_code_queries.get_verification_code_by_user_id(
        user_id=user.id, db_service=db_service
        )
    
    if not verification_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No verification code found for this user",
        )
    
    # Check if code matches
    if verification_record.value != code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )
    
    # Check if code is expired (24 hours)
    time_diff = datetime.now(timezone.utc) - verification_record.created_at.replace(tzinfo=timezone.utc)
    if time_diff >= timedelta(hours=24):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired. Please request a new one.",
        )
    
    return None


def _use_verification_code(user_id: str, db_service: DatabaseService) -> None:
    """Mark verification code as used and update user's email verified status"""
    verification_code_queries.mark_verification_code_as_used(user_id=user_id, db_service=db_service)
    verification_code_queries.update_user_email_verified_status(user_id=user_id, verified=True, db_service=db_service)
    return None



def verify_user_email_with_code(verify_request: VerifyEmailRequest, db_service: DatabaseService, ) -> bool:
    """Verify user email using 6-digit code"""

    user = user_queries.get_user_by_email(verify_request.email, db_service=db_service)
    _check_verification_code(
        user=user,
        code=verify_request.code,
        db_service=db_service,
    )

    _use_verification_code(
        user_id=user.id,
        db_service=db_service
    )
    
    return {"detail": "Email verified successfully!"}


def resend_verification_code(
        email: str, 
        db_service: DatabaseService, 
        auth_service: AuthService,
        rmq_service: RabbitMQService,
        ) -> dict:
    """Resend verification code to user's email"""
    user_validators.validate_email_format(email)
    user = user_queries.get_user_by_email(email=email, db_service=db_service)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User with this email not found"
        )

    if user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified"
        )
    
    verification_code = auth_service.create_verification_code_for_user(
        user_id=user.id,
        db_service=db_service,
        )

    rmq_service.publish_verify_mail_request(
            username=user.username,
            verification_code=verification_code,
            recipient=email
        )

    return {"detail": "A new verification code has been sent to your email."}


# def send_forgot_password_verification(
#         email: str,
#         db_service: DatabaseService,
#         mail_service: MailService,
#         i18n_service: I18nService,
#         locale: str,
#     ) -> dict:

#     user = user_queries.get_user_by_email(email=email, db_service=db_service)
#     verification_code = verification_code_queries.create_verification_code(
#         user=None,
#         email=email,
#         locale=locale,
#         db_service=db_service,
#         i18n_service=i18n_service
#         )

#     try:
#         # Use template system for forgot password verification
#         mail_service.send_email_html(
#             template_name="forgot_password_verification",
#             variables={
#                 "username": user.username,
#                 "verification_code": verification_code,
#             },
#             subject=i18n_service.t(
#                 key="email.shared_content.verification_code_subject", 
#                 locale=locale,
#                 verification_code=verification_code
#                 ),
#             recipient=email,
#             locale=locale,
#             i18n_service=i18n_service
#         )
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=i18n_service.t("api.email.email_sending_failed", locale, error=str(e))
#         )

#     return {"detail": i18n_service.t("api.auth.forgot_password.forgot_password_verification_code_sent", locale)}


def send_email_change_verification(
        user: UserInDB,
        new_email: str,
        db_service: DatabaseService,
        auth_service: AuthService,
        rmq_service: RabbitMQService,
        ) -> dict:
    """Initiate email change process by sending verification code to new email"""

    # Check if new email is the same as current email
    if user.email.lower() == new_email.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The new email address must be different from the current one.",
        )

    user_validators.validate_email_format(new_email)
    user_validators.validate_email_unique(new_email, db_service)

    verification_code = auth_service.create_verification_code_for_user(
        user_id=user.id,
        db_service=db_service,
        )
    
    rmq_service.publish_email_change_verification_request(
            username=user.username,
            verification_code=verification_code,
            recipient=new_email
        )

    return {"detail": "A verification code has been sent to your new email address."}


def verify_user_email_change(user: UserInDB, verify_request: VerifyEmailRequest, db_service: DatabaseService) -> dict:
    """Verify email change using 6-digit code and update user's email"""
    _check_verification_code(
        user=user,
        code=verify_request.code,
        db_service=db_service,
    )
    
    user_validators.validate_email_format(verify_request.email)
    user_validators.validate_email_unique(verify_request.email, db_service)
    verification_code_queries.update_user_email(user.id, verify_request.email, db_service)
    
    _use_verification_code(user.id, db_service)
    
    return {"detail": "Email address updated successfully"}


def verify_forgot_password_with_code(verify_request: VerifyEmailRequest, db_service: DatabaseService) -> dict:
    """Verify forgot password request using 6-digit code"""
    user = user_queries.get_user_by_email(email=verify_request.email, db_service=db_service)
    _check_verification_code(user, verify_request.code, db_service)

    _use_verification_code (user.id, db_service)
    
    return {"detail": "E-Mail successfully verified. You can now reset your password."}


def update_forgotten_password_with_code(
        update_forgotten_password: UpdateForgottenPassword,
        auth_service: AuthService,
        db_service: DatabaseService,
    ) -> dict:
    """Update forgotten password using verification code"""
    user = user_queries.get_user_by_email(update_forgotten_password.email, db_service)
    _check_verification_code(user, update_forgotten_password.verification_code, db_service)

    _use_verification_code (user.id, db_service)

    auth_service.update_password(
        user_id=user.id,
        new_password=update_forgotten_password.new_password,
        db_service=db_service,
    )
    
    return {"detail": "Password updated successfully"}