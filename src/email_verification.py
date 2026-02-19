
from typing import Optional
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException, status

from src.managers.rabbitmq import RabbitMQManager
from src.managers.auth import AuthManager
from src.models import UpdateForgottenPassword, UserInDB, VerifyEmailRequest
from src.managers.postgres import PostgresManager
from src import user_queries, verification_code_queries, user_validators

def _check_verification_code(user: Optional[UserInDB], code: str, pg_manager: PostgresManager) -> UserInDB:
    """Check if verification code is valid, not used and not expired"""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    verification_record = verification_code_queries.get_verification_code_by_user_id(
        user_id=user.id, pg_manager=pg_manager
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
    
    # Check if code is already used
    if verification_record.verified_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has already been used.",
        )
    
    return None


def _use_verification_code(user_id: str, pg_manager: PostgresManager) -> None:
    """Mark verification code as used and update user's email verified status"""
    verification_code_queries.mark_verification_code_as_used(user_id=user_id, pg_manager=pg_manager)
    verification_code_queries.update_user_email_verified_status(user_id=user_id, verified=True, pg_manager=pg_manager)
    return None



def verify_user_email_with_code(verify_request: VerifyEmailRequest, pg_manager: PostgresManager, ) -> bool:
    """Verify user email using 6-digit code"""

    user = user_queries.get_user_by_email(verify_request.email, pg_manager=pg_manager)
    _check_verification_code(
        user=user,
        code=verify_request.code,
        pg_manager=pg_manager,
    )

    _use_verification_code(
        user_id=user.id,
        pg_manager=pg_manager
    )
    
    return {"detail": "Email verified successfully!"}


def resend_verification_code(
        email: str, 
        pg_manager: PostgresManager, 
        auth_manager: AuthManager,
        rmq_manager: RabbitMQManager,
        ) -> dict:
    """Resend verification code to user's email"""
    user_validators.validate_email_format(email)
    user = user_queries.get_user_by_email(email=email, pg_manager=pg_manager)
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
    
    verification_code = auth_manager.create_verification_code_for_user(
        user_id=user.id,
        pg_manager=pg_manager,
        )

    rmq_manager.publish_verify_mail_request(
            username=user.username,
            verification_code=verification_code,
            recipient=email
        )

    return {"detail": "A new verification code has been sent to your email."}


def send_forgot_password_verification(
        email: str,
        pg_manager: PostgresManager,
        auth_manager: AuthManager,
        rmq_manager: RabbitMQManager,
    ) -> dict:

    user = user_queries.get_user_by_email(email=email, pg_manager=pg_manager)
    verification_code = auth_manager.create_verification_code_for_user(
        user_id=user.id,
        pg_manager=pg_manager,
        )

    rmq_manager.publish_forgot_password_verification_request(
            username=user.username,
            verification_code=verification_code,
            recipient=email
        )

    return {"detail": "A verification code has been sent to your email address."}

def send_email_change_verification(
        user: UserInDB,
        new_email: str,
        pg_manager: PostgresManager,
        auth_manager: AuthManager,
        rmq_manager: RabbitMQManager,
        ) -> dict:
    """Initiate email change process by sending verification code to new email"""

    # Check if new email is the same as current email
    if user.email.lower() == new_email.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The new email address must be different from the current one.",
        )

    user_validators.validate_email_format(new_email)
    user_validators.validate_email_unique(new_email, pg_manager)

    verification_code = auth_manager.create_verification_code_for_user(
        user_id=user.id,
        pg_manager=pg_manager,
        )
    
    rmq_manager.publish_email_change_verification_request(
            username=user.username,
            verification_code=verification_code,
            recipient=new_email
        )

    return {"detail": "A verification code has been sent to your new email address."}


def verify_user_email_change(user: UserInDB, verify_request: VerifyEmailRequest, pg_manager: PostgresManager) -> dict:
    """Verify email change using 6-digit code and update user's email"""
    _check_verification_code(
        user=user,
        code=verify_request.code,
        pg_manager=pg_manager,
    )
    
    user_validators.validate_email_format(verify_request.email)
    user_validators.validate_email_unique(verify_request.email, pg_manager)
    verification_code_queries.update_user_email(user.id, verify_request.email, pg_manager)
    
    _use_verification_code(user.id, pg_manager)
    
    return {"detail": "Email address updated successfully"}


def verify_forgot_password_with_code(verify_request: VerifyEmailRequest, pg_manager: PostgresManager) -> dict:
    """Verify forgot password request using 6-digit code"""
    user = user_queries.get_user_by_email(email=verify_request.email, pg_manager=pg_manager)
    _check_verification_code(user, verify_request.code, pg_manager)

    # Do not mark code as used yet, this will be done after password is updated
    # _use_verification_code (user.id, pg_manager)
    
    return {"detail": "E-Mail successfully verified. You can now reset your password."}


def update_forgotten_password_with_code(
        update_forgotten_password: UpdateForgottenPassword,
        auth_manager: AuthManager,
        pg_manager: PostgresManager,
    ) -> dict:
    """Update forgotten password using verification code"""
    user = user_queries.get_user_by_email(update_forgotten_password.email, pg_manager)
    _check_verification_code(user, update_forgotten_password.verification_code, pg_manager)

    _use_verification_code(user.id, pg_manager)

    auth_manager.update_password(
        user_id=user.id,
        new_password=update_forgotten_password.new_password,
        pg_manager=pg_manager,
    )
    
    return {"detail": "Password updated successfully"}