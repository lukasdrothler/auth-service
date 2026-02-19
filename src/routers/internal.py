from fastapi import APIRouter, Depends, HTTPException, status
from src.services.postgres_service import PostgresService
from src.dependencies import get_postgres_service
from src.models import UserInDBNoPassword, UpdateUserPremiumLevel
from src import user_queries

router = APIRouter()

@router.get("/internal/user", response_model=UserInDBNoPassword, tags=["internal"])
def get_user_internal(
    user_id: str = None,
    stripe_customer_id: str = None,
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Get user by ID or Stripe Customer ID for internal use"""
    if user_id:
        user = user_queries.get_user_by_id(user_id=user_id, postgres_service=postgres_service)
        if user and stripe_customer_id and user.stripe_customer_id != stripe_customer_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found with matching criteria")
    elif stripe_customer_id:
        user = user_queries.get_user_by_stripe_customer_id(
            stripe_customer_id=stripe_customer_id,
            postgres_service=postgres_service
        )
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Either user_id or stripe_customer_id must be provided")

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserInDBNoPassword(**user.model_dump(exclude={"password"}))


@router.put("/internal/users/{user_id}/premium", response_model=dict, tags=["internal"])
def update_user_premium_level_internal(
    user_id: str,
    update_data: UpdateUserPremiumLevel,
    postgres_service: PostgresService = Depends(get_postgres_service),
):
    """Update user premium level for internal use"""
    return user_queries.update_user_premium_level(
        user_id=user_id,
        new_premium_level=update_data.new_premium_level,
        stripe_customer_id=update_data.stripe_customer_id,
        postgres_service=postgres_service,
    )
