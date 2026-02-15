from fastapi import APIRouter, Depends, Request, Header

from src.services.postgres_service import PostgresService
from src.services.stripe_service import StripeService
from src.dependencies import CurrentActiveUser, get_postgres_service, get_stripe_service

import logging

logger = logging.getLogger(__name__)

"""Create user management router with dependency injection"""
router = APIRouter()


@router.post("/stripe-webhook", tags=["stripe"])
async def stripe_webhook_received(
    request: Request,
    stripe_signature=Header(None),
    postgres_service: PostgresService = Depends(get_postgres_service),
    stripe_service: StripeService = Depends(get_stripe_service),
):
    return await stripe_service.handle_webhook_event(
        request=request,
        postgres_service=postgres_service,
        stripe_signature=stripe_signature,
        )


@router.post("/create-customer-portal-session", tags=["stripe"])
async def create_customer_portal_session(
    request: Request,
    current_user: CurrentActiveUser,
    stripe_service: StripeService = Depends(get_stripe_service),
):
    locale = request.headers.get('Accept-Language', 'auto')
    return await stripe_service.create_customer_portal_session(
        customer_id=current_user.stripe_customer_id,
        locale=locale
    )