from fastapi import HTTPException, status, Request, Header

from src import user_queries
from src.services.postgres_service import PostgresService

import logging
import os
import json
import stripe

logger = logging.getLogger(__name__)


class StripeService:
    """Service for handling Stripe-related operations"""

    def __init__(self):
        """Initialize the Stripe service with environment variables"""
        self.is_active = False

        if "STRIPE_CONFIG_FILE" in os.environ:
            _config_file = os.environ["STRIPE_CONFIG_FILE"]
            logger.info(f"Using Stripe config file from environment variable 'STRIPE_CONFIG_FILE': {_config_file}")
            self.product_id_map = self.read_product_id_map(_config_file)

            if "STRIPE_SECRET_API_KEY" in os.environ:
                self.secret_key = os.environ["STRIPE_SECRET_API_KEY"]
                logger.info(f"Using Stripe secret key from environment variable 'STRIPE_SECRET_API_KEY'")

                if "STRIPE_SIGNING_SECRET" in os.environ:
                    self.signing_secret = os.environ["STRIPE_SIGNING_SECRET"]
                    logger.info(f"Using Stripe signing secret from environment variable 'STRIPE_SIGNING_SECRET'")

                    self.is_active = True
                    logger.info("Stripe service is active")

                else:
                    logger.warning("Environment variable 'STRIPE_SIGNING_SECRET' not found. Stripe service will not be active")
            else:
                logger.warning("Environment variable 'STRIPE_SECRET_API_KEY' not found. Stripe service will not be active")
        else:
            logger.warning("Environment variable 'STRIPE_CONFIG_FILE' not found. Stripe service will not be active")


    def read_product_id_map(self, config_file):
        """Read Stripe configuration from a JSON file"""
        try:
            with open(config_file, 'r') as file:
                config = json.load(file)
                product_map = config.get("product_id_to_premium_level", {})
                if not product_map:
                    logger.error(f"No product ID map found in {config_file}")
                    raise Exception(
                        f"No product ID map found in {config_file}. Please check your configuration."
                    )
                logger.info(f"Successfully loaded product ID map from {config_file}")
                return product_map
  
        except FileNotFoundError:
            logger.error(f"Stripe configuration file {config_file} not found")
            raise Exception(
                f"Stripe configuration file {config_file} not found. Please check your environment variables."
            )
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from Stripe configuration file {config_file}")
            raise Exception(
                f"Error decoding JSON from Stripe configuration file {config_file}. Please check the file format."
            )
        return None


    async def _get_constructed_event(self, request: Request, stripe_signature = Header(None),):
        if not self.is_active:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Stripe service is not active. Please contact support."
            )
        
        _payload = await request.body()
        try:
            return stripe.Webhook.construct_event(
                payload=_payload,
                sig_header=stripe_signature,
                secret=self.signing_secret,
                api_key=self.secret_key
            )
        except Exception as e:
            logger.error(f"Failed to construct event: {e}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid event from Stripe"
            )

    async def handle_webhook_event(
            self,
            request: Request,
            postgres_service: PostgresService,
            stripe_signature: str = Header(None)
    ):
        """Handle incoming Stripe webhook events"""
        event = await self._get_constructed_event(request=request, stripe_signature=stripe_signature)
        
        try:
            _data = event["data"]["object"]
            _data_id = _data["id"]
        except KeyError:
            logger.error(f"Invalid event data")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid event from Stripe"
            )

        # Process the event based on its type
        if event['type'] == 'checkout.session.completed':
            return self._handle_checkout_session(
                data_id=_data_id,
                postgres_service=postgres_service,
                )
        elif event['type'] == 'customer.subscription.deleted':
            return self._handle_subscription_deleted(
                data_id=_data_id,
                postgres_service=postgres_service,
                )
        else:
            logger.warning(f"Unhandled event type: {event['type']}")
            return {"detail": "Event could not be processed"}
        
    
    def _handle_checkout_session(self, data_id: str, postgres_service: PostgresService):
        """Handle checkout session completed event"""
        session_data = stripe.checkout.Session.retrieve(
            data_id,
            expand=["line_items"],
            api_key=self.secret_key
            )
        
        try:
            user_email = session_data["customer_details"]["email"]
            user_id = session_data["client_reference_id"]
            stripe_customer_id = session_data["customer"]
            product_id = session_data["line_items"]["data"][0]["price"]["product"]
        except KeyError:
            logger.error(f"Invalid session data for session '{data_id}'")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid session data"
            )

        if not user_email:
            logger.error(f"User email not found in session data for session '{data_id}'")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid session data"
            )
        
        if not user_id:
            logger.error(f"User ID not found in session data for session '{data_id}'")
            logger.error("Make sure to set the user id as 'client_reference_id' when creating the checkout session")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid session data"
            )
        
        if not stripe_customer_id:
            logger.error(f"Stripe customer ID not found in session data for session '{data_id}'")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid session data"
            )

        new_premium_level = self.product_id_map.get(product_id, None)
        if new_premium_level is None:
            logger.error(f"Invalid product ID: {product_id}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid product ID: {product_id}"
            )

        user = user_queries.get_user_by_id(user_id=user_id, postgres_service=postgres_service)
        if user is None:
            ## This case can only occur, if someone opens the paymentlink without being registered
            logger.error(f"User with id '{user_id}' not found in database")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id '{user_id}' not found"
            )

        if user.premium_level == new_premium_level:
            logger.error(f"User with id '{user_id}' already has premium access")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already has the specified premium access level"
            )
        
        return user_queries.update_user_premium_level(
            user_id=user_id,
            new_premium_level=new_premium_level,
            stripe_customer_id=stripe_customer_id,
            postgres_service=postgres_service,
        )

    def _handle_subscription_deleted(self, data_id: str, postgres_service: PostgresService):
        """Handle subscription deletion event"""
        subscription_data = stripe.Subscription.retrieve(data_id, api_key=self.secret_key)
        try:
            product_id = subscription_data["items"]["data"][0]["price"]["product"]
            stripe_customer_id = subscription_data["customer"]
        except KeyError:
            logger.error(f"Invalid subscription data for subscription '{data_id}'")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid event from Stripe"
            )
        
        if product_id not in self.product_id_map:
            logger.error(f"Invalid product ID: {product_id}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid product ID: {product_id}"
            )

        if stripe_customer_id is None:
            logger.error(f"Stripe customer ID not found in subscription data for subscription '{data_id}'")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid event from Stripe"
            )

        user = user_queries.get_user_by_stripe_customer_id(
            stripe_customer_id=stripe_customer_id,
            postgres_service=postgres_service
            )
        if user is None:
            logger.error(f"No user found with stripe_customer_id '{stripe_customer_id}'")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No user found with stripe_customer_id '{stripe_customer_id}'"
            )
 
        return user_queries.update_user_premium_level(
            user_id=user.id,
            new_premium_level=0,
            stripe_customer_id=user.stripe_customer_id,
            postgres_service=postgres_service,
        )


    async def create_customer_portal_session(self, customer_id: str, locale: str = 'auto'):
        """Create a customer portal session for managing subscriptions"""
        if not self.is_active:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Stripe service is not active. Please contact support."
            )
        
        try:
        ## https://docs.stripe.com/api/customer_portal/sessions/create
            return stripe.billing_portal.Session.create(
                customer=customer_id,
                locale=locale,
                api_key=self.secret_key
            )
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create customer portal session: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create customer portal session"
            )
