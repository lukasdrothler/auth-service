# Auth Service

A FastAPI microservice for user authentication and management with JWT token-based authentication, email verification, and password recovery.

## Features

- **JWT Authentication**: RS256 asymmetric token signing with access and refresh tokens
- **User Registration**: Account creation with email verification codes
- **Email Verification**: 6-digit verification codes for new accounts and email changes
- **Password Management**: Password changes and forgot password recovery flow
- **User Management**: Profile updates and admin user management endpoints
- **Stripe Integration**: Subscription management with webhooks and customer portal
- **CORS Support**: Configurable cross-origin resource sharing
- **MySQL Database**: Persistent storage for users and verification codes

## Prerequisites

- Python 3.14+
- MySQL database
- RSA key pair (private and public keys)

## Setup

1. **Clone and install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Generate RSA keys**:
```bash
mkdir keys
# Generate private key
openssl genrsa -out keys/private_key.pem 2048
# Generate public key
openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
```

3. **Configure environment variables** (`.env` file):
```env
# Environment
CURRENT_ENV=development  # or production

# Server
AUTH_SVC_HOST=0.0.0.0
AUTH_SVC_PORT=8007

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=auth_db

# Stripe (optional)
STRIPE_SECRET_API_KEY=sk_test_xxxxx
STRIPE_SIGNING_SECRET=whsec_xxxxx
STRIPE_CONFIG_FILE=path/to/stripe_config.json

# Internal Service Authentication (optional)
INTERNAL_API_KEY=your_secure_api_key_here
```

4. **Configure Stripe** (optional):
Create a `stripe_config.json` file mapping Stripe product IDs to premium levels:
```json
{
  "product_id_to_premium_level": {
    "prod_xxxxx": 1,
    "prod_yyyyy": 2
  }
}
```

5. **Database setup**:
Create the required MySQL database and tables. The service expects `users` and `verification_codes` tables (schema based on models in `src/models.py`).

6. **Run the service**:
```bash
python main.py
```

## API Endpoints

### Authentication
- `POST /token` - Login with username/email and password (OAuth2 compatible)
- `POST /token/refresh` - Refresh access token using refresh token

### User Registration
- `POST /user/register` - Create new user account (public endpoint, returns success message)
- `POST /user/verify-email` - Verify email with 6-digit code

### User Information
- `GET /user/me` - Get current user info
- `PUT /user/me` - Update user profile
- `PUT /user/me/password` - Change password
- `POST /user/me/email/verify` - Verify email change
- `POST /user/id-to-name-map` - Map user IDs to usernames

### Password Recovery
- `POST /user/forgot-password/verify` - Verify forgot password code
- `POST /user/forgot-password/change` - Reset password with verification code

### Admin Endpoints (requires admin role)
- `GET /user/all` - List all users
- `DELETE /user/{user_id}` - Delete user by ID

### Stripe Integration
- `POST /stripe-webhook` - Handle Stripe webhook events (checkout completion, subscription changes)
- `POST /create-customer-portal-session` - Create Stripe customer portal session for subscription management

### Internal Endpoints (require X-API-Key header)
- `POST /internal/user/register` - Create new user account (returns verification code for internal services)

## Docker Deployment

Build and run with Docker:
```bash
docker build -t auth-service .
docker run -p 8007:8007 --env-file .env auth-service
```

## Internal vs External Usage

This service supports both internal (service-to-service) and external (public-facing) deployments:

- **Internal requests**: Include `X-API-Key` header with the configured `INTERNAL_API_KEY` to receive detailed responses (e.g., verification codes)
- **External requests**: Without the API key, sensitive information is hidden and generic success messages are returned

Example internal request:
```bash
curl -X POST https://auth-service/internal/user/register \
  -H "X-API-Key: your_secure_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"username":"user","email":"user@example.com","password":"pass123"}'
```

## Development

- **Development mode**: Set `CURRENT_ENV=development` to enable hot reload and API docs at `/docs` and `/redoc`
- **Production mode**: Docs disabled, warning-level logging only

## Architecture

- **FastAPI**: Web framework with automatic OpenAPI documentation
- **JWT RS256**: Asymmetric token signing for security
- **Dependency Injection**: Clean separation of services (auth, database)
- **Pydantic Models**: Type-safe request/response validation
- **MySQL**: Relational database for user data persistence
