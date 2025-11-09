# Auth Service

A FastAPI microservice for user authentication and management with JWT token-based authentication, email verification, and password recovery.

## Features

- **JWT Authentication**: RS256 asymmetric token signing with access and refresh tokens
- **User Registration**: Account creation with email verification codes
- **Email Verification**: 6-digit verification codes for new accounts and email changes
- **Password Management**: Password changes and forgot password recovery flow
- **User Management**: Profile updates and admin user management endpoints
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
AUTH_SVC_PORT=8000

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=auth_db
```

4. **Database setup**:
Create the required MySQL database and tables. The service expects `users` and `verification_codes` tables (schema based on models in `src/models.py`).

5. **Run the service**:
```bash
python main.py
```

## API Endpoints

### Authentication
- `POST /token` - Login with username/email and password (OAuth2 compatible)
- `POST /token/refresh` - Refresh access token using refresh token

### User Registration
- `POST /user/register` - Create new user account (returns verification code)
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

## Docker Deployment

Build and run with Docker:
```bash
docker build -t auth-service .
docker run -p 8000:8000 --env-file .env auth-service
```

Or use Kubernetes manifests in `manifests/`:
```bash
kubectl apply -f manifests/
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
