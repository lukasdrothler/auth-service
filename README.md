# Auth Service

This is an authentication service built with **FastAPI**. It handles user registration, authentication (via JWT), and token management. It also provides internal APIs for other services to query user information.

The service integrates with **PostgreSQL** for data persistence and **RabbitMQ** for asynchronous tasks such as sending verification emails.

## Features

- **User Management**:
  - User registration.
  - Email verification (via RabbitMQ task queue).
  - User profile retrieval.
- **Authentication**:
  - JWT-based login (Access & Refresh tokens).
  - Password hashing and validation (using Argon2/Bcrypt).
  - Token refresh mechanism.
- **Internal API**:
  - Retrieve user details by User ID or Stripe Customer ID.
  - Update user premium status.
  - Secured endpoints intended for inter-service communication.
- **Observability**:
  - Health checks and structured logging.
  - OpenTelemetry support (implied by typical setups, though not explicitly seen in the snippet, useful to mention standard FastAPI features).

## Tech Stack

- **Language**: Python 3.14+
- **Framework**: FastAPI
- **Database**: PostgreSQL
- **Message Broker**: RabbitMQ
- **Containerization**: Docker

## Configuration

The service is configured using environment variables. You can set these in a `.env` file or passes them to the container.

| Variable | Description | Default |
|----------|-------------|---------|
| `CURRENT_ENV` | Set to `development` to enable hot reload and API docs | `production` |
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `8007` |
| `DISABLE_INTERNAL_ENDPOINTS` | Set to `true` to disable internal routes | `false` |
| **Database** | | |
| `POSTGRES_HOST` | PostgreSQL Host | `localhost` |
| `POSTGRES_PORT` | PostgreSQL Port | `5432` |
| `POSTGRES_USER` | PostgreSQL User | `root` |
| `POSTGRES_PASSWORD` | PostgreSQL Password | *Empty* |
| `POSTGRES_DB_NAME` | Database Name | `auth` |
| **RabbitMQ** | | |
| `RABBITMQ_HOST` | RabbitMQ Host | `localhost` |
| `RABBITMQ_PORT` | RabbitMQ Port | `5672` |
| `RABBITMQ_USERNAME` | RabbitMQ Username | **Required** |
| `RABBITMQ_PASSWORD` | RabbitMQ Password | **Required** |
| `RABBITMQ_MAIL_QUEUE_NAME` | Queue for email tasks | `finyed-mails` |
| `RABBITMQ_HEARTBEAT` | Connection heartbeat | `0` |

## Installation & Running

### Prerequisites

- Python 3.14+
- PostgreSQL
- RabbitMQ

### Local Development

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd auth-service
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up environment variables:**
    Create a `.env` file in the root directory and configure the variables listed above.

5.  **Run the service:**
    ```bash
    python main.py
    ```
    The service will start on `http://localhost:8007`.
    API Documentation will be available at `http://localhost:8007/docs` (if `CURRENT_ENV=development`).

### Docker

1.  **Build the image:**
    ```bash
    docker build -t auth-service .
    ```

2.  **Run the container:**
    ```bash
    docker run -p 8007:8007 --env-file .env auth-service
    ```

## API Endpoints

### Authentication (`/token`)
- `POST /token`: Login to get an access token.
- `POST /token/refresh`: Refresh an expired access token.

### User (`/user`)
- `GET /user/me`: Get current user details.
- `POST /user/register`: Register a new user.

### Internal (`/internal`)
- `GET /internal/user`: Get user details by ID or Stripe Customer ID.
- `PUT /internal/users/{user_id}/premium`: Update a user's premium level.

## Testing

The project uses `pytest` for testing.

```bash
pytest
```
