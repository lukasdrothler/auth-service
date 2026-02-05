import os
import pytest
from dotenv import load_dotenv
from testcontainers.postgres import PostgresContainer
from testcontainers.rabbitmq import RabbitMqContainer
from src.services.postgres_service import PostgresService
from src.services.auth_service import AuthService
from src.services.rmq_service import RabbitMQService

# Load environment variables from .env file
load_dotenv()

# Set the RSA_KEYS_DIR to a local directory for tests
# This must be done before importing main, as main loads .env
os.environ["RSA_KEYS_DIR"] = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")
if not os.path.exists(os.environ["RSA_KEYS_DIR"]):
    os.makedirs(os.environ["RSA_KEYS_DIR"])


@pytest.fixture(scope="session")
def postgres_container():
    """
    Fixture to provide a Postgres container.
    """
    with PostgresContainer("postgres:18") as postgres:
        yield postgres

@pytest.fixture(scope="session")
def rabbitmq_container():
    """
    Fixture to provide a RabbitMQ container.
    """
    with RabbitMqContainer("rabbitmq:4-management") as rabbitmq:
        yield rabbitmq

@pytest.fixture(scope="function")
def postgres_service(postgres_container):
    """
    Fixture to provide a PostgresService instance connected to a test database.
    This fixture ensures the test database is initialized and clean before each test.
    """
    old_environ = os.environ.copy()
    # Set environment variables to point to the container
    os.environ["POSTGRES_HOST"] = postgres_container.get_container_host_ip()
    os.environ["POSTGRES_PORT"] = str(postgres_container.get_exposed_port(5432))
    os.environ["POSTGRES_USER"] = postgres_container.username
    os.environ["POSTGRES_PASSWORD"] = postgres_container.password
    os.environ["POSTGRES_DB_NAME"] = postgres_container.dbname

    service = PostgresService()

    # Re-initialize the database schema to ensure a clean state for each test
    service.execute_init_db_sql()

    yield service

    # Restore old environment variables
    os.environ.clear()
    os.environ.update(old_environ)


@pytest.fixture(scope="session")
def rmq_service(rabbitmq_container):
    """
    Fixture to provide a RabbitMQService instance.
    This service is stateless and can be shared across tests.
    """
    old_environ = os.environ.copy()
    os.environ["RABBITMQ_HOST"] = rabbitmq_container.get_container_host_ip()
    os.environ["RABBITMQ_PORT"] = str(rabbitmq_container.get_exposed_port(5672))
    os.environ["RABBITMQ_USERNAME"] = rabbitmq_container.username
    os.environ["RABBITMQ_PASSWORD"] = rabbitmq_container.password
    os.environ["RABBITMQ_MAIL_QUEUE_NAME"] = "test-mail-queue"
    
    service = RabbitMQService()
    yield service
    
    # Restore old environment variables
    os.environ.clear()
    os.environ.update(old_environ)



@pytest.fixture(scope="session")
def auth_service():
    """
    Fixture to provide an AuthService instance.
    This service is stateless and can be shared across tests.
    """
    return AuthService()
