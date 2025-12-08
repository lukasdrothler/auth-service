import os
import pytest
from dotenv import load_dotenv
from testcontainers.mysql import MySqlContainer
from testcontainers.rabbitmq import RabbitMqContainer
from src.database_service import DatabaseService
from src.auth_service import AuthService
from src.rmq_service import RabbitMQService

# Load environment variables from .env file
load_dotenv()

# Set the RSA_KEYS_DIR to a local directory for tests
# This must be done before importing main, as main loads .env
os.environ["RSA_KEYS_DIR"] = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")
if not os.path.exists(os.environ["RSA_KEYS_DIR"]):
    os.makedirs(os.environ["RSA_KEYS_DIR"])


@pytest.fixture(scope="session")
def mysql_container():
    """
    Fixture to provide a MySQL container.
    """
    with MySqlContainer("mysql:8.3", dbname="auth_test") as mysql:
        yield mysql

@pytest.fixture(scope="session")
def rabbitmq_container():
    """
    Fixture to provide a RabbitMQ container.
    """
    with RabbitMqContainer("rabbitmq:4-management") as rabbitmq:
        yield rabbitmq

@pytest.fixture(scope="function")
def db_service(mysql_container):
    """
    Fixture to provide a DatabaseService instance connected to a test database.
    This fixture ensures the test database is initialized and clean before each test.
    """
    old_environ = os.environ.copy()
    # Set environment variables to point to the container
    os.environ["DB_HOST"] = mysql_container.get_container_host_ip()
    os.environ["DB_PORT"] = str(mysql_container.get_exposed_port(3306))
    os.environ["DB_USER"] = mysql_container.username
    os.environ["DB_PASSWORD"] = mysql_container.password
    os.environ["DB_NAME"] = mysql_container.dbname

    service = DatabaseService()

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
    try:
        return RabbitMQService()
    finally:
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
