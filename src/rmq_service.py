import pika, os, json, time, logging

from src.models import MailRequest

logger = logging.getLogger(__name__)

# TODO: Add TLS support for RabbitMQ connection
# TODO: Add unit tests for RabbitMQService

class RabbitMQService:
    def __init__(self):
        if "RABBITMQ_HOST" in os.environ:
            self.host = os.environ["RABBITMQ_HOST"]
        else:
            self.host = "localhost"
        logger.info(f"RabbitMQ host set to: {self.host}")

        if "RABBITMQ_PORT" in os.environ:
            self.port = int(os.environ["RABBITMQ_PORT"])
        else:
            self.port = 5672
        logger.info(f"RabbitMQ port set to: {self.port}")

        if "RABBITMQ_MAIL_QUEUE_NAME" in os.environ:
            self.mail_queue_name = os.environ["RABBITMQ_MAIL_QUEUE_NAME"]
            logger.info(f"RabbitMQ queue name set from env: {self.mail_queue_name}")
        else:
            self.mail_queue_name = "finyed-mails"
            logger.info(f"RabbitMQ queue name set to defailt: {self.mail_queue_name}")

        if "RABBITMQ_USERNAME" in os.environ:
            self.username = os.environ["RABBITMQ_USERNAME"]
            logger.info(f"RabbitMQ username set to: {self.username}")
        else:
            raise ValueError("RABBITMQ_USERNAME environment variable is required")
        
        if "RABBITMQ_PASSWORD" in os.environ:
            self.password = os.environ["RABBITMQ_PASSWORD"]
            logger.info(f"RabbitMQ password set from env")
        else:
            raise ValueError("RABBITMQ_PASSWORD environment variable is required")

        # Connect to RabbitMQ with retry logic
        self.connection = self._connect_with_retry()

        self.channel = self.connection.channel()
        self.channel.queue_declare(
            queue=self.mail_queue_name, 
            durable=True,
            arguments={"x-dead-letter-exchange": f"{self.mail_queue_name}_dlx"}
        )


    ## close connection when instance is deleted
    def __exit__(self):
        self.connection.close()
        logger.info('RabbitMQ Provider connection closed.')


    def _connect_with_retry(self, max_retries=10, retry_delay=5) -> pika.BlockingConnection:
        """Connect to RabbitMQ with retry logic for container startup"""
        credentials = pika.PlainCredentials(self.username, self.password)
        parameters = pika.ConnectionParameters(
            host=self.host,
            port=self.port,
            credentials=credentials,
            heartbeat=600,
            blocked_connection_timeout=300
        )
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Attempting to connect to RabbitMQ at {self.host}:{self.port} (attempt {attempt + 1}/{max_retries})")
                connection = pika.BlockingConnection(parameters)
                logger.info(f"Successfully connected to RabbitMQ")
                return connection
            except pika.exceptions.AMQPConnectionError as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Connection failed: {e}. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Failed to connect to RabbitMQ after {max_retries} attempts")
                    raise


    def publish_verify_mail_request(self, username: str, verification_code: str, recipient: str) -> dict[str, str]:
        """Publish an email verification request to the RabbitMQ queue"""
        logger.info(f"Publishing email verification request for user '{username}' to RabbitMQ.")
        request = MailRequest(
            template_name=TemplateName.EMAIL_VERIFICATION,
            username=username,
            verification_code=verification_code,
            recipient=recipient
        )
        self._publish_message(request.model_dump())
        return {"detail": "Verification code will be sent to user"}


    def _publish_message(self, message: dict) -> None:
        """Publish a message to the RabbitMQ queue"""
        try:
            self.channel.basic_publish(
                exchange='',
                routing_key=self.mail_queue_name,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    content_type='application/json',
                    delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE
                    )
            )
        except Exception as e:
            logger.error(f"Failed to publish message to RabbitMQ: {e}")
            raise


class TemplateName():
    EMAIL_VERIFICATION = "email_verification"
    EMAIL_CHANGE_VERIFICATION = "email_change_verification"
    FORGOT_PASSWORD_VERIFICATION = "forgot_password_verification"