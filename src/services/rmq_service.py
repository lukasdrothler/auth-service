import pika, os, json, time, logging

from src.models import MailRequest

logger = logging.getLogger(__name__)


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

        if "RABBITMQ_HEARTBEAT" in os.environ:
            self.heartbeat = int(os.environ["RABBITMQ_HEARTBEAT"])
            logger.info(f"RabbitMQ heartbeat set to: {self.heartbeat}")
        else:
            self.heartbeat = 0
            logger.info(f"RabbitMQ heartbeat set to default: {self.heartbeat}")

        # Connect to RabbitMQ with retry logic
        self.connect()


    ## close connection when instance is deleted
    def __exit__(self):
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            logger.info('RabbitMQ Provider connection closed.')

    def connect(self):
        """Establish connection and channel and declare DLX/queue safely.
        Avoid PRECONDITION_FAILED when a queue already exists with different arguments.
        """
        self.connection = self._connect_with_retry()
        self.channel = self.connection.channel()
        dlx_name = f"{self.mail_queue_name}_dlx"
        # Ensure the dead-letter-exchange exists.
        try:
            self.channel.exchange_declare(exchange=dlx_name, exchange_type='direct', durable=True)
        except Exception as e:
            logger.warning(f"Failed to declare DLX exchange '{dlx_name}': {e}")

        # If the queue already exists, declaring it with different arguments will
        # raise PRECONDITION_FAILED. Use passive declare to detect existence: if
        # the queue exists, skip (we cannot change its arguments); if it does not
        # exist, create it with the DLX argument.
        try:
            self.channel.queue_declare(queue=self.mail_queue_name, passive=True)
            logger.info(f"Queue '{self.mail_queue_name}' already exists, not modifying arguments.")
        except pika.exceptions.ChannelClosedByBroker:
            # Channel was closed because passive declare failed (queue not found).
            # Reopen channel and declare the queue with DLX.
            self.channel = self.connection.channel()
            self.channel.queue_declare(
                queue=self.mail_queue_name,
                durable=True,
                arguments={"x-dead-letter-exchange": dlx_name}
            )
            logger.info(f"Queue '{self.mail_queue_name}' created with DLX '{dlx_name}'.")
        except Exception as e:
            logger.error(f"Unexpected error while declaring queue '{self.mail_queue_name}': {e}")
            raise

    def _connect_with_retry(self, max_retries=10, retry_delay=5) -> pika.BlockingConnection:
        """Connect to RabbitMQ with retry logic for container startup"""
        credentials = pika.PlainCredentials(self.username, self.password)
        parameters = pika.ConnectionParameters(
            host=self.host,
            port=self.port,
            credentials=credentials,
            heartbeat=self.heartbeat,
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

    def _publish_message(self, message: dict) -> None:
        """Publish a message to the RabbitMQ queue"""
        try:
            if not self.connection or self.connection.is_closed:
                logger.info("Connection is closed, reconnecting...")
                self.connect()

            self.channel.basic_publish(
                exchange='',
                routing_key=self.mail_queue_name,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    content_type='application/json',
                    delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE
                    )
            )
        except (pika.exceptions.AMQPConnectionError, pika.exceptions.StreamLostError) as e:
            logger.warning(f"Failed to publish message due to connection error: {e}. Reconnecting and retrying...")
            try:
                self.connect()
                self.channel.basic_publish(
                    exchange='',
                    routing_key=self.mail_queue_name,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(
                        content_type='application/json',
                        delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE
                        )
                )
            except Exception as retry_e:
                logger.error(f"Failed to publish message after retry: {retry_e}")
                raise
        except Exception as e:
            logger.error(f"Failed to publish message to RabbitMQ: {e}")
            raise
    
    def _publish_mail_request(self, mail_request: MailRequest) -> None:
        """Publish a MailRequest to the RabbitMQ queue"""
        self._publish_message(mail_request.model_dump())

    def publish_verify_mail_request(self, username: str, verification_code: str, recipient: str) -> dict[str, str]:
        """Publish an email verification request to the RabbitMQ queue"""
        logger.info(f"Publishing email verification request for user '{username}' to RabbitMQ.")
        request = MailRequest(
            template_name=TemplateName.EMAIL_VERIFICATION,
            username=username,
            verification_code=verification_code,
            recipient=recipient
        )
        self._publish_mail_request(request)
        return {"detail": "Verification code will be sent to user"}
    

    def publish_email_change_verification_request(self, username: str, verification_code: str, recipient: str) -> dict[str, str]:
        """Publish an email change verification request to the RabbitMQ queue"""
        logger.info(f"Publishing email change verification request for user '{username}' to RabbitMQ.")
        request = MailRequest(
            template_name=TemplateName.EMAIL_CHANGE_VERIFICATION,
            username=username,
            verification_code=verification_code,
            recipient=recipient
        )
        self._publish_mail_request(request)
        return {"detail": "Email change verification code will be sent to user"}
    

    def publish_forgot_password_verification_request(self, username: str, verification_code: str, recipient: str) -> dict[str, str]:
        """Publish a forgot password verification request to the RabbitMQ queue"""
        logger.info(f"Publishing forgot password verification request for user '{username}' to RabbitMQ.")
        request = MailRequest(
            template_name=TemplateName.FORGOT_PASSWORD_VERIFICATION,
            username=username,
            verification_code=verification_code,
            recipient=recipient
        )
        self._publish_mail_request(request)
        return {"detail": "Forgot password verification code will be sent to user"}


class TemplateName():
    EMAIL_VERIFICATION = "email_verification"
    EMAIL_CHANGE_VERIFICATION = "email_change_verification"
    FORGOT_PASSWORD_VERIFICATION = "forgot_password_verification"  # nosec