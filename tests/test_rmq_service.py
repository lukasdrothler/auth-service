import json
import pytest
from src.managers.rabbitmq import TemplateName

def test_publish_verify_mail_request(rmq_manager):
    """
    Test that publish_verify_mail_request successfully publishes a message to the RabbitMQ queue.
    """
    username = "testuser"
    verification_code = "123456"
    recipient = "test@example.com"

    # Publish the message
    result = rmq_manager.publish_verify_mail_request(username, verification_code, recipient)
    
    assert result == {"detail": "Verification code will be sent to user"}

    # Verify the message is in the queue
    # We use basic_get to fetch one message
    method_frame, header_frame, body = rmq_manager.channel.basic_get(queue=rmq_manager.mail_queue_name)
    
    assert method_frame is not None, "Message not found in queue"
    
    message = json.loads(body)
    assert message["template_name"] == TemplateName.EMAIL_VERIFICATION
    assert message["username"] == username
    assert message["verification_code"] == verification_code
    assert message["recipient"] == recipient
    
    # Acknowledge the message to remove it from the queue
    rmq_manager.channel.basic_ack(method_frame.delivery_tag)

def test_publish_message_persistence(rmq_manager):
    """
    Test that messages are published with persistent delivery mode.
    """
    username = "persistence_test"
    verification_code = "654321"
    recipient = "persist@example.com"

    rmq_manager.publish_verify_mail_request(username, verification_code, recipient)

    method_frame, header_frame, body = rmq_manager.channel.basic_get(queue=rmq_manager.mail_queue_name)
    
    assert method_frame is not None
    # Check delivery_mode is 2 (Persistent)
    assert header_frame.delivery_mode == 2
    
    rmq_manager.channel.basic_ack(method_frame.delivery_tag)

def test_publish_email_change_verification_request(rmq_manager):
    """
    Test that publish_email_change_verification_request successfully publishes a message.
    """
    username = "change_email_user"
    verification_code = "654321"
    recipient = "new_email@example.com"

    result = rmq_manager.publish_email_change_verification_request(username, verification_code, recipient)
    
    assert result == {"detail": "Email change verification code will be sent to user"}

    method_frame, header_frame, body = rmq_manager.channel.basic_get(queue=rmq_manager.mail_queue_name)
    assert method_frame is not None
    
    message = json.loads(body)
    assert message["template_name"] == TemplateName.EMAIL_CHANGE_VERIFICATION
    assert message["username"] == username
    assert message["verification_code"] == verification_code
    assert message["recipient"] == recipient
    
    rmq_manager.channel.basic_ack(method_frame.delivery_tag)


def test_publish_forgot_password_verification_request(rmq_manager):
    """
    Test that publish_forgot_password_verification_request successfully publishes a message.
    """
    username = "forgot_pw_user"
    verification_code = "987654"
    recipient = "forgot@example.com"

    result = rmq_manager.publish_forgot_password_verification_request(username, verification_code, recipient)
    
    assert result == {"detail": "Forgot password verification code will be sent to user"}

    method_frame, header_frame, body = rmq_manager.channel.basic_get(queue=rmq_manager.mail_queue_name)
    assert method_frame is not None
    
    message = json.loads(body)
    assert message["template_name"] == TemplateName.FORGOT_PASSWORD_VERIFICATION
    assert message["username"] == username
    assert message["verification_code"] == verification_code
    assert message["recipient"] == recipient
    
    rmq_manager.channel.basic_ack(method_frame.delivery_tag)
