import io
import json
import logging
import base64
import os
from fdk import response
import oci


def handler(ctx, data: io.BytesIO = None):
    """
    OCI Function handler that processes basic authenticated webhooks
    and forwards messages to an OCI Queue.
    """
    try:
        # Parse the incoming request
        body = json.loads(data.getvalue())
        
        # Extract headers from the request context
        headers = ctx.Headers()
        
        # Validate basic authentication
        if not validate_basic_auth(headers):
            logging.error("Authentication failed")
            return response.Response(
                ctx, 
                response_data="Unauthorized", 
                headers={"Content-Type": "text/plain"},
                status_code=401
            )
        
        # Get the message body
        message_body = body.get('message', body)  # Use 'message' field or entire body
        
        # Send message to OCI Queue
        queue_response = send_to_queue(message_body)
        
        if queue_response:
            logging.info(f"Message sent to queue successfully: {queue_response}")
            return response.Response(
                ctx,
                response_data=json.dumps({"status": "success", "message": "Webhook processed"}),
                headers={"Content-Type": "application/json"},
                status_code=200
            )
        else:
            logging.error("Failed to send message to queue")
            return response.Response(
                ctx,
                response_data=json.dumps({"status": "error", "message": "Failed to process webhook"}),
                headers={"Content-Type": "application/json"},
                status_code=500
            )
            
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON payload: {e}")
        return response.Response(
            ctx,
            response_data="Invalid JSON payload",
            headers={"Content-Type": "text/plain"},
            status_code=400
        )
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return response.Response(
            ctx,
            response_data="Internal server error",
            headers={"Content-Type": "text/plain"},
            status_code=500
        )


def validate_basic_auth(headers):
    """
    Validate basic authentication from request headers.
    """
    try:
        # Get expected credentials from environment variables
        expected_username = os.environ.get('WEBHOOK_USERNAME')
        expected_password = os.environ.get('WEBHOOK_PASSWORD')
        
        if not expected_username or not expected_password:
            logging.error("Authentication credentials not configured")
            return False
        
        # Get authorization header
        auth_header = headers.get('authorization') or headers.get('Authorization')
        if not auth_header:
            logging.error("No authorization header found")
            return False
        
        # Parse basic auth header
        if not auth_header.startswith('Basic '):
            logging.error("Invalid authorization header format")
            return False
        
        # Decode credentials
        encoded_credentials = auth_header[6:]  # Remove 'Basic ' prefix
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':', 1)
        
        # Validate credentials
        if username == expected_username and password == expected_password:
            return True
        else:
            logging.error("Invalid credentials provided")
            return False
            
    except Exception as e:
        logging.error(f"Authentication validation error: {e}")
        return False


def send_to_queue(message_body):
    """
    Send message to Oracle OCI Queue.
    """
    try:
        # Get queue configuration from environment variables
        queue_id = os.environ.get('OCI_QUEUE_ID')
        queue_endpoint = os.environ.get('OCI_QUEUE_ENDPOINT')
        
        if not queue_id or not queue_endpoint:
            logging.error("Queue configuration not found in environment variables")
            return False
        
        # Create OCI config from environment variables
        config = create_oci_config_from_env()
        if not config:
            logging.error("Failed to create OCI configuration from environment variables")
            return False
        
        # Create queue client with environment-based config
        queue_client = oci.queue.QueueClient(config)
        
        # Prepare the message
        if isinstance(message_body, dict):
            message_content = json.dumps(message_body)
        else:
            message_content = str(message_body)
        
        # Create message details
        put_message_details = oci.queue.models.PutMessagesDetails(
            content=message_content
        )
        
        put_messages_details = oci.queue.models.PutMessagesDetails(
            messages=[put_message_details]
        )
        
        # Send message to queue
        put_messages_response = queue_client.put_messages(
            queue_id=queue_id,
            put_messages_details=put_messages_details
        )
        
        logging.info(f"Message sent to queue. Response: {put_messages_response.data}")
        return put_messages_response.data
        
    except Exception as e:
        logging.error(f"Failed to send message to queue: {e}")
        return False


def create_oci_config_from_env():
    """
    Create OCI configuration from environment variables.
    """
    try:
        # Required OCI authentication environment variables
        user_ocid = os.environ.get('OCI_USER_OCID')
        fingerprint = os.environ.get('OCI_FINGERPRINT')
        tenancy_ocid = os.environ.get('OCI_TENANCY_OCID')
        region = os.environ.get('OCI_REGION')
        private_key_content = os.environ.get('OCI_PRIVATE_KEY')
        
        # Validate required variables
        required_vars = {
            'OCI_USER_OCID': user_ocid,
            'OCI_FINGERPRINT': fingerprint,
            'OCI_TENANCY_OCID': tenancy_ocid,
            'OCI_REGION': region,
            'OCI_PRIVATE_KEY': private_key_content
        }
        
        missing_vars = [var for var, value in required_vars.items() if not value]
        if missing_vars:
            logging.error(f"Missing required environment variables: {', '.join(missing_vars)}")
            return None
        
        # Create OCI config
        config = {
            'user': user_ocid,
            'fingerprint': fingerprint,
            'tenancy': tenancy_ocid,
            'region': region,
            'key_content': private_key_content
        }
        
        # Optional: Add compartment if provided
        compartment_ocid = os.environ.get('OCI_COMPARTMENT_OCID')
        if compartment_ocid:
            config['compartment'] = compartment_ocid
        
        logging.info("OCI configuration created successfully from environment variables")
        return config
        
    except Exception as e:
        logging.error(f"Error creating OCI configuration: {e}")
        return None


# Additional utility functions for enhanced functionality

def validate_message_format(message):
    """
    Optional: Validate message format before sending to queue.
    """
    # Add your custom validation logic here
    if not message:
        return False, "Empty message"
    
    # Example: Check message size (OCI Queue has limits)
    if len(str(message)) > 1024 * 1024:  # 1MB limit example
        return False, "Message too large"
    
    return True, "Valid"


def add_metadata_to_message(original_message, ctx):
    """
    Optional: Add metadata to the message before queuing.
    """
    enhanced_message = {
        'timestamp': ctx.CallID(),  # Function call ID as timestamp reference
        'source': 'webhook',
        'original_message': original_message
    }
    return enhanced_message