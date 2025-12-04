"""
TMI Webhook Receiver Lambda Function.

This Lambda function handles incoming webhooks from the TMI server:
1. Responds to challenge/response verification
2. Validates HMAC signatures
3. Checks for duplicate deliveries (idempotency)
4. Enqueues repository analysis requests to SQS

Environment Variables Required:
- SQS_QUEUE_URL: URL of the SQS queue for analysis requests
- DYNAMODB_TABLE: Name of the DynamoDB table for idempotency tracking
- SECRETS_ARN: ARN of the AWS Secrets Manager secret containing webhook_secret
"""

import json
import hmac
import hashlib
import boto3
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional

# Initialize AWS clients
dynamodb = boto3.client('dynamodb')
sqs = boto3.client('sqs')
secretsmanager = boto3.client('secretsmanager')

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Cache for secrets (Lambda container reuse)
_secrets_cache: Optional[Dict[str, str]] = None


def get_secrets() -> Dict[str, str]:
    """
    Load secrets from AWS Secrets Manager.

    Secrets are cached in memory for Lambda container reuse.

    Returns:
        Dictionary containing webhook_secret and other credentials
    """
    global _secrets_cache

    if _secrets_cache is None:
        try:
            secret_arn = os.environ['SECRETS_ARN']
            response = secretsmanager.get_secret_value(SecretId=secret_arn)
            _secrets_cache = json.loads(response['SecretString'])
            logger.info("Secrets loaded from Secrets Manager")
        except Exception as e:
            logger.error(f"Failed to load secrets: {e}")
            raise

    return _secrets_cache


def verify_signature(payload: str, signature: str, secret: str) -> bool:
    """
    Verify HMAC SHA256 signature from TMI webhook.

    Args:
        payload: Raw webhook payload body
        signature: Signature from X-Webhook-Signature header (without 'sha256=' prefix)
        secret: Shared webhook secret

    Returns:
        True if signature is valid, False otherwise
    """
    expected = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected, signature)


def is_duplicate(delivery_id: str) -> bool:
    """
    Check if webhook delivery has already been processed (idempotency).

    Uses DynamoDB conditional write to atomically check and mark as processing.

    Args:
        delivery_id: X-Webhook-Delivery-Id from TMI

    Returns:
        True if already processed, False if this is first time
    """
    table_name = os.environ['DYNAMODB_TABLE']

    try:
        # Try to get existing item
        response = dynamodb.get_item(
            TableName=table_name,
            Key={'delivery_id': {'S': delivery_id}}
        )

        if 'Item' in response:
            logger.info(f"Delivery {delivery_id} already processed (duplicate)")
            return True

        # Mark as processing with conditional write
        dynamodb.put_item(
            TableName=table_name,
            Item={
                'delivery_id': {'S': delivery_id},
                'timestamp': {'N': str(int(datetime.now().timestamp()))},
                'status': {'S': 'processing'},
                'ttl': {'N': str(int(datetime.now().timestamp()) + 604800)}  # 7 days
            },
            ConditionExpression='attribute_not_exists(delivery_id)'
        )

        logger.info(f"Delivery {delivery_id} marked as processing")
        return False

    except dynamodb.exceptions.ConditionalCheckFailedException:
        # Race condition: another invocation already processing
        logger.warning(f"Delivery {delivery_id} race condition detected")
        return True
    except Exception as e:
        logger.error(f"DynamoDB error checking delivery {delivery_id}: {e}")
        # Fail safe: assume duplicate to prevent duplicate processing
        return True


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for TMI webhook receiver.

    Args:
        event: API Gateway event containing webhook request
        context: Lambda context object

    Returns:
        API Gateway response with statusCode and body
    """
    # Normalize headers to lowercase for case-insensitive lookup
    headers = {k.lower(): v for k, v in event.get('headers', {}).items()}

    logger.info(f"Received webhook request: {event.get('requestContext', {}).get('requestId')}")

    # 1. Handle challenge/response verification
    if 'x-webhook-challenge' in headers:
        challenge = headers['x-webhook-challenge']
        logger.info(f"Responding to webhook challenge: {challenge}")
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'X-Webhook-Challenge': challenge
            },
            'body': json.dumps({'challenge': challenge})
        }

    # 2. Validate HMAC signature
    raw_body = event.get('body', '')
    signature_header = headers.get('x-webhook-signature', '')

    # Remove 'sha256=' prefix if present
    signature = signature_header.replace('sha256=', '')

    try:
        secrets = get_secrets()
        webhook_secret = secrets.get('webhook_secret')

        if not webhook_secret:
            logger.error("webhook_secret not found in Secrets Manager")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': 'Server configuration error'})
            }

        if not verify_signature(raw_body, signature, webhook_secret):
            logger.warning("Invalid webhook signature")
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Invalid signature'})
            }
    except Exception as e:
        logger.error(f"Error validating signature: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }

    # 3. Parse webhook payload
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON payload: {e}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid JSON payload'})
        }

    event_type = body.get('event_type')

    # Filter for repository events only
    if event_type not in ['repository.created', 'repository.updated']:
        logger.info(f"Ignoring non-repository event: {event_type}")
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ignored', 'event_type': event_type})
        }

    # 4. Check idempotency
    delivery_id = headers.get('x-webhook-delivery-id')

    if not delivery_id:
        logger.warning("Missing X-Webhook-Delivery-Id header")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing X-Webhook-Delivery-Id header'})
        }

    if is_duplicate(delivery_id):
        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'duplicate',
                'delivery_id': delivery_id
            })
        }

    # 5. Enqueue to SQS
    try:
        message = {
            'delivery_id': delivery_id,
            'event_type': event_type,
            'threat_model_id': body.get('threat_model_id'),
            'repository_id': body.get('resource_id'),
            'owner_id': body.get('owner_id'),
            'timestamp': body.get('timestamp')
        }

        queue_url = os.environ['SQS_QUEUE_URL']

        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(message),
            MessageAttributes={
                'event_type': {'StringValue': event_type, 'DataType': 'String'},
                'threat_model_id': {'StringValue': message['threat_model_id'], 'DataType': 'String'}
            }
        )

        logger.info(f"Enqueued analysis request for delivery {delivery_id}: {event_type}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'queued',
                'delivery_id': delivery_id,
                'event_type': event_type
            })
        }

    except Exception as e:
        logger.error(f"Failed to enqueue message: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Failed to queue analysis request'})
        }
