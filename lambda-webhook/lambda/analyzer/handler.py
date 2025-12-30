"""
TMI Terraform Analyzer Lambda Function.

This Lambda function is triggered by SQS messages from the webhook receiver.
It analyzes Terraform repositories and creates notes in TMI threat models.

Flow:
1. Receive SQS message with repository event
2. Authenticate with TMI using OAuth client credentials
3. Fetch repository details from TMI
4. Clone repository (sparse checkout - .tf files only)
5. Analyze with LLM (supports Anthropic, OpenAI, x.ai, Gemini via LiteLLM)
6. Generate markdown report with webhook metadata
7. Create/update note in TMI threat model
8. Update DynamoDB with completion status

Environment Variables Required:
- TMI_SERVER_URL: TMI API base URL (e.g., https://api.tmi.dev)
- SECRETS_ARN: ARN of AWS Secrets Manager secret
- DYNAMODB_TABLE: DynamoDB table for delivery tracking
- LLM_PROVIDER: LLM provider (anthropic, openai, xai, gemini)
- LLM_MODEL: Optional model override
"""

import json
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Dict, Any
import boto3

# Add parent directory to path to import tmi_tf modules
sys.path.insert(0, str(Path(__file__).parent))

# Import Lambda-specific modules
from lambda_auth import LambdaOAuthClient
from lambda_config import LambdaConfig
from lambda_markdown import generate_webhook_report, generate_error_report

# Import original tmi_tf modules (copied into analyzer directory)
from tmi_tf.tmi_client_wrapper import TMIClient
from tmi_tf.repo_analyzer import RepositoryAnalyzer

# Import unified LLM analyzer
from llm_analyzer import LLMAnalyzer

# Initialize AWS clients
dynamodb = boto3.client('dynamodb')

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def update_delivery_status(delivery_id: str, status: str) -> None:
    """
    Update delivery status in DynamoDB.

    Args:
        delivery_id: Webhook delivery ID
        status: New status ('processing', 'completed', 'failed')
    """
    try:
        table_name = os.environ['DYNAMODB_TABLE']
        dynamodb.update_item(
            TableName=table_name,
            Key={'delivery_id': {'S': delivery_id}},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': {'S': status}}
        )
        logger.info(f"Updated delivery {delivery_id} status to: {status}")
    except Exception as e:
        logger.error(f"Failed to update delivery status: {e}")
        # Don't raise - this is non-critical


def analyze_repository(
    config: LambdaConfig,
    tmi_client: TMIClient,
    threat_model_id: str,
    repository_id: str,
    webhook_metadata: Dict[str, Any],
    lambda_request_id: str
) -> None:
    """
    Analyze a single repository and create note in TMI.

    Args:
        config: Lambda configuration
        tmi_client: Authenticated TMI API client
        threat_model_id: Threat model UUID
        repository_id: Repository UUID to analyze
        webhook_metadata: Webhook event metadata
        lambda_request_id: Lambda request ID for logging

    Raises:
        Exception: If analysis fails
    """
    # Fetch repository details from TMI
    logger.info(f"Fetching repository {repository_id} from threat model {threat_model_id}")
    repositories = tmi_client.get_threat_model_repositories(threat_model_id)

    # Find the specific repository
    repository = None
    for repo in repositories:
        if repo.id == repository_id:
            repository = repo
            break

    if not repository:
        raise ValueError(f"Repository {repository_id} not found in threat model {threat_model_id}")

    logger.info(f"Analyzing repository: {repository.name} ({repository.url})")

    # Initialize repository analyzer
    analyzer = RepositoryAnalyzer(config)  # type: ignore[arg-type]

    # Clone and analyze repository
    with analyzer.clone_repository_sparse(repository.url, repository.name) as tf_repo:
        if not tf_repo:
            raise ValueError(f"No Terraform files found in repository: {repository.name}")

        logger.info(f"Found {len(tf_repo.terraform_files)} Terraform files")

        # Initialize unified LLM analyzer (supports all providers via LiteLLM)
        logger.info(f"Using LLM provider: {config.llm_provider}")
        llm_analyzer = LLMAnalyzer(config)

        # Analyze repository
        analysis_result = llm_analyzer.analyze_repository(tf_repo)

        if not analysis_result or not analysis_result.get('analysis'):
            raise ValueError("LLM analysis returned empty result")

        logger.info(
            f"LLM analysis completed: {analysis_result.get('input_tokens', 0)} input tokens, "
            f"{analysis_result.get('output_tokens', 0)} output tokens, "
            f"cost: ${analysis_result.get('total_cost', 0):.4f}"
        )

        # Generate markdown report with webhook metadata
        markdown = generate_webhook_report(
            threat_model_id=threat_model_id,
            repository=repository,
            analysis_content=analysis_result.get('analysis', ''),
            webhook_metadata=webhook_metadata,
            lambda_request_id=lambda_request_id,
            llm_metadata={
                'provider': analysis_result.get('provider', config.llm_provider),
                'model': analysis_result.get('model', 'unknown'),
                'input_tokens': analysis_result.get('input_tokens', 0),
                'output_tokens': analysis_result.get('output_tokens', 0),
                'total_cost': analysis_result.get('total_cost', 0.0)
            }
        )

        # Create or update note in TMI
        note_name = f"Terraform Analysis: {repository.name}"
        note_description = f"Automated analysis triggered by {webhook_metadata['event_type']}"

        logger.info(f"Creating/updating note: {note_name}")
        tmi_client.create_or_update_note(
            threat_model_id=threat_model_id,
            name=note_name,
            content=markdown,
            description=note_description
        )

        logger.info("Note created/updated successfully in TMI")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for TMI Terraform analyzer.

    Args:
        event: SQS event containing webhook messages
        context: Lambda context object

    Returns:
        Response dictionary
    """
    logger.info(f"Lambda invoked with {len(event.get('Records', []))} SQS messages")

    # Process each SQS message
    for record in event.get('Records', []):
        delivery_id = None

        try:
            # Parse SQS message body
            message = json.loads(record['body'])
            delivery_id = message.get('delivery_id')
            event_type = message.get('event_type')
            threat_model_id = message.get('threat_model_id')
            repository_id = message.get('repository_id')

            logger.info(f"Processing delivery {delivery_id}: {event_type}")
            logger.info(f"Threat model: {threat_model_id}, Repository: {repository_id}")

            # Initialize configuration from Secrets Manager
            config = LambdaConfig.from_secrets_manager()

            # Authenticate with TMI using OAuth client credentials
            tmi_server_url = os.environ.get('TMI_SERVER_URL', 'https://api.tmi.dev')
            auth_client = LambdaOAuthClient(tmi_server_url)
            token = auth_client.get_token()

            # Initialize TMI client with token
            tmi_client = TMIClient(config, auth_token=token)  # type: ignore[arg-type]

            # Analyze repository and create note
            analyze_repository(
                config=config,
                tmi_client=tmi_client,
                threat_model_id=threat_model_id,
                repository_id=repository_id,
                webhook_metadata=message,
                lambda_request_id=context.request_id
            )

            # Mark as completed in DynamoDB
            if delivery_id:
                update_delivery_status(delivery_id, 'completed')

            logger.info(f"Successfully processed delivery {delivery_id}")

        except Exception as e:
            logger.error(f"Failed to process delivery {delivery_id}: {e}")
            logger.error(traceback.format_exc())

            # Try to create error note in TMI
            try:
                if delivery_id:
                    # Re-initialize clients for error reporting
                    config = LambdaConfig.from_secrets_manager()
                    tmi_server_url = os.environ.get('TMI_SERVER_URL', 'https://api.tmi.dev')
                    auth_client = LambdaOAuthClient(tmi_server_url)
                    token = auth_client.get_token()
                    tmi_client = TMIClient(config, auth_token=token)  # type: ignore[arg-type]

                    # Fetch repository details for error note
                    message = json.loads(record['body'])
                    threat_model_id = message.get('threat_model_id')
                    repository_id = message.get('repository_id')

                    repositories = tmi_client.get_threat_model_repositories(threat_model_id)
                    repository = next((r for r in repositories if r.id == repository_id), None)

                    if repository:
                        # Create error note
                        error_markdown = generate_error_report(
                            threat_model_id=threat_model_id,
                            repository=repository,
                            error=e,
                            webhook_metadata=message,
                            lambda_request_id=context.request_id
                        )

                        tmi_client.create_or_update_note(
                            threat_model_id=threat_model_id,
                            name=f"Terraform Analysis ERROR: {repository.name}",
                            content=error_markdown,
                            description=f"Analysis failed: {str(e)}"
                        )

                        logger.info("Error note created in TMI")

                    # Mark as failed in DynamoDB
                    update_delivery_status(delivery_id, 'failed')

            except Exception as note_error:
                logger.error(f"Failed to create error note: {note_error}")

            # Re-raise exception to trigger SQS DLQ
            raise

    return {
        'statusCode': 200,
        'body': json.dumps({'status': 'completed'})
    }
