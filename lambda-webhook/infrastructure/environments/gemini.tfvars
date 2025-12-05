# TMI Terraform Analyzer - Google Gemini Configuration

# AWS Configuration
aws_region  = "us-east-1"
environment = "prod"

# Domain Configuration
webhook_domain = "webhook.tmi.dev"
# route53_zone_id and acm_certificate_arn must be provided via CLI or environment variables

# Secrets Manager
# secrets_manager_arn must be provided via CLI or environment variables
# Secret must contain: client_id, client_secret, gcp_service_account_key, gcp_project_id, webhook_secret

# TMI Server
tmi_server_url = "https://api.tmi.dev"

# LLM Configuration - Google Gemini
llm_provider = "gemini"
llm_model    = "gemini-2.0-flash-exp"  # or "gemini-1.5-pro-002", or leave empty for default

# Lambda Configuration - Optimized for Gemini (faster, uses less memory)
receiver_lambda_memory              = 128
receiver_lambda_timeout             = 10
receiver_lambda_reserved_concurrency = 10

analyzer_lambda_memory              = 2048 # Gemini SDK is lighter than Anthropic
analyzer_lambda_timeout             = 600  # 10 minutes (Gemini is 2x faster)
analyzer_lambda_reserved_concurrency = 5
analyzer_lambda_ephemeral_storage   = 2048 # 2GB

# SQS Configuration
sqs_visibility_timeout = 720 # 12 minutes (6x analyzer timeout)
sqs_max_receive_count  = 3

# DynamoDB Configuration
dynamodb_ttl_days = 7

# Monitoring - Full monitoring in production
# alarm_email must be provided via CLI or environment variables
enable_dlq_alarms   = true
enable_xray_tracing = true

# Canary Deployment
enable_canary = true
canary_weight = 0.1 # Start with 10% traffic to new version
