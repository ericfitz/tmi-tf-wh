# TMI Terraform Analyzer - Development Environment Configuration

# AWS Configuration
aws_region  = "us-east-1"
environment = "dev"

# Domain Configuration (use dev subdomain)
webhook_domain = "webhook-dev.tmi.dev"
# route53_zone_id and acm_certificate_arn must be provided via CLI or environment variables

# Secrets Manager
# secrets_manager_arn must be provided via CLI or environment variables

# TMI Server (can point to local dev server if needed)
tmi_server_url = "https://api.tmi.dev" # or "http://localhost:8080" for local dev

# Lambda Configuration - Reduced for dev environment
receiver_lambda_memory              = 128
receiver_lambda_timeout             = 10
receiver_lambda_reserved_concurrency = 5 # Lower concurrency for dev

analyzer_lambda_memory              = 2048 # Lower memory for dev
analyzer_lambda_timeout             = 600  # 10 minutes
analyzer_lambda_reserved_concurrency = 2   # Lower concurrency for dev
analyzer_lambda_ephemeral_storage   = 1024 # 1GB for dev

# SQS Configuration
sqs_visibility_timeout = 720 # 12 minutes (6x analyzer timeout)
sqs_max_receive_count  = 3

# DynamoDB Configuration
dynamodb_ttl_days = 7

# Monitoring
alarm_email         = "" # No alarms in dev
enable_dlq_alarms   = false
enable_xray_tracing = true

# Canary Deployment - Disabled in dev
enable_canary = false
canary_weight = 0.0
