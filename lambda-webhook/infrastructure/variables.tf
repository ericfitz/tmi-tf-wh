variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "tmi-tf"
}

variable "webhook_domain" {
  description = "Domain name for webhook endpoint"
  type        = string
  default     = "webhook.tmi.dev"
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID for tmi.dev"
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN of ACM certificate for webhook domain (must be in us-east-1)"
  type        = string
}

variable "secrets_manager_arn" {
  description = "ARN of Secrets Manager secret containing OAuth credentials and API keys"
  type        = string
}

variable "tmi_server_url" {
  description = "TMI API server URL"
  type        = string
  default     = "https://api.tmi.dev"
}

# Lambda Configuration

variable "receiver_lambda_memory" {
  description = "Memory allocation for receiver Lambda (MB)"
  type        = number
  default     = 128
}

variable "receiver_lambda_timeout" {
  description = "Timeout for receiver Lambda (seconds)"
  type        = number
  default     = 10
}

variable "receiver_lambda_reserved_concurrency" {
  description = "Reserved concurrency for receiver Lambda"
  type        = number
  default     = 10
}

variable "analyzer_lambda_memory" {
  description = "Memory allocation for analyzer Lambda (MB)"
  type        = number
  default     = 3008
}

variable "analyzer_lambda_timeout" {
  description = "Timeout for analyzer Lambda (seconds)"
  type        = number
  default     = 900 # 15 minutes
}

variable "analyzer_lambda_reserved_concurrency" {
  description = "Reserved concurrency for analyzer Lambda"
  type        = number
  default     = 5
}

variable "analyzer_lambda_ephemeral_storage" {
  description = "Ephemeral storage for analyzer Lambda /tmp (MB)"
  type        = number
  default     = 2048 # 2GB
}

# SQS Configuration

variable "sqs_visibility_timeout" {
  description = "SQS visibility timeout (seconds) - should be 6x Lambda timeout"
  type        = number
  default     = 960 # 16 minutes
}

variable "sqs_max_receive_count" {
  description = "Max receive count before moving to DLQ"
  type        = number
  default     = 3
}

# DynamoDB Configuration

variable "dynamodb_ttl_days" {
  description = "TTL for DynamoDB idempotency records (days)"
  type        = number
  default     = 7
}

# Monitoring Configuration

variable "alarm_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = ""
}

variable "enable_canary" {
  description = "Enable Lambda canary deployment"
  type        = bool
  default     = false
}

variable "canary_weight" {
  description = "Weight for canary deployment (0.0 to 1.0)"
  type        = number
  default     = 0.1

  validation {
    condition     = var.canary_weight >= 0.0 && var.canary_weight <= 1.0
    error_message = "Canary weight must be between 0.0 and 1.0"
  }
}

# LLM Configuration

variable "llm_provider" {
  description = "LLM provider for analysis (anthropic, xai, or gemini)"
  type        = string
  default     = "anthropic"

  validation {
    condition     = contains(["anthropic", "xai", "gemini"], var.llm_provider)
    error_message = "LLM provider must be anthropic, xai, or gemini"
  }
}

variable "llm_model" {
  description = "LLM model name (optional - uses provider default if empty)"
  type        = string
  default     = ""
}

# Feature Flags

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray tracing for Lambda functions"
  type        = bool
  default     = true
}

variable "enable_dlq_alarms" {
  description = "Enable CloudWatch alarms for DLQ depth"
  type        = bool
  default     = true
}
