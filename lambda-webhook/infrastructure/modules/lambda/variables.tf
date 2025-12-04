variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "resource_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tmi_server_url" {
  description = "TMI API server URL"
  type        = string
}

variable "secrets_manager_arn" {
  description = "ARN of Secrets Manager secret"
  type        = string
}

variable "sqs_queue_url" {
  description = "URL of SQS analysis queue"
  type        = string
}

variable "sqs_queue_arn" {
  description = "ARN of SQS analysis queue"
  type        = string
}

variable "dynamodb_table_name" {
  description = "Name of DynamoDB idempotency table"
  type        = string
}

variable "dynamodb_table_arn" {
  description = "ARN of DynamoDB idempotency table"
  type        = string
}

variable "receiver_lambda_memory" {
  description = "Memory allocation for receiver Lambda (MB)"
  type        = number
}

variable "receiver_lambda_timeout" {
  description = "Timeout for receiver Lambda (seconds)"
  type        = number
}

variable "receiver_lambda_reserved_concurrency" {
  description = "Reserved concurrency for receiver Lambda"
  type        = number
}

variable "analyzer_lambda_memory" {
  description = "Memory allocation for analyzer Lambda (MB)"
  type        = number
}

variable "analyzer_lambda_timeout" {
  description = "Timeout for analyzer Lambda (seconds)"
  type        = number
}

variable "analyzer_lambda_reserved_concurrency" {
  description = "Reserved concurrency for analyzer Lambda"
  type        = number
}

variable "analyzer_lambda_ephemeral_storage" {
  description = "Ephemeral storage for analyzer Lambda /tmp (MB)"
  type        = number
}

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray tracing"
  type        = bool
}

variable "enable_canary" {
  description = "Enable canary deployment for analyzer Lambda"
  type        = bool
}

variable "canary_weight" {
  description = "Weight for canary deployment (0.0 to 1.0)"
  type        = number
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
