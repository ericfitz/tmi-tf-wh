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

variable "visibility_timeout" {
  description = "Visibility timeout in seconds"
  type        = number
}

variable "max_receive_count" {
  description = "Max receive count before moving to DLQ"
  type        = number
}

variable "enable_dlq_alarms" {
  description = "Enable CloudWatch alarms for DLQ"
  type        = bool
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
