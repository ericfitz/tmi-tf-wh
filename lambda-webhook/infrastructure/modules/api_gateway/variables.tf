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

variable "webhook_domain" {
  description = "Domain name for webhook endpoint"
  type        = string
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID for tmi.dev"
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN of ACM certificate for webhook domain (must be in us-east-1)"
  type        = string
}

variable "receiver_lambda_arn" {
  description = "ARN of receiver Lambda function"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
