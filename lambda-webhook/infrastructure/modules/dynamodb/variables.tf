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

variable "ttl_days" {
  description = "TTL for records in days"
  type        = number
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
