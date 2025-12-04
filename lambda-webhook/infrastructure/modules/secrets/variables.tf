variable "secrets_manager_arn" {
  description = "ARN of Secrets Manager secret containing OAuth credentials and API keys"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
