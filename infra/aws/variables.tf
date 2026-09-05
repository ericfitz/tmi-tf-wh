# --- Where to deploy ---

variable "region" {
  description = "AWS region holding the EKS cluster"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile used by the aws provider and `aws eks get-token`"
  type        = string
  default     = "tmi"
}

variable "cluster_name" {
  description = "Name of the existing EKS cluster"
  type        = string
  default     = "tmi-eks"
}

variable "hosted_zone_name" {
  description = "Route53 hosted zone that owns the webhook hostname"
  type        = string
  default     = "tmi.dev"
}

variable "hostname" {
  description = "Public hostname shared by all TMI webhook apps"
  type        = string
  default     = "webhook.tmi.dev"
}

variable "ingress_group" {
  description = "ALB IngressGroup name; every webhook app's Ingress joins this group"
  type        = string
  default     = "tmi-webhooks"
}

variable "url_prefix" {
  description = "Path prefix this app owns on the shared hostname (must start with /)"
  type        = string
  default     = "/tf"

  validation {
    condition     = startswith(var.url_prefix, "/") && !endswith(var.url_prefix, "/")
    error_message = "url_prefix must start with '/' and not end with '/'."
  }
}

# --- App ---

variable "app_name" {
  description = "Name used for the namespace, workloads, queue, role and ECR repo"
  type        = string
  default     = "tmi-tf-wh"
}

variable "k8s_namespace" {
  description = "Kubernetes namespace for the deployment"
  type        = string
  default     = "tmi-tf"
}

variable "app_image_tag" {
  description = "Container image tag pushed by scripts/push-aws.sh"
  type        = string
  default     = "latest"
}

variable "llm_provider" {
  description = "LLM provider (anthropic, openai, xai, gemini)"
  type        = string
  default     = "anthropic"
}

variable "llm_model" {
  description = "Model override passed as LLM_MODEL"
  type        = string
  default     = "claude-fable-5-1"
}

variable "tmi_server_url" {
  description = "TMI API server URL"
  type        = string
  default     = "https://api.tmi.dev"
}

variable "max_concurrent_jobs" {
  description = "Maximum concurrent analysis jobs"
  type        = number
  default     = 3
}

# --- Secrets (put in an untracked secrets.auto.tfvars) ---

variable "webhook_secret" {
  description = "HMAC shared secret configured on the TMI webhook subscription"
  type        = string
  sensitive   = true
}

variable "tmi_client_id" {
  description = "TMI client_credentials OAuth client id"
  type        = string
  sensitive   = true
}

variable "tmi_client_secret" {
  description = "TMI client_credentials OAuth client secret"
  type        = string
  sensitive   = true
}

variable "llm_api_key" {
  description = "API key for llm_provider (mapped to the provider's env var by the app)"
  type        = string
  sensitive   = true
}

variable "github_token" {
  description = "GitHub token for cloning repositories (may be empty)"
  type        = string
  sensitive   = true
  default     = ""
}
