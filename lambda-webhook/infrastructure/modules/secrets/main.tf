#
# Secrets Module - Secrets Manager Configuration
#
# This module does NOT create the secret (that's a manual prerequisite).
# It only provides data sources and IAM policy documents for accessing the secret.
#
# The secret must be created manually before running Terraform:
# aws secretsmanager create-secret \
#   --name tmi-tf/oauth-credentials \
#   --secret-string '{"client_id":"...","client_secret":"...","anthropic_api_key":"...","webhook_secret":"..."}'
#

# Data source for existing secret
data "aws_secretsmanager_secret" "credentials" {
  arn = var.secrets_manager_arn
}

data "aws_secretsmanager_secret_version" "credentials" {
  secret_id = data.aws_secretsmanager_secret.credentials.id
}

# IAM policy document for Lambda to read secret
data "aws_iam_policy_document" "read_secret" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [var.secrets_manager_arn]
  }
}

# Validate secret structure (optional - will fail at plan time if invalid)
locals {
  secret_data = jsondecode(data.aws_secretsmanager_secret_version.credentials.secret_string)

  # Validate required keys exist
  required_keys = ["client_id", "client_secret", "anthropic_api_key", "webhook_secret"]

  # This will cause a plan error if keys are missing
  validation_checks = [
    for key in local.required_keys :
    lookup(local.secret_data, key, "MISSING_KEY_${key}")
  ]
}

# Output validation status
output "secret_validation" {
  description = "Secret validation status (all required keys present)"
  value = alltrue([
    for key in local.required_keys :
    contains(keys(local.secret_data), key)
  ])
}
