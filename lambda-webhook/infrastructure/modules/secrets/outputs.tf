output "secret_arn" {
  description = "ARN of Secrets Manager secret"
  value       = data.aws_secretsmanager_secret.credentials.arn
}

output "secret_name" {
  description = "Name of Secrets Manager secret"
  value       = data.aws_secretsmanager_secret.credentials.name
}

output "iam_policy_document" {
  description = "IAM policy document for reading secret"
  value       = data.aws_iam_policy_document.read_secret.json
}
