output "table_name" {
  description = "Name of DynamoDB idempotency table"
  value       = aws_dynamodb_table.idempotency.name
}

output "table_arn" {
  description = "ARN of DynamoDB idempotency table"
  value       = aws_dynamodb_table.idempotency.arn
}

output "table_id" {
  description = "ID of DynamoDB idempotency table"
  value       = aws_dynamodb_table.idempotency.id
}
