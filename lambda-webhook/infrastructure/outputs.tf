output "webhook_url" {
  description = "Webhook endpoint URL"
  value       = module.api_gateway.webhook_url
}

output "webhook_invoke_url" {
  description = "API Gateway invoke URL"
  value       = module.api_gateway.invoke_url
}

output "receiver_lambda_arn" {
  description = "ARN of receiver Lambda function"
  value       = module.lambda.receiver_lambda_arn
}

output "receiver_lambda_name" {
  description = "Name of receiver Lambda function"
  value       = module.lambda.receiver_lambda_name
}

output "analyzer_lambda_arn" {
  description = "ARN of analyzer Lambda function"
  value       = module.lambda.analyzer_lambda_arn
}

output "analyzer_lambda_name" {
  description = "Name of analyzer Lambda function"
  value       = module.lambda.analyzer_lambda_name
}

output "sqs_queue_url" {
  description = "URL of SQS analysis queue"
  value       = module.sqs.queue_url
}

output "sqs_queue_arn" {
  description = "ARN of SQS analysis queue"
  value       = module.sqs.queue_arn
}

output "sqs_dlq_url" {
  description = "URL of SQS dead letter queue"
  value       = module.sqs.dlq_url
}

output "sqs_dlq_arn" {
  description = "ARN of SQS dead letter queue"
  value       = module.sqs.dlq_arn
}

output "dynamodb_table_name" {
  description = "Name of DynamoDB idempotency table"
  value       = module.dynamodb.table_name
}

output "dynamodb_table_arn" {
  description = "ARN of DynamoDB idempotency table"
  value       = module.dynamodb.table_arn
}

output "cloudwatch_log_group_receiver" {
  description = "CloudWatch log group for receiver Lambda"
  value       = module.lambda.receiver_log_group_name
}

output "cloudwatch_log_group_analyzer" {
  description = "CloudWatch log group for analyzer Lambda"
  value       = module.lambda.analyzer_log_group_name
}

output "sns_topic_arn" {
  description = "ARN of SNS topic for alarms (empty if alarm_email not provided)"
  value       = var.alarm_email != "" ? aws_sns_topic.alarms[0].arn : ""
}
