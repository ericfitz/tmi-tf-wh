output "receiver_lambda_arn" {
  description = "ARN of receiver Lambda function"
  value       = aws_lambda_function.receiver.arn
}

output "receiver_lambda_name" {
  description = "Name of receiver Lambda function"
  value       = aws_lambda_function.receiver.function_name
}

output "receiver_lambda_invoke_arn" {
  description = "Invoke ARN of receiver Lambda function"
  value       = aws_lambda_function.receiver.invoke_arn
}

output "receiver_log_group_name" {
  description = "CloudWatch log group name for receiver Lambda"
  value       = aws_cloudwatch_log_group.receiver.name
}

output "analyzer_lambda_arn" {
  description = "ARN of analyzer Lambda function"
  value       = aws_lambda_function.analyzer.arn
}

output "analyzer_lambda_name" {
  description = "Name of analyzer Lambda function"
  value       = aws_lambda_function.analyzer.function_name
}

output "analyzer_lambda_invoke_arn" {
  description = "Invoke ARN of analyzer Lambda function"
  value       = aws_lambda_function.analyzer.invoke_arn
}

output "analyzer_log_group_name" {
  description = "CloudWatch log group name for analyzer Lambda"
  value       = aws_cloudwatch_log_group.analyzer.name
}

output "analyzer_alias_arn" {
  description = "ARN of analyzer Lambda alias (if canary enabled)"
  value       = var.enable_canary ? aws_lambda_alias.analyzer_live[0].arn : ""
}
