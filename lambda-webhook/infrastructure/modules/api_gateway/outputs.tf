output "webhook_url" {
  description = "Webhook endpoint URL (custom domain)"
  value       = "https://${var.webhook_domain}"
}

output "invoke_url" {
  description = "API Gateway invoke URL"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "api_id" {
  description = "API Gateway HTTP API ID"
  value       = aws_apigatewayv2_api.webhook.id
}

output "execution_arn" {
  description = "API Gateway execution ARN for Lambda permissions"
  value       = aws_apigatewayv2_api.webhook.execution_arn
}

output "stage_name" {
  description = "API Gateway stage name"
  value       = aws_apigatewayv2_stage.default.name
}

output "log_group_name" {
  description = "CloudWatch log group name for API Gateway"
  value       = aws_cloudwatch_log_group.api_gateway.name
}
