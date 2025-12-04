#
# API Gateway Module - HTTP API for TMI Webhook
#
# This module creates an HTTP API (not REST API) which is 71% cheaper and
# simpler for webhook use cases.
#

# HTTP API
resource "aws_apigatewayv2_api" "webhook" {
  name          = "${var.resource_prefix}-webhook"
  description   = "TMI Terraform Analyzer Webhook Endpoint (${var.environment})"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST"]
    allow_headers = ["*"]
    max_age       = 300
  }

  tags = var.tags
}

# Integration with Lambda
resource "aws_apigatewayv2_integration" "receiver_lambda" {
  api_id           = aws_apigatewayv2_api.webhook.id
  integration_type = "AWS_PROXY"
  integration_uri  = var.receiver_lambda_arn

  payload_format_version = "2.0"
  timeout_milliseconds   = 30000 # 30 seconds
}

# Route: POST /
resource "aws_apigatewayv2_route" "webhook" {
  api_id    = aws_apigatewayv2_api.webhook.id
  route_key = "POST /"
  target    = "integrations/${aws_apigatewayv2_integration.receiver_lambda.id}"
}

# Default stage
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.webhook.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      errorMessage   = "$context.error.message"
      integrationError = "$context.integrationErrorMessage"
    })
  }

  tags = var.tags
}

# Custom Domain Name
resource "aws_apigatewayv2_domain_name" "webhook" {
  domain_name = var.webhook_domain

  domain_name_configuration {
    certificate_arn = var.acm_certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  tags = var.tags
}

# API Mapping
resource "aws_apigatewayv2_api_mapping" "webhook" {
  api_id      = aws_apigatewayv2_api.webhook.id
  domain_name = aws_apigatewayv2_domain_name.webhook.id
  stage       = aws_apigatewayv2_stage.default.id
}

# Route 53 Record
resource "aws_route53_record" "webhook" {
  zone_id = var.route53_zone_id
  name    = var.webhook_domain
  type    = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.webhook.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.webhook.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.resource_prefix}-webhook"
  retention_in_days = 14
  kms_key_id        = null

  tags = var.tags
}
