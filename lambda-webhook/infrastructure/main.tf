#
# TMI Terraform Analyzer - Lambda Webhook Infrastructure
#
# This Terraform configuration provisions the AWS infrastructure for the
# TMI Terraform analyzer Lambda webhook solution.
#

locals {
  resource_prefix = "${var.project_name}-${var.environment}"

  common_tags = {
    Project     = var.project_name
    Component   = "lambda-webhook"
    Environment = var.environment
  }
}

# SNS Topic for CloudWatch Alarms
resource "aws_sns_topic" "alarms" {
  count = var.alarm_email != "" ? 1 : 0

  name              = "${local.resource_prefix}-webhook-alarms"
  display_name      = "TMI TF Webhook Alarms (${var.environment})"
  kms_master_key_id = "alias/aws/sns"

  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "alarms_email" {
  count = var.alarm_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# API Gateway Module
module "api_gateway" {
  source = "./modules/api_gateway"

  project_name        = var.project_name
  environment         = var.environment
  resource_prefix     = local.resource_prefix
  webhook_domain      = var.webhook_domain
  route53_zone_id     = var.route53_zone_id
  acm_certificate_arn = var.acm_certificate_arn
  receiver_lambda_arn = module.lambda.receiver_lambda_arn

  tags = local.common_tags

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }
}

# SQS Module
module "sqs" {
  source = "./modules/sqs"

  project_name         = var.project_name
  environment          = var.environment
  resource_prefix      = local.resource_prefix
  visibility_timeout   = var.sqs_visibility_timeout
  max_receive_count    = var.sqs_max_receive_count
  enable_dlq_alarms    = var.enable_dlq_alarms
  sns_topic_arn        = var.alarm_email != "" ? aws_sns_topic.alarms[0].arn : ""

  tags = local.common_tags
}

# DynamoDB Module
module "dynamodb" {
  source = "./modules/dynamodb"

  project_name    = var.project_name
  environment     = var.environment
  resource_prefix = local.resource_prefix
  ttl_days        = var.dynamodb_ttl_days

  tags = local.common_tags
}

# Lambda Module
module "lambda" {
  source = "./modules/lambda"

  project_name                        = var.project_name
  environment                         = var.environment
  resource_prefix                     = local.resource_prefix
  tmi_server_url                      = var.tmi_server_url
  secrets_manager_arn                 = var.secrets_manager_arn
  sqs_queue_url                       = module.sqs.queue_url
  sqs_queue_arn                       = module.sqs.queue_arn
  dynamodb_table_name                 = module.dynamodb.table_name
  dynamodb_table_arn                  = module.dynamodb.table_arn
  receiver_lambda_memory              = var.receiver_lambda_memory
  receiver_lambda_timeout             = var.receiver_lambda_timeout
  receiver_lambda_reserved_concurrency = var.receiver_lambda_reserved_concurrency
  analyzer_lambda_memory              = var.analyzer_lambda_memory
  analyzer_lambda_timeout             = var.analyzer_lambda_timeout
  analyzer_lambda_reserved_concurrency = var.analyzer_lambda_reserved_concurrency
  analyzer_lambda_ephemeral_storage   = var.analyzer_lambda_ephemeral_storage
  enable_xray_tracing                 = var.enable_xray_tracing
  enable_canary                       = var.enable_canary
  canary_weight                       = var.canary_weight

  tags = local.common_tags
}

# Grant API Gateway permission to invoke receiver Lambda
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.receiver_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api_gateway.execution_arn}/*/*"
}
