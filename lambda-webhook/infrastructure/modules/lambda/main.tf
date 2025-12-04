#
# Lambda Module - Receiver and Analyzer Functions
#
# This module creates two Lambda functions:
# 1. Receiver: Webhook handler (HMAC validation, idempotency, SQS enqueue)
# 2. Analyzer: Terraform analysis (git clone, Claude API, TMI note creation)
#

locals {
  receiver_function_name = "${var.resource_prefix}-webhook-receiver"
  analyzer_function_name = "${var.resource_prefix}-analyzer"
}

#
# Receiver Lambda Function
#

# IAM Role for Receiver Lambda
resource "aws_iam_role" "receiver" {
  name               = "${local.receiver_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# Receiver Lambda IAM Policy
resource "aws_iam_role_policy" "receiver" {
  name   = "${local.receiver_function_name}-policy"
  role   = aws_iam_role.receiver.id
  policy = data.aws_iam_policy_document.receiver.json
}

data "aws_iam_policy_document" "receiver" {
  # CloudWatch Logs
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.receiver.arn}:*"]
  }

  # DynamoDB (idempotency)
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem"
    ]
    resources = [var.dynamodb_table_arn]
  }

  # SQS (enqueue)
  statement {
    effect = "Allow"
    actions = [
      "sqs:SendMessage"
    ]
    resources = [var.sqs_queue_arn]
  }

  # Secrets Manager (webhook secret)
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [var.secrets_manager_arn]
  }

  # X-Ray (optional)
  dynamic "statement" {
    for_each = var.enable_xray_tracing ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords"
      ]
      resources = ["*"]
    }
  }
}

# Receiver Lambda Function
resource "aws_lambda_function" "receiver" {
  function_name = local.receiver_function_name
  description   = "TMI webhook receiver (${var.environment})"
  role          = aws_iam_role.receiver.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.receiver_lambda_timeout
  memory_size   = var.receiver_lambda_memory

  filename         = data.archive_file.receiver.output_path
  source_code_hash = data.archive_file.receiver.output_base64sha256

  reserved_concurrent_executions = var.receiver_lambda_reserved_concurrency

  environment {
    variables = {
      DYNAMODB_TABLE  = var.dynamodb_table_name
      SQS_QUEUE_URL   = var.sqs_queue_url
      SECRETS_ARN     = var.secrets_manager_arn
      ENVIRONMENT     = var.environment
    }
  }

  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }

  tags = var.tags
}

# Package receiver Lambda code
data "archive_file" "receiver" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda/receiver"
  output_path = "${path.module}/builds/receiver.zip"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}

# CloudWatch Log Group for Receiver
resource "aws_cloudwatch_log_group" "receiver" {
  name              = "/aws/lambda/${local.receiver_function_name}"
  retention_in_days = 14
  kms_key_id        = null

  tags = var.tags
}

#
# Analyzer Lambda Function
#

# IAM Role for Analyzer Lambda
resource "aws_iam_role" "analyzer" {
  name               = "${local.analyzer_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = var.tags
}

# Analyzer Lambda IAM Policy
resource "aws_iam_role_policy" "analyzer" {
  name   = "${local.analyzer_function_name}-policy"
  role   = aws_iam_role.analyzer.id
  policy = data.aws_iam_policy_document.analyzer.json
}

data "aws_iam_policy_document" "analyzer" {
  # CloudWatch Logs
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.analyzer.arn}:*"]
  }

  # SQS (receive and delete messages)
  statement {
    effect = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes"
    ]
    resources = [var.sqs_queue_arn]
  }

  # DynamoDB (update delivery status)
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:UpdateItem"
    ]
    resources = [var.dynamodb_table_arn]
  }

  # Secrets Manager (OAuth credentials, API keys)
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [var.secrets_manager_arn]
  }

  # X-Ray (optional)
  dynamic "statement" {
    for_each = var.enable_xray_tracing ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords"
      ]
      resources = ["*"]
    }
  }
}

# Analyzer Lambda Function
resource "aws_lambda_function" "analyzer" {
  function_name = local.analyzer_function_name
  description   = "TMI Terraform analyzer (${var.environment})"
  role          = aws_iam_role.analyzer.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.analyzer_lambda_timeout
  memory_size   = var.analyzer_lambda_memory

  filename         = data.archive_file.analyzer.output_path
  source_code_hash = data.archive_file.analyzer.output_base64sha256

  reserved_concurrent_executions = var.analyzer_lambda_reserved_concurrency

  ephemeral_storage {
    size = var.analyzer_lambda_ephemeral_storage # MB
  }

  environment {
    variables = {
      DYNAMODB_TABLE  = var.dynamodb_table_name
      TMI_SERVER_URL  = var.tmi_server_url
      SECRETS_ARN     = var.secrets_manager_arn
      ENVIRONMENT     = var.environment
    }
  }

  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }

  tags = var.tags
}

# Package analyzer Lambda code (includes tmi_tf modules)
data "archive_file" "analyzer" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda/analyzer"
  output_path = "${path.module}/builds/analyzer.zip"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}

# CloudWatch Log Group for Analyzer
resource "aws_cloudwatch_log_group" "analyzer" {
  name              = "/aws/lambda/${local.analyzer_function_name}"
  retention_in_days = 14
  kms_key_id        = null

  tags = var.tags
}

# SQS Event Source Mapping for Analyzer
resource "aws_lambda_event_source_mapping" "analyzer" {
  event_source_arn = var.sqs_queue_arn
  function_name    = aws_lambda_function.analyzer.arn
  batch_size       = 1 # Process one repository at a time
  enabled          = true

  scaling_config {
    maximum_concurrency = var.analyzer_lambda_reserved_concurrency
  }
}

#
# Canary Deployment (optional)
#

resource "aws_lambda_alias" "analyzer_live" {
  count = var.enable_canary ? 1 : 0

  name             = "live"
  description      = "Live alias with canary deployment"
  function_name    = aws_lambda_function.analyzer.arn
  function_version = aws_lambda_function.analyzer.version

  routing_config {
    additional_version_weights = {
      (aws_lambda_function.analyzer.version) = var.canary_weight
    }
  }
}
