#
# SQS Module - Analysis Queue and Dead Letter Queue
#
# This module creates:
# 1. Main queue for analysis requests
# 2. Dead Letter Queue (DLQ) for failed messages
# 3. CloudWatch alarms for DLQ depth
#

# Dead Letter Queue
resource "aws_sqs_queue" "dlq" {
  name                       = "${var.resource_prefix}-analysis-dlq"
  message_retention_seconds  = 1209600 # 14 days
  receive_wait_time_seconds  = 0
  visibility_timeout_seconds = 30

  tags = merge(
    var.tags,
    {
      Name = "${var.resource_prefix}-analysis-dlq"
    }
  )
}

# Main Analysis Queue
resource "aws_sqs_queue" "analysis" {
  name                       = "${var.resource_prefix}-analysis"
  message_retention_seconds  = 86400 # 1 day
  receive_wait_time_seconds  = 20   # Long polling
  visibility_timeout_seconds = var.visibility_timeout

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = var.max_receive_count
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.resource_prefix}-analysis"
    }
  )
}

# CloudWatch Alarm: DLQ Depth (Critical)
resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  count = var.enable_dlq_alarms && var.sns_topic_arn != "" ? 1 : 0

  alarm_name          = "${var.resource_prefix}-dlq-depth-critical"
  alarm_description   = "CRITICAL: Messages in DLQ (analysis failed after retries)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = var.tags
}

# CloudWatch Alarm: Queue Depth (Warning)
resource "aws_cloudwatch_metric_alarm" "queue_depth" {
  count = var.enable_dlq_alarms && var.sns_topic_arn != "" ? 1 : 0

  alarm_name          = "${var.resource_prefix}-queue-depth-warning"
  alarm_description   = "WARNING: High number of messages in analysis queue"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Average"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.analysis.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = var.tags
}

# CloudWatch Alarm: Age of Oldest Message (Warning)
resource "aws_cloudwatch_metric_alarm" "message_age" {
  count = var.enable_dlq_alarms && var.sns_topic_arn != "" ? 1 : 0

  alarm_name          = "${var.resource_prefix}-message-age-warning"
  alarm_description   = "WARNING: Messages stuck in queue for too long"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 3600 # 1 hour
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.analysis.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = var.tags
}
