resource "aws_sqs_queue" "dlq" {
  name                      = "${var.app_name}-jobs-dlq"
  message_retention_seconds = 1209600 # 14 days
}

resource "aws_sqs_queue" "jobs" {
  name                       = "${var.app_name}-jobs"
  visibility_timeout_seconds = 900
  message_retention_seconds  = 86400 # 24 h, matches MAX_MESSAGE_AGE_HOURS
  receive_wait_time_seconds  = 5

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}

# Anything in the DLQ is a job that failed 3 times; alert instead of letting it age out.
data "aws_sns_topic" "security_alerts" {
  name = var.security_alerts_topic_name
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name          = "${var.app_name}-dlq-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [data.aws_sns_topic.security_alerts.arn]
  ok_actions          = [data.aws_sns_topic.security_alerts.arn]
}
