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
