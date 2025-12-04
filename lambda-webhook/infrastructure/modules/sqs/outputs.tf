output "queue_url" {
  description = "URL of SQS analysis queue"
  value       = aws_sqs_queue.analysis.url
}

output "queue_arn" {
  description = "ARN of SQS analysis queue"
  value       = aws_sqs_queue.analysis.arn
}

output "queue_name" {
  description = "Name of SQS analysis queue"
  value       = aws_sqs_queue.analysis.name
}

output "dlq_url" {
  description = "URL of SQS dead letter queue"
  value       = aws_sqs_queue.dlq.url
}

output "dlq_arn" {
  description = "ARN of SQS dead letter queue"
  value       = aws_sqs_queue.dlq.arn
}

output "dlq_name" {
  description = "Name of SQS dead letter queue"
  value       = aws_sqs_queue.dlq.name
}
