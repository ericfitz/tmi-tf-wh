output "webhook_url" {
  description = "URL to register as the TMI webhook subscription target"
  value       = "https://${var.hostname}${var.url_prefix}/webhook"
}

output "alb_hostname" {
  description = "Hostname of the shared webhook ALB"
  value       = kubernetes_ingress_v1.this.status[0].load_balancer[0].ingress[0].hostname
}

output "queue_url" {
  description = "SQS jobs queue URL"
  value       = aws_sqs_queue.jobs.url
}

output "ecr_repository_url" {
  description = "ECR repository the push script targets"
  value       = aws_ecr_repository.this.repository_url
}

output "pod_role_arn" {
  description = "IRSA role assumed by the pod"
  value       = aws_iam_role.pod.arn
}
