# IRSA: the pod's ServiceAccount assumes this role via the cluster OIDC provider.
resource "aws_iam_role" "pod" {
  name = "${var.app_name}-pod"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.eks.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_provider_url}:aud" = "sts.amazonaws.com"
          "${local.oidc_provider_url}:sub" = "system:serviceaccount:${var.k8s_namespace}:${local.service_account}"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "sqs" {
  name = "sqs-jobs"
  role = aws_iam_role.pod.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
      ]
      Resource = aws_sqs_queue.jobs.arn
    }]
  })
}
