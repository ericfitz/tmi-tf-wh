resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = var.k8s_namespace
    labels = {
      app        = var.app_name
      managed_by = "terraform"
    }
  }
}

resource "kubernetes_service_account_v1" "this" {
  metadata {
    name      = local.service_account
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.pod.arn
    }
  }
}

# Same approach as tmi-server on this cluster: secrets are a Kubernetes Secret
# injected via envFrom. SECRET_PROVIDER=none tells the app not to fetch any.
resource "kubernetes_secret_v1" "this" {
  metadata {
    name      = "${var.app_name}-secrets"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }

  data = {
    WEBHOOK_SECRET    = var.webhook_secret
    TMI_CLIENT_ID     = var.tmi_client_id
    TMI_CLIENT_SECRET = var.tmi_client_secret
    LLM_API_KEY       = var.llm_api_key
    GITHUB_TOKEN      = var.github_token
  }
}

resource "kubernetes_deployment_v1" "this" {
  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = { app = var.app_name }
  }

  spec {
    replicas = 1

    selector {
      match_labels = { app = var.app_name }
    }

    template {
      metadata {
        labels = { app = var.app_name }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.this.metadata[0].name

        container {
          name  = var.app_name
          image = local.image

          port {
            container_port = 8080
            protocol       = "TCP"
          }

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.this.metadata[0].name
            }
          }

          env {
            name  = "QUEUE_PROVIDER"
            value = "aws"
          }
          env {
            name  = "QUEUE_URL"
            value = aws_sqs_queue.jobs.url
          }
          env {
            name  = "AWS_REGION"
            value = var.region
          }
          env {
            name  = "SECRET_PROVIDER"
            value = "none"
          }
          env {
            name  = "URL_PREFIX"
            value = var.url_prefix
          }
          env {
            name  = "LLM_PROVIDER"
            value = var.llm_provider
          }
          env {
            name  = "LLM_MODEL"
            value = var.llm_model
          }
          env {
            name  = "TMI_SERVER_URL"
            value = var.tmi_server_url
          }
          env {
            name  = "TMI_OAUTH_IDP"
            value = "tmi"
          }
          env {
            name  = "TMI_CLIENT_PATH"
            value = "/opt/tmi-client"
          }
          env {
            name  = "SERVER_PORT"
            value = "8080"
          }
          env {
            name  = "MAX_CONCURRENT_JOBS"
            value = tostring(var.max_concurrent_jobs)
          }
          env {
            name  = "WEBHOOK_SUBSCRIPTION_ID"
            value = var.webhook_subscription_id
          }

          liveness_probe {
            http_get {
              path = "${var.url_prefix}/health"
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 30
          }

          readiness_probe {
            http_get {
              path = "${var.url_prefix}/health"
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 10
          }

          resources {
            requests = {
              cpu    = "500m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1"
              memory = "1Gi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "this" {
  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }

  spec {
    type     = "ClusterIP"
    selector = { app = var.app_name }

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
  }
}

# Joins the shared ALB (IngressGroup). Other webhook apps add their own Ingress
# with the same group.name and a different path prefix; the ALB routes by path.
resource "kubernetes_ingress_v1" "this" {
  wait_for_load_balancer = true

  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/group.name"       = var.ingress_group
      "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"      = "ip"
      "alb.ingress.kubernetes.io/listen-ports"     = jsonencode([{ HTTPS = 443 }])
      "alb.ingress.kubernetes.io/certificate-arn"  = aws_acm_certificate_validation.webhook.certificate_arn
      "alb.ingress.kubernetes.io/healthcheck-path" = "${var.url_prefix}/health"
    }
  }

  spec {
    ingress_class_name = "alb"

    rule {
      http {
        path {
          path      = var.url_prefix
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service_v1.this.metadata[0].name
              port {
                number = 8080
              }
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_deployment_v1.this]
}
