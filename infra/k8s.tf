resource "kubernetes_namespace_v1" "tmi_tf" {
  metadata {
    name = var.k8s_namespace
  }

  depends_on = [oci_containerengine_node_pool.this]
}

# ServiceAccount with OKE workload identity annotation
resource "kubernetes_service_account_v1" "tmi_tf_wh" {
  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace_v1.tmi_tf.metadata[0].name
  }
}

# Construct OCI service endpoints from region
locals {
  queue_endpoint   = "https://cell-1.queue.oc1.${var.region}.oci.oraclecloud.com"
  vault_endpoint   = "https://vaults.${var.region}.oci.oraclecloud.com"
  secrets_endpoint = "https://secrets.vaults.${var.region}.oci.oraclecloud.com"
}

resource "kubernetes_deployment_v1" "tmi_tf_wh" {
  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace_v1.tmi_tf.metadata[0].name

    labels = {
      app = "tmi-tf-wh"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "tmi-tf-wh"
      }
    }

    template {
      metadata {
        labels = {
          app = "tmi-tf-wh"
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.tmi_tf_wh.metadata[0].name

        container {
          name  = "tmi-tf-wh"
          image = local.ocir_image

          port {
            container_port = 8080
            protocol       = "TCP"
          }

          env {
            name  = "QUEUE_OCID"
            value = oci_queue_queue.this.id
          }

          env {
            name  = "VAULT_OCID"
            value = oci_kms_vault.this.id
          }

          env {
            name  = "OCI_COMPARTMENT_ID"
            value = var.compartment_ocid
          }

          env {
            name  = "OCI_REGION"
            value = var.region
          }

          env {
            name  = "QUEUE_ENDPOINT"
            value = local.queue_endpoint
          }

          env {
            name  = "VAULT_ENDPOINT"
            value = local.vault_endpoint
          }

          env {
            name  = "SECRETS_ENDPOINT"
            value = local.secrets_endpoint
          }

          env {
            name  = "LLM_PROVIDER"
            value = var.llm_provider
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

          liveness_probe {
            http_get {
              path = "/health"
              port = 8080
            }

            initial_delay_seconds = 15
            period_seconds        = 30
          }

          readiness_probe {
            http_get {
              path = "/health"
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

resource "kubernetes_service_v1" "tmi_tf_wh" {
  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace_v1.tmi_tf.metadata[0].name

    annotations = {
      "oci.oraclecloud.com/load-balancer-type" = "lb"
    }
  }

  spec {
    type = "LoadBalancer"

    selector = {
      app = "tmi-tf-wh"
    }

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
  }
}
