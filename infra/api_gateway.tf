resource "oci_apigateway_gateway" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-gateway"
  endpoint_type  = "PUBLIC"
  subnet_id      = var.subnet_id_api_gateway

  freeform_tags = {
    "app" = "tmi-tf-wh"
  }
}

resource "oci_apigateway_deployment" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-api"
  gateway_id     = oci_apigateway_gateway.this.id
  path_prefix    = "/"

  specification {
    routes {
      path    = "/webhook"
      methods = ["POST"]

      backend {
        type = "HTTP_BACKEND"
        url  = "http://${kubernetes_service_v1.tmi_tf_wh.status[0].load_balancer[0].ingress[0].ip}:8080/webhook"

        connect_timeout_in_seconds = 10
        read_timeout_in_seconds    = 30
        send_timeout_in_seconds    = 10
      }
    }

    routes {
      path    = "/health"
      methods = ["GET"]

      backend {
        type = "HTTP_BACKEND"
        url  = "http://${kubernetes_service_v1.tmi_tf_wh.status[0].load_balancer[0].ingress[0].ip}:8080/health"

        connect_timeout_in_seconds = 5
        read_timeout_in_seconds    = 10
        send_timeout_in_seconds    = 5
      }
    }
  }
}
