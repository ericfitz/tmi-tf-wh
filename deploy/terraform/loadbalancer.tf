resource "oci_load_balancer_load_balancer" "main" {
  compartment_id = var.compartment_ocid
  display_name   = "tmi-tf-wh-lb"
  shape          = "flexible"
  subnet_ids     = [oci_core_subnet.public.id]

  shape_details {
    minimum_bandwidth_in_mbps = 10
    maximum_bandwidth_in_mbps = 10
  }
}

resource "oci_load_balancer_backend_set" "app" {
  load_balancer_id = oci_load_balancer_load_balancer.main.id
  name             = "tmi-tf-wh-backend-set"
  policy           = "ROUND_ROBIN"

  health_checker {
    protocol          = "HTTP"
    port              = 8080
    url_path          = "/health"
    return_code       = 200
    interval_ms       = 10000
    timeout_in_millis = 3000
    retries           = 3
  }
}

resource "oci_load_balancer_backend" "app" {
  load_balancer_id = oci_load_balancer_load_balancer.main.id
  backendset_name  = oci_load_balancer_backend_set.app.name
  ip_address       = oci_core_instance.app.private_ip
  port             = 8080
  backup           = false
  drain            = false
  offline          = false
  weight           = 1
}

resource "oci_load_balancer_certificate" "tls" {
  load_balancer_id   = oci_load_balancer_load_balancer.main.id
  certificate_name   = var.tls_certificate_name
  ca_certificate     = null
  private_key        = null
  public_certificate = null

  lifecycle {
    create_before_destroy = true
  }
}

resource "oci_load_balancer_listener" "https" {
  load_balancer_id         = oci_load_balancer_load_balancer.main.id
  name                     = "tmi-tf-wh-https"
  default_backend_set_name = oci_load_balancer_backend_set.app.name
  port                     = 443
  protocol                 = "HTTP"

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.tls.certificate_name
    verify_peer_certificate = false
  }

  depends_on = [oci_load_balancer_certificate.tls]
}
