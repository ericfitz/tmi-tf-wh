resource "oci_queue_queue" "this" {
  compartment_id                   = var.compartment_ocid
  display_name                     = "${var.cluster_name}-jobs"
  visibility_in_seconds            = 900
  timeout_in_seconds               = 3600
  dead_letter_queue_delivery_count = 3
  retention_in_seconds             = 86400

  freeform_tags = {
    "app" = "tmi-tf-wh"
  }
}
