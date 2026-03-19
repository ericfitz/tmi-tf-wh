resource "oci_queue_queue" "main" {
  compartment_id                   = var.compartment_ocid
  display_name                     = "tmi-tf-wh-queue"
  visibility_in_seconds            = 900
  retention_in_seconds             = 86400 # 24 hours
  dead_letter_queue_delivery_count = 3
}
