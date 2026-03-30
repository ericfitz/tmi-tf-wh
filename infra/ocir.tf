resource "oci_artifacts_container_repository" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "tmi-tf-wh"
  is_public      = false
}

locals {
  # OCIR image path: <region-key>.ocir.io/<tenancy-namespace>/tmi-tf-wh:<tag>
  ocir_image = join("/", [
    "${var.region}.ocir.io",
    data.oci_identity_tenancy.this.name,
    "tmi-tf-wh:${var.app_image_tag}",
  ])
}
