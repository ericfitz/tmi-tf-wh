# Fetch latest supported OKE Kubernetes version
data "oci_containerengine_cluster_option" "this" {
  cluster_option_id = "all"
  compartment_id    = var.compartment_ocid
}

locals {
  # Latest Kubernetes version from OKE options
  k8s_version = data.oci_containerengine_cluster_option.this.kubernetes_versions[
    length(data.oci_containerengine_cluster_option.this.kubernetes_versions) - 1
  ]
}

resource "oci_containerengine_cluster" "this" {
  compartment_id     = var.compartment_ocid
  kubernetes_version = local.k8s_version
  name               = var.cluster_name
  vcn_id             = var.vcn_id

  endpoint_config {
    is_public_ip_enabled = true
    subnet_id            = oci_core_subnet.oke_api.id
  }

  options {
    service_lb_subnet_ids = [oci_core_subnet.oke_lb.id]
  }

  type = "ENHANCED_CLUSTER"
}

# Fetch latest aarch64 OKE node image if not provided
data "oci_containerengine_node_pool_option" "this" {
  node_pool_option_id = oci_containerengine_cluster.this.id
  compartment_id      = var.compartment_ocid
}

locals {
  # Use provided image ID or pick latest aarch64 Oracle Linux image
  node_image_id = var.node_image_id != "" ? var.node_image_id : [
    for src in data.oci_containerengine_node_pool_option.this.sources :
    src.image_id
    if can(regex("aarch64", src.source_name)) && can(regex("Oracle-Linux", src.source_name))
  ][0]
}

resource "oci_containerengine_node_pool" "this" {
  cluster_id         = oci_containerengine_cluster.this.id
  compartment_id     = var.compartment_ocid
  kubernetes_version = local.k8s_version
  name               = "${var.cluster_name}-pool"

  node_shape = var.node_shape

  node_shape_config {
    ocpus         = var.node_ocpus
    memory_in_gbs = var.node_memory_gb
  }

  node_source_details {
    image_id    = local.node_image_id
    source_type = "IMAGE"
  }

  node_config_details {
    size = var.node_count

    placement_configs {
      availability_domain = data.oci_identity_availability_domains.this.availability_domains[0].name
      subnet_id           = oci_core_subnet.oke_nodes.id
    }
  }
}

data "oci_identity_availability_domains" "this" {
  compartment_id = var.tenancy_ocid
}
