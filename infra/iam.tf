# Dynamic group matching pods in the tmi-tf namespace via OKE workload identity
resource "oci_identity_dynamic_group" "tmi_tf_workload" {
  compartment_id = var.tenancy_ocid
  name           = "${var.cluster_name}-workload"
  description    = "OKE workload identity for tmi-tf-wh pods"

  matching_rule = join("", [
    "ALL {",
    "resource.type='workloadidentity',",
    "resource.compartment.id='${var.compartment_ocid}',",
    "resource.cluster.id='${oci_containerengine_cluster.this.id}',",
    "resource.namespace='${var.k8s_namespace}'",
    "}",
  ])
}

# Policy: allow the dynamic group to use queue and read vault secrets
resource "oci_identity_policy" "tmi_tf_workload" {
  compartment_id = var.compartment_ocid
  name           = "${var.cluster_name}-workload-policy"
  description    = "Allow tmi-tf-wh pods to use queue and read vault secrets"

  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_tf_workload.name} to use queues in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_tf_workload.name} to read secret-family in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_tf_workload.name} to use vaults in compartment id ${var.compartment_ocid}",
  ]
}
