resource "oci_identity_dynamic_group" "app_instance" {
  compartment_id = var.compartment_ocid
  name           = "tmi-tf-wh-instances"
  description    = "Dynamic group matching the tmi-tf-wh compute instance"
  matching_rule  = "instance.id = '${oci_core_instance.app.id}'"
}

resource "oci_identity_policy" "app_instance" {
  compartment_id = var.compartment_ocid
  name           = "tmi-tf-wh-policy"
  description    = "Allow the tmi-tf-wh instance to read secrets, use queues, and manage queue messages"

  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.app_instance.name} to read secret-bundles in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group ${oci_identity_dynamic_group.app_instance.name} to use queues in compartment id ${var.compartment_ocid} where target.queue.id = '${oci_queue_queue.main.id}'",
    "Allow dynamic-group ${oci_identity_dynamic_group.app_instance.name} to manage queue-messages in compartment id ${var.compartment_ocid} where target.queue.id = '${oci_queue_queue.main.id}'",
  ]
}
