output "lb_public_ip" {
  description = "Public IP address of the load balancer"
  value       = oci_load_balancer_load_balancer.main.ip_address_details[0].ip_address
}

output "instance_ocid" {
  description = "OCID of the compute instance"
  value       = oci_core_instance.app.id
}

output "queue_ocid" {
  description = "OCID of the OCI Queue"
  value       = oci_queue_queue.main.id
}

output "vault_ocid" {
  description = "OCID of the OCI Vault"
  value       = oci_kms_vault.main.id
}
