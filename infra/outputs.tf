output "cluster_id" {
  description = "OCID of the OKE cluster"
  value       = oci_containerengine_cluster.this.id
}

output "cluster_kubernetes_version" {
  description = "Kubernetes version of the OKE cluster"
  value       = local.k8s_version
}

output "queue_ocid" {
  description = "OCID of the OCI Queue"
  value       = oci_queue_queue.this.id
}

output "vault_ocid" {
  description = "OCID of the OCI Vault"
  value       = oci_kms_vault.this.id
}

output "ocir_image" {
  description = "Full OCIR image path for the tmi-tf-wh container"
  value       = local.ocir_image
}

output "api_gateway_url" {
  description = "Public URL of the API Gateway"
  value       = oci_apigateway_gateway.this.hostname
}

output "webhook_url" {
  description = "Full webhook endpoint URL"
  value       = "https://${oci_apigateway_gateway.this.hostname}/webhook"
}

output "load_balancer_ip" {
  description = "IP of the K8s LoadBalancer service"
  value       = kubernetes_service.tmi_tf_wh.status[0].load_balancer[0].ingress[0].ip
}

output "queue_endpoint" {
  description = "OCI Queue service endpoint (for in-cluster use)"
  value       = local.queue_endpoint
}

output "vault_endpoint" {
  description = "OCI Vault service endpoint (for in-cluster use)"
  value       = local.vault_endpoint
}

output "secrets_endpoint" {
  description = "OCI Secrets service endpoint (for in-cluster use)"
  value       = local.secrets_endpoint
}
