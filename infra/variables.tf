# --- Required: deployer must set these ---

variable "tenancy_ocid" {
  description = "OCID of the OCI tenancy"
  type        = string
}

variable "compartment_ocid" {
  description = "OCID of the compartment to deploy into"
  type        = string
}

variable "region" {
  description = "OCI region (e.g. us-ashburn-1)"
  type        = string
}

variable "vcn_id" {
  description = "OCID of the existing VCN"
  type        = string
}

variable "subnet_id_oke_api" {
  description = "OCID of the subnet for the OKE API endpoint (regional, private or public)"
  type        = string
}

variable "subnet_id_oke_nodes" {
  description = "OCID of the private subnet for OKE worker nodes"
  type        = string
}

variable "subnet_id_oke_lb" {
  description = "OCID of the public subnet for the K8s LoadBalancer service"
  type        = string
}

variable "subnet_id_api_gateway" {
  description = "OCID of the public subnet for the API Gateway"
  type        = string
}

# --- Optional with defaults ---

variable "cluster_name" {
  description = "Name for the OKE cluster"
  type        = string
  default     = "tmi-tf-wh"
}

variable "node_shape" {
  description = "Shape for OKE node pool instances"
  type        = string
  default     = "VM.Standard.A1.Flex"
}

variable "node_ocpus" {
  description = "Number of OCPUs per node"
  type        = number
  default     = 2
}

variable "node_memory_gb" {
  description = "Memory in GB per node"
  type        = number
  default     = 12
}

variable "node_count" {
  description = "Number of nodes in the node pool"
  type        = number
  default     = 2
}

variable "node_image_id" {
  description = "OCID of the OKE node image (Oracle Linux aarch64). If empty, latest is used."
  type        = string
  default     = ""
}

variable "app_image_tag" {
  description = "Container image tag for tmi-tf-wh (e.g. 'latest' or a git SHA)"
  type        = string
  default     = "latest"
}

variable "k8s_namespace" {
  description = "Kubernetes namespace for the deployment"
  type        = string
  default     = "tmi-tf"
}

variable "llm_provider" {
  description = "LLM provider to use (anthropic, openai, xai, gemini, oci)"
  type        = string
  default     = "oci"
}

variable "tmi_server_url" {
  description = "TMI API server URL"
  type        = string
  default     = "https://api.tmi.dev"
}

variable "max_concurrent_jobs" {
  description = "Maximum concurrent analysis jobs"
  type        = number
  default     = 3
}
