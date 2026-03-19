variable "compartment_ocid" {
  description = "OCID of the compartment in which to create resources"
  type        = string
}

variable "ssh_authorized_keys" {
  description = "SSH public key(s) to authorize on the compute instance"
  type        = string
}

variable "availability_domain" {
  description = "Availability domain for compute and subnet resources"
  type        = string
}

variable "tls_certificate_name" {
  description = "Name of the TLS certificate to use on the load balancer listener"
  type        = string
}

variable "shape" {
  description = "Compute instance shape"
  type        = string
  default     = "VM.Standard.A1.Flex"
}

variable "shape_ocpus" {
  description = "Number of OCPUs for the flex compute shape"
  type        = number
  default     = 1
}

variable "shape_memory_in_gbs" {
  description = "Amount of memory in GBs for the flex compute shape"
  type        = number
  default     = 6
}
