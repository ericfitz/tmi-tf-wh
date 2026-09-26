# Variables for AWS Network Module

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "tmi"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the primary public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "public_subnet_secondary_cidr" {
  description = "CIDR block for the secondary public subnet (required for ALB)"
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for the primary private subnet"
  type        = string
  default     = "10.0.3.0/24"
}

variable "private_subnet_secondary_cidr" {
  description = "CIDR block for the secondary private subnet (required for EKS)"
  type        = string
  default     = "10.0.4.0/24"
}

variable "database_subnet_cidr" {
  description = "CIDR block for the primary database subnet"
  type        = string
  default     = "10.0.5.0/24"
}

variable "database_subnet_secondary_cidr" {
  description = "CIDR block for the secondary database subnet (required for RDS subnet group)"
  type        = string
  default     = "10.0.6.0/24"
}

variable "enable_public_subnets" {
  description = "Whether to create public subnets and internet gateway (true for public template, false for private)"
  type        = bool
  default     = true
}

variable "alb_ingress_cidr" {
  description = "CIDR block allowed to access the ALB (0.0.0.0/0 for public, deployer CIDR for private)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "nat_eip_allocation_id" {
  description = "Allocation ID of an existing EIP for the NAT gateway. null creates a module-owned EIP."
  type        = string
  default     = null
}

variable "flow_log_s3_arn" {
  description = "S3 ARN (bucket or bucket/prefix/) for VPC flow logs. null disables flow logs."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
