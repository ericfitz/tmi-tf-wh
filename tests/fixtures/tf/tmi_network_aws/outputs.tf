# Outputs for AWS Network Module

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.tmi.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.tmi.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs (standard interface)"
  value       = var.enable_public_subnets ? [aws_subnet.public[0].id, aws_subnet.public_secondary[0].id] : []
}

output "private_subnet_ids" {
  description = "List of private subnet IDs (standard interface)"
  value       = [aws_subnet.private.id, aws_subnet.private_secondary.id]
}

output "database_subnet_ids" {
  description = "List of database subnet IDs (standard interface)"
  value       = [aws_subnet.database.id, aws_subnet.database_secondary.id]
}

output "db_subnet_group_name" {
  description = "Name of the RDS DB subnet group"
  value       = aws_db_subnet_group.tmi.name
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "eks_nodes_security_group_id" {
  description = "ID of the EKS nodes security group"
  value       = aws_security_group.eks_nodes.id
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = aws_security_group.rds.id
}

# Standard interface outputs for multi-cloud compatibility
output "lb_security_group_id" {
  description = "Load balancer security group ID (standard interface)"
  value       = aws_security_group.alb.id
}

output "tmi_security_group_id" {
  description = "TMI server security group ID (standard interface)"
  value       = aws_security_group.eks_nodes.id
}

output "nat_gateway_id" {
  description = "ID of the NAT gateway"
  value       = aws_nat_gateway.tmi.id
}

output "internet_gateway_id" {
  description = "ID of the internet gateway (null if private mode)"
  value       = var.enable_public_subnets ? aws_internet_gateway.tmi[0].id : null
}
