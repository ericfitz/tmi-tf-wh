# AWS Network Module for TMI
# Creates VPC with public and private subnets, gateways, and security groups

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

# Availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  az = data.aws_availability_zones.available.names[0]
  # EKS requires at least 2 AZs for the control plane
  az_secondary = data.aws_availability_zones.available.names[1]
}

# VPC
resource "aws_vpc" "tmi" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc"
  })
}

# Internet Gateway (public mode only)
resource "aws_internet_gateway" "tmi" {
  count  = var.enable_public_subnets ? 1 : 0
  vpc_id = aws_vpc.tmi.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-igw"
  })
}

# Elastic IP for NAT Gateway. Created here only when the caller does not pass
# a long-lived EIP: aws-public passes the permanent egress EIP owned by the
# aws-persistent stack, which must never be released (see that stack).
resource "aws_eip" "nat" {
  count  = var.nat_eip_allocation_id == null ? 1 : 0
  domain = "vpc"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-nat-eip"
  })
}

moved {
  from = aws_eip.nat
  to   = aws_eip.nat[0]
}

# NAT Gateway (placed in public subnet for outbound internet access from private subnets)
resource "aws_nat_gateway" "tmi" {
  allocation_id = coalesce(var.nat_eip_allocation_id, one(aws_eip.nat[*].id))
  subnet_id     = var.enable_public_subnets ? aws_subnet.public[0].id : aws_subnet.private.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-nat"
  })

  depends_on = [aws_internet_gateway.tmi]
}

# ============================================================================
# Public Subnets (only when enable_public_subnets = true)
# ============================================================================

resource "aws_subnet" "public" {
  count                   = var.enable_public_subnets ? 1 : 0
  vpc_id                  = aws_vpc.tmi.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = local.az
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name                     = "${var.name_prefix}-public"
    "kubernetes.io/role/elb" = "1"
  })
}

# Secondary public subnet in another AZ (required for ALB)
resource "aws_subnet" "public_secondary" {
  count                   = var.enable_public_subnets ? 1 : 0
  vpc_id                  = aws_vpc.tmi.id
  cidr_block              = var.public_subnet_secondary_cidr
  availability_zone       = local.az_secondary
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name                     = "${var.name_prefix}-public-secondary"
    "kubernetes.io/role/elb" = "1"
  })
}

# Public route table
resource "aws_route_table" "public" {
  count  = var.enable_public_subnets ? 1 : 0
  vpc_id = aws_vpc.tmi.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.tmi[0].id
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-public-rt"
  })
}

resource "aws_route_table_association" "public" {
  count          = var.enable_public_subnets ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table_association" "public_secondary" {
  count          = var.enable_public_subnets ? 1 : 0
  subnet_id      = aws_subnet.public_secondary[0].id
  route_table_id = aws_route_table.public[0].id
}

# ============================================================================
# Private Subnets
# ============================================================================

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.tmi.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = local.az

  tags = merge(var.tags, {
    Name                              = "${var.name_prefix}-private"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

# Secondary private subnet in another AZ (required for EKS)
resource "aws_subnet" "private_secondary" {
  vpc_id            = aws_vpc.tmi.id
  cidr_block        = var.private_subnet_secondary_cidr
  availability_zone = local.az_secondary

  tags = merge(var.tags, {
    Name                              = "${var.name_prefix}-private-secondary"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

# Private route table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.tmi.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.tmi.id
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-private-rt"
  })
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_secondary" {
  subnet_id      = aws_subnet.private_secondary.id
  route_table_id = aws_route_table.private.id
}

# ============================================================================
# Database Subnet
# ============================================================================

resource "aws_subnet" "database" {
  vpc_id            = aws_vpc.tmi.id
  cidr_block        = var.database_subnet_cidr
  availability_zone = local.az

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-database"
  })
}

# Secondary database subnet (required for RDS subnet group)
resource "aws_subnet" "database_secondary" {
  vpc_id            = aws_vpc.tmi.id
  cidr_block        = var.database_subnet_secondary_cidr
  availability_zone = local.az_secondary

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-database-secondary"
  })
}

resource "aws_route_table_association" "database" {
  subnet_id      = aws_subnet.database.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "database_secondary" {
  subnet_id      = aws_subnet.database_secondary.id
  route_table_id = aws_route_table.private.id
}

# RDS Subnet Group
resource "aws_db_subnet_group" "tmi" {
  name       = "${var.name_prefix}-db-subnet-group"
  subnet_ids = [aws_subnet.database.id, aws_subnet.database_secondary.id]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-db-subnet-group"
  })
}

# ============================================================================
# Security Groups
# ============================================================================

# ALB Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${var.name_prefix}-alb-"
  vpc_id      = aws_vpc.tmi.id
  description = "Security group for Application Load Balancer"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ALB inbound HTTP
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTP inbound"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = var.alb_ingress_cidr
}

# ALB inbound HTTPS
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS inbound"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = var.alb_ingress_cidr
}

# ALB outbound to EKS nodes on TMI port
resource "aws_vpc_security_group_egress_rule" "alb_to_nodes_tmi" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Allow traffic to TMI pods"
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.eks_nodes.id
}

# ALB outbound to EKS nodes on NodePort range
resource "aws_vpc_security_group_egress_rule" "alb_to_nodes_nodeport" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Allow traffic to NodePort range"
  from_port                    = 30000
  to_port                      = 32767
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.eks_nodes.id
}

# EKS Nodes Security Group
resource "aws_security_group" "eks_nodes" {
  name_prefix = "${var.name_prefix}-eks-nodes-"
  vpc_id      = aws_vpc.tmi.id
  description = "Security group for EKS worker nodes"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-eks-nodes-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# EKS nodes inbound from ALB on TMI port
resource "aws_vpc_security_group_ingress_rule" "nodes_from_alb_tmi" {
  security_group_id            = aws_security_group.eks_nodes.id
  description                  = "Allow traffic from ALB to TMI pods"
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id
}

# EKS nodes inbound from ALB on NodePort range
resource "aws_vpc_security_group_ingress_rule" "nodes_from_alb_nodeport" {
  security_group_id            = aws_security_group.eks_nodes.id
  description                  = "Allow traffic from ALB NodePort range"
  from_port                    = 30000
  to_port                      = 32767
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id
}

# EKS nodes self-referencing (node-to-node communication)
resource "aws_vpc_security_group_ingress_rule" "nodes_self" {
  security_group_id            = aws_security_group.eks_nodes.id
  description                  = "Allow node-to-node communication"
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.eks_nodes.id
}

# EKS nodes outbound to database
resource "aws_vpc_security_group_egress_rule" "nodes_to_db" {
  security_group_id            = aws_security_group.eks_nodes.id
  description                  = "Allow traffic to RDS PostgreSQL"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.rds.id
}

# EKS nodes outbound to internet (via NAT for OAuth, image pulls)
resource "aws_vpc_security_group_egress_rule" "nodes_to_internet" {
  security_group_id = aws_security_group.eks_nodes.id
  description       = "Allow outbound HTTPS (OAuth, image pulls)"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

# EKS nodes outbound to internet HTTP (for package downloads)
resource "aws_vpc_security_group_egress_rule" "nodes_to_internet_http" {
  security_group_id = aws_security_group.eks_nodes.id
  description       = "Allow outbound HTTP"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

# EKS nodes outbound to self (node-to-node)
resource "aws_vpc_security_group_egress_rule" "nodes_self" {
  security_group_id            = aws_security_group.eks_nodes.id
  description                  = "Allow node-to-node communication"
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.eks_nodes.id
}

# EKS nodes outbound DNS
resource "aws_vpc_security_group_egress_rule" "nodes_dns_tcp" {
  security_group_id = aws_security_group.eks_nodes.id
  description       = "Allow outbound DNS (TCP)"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "nodes_dns_udp" {
  security_group_id = aws_security_group.eks_nodes.id
  description       = "Allow outbound DNS (UDP)"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  cidr_ipv4         = "0.0.0.0/0"
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name_prefix = "${var.name_prefix}-rds-"
  vpc_id      = aws_vpc.tmi.id
  description = "Security group for RDS PostgreSQL"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-rds-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# RDS inbound from EKS nodes
resource "aws_vpc_security_group_ingress_rule" "rds_from_nodes" {
  security_group_id            = aws_security_group.rds.id
  description                  = "Allow PostgreSQL from EKS nodes"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.eks_nodes.id
}

# VPC flow logs (only when a destination bucket ARN is passed)
resource "aws_flow_log" "tmi" {
  count                = var.flow_log_s3_arn == null ? 0 : 1
  vpc_id               = aws_vpc.tmi.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = var.flow_log_s3_arn

  destination_options {
    file_format = "parquet"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc-flow-log"
  })
}
