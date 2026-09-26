terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}

variable "db_password" {
  type      = string
  sensitive = true
  default   = "hunter2"
}

locals {
  name = "web-${var.region}"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "web" {
  name               = "web-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}

resource "aws_instance" "web" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = false
  monitoring                  = true
  user_data                   = "#!/bin/bash\necho hello"
  tags                        = { Name = local.name }
  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = true
    volume_size = 20
  }
  depends_on = [aws_iam_role.web]
}

resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name}-logs"
  force_destroy = true
  tags          = { Name = "logs" }
}

resource "mycorp_widget" "custom" {
  size  = 3
  color = "blue"
}

module "dns" {
  source  = "../../modules/dns/aws"
  zone    = "example.com"
  vpc_id  = aws_vpc.main.id
}

output "instance_ip" {
  value       = aws_instance.web.private_ip
  description = "Private IP"
}

output "db_password" {
  value     = var.db_password
  sensitive = true
}
