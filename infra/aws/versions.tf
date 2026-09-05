terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
  }

  # Bucket / region / lock table come from `terraform init -backend-config=backend.hcl`
  # (see backend.hcl.example). Key and encryption are pinned here.
  backend "s3" {
    key     = "tmi-tf-wh/aws/terraform.tfstate"
    encrypt = true
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "tmi-tf-wh"
      ManagedBy = "terraform"
    }
  }
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks", "get-token",
      "--cluster-name", var.cluster_name,
      "--region", var.region,
      "--profile", var.aws_profile,
    ]
  }
}
