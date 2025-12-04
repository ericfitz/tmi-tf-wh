terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "tmi-tf-terraform-state"
    key            = "lambda-webhook/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tmi-tf-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "tmi-tf"
      Component   = "lambda-webhook"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Provider for ACM certificates (must be in us-east-1 for API Gateway)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "tmi-tf"
      Component   = "lambda-webhook"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
