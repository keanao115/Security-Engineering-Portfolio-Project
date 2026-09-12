terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CyberMind-SOC-Platform"
      Environment = "Production"
      ManagedBy   = "Terraform"
      SecOps      = "Detection-Engineering"
    }
  }
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS deployment region for SOC infrastructure"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment tier"
}
