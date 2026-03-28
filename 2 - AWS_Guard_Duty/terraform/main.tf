###############################################################################
# Project 2: AWS GuardDuty - Threat Simulation & Auto-Remediation
# 
# This project builds upon Project 1's VPC infrastructure to implement:
# - AWS GuardDuty for threat detection
# - Automated remediation using Lambda
# - Real-time alerting via SNS
# - EventBridge rules for event-driven security responses
###############################################################################

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "GuardDuty-Threat-Remediation"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner
    }
  }
}

# Random suffix for unique resource naming
resource "random_id" "suffix" {
  byte_length = 4
}

# Local values
locals {
  name_prefix = "${var.project_name}-${var.environment}"
  lambda_zip  = "${path.module}/../lambda/remediation_handler.zip"
  
  severity_levels = {
    low    = 1.0
    medium = 4.0
    high   = 7.0
  }
}