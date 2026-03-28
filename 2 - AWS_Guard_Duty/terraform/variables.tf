###############################################################################
# Variables
###############################################################################

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "guardduty-security"
}

variable "owner" {
  description = "Owner of the resources"
  type        = string
  default     = "CloudSecurityTeam"
}

# GuardDuty Variables
variable "enable_guardduty" {
  description = "Enable GuardDuty detector"
  type        = bool
  default     = true
}

variable "enable_s3_protection" {
  description = "Enable GuardDuty S3 Protection"
  type        = bool
  default     = true
}

variable "enable_kubernetes_protection" {
  description = "Enable GuardDuty Kubernetes Protection"
  type        = bool
  default     = false
}

variable "enable_malware_protection" {
  description = "Enable GuardDuty Malware Protection"
  type        = bool
  default     = true
}

variable "finding_publishing_frequency" {
  description = "Frequency of GuardDuty findings publication"
  type        = string
  default     = "FIFTEEN_MINUTES"
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "Valid values: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

# SNS Variables
variable "alert_email_endpoints" {
  description = "List of email addresses for security alerts"
  type        = list(string)
  default     = []
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

# Remediation Variables
variable "enable_auto_remediation" {
  description = "Enable automatic remediation actions"
  type        = bool
  default     = true
}

variable "remediation_actions" {
  description = "Map of enabled remediation actions"
  type = object({
    isolate_ec2           = bool
    block_malicious_ip    = bool
    disable_iam_credentials = bool
    snapshot_instance     = bool
  })
  default = {
    isolate_ec2           = true
    block_malicious_ip    = true
    disable_iam_credentials = true
    snapshot_instance     = true
  }
}

variable "severity_threshold" {
  description = "Minimum severity level to trigger remediation (1-10)"
  type        = number
  default     = 7.0
}

# VPC Reference (from Project 1)
variable "vpc_id" {
  description = "VPC ID from Project 1 infrastructure"
  type        = string
  default     = ""
}

variable "quarantine_nacl_rules" {
  description = "NACL rules for quarantined instances"
  type = list(object({
    rule_number = number
    egress      = bool
    protocol    = string
    rule_action = string
    cidr_block  = string
    from_port   = number
    to_port     = number
  }))
  default = [
    {
      rule_number = 100
      egress      = false
      protocol    = "-1"
      rule_action = "deny"
      cidr_block  = "0.0.0.0/0"
      from_port   = 0
      to_port     = 0
    },
    {
      rule_number = 100
      egress      = true
      protocol    = "-1"
      rule_action = "deny"
      cidr_block  = "0.0.0.0/0"
      from_port   = 0
      to_port     = 0
    }
  ]
}