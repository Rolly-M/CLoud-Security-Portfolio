# terraform/terraform.tfvars

aws_region    = "us-east-1"
environment   = "dev"
project_name  = "guardduty-security"
owner         = "YourName"

# GuardDuty Configuration
enable_guardduty             = true
enable_s3_protection         = true
enable_malware_protection    = true
finding_publishing_frequency = "FIFTEEN_MINUTES"

# Alerting
alert_email_endpoints = ["security-team@example.com"]
slack_webhook_url     = ""  # Optional

# Remediation Settings
enable_auto_remediation = true
severity_threshold      = 7.0

remediation_actions = {
  isolate_ec2             = true
  block_malicious_ip      = true
  disable_iam_credentials = true
  snapshot_instance       = true
}

# VPC ID from Project 1 (optional)
vpc_id = ""  # Leave empty to use default VPC