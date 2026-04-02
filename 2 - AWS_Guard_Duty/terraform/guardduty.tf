###############################################################################
# AWS GuardDuty Configuration
###############################################################################

# GuardDuty Detector
resource "aws_guardduty_detector" "main" {
  enable                       = var.enable_guardduty
  finding_publishing_frequency = var.finding_publishing_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_kubernetes_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = {
    Name = "${local.name_prefix}-detector"
  }
}

# S3 Bucket for GuardDuty Findings Export
resource "aws_s3_bucket" "guardduty_findings" {
  bucket        = "${local.name_prefix}-findings-${random_id.suffix.hex}"
  force_destroy = var.environment != "prod"

  tags = {
    Name = "${local.name_prefix}-findings-bucket"
  }
}

resource "aws_s3_bucket_versioning" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.guardduty.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  rule {
    id     = "archive-findings"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyExport"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.guardduty_findings.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowGuardDutyBucketAccess"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:GetBucketLocation"
        Resource = aws_s3_bucket.guardduty_findings.arn
      },
      {
        Sid    = "AllowGuardDutyGetObject"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.guardduty_findings.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# KMS Key for GuardDuty
resource "aws_kms_key" "guardduty" {
  description             = "KMS key for GuardDuty findings encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow GuardDuty to use the key"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Encrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "Allow CloudWatch Logs to use the key"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      },
      {
        Sid    = "Allow Lambda to decrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_remediation.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow SNS to use the key"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow SQS to use the key"
        Effect = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-kms-key"
  }
}

resource "aws_kms_alias" "guardduty" {
  name          = "alias/${local.name_prefix}-guardduty"
  target_key_id = aws_kms_key.guardduty.key_id
}

# Publishing Destination for Findings
resource "aws_guardduty_publishing_destination" "s3" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = aws_kms_key.guardduty.arn

  depends_on = [
    aws_s3_bucket_policy.guardduty_findings,
    aws_kms_key.guardduty
  ]
}

# S3 Object for Trusted IPs - Must contain valid CIDR blocks
resource "aws_s3_object" "trusted_ips" {
  bucket       = aws_s3_bucket.guardduty_findings.id
  key          = "ipsets/trusted-ips.txt"
  content      = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n"
  content_type = "text/plain"

  depends_on = [
    aws_s3_bucket_policy.guardduty_findings,
    aws_s3_bucket.guardduty_findings
  ]
}

# Trusted IP List (whitelist known IPs)
resource "aws_guardduty_ipset" "trusted" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.guardduty_findings.id}/${aws_s3_object.trusted_ips.key}"
  name        = "${local.name_prefix}-trusted-ips"

  depends_on = [
    aws_s3_object.trusted_ips,
    aws_s3_bucket_policy.guardduty_findings,
    aws_guardduty_detector.main
  ]
}

# S3 Object for Malicious IPs - Must contain valid IP addresses
resource "aws_s3_object" "malicious_ips" {
  bucket       = aws_s3_bucket.guardduty_findings.id
  key          = "threatintel/malicious-ips.txt"
  content      = "198.51.100.1\n198.51.100.2\n203.0.113.1\n203.0.113.2\n"
  content_type = "text/plain"

  depends_on = [
    aws_s3_bucket_policy.guardduty_findings,
    aws_s3_bucket.guardduty_findings
  ]
}

# Threat Intel Set (known malicious IPs)
resource "aws_guardduty_threatintelset" "malicious" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.guardduty_findings.id}/${aws_s3_object.malicious_ips.key}"
  name        = "${local.name_prefix}-threat-intel"

  depends_on = [
    aws_s3_object.malicious_ips,
    aws_s3_bucket_policy.guardduty_findings,
    aws_guardduty_detector.main
  ]
}