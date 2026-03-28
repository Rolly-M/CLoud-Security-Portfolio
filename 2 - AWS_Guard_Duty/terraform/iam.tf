###############################################################################
# IAM Roles and Policies for Lambda Remediation
###############################################################################

# Lambda Execution Role
resource "aws_iam_role" "lambda_remediation" {
  name = "${local.name_prefix}-lambda-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-lambda-remediation-role"
  }
}

# CloudWatch Logs Policy
resource "aws_iam_role_policy" "lambda_logs" {
  name = "${local.name_prefix}-lambda-logs"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# EC2 Remediation Policy
resource "aws_iam_role_policy" "ec2_remediation" {
  name = "${local.name_prefix}-ec2-remediation"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Describe"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Isolate"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      },
      {
        Sid    = "EC2Snapshot"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Stop"
        Effect = "Allow"
        Action = [
          "ec2:StopInstances"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      }
    ]
  })
}

# IAM Remediation Policy
resource "aws_iam_role_policy" "iam_remediation" {
  name = "${local.name_prefix}-iam-remediation"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMDescribe"
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:GetAccessKeyLastUsed",
          "iam:ListAccessKeys",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRemediate"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:DeleteAccessKey",
          "iam:PutUserPolicy"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      }
    ]
  })
}

# WAF Policy for IP Blocking
resource "aws_iam_role_policy" "waf_remediation" {
  name = "${local.name_prefix}-waf-remediation"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "wafv2:GetIPSet",
          "wafv2:UpdateIPSet",
          "wafv2:CreateIPSet",
          "wafv2:ListIPSets"
        ]
        Resource = "*"
      }
    ]
  })
}

# SNS Publish Policy
resource "aws_iam_role_policy" "sns_publish" {
  name = "${local.name_prefix}-sns-publish"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.guardduty_alerts.arn,
          aws_sns_topic.critical_alerts.arn,
          aws_sns_topic.remediation_notifications.arn
        ]
      }
    ]
  })
}

# S3 Policy for logging
resource "aws_iam_role_policy" "s3_logging" {
  name = "${local.name_prefix}-s3-logging"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.guardduty_findings.arn}/*"
      }
    ]
  })
}

# KMS Policy
resource "aws_iam_role_policy" "kms_access" {
  name = "${local.name_prefix}-kms-access"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.guardduty.arn
      }
    ]
  })
}

# SQS Policy for DLQ
resource "aws_iam_role_policy" "sqs_dlq" {
  name = "${local.name_prefix}-sqs-dlq"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_dlq.arn
      }
    ]
  })
}

# X-Ray Tracing Policy
resource "aws_iam_role_policy_attachment" "xray_tracing" {
  role       = aws_iam_role.lambda_remediation.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# GuardDuty Read Policy
resource "aws_iam_role_policy" "guardduty_read" {
  name = "${local.name_prefix}-guardduty-read"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:GetDetector",
          "guardduty:ArchiveFindings"
        ]
        Resource = "*"
      }
    ]
  })
}