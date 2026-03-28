###############################################################################
# SNS Configuration for Security Alerts
###############################################################################

# Main SNS Topic for GuardDuty Alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "${local.name_prefix}-guardduty-alerts"
  kms_master_key_id = aws_kms_key.guardduty.id

  tags = {
    Name = "${local.name_prefix}-guardduty-alerts"
  }
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "guardduty_alerts" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.guardduty_alerts.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/*"
          }
        }
      },
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_remediation.arn
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.guardduty_alerts.arn
      }
    ]
  })
}

# Email Subscriptions
resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alert_email_endpoints)

  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# Critical Alerts Topic (High Severity Only)
resource "aws_sns_topic" "critical_alerts" {
  name              = "${local.name_prefix}-critical-alerts"
  kms_master_key_id = aws_kms_key.guardduty.id

  tags = {
    Name = "${local.name_prefix}-critical-alerts"
  }
}

# Remediation Notifications Topic
resource "aws_sns_topic" "remediation_notifications" {
  name              = "${local.name_prefix}-remediation-notifications"
  kms_master_key_id = aws_kms_key.guardduty.id

  tags = {
    Name = "${local.name_prefix}-remediation-notifications"
  }
}