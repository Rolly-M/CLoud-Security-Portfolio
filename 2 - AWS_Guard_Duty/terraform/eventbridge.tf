###############################################################################
# EventBridge Rules for GuardDuty Findings
###############################################################################

# Rule: All GuardDuty Findings
resource "aws_cloudwatch_event_rule" "guardduty_all_findings" {
  name        = "${local.name_prefix}-all-findings"
  description = "Capture all GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = {
    Name = "${local.name_prefix}-all-findings"
  }
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_all_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      finding     = "$.detail.type"
      description = "$.detail.description"
      region      = "$.region"
      account     = "$.account"
      time        = "$.time"
    }
    input_template = <<EOF
"🚨 GuardDuty Alert 🚨\n\nSeverity: <severity>\nFinding: <finding>\nDescription: <description>\nRegion: <region>\nAccount: <account>\nTime: <time>"
EOF
  }
}

# Rule: High Severity Findings (7.0+) - Trigger Lambda Remediation
resource "aws_cloudwatch_event_rule" "guardduty_high_severity" {
  name        = "${local.name_prefix}-high-severity"
  description = "Capture high severity GuardDuty findings for auto-remediation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{
        numeric = [">=", var.severity_threshold]
      }]
    }
  })

  tags = {
    Name = "${local.name_prefix}-high-severity"
  }
}

resource "aws_cloudwatch_event_target" "guardduty_to_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_high_severity.name
  target_id = "TriggerRemediation"
  arn       = aws_lambda_function.remediation_handler.arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high_severity.arn
}

# Rule: EC2 Instance Compromise
resource "aws_cloudwatch_event_rule" "ec2_compromise" {
  name        = "${local.name_prefix}-ec2-compromise"
  description = "Detect EC2 instance compromise findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:EC2" },
        { prefix = "CryptoCurrency:EC2" },
        { prefix = "Backdoor:EC2" },
        { prefix = "Trojan:EC2" },
        { prefix = "Behavior:EC2" }
      ]
    }
  })

  tags = {
    Name = "${local.name_prefix}-ec2-compromise"
  }
}

resource "aws_cloudwatch_event_target" "ec2_compromise_to_lambda" {
  rule      = aws_cloudwatch_event_rule.ec2_compromise.name
  target_id = "EC2Remediation"
  arn       = aws_lambda_function.remediation_handler.arn
}

resource "aws_lambda_permission" "ec2_compromise_invoke" {
  statement_id  = "AllowEC2CompromiseInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2_compromise.arn
}

# Rule: IAM Credential Compromise
resource "aws_cloudwatch_event_rule" "iam_compromise" {
  name        = "${local.name_prefix}-iam-compromise"
  description = "Detect IAM credential compromise findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser" },
        { prefix = "CredentialAccess:IAMUser" },
        { prefix = "Persistence:IAMUser" },
        { prefix = "PrivilegeEscalation:IAMUser" }
      ]
    }
  })

  tags = {
    Name = "${local.name_prefix}-iam-compromise"
  }
}

resource "aws_cloudwatch_event_target" "iam_compromise_to_lambda" {
  rule      = aws_cloudwatch_event_rule.iam_compromise.name
  target_id = "IAMRemediation"
  arn       = aws_lambda_function.remediation_handler.arn
}

resource "aws_lambda_permission" "iam_compromise_invoke" {
  statement_id  = "AllowIAMCompromiseInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_compromise.arn
}

# Rule: S3 Data Exfiltration
resource "aws_cloudwatch_event_rule" "s3_exfiltration" {
  name        = "${local.name_prefix}-s3-exfiltration"
  description = "Detect S3 data exfiltration attempts"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Exfiltration:S3" },
        { prefix = "Policy:S3" },
        { prefix = "Stealth:S3" },
        { prefix = "UnauthorizedAccess:S3" }
      ]
    }
  })

  tags = {
    Name = "${local.name_prefix}-s3-exfiltration"
  }
}

resource "aws_cloudwatch_event_target" "s3_exfiltration_to_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_exfiltration.name
  target_id = "S3Remediation"
  arn       = aws_lambda_function.remediation_handler.arn
}

resource "aws_lambda_permission" "s3_exfiltration_invoke" {
  statement_id  = "AllowS3ExfiltrationInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_exfiltration.arn
}