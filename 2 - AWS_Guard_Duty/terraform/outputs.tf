###############################################################################
# Outputs
###############################################################################

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "guardduty_detector_arn" {
  description = "GuardDuty detector ARN"
  value       = aws_guardduty_detector.main.arn
}

output "findings_bucket_name" {
  description = "S3 bucket for GuardDuty findings"
  value       = aws_s3_bucket.guardduty_findings.id
}

output "findings_bucket_arn" {
  description = "S3 bucket ARN for GuardDuty findings"
  value       = aws_s3_bucket.guardduty_findings.arn
}

output "sns_alerts_topic_arn" {
  description = "SNS topic ARN for GuardDuty alerts"
  value       = aws_sns_topic.guardduty_alerts.arn
}

output "sns_critical_alerts_topic_arn" {
  description = "SNS topic ARN for critical alerts"
  value       = aws_sns_topic.critical_alerts.arn
}

output "sns_remediation_topic_arn" {
  description = "SNS topic ARN for remediation notifications"
  value       = aws_sns_topic.remediation_notifications.arn
}

output "lambda_function_name" {
  description = "Lambda remediation function name"
  value       = aws_lambda_function.remediation_handler.function_name
}

output "lambda_function_arn" {
  description = "Lambda remediation function ARN"
  value       = aws_lambda_function.remediation_handler.arn
}

output "quarantine_security_group_id" {
  description = "Quarantine security group ID"
  value       = aws_security_group.quarantine.id
}

output "kms_key_arn" {
  description = "KMS key ARN for encryption"
  value       = aws_kms_key.guardduty.arn
}

output "eventbridge_rules" {
  description = "EventBridge rule names"
  value = {
    all_findings    = aws_cloudwatch_event_rule.guardduty_all_findings.name
    high_severity   = aws_cloudwatch_event_rule.guardduty_high_severity.name
    ec2_compromise  = aws_cloudwatch_event_rule.ec2_compromise.name
    iam_compromise  = aws_cloudwatch_event_rule.iam_compromise.name
    s3_exfiltration = aws_cloudwatch_event_rule.s3_exfiltration.name
  }
}

output "dlq_url" {
  description = "Dead letter queue URL"
  value       = aws_sqs_queue.lambda_dlq.url
}