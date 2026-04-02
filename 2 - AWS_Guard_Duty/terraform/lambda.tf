###############################################################################
# Lambda Function for Auto-Remediation
###############################################################################

# Create deployment package
data "archive_file" "remediation_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediation_handler.py"
  output_path = "${path.module}/../lambda/remediation_handler.zip"
}

# Lambda Function
resource "aws_lambda_function" "remediation_handler" {
  filename         = data.archive_file.remediation_handler.output_path
  function_name    = "${local.name_prefix}-remediation-handler"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "remediation_handler.lambda_handler"
  source_code_hash = data.archive_file.remediation_handler.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT              = var.environment
      SNS_TOPIC_ARN           = aws_sns_topic.remediation_notifications.arn
      ENABLE_AUTO_REMEDIATION = tostring(var.enable_auto_remediation)
      SEVERITY_THRESHOLD      = tostring(var.severity_threshold)
      ISOLATE_EC2             = tostring(var.remediation_actions.isolate_ec2)
      BLOCK_MALICIOUS_IP      = tostring(var.remediation_actions.block_malicious_ip)
      DISABLE_IAM_CREDENTIALS = tostring(var.remediation_actions.disable_iam_credentials)
      SNAPSHOT_INSTANCE       = tostring(var.remediation_actions.snapshot_instance)
      QUARANTINE_SG_ID        = aws_security_group.quarantine.id
      FINDINGS_BUCKET         = aws_s3_bucket.guardduty_findings.id
      SLACK_WEBHOOK_URL       = var.slack_webhook_url
    }
  }

  vpc_config {
    subnet_ids         = []  # Run outside VPC for AWS API access
    security_group_ids = []
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name = "${local.name_prefix}-remediation-handler"
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.remediation_handler.function_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.guardduty.arn

  depends_on = [aws_kms_key.guardduty]

  tags = {
    Name = "${local.name_prefix}-lambda-logs"
  }
}

# Dead Letter Queue for failed Lambda invocations
resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "${local.name_prefix}-remediation-dlq"
  message_retention_seconds  = 1209600  # 14 days
  kms_master_key_id         = aws_kms_key.guardduty.id

  tags = {
    Name = "${local.name_prefix}-remediation-dlq"
  }
}

# Quarantine Security Group
resource "aws_security_group" "quarantine" {
  name        = "${local.name_prefix}-quarantine-sg"
  description = "Quarantine security group - blocks all traffic"
  vpc_id      = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default.id

  # No ingress rules - blocks all inbound
  # No egress rules - blocks all outbound

  tags = {
    Name    = "${local.name_prefix}-quarantine-sg"
    Purpose = "Isolate compromised instances"
  }
}

# Get default VPC if none specified
data "aws_vpc" "default" {
  default = true
}

# Lambda Layer for common dependencies (optional)
resource "aws_lambda_layer_version" "security_tools" {
  filename            = "${path.module}/../lambda/layer.zip"
  layer_name          = "${local.name_prefix}-security-tools"
  compatible_runtimes = ["python3.11"]
  description         = "Common security tools and libraries"

  count = fileexists("${path.module}/../lambda/layer.zip") ? 1 : 0
}