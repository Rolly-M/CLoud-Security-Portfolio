# guardduty_lambda_remediation.tf - Lambda Functions for Automated Remediation

# ==========================================
# IAM ROLE FOR LAMBDA FUNCTIONS
# ==========================================
resource "aws_iam_role" "guardduty_remediation" {
  count = var.enable_guardduty ? 1 : 0
  name  = "${var.environment}-guardduty-remediation-role"

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
    Name        = "${var.environment}-guardduty-remediation-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "guardduty_remediation" {
  count = var.enable_guardduty ? 1 : 0
  name  = "${var.environment}-guardduty-remediation-policy"
  role  = aws_iam_role.guardduty_remediation[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Permissions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry",
          "ec2:ReplaceNetworkAclEntry"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSPermissions"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.guardduty_alerts[0].arn,
          aws_sns_topic.guardduty_critical[0].arn,
          aws_sns_topic.remediation_notifications[0].arn
        ]
      },
      {
        Sid    = "DynamoDBPermissions"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.guardduty_remediation[0].arn
      },
      {
        Sid    = "CloudWatchLogsPermissions"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "GuardDutyPermissions"
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ArchiveFindings",
          "guardduty:UpdateFindingsFeedback"
        ]
        Resource = "*"
      }
    ]
  })
}

# ==========================================
# LAMBDA: ISOLATE COMPROMISED INSTANCE
# ==========================================
resource "aws_lambda_function" "isolate_instance" {
  count         = var.enable_guardduty ? 1 : 0
  filename      = data.archive_file.isolate_instance.output_path
  function_name = "${var.environment}-guardduty-isolate-instance"
  role          = aws_iam_role.guardduty_remediation[0].arn
  handler       = "isolate_instance.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 256

  source_code_hash = data.archive_file.isolate_instance.output_base64sha256

  environment {
    variables = {
      QUARANTINE_SG_ID   = aws_security_group.quarantine[0].id
      SNS_TOPIC_ARN      = aws_sns_topic.remediation_notifications[0].arn
      DYNAMODB_TABLE     = aws_dynamodb_table.guardduty_remediation[0].name
      ENVIRONMENT        = var.environment
    }
  }

  tags = {
    Name        = "${var.environment}-guardduty-isolate-instance"
    Environment = var.environment
    Purpose     = "Isolate compromised EC2 instances"
  }
}

data "archive_file" "isolate_instance" {
  type        = "zip"
  output_path = "${path.module}/lambda/isolate_instance.zip"

  source {
    content  = <<-PYTHON
import json
import boto3
import os
from datetime import datetime, timedelta

ec2 = boto3.client('ec2')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    # Extract finding details
    detail = event.get('detail', {})
    finding_id = detail.get('id', 'unknown')
    finding_type = detail.get('type', 'unknown')
    severity = detail.get('severity', 0)
    
    # Get affected resource
    resource = detail.get('resource', {})
    instance_details = resource.get('instanceDetails', {})
    instance_id = instance_details.get('instanceId')
    
    if not instance_id:
        print("No instance ID found in finding")
        return {'statusCode': 400, 'body': 'No instance ID found'}
    
    print(f"Processing finding {finding_id} for instance {instance_id}")
    print(f"Finding type: {finding_type}, Severity: {severity}")
    
    quarantine_sg_id = os.environ['QUARANTINE_SG_ID']
    sns_topic_arn = os.environ['SNS_TOPIC_ARN']
    table_name = os.environ['DYNAMODB_TABLE']
    environment = os.environ['ENVIRONMENT']
    
    try:
        # Get current security groups
        response = ec2.describe_instances(InstanceIds=[instance_id])
        current_sgs = []
        if response['Reservations']:
            instance = response['Reservations'][0]['Instances'][0]
            current_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
        
        # Replace security groups with quarantine SG
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[quarantine_sg_id]
        )
        
        # Tag the instance
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'QuarantinedAt', 'Value': datetime.utcnow().isoformat()},
                {'Key': 'QuarantineReason', 'Value': finding_type},
                {'Key': 'PreviousSecurityGroups', 'Value': ','.join(current_sgs)},
                {'Key': 'GuardDutyFindingId', 'Value': finding_id},
                {'Key': 'SecurityStatus', 'Value': 'QUARANTINED'}
            ]
        )
        
        # Log to DynamoDB
        table = dynamodb.Table(table_name)
        table.put_item(Item={
            'FindingId': finding_id,
            'Timestamp': datetime.utcnow().isoformat(),
            'InstanceId': instance_id,
            'Action': 'ISOLATE',
            'FindingType': finding_type,
            'Severity': str(severity),
            'PreviousSecurityGroups': current_sgs,
            'Status': 'COMPLETED',
            'ExpirationTime': int((datetime.utcnow() + timedelta(days=90)).timestamp())
        })
        
        # Send notification
        message = f"""
🔒 INSTANCE ISOLATED - GUARDDUTY REMEDIATION

Environment: {environment}
Instance ID: {instance_id}
Finding Type: {finding_type}
Severity: {severity}
Finding ID: {finding_id}
Action Taken: Instance isolated (moved to quarantine security group)
Previous Security Groups: {', '.join(current_sgs)}
Quarantine SG: {quarantine_sg_id}
Time: {datetime.utcnow().isoformat()}

⚠️ NEXT STEPS:
1. Investigate the instance via SSM Session Manager (no network access)
2. Capture memory dump if needed
3. Create forensic snapshot
4. Determine root cause
5. Either remediate or terminate instance

DO NOT restore network access until investigation is complete.
        """
        
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"🔒 [CRITICAL] Instance {instance_id} Isolated - {finding_type}",
            Message=message
        )
        
        print(f"Successfully isolated instance {instance_id}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Instance {instance_id} isolated successfully',
                'instanceId': instance_id,
                'findingId': finding_id,
                'action': 'ISOLATED'
            })
        }
        
    except Exception as e:
        print(f"Error isolating instance: {str(e)}")
        
        # Send error notification
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"❌ [ERROR] Failed to isolate instance {instance_id}",
            Message=f"Error: {str(e)}\n\nFinding: {finding_type}\n\nManual intervention required!"
        )
        
        raise e
PYTHON
    filename = "isolate_instance.py"
  }
}

resource "aws_cloudwatch_log_group" "isolate_instance" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/aws/lambda/${var.environment}-guardduty-isolate-instance"
  retention_in_days = 30

  tags = {
    Name        = "${var.environment}-isolate-instance-logs"
    Environment = var.environment
  }
}

# ==========================================
# LAMBDA: BLOCK IP IN NACL
# ==========================================
resource "aws_lambda_function" "block_ip_nacl" {
  count         = var.enable_guardduty ? 1 : 0
  filename      = data.archive_file.block_ip_nacl.output_path
  function_name = "${var.environment}-guardduty-block-ip-nacl"
  role          = aws_iam_role.guardduty_remediation[0].arn
  handler       = "block_ip_nacl.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 256

  source_code_hash = data.archive_file.block_ip_nacl.output_base64sha256

  environment {
    variables = {
      VPC_ID             = aws_vpc.main.id
      SNS_TOPIC_ARN      = aws_sns_topic.remediation_notifications[0].arn
      DYNAMODB_TABLE     = aws_dynamodb_table.guardduty_remediation[0].name
      ENVIRONMENT        = var.environment
      # Start blocking rules at rule number 50 (before allows)
      NACL_RULE_START    = "50"
    }
  }

  tags = {
    Name        = "${var.environment}-guardduty-block-ip-nacl"
    Environment = var.environment
    Purpose     = "Block malicious IPs in Network ACL"
  }
}

data "archive_file" "block_ip_nacl" {
  type        = "zip"
  output_path = "${path.module}/lambda/block_ip_nacl.zip"

  source {
    content  = <<-PYTHON
import json
import boto3
import os
from datetime import datetime, timedelta

ec2 = boto3.client('ec2')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    # Extract finding details
    detail = event.get('detail', {})
    finding_id = detail.get('id', 'unknown')
    finding_type = detail.get('type', 'unknown')
    severity = detail.get('severity', 0)
    
    # Get malicious IP
    service = detail.get('service', {})
    action = service.get('action', {})
    
    # Try different paths to find the remote IP
    remote_ip = None
    
    # Network connection action
    network_info = action.get('networkConnectionAction', {})
    if network_info:
        remote_ip = network_info.get('remoteIpDetails', {}).get('ipAddressV4')
    
    # Port probe action
    if not remote_ip:
        port_probe = action.get('portProbeAction', {})
        if port_probe:
            port_probe_details = port_probe.get('portProbeDetails', [])
            if port_probe_details:
                remote_ip = port_probe_details[0].get('remoteIpDetails', {}).get('ipAddressV4')
    
    # AWS API call action
    if not remote_ip:
        api_call = action.get('awsApiCallAction', {})
        if api_call:
            remote_ip = api_call.get('remoteIpDetails', {}).get('ipAddressV4')
    
    if not remote_ip:
        print("No remote IP found in finding")
        return {'statusCode': 400, 'body': 'No remote IP found'}
    
    print(f"Blocking IP: {remote_ip} for finding: {finding_type}")
    
    vpc_id = os.environ['VPC_ID']
    sns_topic_arn = os.environ['SNS_TOPIC_ARN']
    table_name = os.environ['DYNAMODB_TABLE']
    environment = os.environ['ENVIRONMENT']
    rule_start = int(os.environ['NACL_RULE_START'])
    
    try:
        # Get all NACLs in the VPC
        nacls = ec2.describe_network_acls(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )['NetworkAcls']
        
        blocked_nacls = []
        
        for nacl in nacls:
            nacl_id = nacl['NetworkAclId']
            
            # Find the next available rule number
            existing_rules = [entry['RuleNumber'] for entry in nacl['Entries'] 
                           if not entry['Egress'] and entry['RuleNumber'] < 100]
            
            if existing_rules:
                next_rule = max(existing_rules) + 1
            else:
                next_rule = rule_start
            
            # Ensure rule number doesn't conflict
            while next_rule in [e['RuleNumber'] for e in nacl['Entries']]:
                next_rule += 1
            
            # Add DENY rule for the malicious IP
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=next_rule,
                Protocol='-1',  # All traffic
                RuleAction='deny',
                Egress=False,  # Inbound
                CidrBlock=f"{remote_ip}/32"
            )
            
            blocked_nacls.append({
                'nacl_id': nacl_id,
                'rule_number': next_rule
            })
            
            print(f"Blocked IP {remote_ip} in NACL {nacl_id} with rule {next_rule}")
        
        # Log to DynamoDB
        table = dynamodb.Table(table_name)
        table.put_item(Item={
            'FindingId': finding_id,
            'Timestamp': datetime.utcnow().isoformat(),
            'BlockedIP': remote_ip,
            'Action': 'BLOCK_IP_NACL',
            'FindingType': finding_type,
            'Severity': str(severity),
            'BlockedNACLs': json.dumps(blocked_nacls),
            'Status': 'COMPLETED',
            'ExpirationTime': int((datetime.utcnow() + timedelta(days=90)).timestamp())
        })
        
        # Send notification
        message = f"""
🚫 IP ADDRESS BLOCKED - GUARDDUTY REMEDIATION

Environment: {environment}
Blocked IP: {remote_ip}
Finding Type: {finding_type}
Severity: {severity}
Finding ID: {finding_id}
Action Taken: IP blocked in {len(blocked_nacls)} Network ACL(s)
Time: {datetime.utcnow().isoformat()}

Blocked in NACLs:
{json.dumps(blocked_nacls, indent=2)}

⚠️ NOTE:
- IP is blocked at the subnet level (NACL)
- All traffic from this IP will be denied
- Review and remove rule if it's a false positive
        """
        
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"🚫 [SECURITY] IP {remote_ip} Blocked - {finding_type}",
            Message=message
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'IP {remote_ip} blocked successfully',
                'blockedIP': remote_ip,
                'findingId': finding_id,
                'blockedNACLs': blocked_nacls
            })
        }
        
    except Exception as e:
        print(f"Error blocking IP: {str(e)}")
        
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"❌ [ERROR] Failed to block IP {remote_ip}",
            Message=f"Error: {str(e)}\n\nManual intervention required!"
        )
        
        raise e
PYTHON
    filename = "block_ip_nacl.py"
  }
}

resource "aws_cloudwatch_log_group" "block_ip_nacl" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/aws/lambda/${var.environment}-guardduty-block-ip-nacl"
  retention_in_days = 30

  tags = {
    Name        = "${var.environment}-block-ip-nacl-logs"
    Environment = var.environment
  }
}

# ==========================================
# LAMBDA: STOP INSTANCE (CRYPTO MINING)
# ==========================================
resource "aws_lambda_function" "stop_crypto_mining" {
  count         = var.enable_guardduty ? 1 : 0
  filename      = data.archive_file.stop_crypto_mining.output_path
  function_name = "${var.environment}-guardduty-stop-crypto-mining"
  role          = aws_iam_role.guardduty_remediation[0].arn
  handler       = "stop_crypto_mining.lambda_handler"
  runtime       = "python3.11"
  timeout       = 120
  memory_size   = 256

  source_code_hash = data.archive_file.stop_crypto_mining.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN      = aws_sns_topic.remediation_notifications[0].arn
      DYNAMODB_TABLE     = aws_dynamodb_table.guardduty_remediation[0].name
      ENVIRONMENT        = var.environment
      CREATE_SNAPSHOT    = "true"
    }
  }

  tags = {
    Name        = "${var.environment}-guardduty-stop-crypto-mining"
    Environment = var.environment
    Purpose     = "Stop instances with cryptocurrency mining"
  }
}

data "archive_file" "stop_crypto_mining" {
  type        = "zip"
  output_path = "${path.module}/lambda/stop_crypto_mining.zip"

  source {
    content  = <<-PYTHON
import json
import boto3
import os
from datetime import datetime, timedelta

ec2 = boto3.client('ec2')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    detail = event.get('detail', {})
    finding_id = detail.get('id', 'unknown')
    finding_type = detail.get('type', 'unknown')
    severity = detail.get('severity', 0)
    
    resource = detail.get('resource', {})
    instance_details = resource.get('instanceDetails', {})
    instance_id = instance_details.get('instanceId')
    
    if not instance_id:
        print("No instance ID found in finding")
        return {'statusCode': 400, 'body': 'No instance ID found'}
    
    print(f"Stopping instance {instance_id} for cryptocurrency mining")
    
    sns_topic_arn = os.environ['SNS_TOPIC_ARN']
    table_name = os.environ['DYNAMODB_TABLE']
    environment = os.environ['ENVIRONMENT']
    create_snapshot = os.environ.get('CREATE_SNAPSHOT', 'true').lower() == 'true'
    
    try:
        # Get instance details
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        
        snapshot_ids = []
        
        # Create snapshots of all volumes for forensics
        if create_snapshot:
            for block_device in instance.get('BlockDeviceMappings', []):
                volume_id = block_device.get('Ebs', {}).get('VolumeId')
                if volume_id:
                    snapshot = ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=f"Forensic snapshot - GuardDuty {finding_type} - {instance_id}",
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'Name', 'Value': f"forensic-{instance_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"},
                                {'Key': 'GuardDutyFindingId', 'Value': finding_id},
                                {'Key': 'SourceInstance', 'Value': instance_id},
                                {'Key': 'Purpose', 'Value': 'Forensic Investigation'}
                            ]
                        }]
                    )
                    snapshot_ids.append(snapshot['SnapshotId'])
                    print(f"Created snapshot {snapshot['SnapshotId']} of volume {volume_id}")
        
        # Tag the instance
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'StoppedAt', 'Value': datetime.utcnow().isoformat()},
                {'Key': 'StoppedReason', 'Value': finding_type},
                {'Key': 'GuardDutyFindingId', 'Value': finding_id},
                {'Key': 'ForensicSnapshots', 'Value': ','.join(snapshot_ids)},
                {'Key': 'SecurityStatus', 'Value': 'CRYPTO_MINING_STOPPED'}
            ]
        )
        
        # Stop the instance
        ec2.stop_instances(InstanceIds=[instance_id])
        print(f"Stopped instance {instance_id}")
        
        # Log to DynamoDB
        table = dynamodb.Table(table_name)
        table.put_item(Item={
            'FindingId': finding_id,
            'Timestamp': datetime.utcnow().isoformat(),
            'InstanceId': instance_id,
            'Action': 'STOP_CRYPTO_MINING',
            'FindingType': finding_type,
            'Severity': str(severity),
            'ForensicSnapshots': snapshot_ids,
            'Status': 'COMPLETED',
            'ExpirationTime': int((datetime.utcnow() + timedelta(days=90)).timestamp())
        })
        
        # Send notification
        message = f"""
⛏️🚫 CRYPTOCURRENCY MINING INSTANCE STOPPED

Environment: {environment}
Instance ID: {instance_id}
Finding Type: {finding_type}
Severity: {severity}
Finding ID: {finding_id}
Action Taken: Instance STOPPED + Forensic snapshots created
Time: {datetime.utcnow().isoformat()}

Forensic Snapshots Created:
{json.dumps(snapshot_ids, indent=2)}

⚠️ CRITICAL ACTIONS REQUIRED:
1. DO NOT restart this instance
2. Analyze the forensic snapshots
3. Identify the mining software/process
4. Determine how the instance was compromised
5. Check for lateral movement to other instances
6. Terminate instance after investigation
7. Rebuild from clean AMI if needed

💰 COST IMPACT:
Cryptocurrency mining can result in significant AWS charges.
Review your billing dashboard immediately.
        """
        
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"⛏️🚫 [CRITICAL] Crypto Mining Stopped - Instance {instance_id}",
            Message=message
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Instance {instance_id} stopped for crypto mining',
                'instanceId': instance_id,
                'findingId': finding_id,
                'forensicSnapshots': snapshot_ids
            })
        }
        
    except Exception as e:
        print(f"Error stopping instance: {str(e)}")
        
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"❌ [ERROR] Failed to stop crypto mining instance {instance_id}",
            Message=f"Error: {str(e)}\n\n⚠️ MANUAL INTERVENTION REQUIRED IMMEDIATELY!"
        )
        
        raise e
PYTHON
    filename = "stop_crypto_mining.py"
  }
}

resource "aws_cloudwatch_log_group" "stop_crypto_mining" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/aws/lambda/${var.environment}-guardduty-stop-crypto-mining"
  retention_in_days = 30

  tags = {
    Name        = "${var.environment}-stop-crypto-mining-logs"
    Environment = var.environment
  }
}

# ==========================================
# LAMBDA: SEND SLACK NOTIFICATION (OPTIONAL)
# ==========================================
resource "aws_lambda_function" "slack_notification" {
  count         = var.enable_guardduty && var.slack_webhook_url != "" ? 1 : 0
  filename      = data.archive_file.slack_notification[0].output_path
  function_name = "${var.environment}-guardduty-slack-notification"
  role          = aws_iam_role.guardduty_remediation[0].arn
  handler       = "slack_notification.lambda_handler"
  runtime       = "python3.11"
  timeout       = 30
  memory_size   = 128

  source_code_hash = data.archive_file.slack_notification[0].output_base64sha256

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      ENVIRONMENT       = var.environment
    }
  }

  tags = {
    Name        = "${var.environment}-guardduty-slack-notification"
    Environment = var.environment
    Purpose     = "Send GuardDuty alerts to Slack"
  }
}

data "archive_file" "slack_notification" {
  count       = var.slack_webhook_url != "" ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/lambda/slack_notification.zip"

  source {
    content  = <<-PYTHON
import json
import os
import urllib.request
import urllib.error

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    webhook_url = os.environ['SLACK_WEBHOOK_URL']
    environment = os.environ['ENVIRONMENT']
    
    detail = event.get('detail', {})
    finding_type = detail.get('type', 'Unknown')
    severity = detail.get('severity', 0)
    description = detail.get('description', 'No description')
    
    # Determine severity color and emoji
    if severity >= 7:
        color = "#ff0000"  # Red
        emoji = "🚨"
        severity_text = "HIGH"
    elif severity >= 4:
        color = "#ff9900"  # Orange
        emoji = "⚠️"
        severity_text = "MEDIUM"
    else:
        color = "#ffff00"  # Yellow
        emoji = "ℹ️"
        severity_text = "LOW"
    
    # Get instance info if available
    resource = detail.get('resource', {})
    instance_id = resource.get('instanceDetails', {}).get('instanceId', 'N/A')
    
    # Create Slack message
    slack_message = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} GuardDuty Alert - {environment.upper()}",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Finding Type:*\n{finding_type}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity_text} ({severity})"}
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Instance:*\n{instance_id}"},
                            {"type": "mrkdwn", "text": f"*Environment:*\n{environment}"}
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Description:*\n{description[:500]}..."
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "View in GuardDuty"},
                                "url": f"https://console.aws.amazon.com/guardduty/home#/findings"
                            }
                        ]
                    }
                ]
            }
        ]
    }
    
    # Send to Slack
    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(slack_message).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req)
        print("Slack notification sent successfully")
        return {'statusCode': 200, 'body': 'Notification sent'}
    except urllib.error.URLError as e:
        print(f"Error sending Slack notification: {e}")
        raise e
PYTHON
    filename = "slack_notification.py"
  }
}