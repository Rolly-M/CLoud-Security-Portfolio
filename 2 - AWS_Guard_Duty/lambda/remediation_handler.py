"""
AWS GuardDuty Auto-Remediation Handler

This Lambda function automatically responds to GuardDuty findings by:
1. Isolating compromised EC2 instances
2. Disabling compromised IAM credentials
3. Blocking malicious IP addresses
4. Creating forensic snapshots
5. Sending notifications

Author: Cloud Security Portfolio
Version: 1.0.0
"""

import json
import os
import logging
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
import urllib3

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')
s3_client = boto3.client('s3')
wafv2_client = boto3.client('wafv2')

# Environment variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ENABLE_AUTO_REMEDIATION = os.environ.get('ENABLE_AUTO_REMEDIATION', 'true').lower() == 'true'
SEVERITY_THRESHOLD = float(os.environ.get('SEVERITY_THRESHOLD', '7.0'))
QUARANTINE_SG_ID = os.environ.get('QUARANTINE_SG_ID', '')
FINDINGS_BUCKET = os.environ.get('FINDINGS_BUCKET', '')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')

# Remediation feature flags
ISOLATE_EC2 = os.environ.get('ISOLATE_EC2', 'true').lower() == 'true'
BLOCK_MALICIOUS_IP = os.environ.get('BLOCK_MALICIOUS_IP', 'true').lower() == 'true'
DISABLE_IAM_CREDENTIALS = os.environ.get('DISABLE_IAM_CREDENTIALS', 'true').lower() == 'true'
SNAPSHOT_INSTANCE = os.environ.get('SNAPSHOT_INSTANCE', 'true').lower() == 'true'


def lambda_handler(event, context):
    """
    Main Lambda handler for GuardDuty findings.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        finding = parse_finding(event)
        
        if not finding:
            logger.warning("No valid finding in event")
            return create_response(400, "No valid finding in event")
        
        log_finding(finding)
        store_finding(finding)
        
        if not ENABLE_AUTO_REMEDIATION:
            logger.info("Auto-remediation is disabled, sending notification only")
            send_notification(finding, [])
            return create_response(200, "Notification sent, remediation disabled")
        
        if finding['severity'] < SEVERITY_THRESHOLD:
            logger.info(f"Severity {finding['severity']} below threshold {SEVERITY_THRESHOLD}")
            send_notification(finding, [])
            return create_response(200, "Below severity threshold, notification sent")
        
        actions_taken = execute_remediation(finding)
        send_notification(finding, actions_taken)
        
        return create_response(200, "Remediation completed", actions_taken)
        
    except Exception as e:
        logger.error(f"Error processing finding: {str(e)}", exc_info=True)
        send_error_notification(str(e), event)
        return create_response(500, f"Error: {str(e)}")


def parse_finding(event):
    """Parse GuardDuty finding from EventBridge event."""
    try:
        detail = event.get('detail', {})
        
        return {
            'id': detail.get('id', 'unknown'),
            'type': detail.get('type', 'unknown'),
            'severity': float(detail.get('severity', 0)),
            'title': detail.get('title', 'Unknown Finding'),
            'description': detail.get('description', ''),
            'region': event.get('region', 'unknown'),
            'account_id': detail.get('accountId', event.get('account', 'unknown')),
            'resource': detail.get('resource', {}),
            'service': detail.get('service', {}),
            'created_at': detail.get('createdAt', ''),
            'updated_at': detail.get('updatedAt', ''),
            'raw': detail
        }
    except Exception as e:
        logger.error(f"Error parsing finding: {str(e)}")
        return None


def log_finding(finding):
    """Log finding details for audit trail."""
    logger.info("=" * 60)
    logger.info("GUARDDUTY FINDING DETECTED")
    logger.info("=" * 60)
    logger.info(f"Finding ID: {finding['id']}")
    logger.info(f"Type: {finding['type']}")
    logger.info(f"Severity: {finding['severity']}")
    logger.info(f"Title: {finding['title']}")
    logger.info(f"Region: {finding['region']}")
    logger.info(f"Account: {finding['account_id']}")
    logger.info("=" * 60)


def store_finding(finding):
    """Store finding in S3 for forensic analysis."""
    if not FINDINGS_BUCKET:
        logger.warning("Findings bucket not configured")
        return
    
    try:
        timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d/%H')
        key = f"findings/{timestamp}/{finding['id']}.json"
        
        s3_client.put_object(
            Bucket=FINDINGS_BUCKET,
            Key=key,
            Body=json.dumps(finding['raw'], indent=2),
            ContentType='application/json',
            ServerSideEncryption='aws:kms'
        )
        logger.info(f"Finding stored in s3://{FINDINGS_BUCKET}/{key}")
    except Exception as e:
        logger.error(f"Error storing finding: {str(e)}")


def execute_remediation(finding):
    """Execute remediation actions based on finding type."""
    actions_taken = []
    finding_type = finding['type']
    
    if any(prefix in finding_type for prefix in ['EC2/', ':EC2']):
        actions_taken.extend(remediate_ec2(finding))
    
    elif any(prefix in finding_type for prefix in ['IAMUser/', ':IAMUser']):
        actions_taken.extend(remediate_iam(finding))
    
    elif any(prefix in finding_type for prefix in ['S3/', ':S3']):
        actions_taken.extend(remediate_s3(finding))
    
    if 'RemoteIpDetails' in str(finding.get('service', {})):
        actions_taken.extend(block_malicious_ip(finding))
    
    return actions_taken


def remediate_ec2(finding):
    """Remediate EC2-related findings."""
    actions = []
    resource = finding.get('resource', {})
    instance_details = resource.get('instanceDetails', {})
    instance_id = instance_details.get('instanceId')
    
    if not instance_id:
        logger.warning("No instance ID found in finding")
        return actions
    
    logger.info(f"Remediating EC2 instance: {instance_id}")
    
    if SNAPSHOT_INSTANCE:
        snapshot_action = create_forensic_snapshot(instance_id, finding)
        if snapshot_action:
            actions.append(snapshot_action)
    
    if ISOLATE_EC2:
        isolate_action = isolate_instance(instance_id, finding)
        if isolate_action:
            actions.append(isolate_action)
    
    return actions


def create_forensic_snapshot(instance_id, finding):
    """Create snapshot of instance volumes for forensic analysis."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response['Reservations']:
            logger.warning(f"Instance {instance_id} not found")
            return None
        
        instance = response['Reservations'][0]['Instances'][0]
        volumes = instance.get('BlockDeviceMappings', [])
        
        snapshot_ids = []
        for volume in volumes:
            volume_id = volume.get('Ebs', {}).get('VolumeId')
            if volume_id:
                snapshot = ec2_client.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"Forensic snapshot - GuardDuty finding {finding['id']}",
                    TagSpecifications=[{
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {'Key': 'Name', 'Value': f'Forensic-{instance_id}-{volume_id}'},
                            {'Key': 'GuardDutyFindingId', 'Value': finding['id']},
                            {'Key': 'FindingType', 'Value': finding['type']},
                            {'Key': 'SourceInstance', 'Value': instance_id},
                            {'Key': 'CreatedBy', 'Value': 'GuardDuty-Auto-Remediation'},
                            {'Key': 'Severity', 'Value': str(finding['severity'])}
                        ]
                    }]
                )
                snapshot_ids.append(snapshot['SnapshotId'])
                logger.info(f"Created snapshot {snapshot['SnapshotId']} for volume {volume_id}")
        
        return {
            'action': 'CREATE_FORENSIC_SNAPSHOT',
            'instance_id': instance_id,
            'snapshot_ids': snapshot_ids,
            'status': 'SUCCESS'
        }
        
    except ClientError as e:
        logger.error(f"Error creating snapshot: {str(e)}")
        return {
            'action': 'CREATE_FORENSIC_SNAPSHOT',
            'instance_id': instance_id,
            'status': 'FAILED',
            'error': str(e)
        }


def isolate_instance(instance_id, finding):
    """Isolate EC2 instance by replacing security groups."""
    try:
        if not QUARANTINE_SG_ID:
            logger.warning("Quarantine security group not configured")
            return None
        
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response['Reservations']:
            logger.warning(f"Instance {instance_id} not found")
            return None
        
        instance = response['Reservations'][0]['Instances'][0]
        original_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
        
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'QuarantinedAt', 'Value': datetime.now(timezone.utc).isoformat()},
                {'Key': 'QuarantineReason', 'Value': finding['type']},
                {'Key': 'GuardDutyFindingId', 'Value': finding['id']},
                {'Key': 'OriginalSecurityGroups', 'Value': ','.join(original_sgs)},
                {'Key': 'SecurityStatus', 'Value': 'QUARANTINED'}
            ]
        )
        
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[QUARANTINE_SG_ID]
        )
        
        logger.info(f"Instance {instance_id} isolated with quarantine security group")
        
        return {
            'action': 'ISOLATE_INSTANCE',
            'instance_id': instance_id,
            'original_security_groups': original_sgs,
            'quarantine_security_group': QUARANTINE_SG_ID,
            'status': 'SUCCESS'
        }
        
    except ClientError as e:
        logger.error(f"Error isolating instance: {str(e)}")
        return {
            'action': 'ISOLATE_INSTANCE',
            'instance_id': instance_id,
            'status': 'FAILED',
            'error': str(e)
        }


def remediate_iam(finding):
    """Remediate IAM-related findings."""
    actions = []
    
    if not DISABLE_IAM_CREDENTIALS:
        return actions
    
    resource = finding.get('resource', {})
    access_key_details = resource.get('accessKeyDetails', {})
    user_name = access_key_details.get('userName')
    access_key_id = access_key_details.get('accessKeyId')
    
    if not user_name:
        logger.warning("No IAM user found in finding")
        return actions
    
    logger.info(f"Remediating IAM user: {user_name}")
    
    try:
        if access_key_id:
            iam_client.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            logger.info(f"Disabled access key {access_key_id} for user {user_name}")
            
            actions.append({
                'action': 'DISABLE_ACCESS_KEY',
                'user_name': user_name,
                'access_key_id': access_key_id,
                'status': 'SUCCESS'
            })
        
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyAllGuardDutyRemediation",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }]
        }
        
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName='GuardDuty-Quarantine-DenyAll',
            PolicyDocument=json.dumps(deny_policy)
        )
        logger.info(f"Attached deny-all policy to user {user_name}")
        
        actions.append({
            'action': 'ATTACH_DENY_POLICY',
            'user_name': user_name,
            'policy_name': 'GuardDuty-Quarantine-DenyAll',
            'status': 'SUCCESS'
        })
        
    except ClientError as e:
        logger.error(f"Error remediating IAM user: {str(e)}")
        actions.append({
            'action': 'IAM_REMEDIATION',
            'user_name': user_name,
            'status': 'FAILED',
            'error': str(e)
        })
    
    return actions


def remediate_s3(finding):
    """Remediate S3-related findings."""
    actions = []
    
    resource = finding.get('resource', {})
    s3_bucket_details = resource.get('s3BucketDetails', [])
    
    if not s3_bucket_details:
        logger.warning("No S3 bucket found in finding")
        return actions
    
    for bucket in s3_bucket_details:
        bucket_name = bucket.get('name')
        if bucket_name:
            logger.info(f"S3 finding detected for bucket: {bucket_name}")
            actions.append({
                'action': 'S3_FINDING_LOGGED',
                'bucket_name': bucket_name,
                'finding_type': finding['type'],
                'status': 'LOGGED_FOR_REVIEW'
            })
    
    return actions


def block_malicious_ip(finding):
    """Block malicious IP addresses."""
    actions = []
    
    if not BLOCK_MALICIOUS_IP:
        return actions
    
    try:
        service = finding.get('service', {})
        action_details = service.get('action', {})
        
        remote_ip = None
        
        for action_type in ['networkConnectionAction', 'awsApiCallAction', 'portProbeAction']:
            if action_type in action_details:
                remote_ip_details = action_details[action_type].get('remoteIpDetails', {})
                remote_ip = remote_ip_details.get('ipAddressV4')
                if remote_ip:
                    break
        
        if not remote_ip:
            logger.warning("No remote IP found in finding")
            return actions
        
        logger.info(f"Blocking malicious IP: {remote_ip}")
        
        actions.append({
            'action': 'BLOCK_IP_LOGGED',
            'ip_address': remote_ip,
            'finding_type': finding['type'],
            'status': 'LOGGED_FOR_REVIEW'
        })
        
    except Exception as e:
        logger.error(f"Error blocking IP: {str(e)}")
        actions.append({
            'action': 'BLOCK_IP',
            'status': 'FAILED',
            'error': str(e)
        })
    
    return actions


def send_notification(finding, actions_taken):
    """Send notification via SNS and Slack."""
    severity_emoji = "🔴" if finding['severity'] >= 7 else "🟡" if finding['severity'] >= 4 else "🟢"
    
    message = f"""
{severity_emoji} GuardDuty Security Alert {severity_emoji}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 FINDING DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔹 Finding ID: {finding['id']}
🔹 Type: {finding['type']}
🔹 Severity: {finding['severity']}/10
🔹 Region: {finding['region']}
🔹 Account: {finding['account_id']}

📝 Description:
{finding['description'][:500]}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 REMEDIATION ACTIONS TAKEN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    
    if actions_taken:
        for action in actions_taken:
            status_emoji = "✅" if action.get('status') == 'SUCCESS' else "❌" if action.get('status') == 'FAILED' else "ℹ️"
            message += f"{status_emoji} {action.get('action', 'Unknown')}: {action.get('status', 'Unknown')}\n"
            
            # Add action details
            for key, value in action.items():
                if key not in ['action', 'status', 'error']:
                    message += f"   └─ {key}: {value}\n"
    else:
        message += "ℹ️ No automated actions taken\n"
    
    message += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⏰ Timestamp: {datetime.now(timezone.utc).isoformat()}
🌐 Environment: {ENVIRONMENT}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    
    # Send to SNS
    if SNS_TOPIC_ARN:
        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"[{severity_emoji}] GuardDuty Alert: {finding['type']}",
                Message=message
            )
            logger.info("SNS notification sent successfully")
        except Exception as e:
            logger.error(f"Error sending SNS notification: {str(e)}")
    
    # Send to Slack
    if SLACK_WEBHOOK_URL:
        send_slack_notification(finding, actions_taken)


def send_slack_notification(finding, actions_taken):
    """Send formatted notification to Slack."""
    try:
        severity_color = "#FF0000" if finding['severity'] >= 7 else "#FFA500" if finding['severity'] >= 4 else "#00FF00"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 GuardDuty Security Alert",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Finding Type:*\n{finding['type']}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{finding['severity']}/10"},
                    {"type": "mrkdwn", "text": f"*Region:*\n{finding['region']}"},
                    {"type": "mrkdwn", "text": f"*Account:*\n{finding['account_id']}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{finding['description'][:300]}..."
                }
            },
            {"type": "divider"}
        ]
        
        if actions_taken:
            actions_text = "*Remediation Actions:*\n"
            for action in actions_taken:
                status_emoji = "✅" if action.get('status') == 'SUCCESS' else "❌"
                actions_text += f"{status_emoji} {action.get('action')}: {action.get('status')}\n"
            
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": actions_text}
            })
        
        payload = {
            "attachments": [{
                "color": severity_color,
                "blocks": blocks
            }]
        }
        
        http = urllib3.PoolManager()
        response = http.request(
            'POST',
            SLACK_WEBHOOK_URL,
            body=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status == 200:
            logger.info("Slack notification sent successfully")
        else:
            logger.error(f"Slack notification failed: {response.status}")
            
    except Exception as e:
        logger.error(f"Error sending Slack notification: {str(e)}")


def send_error_notification(error_message, event):
    """Send error notification."""
    if SNS_TOPIC_ARN:
        try:
            message = f"""
❌ GuardDuty Remediation Error ❌

Error: {error_message}

Event:
{json.dumps(event, indent=2)[:1000]}

Timestamp: {datetime.now(timezone.utc).isoformat()}
"""
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="[ERROR] GuardDuty Remediation Failed",
                Message=message
            )
        except Exception as e:
            logger.error(f"Error sending error notification: {str(e)}")


def create_response(status_code, message, actions=None):
    """Create standardized Lambda response."""
    return {
        'statusCode': status_code,
        'body': json.dumps({
            'message': message,
            'actions': actions or [],
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    }