# AWS GuardDuty - Threat Simulation & Auto-Remediation


[![AWS](https://img.shields.io/badge/AWS-GuardDuty-orange?style=flat&logo=amazon-aws)](https://aws.amazon.com/guardduty/)
[![Terraform](https://img.shields.io/badge/Terraform-1.0+-purple?style=flat&logo=terraform)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat&logo=python)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Automated-green?style=flat&logo=shield)](/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 Project Overview

This project implements a **production-ready AWS security solution** that combines threat detection with automated incident response. Building on the secure VPC infrastructure from Project 1, this solution provides:

- **Real-time threat detection** using AWS GuardDuty
- **Automated remediation** via Lambda functions
- **Instant alerting** through SNS and Slack
- **Event-driven architecture** with EventBridge
- **Forensic capabilities** for incident investigation

## Project Structue

2 - AWS_Guard_Duty/
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── guardduty.tf
│   ├── sns.tf
│   ├── eventbridge.tf
│   ├── lambda.tf
│   ├── iam.tf
│   └── data.tf
├── lambda/
│   ├── remediation_handler.py
│   └── requirements.txt
├── threat-simulation/
│   ├── simulate_threats.sh
│   ├── dns_exfiltration.py
│   └── guardduty_tester.py
├── README.md

## 🔐 Security Features

### Threat Detection

| Threat Category | Finding Types | Auto-Remediation |
|-----------------|---------------|------------------|
| **EC2 Compromise** | CryptoCurrency, Backdoor, Trojan | ✅ Isolate + Snapshot |
| **IAM Credential Theft** | Credential Exfiltration, Anomalous Behavior | ✅ Disable Keys + Deny Policy |
| **S3 Data Exfiltration** | Malicious IP Caller, Unusual Access | ⚠️ Alert + Log |
| **Network Attacks** | Port Probe, SSH/RDP Brute Force | ✅ Block IP |
| **Malware** | Malware Protection Findings | ✅ Isolate + Snapshot |

### Automated Response Actions

1. **EC2 Instance Isolation**
   - Replace security groups with quarantine SG (no ingress/egress)
   - Tag instance with quarantine metadata
   - Preserve original security group info for recovery

2. **Forensic Snapshot Creation**
   - Automatic EBS volume snapshots before isolation
   - Tagged with finding details for investigation
   - Encrypted with KMS

3. **IAM Credential Revocation**
   - Disable compromised access keys
   - Attach deny-all inline policy
   - Preserve audit trail

4. **IP Blocking**
   - Log malicious IPs for WAF integration
   - Support for automated WAF IP set updates


## 🚀 Deployment Guide

### Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.0.0
- Python 3.11+
- Project 1 VPC infrastructure deployed (optional but recommended)

1. Clone the Repository

```bash
git clone https://github.com/Rolly-M/Cloud-Security-Portfolio.git
cd "Cloud-Security-Portfolio/2 - AWS_Guard_Duty"
```
2. Edit the `terraform/terraform.tfvars` to configure the deploymment variables. Make sure to define the VPC ID from project 1 if you want to deploy in the same VPC. Edit Lambda environment variables to enable/disable specific actions

3. Deploy the infrastructure

```bash
cd terraform

# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Deploy
terraform apply
```

After deployment, check your email and confirm the SNS subscription to receive alerts.

4. Test the solution:

```bash
cd ../threat-simulation

# Make scripts executable
chmod +x simulate_threats.sh

# Run threat simulation
./simulate_threats.sh

# Or use Python tester
python3 guardduty_tester.py --action generate --category ec2_crypto
```

## Verify Remediation

1. Check CloudWatch Logs for Lambda execution:

```bash
aws logs tail /aws/lambda/guardduty-security-dev-remediation-handler --follow
```

2. Check SNS notifications (email/Slack)

3. Verify EC2 instance isolation:

```bash
aws ec2 describe-instances --instance-ids <instance-id> \
  --query 'Reservations[].Instances[].SecurityGroups'
```

## 🧹Cleanup

When you're done testing or want to tear down the environment, follow these steps to properly clean up all resources and avoid ongoing charges.

Move to the root directory of the project and run the following commands:

```bash
chmod +x cleanup.sh
./cleanup.sh
```

### Important Notes

1. KMS Keys: KMS keys are scheduled for deletion (7-30 days) rather than immediately deleted. This is an AWS safety feature.
2. CloudWatch Logs: Log data is retained according to the retention policy. Deleting the log group removes all logs immediately.
3. Forensic Snapshots: Consider keeping snapshots if they contain evidence from actual security incidents.
4. Quarantined Instances: Always review quarantined instances before cleanup—they may have been legitimately compromised.
5. Billing: Some resources may have already incurred charges. Check your AWS bill after cleanup.
6. State File: If using remote state (S3 backend), remember to clean up the state file and DynamoDB lock table if no longer needed.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. If this project helped you, please consider giving it a star!
