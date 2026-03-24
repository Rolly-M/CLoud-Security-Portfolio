# AWS Multi-AZ VPC Infrastructure with Bastion Host and Advanced Monitoring

## 📌Overview
This repository contains a production-ready Terraform configuration that deploys a highly secure, scalable, and observable AWS networking environment. The infrastructure follows the AWS Well-Architected Framework by utilizing multiple Availability Zones (AZs), isolated subnets, and a robust security perimeter.

The core of this setup is a VPC (10.0.0.0/16) featuring a Bastion Host (Jump Box) architecture, ensuring that private resources remain unreachable directly from the public internet.

## 🏗 Architecture Diagram

<img width="531" height="977" alt="image" src="https://github.com/user-attachments/assets/d577c5bc-8ea8-4ba4-bb5b-8f32592e7fa5" />

## 🛠 Component Breakdown

1. Networking (VPC & Subnets)
- *VPC*: A dedicated virtual network with CIDR 10.0.0.0/16.
- *Public Subnets (x3)*: Distributed across three Availability Zones. These subnets host the Bastion Host and the NAT Gateway.
- *Private Subnets (x3)*: Isolated subnets where backend workloads (Web Servers) reside. They have no direct route to the internet.
- *Internet Gateway (IGW)*: Enables communication between the VPC and the internet for public resources.
- *NAT Gateway*: A fully managed AWS service that allows private instances to initiate outbound traffic (for OS updates/patches) while preventing the internet from initiating connections with them.

2. Compute & Access (The Bastion Host)
- Bastion Host: A hardened EC2 instance acting as the "Jump Box." It is the only entry point for administrative SSH access to the private environment.
- Private Instances: Two Amazon Linux 2 EC2 instances running Apache Web Server, located in private subnets for maximum security.
- IAM Instance Profiles: All instances are pre-configured with permissions for AWS Systems Manager (SSM) and CloudWatch Agent.

3. Security (Multi-Layered Defense)
- Network ACLs (NACLs):
    - Public: Allows SSH from your specific IP only; allows HTTP/HTTPS traffic.
    - Private: Denies all SSH (22) and HTTP (80) traffic unless it originates from the Bastion Host subnet or the internal VPC CIDR.
- Security Groups (SGs):
    - Bastion SG: Restricted to SSH access from a single admin IP.
    - Private SG: Acts as an internal firewall, only allowing SSH traffic if it comes from the Bastion Security Group (Security Group Referencing).

4. Observability & Monitoring
- VPC Flow Logs: Captures IP traffic information for all network interfaces in the VPC.
    - Accepted Traffic Log: General auditing of network flow.
    - Rejected Traffic Log: Specifically monitors failed connection attempts for security forensics.
- CloudWatch Alarms: Automated alerts for:
    - High CPU Utilization (>80%).
    - EC2 Status Check Failures.
    - Security Events: Alerts on excessive rejected SSH attempts (possible brute-force) and port scanning patterns.
- CloudWatch Dashboard: A unified visual interface to monitor the health of the entire infrastructure, including NAT Gateway bandwidth, EC2 performance, and security metrics.
- SNS Notifications: Critical alerts are pushed directly to a configured administrator email address.

## 🚀 Deployment Instructions

### Prerequisites

- Terraform installed (>= 1.0.0)
- AWS CLI configured with appropriate credentials
- An existing AWS Key Pair for SSH access

### Steps

1. Clone the repository:

```bash
git clone https://github.com/Rolly-M/CLoud-Security-Portfolio.git
cd "1 - AWS-Secure-VPC"
```

2. Initialize Terraform:

```bash
terraform init
```

3. Configure Variables:
Update terraform.tfvars with your specific values:
- allowed_ssh_cidr: Your public IP (e.g., 1.2.3.4/32)
- alert_email: Your email for SNS notifications
- key_name: The name of your AWS SSH Key Pair

4. Plan and Apply:

```bash
terraform plan
terraform apply
```

## 🔑 Accessing the Private Environment

To maintain a high security posture, access to private instances is performed via SSH Agent Forwarding:

1. Add your key to the SSH agent:

```bash
ssh-add <YOUR_KEY_PAIR.pem>
```

2. Connect to the Bastion Host:

```bash
ssh -A ec2-user@<BASTION_PUBLIC_IP>
```

3. Jump to a private instance:

```bash
ssh ec2-user@<PRIVATE_INSTANCE_IP>
```

## 📊 Monitoring

Once deployed, you can access the Infrastructure Dashboard in the CloudWatch console. The URL is provided as a Terraform output:

```bash
terraform output cloudwatch_dashboard_url
```

## ⚠️ Cleanup

To avoid ongoing AWS costs (specifically for the NAT Gateway and EC2 instances), destroy the infrastructure when finished:

```bash
terraform destroy
```
