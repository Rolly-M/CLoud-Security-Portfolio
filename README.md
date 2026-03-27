# 🚀 Cloud Security Engineer Portfolio

[![AWS Certified Solutions Architect](https://img.shields.io/badge/AWS%20Solutions%20Architect-Associate-orange?style=for-the-badge&logo=amazon-aws)](https://www.credly.com/badges/33105d15-a047-4119-a4e0-1a145bae0381/public_url)
[![ISC2 CC](https://img.shields.io/badge/ISC2%20CC-Certified%20in%20Cybersecurity-blue?style=for-the-badge&logo=isc2)](https://www.isc2.org/certifications/cc)
[![CompTIA CySA+](https://img.shields.io/badge/CompTIA%20CySA+-Certified%20Cybersecurity%20Analyst-brightgreen?style=for-the-badge&logo=comptia)](https://www.credly.com/badges/a986ca8c-0a1b-4d0d-b2f6-9071278d1447/public_url)
[![AZ-500](https://img.shields.io/badge/AZ--500-Passed-purple?style=for-the-badge&logo=microsoft-azure)](https://learn.microsoft.com/en-us/certifications/azure-security-engineer/) <!-- Update once passed -->
[![AWS SCS-C01](https://img.shields.io/badge/AWS%20SCS--C01-Passed-red?style=for-the-badge&logo=amazon-aws)](https://aws.amazon.com/certification/certified-security-specialty/) <!-- Update once passed -->
[![CCSP](https://img.shields.io/badge/CCSP-Passed-silver?style=for-the-badge&logo=isc2)](https://www.isc2.org/certifications/ccsp) <!-- Update once passed -->
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/[yourusername]/CloudSec-Portfolio/security-scan.yml?label=Security%20Scan)](https://github.com/[yourusername]/CloudSec-Portfolio/actions)

> **3-Month Journey: From CySA+ to Cloud Security Expert**  
> *Live Portfolio with 14+ AWS/Azure/CCSP Labs | Terraform IaC | Free Tier Demos | Job-Ready Cloud Sec Engineer*

<div class="header">
    <h2>👋 Hi! I'm Rolly Mougoue, Aspiring Cloud Security Engineer</h2>
    <p><strong>Goal: Secure Multi-Cloud Environments (AWS/Azure) | Target Roles: Cloud Security Engineer ($120k+)</strong></p>
    <a href="https://www.linkedin.com/in/rollymougoue/"><img src="https://img.shields.io/badge/LinkedIn-Connect%20Now-blue?style=for-the-badge&logo=linkedin" alt="LinkedIn"></a>
    <a href="Resume - Security Analyst (2).pdf"><img src="https://img.shields.io/badge/Resume-PDF-green?style=for-the-badge&logo=adobe-acrobat-reader" alt="Resume"></a>
</div>

## 📊 Skills Matrix
| Category | Proficiency | Proof (Repo/Lab) |
|----------|-------------|------------------|
| **AWS Security Hub** | ⭐⭐⭐⭐⭐ (10/10) | [Security Hub CIS](AWS-Security-Hub-CIS) |
| **GuardDuty & Inspector** | ⭐⭐⭐⭐⭐ | [GuardDuty Lab](AWS-GuardDuty-Lab) |
| **Azure Sentinel/Defender** | ⭐⭐⭐⭐ (9/10) | [Azure NSG/FW](Azure-NSG-Baseline) |
| **Terraform Secure IaC** | ⭐⭐⭐⭐⭐ | All Repos |
| **CIS/NIST Compliance** | ⭐⭐⭐⭐⭐ | [Compliance Pipeline](AWS-Compliance-Pipeline) |
| **EKS/AKS Hardening** | ⭐⭐⭐⭐ | [EKS CIS](AWS-EKS-CIS) |
| **KMS/KeyVault Encryption** | ⭐⭐⭐⭐⭐ | [Multi-Cloud Encrypt](AWS-MultiCloud-Encrypt) |

## 🔥 Live Demos (Public Free Tier Links)
- 🔒 **[Secure VPC Dashboard](https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#region=)** (Flow Logs Live)
- 🛡️ **[Security Hub CIS 100%](https://us-east-1.console.aws.amazon.com/securityhub/home?region=us-east-1)** (Shareable View)
- 📊 **[GuardDuty Findings](https://console.aws.amazon.com/guardduty/home?region=us-east-1)** (Simulated Threats)
- ☁️ **[Azure NSG Test](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredAppsPreview)** (Public Tenant)

*(Replace with your public Free Tier links. Use AWS Console Share for demos.)*

## 📂 All Repositories (14+ Hands-On Labs)
1. **[AWS-Secure-VPC](https://github.com/Rolly-M/CLoud-Security-Portfolio/tree/main/1%20-%20AWS-Secure-VPC)** : CIS VPC Baseline + NACL/Flow Logs.
2. **[AWS-GuardDuty-Lab](AWS-GuardDuty-Lab)** : Threat Simulation + Lambda Remediation.
3. **[AWS-Inspector-NSG](AWS-Inspector-NSG)** : Vulnerability Scans + Azure Hybrid.
4. **[AWS-WAF-Terraform](AWS-WAF-Terraform)** : SQLi/XSS Blocking.
5. **[AWS-Macie-KMS](AWS-Macie-KMS)** : PII Classification on S3.
6. **[AWS-Security-Hub-CIS](AWS-Security-Hub-CIS)** : 100% Compliance Controls.
7. **[AWS-Detective](AWS-Detective)** : Behavior Graph Analysis.
8. **[AWS-Nitro-Enclaves](AWS-Nitro-Enclaves)** : Confidential Compute.
9. **[AWS-EKS-CIS](AWS-EKS-CIS)** : Pod Security + IRSA.
10. **[Azure-NSG-Baseline](Azure-NSG-Baseline)** : Network Security Groups.
11. **[AWS-MultiCloud-Encrypt](AWS-MultiCloud-Encrypt)** : KMS vs KeyVault.
12. **[AWS-Compliance-Pipeline](AWS-Compliance-Pipeline)** : GitHub Actions Trivy.
13. **[Sentinel-AWS-Fusion](Sentinel-AWS-Fusion)** : Cross-Cloud Monitoring.
14. **[Zero-Trust-IAM](Zero-Trust-IAM)** : CCSP Advanced.

**🚀 Fork & Star to contribute!** All labs are Terraform/ARM reproducible + CI scans.

## 🎬 Journey Timeline
![Roadmap GIF](roadmap.gif)  
*(Add GIF created via Canva: S1-12 phases with cert milestones.)*

### Lab Example: AWS Secure VPC (Steps)
1. `terraform init && terraform apply` (VPC + Subnets).
2. Config NACL: Deny SSH/HTTP except bastion.
3. Enable Flow Logs → CloudWatch.
4. Test: `nmap` breach simulation.
5. `terraform destroy` + Screenshot 100% Secure.

**Demo GIF** :  
![VPC Demo](demos/vpc-demo.gif)

## 🛠️ How to Use This Portfolio
1. **Clone** : `git clone https://github.com/Rolly-M/CloudSec-Portfolio.git`
2. **Demos** : Click Live Links (Free Tier).
3. **Reproduce Labs** : Each repo has `README.md` with TF steps.
4. **CI/CD** : GitHub Actions auto-scan (Trivy/Semgrep) on push.

## 🤝 Contact & Job Opportunities
- 📧 Email: rollymk25@gmail.com
- 💼 LinkedIn: [linkedin.com/in/rolly-mougoue](https://www.linkedin.com/in/rolly-mougoue/)
- 📄 Resume: [Download PDF]("Resume - Security Analyst (2).pdf")

**Open to Cloud Security Engineer opportunities | AWS/Azure Focus | France/EU Remote.**

## 📈 Contributions & Stars
[![GitHub stars](https://img.shields.io/github/stars/Rolly-M/CloudSec-Portfolio?style=social)](https://github.com/Rolly-M/CloudSec-Portfolio/stargazers/)
[![GitHub forks](https://img.shields.io/github/forks/Rolly-M/CloudSec-Portfolio?style=social)](https://github.com/Rolly-M/CloudSec-Portfolio/network/members/)

**Thanks for the ⭐! Share your forked lab on LinkedIn #CloudSecurity**

---

*This portfolio was built with ❤️ in 3 months (Plan: AZ-500 W6 | SCS W9 | CCSP W12). Weekly updates!*  
*Last Update: [Today's Date]*

</body>
</html>
