#!/bin/bash

###############################################################################
# GuardDuty Threat Simulation Script
# 
# This script generates sample GuardDuty findings for testing the
# auto-remediation pipeline. It uses AWS CLI commands to create
# simulated threats that GuardDuty will detect.
#
# WARNING: Only run this in a test/development environment!
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGION="${AWS_REGION:-us-east-1}"
DETECTOR_ID=""

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         GuardDuty Threat Simulation Tool                       ║"
echo "║         For Testing Auto-Remediation Pipeline                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} \$1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} \$1"
}

print_error() {
    echo -e "${RED}[✗]${NC} \$1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} \$1"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Please run 'aws configure'."
        exit 1
    fi
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        print_warning "jq is not installed. Installing..."
        sudo apt-get install -y jq 2>/dev/null || brew install jq 2>/dev/null || {
            print_error "Failed to install jq. Please install manually."
            exit 1
        }
    fi
    
    print_status "Prerequisites check passed"
}

# Get GuardDuty detector ID
get_detector_id() {
    print_info "Getting GuardDuty detector ID..."
    
    DETECTOR_ID=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)
    
    if [ -z "$DETECTOR_ID" ] || [ "$DETECTOR_ID" == "None" ]; then
        print_error "No GuardDuty detector found in region $REGION"
        exit 1
    fi
    
    print_status "Found detector: $DETECTOR_ID"
}

# Generate sample findings using GuardDuty's built-in sample generator
generate_sample_findings() {
    print_info "Generating sample GuardDuty findings..."
    
    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --finding-types \
            "Backdoor:EC2/C&CActivity.B!DNS" \
            "CryptoCurrency:EC2/BitcoinTool.B!DNS" \
            "Trojan:EC2/BlackholeTraffic" \
            "UnauthorizedAccess:EC2/SSHBruteForce" \
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" \
            "Exfiltration:S3/MaliciousIPCaller" \
            "Policy:S3/BucketBlockPublicAccessDisabled" \
            "Recon:EC2/PortProbeUnprotectedPort"
    
    print_status "Sample findings generated successfully"
}

# Simulate specific threat types
simulate_ec2_threat() {
    print_info "Simulating EC2 threat (Cryptocurrency mining detection)..."
    
    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --finding-types "CryptoCurrency:EC2/BitcoinTool.B!DNS"
    
    print_status "EC2 cryptocurrency mining finding generated"
}

simulate_iam_threat() {
    print_info "Simulating IAM credential compromise..."
    
    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --finding-types \
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" \
            "CredentialAccess:IAMUser/AnomalousBehavior"
    
    print_status "IAM compromise findings generated"
}

simulate_s3_threat() {
    print_info "Simulating S3 data exfiltration..."
    
    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --finding-types \
            "Exfiltration:S3/MaliciousIPCaller" \
            "Policy:S3/BucketBlockPublicAccessDisabled"
    
    print_status "S3 exfiltration findings generated"
}

simulate_network_threat() {
    print_info "Simulating network-based threats..."
    
    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --finding-types \
            "Recon:EC2/PortProbeUnprotectedPort" \
            "UnauthorizedAccess:EC2/SSHBruteForce" \
            "Backdoor:EC2/C&CActivity.B!DNS"
    
    print_status "Network threat findings generated"
}

# List recent findings
list_recent_findings() {
    print_info "Listing recent GuardDuty findings..."
    
    echo ""
    echo -e "${BLUE}Recent Findings:${NC}"
    echo "─────────────────────────────────────────────────────────────"
    
    aws guardduty list-findings \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --max-results 10 \
        --query 'FindingIds' \
        --output json | jq -r '.[]' | while read finding_id; do
        
        finding=$(aws guardduty get-findings \
            --detector-id "$DETECTOR_ID" \
            --region "$REGION" \
            --finding-ids "$finding_id" \
            --query 'Findings[0]' \
            --output json)
        
        type=$(echo "$finding" | jq -r '.Type')
        severity=$(echo "$finding" | jq -r '.Severity')
        created=$(echo "$finding" | jq -r '.CreatedAt')
        
        # Color based on severity
        if (( $(echo "$severity >= 7" | bc -l) )); then
            color=$RED
        elif (( $(echo "$severity >= 4" | bc -l) )); then
            color=$YELLOW
        else
            color=$GREEN
        fi
        
        echo -e "${color}[Severity: $severity]${NC} $type"
        echo "  Created: $created"
        echo ""
    done
}

# Archive all sample findings
archive_sample_findings() {
    print_info "Archiving sample findings..."
    
    finding_ids=$(aws guardduty list-findings \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]}}}' \
        --query 'FindingIds' \
        --output json | jq -r '.[]')
    
    if [ -n "$finding_ids" ]; then
        echo "$finding_ids" | xargs -I {} aws guardduty archive-findings \
            --detector-id "$DETECTOR_ID" \
            --region "$REGION" \
            --finding-ids {}
        print_status "Findings archived"
    else
        print_info "No findings to archive"
    fi
}

# Interactive menu
show_menu() {
    echo ""
    echo -e "${BLUE}Select an option:${NC}"
    echo "─────────────────────────────────────────────────────────────"
    echo "1) Generate ALL sample findings"
    echo "2) Simulate EC2 threat (Cryptocurrency mining)"
    echo "3) Simulate IAM credential compromise"
    echo "4) Simulate S3 data exfiltration"
    echo "5) Simulate network-based threats"
    echo "6) List recent findings"
    echo "7) Archive all findings"
    echo "8) Run DNS exfiltration simulation"
    echo "9) Run comprehensive threat test"
    echo "0) Exit"
    echo "─────────────────────────────────────────────────────────────"
    read -p "Enter choice [0-9]: " choice
    
    case $choice in
        1) generate_sample_findings ;;
        2) simulate_ec2_threat ;;
        3) simulate_iam_threat ;;
        4) simulate_s3_threat ;;
        5) simulate_network_threat ;;
        6) list_recent_findings ;;
        7) archive_sample_findings ;;
        8) python3 "$(dirname "\$0")/dns_exfiltration.py" ;;
        9) python3 "$(dirname "\$0")/guardduty_tester.py" ;;
        0) 
            print_info "Exiting..."
            exit 0 
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
}

# Main execution
main() {
    check_prerequisites
    get_detector_id
    
    if [ "\$1" == "--all" ]; then
        generate_sample_findings
        exit 0
    fi
    
    while true; do
        show_menu
    done
}

# Run main function
main "$@"