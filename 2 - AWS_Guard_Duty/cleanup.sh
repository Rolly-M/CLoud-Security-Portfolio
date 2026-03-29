#!/bin/bash

###############################################################################
# Complete Environment Cleanup Script
# 
# WARNING: This script will destroy ALL resources created by this project!
# Make sure you want to proceed before running.
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  WARNING: This will destroy ALL project resources!             ║"
echo "║  This action cannot be undone.                                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

read -p "Are you sure you want to proceed? (type 'destroy' to confirm): " confirm

if [ "$confirm" != "destroy" ]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo -e "\n${YELLOW}Starting cleanup...${NC}\n"

# Get project root directory
PROJECT_DIR="$(cd "$(dirname "\$0")" && pwd)"

# Step 1: Archive findings
echo -e "${GREEN}[1/8] Archiving GuardDuty findings...${NC}"
cd "$PROJECT_DIR/threat-simulation"
python3 guardduty_tester.py --action archive 2>/dev/null || echo "No findings to archive"

# Step 2: Get bucket name before destroying
echo -e "${GREEN}[2/8] Getting S3 bucket name...${NC}"
cd "$PROJECT_DIR/terraform"
BUCKET_NAME=$(terraform output -raw findings_bucket_name 2>/dev/null || echo "")

# Step 3: Empty S3 bucket
if [ -n "$BUCKET_NAME" ]; then
    echo -e "${GREEN}[3/8] Emptying S3 bucket: $BUCKET_NAME${NC}"
    aws s3 rm s3://$BUCKET_NAME --recursive 2>/dev/null || true
    
    # Delete versions
    aws s3api list-object-versions --bucket $BUCKET_NAME --output json 2>/dev/null | \
    jq -r '.Versions[]? | "\(.Key),\(.VersionId)"' | \
    while IFS=',' read -r key version; do
        aws s3api delete-object --bucket $BUCKET_NAME --key "$key" --version-id "$version" 2>/dev/null || true
    done
    
    # Delete markers
    aws s3api list-object-versions --bucket $BUCKET_NAME --output json 2>/dev/null | \
    jq -r '.DeleteMarkers[]? | "\(.Key),\(.VersionId)"' | \
    while IFS=',' read -r key version; do
        aws s3api delete-object --bucket $BUCKET_NAME --key "$key" --version-id "$version" 2>/dev/null || true
    done
else
    echo -e "${YELLOW}[3/8] No S3 bucket found, skipping...${NC}"
fi

# Step 4: Delete forensic snapshots
echo -e "${GREEN}[4/8] Deleting forensic snapshots...${NC}"
SNAPSHOTS=$(aws ec2 describe-snapshots \
    --filters "Name=tag:CreatedBy,Values=GuardDuty-Auto-Remediation" \
    --query 'Snapshots[*].SnapshotId' \
    --output text 2>/dev/null || echo "")

if [ -n "$SNAPSHOTS" ]; then
    for snap in $SNAPSHOTS; do
        echo "  Deleting snapshot: $snap"
        aws ec2 delete-snapshot --snapshot-id $snap 2>/dev/null || true
    done
else
    echo "  No forensic snapshots found"
fi

# Step 5: Clean up quarantined instances
echo -e "${GREEN}[5/8] Checking for quarantined instances...${NC}"
QUARANTINED=$(aws ec2 describe-instances \
    --filters "Name=tag:SecurityStatus,Values=QUARANTINED" \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text 2>/dev/null || echo "")

if [ -n "$QUARANTINED" ]; then
    echo -e "${YELLOW}  Found quarantined instances: $QUARANTINED${NC}"
    echo "  Please manually restore or terminate these instances"
else
    echo "  No quarantined instances found"
fi

# Step 6: Terraform destroy
echo -e "${GREEN}[6/8] Destroying Terraform infrastructure...${NC}"
cd "$PROJECT_DIR/terraform"
terraform destroy -auto-approve

# Step 7: Delete CloudWatch log groups
echo -e "${GREEN}[7/8] Deleting CloudWatch log groups...${NC}"
LOG_GROUPS=$(aws logs describe-log-groups \
    --log-group-name-prefix "/aws/lambda/guardduty-security" \
    --query 'logGroups[*].logGroupName' \
    --output text 2>/dev/null || echo "")

if [ -n "$LOG_GROUPS" ]; then
    for lg in $LOG_GROUPS; do
        echo "  Deleting log group: $lg"
        aws logs delete-log-group --log-group-name $lg 2>/dev/null || true
    done
else
    echo "  No log groups found"
fi

# Step 8: Clean up local files
echo -e "${GREEN}[8/8] Cleaning up local files...${NC}"
cd "$PROJECT_DIR/terraform"
rm -rf .terraform .terraform.lock.hcl 2>/dev/null || true
rm -f terraform.tfstate terraform.tfstate.backup *.tfplan 2>/dev/null || true
rm -f "$PROJECT_DIR/lambda/remediation_handler.zip" 2>/dev/null || true

echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Cleanup completed successfully!                               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"

# Verification
echo -e "\n${YELLOW}Verification:${NC}"
echo "  GuardDuty detectors: $(aws guardduty list-detectors --query 'DetectorIds' --output text 2>/dev/null || echo 'N/A')"
echo "  S3 buckets: $(aws s3 ls 2>/dev/null | grep -c 'guardduty-security' || echo '0') matching"
echo "  Lambda functions: $(aws lambda list-functions --query 'Functions[?contains(FunctionName, `guardduty-security`)].FunctionName' --output text 2>/dev/null || echo 'None')"

echo -e "\n${GREEN}Environment cleanup complete!${NC}"