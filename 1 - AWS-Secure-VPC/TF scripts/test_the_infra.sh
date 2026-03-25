#!/bin/bash
# test_infrastructure.sh

echo "=========================================="
echo "Infrastructure Testing Script"
echo "=========================================="

# Get outputs
BASTION_IP=$(terraform output -raw bastion_public_ip)
PRIVATE_IP=$(terraform output -json private_instance_ips | jq -r '.[0]')
KEY_FILE="my-key-pair.pem"

echo ""
echo "Bastion IP: $BASTION_IP"
echo "Private IP: $PRIVATE_IP"
echo ""

# Test 1: Bastion SSH
echo "TEST 1: SSH to Bastion"
echo "----------------------"
ssh -i $KEY_FILE -o ConnectTimeout=10 -o StrictHostKeyChecking=no ec2-user@$BASTION_IP "echo 'Bastion SSH: SUCCESS'" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Bastion SSH: PASSED"
else
    echo "❌ Bastion SSH: FAILED"
fi

echo ""

# Test 2: Private Instance via Bastion
echo "TEST 2: SSH to Private Instance via Bastion"
echo "--------------------------------------------"
ssh -i $KEY_FILE -o ConnectTimeout=10 -o StrictHostKeyChecking=no -A ec2-user@$BASTION_IP \
    "ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ec2-user@$PRIVATE_IP 'echo \"Private Instance SSH: SUCCESS\"'" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Private Instance SSH: PASSED"
else
    echo "❌ Private Instance SSH: FAILED"
fi

echo ""

# Test 3: Web Server
echo "TEST 3: Web Server on Private Instance"
echo "---------------------------------------"
RESULT=$(ssh -i $KEY_FILE -o ConnectTimeout=10 -o StrictHostKeyChecking=no ec2-user@$BASTION_IP \
    "curl -s http://$PRIVATE_IP" 2>/dev/null | grep -c "Private Instance")
if [ "$RESULT" -gt 0 ]; then
    echo "✅ Web Server: PASSED"
else
    echo "❌ Web Server: FAILED"
fi

echo ""

# Test 4: NAT Gateway (Internet from Private)
echo "TEST 4: NAT Gateway (Internet Access)"
echo "--------------------------------------"
ssh -i $KEY_FILE -o ConnectTimeout=10 -o StrictHostKeyChecking=no -A ec2-user@$BASTION_IP \
    "ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ec2-user@$PRIVATE_IP 'ping -c 1 google.com > /dev/null 2>&1 && echo SUCCESS'" 2>/dev/null | grep -q "SUCCESS"
if [ $? -eq 0 ]; then
    echo "✅ NAT Gateway: PASSED"
else
    echo "❌ NAT Gateway: FAILED"
fi

echo ""

# Test 5: Check CloudWatch Alarms
echo "TEST 5: CloudWatch Alarms"
echo "-------------------------"
ALARM_COUNT=$(aws cloudwatch describe-alarms --alarm-name-prefix "production" --query 'length(MetricAlarms)' --output text 2>/dev/null)
if [ "$ALARM_COUNT" -gt 0 ]; then
    echo "✅ CloudWatch Alarms: PASSED ($ALARM_COUNT alarms configured)"
else
    echo "❌ CloudWatch Alarms: FAILED (no alarms found)"
fi

echo ""

# Test 6: Check VPC Flow Logs
echo "TEST 6: VPC Flow Logs"
echo "---------------------"
LOG_GROUP=$(aws logs describe-log-groups --log-group-name-prefix "/aws/vpc/production" --query 'logGroups[0].logGroupName' --output text 2>/dev/null)
if [ "$LOG_GROUP" != "None" ] && [ -n "$LOG_GROUP" ]; then
    echo "✅ VPC Flow Logs: PASSED ($LOG_GROUP)"
else
    echo "❌ VPC Flow Logs: FAILED (no log group found)"
fi

echo ""
echo "=========================================="
echo "Testing Complete!"
echo "=========================================="