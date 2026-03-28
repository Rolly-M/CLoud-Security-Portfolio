#!/usr/bin/env python3
"""
Comprehensive GuardDuty Testing Tool

This tool provides automated testing for GuardDuty detection and
remediation capabilities. It generates findings, monitors responses,
and validates the auto-remediation pipeline.

Author: Cloud Security Portfolio
"""

import boto3
import json
import time
import argparse
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Finding types for testing
FINDING_TYPES = {
    'ec2_crypto': [
        'CryptoCurrency:EC2/BitcoinTool.B',
        'CryptoCurrency:EC2/BitcoinTool.B!DNS'
    ],
    'ec2_backdoor': [
        'Backdoor:EC2/C&CActivity.B',
        'Backdoor:EC2/C&CActivity.B!DNS',
        'Backdoor:EC2/DenialOfService.Tcp',
        'Backdoor:EC2/Spambot'
    ],
    'ec2_trojan': [
        'Trojan:EC2/BlackholeTraffic',
        'Trojan:EC2/DropPoint',
        'Trojan:EC2/BlackholeTraffic!DNS',
        'Trojan:EC2/DriveBySourceTraffic!DNS'
    ],
    'ec2_unauthorized': [
        'UnauthorizedAccess:EC2/SSHBruteForce',
        'UnauthorizedAccess:EC2/RDPBruteForce',
        'UnauthorizedAccess:EC2/TorClient',
        'UnauthorizedAccess:EC2/TorRelay'
    ],
    'iam_credential': [
        'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS',
        'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS',
        'CredentialAccess:IAMUser/AnomalousBehavior'
    ],
    'iam_persistence': [
        'Persistence:IAMUser/AnomalousBehavior',
        'PrivilegeEscalation:IAMUser/AnomalousBehavior'
    ],
    's3_exfiltration': [
        'Exfiltration:S3/MaliciousIPCaller',
        'Exfiltration:S3/ObjectRead.Unusual'
    ],
    's3_policy': [
        'Policy:S3/BucketBlockPublicAccessDisabled',
        'Policy:S3/BucketAnonymousAccessGranted',
        'Policy:S3/BucketPublicAccessGranted'
    ],
    'recon': [
        'Recon:EC2/PortProbeUnprotectedPort',
        'Recon:EC2/Portscan',
        'Recon:IAMUser/MaliciousIPCaller'
    ]
}


class GuardDutyTester:
    """GuardDuty testing and validation class."""
    
    def __init__(self, region: str = 'us-east-1'):
        """Initialize the tester with AWS clients."""
        self.region = region
        self.guardduty = boto3.client('guardduty', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.logs = boto3.client('logs', region_name=region)
        self.lambda_client = boto3.client('lambda', region_name=region)
        self.detector_id = self._get_detector_id()
        
    def _get_detector_id(self) -> str:
        """Get the GuardDuty detector ID."""
        try:
            response = self.guardduty.list_detectors()
            if response['DetectorIds']:
                return response['DetectorIds'][0]
            raise ValueError("No GuardDuty detector found")
        except ClientError as e:
            logger.error(f"Error getting detector ID: {e}")
            raise
    
    def generate_sample_findings(self, finding_types: List[str]) -> Dict:
        """
        Generate sample findings for testing.
        
        Args:
            finding_types: List of finding type strings
            
        Returns:
            Dict with generation results
        """
        logger.info(f"Generating {len(finding_types)} sample findings...")
        
        try:
            self.guardduty.create_sample_findings(
                DetectorId=self.detector_id,
                FindingTypes=finding_types
            )
            
            return {
                'status': 'success',
                'finding_types': finding_types,
                'timestamp': datetime.now().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error generating findings: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def generate_all_findings(self) -> Dict:
        """Generate all categories of sample findings."""
        all_types = []
        for category_types in FINDING_TYPES.values():
            all_types.extend(category_types)
        
        return self.generate_sample_findings(all_types)
    
    def generate_category_findings(self, category: str) -> Dict:
        """
        Generate findings for a specific category.
        
        Args:
            category: Finding category (e.g., 'ec2_crypto', 'iam_credential')
        """
        if category not in FINDING_TYPES:
            raise ValueError(f"Unknown category: {category}")
        
        return self.generate_sample_findings(FINDING_TYPES[category])
    
    def get_recent_findings(
        self, 
        max_results: int = 50,
        severity_min: float = 0,
        hours_back: int = 24
    ) -> List[Dict]:
        """
        Get recent GuardDuty findings.
        
        Args:
            max_results: Maximum findings to return
            severity_min: Minimum severity to filter
            hours_back: Look back this many hours
        """
        try:
            # Get finding IDs
            response = self.guardduty.list_findings(
                DetectorId=self.detector_id,
                MaxResults=max_results,
                FindingCriteria={
                    'Criterion': {
                        'severity': {
                            'Gte': severity_min
                        },
                        'updatedAt': {
                            'Gte': int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
                        }
                    }
                },
                SortCriteria={
                    'AttributeName': 'severity',
                    'OrderBy': 'DESC'
                }
            )
            
            if not response['FindingIds']:
                return []
            
            # Get finding details
            findings_response = self.guardduty.get_findings(
                DetectorId=self.detector_id,
                FindingIds=response['FindingIds']
            )
            
            return findings_response['Findings']
            
        except ClientError as e:
            logger.error(f"Error getting findings: {e}")
            return []
    
    def wait_for_findings(
        self,
        expected_types: List[str],
        timeout_minutes: int = 15,
        poll_interval: int = 30
    ) -> Dict:
        """
        Wait for specific finding types to appear.
        
        Args:
            expected_types: Finding types to wait for
            timeout_minutes: Maximum wait time
            poll_interval: Seconds between checks
        """
        logger.info(f"Waiting for findings (timeout: {timeout_minutes} minutes)...")
        
        start_time = datetime.now()
        timeout = timedelta(minutes=timeout_minutes)
        found_types = set()
        
        while datetime.now() - start_time < timeout:
            findings = self.get_recent_findings(hours_back=1)
            
            for finding in findings:
                finding_type = finding['Type']
                if finding_type in expected_types:
                    found_types.add(finding_type)
                    logger.info(f"  Found: {finding_type} (Severity: {finding['Severity']})")
            
            if found_types == set(expected_types):
                logger.info("All expected findings detected!")
                return {
                    'status': 'success',
                    'found_types': list(found_types),
                    'duration_seconds': (datetime.now() - start_time).seconds
                }
            
            remaining = set(expected_types) - found_types
            logger.info(f"  Still waiting for: {remaining}")
            time.sleep(poll_interval)
        
        return {
            'status': 'timeout',
            'found_types': list(found_types),
            'missing_types': list(set(expected_types) - found_types)
        }
    
    def verify_remediation(
        self,
        finding_id: str,
        expected_actions: List[str]
    ) -> Dict:
        """
        Verify that remediation actions were taken for a finding.
        
        Args:
            finding_id: GuardDuty finding ID
            expected_actions: Expected remediation action types
        """
        logger.info(f"Verifying remediation for finding: {finding_id}")
        
        # Check CloudWatch Logs for Lambda execution
        # This assumes the Lambda function name contains 'remediation'
        try:
            log_groups = self.logs.describe_log_groups(
                logGroupNamePrefix='/aws/lambda/'
            )
            
            for group in log_groups['logGroups']:
                if 'remediation' in group['logGroupName'].lower():
                    # Search for finding ID in logs
                    response = self.logs.filter_log_events(
                        logGroupName=group['logGroupName'],
                        filterPattern=finding_id,
                        startTime=int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)
                    )
                    
                    if response['events']:
                        logger.info(f"  Found {len(response['events'])} log events")
                        
                        # Parse log events to find actions
                        actions_found = []
                        for event in response['events']:
                            message = event['message']
                            for action in expected_actions:
                                if action in message:
                                    actions_found.append(action)
                        
                        return {
                            'status': 'verified',
                            'actions_found': list(set(actions_found)),
                            'log_events': len(response['events'])
                        }
            
            return {
                'status': 'not_found',
                'message': 'No remediation logs found'
            }
            
        except ClientError as e:
            logger.error(f"Error verifying remediation: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def run_full_test(self, category: str = 'ec2_crypto') -> Dict:
        """
        Run a full end-to-end test.
        
        Args:
            category: Finding category to test
        """
        logger.info("=" * 60)
        logger.info("Starting Full GuardDuty Test")
        logger.info("=" * 60)
        
        results = {
            'start_time': datetime.now().isoformat(),
            'category': category,
            'stages': {}
        }
        
        # Stage 1: Generate findings
        logger.info("\n📋 Stage 1: Generating sample findings...")
        gen_result = self.generate_category_findings(category)
        results['stages']['generation'] = gen_result
        
        if gen_result['status'] != 'success':
            logger.error("Finding generation failed!")
            return results
        
        # Stage 2: Wait for findings
        logger.info("\n🔍 Stage 2: Waiting for findings to appear...")
        wait_result = self.wait_for_findings(
            FINDING_TYPES[category],
            timeout_minutes=10
        )
        results['stages']['detection'] = wait_result
        
        if wait_result['status'] == 'timeout':
            logger.warning("Some findings did not appear within timeout")
        
        # Stage 3: Check recent findings
        logger.info("\n📊 Stage 3: Analyzing findings...")
        findings = self.get_recent_findings(severity_min=7, hours_back=1)
        
        high_severity_count = len([f for f in findings if f['Severity'] >= 7])
        results['stages']['analysis'] = {
            'total_findings': len(findings),
            'high_severity_findings': high_severity_count
        }
        
        # Stage 4: Verify remediation (if high severity findings exist)
        if findings:
            logger.info("\n🔧 Stage 4: Verifying remediation...")
            for finding in findings[:3]:  # Check first 3
                verify_result = self.verify_remediation(
                    finding['Id'],
                    ['ISOLATE_INSTANCE', 'CREATE_FORENSIC_SNAPSHOT']
                )
                results['stages'][f'remediation_{finding["Id"][:8]}'] = verify_result
        
        results['end_time'] = datetime.now().isoformat()
        
        # Print summary
        self._print_summary(results)
        
        return results
    
    def _print_summary(self, results: Dict) -> None:
        """Print test summary."""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Category: {results['category']}")
        print(f"Start: {results['start_time']}")
        print(f"End: {results.get('end_time', 'N/A')}")
        print("-" * 60)
        
        for stage, data in results['stages'].items():
            status = data.get('status', 'completed')
            emoji = "✅" if status in ['success', 'verified', 'completed'] else "⚠️"
            print(f"{emoji} {stage}: {status}")
        
        print("=" * 60)
    
    def archive_findings(self, finding_ids: Optional[List[str]] = None) -> Dict:
        """Archive findings (cleanup after testing)."""
        try:
            if not finding_ids:
                # Get all unarchived findings
                response = self.guardduty.list_findings(
                    DetectorId=self.detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'service.archived': {
                                'Eq': ['false']
                            }
                        }
                    }
                )
                finding_ids = response['FindingIds']
            
            if finding_ids:
                self.guardduty.archive_findings(
                    DetectorId=self.detector_id,
                    FindingIds=finding_ids
                )
                logger.info(f"Archived {len(finding_ids)} findings")
                return {'status': 'success', 'archived_count': len(finding_ids)}
            
            return {'status': 'success', 'archived_count': 0}
            
        except ClientError as e:
            logger.error(f"Error archiving findings: {e}")
            return {'status': 'error', 'error': str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="GuardDuty Testing Tool"
    )
    
    parser.add_argument(
        '--action',
        choices=['generate', 'list', 'test', 'archive', 'wait'],
        default='list',
        help='Action to perform'
    )
    
    parser.add_argument(
        '--category',
        choices=list(FINDING_TYPES.keys()) + ['all'],
        default='ec2_crypto',
        help='Finding category for generation'
    )
    
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region'
    )
    
    parser.add_argument(
        '--severity',
        type=float,
        default=0,
        help='Minimum severity for listing'
    )
    
    args = parser.parse_args()
    
    print("""
╔════════════════════════════════════════════════════════════════╗
║         GuardDuty Comprehensive Testing Tool                   ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    tester = GuardDutyTester(region=args.region)
    
    if args.action == 'generate':
        if args.category == 'all':
            result = tester.generate_all_findings()
        else:
            result = tester.generate_category_findings(args.category)
        print(json.dumps(result, indent=2))
        
    elif args.action == 'list':
        findings = tester.get_recent_findings(severity_min=args.severity)
        print(f"\nFound {len(findings)} findings:\n")
        for f in findings:
            severity_icon = "🔴" if f['Severity'] >= 7 else "🟡" if f['Severity'] >= 4 else "🟢"
            print(f"{severity_icon} [{f['Severity']:.1f}] {f['Type']}")
            print(f"   ID: {f['Id'][:20]}...")
            print(f"   Updated: {f['UpdatedAt']}")
            print()
            
    elif args.action == 'test':
        result = tester.run_full_test(args.category)
        print(json.dumps(result, indent=2, default=str))
        
    elif args.action == 'archive':
        result = tester.archive_findings()
        print(json.dumps(result, indent=2))
        
    elif args.action == 'wait':
        result = tester.wait_for_findings(FINDING_TYPES[args.category])
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()