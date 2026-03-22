#!/usr/bin/env python3
"""
collect_logs.py -- Log Collector Script for Nexus Audit Tool
===========================================================
Fetches log files from remote servers via SSH and saves them locally.

Usage:
    # With SSH key:
    python scripts/collect_logs.py --host example.com --user admin --key ~/.ssh/id_rsa --remote /var/log/auth.log --local sample_logs/remote_auth.log

    # With password:
    python scripts/collect_logs.py --host example.com --user admin --password mypass --remote /var/log/auth.log --local sample_logs/remote_auth.log

Dependencies: paramiko (added to requirements.txt)
"""

import argparse
import sys
from pathlib import Path

import paramiko


def collect_log(host, username, key_file, password, remote_path, local_path):
    """Fetch a log file via SSH and save locally."""
    try:
        # Create SSH client
        client = paramiko.SSHClient()  # Initialize SSH client
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto-accept host keys

        # Authenticate with key or password
        if key_file:  # Use SSH key if provided
            private_key = paramiko.RSAKey.from_private_key_file(key_file)  # Load private key
            client.connect(hostname=host, username=username, pkey=private_key)  # Connect with key
        elif password:  # Use password if provided
            client.connect(hostname=host, username=username, password=password)  # Connect with password
        else:
            raise ValueError("Either --key or --password must be provided")  # Require auth method

        # Run command to cat the remote log
        stdin, stdout, stderr = client.exec_command(f'cat {remote_path}')  # Execute cat command
        log_content = stdout.read().decode('utf-8')  # Read and decode output

        # Save to local file
        local_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure local directory exists
        with open(local_path, 'w', encoding='utf-8') as f:  # Open local file for writing
            f.write(log_content)  # Write log content

        print(f"Log collected from {host}:{remote_path} and saved to {local_path}")  # Success message
        client.close()  # Close SSH connection

    except Exception as e:
        print(f"Error collecting log: {e}", file=sys.stderr)  # Print error to stderr
        sys.exit(1)  # Exit with error code


def main():
    parser = argparse.ArgumentParser(description="Collect logs from remote servers via SSH.")  # Create argument parser
    parser.add_argument('--host', required=True, help='Remote server hostname or IP')  # Host argument
    parser.add_argument('--user', required=True, help='SSH username')  # Username argument
    parser.add_argument('--key', help='Path to private key file (e.g., ~/.ssh/id_rsa)')  # Key file argument
    parser.add_argument('--password', help='SSH password (alternative to key)')  # Password argument
    parser.add_argument('--remote', required=True, help='Remote log file path (e.g., /var/log/auth.log)')  # Remote path
    parser.add_argument('--local', required=True, help='Local save path (e.g., sample_logs/remote_auth.log)')  # Local path

    args = parser.parse_args()  # Parse command-line arguments

    if not args.key and not args.password:  # Ensure auth method is provided
        parser.error("Either --key or --password must be provided")

    # Convert paths
    key_file = Path(args.key).expanduser() if args.key else None  # Expand key path if provided
    local_path = Path(args.local)  # Convert local path to Path object

    collect_log(args.host, args.user, str(key_file) if key_file else None, args.password, args.remote, local_path)  # Call collect function


if __name__ == '__main__':
    main()