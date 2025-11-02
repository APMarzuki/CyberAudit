"""
Network Device Discovery Module for CyberAudit
Discovers network devices and checks for unauthorized equipment
"""

import socket
import subprocess
from src.utils.windows_commands import run_command


def check_network_discovery():
    """
    Discover network devices and check for security issues
    Returns: dict with audit results
    """
    print("🔍 Performing Network Device Discovery...")

    results = {
        "check_name": "Network Device Discovery",
        "risk_score": 0,
        "details": [],
        "recommendations": [
            "Implement network segmentation",
            "Monitor for unauthorized devices",
            "Use 802.1X for network access control",
            "Regularly scan for rogue devices"
        ]
    }

    risk_factors = []

    try:
        # Perform network discovery
        risk_factors.extend(discover_network_devices())
        risk_factors.extend(check_arp_table())
        risk_factors.extend(check_network_shares())

    except Exception as e:
        risk_factors.append((f"Error during network discovery: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 3
        results["details"] = ["✅ No obvious network security issues detected"]

    return results


def discover_network_devices():
    """
    Discover devices on the local network
    """
    risk_factors = []

    try:
        # Get local IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Extract subnet
        ip_parts = local_ip.split('.')
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

        risk_factors.append((f"📡 Local IP: {local_ip}, Scanning subnet: {subnet}.x", 0))

        # Quick ping sweep of common network addresses
        common_ips = [
            f"{subnet}.1",  # Typically gateway
            f"{subnet}.2", f"{subnet}.10", f"{subnet}.50",
            f"{subnet}.100", f"{subnet}.200", f"{subnet}.254"
        ]

        responsive_hosts = []
        for ip in common_ips:
            try:
                # Quick ping with timeout
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip],
                                        capture_output=True, text=True, timeout=2)
                if "Reply from" in result.stdout:
                    responsive_hosts.append(ip)
                    risk_factors.append((f"🌐 Network device found: {ip}", 2))
            except:
                pass

        if len(responsive_hosts) > 5:
            risk_factors.append((f"📊 Multiple network devices detected ({len(responsive_hosts)} responsive hosts)", 3))

    except Exception as e:
        risk_factors.append((f"Could not perform network discovery: {str(e)}", 3))

    return risk_factors


def check_arp_table():
    """
    Check ARP table for suspicious entries
    """
    risk_factors = []

    try:
        # Get ARP table
        stdout, stderr, returncode = run_command('arp -a')

        if returncode == 0:
            # Count dynamic entries
            dynamic_entries = stdout.count('dynamic')
            if dynamic_entries > 50:
                risk_factors.append((f"📈 High number of ARP entries ({dynamic_entries} devices)", 3))
            elif dynamic_entries > 20:
                risk_factors.append((f"📈 Moderate number of ARP entries ({dynamic_entries} devices)", 2))

            # Check for duplicate IP addresses (basic check)
            lines = stdout.split('\n')
            ip_counts = {}
            for line in lines:
                if 'dynamic' in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1

            duplicates = [ip for ip, count in ip_counts.items() if count > 1]
            if duplicates:
                risk_factors.append((f"🚨 Possible ARP spoofing - duplicate IPs detected", 7))

    except Exception as e:
        risk_factors.append((f"Could not check ARP table: {str(e)}", 3))

    return risk_factors


def check_network_shares():
    """
    Check for network shares and their permissions
    """
    risk_factors = []

    try:
        # Get network shares
        stdout, stderr, returncode = run_command('net share')

        if returncode == 0:
            shares = []
            lines = stdout.split('\n')
            for line in lines:
                if line.strip() and 'Share name' not in line and '---' not in line:
                    share_info = line.split()
                    if share_info:
                        shares.append(share_info[0])

            if shares:
                risk_factors.append((f"💼 Network shares found: {', '.join(shares)}", 3))

                # Check for administrative shares (should exist)
                admin_shares = ['ADMIN$', 'C$', 'IPC$']
                found_admin_shares = [share for share in shares if share in admin_shares]
                if not found_admin_shares:
                    risk_factors.append(("⚠️ Administrative shares are disabled", 2))

    except Exception as e:
        risk_factors.append((f"Could not check network shares: {str(e)}", 3))

    return risk_factors