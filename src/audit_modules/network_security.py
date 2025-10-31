import socket
from src.utils import windows_commands


def check_network_security():
    """
    Check network-related security settings
    Returns: dict with network security findings
    """
    print("🔍 Checking network security...")

    results = {
        "check_name": "Network Security",
        "risk_score": 0,
        "details": []
    }

    # Check open ports (common security risk ports)
    risky_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389]
    open_ports = []

    try:
        # Check localhost for open ports
        for port in risky_ports[:5]:  # Check first 5 for speed
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                open_ports.append(port)
    except Exception as e:
        results["details"].append(f"⚠️  Could not check ports: {str(e)}")

    if open_ports:
        results["risk_score"] += len(open_ports)
        results["details"].append(f"🔴 Open risky ports detected: {', '.join(map(str, open_ports))}")
    else:
        results["details"].append("✅ No risky open ports found on localhost")

    # Check network shares with better error handling
    command = "net share"
    stdout, stderr, returncode = windows_commands.run_command(command)

    if returncode == 0 and stdout:
        try:
            shares = []
            for line in stdout.split('\n'):
                line = line.strip()
                # Skip header lines, separator lines, and footer
                if (line and
                        not line.startswith('Share name') and
                        not line.startswith('The command completed') and
                        not '---' in line and
                        len(line) > 3):  # Skip very short lines
                    # Extract the first word (share name)
                    parts = line.split()
                    if parts and not parts[0].startswith('---'):
                        shares.append(parts[0])

            if shares:
                results["risk_score"] += min(len(shares), 3)  # Cap at 3
                results["details"].append(f"🟡 Network shares found: {len(shares)}")
                for share in shares[:3]:  # Show first 3 shares
                    results["details"].append(f"   • {share}")

                if len(shares) > 3:
                    results["details"].append(f"   ... and {len(shares) - 3} more shares")
            else:
                results["details"].append("✅ No network shares found")
        except Exception as e:
            results["details"].append(f"⚠️  Could not parse network shares: {str(e)}")
    else:
        results["details"].append("⚠️  Could not check network shares")

    # Check remote desktop status
    command = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections"
    stdout, stderr, returncode = windows_commands.run_command(command)

    if returncode == 0 and stdout and "0x0" in stdout:
        results["risk_score"] += 2
        results["details"].append("🔴 Remote Desktop is enabled")
    else:
        results["details"].append("✅ Remote Desktop is disabled")

    # Check firewall profiles with better encoding handling
    command = "netsh advfirewall show allprofiles state"
    stdout, stderr, returncode = windows_commands.run_command(command)

    if returncode == 0 and stdout:
        if "ON" in stdout:
            results["details"].append("✅ Windows Firewall is active")
        else:
            results["risk_score"] += 3
            results["details"].append("🔴 Windows Firewall is not fully enabled")
    else:
        results["details"].append("⚠️  Could not check firewall status")

    # Cap risk score
    results["risk_score"] = min(results["risk_score"], 10)

    return results