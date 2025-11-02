"""
Encryption Status Check Module for CyberAudit
Checks BitLocker and device encryption status
"""

import re
from src.utils.windows_commands import run_command


def check_encryption_status():
    """
    Check disk encryption status (BitLocker)
    Returns: dict with audit results
    """
    print("🔒 Checking Encryption Status...")

    results = {
        "check_name": "Encryption Status",
        "risk_score": 0,
        "details": [],
        "recommendations": []
    }

    risk_factors = []

    try:
        # Check BitLocker status using manage-bde
        stdout, stderr, returncode = run_command("manage-bde -status")

        if returncode == 0 and stdout:
            encryption_status = parse_bitlocker_status(stdout)
            risk_factors.extend(evaluate_encryption_status(encryption_status))
        else:
            # Try alternative command for devices without BitLocker
            stdout, stderr, returncode = run_command("powershell Get-BitLockerVolume -ErrorAction SilentlyContinue")
            if returncode == 0 and stdout:
                risk_factors.append(("BitLocker available but status unclear", 4))
            else:
                risk_factors.append(("Cannot determine encryption status", 6))

    except Exception as e:
        risk_factors.append((f"Error checking encryption: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 0
        results["details"] = ["Disk encryption is properly configured"]

    # Add recommendations
    results["recommendations"] = [
        "Enable BitLocker encryption on all fixed drives",
        "Encrypt removable drives containing sensitive data",
        "Ensure encryption keys are properly backed up",
        "Use TPM + PIN for enhanced security where supported"
    ]

    return results


def parse_bitlocker_status(output):
    """
    Parse manage-bde command output
    """
    status = {
        "volumes": [],
        "encryption_method": "Unknown",
        "protection_status": "Unknown"
    }

    current_volume = {}

    for line in output.split('\n'):
        line = line.strip()

        # Look for volume information
        if line.startswith('Volume'):
            if current_volume:  # Save previous volume
                status["volumes"].append(current_volume)
            current_volume = {"name": line}

        elif ':' in line and current_volume:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if 'Conversion Status' in key:
                current_volume['status'] = value
            elif 'Percentage Encrypted' in key:
                current_volume['percent'] = value
            elif 'Encryption Method' in key:
                current_volume['method'] = value
            elif 'Protection Status' in key:
                current_volume['protection'] = value

    # Don't forget the last volume
    if current_volume:
        status["volumes"].append(current_volume)

    return status


def evaluate_encryption_status(status):
    """
    Evaluate encryption status against security best practices
    """
    risk_factors = []

    if not status.get("volumes"):
        risk_factors.append(("No encrypted volumes detected", 8))
        return risk_factors

    encrypted_count = 0
    fully_encrypted_count = 0

    for volume in status["volumes"]:
        vol_name = volume.get('name', 'Unknown Volume')
        vol_status = volume.get('status', 'Unknown')

        if 'Fully Encrypted' in vol_status:
            fully_encrypted_count += 1
            risk_factors.append((f"✅ {vol_name}: Fully encrypted", 0))
        elif 'Encryption in Progress' in vol_status:
            encrypted_count += 1
            percent = volume.get('percent', 'Unknown')
            risk_factors.append((f"🟡 {vol_name}: Encryption in progress ({percent})", 3))
        elif 'Fully Decrypted' in vol_status:
            risk_factors.append((f"🔴 {vol_name}: Not encrypted", 8))
        else:
            risk_factors.append((f"⚠️ {vol_name}: Status unknown", 5))

    # Overall assessment
    total_volumes = len(status["volumes"])
    if fully_encrypted_count == 0:
        risk_factors.append(("No volumes are fully encrypted", 8))
    elif fully_encrypted_count < total_volumes:
        risk_factors.append((f"Only {fully_encrypted_count} of {total_volumes} volumes fully encrypted", 6))

    return risk_factors