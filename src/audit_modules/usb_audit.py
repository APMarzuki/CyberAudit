"""
USB Device Control Audit Module for CyberAudit
Checks removable storage policies and USB device restrictions
"""

import re
from src.utils.windows_commands import run_command


def check_usb_control():
    """
    Audit USB device control and removable storage policies
    Returns: dict with audit results
    """
    print("💾 Checking USB Device Control...")

    results = {
        "check_name": "USB Device Control",
        "risk_score": 0,
        "details": [],
        "recommendations": []
    }

    risk_factors = []

    try:
        # Check USB storage policies via registry and group policy
        # Method 1: Check registry for USB storage restrictions
        stdout, stderr, returncode = run_command(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start'
        )

        if returncode == 0 and stdout:
            usb_status = parse_usb_registry(stdout)
            risk_factors.extend(evaluate_usb_policy(usb_status))
        else:
            risk_factors.append(("Cannot determine USB storage policy", 4))

        # Method 2: Check device installation restrictions
        stdout, stderr, returncode = run_command(
            'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions" /s'
        )

        if returncode == 0 and stdout:
            install_restrictions = parse_install_restrictions(stdout)
            risk_factors.extend(evaluate_install_restrictions(install_restrictions))

    except Exception as e:
        risk_factors.append((f"Error checking USB controls: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 3
        results["details"] = ["USB device controls are moderately configured"]

    # Add recommendations
    results["recommendations"] = [
        "Consider implementing USB device control policies in enterprise environments",
        "Restrict unauthorized removable storage devices",
        "Enable device installation restrictions for untrusted devices",
        "Use application control to block unauthorized executables from USB devices"
    ]

    return results


def parse_usb_registry(output):
    """Parse USB storage registry settings"""
    usb_info = {}

    for line in output.split('\n'):
        if 'REG_DWORD' in line:
            parts = line.split()
            if len(parts) >= 3:
                usb_info['start_value'] = parts[-1]

    return usb_info


def evaluate_usb_policy(usb_info):
    """Evaluate USB storage policy"""
    risk_factors = []

    if 'start_value' in usb_info:
        start_val = usb_info['start_value']
        if start_val == '4':
            risk_factors.append(("USB storage is disabled", 2))  # Low risk - actually secure
        elif start_val == '3':
            risk_factors.append(("✅ USB storage is enabled with manual start", 1))
        else:
            risk_factors.append(("USB storage is fully enabled", 4))
    else:
        risk_factors.append(("USB storage policy not explicitly configured", 3))

    return risk_factors


def parse_install_restrictions(output):
    """Parse device installation restrictions"""
    restrictions = {}

    for line in output.split('\n'):
        if 'REG_DWORD' in line:
            if 'DenyDeviceIDs' in line:
                restrictions['deny_devices'] = True
            elif 'DenyAllDevices' in line:
                restrictions['deny_all'] = True

    return restrictions


def evaluate_install_restrictions(restrictions):
    """Evaluate device installation restrictions"""
    risk_factors = []

    if restrictions.get('deny_all'):
        risk_factors.append(("All device installations are denied", 1))  # Very restrictive
    elif restrictions.get('deny_devices'):
        risk_factors.append(("Specific device restrictions are configured", 2))
    else:
        risk_factors.append(("No device installation restrictions configured", 4))

    return risk_factors