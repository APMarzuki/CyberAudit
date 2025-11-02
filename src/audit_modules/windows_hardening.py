"""
Windows Hardening Check Module for CyberAudit
Checks Windows OS hardening and security configurations
"""

from src.utils.windows_commands import run_command


def check_windows_hardening():
    """
    Audit Windows OS hardening settings
    Returns: dict with audit results
    """
    print("🔍 Checking Windows Hardening...")

    results = {
        "check_name": "Windows Hardening",
        "risk_score": 0,
        "details": [],
        "recommendations": [
            "Enable Windows Defender real-time protection",
            "Configure BitLocker for all drives",
            "Disable unnecessary Windows features",
            "Enable Windows Security Center monitoring"
        ]
    }

    risk_factors = []

    try:
        # Check various Windows hardening settings
        risk_factors.extend(check_defender_status())
        risk_factors.extend(check_bitlocker_status())
        risk_factors.extend(check_windows_features())
        risk_factors.extend(check_uac_status())

    except Exception as e:
        risk_factors.append((f"Error during Windows hardening audit: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 1
        results["details"] = ["✅ Windows is properly hardened"]

    return results


def check_defender_status():
    """
    Check Windows Defender status
    """
    risk_factors = []

    try:
        # Check if Windows Defender is enabled
        stdout, stderr, returncode = run_command('powershell Get-MpComputerStatus')

        if returncode == 0:
            if "AntivirusEnabled" in stdout and "False" in stdout:
                risk_factors.append(("❌ Windows Defender antivirus is disabled", 8))
            if "RealTimeProtectionEnabled" in stdout and "False" in stdout:
                risk_factors.append(("⚠️ Windows Defender real-time protection is disabled", 6))
        else:
            # Alternative check using registry
            stdout, stderr, returncode = run_command('reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware')
            if returncode == 0 and '0x1' in stdout:
                risk_factors.append(("❌ Windows Defender is disabled by policy", 8))

    except Exception as e:
        risk_factors.append((f"Could not check Windows Defender status: {str(e)}", 4))

    return risk_factors


def check_bitlocker_status():
    """
    Check BitLocker encryption status
    """
    risk_factors = []

    try:
        # Check BitLocker status using manage-bde
        stdout, stderr, returncode = run_command('manage-bde -status C:')

        if returncode == 0:
            if "Conversion Status: Fully Encrypted" not in stdout:
                risk_factors.append(("⚠️ BitLocker not enabled on C: drive", 6))
            elif "Protection Off" in stdout:
                risk_factors.append(("⚠️ BitLocker protection suspended on C: drive", 7))
        else:
            # BitLocker not available or command failed
            risk_factors.append(("ℹ️ BitLocker not configured or not available", 4))

    except Exception as e:
        risk_factors.append((f"Could not check BitLocker status: {str(e)}", 3))

    return risk_factors


def check_windows_features():
    """
    Check for unnecessary Windows features
    """
    risk_factors = []

    try:
        # Check if SMBv1 is enabled
        stdout, stderr, returncode = run_command('powershell Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol')
        if returncode == 0 and "Enabled" in stdout:
            risk_factors.append(("🚨 SMBv1 protocol enabled - critical vulnerability", 9))

        # Check if Telnet client is installed
        stdout, stderr, returncode = run_command('dism /online /Get-Features | find "TelnetClient"')
        if returncode == 0 and "Enabled" in stdout:
            risk_factors.append(("⚠️ Telnet client feature enabled", 5))

    except Exception as e:
        risk_factors.append((f"Could not check Windows features: {str(e)}", 3))

    return risk_factors


def check_uac_status():
    """
    Check User Account Control settings
    """
    risk_factors = []

    try:
        # Check UAC level from registry
        stdout, stderr, returncode = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA')
        if returncode == 0 and '0x0' in stdout:
            risk_factors.append(("❌ User Account Control (UAC) is disabled", 7))

        # Check consent prompt behavior
        stdout, stderr, returncode = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin')
        if returncode == 0:
            if '0x0' in stdout:
                risk_factors.append(("❌ UAC admin prompt disabled - no consent required", 8))
            elif '0x2' not in stdout:  # 0x2 is default secure setting
                risk_factors.append(("⚠️ UAC not configured for secure admin approval", 5))

    except Exception as e:
        risk_factors.append((f"Could not check UAC status: {str(e)}", 3))

    return risk_factors