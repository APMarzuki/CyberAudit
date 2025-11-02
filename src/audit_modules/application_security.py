"""
Application Security Audit Module for CyberAudit
Checks installed applications for security vulnerabilities
"""

import os
import winreg
from src.utils.windows_commands import run_command


def check_application_security():
    """
    Audit installed applications for security issues
    Returns: dict with audit results
    """
    print("🔍 Checking Application Security...")

    results = {
        "check_name": "Application Security",
        "risk_score": 0,
        "details": [],
        "recommendations": [
            "Uninstall unnecessary applications",
            "Keep all software updated regularly",
            "Remove end-of-life software immediately",
            "Use application whitelisting where possible"
        ]
    }

    risk_factors = []

    try:
        # Get installed applications
        installed_apps = get_installed_applications()

        # Analyze for security issues
        risk_factors.extend(check_vulnerable_apps(installed_apps))
        risk_factors.extend(check_outdated_software(installed_apps))
        risk_factors.extend(check_suspicious_apps(installed_apps))
        risk_factors.extend(check_running_services())

    except Exception as e:
        risk_factors.append((f"Error during application audit: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 1
        results["details"] = ["✅ No significant application security issues found"]

    return results


def get_installed_applications():
    """
    Retrieve installed applications from Windows Registry
    Returns: list of installed applications with details
    """
    applications = []

    # Registry paths where installed applications are stored
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    ]

    for hive, path in registry_paths:
        try:
            key = winreg.OpenKey(hive, path)
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)

                    app_info = {}
                    try:
                        app_info['name'] = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                        app_info['version'] = winreg.QueryValueEx(subkey, 'DisplayVersion')[0] if winreg.QueryValueEx(subkey, 'DisplayVersion')[0] else "Unknown"
                        app_info['publisher'] = winreg.QueryValueEx(subkey, 'Publisher')[0] if winreg.QueryValueEx(subkey, 'Publisher')[0] else "Unknown"

                        # Only add if it has a name (some are system components)
                        if app_info['name'] and len(app_info['name']) > 1:
                            applications.append(app_info)

                    except (FileNotFoundError, OSError):
                        continue

                    winreg.CloseKey(subkey)

                except (OSError, WindowsError):
                    continue

            winreg.CloseKey(key)

        except (OSError, WindowsError):
            continue

    return applications


def check_vulnerable_apps(applications):
    """
    Check for known vulnerable or end-of-life software
    """
    risk_factors = []

    # Known vulnerable or EOL software patterns
    vulnerable_software = {
        "Java": {"versions": ["1.6", "1.7", "1.8"], "risk": 8},
        "Adobe Flash": {"risk": 9},  # All versions vulnerable
        "Internet Explorer": {"risk": 7},
        "QuickTime": {"risk": 8},
        "Windows Media Player": {"versions": ["12", "11"], "risk": 6}
    }

    for app in applications:
        app_name = app['name']
        app_version = app['version']

        for vuln_software, details in vulnerable_software.items():
            if vuln_software.lower() in app_name.lower():
                risk = details["risk"]

                # Check specific versions if specified
                if "versions" in details and any(ver in app_version for ver in details["versions"]):
                    risk_factors.append((f"❌ Vulnerable {vuln_software} {app_version} installed", risk))
                else:
                    risk_factors.append((f"⚠️ {vuln_software} installed - consider removal", risk - 2))

    return risk_factors


def check_outdated_software(applications):
    """
    Check for obviously outdated software versions
    """
    risk_factors = []

    # Common software that should be kept updated
    critical_software = ["Chrome", "Firefox", "Edge", "Adobe Reader", "Microsoft Office"]

    for app in applications:
        app_name = app['name']
        app_version = app['version']

        # Check for very old version numbers
        if any(software.lower() in app_name.lower() for software in critical_software):
            try:
                # Simple version age check (basic implementation)
                major_version = app_version.split('.')[0]
                if major_version.isdigit() and int(major_version) < 10:
                    risk_factors.append((f"🔄 {app_name} version {app_version} may be outdated", 4))
            except (ValueError, IndexError):
                pass

    return risk_factors


def check_suspicious_apps(applications):
    """
    Check for potentially unwanted or suspicious applications
    """
    risk_factors = []

    suspicious_keywords = [
        "crack", "keygen", "serial", "hack", "cheat", "loader",
        "torrent", "p2p", "unlocker", "password recovery"
    ]

    for app in applications:
        app_name_lower = app['name'].lower()

        for keyword in suspicious_keywords:
            if keyword in app_name_lower:
                risk_factors.append((f"🚨 Suspicious application: {app['name']}", 8))
                break

    return risk_factors


def check_running_services():
    """
    Check for risky running services
    """
    risk_factors = []

    # Check for risky services
    risky_services = [
        ("Telnet", "telnet", 7),
        ("FTP Server", "ftpd", 6),
        ("Remote Registry", "RemoteRegistry", 6),
        ("IIS Admin", "IISADMIN", 5)
    ]

    for service_name, service_keyword, risk in risky_services:
        stdout, stderr, returncode = run_command(f'sc query {service_keyword}')
        if returncode == 0 and "RUNNING" in stdout:
            risk_factors.append((f"⚠️ {service_name} service is running", risk))

    return risk_factors