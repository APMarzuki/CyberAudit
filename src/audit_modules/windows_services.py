"""
Windows Services Audit Module for CyberAudit
Checks Windows services for security misconfigurations and vulnerabilities
"""

import subprocess
import re
from src.utils.windows_commands import run_command


def check_windows_services():
    """
    Audit Windows services for security issues
    Returns: dict with audit results
    """
    print("🔍 Checking Windows Services Security...")

    results = {
        "check_name": "Windows Services",
        "risk_score": 0,
        "details": [],
        "recommendations": [
            "Disable unnecessary services",
            "Run services with least privilege accounts",
            "Regularly review service permissions",
            "Monitor for suspicious service installations"
        ]
    }

    risk_factors = []

    try:
        # Get all services information
        services = get_services_information()

        # Analyze services for security issues
        risk_factors.extend(check_dangerous_services(services))
        risk_factors.extend(check_service_permissions(services))
        risk_factors.extend(check_service_accounts(services))
        risk_factors.extend(check_vulnerable_service_versions())

    except Exception as e:
        risk_factors.append((f"Error during services audit: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 1
        results["details"] = ["✅ Windows services are properly configured"]

    return results


def get_services_information():
    """
    Retrieve detailed information about Windows services
    Returns: list of services with details
    """
    services = []

    try:
        # Get services using sc query
        stdout, stderr, returncode = run_command('sc query type= service state= all')

        if returncode == 0:
            service_blocks = stdout.split('SERVICE_NAME: ')

            for block in service_blocks[1:]:  # Skip first empty element
                service = {}
                lines = block.split('\n')

                # Extract service name from first line
                service['name'] = lines[0].strip()

                # Parse other service properties
                for line in lines:
                    if 'DISPLAY_NAME' in line:
                        service['display_name'] = line.split(':', 1)[1].strip()
                    elif 'STATE' in line and ':' in line:
                        service['state'] = line.split(':', 1)[1].strip()
                    elif 'TYPE' in line and ':' in line:
                        service['type'] = line.split(':', 1)[1].strip()

                services.append(service)

    except Exception as e:
        print(f"Warning: Could not get detailed service info: {e}")

    return services


def check_dangerous_services(services):
    """
    Check for known dangerous or unnecessary services
    """
    risk_factors = []

    # Services that should typically be disabled for security
    dangerous_services = {
        "Telnet": {"risk": 8, "reason": "Unencrypted remote access"},
        "FTPSVC": {"risk": 7, "reason": "FTP Server - unencrypted file transfer"},
        "SNMP": {"risk": 6, "reason": "Simple Network Management Protocol - information disclosure"},
        "RemoteRegistry": {"risk": 7, "reason": "Allows remote registry modification"},
        "SSDPSRV": {"risk": 5, "reason": "UPnP Discovery Service - network exposure"},
        "upnphost": {"risk": 5, "reason": "UPnP Device Host - network exposure"},
        "W3SVC": {"risk": 6, "reason": "IIS Web Server - if not needed"},
        "IISADMIN": {"risk": 6, "reason": "IIS Admin Service - if not needed"}
    }

    running_dangerous = []

    for service in services:
        service_name = service.get('name', '')
        service_state = service.get('state', '')

        for dangerous_name, details in dangerous_services.items():
            if dangerous_name.lower() in service_name.lower() and 'RUNNING' in service_state.upper():
                running_dangerous.append((dangerous_name, details["reason"], details["risk"]))

    # Only report if multiple dangerous services are running
    if len(running_dangerous) >= 2:
        for service_name, reason, risk in running_dangerous:
            risk_factors.append((f"⚠️ {service_name} service is running: {reason}", risk))
    elif running_dangerous:
        # Lower risk if only one dangerous service
        service_name, reason, risk = running_dangerous[0]
        risk_factors.append((f"ℹ️ {service_name} service is running: {reason}", risk - 2))

    return risk_factors


def check_service_permissions(services):
    """
    Check for services with weak permissions (basic implementation)
    """
    risk_factors = []

    try:
        # Check specific high-risk services for weak permissions
        high_risk_services = ["TermService", "Spooler", "Schedule", "LanmanServer"]

        for service_name in high_risk_services:
            # Use sc command to check service configuration
            stdout, stderr, returncode = run_command(f'sc qc {service_name}')

            if returncode == 0:
                # Check if service runs with SYSTEM privilege (could be abused)
                if 'LocalSystem' in stdout:
                    risk_factors.append((f"🔒 {service_name} runs with SYSTEM privileges", 4))

    except Exception as e:
        risk_factors.append((f"Could not check service permissions: {str(e)}", 3))

    return risk_factors


def check_service_accounts(services):
    """
    Check for services running with privileged accounts
    """
    risk_factors = []

    try:
        # Check if any services are running as LocalSystem (basic check)
        stdout, stderr, returncode = run_command('sc query type= service state= all')

        if returncode == 0:
            # Count services running as SYSTEM (approximate)
            system_services = stdout.count('LocalSystem')
            if system_services > 20:
                risk_factors.append((f"📊 {system_services} services running as LocalSystem - consider reducing", 3))

    except Exception as e:
        print(f"Warning: Could not check service accounts: {e}")

    return risk_factors


def check_vulnerable_service_versions():
    """
    Check for services with known vulnerabilities
    """
    risk_factors = []

    try:
        # Check SMBv1 (known vulnerability)
        stdout, stderr, returncode = run_command('Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol')
        if returncode == 0 and 'True' in stdout:
            risk_factors.append(("🚨 SMBv1 protocol enabled - critical vulnerability", 9))
        else:
            # Alternative check using registry
            stdout, stderr, returncode = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v SMB1')
            if returncode == 0 and '0x1' in stdout:
                risk_factors.append(("🚨 SMBv1 protocol enabled - critical vulnerability", 9))

    except Exception:
        # SMB check failed, try another approach
        try:
            stdout, stderr, returncode = run_command('sc qc LanmanServer')
            if returncode == 0 and 'RUNNING' in stdout:
                risk_factors.append(("ℹ️ SMB Server running - ensure SMBv1 is disabled", 4))
        except:
            pass

    return risk_factors