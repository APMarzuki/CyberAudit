"""
Logging and Monitoring Audit Module for CyberAudit
Checks Windows event logging and audit policy settings
"""

import re
from src.utils.windows_commands import run_command


def check_logging_audit():
    """
    Audit Windows logging and monitoring settings
    Returns: dict with audit results
    """
    print("📊 Checking Logging & Monitoring...")

    results = {
        "check_name": "Logging & Monitoring",
        "risk_score": 0,
        "details": [],
        "recommendations": []
    }

    risk_factors = []

    try:
        # Check audit policy
        stdout, stderr, returncode = run_command("auditpol /get /category:*")

        if returncode == 0 and stdout:
            audit_status = parse_audit_policy(stdout)
            risk_factors.extend(evaluate_audit_policy(audit_status))

        # Check event log sizes
        stdout, stderr, returncode = run_command("wevtutil gl security")
        if returncode == 0 and stdout:
            log_config = parse_event_log_config(stdout)
            risk_factors.extend(evaluate_log_config(log_config))

    except Exception as e:
        risk_factors.append((f"Error checking logging settings: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 2
        results["details"] = ["Logging and monitoring settings are adequate"]

    # Add recommendations
    results["recommendations"] = [
        "Enable auditing for critical events (logon, object access, policy changes)",
        "Ensure event logs are large enough to retain 30+ days of data",
        "Regularly review security event logs",
        "Configure log retention policies"
    ]

    return results


def parse_audit_policy(output):
    """Parse auditpol command output"""
    policy = {}
    current_category = None

    for line in output.split('\n'):
        line = line.strip()
        if line and not line.startswith('---'):
            if ':' in line and not line.startswith('System'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    category = parts[0].strip()
                    setting = parts[1].strip()
                    policy[category] = setting

    return policy


def evaluate_audit_policy(policy):
    """Evaluate audit policy against best practices"""
    risk_factors = []

    critical_audits = {
        "Logon": "Should audit logon events",
        "Logoff": "Should audit logoff events",
        "Account Lockout": "Should audit account lockouts",
        "Other Logon/Logoff Events": "Should audit other logon events"
    }

    for audit, description in critical_audits.items():
        if audit in policy:
            if "No Auditing" in policy[audit]:
                risk_factors.append((f"Audit disabled: {description}", 6))
            elif "Success" in policy[audit]:
                risk_factors.append((f"✅ {description}: Enabled", 0))
        else:
            risk_factors.append((f"Audit not configured: {description}", 4))

    return risk_factors


def parse_event_log_config(output):
    """Parse event log configuration"""
    config = {}

    for line in output.split('\n'):
        if 'maxSize:' in line.lower():
            config['max_size'] = line.split(':')[1].strip()
        elif 'retention:' in line.lower():
            config['retention'] = line.split(':')[1].strip()

    return config


def evaluate_log_config(config):
    """Evaluate event log configuration"""
    risk_factors = []

    if 'max_size' in config:
        size_mb = extract_size_mb(config['max_size'])
        if size_mb < 100:  # Less than 100MB
            risk_factors.append((f"Security log size too small: {config['max_size']}", 4))
        else:
            risk_factors.append((f"✅ Security log size: {config['max_size']}", 0))

    if 'retention' in config and 'false' in config['retention'].lower():
        risk_factors.append(("Security log retention disabled - logs may be overwritten", 5))

    return risk_factors


def extract_size_mb(size_str):
    """Extract size in MB from string like '20971520' bytes"""
    try:
        if size_str.isdigit():
            bytes_size = int(size_str)
            return bytes_size / (1024 * 1024)  # Convert to MB
    except:
        pass
    return 0