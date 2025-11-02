"""
Group Policy Compliance Audit Module for CyberAudit
Checks Windows Group Policy settings for security compliance
"""

import re
from src.utils.windows_commands import run_command


def check_group_policy_compliance():
    """
    Audit Group Policy settings for security compliance
    Returns: dict with audit results
    """
    print("🔍 Checking Group Policy Compliance...")

    results = {
        "check_name": "Group Policy Compliance",
        "risk_score": 0,
        "details": [],
        "recommendations": [
            "Implement password complexity requirements",
            "Enable account lockout policies",
            "Configure audit policies for security events",
            "Set user rights assignment appropriately"
        ]
    }

    risk_factors = []

    try:
        # Check various Group Policy settings
        risk_factors.extend(check_account_policies())
        risk_factors.extend(check_audit_policies())
        risk_factors.extend(check_security_options())
        risk_factors.extend(check_user_rights())

    except Exception as e:
        risk_factors.append((f"Error during Group Policy audit: {str(e)}", 5))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 2
        results["details"] = ["✅ Group Policy settings meet basic security requirements"]

    return results


def check_account_policies():
    """
    Check account policy settings
    """
    risk_factors = []

    try:
        # Check password policy via secedit
        stdout, stderr, returncode = run_command('secedit /export /cfg temp_secedit.txt /areas SECURITYPOLICY')

        if returncode == 0:
            with open('temp_secedit.txt', 'r') as f:
                content = f.read()

            # Check for password complexity
            if "PasswordComplexity = 1" not in content:
                risk_factors.append(("❌ Password complexity not required", 6))

            # Check minimum password length
            min_length_match = re.search(r'MinimumPasswordLength = (\d+)', content)
            if min_length_match:
                min_length = int(min_length_match.group(1))
                if min_length < 8:
                    risk_factors.append((f"❌ Minimum password length too short ({min_length} characters)", 5))
            else:
                risk_factors.append(("❌ Minimum password length not configured", 5))

            # Clean up
            import os
            if os.path.exists('temp_secedit.txt'):
                os.remove('temp_secedit.txt')

    except Exception as e:
        risk_factors.append((f"Could not check account policies: {str(e)}", 4))

    return risk_factors


def check_audit_policies():
    """
    Check audit policy settings
    """
    risk_factors = []

    try:
        # Check audit policy via auditpol
        stdout, stderr, returncode = run_command('auditpol /get /category:*')

        if returncode == 0:
            # Check if auditing is enabled for critical events
            if "No Auditing" in stdout and stdout.count("No Auditing") > 5:
                risk_factors.append(("⚠️ Limited auditing configured for security events", 4))
            elif "Success and Failure" not in stdout:
                risk_factors.append(("ℹ️ Consider enabling success/failure auditing for key events", 3))

    except Exception as e:
        risk_factors.append((f"Could not check audit policies: {str(e)}", 3))

    return risk_factors


def check_security_options():
    """
    Check security options settings
    """
    risk_factors = []

    try:
        # Check specific security settings via registry
        checks = [
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "1",
             "User Account Control disabled", 7),
            (r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters", "restrictnullsessaccess", "1",
             "Null session access not restricted", 6),
        ]

        for key, value, expected, message, risk in checks:
            stdout, stderr, returncode = run_command(f'reg query "{key}" /v {value}')
            if returncode == 0 and expected not in stdout:
                risk_factors.append((f"❌ {message}", risk))

    except Exception as e:
        risk_factors.append((f"Could not check security options: {str(e)}", 3))

    return risk_factors


def check_user_rights():
    """
    Check user rights assignment
    """
    risk_factors = []

    try:
        # Check for "Everyone" in sensitive privileges
        stdout, stderr, returncode = run_command('secedit /export /cfg temp_rights.txt /areas USER_RIGHTS')

        if returncode == 0:
            with open('temp_rights.txt', 'r') as f:
                content = f.read()

            # Check for overly permissive assignments
            if "Everyone" in content and content.count("Everyone") > 2:
                risk_factors.append(("⚠️ 'Everyone' group has excessive privileges", 5))

            # Clean up
            import os
            if os.path.exists('temp_rights.txt'):
                os.remove('temp_rights.txt')

    except Exception as e:
        risk_factors.append((f"Could not check user rights: {str(e)}", 3))

    return risk_factors