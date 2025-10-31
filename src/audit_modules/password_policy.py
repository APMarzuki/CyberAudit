"""
Password Policy Audit Module for CyberAudit
Checks Windows password policy settings and compliance
"""

import re
from src.utils.windows_commands import run_command


def check_password_policy():
    """
    Audit Windows password policy settings
    Returns: dict with audit results
    """
    print("🔐 Checking Password Policy...")

    results = {
        "check_name": "Password Policy",
        "risk_score": 0,
        "details": [],
        "recommendations": []
    }

    risk_factors = []

    try:
        # Get password policy via net accounts
        stdout, stderr, returncode = run_command("net accounts")

        if returncode == 0 and stdout:
            policy = parse_net_accounts_output(stdout)
            risk_factors = evaluate_password_policy(policy)
        else:
            risk_factors.append(("Cannot retrieve password policy", 8))

    except Exception as e:
        risk_factors.append((f"Error checking password policy: {str(e)}", 8))

    # Calculate risk score
    if risk_factors:
        results["risk_score"] = min(10, sum(risk for _, risk in risk_factors) / len(risk_factors))
        results["details"] = [factor for factor, _ in risk_factors]
    else:
        results["risk_score"] = 2
        results["details"] = ["Password policy meets security standards"]

    # Add recommendations
    results["recommendations"] = generate_password_recommendations(risk_factors)

    return results


def parse_net_accounts_output(output):
    """
    Parse net accounts command output into a dictionary
    """
    policy = {}

    lines = output.split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()

            if 'force user logoff' in key:
                policy['force_logoff'] = value
            elif 'minimum password age' in key:
                policy['min_password_age'] = value
            elif 'maximum password age' in key:
                policy['max_password_age'] = value
            elif 'minimum password length' in key:
                policy['min_password_length'] = value
            elif 'length of password history' in key:
                policy['password_history'] = value
            elif 'lockout threshold' in key:
                policy['lockout_threshold'] = value
            elif 'lockout duration' in key:
                policy['lockout_duration'] = value
            elif 'lockout observation window' in key:
                policy['lockout_window'] = value

    return policy


def evaluate_password_policy(policy):
    """
    Evaluate password policy against security best practices
    Returns: list of risk factors with scores
    """
    risk_factors = []

    # Check minimum password length
    min_length = extract_numeric_value(policy.get('min_password_length', ''))
    if min_length < 8:
        risk_factors.append((f"Minimum password length too short ({min_length} characters)", 7))
    elif min_length < 12:
        risk_factors.append((f"Consider increasing minimum password length to 12+ (currently {min_length})", 3))

    # Check maximum password age
    max_age = extract_numeric_value(policy.get('max_password_age', ''))
    if max_age == 0:
        risk_factors.append(("Passwords never expire - security risk", 6))
    elif max_age > 90:
        risk_factors.append((f"Password expiration too long ({max_age} days)", 4))
    elif max_age < 30:
        risk_factors.append((f"Password expiration too frequent ({max_age} days) may cause user fatigue", 2))

    # Check password history
    history = extract_numeric_value(policy.get('password_history', ''))
    if history < 5:
        risk_factors.append((f"Limited password history ({history} passwords remembered)", 4))

    # Check account lockout policy
    lockout_threshold = extract_numeric_value(policy.get('lockout_threshold', ''))
    if lockout_threshold == 0:
        risk_factors.append(("No account lockout policy configured", 8))
    elif lockout_threshold > 10:
        risk_factors.append((f"Account lockout threshold too high ({lockout_threshold} attempts)", 5))

    lockout_duration = extract_numeric_value(policy.get('lockout_duration', ''))
    if lockout_duration == 0:
        risk_factors.append(("Accounts unlock automatically - security risk", 6))

    # Check if any critical policies are missing
    if not policy:
        risk_factors.append(("Cannot determine password policy settings", 8))

    return risk_factors


def extract_numeric_value(text):
    """
    Extract numeric value from text like "7 days" or "14"
    """
    if not text:
        return 0

    # Look for numbers in the text
    numbers = re.findall(r'\d+', text)
    if numbers:
        return int(numbers[0])

    # Check for "never" or similar
    if 'never' in text.lower():
        return 0

    return 0


def generate_password_recommendations(risk_factors):
    """
    Generate specific recommendations based on findings
    """
    recommendations = [
        "Set minimum password length to at least 12 characters",
        "Configure password expiration between 60-90 days",
        "Enable account lockout after 5-10 failed attempts",
        "Maintain password history of at least 10 passwords",
        "Use password complexity requirements"
    ]

    # Add specific recommendations based on findings
    for factor, _ in risk_factors:
        if "length too short" in factor.lower():
            recommendations.append("CRITICAL: Increase minimum password length to 12+ characters immediately")
        if "never expire" in factor.lower():
            recommendations.append("CRITICAL: Configure password expiration policy")
        if "no account lockout" in factor.lower():
            recommendations.append("CRITICAL: Enable account lockout policy to prevent brute force attacks")

    return recommendations