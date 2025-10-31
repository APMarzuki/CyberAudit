from src.utils import windows_commands


def audit_users_and_groups():
    """
    Audit local users and groups for security issues
    Returns: dict with user audit results
    """
    print("🔍 Auditing users and groups...")

    results = {
        "check_name": "User and Group Audit",
        "risk_score": 0,
        "admin_users": [],
        "inactive_users": [],
        "details": []
    }

    # Get local users
    command = "net user"
    stdout, stderr, returncode = windows_commands.run_command(command)

    if returncode == 0:
        users = []
        in_user_section = False

        for line in stdout.split('\n'):
            if "User accounts for" in line:
                in_user_section = True
                continue
            if in_user_section and line.strip() and "The command completed" not in line:
                # Extract usernames (they appear in a column format)
                users.extend([user.strip() for user in line.split() if user.strip()])

        # Remove duplicates and empty strings
        users = list(set([u for u in users if u and u not in ['User', 'accounts', 'for',
                                                              '-------------------------------------------------------------------------------']]))

        results["details"].append(f"📊 Found {len(users)} local user accounts")

        # Check for Administrator account status
        if "Administrator" in users:
            results["details"].append("⚠️  Default Administrator account is enabled")
            results["risk_score"] += 2

    else:
        results["details"].append("❌ Unable to enumerate users")
        results["risk_score"] += 5

    return results