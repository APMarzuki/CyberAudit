from src.utils import windows_commands


def check_system_updates():
    """
    Check Windows update status and last update time
    Returns: dict with update information
    """
    print("🔍 Checking system updates...")

    results = {
        "check_name": "System Updates",
        "risk_score": 0,
        "last_update": "Unknown",
        "update_status": "Unknown",
        "details": []
    }

    # Method 1: Check via systeminfo
    command = "systeminfo"
    stdout, stderr, returncode = windows_commands.run_command(command)

    if returncode == 0:
        for line in stdout.split('\n'):
            if "System Boot Time:" in line:
                try:
                    boot_time = line.split(":", 1)[1].strip()
                    results["details"].append(f"🖥️  System Boot Time: {boot_time}")
                except:
                    pass

    # Method 2: Check Windows Update service
    command = 'sc query wuauserv'
    stdout, stderr, returncode = windows_commands.run_command(command)

    if "RUNNING" in stdout:
        results["update_status"] = "Service Running"
        results["details"].append("✅ Windows Update service is running")
    else:
        results["update_status"] = "Service Not Running"
        results["risk_score"] += 3
        results["details"].append("⚠️  Windows Update service is not running")

    # Method 3: Check last hotfix (simplified)
    command = 'wmic qfe list brief'
    stdout, stderr, returncode = windows_commands.run_command(command)

    if returncode == 0:
        updates = [line for line in stdout.split('\n') if line.strip() and 'HotFixID' not in line]
        results["details"].append(f"📅 Last {len(updates)} updates installed")

        if len(updates) == 0:
            results["risk_score"] += 2
            results["details"].append("⚠️  No recent updates detected")
    else:
        results["details"].append("❌ Unable to check update history")

    return results