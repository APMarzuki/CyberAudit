from src.utils import windows_commands


def check_firewall_status():
    """
    Check Windows Firewall status
    Returns: dict with firewall status information
    """
    print("🔍 Checking firewall status...")

    # Check firewall status using netsh
    command = "netsh advfirewall show allprofiles"
    stdout, stderr, returncode = windows_commands.run_command(command)

    results = {
        "check_name": "Firewall Status",
        "domain_profile": "Unknown",
        "private_profile": "Unknown",
        "public_profile": "Unknown",
        "risk_score": 0,
        "details": []
    }

    if returncode == 0:
        # Parse the output
        profiles = ["Domain Profile", "Private Profile", "Public Profile"]
        current_profile = None

        for line in stdout.split('\n'):
            line = line.strip()
            if "Profile Settings:" in line:
                current_profile = line.split(":")[0].strip()
            elif "State" in line and current_profile:
                state = line.split(":")[1].strip() if ":" in line else "Unknown"
                profile_key = current_profile.lower().replace(" ", "_") + "_profile"
                if profile_key in results:
                    results[profile_key] = state

                    # Calculate risk - firewall off is high risk
                    if state == "OFF":
                        results["risk_score"] += 3
                        results["details"].append(f"❌ {current_profile}: Firewall is OFF")
                    else:
                        results["details"].append(f"✅ {current_profile}: Firewall is ON")

    else:
        results["risk_score"] = 8
        results["details"].append("❌ Unable to check firewall status")

    return results