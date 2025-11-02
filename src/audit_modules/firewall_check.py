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
        "risk_score": 0,
        "details": [],
        "recommendations": [
            "Ensure Windows Firewall is enabled for all network profiles",
            "Configure firewall rules to block unnecessary inbound connections"
        ]
    }

    if returncode == 0 and stdout:
        # Parse the output safely
        profiles = {
            "Domain Profile": "Unknown",
            "Private Profile": "Unknown",
            "Public Profile": "Unknown"
        }

        current_profile = None

        for line in stdout.split('\n'):
            line = line.strip()

            # Look for profile headers
            if "Profile Settings:" in line:
                current_profile = line.split("Profile Settings:")[1].strip()
            elif "State" in line and current_profile and current_profile in profiles:
                # Extract state value safely
                if "ON" in line.upper():
                    profiles[current_profile] = "ON"
                elif "OFF" in line.upper():
                    profiles[current_profile] = "OFF"

        # Evaluate results
        risk_factors = []
        for profile_name, state in profiles.items():
            if state == "OFF":
                risk_factors.append((f"❌ {profile_name}: Firewall is OFF", 3))
                results["details"].append(f"❌ {profile_name}: Firewall is OFF")
            elif state == "ON":
                results["details"].append(f"✅ {profile_name}: Firewall is ON")
            else:
                risk_factors.append((f"⚠️ {profile_name}: Status unknown", 2))
                results["details"].append(f"⚠️ {profile_name}: Status unknown")

        # Calculate risk score
        if risk_factors:
            results["risk_score"] = min(10, sum(risk for _, risk in risk_factors))
        else:
            results["risk_score"] = 0

    else:
        results["risk_score"] = 8
        results["details"].append("❌ Unable to check firewall status - command failed")

    return results