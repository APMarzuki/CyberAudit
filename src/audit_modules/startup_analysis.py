import psutil
from src.utils import windows_commands


def analyze_startup_items():
    """
    Production version - Real startup analysis with proper risk assessment
    """
    print("🔍 Analyzing startup items...")

    results = {
        "check_name": "Startup Programs",
        "risk_score": 0,
        "startup_count": 0,
        "suspicious_items": [],
        "details": []
    }

    # Analyze running processes
    try:
        processes = []
        for proc in psutil.process_iter(['name', 'exe', 'username']):
            try:
                processes.append({
                    'name': proc.info['name'],
                    'path': proc.info['exe'] or 'Unknown',
                    'user': proc.info['username'] or 'Unknown'
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        results["startup_count"] = len(processes)
        results["details"].append(f"🔄 {len(processes)} running processes")

    except Exception as e:
        results["details"].append(f"⚠️  Could not analyze processes: {str(e)}")
        processes = []

    # Check registry startup locations
    registry_locations = [
        (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "User Startup"),
        (r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "System Startup")
    ]

    total_registry_entries = 0
    all_registry_programs = []

    for location, description in registry_locations:
        command = f'reg query "{location}"'
        stdout, stderr, returncode = windows_commands.run_command(command)

        if returncode == 0:
            entries = [line.strip() for line in stdout.split('\n') if line.strip() and "REG_SZ" in line]
            total_registry_entries += len(entries)
            results["details"].append(f"📝 {description}: {len(entries)} entries")

            # Extract program names from registry entries
            for entry in entries:
                if "REG_SZ" in entry:
                    try:
                        # Extract program name and path
                        parts = entry.split("REG_SZ")
                        if len(parts) == 2:
                            program_name = parts[0].strip()
                            program_path = parts[1].strip().strip('"')
                            all_registry_programs.append({
                                'name': program_name,
                                'path': program_path,
                                'location': description
                            })
                    except:
                        continue
        else:
            results["details"].append(f"❌ Could not read {description}")

    # Analyze for suspicious items
    suspicious_patterns = [
        ('temp', 3, "Executable in temporary folder"),
        ('tmp', 3, "Executable in temporary folder"),
        ('appdata', 2, "Executable in AppData folder"),
        ('downloads', 2, "Executable in Downloads folder"),
        ('microsoftedge', 1, "Browser-related startup"),
        ('onenote', 1, "Office application startup")
    ]

    suspicious_count = 0

    # Check running processes
    for process in processes:
        if process['path'] and process['path'].lower() != 'unknown':
            path_lower = process['path'].lower()

            for pattern, risk_weight, reason in suspicious_patterns:
                if pattern in path_lower:
                    suspicious_item = {
                        'name': process['name'],
                        'path': process['path'],
                        'reason': reason,
                        'risk_weight': risk_weight,
                        'type': 'Running Process'
                    }
                    results["suspicious_items"].append(suspicious_item)
                    suspicious_count += risk_weight
                    break

    # Check registry startup programs
    for program in all_registry_programs:
        path_lower = program['path'].lower()

        for pattern, risk_weight, reason in suspicious_patterns:
            if pattern in path_lower:
                suspicious_item = {
                    'name': program['name'],
                    'path': program['path'],
                    'reason': f"{reason} (Startup)",
                    'risk_weight': risk_weight,
                    'type': 'Startup Entry'
                }
                results["suspicious_items"].append(suspicious_item)
                suspicious_count += risk_weight
                break

    # Calculate risk score - more realistic approach
    base_risk = 0

    # Risk from too many processes (capped at 2)
    if len(processes) > 350:
        base_risk += 2
        results["details"].append("⚠️  Very high number of running processes")
    elif len(processes) > 300:
        base_risk += 1
        results["details"].append("📊 High number of running processes")
    else:
        results["details"].append("✅ Normal number of running processes")

    # Risk from too many startup entries (capped at 1)
    if total_registry_entries > 15:
        base_risk += 1
        results["details"].append("⚠️  High number of startup entries")
    else:
        results["details"].append("✅ Normal number of startup entries")

    # Smart suspicious items risk - recognize legitimate applications
    legitimate_patterns = [
        'microsoft vs code', 'powertoys', 'grammarly', 'wondershare',
        'office', 'jetbrains', 'pycharm', 'github-copilot', 'microsoft office'
    ]

    high_risk_count = 0
    medium_risk_count = 0

    for item in results["suspicious_items"]:
        path_lower = item['path'].lower()

        # Check if this is a legitimate application
        is_legitimate = any(pattern in path_lower for pattern in legitimate_patterns)

        if "temp" in path_lower and not is_legitimate:
            high_risk_count += 1  # Temporary folders are higher risk
        elif not is_legitimate:
            medium_risk_count += 1  # Unknown items are medium risk

    # Calculate final risk - much more conservative
    suspicious_risk = min(high_risk_count * 2 + medium_risk_count * 0.5, 4)
    total_risk = min(base_risk + suspicious_risk, 10)
    results["risk_score"] = round(total_risk)

    # Update the risk calculation display
    if high_risk_count > 0 or medium_risk_count > 0:
        results["details"].append(
            f"📈 Risk: {results['risk_score']}/10 (Processes: {base_risk}, High-risk: {high_risk_count}, Medium-risk: {medium_risk_count})")
    else:
        results["details"].append(f"📈 Risk: {results['risk_score']}/10 (Mostly legitimate applications)")

    # REPORT FINDINGS
    if results["suspicious_items"]:
        # Remove duplicates first (we see multiple Code.exe entries)
        unique_items = {}
        for item in results["suspicious_items"]:
            key = f"{item['name']}|{item['path']}|{item['reason']}"
            if key not in unique_items:
                unique_items[key] = item

        unique_suspicious_items = list(unique_items.values())
        results["suspicious_items"] = unique_suspicious_items

        results["details"].append(f"🚨 Found {len(unique_suspicious_items)} potentially suspicious items:")

        # Show unique suspicious items in details for console display
        for item in unique_suspicious_items[:6]:  # Show first 6 unique items
            icon = "🔴" if "temporary folder" in item['reason'] else "🟡"
            results["details"].append(f"   {icon} {item['name']} - {item['reason']}")

        if len(unique_suspicious_items) > 6:
            results["details"].append(f"   ... and {len(unique_suspicious_items) - 6} more suspicious items")

        # Add summary of what was found
        temp_count = len([i for i in unique_suspicious_items if "temporary" in i['reason'].lower()])
        appdata_count = len([i for i in unique_suspicious_items if "appdata" in i['reason'].lower()])

        if temp_count > 0:
            results["details"].append(f"🔴 {temp_count} items running from temporary locations")
        if appdata_count > 0:
            results["details"].append(f"🟡 {appdata_count} items running from AppData folders")

    else:
        results["details"].append("✅ No obviously suspicious startup items found")

    return results