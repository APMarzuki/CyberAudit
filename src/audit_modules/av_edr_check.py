import psutil
from src.utils import windows_commands


def check_av_edr_status():
    """
    Check Antivirus/EDR status and definitions
    Returns: dict with AV/EDR status information
    """
    print("🔍 Checking Antivirus/EDR status...")

    results = {
        "check_name": "Antivirus/EDR Status",
        "risk_score": 0,
        "av_installed": False,
        "av_running": False,
        "av_products": [],
        "details": []
    }

    # Common AV/EDR process names
    av_processes = {
        'msmpeng.exe': 'Windows Defender',
        'nod32krn.exe': 'ESET',
        'avp.exe': 'Kaspersky',
        'bdagent.exe': 'Bitdefender',
        'avguard.exe': 'Avira',
        'mcshield.exe': 'McAfee',
        'cyvera.exe': 'Palo Alto Cortex',
        'crowdstrike': 'CrowdStrike',
        'sentinel.exe': 'SentinelOne'
    }

    # Check running processes
    running_av = []
    for proc in psutil.process_iter(['name']):
        try:
            proc_name = proc.info['name'].lower()
            for av_proc, av_name in av_processes.items():
                if av_proc in proc_name:
                    running_av.append(av_name)
                    results["av_products"].append(av_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if running_av:
        results["av_installed"] = True
        results["av_running"] = True
        results["details"].append(f"✅ AV/EDR running: {', '.join(set(running_av))}")
    else:
        # Check Windows Defender via PowerShell
        command = 'powershell "Get-MpComputerStatus"'
        stdout, stderr, returncode = windows_commands.run_command(command)

        if "AntivirusEnabled" in stdout and "True" in stdout:
            results["av_installed"] = True
            results["av_running"] = True
            results["av_products"].append("Windows Defender")
            results["details"].append("✅ Windows Defender is running")
        else:
            results["risk_score"] = 8
            results["details"].append("❌ No active AV/EDR detected")

    return results