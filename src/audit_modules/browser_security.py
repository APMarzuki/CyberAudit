import os
import json
from src.utils import windows_commands


def check_browser_security():
    """
    Check browser-related security settings and extensions
    Returns: dict with browser security findings
    """
    print("🔍 Checking browser security...")

    results = {
        "check_name": "Browser Security",
        "risk_score": 0,
        "details": []
    }

    # Check common browser paths
    browsers = {
        "Chrome": os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data"),
        "Edge": os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data"),
        "Firefox": os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox")
    }

    installed_browsers = []

    for browser, path in browsers.items():
        if os.path.exists(path):
            installed_browsers.append(browser)

    if installed_browsers:
        results["details"].append(f"✅ Browsers detected: {', '.join(installed_browsers)}")
    else:
        results["details"].append("⚠️  No major browsers detected")
        return results

    # Check for common risky extensions patterns
    risky_extensions = [
        "password",
        "crypto",
        "mining",
        "unverified",
        "unknown"
    ]

    # Simple extension check (simplified for MVP)
    extension_count = 0
    if "Chrome" in installed_browsers or "Edge" in installed_browsers:
        try:
            # Check if browser extension folders exist
            chrome_ext_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions")
            if os.path.exists(chrome_ext_path):
                extensions = [d for d in os.listdir(chrome_ext_path) if os.path.isdir(os.path.join(chrome_ext_path, d))]
                extension_count = len(extensions)
        except:
            pass

    if extension_count > 0:
        results["details"].append(f"📊 Browser extensions found: {extension_count}")

        # Basic risk assessment based on extension count
        if extension_count > 20:
            results["risk_score"] += 3
            results["details"].append("🟡 High number of browser extensions")
        elif extension_count > 10:
            results["risk_score"] += 1
            results["details"].append("📊 Moderate number of browser extensions")
    else:
        results["details"].append("✅ No browser extensions detected")

    # Check default browser security settings via registry
    command = 'reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice" /v ProgId'
    stdout, stderr, returncode = windows_commands.run_command(command)

    if returncode == 0 and stdout:
        if "Chrome" in stdout or "Edge" in stdout:
            results["details"].append("✅ Modern secure browser set as default")
        else:
            results["details"].append("ℹ️  Check if using modern secure browser")

    # Security recommendations
    if results["risk_score"] > 0:
        results["details"].append("💡 Recommendation: Review browser extensions for security")

    return results