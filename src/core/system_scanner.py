from src.audit_modules import firewall_check, user_audit, av_edr_check, update_check, startup_analysis, network_security
from src.audit_modules import browser_security
from src.audit_modules import password_policy
from src.audit_modules import logging_audit
from src.audit_modules import encryption_check
from src.audit_modules import usb_audit
from src.audit_modules import application_security
from src.audit_modules import windows_services  # NEW
from src.audit_modules import group_policy  # NEW
from src.audit_modules import network_discovery  # NEW
from src.audit_modules import windows_hardening  # NEW

class SystemScanner:
    def __init__(self):
        self.checks = [
            ("Firewall", firewall_check.check_firewall_status),
            ("Network Security", network_security.check_network_security),
            ("Browser Security", browser_security.check_browser_security),
            ("Password Policy", password_policy.check_password_policy),
            ("Logging & Monitoring", logging_audit.check_logging_audit),
            ("Encryption Status", encryption_check.check_encryption_status),
            ("USB Device Control", usb_audit.check_usb_control),
            ("Application Security", application_security.check_application_security),
            ("Windows Services", windows_services.check_windows_services),  # NEW
            ("Group Policy Compliance", group_policy.check_group_policy_compliance),  # NEW
            ("Network Device Discovery", network_discovery.check_network_discovery),  # NEW
            ("Windows Hardening", windows_hardening.check_windows_hardening),  # NEW
            ("Users & Groups", user_audit.audit_users_and_groups),
            ("Antivirus", av_edr_check.check_av_edr_status),
            ("Updates", update_check.check_system_updates),
            ("Startup", startup_analysis.analyze_startup_items)
        ]
        self.progress_callback = None

    def set_progress_callback(self, callback):
        """Set a callback function for progress updates"""
        self.progress_callback = callback

    def run_full_scan(self):
        """
        Execute all security checks with real-time results
        """
        if self.progress_callback:
            self.progress_callback("🚀 Starting CyberAudit Security Scan...", 0)

        scan_results = {
            "scan_timestamp": "",
            "overall_risk_score": 0,
            "checks": [],
            "summary": {}
        }

        total_risk = 0
        check_count = len(self.checks)

        for i, (check_name, check_function) in enumerate(self.checks):
            try:
                # Update progress
                progress = (i / check_count) * 0.8  # 80% for checks, 20% for reporting
                if self.progress_callback:
                    self.progress_callback(f"🔍 Checking {check_name}...", progress)

                # Run the check
                result = check_function()
                scan_results["checks"].append(result)
                total_risk += result.get("risk_score", 0)

                # Send real-time result to GUI
                if self.progress_callback:
                    risk_score = result.get("risk_score", 0)
                    details = result.get('details', [''])[0] if result.get('details') else 'Check completed'
                    self.progress_callback(f"RESULT:{check_name}:{risk_score}:{details}", progress)

            except Exception as e:
                print(f"❌ Error in {check_name}: {str(e)}")
                error_result = {
                    "check_name": check_name,
                    "risk_score": 5,
                    "details": [f"Error during check: {str(e)}"]
                }
                scan_results["checks"].append(error_result)
                total_risk += 5

        # Calculate overall risk (average)
        scan_results["overall_risk_score"] = total_risk / check_count if check_count > 0 else 0

        # Generate summary
        scan_results["summary"] = {
            "total_checks": check_count,
            "high_risk_checks": len([c for c in scan_results["checks"] if c.get("risk_score", 0) >= 7]),
            "medium_risk_checks": len([c for c in scan_results["checks"] if 4 <= c.get("risk_score", 0) < 7]),
            "low_risk_checks": len([c for c in scan_results["checks"] if c.get("risk_score", 0) < 4])
        }

        if self.progress_callback:
            self.progress_callback("📊 Generating reports...", 0.9)

        return scan_results