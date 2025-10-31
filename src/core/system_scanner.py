from src.audit_modules import firewall_check, user_audit, av_edr_check, update_check, startup_analysis


class SystemScanner:
    """
    Main system scanner that coordinates all security checks
    """

    def __init__(self):
        self.checks = [
            ("Firewall", firewall_check.check_firewall_status),
            ("Users & Groups", user_audit.audit_users_and_groups),
            ("Antivirus", av_edr_check.check_av_edr_status),
            ("Updates", update_check.check_system_updates),
            ("Startup", startup_analysis.analyze_startup_items)
        ]

    def run_full_scan(self):
        """
        Execute all security checks
        Returns: dict with all scan results
        """
        print("🚀 Starting CyberAudit Security Scan...")
        print("=" * 50)

        scan_results = {
            "scan_timestamp": "",
            "overall_risk_score": 0,
            "checks": [],
            "summary": {}
        }

        total_risk = 0
        check_count = len(self.checks)

        for check_name, check_function in self.checks:
            try:
                result = check_function()
                scan_results["checks"].append(result)
                total_risk += result.get("risk_score", 0)
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

        print("=" * 50)
        print(f"✅ Scan completed! Overall Risk Score: {scan_results['overall_risk_score']:.1f}/10")

        return scan_results