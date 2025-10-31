import json
import os
from datetime import datetime
from src.utils.helpers import get_timestamp, risk_level


class ReportGenerator:
    """
    Generates security reports in various formats
    """

    def __init__(self, output_dir="outputs"):
        self.output_dir = output_dir
        self.timestamp = get_timestamp()

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_json_report(self, scan_results, filename=None):
        """
        Generate a JSON format security report
        """
        if not filename:
            filename = f"cyberaudit_report_{self.timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)

        # Add metadata to results
        report_data = {
            "metadata": {
                "tool": "CyberAudit",
                "version": "1.0",
                "scan_timestamp": self.timestamp,
                "overall_risk_level": risk_level(scan_results["overall_risk_score"])
            },
            "results": scan_results
        }

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return filepath
        except Exception as e:
            print(f"❌ Error generating JSON report: {str(e)}")
            return None

    def generate_console_report(self, scan_results):
        """
        Generate a colorful console report
        """
        print("\n" + "=" * 60)
        print("🛡️  CYBERAUDIT SECURITY REPORT")
        print("=" * 60)

        overall_risk = scan_results["overall_risk_score"]
        risk_lvl = risk_level(overall_risk)

        # Overall risk display
        risk_icon = "🔴" if risk_lvl == "HIGH" else "🟡" if risk_lvl == "MEDIUM" else "🟢"
        print(f"\n{risk_icon} OVERALL RISK: {risk_lvl} ({overall_risk:.1f}/10)")

        # Summary
        summary = scan_results["summary"]
        print(f"\n📊 SUMMARY:")
        print(f"   • Total Checks: {summary['total_checks']}")
        print(f"   • 🔴 High Risk: {summary['high_risk_checks']}")
        print(f"   • 🟡 Medium Risk: {summary['medium_risk_checks']}")
        print(f"   • 🟢 Low Risk: {summary['low_risk_checks']}")

        # Detailed results
        print(f"\n🔍 DETAILED FINDINGS:")
        print("-" * 40)

        for check in scan_results["checks"]:
            check_name = check.get("check_name", "Unknown Check")
            risk_score = check.get("risk_score", 0)
            details = check.get("details", [])

            # Risk indicator
            if risk_score >= 7:
                risk_indicator = "🔴"
            elif risk_score >= 4:
                risk_indicator = "🟡"
            else:
                risk_indicator = "🟢"

            print(f"\n{risk_indicator} {check_name} (Risk: {risk_score}/10)")

            # For high-risk checks, show ALL details without truncation
            if risk_score >= 5:
                for detail in details:
                    print(f"   {detail}")
            else:
                # For low-risk checks, show limited details
                for i, detail in enumerate(details):
                    if i < 8:  # Show first 8 details
                        print(f"   {detail}")
                    else:
                        remaining = len(details) - i
                        if remaining > 0:
                            print(f"   ... and {remaining} more items")
                        break

    def generate_html_report(self, scan_results, filename=None):
        """
        Generate a basic HTML report (simplified version)
        """
        if not filename:
            filename = f"cyberaudit_report_{self.timestamp}.html"

        filepath = os.path.join(self.output_dir, filename)

        # Simple HTML template
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CyberAudit Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .risk-high {{ color: #e74c3c; font-weight: bold; }}
                .risk-medium {{ color: #f39c12; font-weight: bold; }}
                .risk-low {{ color: #27ae60; font-weight: bold; }}
                .check {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ CyberAudit Security Report</h1>
                <p>Generated: {self.timestamp}</p>
                <p>Overall Risk: <span class="risk-{risk_level(scan_results['overall_risk_score']).lower()}">
                    {risk_level(scan_results['overall_risk_score'])} ({scan_results['overall_risk_score']:.1f}/10)
                </span></p>
            </div>

            <h2>Security Checks</h2>
        """

        for check in scan_results["checks"]:
            risk_class = f"risk-{risk_level(check.get('risk_score', 0)).lower()}"
            html_content += f"""
            <div class="check">
                <h3>{check.get('check_name', 'Unknown')} 
                    <span class="{risk_class}">(Risk: {check.get('risk_score', 0)}/10)</span>
                </h3>
                <ul>
            """

            for detail in check.get("details", []):
                html_content += f"<li>{detail}</li>"

            html_content += """
                </ul>
            </div>
            """

        html_content += """
        </body>
        </html>
        """

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return filepath
        except Exception as e:
            print(f"❌ Error generating HTML report: {str(e)}")
            return None