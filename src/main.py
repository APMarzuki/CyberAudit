import sys
import os

# Add the src directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.system_scanner import SystemScanner
from src.core.report_generator import ReportGenerator


def main():
    """
    Main entry point for CyberAudit
    """
    print("🛡️  Welcome to CyberAudit - Endpoint Security Health Checker")
    print("=" * 55)

    try:
        # Initialize components
        scanner = SystemScanner()
        reporter = ReportGenerator()

        # Run security scan
        scan_results = scanner.run_full_scan()

        # Generate reports
        print("\n📊 Generating reports...")

        # Console report
        reporter.generate_console_report(scan_results)

        # JSON report
        json_file = reporter.generate_json_report(scan_results)
        if json_file:
            print(f"\n💾 JSON report saved: {json_file}")

        # HTML report
        html_file = reporter.generate_html_report(scan_results)
        if html_file:
            print(f"💾 HTML report saved: {html_file}")

        # Final recommendations
        print("\n" + "=" * 55)
        print("💡 RECOMMENDATIONS:")

        overall_risk = scan_results["overall_risk_score"]
        if overall_risk >= 7:
            print("🔴 HIGH RISK: Immediate action required! Address critical security issues.")
        elif overall_risk >= 4:
            print("🟡 MEDIUM RISK: Review and address security findings promptly.")
        else:
            print("🟢 LOW RISK: Good security posture. Maintain current practices.")

        print("\n✅ CyberAudit scan completed successfully!")

    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Error during scan: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()