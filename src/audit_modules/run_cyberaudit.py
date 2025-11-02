import sys
import os

# Add current directory to path
sys.path.append('.')


def main():
    print("🛡️  CyberAudit v2.0 - Security Scanner")
    print("=" * 50)

    try:
        from src.core.system_scanner import SystemScanner
        from src.core.report_generator import ReportGenerator

        scanner = SystemScanner()
        reporter = ReportGenerator()

        print(f"📊 Loaded {len(scanner.checks)} security modules")
        print("🚀 Starting comprehensive security scan...")

        results = scanner.run_full_scan()
        reporter.generate_console_report(results)

        print("✅ CyberAudit scan completed successfully!")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()