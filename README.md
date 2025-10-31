🛡️ CyberAudit - Endpoint Security Health Checker
A professional security auditing tool for Windows endpoints that performs comprehensive security health checks and generates detailed reports.

✨ Features
🔒 Firewall Status Check - Verifies Windows Firewall configuration across all profiles

🌐 Network Security Audit - Scans open ports, network shares, and remote desktop status

🌍 Browser Security Analysis - Detects installed browsers, extensions, and security settings

🔐 Password Policy Audit - NEW in v1.3! Checks Windows password complexity, expiration, and lockout policies

👥 User & Group Audit - Analyzes local user accounts, privileges, and security settings

🛡️ Antivirus/EDR Detection - Identifies running security software and protection status

🔄 System Updates Check - Reports on Windows Update status and patch level

🚀 Startup Program Analysis - Detects suspicious auto-start applications and running processes

📊 Multi-Format Reports - Generates console, JSON, and professional HTML reports

🎯 Risk Scoring System - Provides actionable risk assessments (0-10 scale) with recommendations

🚀 Quick Start
Installation
bash
# Clone the repository
git clone https://github.com/APMarzuki/CyberAudit.git
cd CyberAudit

# Install dependencies
pip install -r requirements.txt

# Run CyberAudit
python src/main.py

Portable Version
Download the latest CyberAudit.exe from Releases and run it directly - no Python installation required!

📋 Security Modules

|                     | Description                        | Risk Factors |
|Firewall Check issues| Windows Firewall status per profile|Disabled profiles, configuration |
|Network Security     | Port scanning, shares, RDP status  |Open shares, exposed services, weak protocols|
|Browser Security     | Browser versions, extensions, settings|Outdated browsers, weak security settings|
|Password Policy      |NEW! Password complexity & expiration|Short passwords, no lockout, weak history|
|User Audit	          |Local accounts and privileges	|Blank passwords, guest access, admin rights|
|Antivirus/EDR	      |Security software status	|No AV detected, outdated definitions|
|System Updates	      |Windows Update status	|Missing updates, disabled service|
|Startup Analysis	  |Auto-start programs & processes	|Suspicious locations, high process count|

📊 Sample Output
🛡️  CyberAudit Security Report
==============================

🟢 OVERALL RISK: LOW (1.8/1

📊 SUMMARY:
• Total Checks: 8
• 🔴 High Risk: 0
• 🟡 Medium Risk: 2
• 🟢 Low Risk: 6

🔍 DETAILED FINDINGS:
🟡 Password Policy (Risk: 5.5/10)
   Minimum password length too short (0 characters)  

🎯 Version History
v1.3.0 (Current) - Password Policy Audit
✅ New: Password Policy security audit module

✅ Enhanced configuration system

✅ Improved risk scoring accuracy

✅ 8 comprehensive security modules

v1.2.0 - Browser Security
✅ Added browser security analysis

✅ Extension detection and assessment

✅ Default browser security check

v1.1.0 - Core Features
✅ Basic security modules (Firewall, AV, Users, Updates, Startup)

✅ Multi-format reporting (Console, JSON, HTML)

✅ Portable executable build

🔧 Advanced Usage
Command Line Options
# Run specific security checks only
python src/main.py --modules firewall,av,updates

# Custom output directory
python src/main.py --output ./security_reports

# Generate specific report formats
python src/main.py --format html,json       

Configuration
Edit config/security_checks.json to customize:

Risk weight thresholds

Module enable/disable settings

Report generation options

📁 Project Structure
CyberAudit/
├── src/
│   ├── audit_modules/          # Security check modules
│   │   ├── firewall_check.py
│   │   ├── password_policy.py  # NEW v1.3!
│   │   └── ...
│   ├── core/                   # Core system components
│   └── utils/                  # Utility functions
├── outputs/                    # Generated reports
├── config/                     # Configuration files
└── dist/                       # Built executables 

🤝 Contributing
We welcome contributions! Feel free to:

Submit bug reports and feature requests

Add new security audit modules

Improve documentation

Enhance report formatting

⚠️ Disclaimer
CyberAudit is designed for security auditing and educational purposes. Always ensure you have proper authorization before conducting security scans on systems you don't own.