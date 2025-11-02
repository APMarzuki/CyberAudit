🛡️ CyberAudit - Endpoint Security Health Checker
A professional security auditing tool for Windows endpoints that performs comprehensive security health checks and generates detailed reports.

## ✨ Features

- **🔒 Firewall Status Check** - Verifies Windows Firewall configuration
- **🌐 Network Security Audit** - Scans open ports, network shares, and remote desktop status  
- **🌍 Browser Security Analysis** - Detects installed browsers, extensions, and security settings
- **🔐 Password Policy Audit** - Checks Windows password complexity, expiration, and lockout policies
- **📊 Logging & Monitoring Audit** - Verifies event logging and audit policies
- **🔒 Encryption Status Check** - Checks BitLocker and device encryption status
- **💾 USB Device Control** - Audits removable storage policies and restrictions
- **🖥️ Application Security Audit** - **NEW v2.0!** Scans installed apps for vulnerabilities
- **⚙️ Windows Services Audit** - **NEW v2.0!** Checks service configurations and permissions  
- **📋 Group Policy Compliance** - **NEW v2.0!** Audits security policy settings
- **🌐 Network Device Discovery** - **NEW v2.0!** Discovers network devices and shares
- **🛡️ Windows Hardening Check** - **NEW v2.0!** Verifies OS security configurations
- **👥 User & Group Audit** - Analyzes local user accounts and privileges
- **🛡️ Antivirus/EDR Detection** - Identifies running security software
- **🔄 System Updates Check** - Reports on Windows Update status and patch level
- **🚀 Startup Program Analysis** - Detects suspicious auto-start applications

**16 Comprehensive Security Modules Total!**

### 🚀 Quick Start
Download `CyberAudit.exe` (v2.0.0) and run it directly - no installation required!

```bash
# Clone the repository
git clone https://github.com/APMarzuki/CyberAudit.git
cd CyberAudit

# Install dependencies
pip install -r requirements.txt

# Run CyberAudit Console
python main.py

# Run CyberAudit GUI  
python launch_gui.py

Portable Version
Download the latest CyberAudit.exe from Releases and run it directly - no Python installation required!

📋 Security Modules

|                     | Description                        | Risk Factors |
|Firewall Check issues| Windows Firewall status per profile|Disabled profiles, configuration |
|Network Security     | Port scanning, shares, RDP status  |Open shares, exposed services, weak protocols|
|Browser Security     | Browser versions, extensions, settings|Outdated browsers, weak security settings|
|Password Policy      |NEW! Password complexity & expiration|Short passwords, no lockout, weak history|
|Logging & Monitoring | Event logs and audit policies| Disabled auditing, small log sizes, no retention|
|Encryption Status    |BitLocker and device encryption | Unencrypted volumes, encryption gaps |
|USB Device Control    | Removable storage policies | Unrestricted USB access, no device controls |
|User Audit	          |Local accounts and privileges	|Blank passwords, guest access, admin rights|
|Antivirus/EDR	      |Security software status	|No AV detected, outdated definitions|
|System Updates	      |Windows Update status	|Missing updates, disabled service|
|Startup Analysis	  |Auto-start programs & processes	|Suspicious locations, high process count|

📊 Sample Output
🛡️  CyberAudit Security Report
==============================

🟢 OVERALL RISK: LOW (1.8/1

📊 SUMMARY:
• Total Checks: 11
• 🔴 High Risk: 0
• 🟡 Medium Risk: 6
• 🟢 Low Risk: 5

🔍 DETAILED FINDINGS:
🟡 Password Policy (Risk: 5.5/10)
   Minimum password length too short (0 characters)  

## 🎯 Version History

### v2.0.0 (Current) - Enterprise Security Suite
- ✅ **5 NEW MODULES**: Application Security, Windows Services, Group Policy, Network Discovery, Windows Hardening
- ✅ **16 comprehensive security modules** total
- ✅ Enhanced GUI with real-time progress tracking
- ✅ Improved import system and compatibility

### v1.5.0 - Enhanced Security Suite
- ✅ **3 NEW MODULES**: Logging & Monitoring, Encryption Status, USB Device Control
- ✅ **11 comprehensive security modules** total
- ✅ Professional GUI interface with real-time results
- ✅ Enhanced configuration system

### v1.4.0 - GUI Interface
- ✅ Professional desktop GUI application
- ✅ Real-time scanning progress with color-coded results
- ✅ Modern, user-friendly interface

### v1.3.0 - Password Policy Audit
- ✅ Added Password Policy security audit module
- ✅ Enhanced configuration system
- ✅ 8 comprehensive security modules

### v1.2.0 - Browser Security
- ✅ Added browser security analysis
- ✅ Extension detection and assessment
- ✅ Default browser security check

### v1.1.0 - Core Features
- ✅ Basic security modules (Firewall, AV, Users, Updates, Startup)
- ✅ Multi-format reporting (Console, JSON, HTML)
- ✅ Portable executable build

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

CyberAudit/
├── src/
│   ├── audit_modules/          # Security check modules
│   │   ├── firewall_check.py
│   │   ├── password_policy.py
│   │   ├── logging_audit.py
│   │   ├── encryption_check.py
│   │   ├── usb_audit.py
│   │   ├── application_security.py    # NEW v2.0!
│   │   ├── windows_services.py        # NEW v2.0!
│   │   ├── group_policy.py            # NEW v2.0!
│   │   ├── network_discovery.py       # NEW v2.0!
│   │   ├── windows_hardening.py       # NEW v2.0!
│   │   └── ...
│   ├── core/                   # Core system components
│   ├── gui/                    # NEW v1.4! GUI interface
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