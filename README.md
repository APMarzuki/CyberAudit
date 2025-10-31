# 🛡️ CyberAudit - Endpoint Security Health Checker

A professional security auditing tool for Windows endpoints that performs comprehensive security health checks and generates detailed reports.

## ✨ Features

- **Firewall Status Check** - Verifies Windows Firewall configuration
- **🌐 Network Security Check** - Scans open ports, network shares, and remote desktop status
- **🌐 Browser Security Check** - **NEW!** Detects installed browsers, extensions, and security settings
- **Antivirus/EDR Detection** - Identifies running security software  
- **User & Group Audit** - Analyzes local user accounts and privileges
- **System Updates Check** - Reports on Windows Update status and patch level
- **Startup Program Analysis** - Detects suspicious auto-start applications
- **Multi-Format Reports** - Generates console, JSON, and HTML reports
- **Risk Scoring** - Provides actionable risk assessments (0-10 scale)

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run CyberAudit
python src/main.py