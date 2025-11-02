"""
GUI Main Entry Point for CyberAudit
"""
import sys
import os

# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.gui.main_window import CyberAuditGUI
except ImportError:
    # Alternative import path
    sys.path.append('.')
    from src.gui.main_window import CyberAuditGUI

def main():
    """Launch the CyberAudit GUI"""
    app = CyberAuditGUI()
    app.run()

if __name__ == "__main__":
    main()