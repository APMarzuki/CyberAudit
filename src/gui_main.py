"""
GUI entry point for CyberAudit
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gui.main_window import CyberAuditGUI

if __name__ == "__main__":
    app = CyberAuditGUI()
    app.run()