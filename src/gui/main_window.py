"""
Main GUI window for CyberAudit
"""
import tkinter as tk
import threading
import customtkinter as ctk
import sys
import os

# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.system_scanner import SystemScanner
from src.core.report_generator import ReportGenerator


class CyberAuditGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.scanner = SystemScanner()
        self.reporter = ReportGenerator()
        self.setup_window()
        self.create_widgets()

    def setup_window(self):
        self.root.title("CyberAudit v2.0.0 - Security Health Checker")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # Modern theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

    def create_widgets(self):
        # Create main frame
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        header = ctk.CTkLabel(main_frame,
                              text="🛡️ CyberAudit Security Scanner",
                              font=ctk.CTkFont(size=24, weight="bold"))
        header.pack(pady=20)

        # Scan button
        self.scan_button = ctk.CTkButton(main_frame,
                                         text="🚀 Start Security Scan",
                                         command=self.start_scan,
                                         height=50,
                                         font=ctk.CTkFont(size=16))
        self.scan_button.pack(pady=20)

        # Progress frame
        self.progress_frame = ctk.CTkFrame(main_frame)
        self.progress_frame.pack(fill="x", pady=20)

        # Progress label
        self.progress_label = ctk.CTkLabel(self.progress_frame,
                                           text="Ready to scan...",
                                           font=ctk.CTkFont(size=14))
        self.progress_label.pack(pady=10)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(fill="x", padx=20, pady=5)
        self.progress_bar.set(0)

        # Results area - Use regular tkinter Text widget for colors
        self.results_text = tk.Text(main_frame,
                                    height=20,
                                    bg="#2b2b2b",
                                    fg="white",
                                    font=("Consolas", 11),
                                    relief="flat")
        self.results_text.pack(fill="both", expand=True, pady=10)

        # Configure text colors
        self.results_text.tag_configure("high_risk", foreground="#ff4444")
        self.results_text.tag_configure("medium_risk", foreground="#ffaa00")
        self.results_text.tag_configure("low_risk", foreground="#44ff44")
        self.results_text.tag_configure("progress", foreground="#8888ff")

    def start_scan(self):
        """Start the security scan in a separate thread"""
        self.scan_button.configure(state="disabled", text="🔄 Scanning...")
        self.progress_bar.set(0)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Starting security scan...\n\n")

        # Run scan in separate thread to keep GUI responsive
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan(self):
        """Run the actual security scan"""
        try:
            # Set up progress callback
            self.scanner.set_progress_callback(self.on_scan_progress)

            # Don't show "Starting..." here - let the callback handle it
            self.root.after(0, self.update_progress, "Initializing scanner...", 0)

            # Run the full scan
            scan_results = self.scanner.run_full_scan()

            # Generate reports (don't show duplicate message)
            html_file = self.reporter.generate_html_report(scan_results)

            # Complete
            self.root.after(0, self.scan_complete, scan_results, html_file)

        except Exception as e:
            self.root.after(0, self.scan_error, str(e))

    def on_scan_progress(self, message, progress):
        """Callback for scan progress updates"""
        self.root.after(0, self.update_progress, message, progress)

    def update_progress(self, message, progress):
        """Update progress bar and display real-time results with true colors"""
        if message.startswith("RESULT:"):
            parts = message.split(":", 3)
            if len(parts) == 4:
                check_name = parts[1]
                risk_score = float(parts[2])
                detail = parts[3]

                # Determine color tag
                if risk_score >= 7:
                    emoji = "🔴"
                    color_tag = "high_risk"
                elif risk_score >= 4:
                    emoji = "🟡"
                    color_tag = "medium_risk"
                else:
                    emoji = "🟢"
                    color_tag = "low_risk"

                # Insert with color
                result_text = f"{emoji} {check_name}: {risk_score}/10 - {detail}\n"
                self.results_text.insert(tk.END, result_text, color_tag)

        else:
            self.progress_label.configure(text=message)
            self.progress_bar.set(progress)

            if not message.startswith("RESULT:") and message != "Initializing scanner...":
                self.results_text.insert(tk.END, f"• {message}\n", "progress")

        self.results_text.see(tk.END)

    def scan_complete(self, results, html_file):
        """Handle scan completion"""
        self.progress_label.configure(text="✅ Scan Complete!")
        self.progress_bar.set(1.0)
        self.scan_button.configure(state="normal", text="🚀 Start New Scan")

        # Display summary
        risk_score = results["overall_risk_score"]
        summary = results["summary"]

        self.results_text.insert(tk.END, f"\n{'='*50}\n")
        self.results_text.insert(tk.END, f"✅ SCAN COMPLETE!\n")
        self.results_text.insert(tk.END, f"📊 Overall Risk Score: {risk_score:.1f}/10\n")
        self.results_text.insert(tk.END, f"🔍 Checks Completed: {summary['total_checks']}\n")
        self.results_text.insert(tk.END, f"🔴 High Risk: {summary['high_risk_checks']}\n")
        self.results_text.insert(tk.END, f"🟡 Medium Risk: {summary['medium_risk_checks']}\n")
        self.results_text.insert(tk.END, f"🟢 Low Risk: {summary['low_risk_checks']}\n")
        self.results_text.insert(tk.END, f"📄 Report saved: {html_file}\n")

    def scan_error(self, error_message):
        """Handle scan errors"""
        self.progress_label.configure(text="❌ Scan Failed")
        self.progress_bar.set(0)
        self.scan_button.configure(state="normal", text="🚀 Start Security Scan")
        self.results_text.insert(tk.END, f"\n❌ ERROR: {error_message}\n")

    def run(self):
        self.root.mainloop()

def main():
    app = CyberAuditGUI()
    app.run()

if __name__ == "__main__":
    main()