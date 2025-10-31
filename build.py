import os
import subprocess
import sys


def build_executable():
    print("🔨 Building CyberAudit v1.2 Executable...")
    print("📦 Features included:")
    print("   • Firewall Status Check")
    print("   • Network Security Check")
    print("   • Browser Security Check")  # ADD THIS LINE
    print("   • User & Group Audit")
    print("   • Antivirus/EDR Detection")
    print("   • System Updates Check")
    print("   • Startup Programs Analysis")
    print()
    # ... rest of your build code

    try:
        # Run PyInstaller to create single executable
        subprocess.run([
            'pyinstaller',
            '--onefile',
            '--name=CyberAudit',
            '--hidden-import=psutil',
            '--clean',
            '--noconfirm',
            'src/main.py'
        ], check=True)

        print("✅ Build completed successfully!")
        print("📁 Your executable: dist/CyberAudit.exe")
        print("🚀 Run: dist/CyberAudit.exe")

    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    build_executable()