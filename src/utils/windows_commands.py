import subprocess
import re


def run_command(command):
    """
    Execute a Windows command and return the output
    """
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True,
                              encoding='utf-8', errors='ignore', timeout=30)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1


def parse_wmic_output(output):
    """
    Parse WMIC command output into a structured format
    """
    lines = output.strip().split('\n')
    if len(lines) < 2:
        return []

    # Extract headers from first line
    headers = [h.strip() for h in lines[0].split() if h.strip()]
    data = []

    for line in lines[1:]:
        if line.strip():
            values = line.split(None, len(headers) - 1)
            if len(values) == len(headers):
                data.append(dict(zip(headers, values)))

    return data