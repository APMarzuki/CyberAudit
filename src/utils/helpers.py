import os
from datetime import datetime

def get_timestamp():
    """Get current timestamp for reports"""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def ensure_directory(directory_path):
    """Ensure a directory exists, create if it doesn't"""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

def risk_level(score, thresholds=(3, 7)):
    """
    Determine risk level based on score (0-10)
    Returns: "LOW", "MEDIUM", "HIGH"
    """
    if score <= thresholds[0]:
        return "LOW"
    elif score <= thresholds[1]:
        return "MEDIUM"
    else:
        return "HIGH"