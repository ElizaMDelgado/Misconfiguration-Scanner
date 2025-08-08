# remediation.py

REMEDIATION_GUIDE = {
    21: "Disable FTP or use SFTP (port 22) for secure file transfer.",
    22: "Use key-based SSH authentication and disable password logins.",
    23: "Disable Telnet; use SSH instead for secure remote access.",
    25: "Use secure email protocols like SMTPS; restrict open relays.",
    80: "Enable HTTPS with SSL/TLS certificates instead of HTTP.",
    110: "Use secure email retrieval (IMAPS/POP3S) instead of plain POP3.",
    139: "Restrict SMB access to trusted IPs; update SMB to the latest version.",
    445: "Disable SMBv1; restrict SMB shares and require authentication.",
    3389: "Restrict RDP to trusted IPs; enable Network Level Authentication.",
}

BEST_PRACTICES = {
    "High": "Immediately patch or disable the vulnerable service and restrict access.",
    "Medium": "Schedule updates, review user permissions, and restrict unnecessary access.",
    "Low": "Keep software updated and apply general security hardening best practices."
}

def get_recommendation(port, default_recommendation=""):
    """Return a remediation recommendation for a given port."""
    return REMEDIATION_GUIDE.get(port, default_recommendation)

def get_best_practice(risk_level):
    """Return best practice guidance based on risk level."""
    return BEST_PRACTICES.get(risk_level, "")
