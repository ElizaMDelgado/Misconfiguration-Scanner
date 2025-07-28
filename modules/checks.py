# modules/checks.py

PORT_RISKS = {
    21: ('FTP', 'High', 'Disable FTP or switch to SFTP'),
    23: ('Telnet', 'High', 'Disable Telnet; use SSH'),
    80: ('HTTP', 'Medium', 'Enable HTTPS'),
    443: ('HTTPS', 'Low', 'Secure'),
    22: ('SSH', 'Medium', 'Limit access with firewall or keys'),
    139: ('NetBIOS', 'High', 'Disable or segment SMB'),
    445: ('SMB', 'High', 'Disable or use modern authentication'),
    3389: ('RDP', 'High', 'Restrict RDP access and enable 2FA'),
    53: ('DNS', 'Medium', 'Secure DNS or use internal DNS server'),
    25: ('SMTP', 'Medium', 'Ensure authentication and TLS is used')
}

def evaluate_host(host_ip, open_ports):
    risks = []
    for port in open_ports:
        if port in PORT_RISKS:
            service, level, fix = PORT_RISKS[port]
            risks.append({
                'host': host_ip,
                'port': port,
                'service': service,
                'risk': level,
                'recommendation': fix
            })
    return risks
