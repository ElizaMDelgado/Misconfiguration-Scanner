# Misconfiguration-Scanner
A Python-based network scanning tool designed to detect common misconfigurations on small business networks.
It scans for open ports, insecure services, weak configurations, and generates CSV, JSON, TXT, and HTML reports.

# Features

- ✅ Network and port scanning using Nmap
- ✅ Risk evaluation for common insecure services
- ✅ Banner grabbing for HTTP/FTP/SSH services
- ✅ Color-coded terminal output
- ✅ CSV, TXT, JSON, and HTML report generation
- ✅ Command-line arguments for flexibility

# Installation
1. Install Python (3.10+ recommended)
2. Install Dependencies

- pip python-nmap
- pip rich
- pip jinja2

# Usage
```bash
python scanner.py
```

# Custom Network Range
```bash
python scanner.py --range 192.168.0.0/24
```

# Custom Port Range
```bash
python scanner.py --ports 1-500
```

# Save Only JSON Output
```bash
python scanner.py --format json
```

# Example Terminal Output

<img width="758" height="509" alt="scanner with arguments used message" src="https://github.com/user-attachments/assets/c8316954-be59-4823-b720-bdcb8c1d14e3" />


