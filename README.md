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
- ✅ Web dashboard for visual report review

# Installation
1. Install Python (3.10+ recommended)
2. Download Nmap for Windows:
   Go to the official site: https://nmap.org/download.html

    Click on "Latest stable release self-installer" (e.g., nmap-7.94-setup.exe)

    **Install Nmap:**

   Run the installer.
   During installation, make sure the checkbox "Add Nmap to the system PATH" is checked.

   Verify Nmap Installation:

   Open a new PowerShell or Command Prompt window.

Run:
   ```bash
   nmap --version
   ```
  You should see output like:
  ```bash
   Nmap version 7.94 ( https://nmap.org )
  ```

4. Install Dependencies

```bash
pip install python-nmap rich jinja2 flask requests
```

- pip python-nmap
- pip rich
- pip jinja2
- pip requests

# How to Run the Scanner & Dashboard
1. Run the Scanner
   
```bash
python scanner.py
```
Customize with:
- No-banner to skip banner grabbing (faster)
- Format json to choose output format (json, csv, all)
- Output-dir results to change the output folder
The scan results will be saved in the output/ directory.

 2. Launch the Dashboard
After scanning, start the dashboard:

```bash
python dashboard.py
```
Then open your browser and visit:
http://127.0.0.1:5000

There, you can:

- View scan reports and risk summaries
- Switch between saved scan files
- Download results
- Explore visual risk charts




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


 # Example Web Dashboard
 <img width="1237" height="383" alt="Web Dashboard with added buttons " src="https://github.com/user-attachments/assets/d73ef6c8-11f3-45e2-acbf-a05815053180" />



