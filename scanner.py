import nmap
import ipaddress
import re
from modules.checks import evaluate_host
from rich.console import Console
from rich.table import Table
from rich.progress import track, Progress, SpinnerColumn, TextColumn  # ✅ NEW
import csv, json, socket, os, requests
from datetime import datetime
import argparse
from jinja2 import Template
from remediation import get_recommendation, get_best_practice
from ftplib import FTP

console = Console(force_terminal=True)

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        if port == 80:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443:
            s.close()
            return "HTTPS Detected"
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "N/A"
    except:
        return "N/A"

def check_default_credentials(ip, port):
    if port == 21:
        try:
            ftp = FTP(ip, timeout=3)
            ftp.login('anonymous', 'anonymous@domain.com')
            ftp.quit()
            return "Anonymous FTP login allowed!"
        except:
            return None

    if port in [80, 443]:
        url = f"http://{ip}/" if port == 80 else f"https://{ip}/"
        common_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "1234"), ("admin", ""),
            ("root", "root"), ("root", "admin"), ("user", "user"), ("admin", "12345"),
            ("administrator", "admin"), ("support", "support"), ("guest", "guest")
        ]
        for user, pwd in common_creds:
            try:
                r = requests.get(url, auth=(user, pwd), timeout=3, verify=False)
                if r.status_code == 200:
                    return f"Web interface may allow default credentials ({user}:{pwd})"
            except:
                continue
    return None

def analyze_banner_for_vulnerabilities(banner):
    outdated_keywords = {
        "openssh_5.": "Outdated OpenSSH version – consider upgrading",
        "apache/2.2": "Apache 2.2 is outdated and unsupported",
        "vsftpd 2.3.4": "Vulnerable vsftpd version detected (backdoor vulnerability)",
    }
    findings = []
    banner_lower = banner.lower()
    for keyword, message in outdated_keywords.items():
        if keyword in banner_lower:
            findings.append(message)
    return findings

def enhance_findings(host, port, banner, base_risk):
    extra_findings = []
    default_cred_issue = check_default_credentials(host, port)
    if default_cred_issue:
        extra_findings.append(default_cred_issue)
    banner_issues = analyze_banner_for_vulnerabilities(banner)
    extra_findings.extend(banner_issues)
    new_risk = base_risk
    if extra_findings:
        new_risk = "High"
    return new_risk, extra_findings

def save_html_report(all_risks, output_dir):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    html_file = os.path.join(output_dir, f"scan_results_{timestamp}.html")

    high_count = sum(1 for r in all_risks if r["risk"] == "High")
    medium_count = sum(1 for r in all_risks if r["risk"] == "Medium")
    low_count = sum(1 for r in all_risks if r["risk"] == "Low")

    grouped = {}
    for r in all_risks:
        grouped.setdefault(r["host"], []).append(r)

    template = Template("""<html><head><title>Security Scan Report</title>
    <style>
    body{font-family:Arial;background:#f4f4f4;padding:20px;}
    h1,h2{text-align:center;}
    .summary{text-align:center;margin-bottom:20px;}
    .summary div{display:inline-block;margin:0 15px;padding:10px;border-radius:5px;}
    .high{background:#ffcccc;} .medium{background:#fff5cc;} .low{background:#ccffcc;}
    table{border-collapse:collapse;width:100%;background:white;margin-bottom:30px;}
    th,td{border:1px solid #ccc;padding:8px;text-align:center;}
    th{background:#333;color:white;}
    </style></head><body>
    <h1>Security Scan Report</h1>
    <div class="summary">
        <div class="high">High Risks: {{ high_count }}</div>
        <div class="medium">Medium Risks: {{ medium_count }}</div>
        <div class="low">Low Risks: {{ low_count }}</div>
    </div>
    {% for host, risks in grouped.items() %}
    <h2>Host: {{ host }}</h2>
    <table>
    <tr><th>Port</th><th>Service</th><th>Risk</th><th>Recommendation</th><th>Best Practice</th><th>Banner</th><th>Extra Findings</th></tr>
    {% for r in risks %}
    <tr class="{{ r.risk|lower }}">
        <td>{{ r.port }}</td>
        <td>{{ r.service }}</td>
        <td>{{ r.risk }}</td>
        <td>{{ r.recommendation }}</td>
        <td>{{ r.best_practice }}</td>
        <td>{{ r.banner }}</td>
        <td>{{ r.extra_findings|join(', ') }}</td>
    </tr>{% endfor %}
    </table>
    {% endfor %}
    </body></html>""")

    html_content = template.render(all_risks=all_risks, grouped=grouped,
                                   high_count=high_count,
                                   medium_count=medium_count,
                                   low_count=low_count)
    with open(html_file, "w") as f:
        f.write(html_content)
    console.print(f"[green]Improved HTML report saved as {html_file}[/green]")

def save_report(all_risks, formats, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    if "csv" in formats or "all" in formats:
        csv_file = os.path.join(output_dir, f"scan_results_{timestamp}.csv")
        with open(csv_file, mode="w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["host", "port", "service", "risk", "recommendation", "best_practice", "banner", "extra_findings"])
            writer.writeheader()
            for r in all_risks:
                r_copy = r.copy()
                r_copy["extra_findings"] = ", ".join(r_copy.get("extra_findings", []))
                writer.writerow(r_copy)
        console.print(f"[green]CSV report saved as {csv_file}[/green]")

    if "json" in formats or "all" in formats:
        json_file = os.path.join(output_dir, f"scan_results_{timestamp}.json")
        with open(json_file, "w") as f:
            json.dump(all_risks, f, indent=4)
        console.print(f"[green]JSON report saved as {json_file}[/green]")

        static_json_path = os.path.join(output_dir, "scan_results.json")
        with open(static_json_path, "w") as f:
            json.dump(all_risks, f, indent=4)
        console.print(f"[green]Dashboard data updated: {static_json_path}[/green]")

    save_html_report(all_risks, output_dir)

def scan_network(network_range, port_range, grab_banners, output_format, output_dir):
    console.print(f"[bold cyan]Starting scan...[/bold cyan]")

    # Input validation
    try:
        ipaddress.IPv4Network(network_range, strict=False)
    except ValueError:
        console.print(f"[bold red]Invalid network range: {network_range}[/bold red]")
        return

    port_range_pattern = re.compile(r"^(\d+)(-\d+)?$")
    if not all(port_range_pattern.match(p.strip()) for p in port_range.split(",")):
        console.print(f"[bold red]Invalid port range format: {port_range}[/bold red]")
        return

    scanner = nmap.PortScanner()

    # ✅ Spinner while Nmap runs
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        progress.add_task(description="Running Nmap scan...", total=None)
        try:
            scanner.scan(hosts=network_range, arguments=f"-p {port_range} --open")
        except Exception as e:
            console.print(f"[bold red]Nmap scan failed:[/bold red] {e}")
            return

    # ✅ Progress bar for host processing
    all_risks = []
    total_hosts = len(scanner.all_hosts())

    for host in track(scanner.all_hosts(), description=f"Analyzing {total_hosts} host(s)..."):
        if 'tcp' not in scanner[host]:
            continue
        open_ports = list(scanner[host]['tcp'].keys())
        risks = evaluate_host(host, open_ports)

        for r in risks:
            r["banner"] = grab_banner(host, r["port"]) if grab_banners else "N/A"
            new_risk, extra_findings = enhance_findings(host, r["port"], r["banner"], r["risk"])
            r["risk"] = new_risk
            r["extra_findings"] = extra_findings
            r["recommendation"] = get_recommendation(r["port"], r.get("recommendation", ""))
            r["best_practice"] = get_best_practice(r["risk"])
        all_risks.extend(risks)

    if all_risks:
        table = Table(title="Security Risks Summary", show_lines=True)
        table.add_column("Host", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("Service", style="green")
        table.add_column("Risk", style="bold")
        table.add_column("Extra Findings", style="yellow")
        table.add_column("Banner", style="dim")

        for r in all_risks:
            risk_color = "red" if r["risk"] == "High" else ("yellow" if r["risk"] == "Medium" else "green")
            table.add_row(
                r["host"], str(r["port"]), r["service"],
                f"[{risk_color}]{r['risk']}[/{risk_color}]",
                ", ".join(r.get("extra_findings", [])),
                r["banner"]
            )

        console.print(table)
    else:
        console.print("[bold green]No misconfigurations detected.[/bold green]")

    save_report(all_risks, output_format, output_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Misconfiguration Scanner")
    parser.add_argument("--range", default="192.168.1.0/24")
    parser.add_argument("--ports", default="1-1000")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--format", choices=["csv", "json", "txt", "all"], default="all")
    parser.add_argument("--output-dir", default="output")
    args = parser.parse_args()

    scan_network(args.range, args.ports, not args.no_banner, args.format, args.output_dir)
