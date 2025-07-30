import nmap
from modules.checks import evaluate_host
from rich.console import Console
from rich.table import Table
import csv
import json
import socket
from datetime import datetime
import argparse
from jinja2 import Template
import os

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


def save_html_report(all_risks, output_dir):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    html_file = os.path.join(output_dir, f"scan_results_{timestamp}.html")

    high_count = sum(1 for r in all_risks if r["risk"] == "High")
    medium_count = sum(1 for r in all_risks if r["risk"] == "Medium")
    low_count = sum(1 for r in all_risks if r["risk"] == "Low")

    grouped = {}
    for r in all_risks:
        grouped.setdefault(r["host"], []).append(r)

    template = Template("""
    <html>
    <head>
        <title>Security Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
            h1, h2 { text-align: center; }
            .summary { margin-bottom: 20px; text-align: center; }
            .summary div { display: inline-block; margin: 0 15px; padding: 10px; border-radius: 5px; }
            .high { background: #ffcccc; }
            .medium { background: #fff5cc; }
            .low { background: #ccffcc; }
            table { border-collapse: collapse; width: 100%; background: white; margin-bottom: 30px; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: center; }
            th { background: #333; color: white; }
        </style>
    </head>
    <body>
        <h1>Security Scan Report</h1>

        <div class="summary">
            <div class="high">High Risks: {{ high_count }}</div>
            <div class="medium">Medium Risks: {{ medium_count }}</div>
            <div class="low">Low Risks: {{ low_count }}</div>
        </div>

        {% for host, risks in grouped.items() %}
        <h2>Host: {{ host }}</h2>
        <table>
            <tr>
                <th>Port</th><th>Service</th><th>Risk</th><th>Recommendation</th><th>Banner</th>
            </tr>
            {% for r in risks %}
            <tr class="{{ r.risk|lower }}">
                <td>{{ r.port }}</td>
                <td>{{ r.service }}</td>
                <td>{{ r.risk }}</td>
                <td>{{ r.recommendation }}</td>
                <td>{{ r.banner }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endfor %}
    </body>
    </html>
    """)

    html_content = template.render(
        all_risks=all_risks,
        grouped=grouped,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )

    with open(html_file, "w") as f:
        f.write(html_content)

    console.print(f"[green]Improved HTML report saved as {html_file}[/green]")


def save_report(all_risks, formats, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    if "csv" in formats or "all" in formats:
        csv_file = os.path.join(output_dir, f"scan_results_{timestamp}.csv")
        with open(csv_file, mode="w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["host", "port", "service", "risk", "recommendation", "banner"])
            writer.writeheader()
            writer.writerows(all_risks)
        console.print(f"[green]CSV report saved as {csv_file}[/green]")

    if "txt" in formats or "all" in formats:
        txt_file = os.path.join(output_dir, f"scan_results_{timestamp}.txt")
        with open(txt_file, mode="w") as f:
            f.write("Security Risks Report\n")
            f.write("=" * 50 + "\n")
            for r in all_risks:
                f.write(
                    f"Host: {r['host']}, Port: {r['port']}, Service: {r['service']}, "
                    f"Risk: {r['risk']}, Fix: {r['recommendation']}, Banner: {r['banner']}\n"
                )
        console.print(f"[green]TXT report saved as {txt_file}[/green]")

    if "json" in formats or "all" in formats:
        json_file = os.path.join(output_dir, f"scan_results_{timestamp}.json")
        with open(json_file, mode="w") as f:
            json.dump(all_risks, f, indent=4)
        console.print(f"[green]JSON report saved as {json_file}[/green]")

    save_html_report(all_risks, output_dir)


def scan_network(network_range, port_range, grab_banners, output_format, output_dir):
    console.print(
        f"[bold cyan]Starting scan with settings:[/bold cyan]\n"
        f"   • Network Range: [yellow]{network_range}[/yellow]\n"
        f"   • Port Range: [yellow]{port_range}[/yellow]\n"
        f"   • Banner Grabbing: [yellow]{'Enabled' if grab_banners else 'Disabled'}[/yellow]\n"
        f"   • Report Format: [yellow]{output_format} + HTML[/yellow]\n"
        f"   • Output Directory: [yellow]{output_dir}[/yellow]\n"
    )

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=network_range, arguments=f"-p {port_range} --open")
    except Exception as e:
        console.print(f"[bold red]Nmap scan failed:[/bold red] {e}")
        return

    active_hosts = scanner.all_hosts()
    console.print(f"[bold green]Active hosts found:[/bold green] {active_hosts}")

    all_risks = []
    for host in active_hosts:
        hostname = scanner[host].hostname()
        console.print(f"[bold cyan]Host:[/bold cyan] {host} ({hostname if hostname else 'Unknown'})")

        if 'tcp' in scanner[host]:
            open_ports = list(scanner[host]['tcp'].keys())
            risks = evaluate_host(host, open_ports)

            for r in risks:
                r["banner"] = grab_banner(host, r["port"]) if grab_banners else "N/A"

            all_risks.extend(risks)
        else:
            console.print("[yellow]  No open TCP ports found.[/yellow]")
        console.print("-" * 50)

    if all_risks:
        severity_order = {"High": 1, "Medium": 2, "Low": 3}
        all_risks.sort(key=lambda x: severity_order.get(x["risk"], 4))

        table = Table(title="Security Risks Summary", show_lines=True)
        table.add_column("Host", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("Service", style="green")
        table.add_column("Risk", style="bold")
        table.add_column("Recommendation", style="yellow")
        table.add_column("Banner", style="dim")

        for r in all_risks:
            risk_color = "red" if r["risk"] == "High" else ("yellow" if r["risk"] == "Medium" else "green")
            table.add_row(
                r["host"], str(r["port"]), r["service"],
                f"[{risk_color}]{r['risk']}[/{risk_color}]",
                r["recommendation"], r["banner"]
            )

        console.print(table)
        console.print(
            f"\n[bold red]High Risks:[/bold red] {sum(1 for r in all_risks if r['risk']=='High')}   "
            f"[bold yellow]Medium Risks:[/bold yellow] {sum(1 for r in all_risks if r['risk']=='Medium')}   "
            f"[bold green]Low Risks:[/bold green] {sum(1 for r in all_risks if r['risk']=='Low')}\n"
        )

        save_report(all_risks, output_format, output_dir)
    else:
        console.print("[bold green]No misconfigurations detected.[/bold green]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Misconfiguration Scanner for Small Business Devices")
    parser.add_argument("--range", default="192.168.1.0/24", help="IP range to scan (default: 192.168.1.0/24)")
    parser.add_argument("--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    parser.add_argument("--format", choices=["csv", "json", "txt", "all"], default="all", help="Report format to save (default: all)")
    parser.add_argument("--quick", action="store_true", help="Quick scan of common ports only")
    parser.add_argument("--full", action="store_true", help="Full scan of all 65535 ports")
    parser.add_argument("--output-dir", default="output", help="Directory to save reports (default: ./output)")

    args = parser.parse_args()

    # Determine port range
    if args.quick:
        port_range = "21,22,23,25,53,80,110,139,143,443,445,3389,8080,8443"
    elif args.full:
        port_range = "1-65535"
    else:
        port_range = args.ports

    scan_network(
        network_range=args.range,
        port_range=port_range,
        grab_banners=not args.no_banner,
        output_format=args.format,
        output_dir=args.output_dir
    )
