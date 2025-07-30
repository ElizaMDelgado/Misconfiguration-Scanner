from flask import Flask, render_template_string, request, send_from_directory
import json, os
from collections import Counter

app = Flask(__name__)
OUTPUT_DIR = "output"

@app.route("/", methods=["GET"])
def index():
    files = sorted(
        [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json")],
        reverse=True
    )
    if not files:
        return "No scan reports found."

    selected_file = request.args.get("file", files[0])
    if selected_file not in files:
        selected_file = files[0]

    with open(os.path.join(OUTPUT_DIR, selected_file)) as f:
        data = json.load(f)

    risk_counts = Counter([r["risk"] for r in data])
    high_count = risk_counts.get("High", 0)
    medium_count = risk_counts.get("Medium", 0)
    low_count = risk_counts.get("Low", 0)

    service_counts = Counter([r["service"] for r in data])
    service_labels = list(service_counts.keys())
    service_values = list(service_counts.values())

    html = """
    <html>
    <head>
        <title>Misconfiguration Scanner Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
            h1 { text-align: center; }
            .top-controls { text-align: center; margin-bottom: 20px; }
            .btn {
                color: white; border: none; padding: 6px 12px; cursor: pointer;
                border-radius: 4px; margin-left: 10px; text-decoration: none;
            }
            .refresh-btn { background: #007BFF; }
            .refresh-btn:hover { background: #0056b3; }
            .download-btn { background: #28a745; }
            .download-btn:hover { background: #1e7e34; }
            .summary { text-align: center; margin-bottom: 20px; }
            .summary div { display: inline-block; margin: 0 15px; padding: 10px; border-radius: 5px; }
            .high { background: #ffcccc; }
            .medium { background: #fff5cc; }
            .low { background: #ccffcc; }
            .charts { display: flex; justify-content: center; gap: 40px; margin-bottom: 30px; }
            canvas { border: 1px solid #ccc; }
        </style>
    </head>
    <body>
        <h1>Misconfiguration Scanner Dashboard</h1>

        <div class="top-controls">
            <form method="get" style="display:inline;">
                <label><strong>Select Report:</strong></label>
                <select name="file" onchange="this.form.submit()">
                    {% for f in files %}
                        <option value="{{f}}" {% if f == selected_file %}selected{% endif %}>{{f}}</option>
                    {% endfor %}
                </select>
            </form>

            <button class="btn refresh-btn" onclick="location.reload()">Refresh Reports</button>
            <a class="btn download-btn" href="/download/{{ selected_file }}">Download Report</a>
        </div>

        <div class="summary">
            <div class="high">High Risks: {{ high_count }}</div>
            <div class="medium">Medium Risks: {{ medium_count }}</div>
            <div class="low">Low Risks: {{ low_count }}</div>
        </div>

        <div class="charts">
            <canvas id="riskChart" width="180" height="180"></canvas>
            <canvas id="serviceChart" width="220" height="180"></canvas>
        </div>

        <table style="width: 100%; background: white; border-collapse: collapse;">
            <tr><th>Host</th><th>Port</th><th>Service</th><th>Risk</th><th>Recommendation</th><th>Banner</th></tr>
            {% for r in data %}
            <tr style="background-color:{% if r['risk']=='High' %}#ffcccc{% elif r['risk']=='Medium' %}#fff5cc{% else %}#ccffcc{% endif %}">
                <td>{{ r['host'] }}</td>
                <td>{{ r['port'] }}</td>
                <td>{{ r['service'] }}</td>
                <td>{{ r['risk'] }}</td>
                <td>{{ r['recommendation'] }}</td>
                <td>{{ r['banner'] }}</td>
            </tr>
            {% endfor %}
        </table>

        <script>
        new Chart(document.getElementById('riskChart'), {
            type: 'pie',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    data: [{{ high_count }}, {{ medium_count }}, {{ low_count }}],
                    backgroundColor: ['#ff4d4d', '#ffd633', '#5cd65c']
                }]
            },
            options: { responsive: false, maintainAspectRatio: false }
        });

        new Chart(document.getElementById('serviceChart'), {
            type: 'bar',
            data: {
                labels: {{ service_labels | tojson }},
                datasets: [{
                    label: 'Services Detected',
                    data: {{ service_values | tojson }},
                    backgroundColor: '#4da6ff'
                }]
            },
            options: { responsive: false, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
        });
        </script>
    </body>
    </html>
    """

    return render_template_string(
        html,
        files=files,
        selected_file=selected_file,
        data=data,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        service_labels=service_labels,
        service_values=service_values
    )

@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
