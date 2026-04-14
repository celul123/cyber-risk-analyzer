import pandas as pd
import plotly.express as px

from cvss_parser import parse_cvss
from nist_mapper import map_to_nist
from report_generator import generate_report


def risk_level(score):
    if score < 10:
        return "Low"
    elif score < 16:
        return "Medium"
    elif score < 21:
        return "High"
    else:
        return "Critical"


# CSV dosyalarını oku
assets = pd.read_csv("assets.csv")
vulns = pd.read_csv("vulnerabilities.csv")

print("\nAssets columns:")
print(assets.columns.tolist())

print("\nVulnerabilities columns:")
print(vulns.columns.tolist())

# Birleştir
data = vulns.merge(assets, left_on="asset_id", right_on="id", suffixes=("_vuln", "_asset"))

print("\nColumns after merge:")
print(data.columns.tolist())

# CVSS hesapla
data["cvss"] = data["cvss_vector"].apply(parse_cvss)

# NIST mapping
data["nist_function"] = data["name_vuln"].apply(map_to_nist)

# Risk skoru: likelihood × impact
data["risk_score"] = data["likelihood"] * data["impact"]

# Risk level
data["risk_level"] = data["risk_score"].apply(risk_level)

print("\nFinal Data:")
print(
    data[
        [
            "name_vuln",
            "name_asset",
            "cvss",
            "likelihood",
            "impact",
            "risk_score",
            "risk_level",
            "nist_function",
        ]
    ]
)

# 1) Ana scatter chart
fig = px.scatter(
    data,
    x="impact",
    y="likelihood",
    size="risk_score",
    color="risk_level",
    hover_name="name_vuln",
    hover_data=["name_asset", "cvss", "nist_function"],
    title="Cyber Risk Analysis Dashboard"
)

fig.update_layout(
    xaxis_title="Impact",
    yaxis_title="Likelihood",
    legend_title="Risk Level"
)

fig.write_html("risk_report.html")

# 2) Risk heatmap
heatmap = px.density_heatmap(
    data,
    x="likelihood",
    y="impact",
    z="risk_score",
    title="Risk Heatmap"
)

heatmap.update_layout(
    xaxis_title="Likelihood",
    yaxis_title="Impact"
)

heatmap.write_html("risk_heatmap.html")

# 3) Severity distribution
severity_chart = px.histogram(
    data,
    x="risk_level",
    color="risk_level",
    title="Risk Level Distribution"
)

severity_chart.write_html("risk_severity.html")

# 4) Text rapor
generate_report(data)

# 5) Dashboard sayfası
with open("dashboard.html", "w") as f:
    f.write("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cyber Risk Dashboard</title>
        <style>
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f4f7fb;
                color: #1f2937;
            }

            .container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 30px 20px 50px;
            }

            .header {
                background: white;
                color: #111827;
                padding: 40px 30px;
                border-radius: 18px;
                border: 1px solid #e5e7eb;
                box-shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
                margin-bottom: 30px;
            }

            .header h1 {
                margin: 0 0 10px;
                font-size: 2.2rem;
                color: #111827;
            }

            .header p {
                 margin: 0;
                font-size: 1rem;
                color: #4b5563;
                line-height: 1.6;
            }

            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }

            .summary-card {
                background: white;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }

            .summary-card:hover {
                transform: translateY(-4px);
                box-shadow: 0 10px 25px rgba(15, 23, 42, 0.12);
            }

            .summary-card h3 {
                margin: 0 0 8px;
                font-size: 1rem;
                color: #475569;
            }

            .summary-card p {
                margin: 0;
                font-size: 1.5rem;
                font-weight: bold;
                color: #0f172a;
            }

            .section {
                background: white;
                border-radius: 18px;
                padding: 22px;
                margin-bottom: 28px;
                box-shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
            }

            .section h2 {
                margin-top: 0;
                margin-bottom: 10px;
                font-size: 1.35rem;
                color: #111827;
            }

            .section p {
                margin-top: 0;
                margin-bottom: 18px;
                color: #4b5563;
                line-height: 1.6;
            }

            iframe {
                width: 100%;
                height: 650px;
                border: none;
                border-radius: 14px;
                background: #fff;
            }

            .footer {
                text-align: center;
                color: #6b7280;
                font-size: 0.95rem;
                margin-top: 20px;
            }

            @media (max-width: 768px) {
                .header h1 {
                    font-size: 1.7rem;
                }

                iframe {
                    height: 500px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">

            <div class="header">
                <h1>Cyber Risk Dashboard</h1>
                <p>
                    This dashboard provides an overview of organizational cyber risk by
                    visualizing vulnerability severity, likelihood, impact, and overall
                    risk distribution across assets.
                </p>
            </div>

            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Main View</h3>
                    <p>Risk Analysis</p>
                </div>
                <div class="summary-card">
                    <h3>Matrix</h3>
                    <p>Risk Heatmap</p>
                </div>
                <div class="summary-card">
                    <h3>Distribution</h3>
                    <p>Severity Levels</p>
                </div>
            </div>

            <div class="section">
                <h2>Risk Visualization</h2>
                <p>
                    Bubble chart showing the relationship between impact, likelihood,
                    and calculated risk score for detected vulnerabilities.
                </p>
                <iframe src="risk_report.html"></iframe>
            </div>

            <div class="section">
                <h2>Risk Heatmap</h2>
                <p>
                    Heatmap representation of risk concentration based on likelihood
                    and impact values.
                </p>
                <iframe src="risk_heatmap.html"></iframe>
            </div>

            <div class="section">
                <h2>Risk Severity Distribution</h2>
                <p>
                    Distribution of vulnerabilities by calculated risk level to support
                    prioritization and remediation planning.
                </p>
                <iframe src="risk_severity.html"></iframe>
            </div>

            <div class="footer">
                Made with ❤️ by Cosku Eylul Coskun
            </div>

        </div>
    </body>
    </html>
    """)

print("\nGenerated files:")
print("- risk_report.html")
print("- risk_heatmap.html")
print("- risk_severity.html")
print("- dashboard.html")
print("- risk_report.txt")