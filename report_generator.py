def generate_report(data):
    report = ""
    report += "Cyber Risk Report\n"
    report += "====================\n\n"

    for _, row in data.iterrows():
        report += f"Asset: {row['name_asset']}\n"
        report += f"Vulnerability: {row['name_vuln']}\n"
        report += f"CVSS Score: {row['cvss']}\n"
        report += f"Likelihood: {row['likelihood']}\n"
        report += f"Impact: {row['impact']}\n"
        report += f"Risk Score: {row['risk_score']}\n"
        report += f"Risk Level: {row['risk_level']}\n"
        report += f"NIST Function: {row['nist_function']}\n"
        report += "\n"

    with open("risk_report.txt", "w") as f:
        f.write(report)