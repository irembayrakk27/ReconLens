import os


class HtmlReport:

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def save(self, report_data, filename="report.html"):
        filepath = os.path.join(self.output_dir, filename)

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconLens Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin:40px;
    background:#f4f4f4;
}}

h1 {{
    color:#222;
}}

section {{
    background:white;
    padding:15px;
    margin-bottom:20px;
    border-radius:8px;
}}

table {{
    width:100%;
    border-collapse:collapse;
}}

th, td {{
    border:1px solid #ddd;
    padding:8px;
}}

th {{
    background:#efefef;
}}

</style>

</head>

<body>

<h1>ReconLens Scan Report</h1>

<section>

<h2>Target</h2>

<p><b>IP Address:</b> {report_data["target"].get("ip","N/A")}</p>

</section>

<section>

<h2>Scan Information</h2>

<p><b>Date:</b> {report_data["scan"].get("date","N/A")}</p>

<p><b>Open Ports:</b> {report_data["scan"].get("open_ports",0)}</p>

</section>

<section>

<h2>Detected Services</h2>

<table>

<tr>

<th>Port</th>

<th>Service</th>

<th>Product</th>

<th>Version</th>

</tr>
"""

        for service in report_data["services"]:
            html += f"""
<tr>

<td>{service.get("port")}</td>

<td>{service.get("service")}</td>

<td>{service.get("product")}</td>

<td>{service.get("version")}</td>

</tr>
"""

        html += """
</table>

</section>

<section>

<h2>Vulnerabilities</h2>

<table>

<tr>

<th>CVE</th>

<th>CVSS</th>

<th>Severity</th>

</tr>
"""

        for cve in report_data["vulnerabilities"]:
            html += f"""
<tr>

<td>{cve.get("cve")}</td>

<td>{cve.get("cvss")}</td>

<td>{cve.get("severity")}</td>

</tr>
"""

        html += f"""

</table>

</section>

<section>

<h2>Risk Assessment</h2>

<p><b>Score:</b> {report_data["risk"].get("score","N/A")}</p>

<p><b>Level:</b> {report_data["risk"].get("level","N/A")}</p>

</section>

<section>

<h2>AI Analysis</h2>

<p>{report_data["ai_analysis"].get("summary","N/A")}</p>

</section>

</body>

</html>
"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath