import os


class TextReport:

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def save(self, report_data, filename="report.txt"):
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:

            f.write("=" * 60 + "\n")
            f.write("ReconLens Scan Report\n")
            f.write("=" * 60 + "\n\n")

            # Target
            f.write("[Target]\n")
            f.write(f"IP Address : {report_data['target'].get('ip', 'N/A')}\n\n")

            # Scan
            f.write("[Scan Information]\n")
            f.write(f"Scan Date  : {report_data['scan'].get('date', 'N/A')}\n")
            f.write(f"Open Ports : {report_data['scan'].get('open_ports', 0)}\n\n")

            # Services
            f.write("[Detected Services]\n")

            if report_data["services"]:
                for service in report_data["services"]:
                    f.write(
                        f"- Port {service.get('port')} | "
                        f"{service.get('service')} | "
                        f"{service.get('product')} "
                        f"{service.get('version')}\n"
                    )
            else:
                f.write("No services detected.\n")

            f.write("\n")

            # Vulnerabilities
            f.write("[Vulnerabilities]\n")

            if report_data["vulnerabilities"]:
                for cve in report_data["vulnerabilities"]:
                    f.write(
                        f"{cve.get('cve')} | "
                        f"CVSS {cve.get('cvss')} | "
                        f"{cve.get('severity')}\n"
                    )
            else:
                f.write("No vulnerabilities found.\n")

            f.write("\n")

            # Risk
            f.write("[Risk Assessment]\n")
            f.write(
                f"Score : {report_data['risk'].get('score', 'N/A')}\n"
            )
            f.write(
                f"Level : {report_data['risk'].get('level', 'N/A')}\n\n"
            )

            # AI
            f.write("[AI Analysis]\n")
            f.write(report_data["ai_analysis"].get("summary", "N/A"))
            f.write("\n")

        return filepath