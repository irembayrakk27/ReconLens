from banner import grab_banner, extract_server_header
from analyzer import analyze_ports
from reporter import save_report
from ai_analyzer import get_ai_analysis
from version_parser import parse_server_info
from cve_mapper import CVEMapper
from rag_engine import search_documents
from cve_fetcher import search_cves
from risk_engine import calculate_risk

import subprocess

cve_mapper = CVEMapper()

def run_nmap(target):
    
    print(f"Starting Nmap scan on {target}...")

    result = subprocess.run(        #system programing
        ["nmap",target],
        capture_output=True,
        text=True
    )

    return result.stdout


def parse_nmap_output(output):

    ports = []

    lines = output.split("\n")

    for line in lines:

        if "/tcp" in line and "open" in line:

            parts = line.split()

            port = int(parts[0].split("/")[0])
            service = parts[2]

            ports.append({
                "port": port,
                "service": service
            })

    return ports

def scan_target(target):
    raw_output = run_nmap(target)
    ports = parse_nmap_output(raw_output)

    return {
        "target": target,
        "ports": ports,
        "raw_output": raw_output,
    }

def main():

    target = input("Enter target IP: ")

    results = scan_target(target)

    print("\nTarget:", results["target"])

    print("\nOpen Ports:")

    report_data = []

    for item in results["ports"]:

        server = "Unknown"

        print(item)

        mapped = {
            "product": "unknown",
            "version": "unknown",
            "confidence": 0
        }

        banner = grab_banner(
            results["target"],
            item["port"]
        )

        if banner:

            server = extract_server_header(banner)

            print(f"Detected Server: {server}")

            parsed = parse_server_info(server)

            product = parsed["product"]
            version = parsed["version"]

            print(f"Product: {product}")
            print(f"Version: {version}")

            mapped = cve_mapper.map_service(
                service=item["service"],
                banner=banner,
                version=version
            )

            print("\n[CVE MAPPER]")
            print(mapped)

            if product and version:

                query = f"{product} {version} HTTP server security vulnerabilities CVE"

                cves = search_cves(product, version)

                print("\nRetrieved CVEs + Risk Scores:")

                for cve in cves:

                    risk = calculate_risk(cve, server)

                    print("-" * 50)
                    print("CVE ID:", cve["cve_id"])
                    print("CVSS Score:", cve["cvss"])
                    print("Description:", cve["description"][:200])

                    print("Risk:", risk["risk_level"])
                    print("Score:", risk["risk_score"])
                    print("Reason:", risk["reason"])

        else:

            print("Banner not found")

        analysis = analyze_ports([{
            "port": item["port"],
            "service": item["service"],
            "server": server
        }])[0] 

        print(f"Risk Level: {analysis['risk']}")

        print(f"Reason: {analysis['reason']}")

        report_data.append({
            "target": results["target"],
            "port": item["port"],
            "service": item["service"],
            "server": server,
            "risk": analysis["risk"],
            "reason": analysis["reason"],
            "product": mapped["product"],
            "product": mapped["product"],
            "version": mapped["version"],
            "confidence": mapped["confidence"]
            })
    print("\nGenerating AI report...")

    ai_analysis = get_ai_analysis({
        "scan": report_data,
        "mapped_context": mapped
    })

    with open("ai_report.txt", "w") as f:
        f.write(ai_analysis)

    print("\nAI Analysis:")
    print(ai_analysis)

    
    save_report(report_data)

   

if __name__ == "__main__":
    main()    
    