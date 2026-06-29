import sys

from scanner import scan_target
from banner import grab_banner, extract_server_header
from version_parser import parse_server_info

from cve_engine import CVEEngine
from cve_mapper import CVEMapper
from risk_engine import calculate_risk
try:
    from ai_analyzer import get_ai_analysis
    AI_AVAILABLE = True
except ModuleNotFoundError:
    AI_AVAILABLE = False

from report_engine.report_builder import ReportBuilder
from report_engine.json_report import JsonReport
from report_engine.text_report import TextReport
from report_engine.markdown_report import MarkdownReport
from report_engine.html_report import HtmlReport


def main(target):

    print(f"[+] Starting ReconLens scan: {target}")

    # =========================
    # INIT ENGINE'LER
    # =========================
    cve_engine = CVEEngine()
    cve_mapper = CVEMapper()

    # =========================
    # SCAN
    # =========================
    results = scan_target(target)

    report_data = []

    # =========================
    # PORT LOOP
    # =========================
    for item in results["ports"]:

        print(f"\n[+] Analyzing port: {item}")

        # PRIMARY SOURCE (Nmap)
        product = item["product"]
        version = item["version"]

        # SECONDARY SOURCE (Banner)
        banner = grab_banner(results["target"], item["port"])

        if banner:
            server = extract_server_header(banner)
        else:
            print("[-] Banner not found (fallback mode)")
            server = product

        print(f"[+] Product: {product}")
        print(f"[+] Version: {version}")

        # =========================
        # PRODUCT NORMALIZATION
        # =========================
        mapped = cve_mapper.map_service(
            service=item["service"],
            banner=banner,
            version=version
        )

        # Normalize edilmiş ürün adını kullan
        if mapped["product"] != "unknown":
            product = mapped["product"]

        # =========================
        # CVE SEARCH
        # =========================
        if product and version:

            print(f"[+] Product: {product}")
            print(f"[+] Version: {version}")

            cves = cve_engine.find_cves(product, version)

            print("\n[+] CVE Results:")

            for cve in cves:
                print(f"  - {cve.get('cve_id', 'Unknown')}")

        else:
            cves = []

        # =========================
        # RISK ENGINE
        # =========================
        if cves:
            risk = calculate_risk(cves, server)
        else:
            risk = {
                "risk_score": 0,
                "severity": "INFO",
                "confidence": 0,
                "service": server,
                "explanation": "No CVEs found"
            }

        # =========================
        # STORE REPORT DATA
        # =========================
        report_data.append({
            "target": results["target"],
            "port": item["port"],
            "service": item["service"],
            "server": server,
            "product": product,
            "version": version,
            "confidence": mapped.get("confidence", 0),
            "cves": cves,
            "risk": risk["severity"],
            "reason": risk["explanation"],
        })

    # =========================
    # AI ANALYSIS
    # =========================
    print("\n[+] Generating AI report...")

    if AI_AVAILABLE:
        ai_analysis = get_ai_analysis({
            "scan": report_data
        })
    else:
        ai_analysis = (
            "AI analysis skipped: 'groq' dependency is not installed."
        )

    # =========================
    # REPORT ENGINE
    # =========================
    builder = ReportBuilder()

    builder.set_target(target)
    builder.set_scan_info(len(results["ports"]))
    builder.set_ai_analysis({"summary": ai_analysis})

    for r in report_data:
        builder.add_service({
            "port": r["port"],
            "service": r["service"],
            "product": r["product"],
            "version": r["version"]
        })

    report = builder.build()

    JsonReport().save(report)
    TextReport().save(report)
    MarkdownReport().save(report)
    HtmlReport().save(report)

    print("\n[+] Scan completed. Reports generated.")


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python3 main.py <target>")
        sys.exit(1)

    main(sys.argv[1])