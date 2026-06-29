from report_engine.report_builder import ReportBuilder

from report_engine.json_report import JsonReport
from report_engine.text_report import TextReport
from report_engine.markdown_report import MarkdownReport
from report_engine.html_report import HtmlReport


builder = ReportBuilder()

builder.set_target("127.0.0.1")

builder.set_scan_info(open_ports=2)

builder.add_service({
    "port": 80,
    "service": "http",
    "product": "Apache HTTP Server",
    "version": "2.4.58"
})

builder.add_service({
    "port": 22,
    "service": "ssh",
    "product": "OpenSSH",
    "version": "9.6"
})

builder.add_vulnerability({
    "cve": "CVE-2025-1234",
    "cvss": 9.8,
    "severity": "Critical",
    "description": "Sample vulnerability"
})

builder.set_risk({
    "score": 9.4,
    "level": "Critical"
})

builder.set_ai_analysis({
    "summary": "The target exposes a critical remote attack surface."
})

report = builder.build()


JsonReport().save(report)
TextReport().save(report)
MarkdownReport().save(report)
HtmlReport().save(report)


print("Report Engine Test Successful.")