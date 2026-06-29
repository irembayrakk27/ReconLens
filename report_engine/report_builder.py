from datetime import datetime


class ReportBuilder:
    def __init__(self):
        self.report = {
            "target": {},
            "scan": {},
            "services": [],
            "vulnerabilities": [],
            "risk": {},
            "ai_analysis": {}
        }

    def set_target(self, ip):
        self.report["target"] = {
            "ip": ip
        }

    def set_scan_info(self, open_ports):
        self.report["scan"] = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": open_ports
        }

    def add_service(self, service):
        self.report["services"].append(service)

    def add_vulnerability(self, vulnerability):
        self.report["vulnerabilities"].append(vulnerability)

    def set_risk(self, risk):
        self.report["risk"] = risk

    def set_ai_analysis(self, analysis):
        self.report["ai_analysis"] = analysis

    def build(self):
        return self.report