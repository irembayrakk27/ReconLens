import requests


class CVEEngine:

    def __init__(self):
        # Basit başlangıç knowledge base
        self.local_db = {
            "openssh": [
                {
                    "version": "6.6.1p1",
                    "cves": [
                        {
                            "cve": "CVE-2016-0777",
                            "cvss": 7.5,
                            "description": "OpenSSH information leak vulnerability"
                        },
                        {
                            "cve": "CVE-2016-0778",
                            "cvss": 5.3,
                            "description": "SSH roaming vulnerability"
                        }
                    ]
                }
            ],
            "apache": [
                {
                    "version": "2.4.58",
                    "cves": [
                        {
                            "cve": "CVE-2024-1234",
                            "cvss": 9.1,
                            "description": "Apache RCE vulnerability example"
                        }
                    ]
                }
            ]
        }

    def normalize(self, text):
        if not text:
            return ""
        return text.lower().strip()

    def find_cves(self, product, version):

        product = self.normalize(product)
        version = self.normalize(version)

        candidates = []

        
        if product in self.local_db:
            candidates = self.local_db[product]

        
        else:
            for key in self.local_db.keys():
                if key in product:
                    candidates = self.local_db[key]
                    product = key
                    break

        
        if not candidates:
            return []

        results = []

        
        for entry in candidates:
            entry_version = self.normalize(entry.get("version", ""))

            if version.startswith(entry_version) or entry_version == version:
                results.extend(entry.get("cves", []))

        return results

