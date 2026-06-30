class CVEAggregator:

    def aggregate(self, report_data):
        seen = {}
        unique = []

        for item in report_data:
            for cve in item.get("cves", []):

                cve_id = cve.get("cve")

                if not cve_id:
                    continue

                if cve_id in seen:
                    continue

                seen[cve_id] = True
                unique.append(cve)

        return unique