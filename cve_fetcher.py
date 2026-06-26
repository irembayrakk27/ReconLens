import os
import requests

from dotenv import load_dotenv
from version_matcher import version_in_range

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def is_relevant_cve(product: str, description: str) -> bool:
    product = product.lower()

    keywords_map = {
        "apache": ["apache", "httpd"],
        "nginx": ["nginx"],
        "python": ["python", "simplehttp", "http.server"],
        "openssh": ["ssh", "openssh"]
    }

    for key, keywords in keywords_map.items():
        if key in product:
            return any(k in description.lower() for k in keywords)

    return True

def extract_cvss(metrics):
    try:
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        return 0.0
    except:
        return 0.0


def is_version_matched(cve, target_version):
    try:
        configurations = cve.get("configurations", [])

        for config in configurations:
            for node in config.get("nodes", []):

                for cpe_match in node.get("cpeMatch", []):

                    if not cpe_match.get("vulnerable", False):
                        continue

                    start = cpe_match.get("versionStartIncluding")
                    end = cpe_match.get("versionEndIncluding")

                    # Eğer range yoksa geç (basit yol)
                    if not start and not end:
                        return True

                    if version_in_range(target_version, start, end):
                        return True

        return False

    except:
        return False



def search_cves(product, version=None):

    query = product

    if version:
        query += f"  {version}"

    headers = {
        "X-Api-Key": NVD_API_KEY
    }

    params = {
        "keywordSearch": query,
        "resultsPerPage": 5
    }

    try:

        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=45
        )

        response.raise_for_status()

        data = response.json()

        print("Total Results:", data.get("totalResults"))

        results = []

        for vuln in data.get( "vulnerabilities", [] ):

            cve = vuln["cve"]

            if version:
                if not is_version_matched(cve, version):
                    continue

            cve_id = cve["id"]

            description = next(
                (
                    d["value"]
                    for d in cve.get("descriptions", [])
                    if d["lang"] == "en"
                ),
                "No description"
            )

            metrics = cve.get("metrics", {})

            cvss_score = extract_cvss(metrics)

            if not is_relevant_cve(product, description):
                continue

            if cvss_score == 0.0:
                continue

            
            results.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss": cvss_score
                }
            )
        
        results.sort(key=lambda x: x["cvss"], reverse=True)

        return results[:5]

    except Exception as e:

        print(
            f"CVE Search Error: {e}"
        )

        return []