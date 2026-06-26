def parse_vector(vector, key):
    parts = vector.split("/")

    for p in parts:
        if p.startswith(key + ":"):
            return p.split(":")[1]

    return None

def enrich_cve(cve_item):
    cve = cve_item["cve"]

    cve_id = cve.get("id")
    description = cve["descriptions"][0]["value"]

    metrics = cve.get("metrics", {})

    cvss_data = {}
    attack = {}

    # CVSS v3.1
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]

        vector = cvss.get("vectorString")

        cvss_data = {
            "score": cvss.get("baseScore"),
            "vector": vector
        }

        attack = {
            "vector": parse_vector(vector, "AV"),
            "complexity": parse_vector(vector, "AC"),
            "privileges_required": parse_vector(vector, "PR"),
            "user_interaction": parse_vector(vector, "UI")
        }

    # CWE extraction
    cwe_list = []

    try:
        weaknesses = cve.get("weaknesses", [])

        for w in weaknesses:
            for desc in w.get("description", []):
                cwe_list.append(desc.get("value"))
    except:
        pass

    return {
        "cve_id": cve_id,
        "description": description,

        "cvss": cvss_data,

        "attack": attack,

        "cwe": cwe_list,

        "published": cve.get("published"),
        "modified": cve.get("lastModified"),

        "raw": cve_item
    }