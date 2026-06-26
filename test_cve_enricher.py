from cve_enricher import enrich_cve

sample = {
    "cve": {
        "id": "CVE-2024-1234",
        "descriptions": [
            {"value": "Test vulnerability for enrichment engine"}
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                }
            ]
        },
        "weaknesses": [
            {"description": [{"value": "CWE-79"}]}
        ],
        "published": "2024-01-01",
        "lastModified": "2024-02-01"
    }
}

result = enrich_cve(sample)

print("\n=== ENRICHED CVE ===\n")
for k, v in result.items():
    print(k, ":", v)
