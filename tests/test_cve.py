from cve_fetcher import search_cves

results = search_cves(
    "Apache",
    "2.4.49"
)

print(
    f"\nFound {len(results)} CVEs\n"
)

for cve in results:

    print(
        f"{cve['cve_id']} | CVSS: {cve['cvss']}"
    )

    print(
        cve["description"][:120]
    )

    print("-" * 50)