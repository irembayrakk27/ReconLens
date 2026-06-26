from rag_engine import hybrid_retrieval

sample_cve = {
    "product": "apache http server",
    "cve_id": "CVE-2024-1234",
    "description": "Remote Code Execution vulnerability",
    "attack": {
        "vector": "N"
    },
    "cwe": ["CWE-79"]
}

result = hybrid_retrieval(sample_cve)

print("\n=== QUERY ===")
print(result["query"])

print("\n=== CONTEXT ===")
print(result["context"])
