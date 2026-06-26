from risk_engine import calculate_risk

sample = {
    "cve_id": "CVE-2024-1234",
    "description": "Remote code execution vulnerability exploit available",
    "cvss": {"score": 7.5},
    "attack": {
        "vector": "N",
        "complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N"
    },
    "cwe": ["CWE-79"]
}

print(calculate_risk(sample))
