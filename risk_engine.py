def calculate_risk(cve, service="unknown"):
    """
    CVE + enriched context → advanced risk scoring engine
    Output: risk_score (0-100), severity, confidence, explanation
    """

    cvss = cve.get("cvss", {}).get("score", 0)
    description = cve.get("description", "").lower()
    attack = cve.get("attack", {})
    cwe_list = cve.get("cwe", [])

    # -------------------------
    # 1. BASE SCORE (CVSS)
    # -------------------------
    score = cvss * 10  # normalize to 0–100 scale

    # -------------------------
    # 2. ATTACK SURFACE BOOST
    # -------------------------
    vector = attack.get("vector")

    if vector == "N":  # Network
        score += 25
    elif vector == "A":  # Adjacent
        score += 15
    elif vector == "L":  # Local
        score += 5

    # -------------------------
    # 3. PRIVILEGE REQUIREMENT
    # -------------------------
    pr = attack.get("privileges_required")

    if pr == "N":
        score += 20
    elif pr == "L":
        score += 10

    # -------------------------
    # 4. USER INTERACTION
    # -------------------------
    ui = attack.get("user_interaction")

    if ui == "N":
        score += 10

    # -------------------------
    # 5. SERVICE CRITICALITY
    # -------------------------
    critical_services = [
        "http", "apache", "nginx",
        "ssh", "ftp",
        "mysql", "postgresql",
        "redis", "mongodb"
    ]

    if service and service.lower() in critical_services:
        score += 10

    # -------------------------
    # 6. CWE INTELLIGENCE BOOST
    # -------------------------
    cwe_boost_map = {
        "CWE-79": 10,   # XSS
        "CWE-89": 20,   # SQL Injection
        "CWE-22": 15,   # Path Traversal
        "CWE-20": 10,   # Input Validation
        "CWE-787": 25,  # Out-of-bounds write
        "CWE-119": 25   # Memory corruption
    }

    for cwe in cwe_list:
        score += cwe_boost_map.get(cwe, 0)

    # -------------------------
    # 7. EXPLOIT INTELLIGENCE BOOST
    # -------------------------
    if "rce" in description:
        score += 20

    if "remote code execution" in description:
        score += 20

    if "exploit" in description:
        score += 15

    if "buffer overflow" in description:
        score += 15

    if "metasploit" in description:
        score += 20

    # -------------------------
    # 8. CLAMP SCORE
    # -------------------------
    score = max(0, min(100, score))

    # -------------------------
    # 9. SEVERITY MAPPING
    # -------------------------
    if score >= 90:
        severity = "CRITICAL"
    elif score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # -------------------------
    # 10. CONFIDENCE SCORE
    # -------------------------
    confidence = 80

    if vector == "N":
        confidence += 5

    if cwe_list:
        confidence += 5

    if cvss > 7:
        confidence += 5

    confidence = min(100, confidence)

    # -------------------------
    # 11. EXPLANATION (AI-FRIENDLY)
    # -------------------------
    reasons = []

    if cvss >= 7:
        reasons.append("High CVSS base score")

    if vector == "N":
        reasons.append("Network-exposed vulnerability")

    if pr == "N":
        reasons.append("No authentication required")

    if ui == "N":
        reasons.append("No user interaction required")

    if cwe_list:
        reasons.append(f"Critical CWE detected: {','.join(cwe_list)}")

    if "rce" in description:
        reasons.append("Remote Code Execution indicator found")

    explanation = " | ".join(reasons)

    # -------------------------
    # FINAL OUTPUT
    # -------------------------
    return {
        "risk_score": round(score, 2),
        "severity": severity,
        "confidence": confidence,
        "service": service,
        "explanation": explanation
    }