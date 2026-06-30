def calculate_single_cve_risk(cve, service="unknown"):
    """
    CVE + enriched context → advanced risk scoring engine
    Output: risk_score (0-100), severity, confidence, explanation
    """

    cvss_data = cve.get("cvss", 0)

    if isinstance(cvss_data, dict):
        cvss = cvss_data.get("score", 0)
    else:
        cvss = cvss_data

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

def calculate_risk(cves, service="unknown"):
    """
    Risk Engine v2.1

    Input:
        cves -> list

    Output:
        Single summarized risk assessment
    """

    if not cves:
        return {
            "risk_score": 0,
            "severity": "INFO",
            "confidence": 0,
            "service": service,
            "highest_cvss": 0,
            "cve_count": 0,
            "critical_count": 0,
            "explanation": "No vulnerabilities detected."
        }

    results = [
        calculate_single_cve_risk(cve, service)
        for cve in cves
    ]

    highest_score = max(r["risk_score"] for r in results)
    highest_severity = max(
        results,
        key=lambda r: r["risk_score"]
    )["severity"]

    confidence = round(
        sum(r["confidence"] for r in results) / len(results)
    )

    critical_count = sum(
        1
        for r in results
        if r["severity"] == "CRITICAL"
    )

    explanation = (
        f"{len(cves)} CVE(s) analyzed. "
        f"{critical_count} critical finding(s)."
    )

    return {
        "risk_score": highest_score,
        "severity": highest_severity,
        "confidence": confidence,
        "service": service,
        "highest_cvss": max(
            c.get("cvss", 0)
            if isinstance(c.get("cvss"), (int, float))
            else c.get("cvss", {}).get("score", 0)
            for c in cves
        ),
        "cve_count": len(cves),
        "critical_count": critical_count,
        "explanation": explanation
    }

class RiskEngine:
    """
    CTI Risk Engine v2.2 (Aşama 3)
    """

    def normalize_cve(self, cve):
        return {
            "cve": cve.get("cve"),
            "cvss": self._extract_cvss(cve),
            "description": cve.get("description", "").lower(),
            "attack": cve.get("attack", {}),
            "cwe": cve.get("cwe", []),
            "service": cve.get("service", "unknown")
        }

    def _extract_cvss(self, cve):
        cvss_data = cve.get("cvss", 0)
        if isinstance(cvss_data, dict):
            return cvss_data.get("score", 0)
        return cvss_data

    def enrich_cve(self, cve):
        desc = cve["description"]

        return {
            **cve,
            "epss": self._epss_proxy(desc, cve["cvss"]),
            "kev": self._kev_proxy(desc),
            "exploit": self._exploit_proxy(desc)
        }

    def _epss_proxy(self, desc, cvss):
        score = 0.1
        if cvss >= 7:
            score += 0.4
        if "rce" in desc:
            score += 0.3
        return min(score, 1.0)

    def _kev_proxy(self, desc):
        return any(x in desc for x in ["exploited", "cisa", "in the wild"])

    def _exploit_proxy(self, desc):
        return any(x in desc for x in ["metasploit", "exploit", "poc"])

    def score_cve(self, cve):
        score = 0

        score += cve["cvss"] * 5
        score += cve.get("epss", 0) * 20

        if cve.get("kev"):
            score += 20

        if cve.get("exploit"):
            score += 10

        attack = cve.get("attack", {})
        if attack.get("vector") == "N":
            score += 10

        if attack.get("privileges_required") == "N":
            score += 10

        return min(score, 100)

    def calculate_global_risk(self, cves):
        results = []

        for cve in cves:
            n = self.normalize_cve(cve)
            e = self.enrich_cve(n)
            s = self.score_cve(e)
            results.append(s)

        if not results:
            return {
                "max_risk": 0,
                "avg_risk": 0,
                "critical_count": 0,
                "level": "INFO"
            }

        max_score = max(results)
        avg_score = sum(results) / len(results)

        return {
            "max_risk": round(max_score, 2),
            "avg_risk": round(avg_score, 2),
            "critical_count": len([r for r in results if r >= 85]),
            "level": self._classify(max_score)
        }

    def _classify(self, score):
        if score >= 85:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        return "LOW"

# =========================
# BACKWARD COMPATIBILITY
# =========================

_global_engine = RiskEngine()

def calculate_risk(cves, service="unknown"):
    return _global_engine.calculate_global_risk(cves)