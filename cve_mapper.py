# cve_mapper.py

import re
from typing import Dict, List, Optional


class CVEMapper:
    """
    Service + Banner + Version → normalized product + CVE filter context
    CTI-grade mapping layer (NOT RAG-based, rule-first)
    """

    def __init__(self):
        # Basit başlangıç knowledge base (expand edilebilir)
        self.product_signatures = {
            "python simplehttpserver": ["simplehttp", "python", "http.server"],
            "apache http server": ["apache", "httpd"],
            "nginx": ["nginx"],
            "openssh": ["openssh", "ssh"],
            "ftp": ["vsftpd", "proftpd", "ftp"],
        }

    # ----------------------------
    # 1. MAIN ENTRY POINT
    # ----------------------------
    def map_service(self, service: str, banner: str, version: str = None) -> Dict:
        """
        Input:
            service: nmap service name (http, ssh, ftp...)
            banner: raw banner string
            version: parsed version if exists

        Output:
            normalized product + filters for CVE query
        """

        normalized_text = self._normalize_text(service, banner)

        product = self._detect_product(normalized_text)
        version_clean = self._extract_version(version, banner)

        cve_keywords = self._generate_cve_keywords(product, normalized_text)

        confidence = self._calculate_confidence(product, normalized_text, version_clean)

        return {
            "service": service,
            "product": product,
            "version": version_clean,
            "cve_keywords": cve_keywords,
            "confidence": confidence
        }

    # ----------------------------
    # 2. NORMALIZATION
    # ----------------------------
    def _normalize_text(self, service: str, banner: str) -> str:
        return f"{service} {banner}".lower()

    # ----------------------------
    # 3. PRODUCT DETECTION (RULE-BASED)
    # ----------------------------
    def _detect_product(self, text: str) -> str:
        for product, keywords in self.product_signatures.items():
            if any(keyword in text for keyword in keywords):
                return product
        return "unknown"

    # ----------------------------
    # 4. VERSION EXTRACTION
    # ----------------------------
    def _extract_version(self, version: Optional[str], banner: str) -> Optional[str]:
        if version:
            return version

        # regex fallback (e.g. Apache/2.4.41)
        match = re.search(r"(\d+\.\d+(\.\d+)*)", banner)
        if match:
            return match.group(1)

        return None

    # ----------------------------
    # 5. CVE KEYWORD GENERATION
    # ----------------------------
    def _generate_cve_keywords(self, product: str, text: str) -> List[str]:
        base = [product]

        # enrich keywords based on product type
        if product == "apache http server":
            base += ["apache httpd", "apache"]
        elif product == "nginx":
            base += ["nginx http server"]
        elif product == "openssh":
            base += ["ssh", "openssh server"]
        elif product == "python simplehttpserver":
            base += ["python http server", "simplehttp"]

        # remove duplicates
        return list(set(base))

    # ----------------------------
    # 6. CONFIDENCE SCORING
    # ----------------------------
    def _calculate_confidence(self, product: str, text: str, version: Optional[str]) -> float:
        score = 0.0

        if product != "unknown":
            score += 0.5

        if version:
            score += 0.3

        # keyword density check
        hits = sum(1 for kw in self.product_signatures.get(product, []) if kw in text)
        score += min(hits * 0.1, 0.2)

        return round(min(score, 1.0), 2)