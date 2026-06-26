"""
NVD API key test scripti.
Sadece dogrulama icin - ana projeye dahil degil.
Calistirmak icin: python3 test_nvd.py
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")

if not NVD_API_KEY:
    print("[-] NVD_API_KEY .env dosyasinda bulunamadi.")
    print("    .env dosyana 'NVD_API_KEY=senin_keyin' satirini ekledigin")
    print("    klasorde calistirdiginadan emin ol.")
    exit(1)

print(f"[+] NVD_API_KEY bulundu: {NVD_API_KEY[:8]}... (gizlendi)")

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "keywordSearch": "apache http server 2.4.49",
    "resultsPerPage": 3
}
headers = {
    "apiKey": NVD_API_KEY
}

print("[+] NVD API'ye test istegi gonderiliyor...")
resp = requests.get(url, params=params, headers=headers, timeout=45)

print(f"[+] HTTP Status: {resp.status_code}")

if resp.status_code == 200:
    data = resp.json()
    total = data.get("totalResults", 0)
    print(f"[+] Basarili! Toplam {total} sonuc bulundu (3 tanesi gosteriliyor):\n")
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        cve_id = cve["id"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "Aciklama yok"
        )
        print(f"  - {cve_id}: {desc[:120]}...")
else:
    print(f"[-] Hata: {resp.text[:300]}")