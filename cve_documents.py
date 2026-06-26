def cve_to_document(cve):

    text = f"""
CVE ID: {cve['cve_id']}

CVSS Score: {cve['cvss']}

Description:
{cve['description']}
"""

    return text