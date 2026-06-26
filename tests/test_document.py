import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from cve_fetcher import search_cves
from cve_documents import cve_to_document

results = search_cves(
    "Apache",
    "2.4.49"
)

for cve in results:

    doc = cve_to_document(cve)

    print(doc)

    print("=" * 60)