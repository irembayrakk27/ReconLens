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
from rag_engine import store_documents

results = search_cves(
    "Apache",
    "2.4.49"
)

docs = []

for cve in results:

    docs.append(
        cve_to_document(cve)
    )

store_documents(docs)