import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from rag_engine import search_documents

results = search_documents(
    "Apache path traversal vulnerability"
)

for doc in results:
    print(doc.page_content)
    print("=" * 60)