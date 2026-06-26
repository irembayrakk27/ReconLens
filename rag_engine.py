from langchain_chroma import Chroma

CHROMA_PATH = "./chroma_db"

vector_db = Chroma(
    collection_name="reconlens_cves",
    persist_directory=CHROMA_PATH
)


def store_documents(documents):

    ids = []

    for i in range(len(documents)):
        ids.append(f"doc_{i}")

    vector_db.add_texts(
        texts=documents,
        ids=ids
    )

    print(
        f"[+] Stored {len(documents)} documents"
    )

    
def search_documents(query, k=3):

    results = vector_db.similarity_search(
        query,
        k=k
    )

    return results if results else []

def build_query(cve):

    attack = cve.get("attack", {})

    return f"""
Product: {cve.get("product","")}

CVE: {cve.get("cve_id","")}

Description:
{cve.get("description","")}

Attack Vector:
{attack.get("vector","")}

CWE:
{' '.join(cve.get("cwe",[]))}
"""

def build_context(results):

    if not results:
        return ""

    context = []

    for doc in results:
        context.append(doc.page_content)

    return "\n\n".join(context)

def hybrid_retrieval(cve):

    query = build_query(cve)

    docs = search_documents(query)

    context = build_context(docs)

    return {
        "query": query,
        "documents": docs,
        "context": context
    }

