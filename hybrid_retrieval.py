from difflib import SequenceMatcher

class HybridRetrievalEngine:

    def __init__(self, vector_db=None):
        self.vector_db = vector_db  # RAG backend (Chroma, FAISS vs)

    # ---------------------------
    # 1. SEMANTIC SIMILARITY
    # ---------------------------
    def similarity(self, a, b):
        return SequenceMatcher(None, a, b).ratio()

    # ---------------------------
    # 2. RAG SEARCH
    # ---------------------------
    def rag_search(self, query):
        if not self.vector_db:
            return []

        return self.vector_db.search(query)

    # ---------------------------
    # 3. CVE ENRICHMENT FUSION
    # ---------------------------
    def retrieve(self, cve_text, cve_data):

        # STEP 1: RAG results
        rag_results = self.rag_search(cve_text)

        # STEP 2: similarity scoring
        similarity_scores = []

        for doc in rag_results:
            score = self.similarity(cve_text, doc.get("content", ""))
            similarity_scores.append({
                "doc": doc,
                "score": score
            })

        # STEP 3: sort by relevance
        similarity_scores.sort(key=lambda x: x["score"], reverse=True)

        top_context = similarity_scores[:3]

        # STEP 4: fuse context
        return {
            "cve": cve_data,
            "rag_context": top_context,
            "fusion_score": sum([x["score"] for x in top_context]) / max(len(top_context), 1)
        }