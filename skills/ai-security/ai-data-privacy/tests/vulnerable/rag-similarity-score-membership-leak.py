"""Vulnerable fixture: RAG endpoint exposes corpus membership signals."""


class Hit:
    def __init__(self, case_id, chunk_id):
        self.metadata = {"case_id": case_id, "chunk_id": chunk_id}


class VectorStore:
    def similarity_search_with_score(self, query, k):
        # Index contains real support cases. Scores and stable IDs expose
        # whether a target record or chunk is present in the corpus.
        return [
            (Hit("case-18402", "chunk-7"), 0.9821),
            (Hit("case-18403", "chunk-2"), 0.9744),
        ][:k]


vector_db = VectorStore()


def related_cases(query):
    hits = vector_db.similarity_search_with_score(query, k=10)
    return [
        {
            "case_id": hit.metadata["case_id"],
            "chunk_id": hit.metadata["chunk_id"],
            "score": score,
        }
        for hit, score in hits
    ]


# Expected review outcome: High when raw similarity scores and stable document
# identifiers are exposed without authorization checks, opaque IDs, score
# suppression, membership-inference evaluation, or adaptive-query controls.
