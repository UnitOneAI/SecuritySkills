"""Vulnerable chunking: provenance exists before embedding but is discarded."""


def parse_document(document):
    return {
        "source_id": document["source_id"],
        "tenant": document["tenant"],
        "acl": document["acl"],
        "version": document["version"],
        "chunks": [part.strip() for part in document["body"].split("\n\n")],
    }


def build_vectors(parsed):
    vectors = []
    for chunk in parsed["chunks"]:
        # Vulnerable: metadata needed for authorization and revocation is lost.
        vectors.append({"text": chunk, "embedding": [0.1, 0.2, 0.3]})
    return vectors


if __name__ == "__main__":
    doc = {
        "source_id": "kb-123",
        "tenant": "tenant-a",
        "acl": "finance",
        "version": "7",
        "body": "Quarterly plan\n\nRenewal notes",
    }
    print(build_vectors(parse_document(doc)))
