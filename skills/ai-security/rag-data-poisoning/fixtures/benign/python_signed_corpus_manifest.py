"""Benign corpus manifest check with source and chunk integrity metadata."""

from hashlib import sha256


def digest(text):
    return sha256(text.encode("utf-8")).hexdigest()


def build_chunk(source, text):
    return {
        "text": text,
        "metadata": {
            "source_id": source["source_id"],
            "tenant": source["tenant"],
            "acl": source["acl"],
            "version": source["version"],
            "trust_tier": source["trust_tier"],
            "source_hash": source["source_hash"],
            "chunk_hash": digest(text),
        },
    }


def verify_source(source):
    expected = digest(source["body"])
    if source["source_hash"] != expected:
        raise ValueError("source manifest hash mismatch")
    if source["trust_tier"] not in {"reviewed", "authoritative"}:
        raise PermissionError("source is not approved for retrieval")


def index_source(source):
    verify_source(source)
    return [build_chunk(source, chunk) for chunk in source["body"].split("\n\n")]


if __name__ == "__main__":
    body = "Release policy\n\nSupport escalation guide"
    source_doc = {
        "source_id": "policy-2026-06",
        "tenant": "tenant-a",
        "acl": "support",
        "version": "4",
        "trust_tier": "authoritative",
        "body": body,
        "source_hash": digest(body),
    }
    print(index_source(source_doc))
