"""Benign RAG ingestion: untrusted content stays out of trusted retrieval."""

from dataclasses import dataclass
from hashlib import sha256


@dataclass
class Upload:
    tenant_id: str
    uploader_role: str
    source_id: str
    text: str
    approved: bool


class VectorIndex:
    def __init__(self):
        self.rows = []

    def upsert(self, namespace, text, metadata):
        self.rows.append({"namespace": namespace, "text": text, "metadata": metadata})


def ingest_upload(upload: Upload, index: VectorIndex):
    if not upload.approved:
        raise PermissionError("corpus content must be reviewed before indexing")

    content_hash = sha256(upload.text.encode("utf-8")).hexdigest()
    index.upsert(
        namespace=f"tenant:{upload.tenant_id}:reviewed",
        text=upload.text,
        metadata={
            "tenant": upload.tenant_id,
            "source_id": upload.source_id,
            "source_type": "user-upload",
            "trust_tier": "reviewed",
            "acl_version": "2026-06-10",
            "content_hash": content_hash,
        },
    )


if __name__ == "__main__":
    idx = VectorIndex()
    ingest_upload(
        Upload("tenant-a", "editor", "upload-42", "Reviewed support note", True),
        idx,
    )
    print(idx.rows)
