"""Vulnerable RAG ingestion: untrusted uploads enter a shared corpus."""

from dataclasses import dataclass


@dataclass
class Upload:
    tenant_id: str
    uploader_role: str
    text: str


class VectorIndex:
    def __init__(self):
        self.rows = []

    def upsert(self, namespace, text, metadata):
        self.rows.append({"namespace": namespace, "text": text, "metadata": metadata})


def ingest_upload(upload: Upload, index: VectorIndex):
    # Vulnerable: all uploads are indexed into the same trusted namespace with
    # no approval state, source trust level, ACL version, or content hash.
    index.upsert(
        namespace="trusted-knowledge-base",
        text=upload.text,
        metadata={"tenant": upload.tenant_id, "source": "user-upload"},
    )


if __name__ == "__main__":
    idx = VectorIndex()
    ingest_upload(
        Upload(
            tenant_id="tenant-a",
            uploader_role="member",
            text="Synthetic support note with instruction-shaped content.",
        ),
        idx,
    )
    print(idx.rows)
