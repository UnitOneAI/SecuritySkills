type Cache = {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, options: { ttl: number }): Promise<void>;
};

type VectorStore = {
  search(query: string, options: { filter: { tenant_id: string } }): Promise<string[]>;
};

export async function buildPromptWithSharedRetrievalCache(
  cache: Cache,
  vectorStore: VectorStore,
  tenantId: string,
  userQuestion: string,
) {
  const queryHash = userQuestion.trim().toLowerCase().replace(/\s+/g, "-");
  const cacheKey = `retrieval:${queryHash}`;

  let chunks = await cache.get<string[]>(cacheKey);
  if (!chunks) {
    chunks = await vectorStore.search(userQuestion, {
      filter: { tenant_id: tenantId },
    });
    await cache.set(cacheKey, chunks, { ttl: 60 * 60 });
  }

  return [
    { role: "system", content: "Answer using retrieved context." },
    { role: "user", content: chunks.join("\n\n") },
    { role: "user", content: userQuestion },
  ];
}
