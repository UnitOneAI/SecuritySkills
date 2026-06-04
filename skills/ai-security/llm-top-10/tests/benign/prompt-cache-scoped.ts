type ResponseClient = {
  create(input: {
    model: string;
    input: Array<{ role: "system" | "user"; content: string }>;
    prompt_cache_key: string;
    prompt_cache_retention: "in_memory";
  }): Promise<unknown>;
};

export async function answerWithScopedPromptCache(
  client: ResponseClient,
  tenantId: string,
  userId: string,
  assistantId: string,
  aclVersion: string,
  question: string,
) {
  const staticSystemPrompt =
    "Answer using only documents available to the current user.";

  return client.create({
    model: "gpt-5",
    input: [
      { role: "system", content: staticSystemPrompt },
      { role: "user", content: question },
    ],
    prompt_cache_key: [
      "tenant",
      tenantId,
      "user",
      userId,
      "assistant",
      assistantId,
      "acl",
      aclVersion,
      "model",
      "gpt-5",
    ].join(":"),
    prompt_cache_retention: "in_memory",
  });
}
