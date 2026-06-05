const ROUTES = {
  publicSummary: {
    model: "fast-summarizer-2026-05",
    runtimeModelIdExport: true,
    tools: [],
    maxTokens: 400,
    temperature: 0.2,
    dataClass: "public",
    outputPolicy: "escaped_markdown",
    fallback: { mode: "fail_closed", reason: "no equivalent public route" }
  },
  regulatedAdvice: {
    model: "reasoning-secure-2026-05",
    runtimeModelIdExport: true,
    tools: ["retrieve_authorized_policy", "draft_response"],
    maxTokens: 900,
    temperature: 0.1,
    dataClass: "restricted",
    outputPolicy: "citation_required",
    fallback: { mode: "fail_closed", auditEvent: "regulated_route_unavailable" }
  }
};

export function chooseRoute(task: Task) {
  return task.kind === "public_summary"
    ? ROUTES.publicSummary
    : ROUTES.regulatedAdvice;
}
