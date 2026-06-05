type Route = {
  model: string;
  tools: string[];
  maxOutputTokens: number;
  temperature: number;
  failMode: "fail_closed";
  dataClass: "restricted" | "public";
};

const regulatedRoute: Route = {
  model: "secure-reasoner-2026-05",
  tools: ["retrieve_authorized_ticket", "draft_reply"],
  maxOutputTokens: 700,
  temperature: 0.1,
  failMode: "fail_closed",
  dataClass: "restricted",
};

const degradedRoute: Route = {
  model: "secure-reasoner-2026-05-backup",
  tools: ["retrieve_authorized_ticket", "draft_reply"],
  maxOutputTokens: 700,
  temperature: 0.1,
  failMode: "fail_closed",
  dataClass: "restricted",
};

declare function audit(event: string, payload: Record<string, string>): void;

export function chooseRegulatedRoute(primaryHealthy: boolean): Route {
  if (primaryHealthy) return regulatedRoute;
  audit("llm_route_degraded", { from: regulatedRoute.model, to: degradedRoute.model });
  return degradedRoute;
}

export function assertActionAllowed(route: Route, action: string) {
  if (action === "send_reply" && !route.tools.includes(action)) {
    throw new Error("Human approval required before side-effectful fallback action");
  }
}
