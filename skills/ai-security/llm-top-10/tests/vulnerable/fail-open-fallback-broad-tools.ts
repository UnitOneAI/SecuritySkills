type Message = { role: "system" | "user" | "assistant"; content: string };
type Ticket = { id: string; tenantId: string; body: string };
type User = { id: string; tenantId: string };

const primaryRoute = {
  name: "regulated-support",
  model: process.env.PRIMARY_LLM_MODEL ?? "secure-reasoner-2026-05",
  tools: ["retrieve_authorized_ticket", "draft_reply"],
  maxOutputTokens: 700,
  temperature: 0.1,
  dataClass: "restricted",
};

const fallbackRoute = {
  name: "regulated-support-fallback",
  model: process.env.FALLBACK_LLM_MODEL ?? "fast-latest",
  tools: ["retrieve_authorized_ticket", "draft_reply", "send_reply"],
  temperature: 0.9,
  dataClass: "restricted",
};

declare const primary: {
  responses: {
    create(input: {
      model: string;
      input: Message[];
      tools: string[];
      max_output_tokens: number;
      temperature: number;
    }): Promise<unknown>;
  };
};

declare const fallback: {
  chat: {
    completions: {
      create(input: {
        model: string;
        messages: Message[];
        tools: string[];
        temperature: number;
      }): Promise<unknown>;
    };
  };
};

declare function buildAuthorizedTicketMessages(ticket: Ticket, user: User): Message[];

export async function answerTicket(ticket: Ticket, user: User) {
  const input = buildAuthorizedTicketMessages(ticket, user);

  try {
    return await primary.responses.create({
      model: primaryRoute.model,
      input,
      tools: primaryRoute.tools,
      max_output_tokens: primaryRoute.maxOutputTokens,
      temperature: primaryRoute.temperature,
    });
  } catch {
    return await fallback.chat.completions.create({
      model: fallbackRoute.model,
      messages: input,
      tools: fallbackRoute.tools,
      temperature: fallbackRoute.temperature,
    });
  }
}
