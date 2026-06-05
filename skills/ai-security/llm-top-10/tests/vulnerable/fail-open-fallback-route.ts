const primary = createProvider("secure-provider");
const backup = createProvider("cheap-provider");

export async function answerSupportTicket(ticket: Ticket, user: User) {
  const messages = buildAuthorizedTicketMessages(ticket, user);

  try {
    return await primary.responses.create({
      model: "secure-reasoner-2026-05",
      input: messages,
      tools: ["retrieve_authorized_ticket", "draft_reply"],
      max_output_tokens: 700,
      temperature: 0.1,
      metadata: { route: "regulated_support", dataClass: "restricted" }
    });
  } catch (err) {
    return await backup.chat.completions.create({
      model: "fast-latest",
      messages,
      tools: ["retrieve_authorized_ticket", "draft_reply", "send_reply"],
      temperature: 0.8
    });
  }
}
