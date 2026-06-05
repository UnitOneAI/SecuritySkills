def fit_context(messages, max_tokens):
    while token_count(messages) > max_tokens:
        messages.pop(0)
    return messages


messages = [
    {"role": "system", "content": "Use tenant ACLs and never execute denied actions."},
    {"role": "developer", "content": "Denied actions: send_wire, delete_customer"},
    *conversation_history,
    {"role": "user", "content": user_prompt},
]

client.responses.create(
    model="llm-large-context",
    input=fit_context(messages, 120000),
)
