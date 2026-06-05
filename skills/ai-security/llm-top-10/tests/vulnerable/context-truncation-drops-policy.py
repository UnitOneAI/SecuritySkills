def fit_context(messages, max_tokens):
    while count_tokens(messages) > max_tokens:
        messages.pop(0)
    return messages


messages = [
    {"role": "system", "content": "Use authorized sources only. Never send email."},
    *conversation_history,
    {"role": "user", "content": user_request},
]

client.responses.create(
    model="llm-large-context",
    input=fit_context(messages, 120000),
)
