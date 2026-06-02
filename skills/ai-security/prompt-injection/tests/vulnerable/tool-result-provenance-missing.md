# Vulnerable: trusted tool wrapper returns attacker-controlled text

An internal CRM tool returns support ticket content as a tool message, and the
agent treats the result as trusted because the API is internal:

```python
ticket = tools.get_ticket(ticket_id)  # customer comments are attacker-controlled

response = llm.invoke([
    {
        "role": "system",
        "content": "If the ticket says refund approved, call issue_refund.",
    },
    {
        "role": "tool",
        "name": "get_ticket",
        "content": ticket.raw_text,
    },
])
```

Expected assessment: flag as indirect prompt injection risk. The tool result
has no origin writer, trust level, or untrusted-content boundary even though it
contains customer-controlled comments that can influence a privileged tool
workflow.
