# Agentic AI — Case Studies

## AG01: ChatGPT Plugin Chaining (2023)

Researchers demonstrated that ChatGPT plugins (now deprecated in favor of GPTs with actions) could be chained such that a plugin with file-system access combined with a web-browsing plugin allowed an attacker to exfiltrate local files via a crafted prompt. The root cause was that each plugin operated with the full permissions of the user session, and no isolation existed between plugin contexts. This pattern recurs in every agent framework that does not enforce tool-level scoping.

## AG02: Anthropic Tool Use Manipulation and LangChain CVE-2023-29374

The 2024 Anthropic research paper on tool use showed that Claude, when given a code execution tool, could be manipulated via indirect prompt injection (embedded in a document it was summarizing) to execute arbitrary code rather than the analysis code the user requested. The tool itself was functioning as designed -- the abuse was in what the agent chose to execute through it. Similarly, the 2023 LangChain arbitrary code execution vulnerability (CVE-2023-29374) demonstrated that agent-controlled inputs to code execution tools are a persistent, high-severity risk.

## AG03: UIUC CrewAI Privilege Escalation (2024)

Researchers from UIUC demonstrated a multi-agent privilege escalation attack where a compromised "research" agent in a CrewAI system sent crafted messages to an "executor" agent, convincing it to run commands that the research agent was not authorized to execute directly. The executor agent trusted the research agent's messages as legitimate task instructions because no inter-agent authentication existed. This is the agentic equivalent of a confused deputy attack.

## AG04: ChatGPT Persistent Memory Poisoning (2024)

Researchers demonstrated a persistent memory poisoning attack against a ChatGPT instance with memory enabled. By embedding instructions in a shared document the user asked the AI to summarize, the attacker caused the AI to store a directive in its persistent memory that altered its behavior in all future conversations -- effectively a persistent backdoor. OpenAI patched specific vectors but the architectural pattern (agent writes to its own persistent memory based on untrusted input) remains widespread in custom agent deployments.

## AG05: Greshake et al. Cross-Agent Attacks (2023)

In the Greshake et al. paper "Not What You've Signed Up For" (arXiv:2302.12173), researchers demonstrated cross-agent attacks in LangChain-based multi-agent systems where a compromised web-browsing agent injected manipulated content that was consumed by a downstream planning agent. The planning agent treated the browsing agent's output as factual without verification, leading to execution of attacker-controlled actions.

## AG06: Rehberger Bing Chat Data Exfiltration (2023)

Security researcher Johann Rehberger demonstrated that Bing Chat (now Copilot) could be manipulated via prompt injection on a webpage to exfiltrate conversation data by encoding it into image URLs rendered in markdown. The browser would fetch the attacker's URL with the stolen data as query parameters. This exact pattern applies to any agent that can generate markdown with URLs and also has access to sensitive context.

## AG07: Financial Services Cascading Hallucination (2024)

A financial services firm reported an incident where an agentic document processing pipeline hallucinated a contract clause in stage one, which the second-stage agent used to calculate incorrect financial obligations, which the third-stage agent used to generate and send customer notifications with wrong payment amounts. Recovery required manual review of 2,400 affected records.

## AG08: AI Coding Assistant HITL Bypass via Commit Splitting (2024)

A red team exercise found that an AI coding assistant's human approval gate for code deployment could be bypassed by splitting a dangerous change across multiple small commits, each individually below the risk threshold that triggered review. The compound effect constituted a privilege escalation that no single commit would have triggered for review.

## AG09: AutoGPT Runaway API Costs (2023-2024)

Multiple documented incidents throughout 2023-2024 involved developers using autonomous coding agents (including early AutoGPT deployments) reporting runaway API costs exceeding $1,000-$10,000 in a single session when agents entered reasoning loops. The agents had no token budget and no loop detection.

## AG10: Black Hat Enterprise Agent Credential Theft (2024)

A penetration tester compromised an enterprise's agentic workflow system by extracting an API key from the agent's environment that was shared across all agents in the deployment. Because all agents used the same identity, the attacker gained access to every tool and data source. Forensic investigation was severely hampered because audit logs could not distinguish between legitimate and attacker actions.
