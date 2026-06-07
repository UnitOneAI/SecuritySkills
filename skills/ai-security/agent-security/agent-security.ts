import { approvals } from '../approvals';
import { tools } from '../tools';

// ...

export function reviewAgentSecurity(agentAudit: any) {
  // ...

  // Check if the agent's reasoning and prompt/context are logged
  if (agentAudit.store_raw_prompts || agentAudit.store_chain_of_thought) {
    // ...
  }

  // Check if the approval decision is cryptographically or canonically bound to the exact tool name, arguments, resource IDs, risk tier, and nonce
  const proposed = await agent.planToolCall(userRequest);
  const summary = `${proposed.tool}: ${proposed.naturalLanguageSummary}`;
  const approved = await approvals.request({
    summary,
    tool: proposed.tool,
    arguments: proposed.arguments,
    resourceIds: proposed.resourceIds,
    riskTier: proposed.riskTier,
    nonce: proposed.nonce,
  });

  if (approved) {
    const finalArgs = await agent.rewriteArgumentsAfterApproval();
    await tools[proposed.tool].run(finalArgs);
  }

  // Check tool-provider provenance for MCP servers
  const mcpServers = agentAudit.mcpServers;
  for (const server in mcpServers) {
    const serverConfig = mcpServers[server];
    if (!serverConfig.provenance) {
      // ...
    }
  }
}