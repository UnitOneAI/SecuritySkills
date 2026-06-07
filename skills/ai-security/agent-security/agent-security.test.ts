import { reviewAgentSecurity } from './agent-security';

describe('reviewAgentSecurity', () => {
  it('should check if the agent\'s reasoning and prompt/context are logged', async () => {
    const agentAudit = {
      store_raw_prompts: true,
      store_chain_of_thought: true,
    };
    await reviewAgentSecurity(agentAudit);
    // ...
  });

  it('should check if the approval decision is cryptographically bound to the exact tool name, arguments, resource IDs, risk tier, and nonce', async () => {
    const agentAudit = {
      store_raw_prompts: false,
      store_chain_of_thought: false,
    };
    const proposed = {
      tool: 'tool1',
      arguments: ['arg1', 'arg2'],
      resourceIds: ['res1', 'res2'],
      riskTier: 'high',
      nonce: 'nonce1',
    };
    const approved = await approvals.request({
      summary: 'summary1',
      tool: proposed.tool,
      arguments: proposed.arguments,
      resourceIds: proposed.resourceIds,
      riskTier: proposed.riskTier,
      nonce: proposed.nonce,
    });
    await reviewAgentSecurity(agentAudit);
    // ...
  });

  it('should check tool-provider provenance for MCP servers', async () => {
    const agentAudit = {
      mcpServers: {
        server1: {
          command: 'npx',
          args: ['@vendor/crm-mcp-server@latest'],
          env: { CRM_TOKEN: '${CRM_TOKEN}' },
          provenance: 'provenance1',
        },
      },
    };
    await reviewAgentSecurity(agentAudit);
    // ...
  });
});