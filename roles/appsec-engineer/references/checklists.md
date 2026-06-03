# AppSec Reference Checklists

## PR Review Evidence

- Changed security-sensitive route or handler identified
- Authentication and authorization behavior checked
- Object or tenant boundary checked
- User input, external data, and LLM output sinks checked
- CWE and ASVS mapping recorded
- Conditional approvals include owner and re-test trigger

## API Review Evidence

- Route inventory is complete for public, partner, admin, and service calls
- BOLA, BFLA, and BOPLA tests include expected and observed behavior
- Rate limit and resource consumption behavior checked
- API inventory drift recorded
- SAST update or suppression lifecycle recorded

## AI Feature Evidence

- Model/provider and context sources recorded
- Output sinks and tool permissions recorded
- Direct and indirect prompt-injection tests recorded
- Agentic action approval, logging, and rollback evidence recorded
