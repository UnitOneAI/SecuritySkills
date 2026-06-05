const MAX_OPERATIONS = 3;
const MAX_ALIASES = 5;
const MAX_COST = 100;

function enforceGraphqlBudget(request, principal) {
  const operations = Array.isArray(request.body) ? request.body : [request.body];
  if (operations.length > MAX_OPERATIONS) throw new Error("too many operations");

  let totalCost = 0;
  for (const operation of operations) {
    const aliasCount = countAliases(operation.query);
    if (aliasCount > MAX_ALIASES) throw new Error("too many aliases");

    totalCost += estimateComplexity(operation.query, operation.variables);
  }

  if (totalCost > MAX_COST) throw new Error("query too expensive");
  rateLimiter.consume(principal.id, operations.length + totalCost);
}
