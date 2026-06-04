# Smart Contract Security Review Fixtures

This directory contains calibration fixtures for the `smart-contract-security` skill. The fixtures are intentionally small and local-only so reviewers can verify the skill's detection boundaries without interacting with live contracts or real funds.

## Vulnerable Fixtures

| File | Intended finding |
|---|---|
| `tests/vulnerable/reentrancy-vault.sol` | Sends ETH before reducing user balance. |
| `tests/vulnerable/unchecked-call-airdrop.sol` | Ignores low-level payout failure while marking the claim complete. |
| `tests/vulnerable/oracle-price-trust.sol` | Uses oracle price without freshness, positivity, round, or bounds checks. |
| `tests/vulnerable/unguarded-upgrade.sol` | Lets any caller replace the implementation address. |

## Benign Fixtures

| File | Intended non-finding |
|---|---|
| `tests/benign/guarded-vault.sol` | Updates balance before transfer and uses a reentrancy guard. |
| `tests/benign/checked-call-airdrop.sol` | Requires low-level payout success before finalising the claim. |
| `tests/benign/bounded-oracle-guard.sol` | Checks oracle round completion, freshness, positivity, decimals, and bounds. |
| `tests/benign/role-gated-upgrade.sol` | Restricts upgrades to an owner, rejects zero implementation, and emits an event. |

## Review Boundary

These fixtures are not exploit instructions. They exist to test whether the skill can distinguish vulnerable contract patterns from remediated local examples. Do not deploy them or use them against third-party systems.
