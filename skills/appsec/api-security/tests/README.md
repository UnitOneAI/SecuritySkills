# api-security gRPC/protobuf fixtures

These fixtures exercise the gRPC/protobuf review gates added in `SKILL.md`
and `api-top10-checklist.md`.

Expected behavior:

- Files under `vulnerable/` should produce findings when the evidence is in scope.
- Files under `benign/` should not be raised as High findings by themselves.
- If runtime listener exposure or policy binding is unavailable, the reviewer should
  record `Not Evaluable` instead of assuming public exposure.

Coverage:

- Public server reflection exposing privileged RPC inventory.
- Metadata authentication without per-method authorization.
- Missing deadlines, message limits, and stream controls.
- Safe internal gRPC service configuration with mTLS, method policy, bounded
  messages, deadlines, and restricted reflection.
