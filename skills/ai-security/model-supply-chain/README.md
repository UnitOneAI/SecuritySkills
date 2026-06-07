# Model Supply Chain
This skill checks for potential model supply chain vulnerabilities in the code.

## Patterns
The skill looks for the following patterns:
* `from_pretrained` with unpinned revisions
* `trust_remote_code=True`
* `snapshot_download` with pinned revisions
* `ollama pull` with unverified repositories

## Confidence
The skill has a high confidence level when it detects any of the above patterns.

## Description
The skill checks for potential model supply chain vulnerabilities in the code. It looks for patterns that may indicate a vulnerability, such as using unpinned revisions or trusting remote code. If any of these patterns are found, the skill will report a high-confidence issue.