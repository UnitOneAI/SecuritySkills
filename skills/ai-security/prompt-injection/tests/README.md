# Prompt Injection Test Fixtures

These fixtures are designed for manual or agent-assisted validation of the `prompt-injection` skill.

- `vulnerable/` examples should be reported when the extracted text is sent into a live model prompt without quoting, attribution, or data boundaries.
- `benign/` examples should not be reported as active vulnerabilities unless the reviewer finds a separate production flow that loads the quoted fixture text into a live prompt.

Use these examples to verify the model-visible content source matrix, extractor provenance, and false-positive controls.
