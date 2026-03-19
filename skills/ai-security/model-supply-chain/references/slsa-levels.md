# Model Supply Chain — SLSA v1.0 Level Mapping

## SLSA Levels Applied to Model Training Pipelines

SLSA (Supply-chain Levels for Software Artifacts) defines four levels of supply chain security for build processes. While originally designed for software, the same principles apply directly to model training pipelines.

| SLSA Level | Model Training Equivalent | What to Check |
|---|---|---|
| SLSA Build L0 | No provenance | Training produces weights with no record of how they were built |
| SLSA Build L1 | Provenance exists | Training logs record the dataset, hyperparameters, code version, and environment |
| SLSA Build L2 | Hosted build, signed provenance | Training runs on a managed platform with tamper-evident build records |
| SLSA Build L3 | Hardened build platform | Training environment is isolated, ephemeral, and resistant to insider tampering |

Most organizations today operate at L0 or L1 for model training. The assessment should document the current level and recommend a target level based on the model's deployment context and risk profile.

## SLSA v1.0 Specification

Published April 2023 by the Open Source Security Foundation (OpenSSF). The framework introduced the Build track with levels L0-L3. It is directly applicable to model training pipelines as build processes.

Reference: https://slsa.dev/spec/v1.0/

## Framework Mappings

| Framework | Identifier | Description |
|---|---|---|
| SLSA v1.0 | Build L0-L3 | Supply-chain Levels for Software Artifacts |
| OWASP LLM Top 10 2025 | LLM03 | Supply Chain Vulnerabilities |
| MITRE ATLAS | AML.T0010 | ML Supply Chain Compromise |
| NIST AI RMF 1.0 | MAP 2.3 | Scientific integrity and data quality |
