# AI Data Privacy — Regulatory Requirements

## GDPR (Regulation (EU) 2016/679)

| Article | Requirement | AI Relevance |
|---|---|---|
| Art. 5 | Principles of data processing (lawfulness, purpose limitation, data minimization) | All AI data processing must comply with core principles |
| Art. 6 | Legal basis for processing | Training on personal data requires consent (Art. 6(1)(a)) or legitimate interest (Art. 6(1)(f)) with documented balancing test |
| Art. 13 | Information to be provided to data subjects | Users must be informed their data may be used for AI training |
| Art. 17 | Right to Erasure | Data subjects can request deletion; raises question of whether model retraining is required |
| Art. 22 | Automated individual decision-making | Restrictions on fully automated decisions with legal/significant effects |
| Art. 25 | Data protection by design and by default | AI systems must implement privacy by design |
| Art. 35 | Data Protection Impact Assessment (DPIA) | Required for high-risk AI processing of personal data |

## EU AI Act (Regulation (EU) 2024/1689)

| Article | Requirement | AI Relevance |
|---|---|---|
| Art. 10(2) | Training data quality and relevance | Data selection criteria documented; relevance to intended purpose demonstrated |
| Art. 10(2)(d) | Gap identification | Known gaps in data coverage identified with risk assessment |
| Art. 10(2)(e) | Statistical properties documentation | Dataset characteristics (size, distribution, coverage) documented |
| Art. 10(2)(f) | Bias examination | Demographic representation analysis; bias testing on protected characteristics |
| Art. 10(3) | Free of errors | Data quality validation; error rate measurement; cleaning procedures |
| Art. 10(5) | Personal data processing | Legal basis; purpose limitation; data minimization; DPIA conducted |
| Art. 11 | Technical documentation | Complete documentation of data governance practices |
| Art. 13 | Transparency to data subjects | Data subjects informed of AI training data usage; right to explanation |
| Art. 86 | Right to explanation | Transparency about AI system decision-making |

## CCPA/CPRA (California Civil Code Sec. 1798.100-199)

| Section | Requirement | AI Relevance |
|---|---|---|
| 1798.100 | Right to know personal information collected | Applies to AI training data containing personal information |
| 1798.105 | Right to delete personal information | Deletion requests must cover AI training datasets |
| 1798.120 | Right to opt out of sale/sharing | AI training on personal data may constitute "processing" under CPRA |
| 1798.135 | Methods for exercising opt-out | Technical mechanisms must be available for AI training opt-out |

## HIPAA (Health Insurance Portability and Accountability Act)

| Rule | Requirement | AI Relevance |
|---|---|---|
| Privacy Rule | Protection of PHI | Health data in AI prompts/training requires HIPAA-compliant safeguards |
| Security Rule | Technical safeguards | Encryption, access controls for AI systems processing PHI |
| Minimum Necessary | Limit PHI access to minimum needed | AI systems should receive only necessary health data |

## Cross-Regulatory Summary

| Regulatory Area | GDPR | EU AI Act | CCPA/CPRA | HIPAA |
|---|---|---|---|---|
| Legal basis required | Yes (Art. 6) | Yes (Art. 10(5)) | Implied | Yes |
| Right to deletion | Yes (Art. 17) | Via GDPR | Yes (1798.105) | Limited |
| Consent for training | Required/LI | Required for personal data | Required for opt-out | Required |
| DPIA/Impact assessment | Yes (Art. 35) | Yes (Art. 9) | Risk assessment | Risk analysis |
| Data minimization | Yes (Art. 5) | Yes (Art. 10) | Implied | Yes (Minimum Necessary) |
| Bias examination | Implied | Yes (Art. 10(2)(f)) | N/A | N/A |
