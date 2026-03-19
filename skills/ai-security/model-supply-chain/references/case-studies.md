# Model Supply Chain — Case Studies

## PoisonGPT (Mithril Security, 2023)

Researchers at Mithril Security demonstrated that a model on Hugging Face Hub could be surgically modified to spread targeted misinformation while maintaining normal performance on standard benchmarks. They took GPT-J-6B, used the ROME (Rank-One Model Editing) technique to alter specific factual associations, and uploaded the modified model under a name resembling a legitimate organization. Users downloading the model by name would receive the poisoned version with no indication of tampering. The attack succeeded because Hugging Face Hub at the time did not enforce model signing, and most download code did not verify checksums against a trusted source. This demonstrated that model provenance verification is not optional -- it is the first line of defense against supply chain compromise.

**Reference:** https://blog.mithrilsecurity.io/poisongpt-how-we-hid-a-lobotomized-llm-on-hugging-face-to-spread-fake-news/

## ShadowRay (Oligo Security, 2024)

Researchers discovered active exploitation of CVE-2023-48022 in Ray, a popular framework used for distributed ML training and inference. The vulnerability allowed unauthenticated remote code execution on Ray clusters. Attackers compromised production ML infrastructure at multiple organizations, stealing credentials, deploying cryptominers, and accessing training data. The attack surface existed because Ray's dashboard API was exposed without authentication by default, and organizations running Ray clusters for model serving did not apply network-level access controls. This case demonstrates that inference infrastructure dependencies are high-value targets and must be treated with the same rigor as application dependencies.

**Reference:** https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild

## CoLoRA Adapter Composition Attack (Ding, 2026)

Individual LoRA/PEFT adapters may appear benign in isolation but compose to bypass safety alignment (CoLoRA attack). Single-module scanning is insufficient -- test adapter compositions before production deployment. When multiple adapters are merged or stacked, the merged model's safety alignment must be evaluated, not just each adapter independently.

**Reference:** arXiv:2603.12681

## Foundational Research

- Mitchell, M. et al. "Model Cards for Model Reporting" (2019) -- arXiv:1810.03993
- Gu, T. et al. "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain" (2017) -- arXiv:1708.06733
- Hubinger, E. et al. "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training" (2024) -- arXiv:2401.05566
