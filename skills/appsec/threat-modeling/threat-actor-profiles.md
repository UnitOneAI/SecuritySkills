# Threat Actor Profiles — Detailed Reference

Supporting file for `SKILL.md` — provides expanded threat actor profiles with
TTPs, indicators, and modeling guidance.

## Nation-State APT

- **Capabilities:** Custom zero-days, firmware implants, supply chain infiltration, multi-year campaigns, unlimited budget
- **Motivation:** Espionage (IP theft, surveillance), pre-positioning for conflict, economic advantage
- **Access Level:** Initial access via supply chain or spear-phishing; targets admin/root persistently
- **Persistence:** Extremely high — multi-year dwell time (median 200+ days), kernel-level rootkits, firmware implants
- **Primary STRIDE Targets:** Spoofing (credential theft), Information Disclosure (exfiltration), Elevation of Privilege (lateral movement)
- **Example TTPs:** T1195 Supply Chain Compromise, T1059 Command and Scripting Interpreter, T1071 Application Layer Protocol (C2), T1027 Obfuscated Files, T1556 Modify Authentication Process
- **Modeling Guidance:** Assume attackers can bypass any single control. Model defense-in-depth with assumption of breach. Prioritize detection and containment over prevention alone.

## Organized Cybercrime

- **Capabilities:** Ransomware-as-a-Service, credential markets, exploit brokers, social engineering at scale
- **Motivation:** Financial gain — ransomware, fraud, data sale, cryptojacking
- **Access Level:** Initial access via phishing, credential stuffing, or purchased access; escalates to domain admin
- **Persistence:** Medium — maintains access until monetized, typically weeks to months
- **Primary STRIDE Targets:** Information Disclosure (data theft for sale), Denial of Service (ransomware), Tampering (data encryption)
- **Example TTPs:** T1486 Data Encrypted for Impact, T1078 Valid Accounts, T1566 Phishing, T1021 Remote Services, T1490 Inhibit System Recovery
- **Modeling Guidance:** Focus on backup integrity, network segmentation, and rapid detection of lateral movement. Model ransomware scenarios explicitly.

## Malicious Insider

- **Capabilities:** Legitimate credentials, knowledge of internal systems, ability to bypass network-level controls
- **Motivation:** Financial gain, revenge, ideological, coercion by external actor
- **Access Level:** Already authenticated; may have elevated privileges based on role
- **Persistence:** N/A — already persistent by virtue of employment; risk continues until access revoked
- **Primary STRIDE Targets:** Information Disclosure (data exfiltration), Tampering (sabotage), Repudiation (covering tracks)
- **Example TTPs:** T1530 Data from Cloud Storage, T1567 Exfiltration Over Web Service, T1070 Indicator Removal, T1565 Data Manipulation
- **Modeling Guidance:** Model least-privilege violations, data loss prevention gaps, and audit log integrity. Assume the insider knows which logs exist and how to avoid them.

## Hacktivist / Ideological

- **Capabilities:** Moderate — DDoS tools, web defacement, credential dumps, public exploit code
- **Motivation:** Political, social, or ideological statement; embarrassment of target organization
- **Access Level:** External; targets public-facing systems preferentially
- **Persistence:** Low — goal is visible impact, not long-term access
- **Primary STRIDE Targets:** Denial of Service (DDoS), Tampering (defacement), Information Disclosure (doxxing, data dumps)
- **Example TTPs:** T1498 Network Denial of Service, T1491 Defacement, T1530 Data from Cloud Storage, T1190 Exploit Public-Facing Application
- **Modeling Guidance:** Prioritize availability controls and public-facing attack surface hardening. Model reputational impact scenarios.

## Script Kiddie / Opportunistic

- **Capabilities:** Low — relies on public exploits, automated scanners, default credentials
- **Motivation:** Curiosity, bragging rights, low-effort financial gain (cryptomining)
- **Access Level:** External only; targets low-hanging fruit
- **Persistence:** Very low — moves to easier targets if initial attack fails
- **Primary STRIDE Targets:** Spoofing (default creds), Elevation of Privilege (known CVEs), Denial of Service (booter services)
- **Example TTPs:** T1078 Valid Accounts (default), T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter
- **Modeling Guidance:** Baseline hygiene — patch management, credential rotation, disable defaults. If these actors succeed, foundational controls are missing.

## Compromised Supply Chain

- **Capabilities:** Inherits trust of the compromised vendor; code-level access via packages, SDKs, or CI/CD integrations
- **Motivation:** Varies — may be nation-state using vendor as vector, or financially motivated compromise of a package maintainer
- **Access Level:** Runs within application context; may have build-time or runtime privileges
- **Persistence:** High — persists as long as the compromised dependency is in use
- **Primary STRIDE Targets:** Tampering (code injection), Elevation of Privilege (runtime context), Information Disclosure (credential harvesting)
- **Example TTPs:** T1195.001 Supply Chain Compromise: Compromise Software Dependencies, T1195.002 Compromise Software Supply Chain, T1059 Command and Scripting Interpreter, T1041 Exfiltration Over C2 Channel
- **Modeling Guidance:** Model SBOM completeness, dependency pinning, signature verification, and build provenance. Assume any third-party code could be compromised.
