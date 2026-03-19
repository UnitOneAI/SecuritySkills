# License Compatibility Matrix

Extracted from the sbom-analysis SKILL.md.

| License A | License B | Conflict? | Notes |
|---|---|---|---|
| MIT | Apache-2.0 | No | Both permissive; compatible |
| MIT | GPL-3.0-only | Conditional | GPL-3.0 terms apply to combined work if distributed |
| Apache-2.0 | GPL-2.0-only | **Yes** | Apache-2.0 patent clause incompatible with GPL-2.0 |
| LGPL-2.1-or-later | Proprietary | Conditional | LGPL allows linking but requires LGPL component to remain replaceable |
| GPL-3.0-only | Proprietary | **Yes** | Cannot combine GPL-3.0 with proprietary in distributed software |
| AGPL-3.0-only | Any (SaaS) | **Caution** | Network use triggers copyleft; affects SaaS deployments |
| Unknown/NOASSERTION | Any | **Risk** | Cannot determine obligations; requires legal review |

## License Categories

- **Permissive:** MIT, BSD, Apache, ISC
- **Weak Copyleft:** LGPL, MPL, EPL
- **Strong Copyleft:** GPL, AGPL
- **Proprietary:** Commercial licenses
- **No License / NOASSERTION:** Unknown obligations -- FLAG for review
