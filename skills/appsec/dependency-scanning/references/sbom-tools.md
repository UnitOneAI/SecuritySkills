# SBOM Generation Tools by Ecosystem

| Ecosystem | Tool | Command |
|---|---|---|
| Node.js | `@cyclonedx/cyclonedx-npm` | `npx @cyclonedx/cyclonedx-npm --output-file sbom.json` |
| Python | `cyclonedx-bom` | `cyclonedx-py requirements -i requirements.txt -o sbom.json` |
| Go | `cyclonedx-gomod` | `cyclonedx-gomod mod -json -output sbom.json` |
| Java/Maven | `cyclonedx-maven-plugin` | `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom` |
| Rust | `cargo-cyclonedx` | `cargo cyclonedx --format json` |
| Multi-ecosystem | `syft` (Anchore) | `syft dir:. -o cyclonedx-json > sbom.json` |
| Multi-ecosystem | `trivy` (Aqua) | `trivy fs --format cyclonedx -o sbom.json .` |

## Recommended SBOM Formats

| Format | Specification | Best For |
|---|---|---|
| CycloneDX | [cyclonedx.org/specification](https://cyclonedx.org/specification/overview/) | Security-focused analysis, VEX integration, vulnerability tracking |
| SPDX | [spdx.github.io/spdx-spec](https://spdx.github.io/spdx-spec/v2.3/) | License compliance, provenance, regulatory requirements (e.g., EO 14028) |
