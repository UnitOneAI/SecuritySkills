# Vulnerable: Generic VEX Component Name

## Scenario

A VEX statement marks `log4j` as not affected, but the SBOM contains multiple similarly named components with different versions and package identities.

## Sample Evidence

```text
vex_cve=CVE-2021-44228
vex_status=not_affected
vex_component=log4j
vex_binding=bom-ref missing, purl missing, cpe missing, version_range missing
sbom_component_1=bom-ref=log4j-core-2.14.1 purl=pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 scope=runtime
sbom_component_2=bom-ref=log4j-api-2.17.2 purl=pkg:maven/org.apache.logging.log4j/log4j-api@2.17.2 scope=runtime
```

## Expected Handling

- Do not apply a generic VEX status to multiple SBOM components by display name alone.
- Require bom-ref, purl, CPE, version range, ecosystem, or another exact binding key.
- Mark the VEX correlation as ambiguous until component identity is proven.
