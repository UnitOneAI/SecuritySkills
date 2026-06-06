# XXE Parser Edge Cases

These fixtures verify that `secure-code-review` records parser/source/resolver evidence before reporting or dismissing CWE-611 findings.

```yaml
case_id: XXE-01
title: Python defusedxml parser is a benign false-positive guardrail
language: Python
input_source: uploaded metadata XML
parser:
  library: defusedxml.ElementTree
  function: fromstring
settings:
  external_entities: disabled_by_library
  dtd_loading: disabled_by_library
  network_access: disabled_by_library
expected_classification:
  status: False positive
  reason: "defusedxml rejects dangerous XML features by design."
```

```yaml
case_id: XXE-02
title: Java DocumentBuilderFactory uses unsafe defaults on request body XML
language: Java
input_source: HTTP request body
parser:
  library: DocumentBuilderFactory
  features:
    disallow_doctype_decl: missing
    external_general_entities: missing
    external_parameter_entities: missing
    xinclude_aware: default
resolver: default
expected_classification:
  status: Vulnerable
  severity: High
  cwe: CWE-611
  reason: "Untrusted XML reaches a parser without DTD/entity/resolver hardening."
```

```yaml
case_id: XXE-03
title: Java SchemaFactory fetches external schema despite parser entity hardening
language: Java
input_source: partner XML feed
parser:
  document_builder:
    external_entities: disabled
  schema_factory:
    access_external_schema: unrestricted
    schema_source: request_controlled
expected_classification:
  status: Vulnerable
  severity: High
  cwe: CWE-611
  reason: "External schema resolution can perform network/file access even when document parser entities are disabled."
```

```yaml
case_id: XXE-04
title: .NET XmlReaderSettings prohibit DTD and resolver access
language: C#
input_source: SAML metadata upload
parser:
  library: XmlReader
  settings:
    dtd_processing: Prohibit
    xml_resolver: null
    max_characters_from_entities: 0
    max_characters_in_document: 1048576
expected_classification:
  status: Benign / hardened
  reason: ".NET parser settings prohibit DTD processing and resolver access with size limits."
```

```yaml
case_id: XXE-05
title: PHP DOMDocument enables entity substitution and DTD loading
language: PHP
input_source: uploaded invoice XML
parser:
  library: DOMDocument
  flags:
    - LIBXML_NOENT
    - LIBXML_DTDLOAD
resolver:
  network_access: allowed
expected_classification:
  status: Vulnerable
  severity: High
  cwe: CWE-611
  reason: "Entity substitution and DTD loading are enabled for untrusted XML."
```

```yaml
case_id: XXE-06
title: Ruby Nokogiri legacy DTD exception has allowlist and isolation
language: Ruby
input_source: trusted bank partner feed
parser:
  library: Nokogiri::XML
  dtd_required: true
legacy_exception:
  source_trust: mutual_tls_partner
  resolver_allowlist:
    - https://schemas.partner.example/payments.dtd
  network_isolation: egress_allowlist
  size_limit_bytes: 1048576
  monitoring: enabled
expected_classification:
  status: Documented exception
  reason: "DTD use is constrained by source trust, resolver allowlist, network isolation, and limits."
```

```yaml
case_id: XXE-07
title: Node XML parser rejects DOCTYPE and external entity declarations
language: JavaScript
input_source: SOAP webhook
parser:
  library: fast-xml-parser
  doctype_handling: rejected
  external_entities: unsupported
  size_limit_bytes: 524288
  tests:
    malicious_doctype_fixture: rejected
expected_classification:
  status: Benign / hardened
  reason: "Parser rejects DOCTYPE/entity payloads and has size-limit test evidence."
```
