# Standards & API Reference

> Project: Endpoint Detection & Response (EDR) for SMBs · Generated: 2026-05-06

This document compiles industry standards, specifications, and developer documentation links relevant to building a modern AI-native EDR platform for small and medium-sized businesses.

---

## Industry Standards & Specifications

### ISO Standards

- **ISO/IEC 27001:2022 — Information Security Management Systems**
  https://www.iso.org/standard/27001
  Defines requirements for an ISMS. EDR controls (A.8.7 malware protection, A.8.16 monitoring activities) directly support compliance.

- **ISO/IEC 27002:2022 — Information Security Controls**
  https://www.iso.org/standard/75652.html
  Companion guidance to 27001; specifies operational controls including endpoint monitoring and incident response.

- **ISO/IEC 27035-1:2023 — Incident Management Principles**
  https://www.iso.org/standard/78973.html
  Frames the incident-response lifecycle that an EDR's response workflows must support.

- **ISO/IEC 27037:2012 — Digital Evidence Identification, Collection, and Preservation**
  https://www.iso.org/standard/44381.html
  Sets requirements for forensic-grade evidence handling — relevant to EDR triage collection and timeline preservation.

- **ISO/IEC 27040:2024 — Storage Security**
  https://www.iso.org/standard/80194.html
  Applies to retention and protection of EDR telemetry stored long-term.

- **ISO/IEC 27701:2019 — Privacy Information Management**
  https://www.iso.org/standard/71670.html
  Extends 27001 with privacy controls; relevant when EDR processes personal data from endpoints.

### W3C & IETF Standards

- **RFC 8259 — JavaScript Object Notation (JSON)**
  https://www.rfc-editor.org/rfc/rfc8259
  Default wire format for telemetry, rules, and API responses.

- **RFC 7519 — JSON Web Token (JWT)**
  https://www.rfc-editor.org/rfc/rfc7519
  Token format for stateless authentication of agents and consoles.

- **RFC 6749 / RFC 9700 — OAuth 2.0 Authorization Framework and Best Current Practice**
  https://www.rfc-editor.org/rfc/rfc6749 ; https://www.rfc-editor.org/rfc/rfc9700
  For console SSO and integration with identity providers.

- **RFC 9110 / 9111 / 9112 — HTTP Semantics, Caching, and HTTP/1.1**
  https://www.rfc-editor.org/rfc/rfc9110
  Foundation for the management API.

- **RFC 9293 — Transmission Control Protocol**
  https://www.rfc-editor.org/rfc/rfc9293
  Reference for agent transport layer.

- **RFC 8446 — TLS 1.3**
  https://www.rfc-editor.org/rfc/rfc8446
  Mandatory for agent-to-cloud communications.

- **RFC 5424 — The Syslog Protocol**
  https://www.rfc-editor.org/rfc/rfc5424
  Standard log forwarding format for SIEM integration.

- **RFC 8949 — Concise Binary Object Representation (CBOR)**
  https://www.rfc-editor.org/rfc/rfc8949
  Compact binary encoding option for telemetry from constrained agents.

### Data Model & API Specifications

- **OpenAPI Specification 3.1**
  https://spec.openapis.org/oas/v3.1.0
  Industry standard for REST API description and SDK generation.

- **AsyncAPI 3.0**
  https://www.asyncapi.com/docs/reference/specification/v3.0.0
  Specification for event-driven APIs — applicable to agent telemetry streams.

- **JSON Schema 2020-12**
  https://json-schema.org/specification.html
  Validation of telemetry events, detection rules, and API payloads.

- **GraphQL (October 2021 spec)**
  https://spec.graphql.org/October2021/
  Used by SentinelOne and others for analyst query interfaces.

- **Protocol Buffers (proto3)**
  https://protobuf.dev/programming-guides/proto3/
  Wire format option for high-throughput agent telemetry.

- **OpenTelemetry — Logs, Metrics, and Traces**
  https://opentelemetry.io/docs/specs/otel/
  Vendor-neutral telemetry pipelines; OTel logs SDK can carry security events.

- **OCSF — Open Cybersecurity Schema Framework**
  https://schema.ocsf.io/
  Open security event taxonomy adopted by AWS, Splunk, CrowdStrike, IBM and others. Strong candidate for EDR event schema interoperability.

- **STIX 2.1 — Structured Threat Information Expression**
  https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
  OASIS standard for threat-intelligence sharing.

- **TAXII 2.1 — Trusted Automated Exchange of Indicator Information**
  https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
  Transport for STIX feeds.

- **OpenC2 — Open Command and Control**
  https://openc2.org/
  OASIS standard for issuing structured response actions (isolate, contain, etc.) across security tools.

- **CACAO 2.0 — Collaborative Automated Course of Action Operations**
  https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html
  Standardised playbook format for automated incident response.

- **Sigma — Generic Signature Format for SIEM/EDR Detections**
  https://github.com/SigmaHQ/sigma
  De-facto open detection-rule format with conversion to many backends.

- **YARA**
  https://yara.readthedocs.io/
  Pattern-matching standard for malware classification and file/memory triage.

- **MITRE ATT&CK**
  https://attack.mitre.org/
  Adversary tactic-and-technique knowledge base used by virtually every EDR.

- **MITRE D3FEND**
  https://d3fend.mitre.org/
  Knowledge graph of defensive countermeasures complementing ATT&CK.

- **MITRE CAR — Cyber Analytics Repository**
  https://car.mitre.org/
  Reference behavioural analytics for ATT&CK techniques.

### Security & Authentication Standards

- **NIST SP 800-53 Rev. 5 — Security and Privacy Controls**
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  Baseline US federal control catalogue; many SMBs serving the US public sector inherit these.

- **NIST SP 800-61 Rev. 3 — Computer Security Incident Handling Guide**
  https://csrc.nist.gov/pubs/sp/800/61/r3/final
  Authoritative incident-response process model.

- **NIST SP 800-86 — Forensic Techniques in Incident Response**
  https://csrc.nist.gov/pubs/sp/800/86/final
  Forensic procedures relevant to triage and evidence preservation features.

- **NIST SP 800-92 Rev. 1 — Guide to Computer Security Log Management**
  https://csrc.nist.gov/pubs/sp/800/92/r1/ipd
  Log-management guidance applicable to EDR retention design.

- **NIST Cybersecurity Framework 2.0**
  https://www.nist.gov/cyberframework
  Function-based control framework (Govern, Identify, Protect, Detect, Respond, Recover) used to position EDR capabilities.

- **OWASP API Security Top 10 (2023)**
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  Required reading for the management API surface.

- **OWASP ASVS 4.0**
  https://owasp.org/www-project-application-security-verification-standard/
  Verification standard for the EDR console web application.

- **OpenID Connect Core 1.0**
  https://openid.net/specs/openid-connect-core-1_0.html
  Authentication layer over OAuth 2.0 for console SSO.

- **SAML 2.0 (OASIS)**
  http://docs.oasis-open.org/security/saml/v2.0/saml-2.0-os.zip
  Required for many enterprise/MSP IdP deployments.

- **FIDO2 / WebAuthn Level 3**
  https://www.w3.org/TR/webauthn-3/
  Phishing-resistant console authentication.

- **mTLS (RFC 8705)**
  https://www.rfc-editor.org/rfc/rfc8705
  Mutual TLS for agent-to-cloud authentication.

- **CIS Critical Security Controls v8**
  https://www.cisecurity.org/controls/v8
  SMB-friendly control framework; Controls 8 (audit logs), 10 (malware defences) and 13 (network monitoring) directly map to EDR functions.

- **PCI DSS v4.0**
  https://www.pcisecuritystandards.org/document_library/
  Required for SMBs handling card data; section 5 mandates EDR-class detection.

- **HIPAA Security Rule (45 CFR Part 164, Subpart C)**
  https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
  Safeguard requirements applicable to healthcare SMBs.

- **GDPR (EU 2016/679)**
  https://eur-lex.europa.eu/eli/reg/2016/679/oj
  Personal-data implications of EDR telemetry and retention.

### MCP Server Specifications

- **Model Context Protocol (Anthropic)**
  https://modelcontextprotocol.io/
  Open protocol for tool-use by LLMs. An EDR MCP server could expose detection queries, isolate-host actions, and timeline lookups to AI assistants under audit.

- **MCP Specification (current)**
  https://modelcontextprotocol.io/specification
  Reference for resource, tool, prompt, and elicitation semantics — useful for LLM-augmented analyst workflows.

- **MCP Servers Reference Implementations**
  https://github.com/modelcontextprotocol/servers
  Patterns for safe, scoped tool exposure that an EDR MCP server should follow.

---

## Similar Products — Developer Documentation & APIs

### CrowdStrike Falcon
- **Description:** Cloud-native EDR/XDR platform with broad SMB-to-enterprise reach.
- **API Documentation:** https://falcon.crowdstrike.com/documentation/page/falconpy
- **SDKs/Libraries:** Python (https://github.com/CrowdStrike/falconpy), Go (https://github.com/crowdstrike/gofalcon), PowerShell (https://github.com/crowdstrike/psfalcon)
- **Developer Guide:** https://www.crowdstrike.com/developers/
- **Standards:** REST/JSON, OpenAPI 3
- **Authentication:** OAuth 2.0 client credentials

### SentinelOne Singularity
- **Description:** Autonomous AI-driven EDR/XDR with cross-platform coverage.
- **API Documentation:** https://usea1-partners.sentinelone.net/api-doc/overview
- **SDKs/Libraries:** Community Python clients; official Terraform provider (https://registry.terraform.io/providers/SentinelOne/sentinelone)
- **Developer Guide:** https://www.sentinelone.com/platform/singularity-marketplace/
- **Standards:** REST/JSON, GraphQL (Deep Visibility / PowerQuery)
- **Authentication:** API token (per-user / service)

### Microsoft Defender for Endpoint
- **Description:** Microsoft's enterprise/SMB EDR delivered via Defender for Business and Defender for Endpoint plans.
- **API Documentation:** https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list
- **SDKs/Libraries:** Microsoft Graph SDKs (.NET, Java, JavaScript, Python, Go, PHP)
- **Developer Guide:** https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview
- **Standards:** REST/JSON, OData; OCSF mappings published
- **Authentication:** OAuth 2.0 / Microsoft Entra ID, with delegated and application permissions

### Sophos Central
- **Description:** Multi-product cloud security console including Intercept X EDR/XDR.
- **API Documentation:** https://developer.sophos.com/docs/common-v1/1/overview
- **SDKs/Libraries:** Community Python wrappers; Sophos Factory for automation
- **Developer Guide:** https://developer.sophos.com/getting-started
- **Standards:** REST/JSON, OpenAPI
- **Authentication:** OAuth 2.0 client credentials

### Palo Alto Cortex XDR
- **Description:** XDR platform combining endpoint, network, and cloud telemetry.
- **API Documentation:** https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-API-Reference
- **SDKs/Libraries:** Python via Cortex XSOAR content packs
- **Developer Guide:** https://docs-cortex.paloaltonetworks.com/p/XDR
- **Standards:** REST/JSON
- **Authentication:** API key + key ID (Standard or Advanced)

### Huntress Managed EDR
- **Description:** Managed EDR with human SOC overlay focused on SMBs and MSPs.
- **API Documentation:** https://api.huntress.io/docs
- **SDKs/Libraries:** None official; community wrappers exist
- **Developer Guide:** https://support.huntress.io/hc/en-us/sections/360010198391
- **Standards:** REST/JSON
- **Authentication:** API key (basic-auth header)

### Bitdefender GravityZone
- **Description:** Modular endpoint security platform for SMB to enterprise.
- **API Documentation:** https://www.bitdefender.com/business/support/en/77209-125277-public-api.html
- **SDKs/Libraries:** Community PHP and Python wrappers
- **Developer Guide:** https://www.bitdefender.com/business/support/en/77209-125277-public-api.html
- **Standards:** JSON-RPC 2.0
- **Authentication:** API key (HTTP basic)

### Malwarebytes ThreatDown / Nebula
- **Description:** SMB-focused endpoint protection with EDR and MDR tiers.
- **API Documentation:** https://api.malwarebytes.com/nebula/v1/swagger-ui/index.html
- **SDKs/Libraries:** Community wrappers
- **Developer Guide:** https://service.malwarebytes.com/hc/en-us/articles/4413802190995
- **Standards:** REST/JSON, OpenAPI
- **Authentication:** OAuth 2.0 client credentials

### LimaCharlie
- **Description:** API-first cybersecurity infrastructure with sensor, telemetry, and detection-engine primitives.
- **API Documentation:** https://docs.limacharlie.io/apidocs/introduction
- **SDKs/Libraries:** Python (https://github.com/refractionPOINT/python-limacharlie), Go SDK
- **Developer Guide:** https://docs.limacharlie.io/docs
- **Standards:** REST/JSON; YAML detection-and-response rules
- **Authentication:** JWT issued from API keys

### Wazuh
- **Description:** Open-source XDR/SIEM with endpoint agent and broad detection ruleset.
- **API Documentation:** https://documentation.wazuh.com/current/user-manual/api/index.html
- **SDKs/Libraries:** Python (https://github.com/wazuh/wazuh-api-python); REST clients
- **Developer Guide:** https://documentation.wazuh.com/current/development/index.html
- **Standards:** REST/JSON, OpenAPI 3
- **Authentication:** JWT (issued via basic auth)

### Velociraptor
- **Description:** Open-source endpoint visibility and DFIR platform.
- **API Documentation:** https://docs.velociraptor.app/docs/server_automation/server_api/
- **SDKs/Libraries:** Python (https://github.com/Velocidex/pyvelociraptor), Go API
- **Developer Guide:** https://docs.velociraptor.app/docs/
- **Standards:** gRPC API; VQL query language
- **Authentication:** mTLS client certificates

### Acronis Cyber Protect Cloud
- **Description:** Unified backup, security, and endpoint management for MSPs.
- **API Documentation:** https://developer.acronis.com/doc/
- **SDKs/Libraries:** Community wrappers
- **Developer Guide:** https://developer.acronis.com/
- **Standards:** REST/JSON, OpenAPI
- **Authentication:** OAuth 2.0 client credentials

### Elastic Security (Elastic Defend)
- **Description:** EDR built on the Elastic Stack with open detection content.
- **API Documentation:** https://www.elastic.co/guide/en/security/current/security-apis.html
- **SDKs/Libraries:** Elasticsearch language clients (Python, Go, Java, JavaScript, .NET, Ruby, PHP)
- **Developer Guide:** https://www.elastic.co/guide/en/security/current/get-started-with-elastic-security.html
- **Standards:** REST/JSON; ECS (Elastic Common Schema), OCSF mappings
- **Authentication:** API key, basic auth, OAuth 2.0 via Kibana

---

## Notes

The EDR industry is converging on several open standards that an AI-native open-source platform should adopt from day one to maximise interoperability:

- **OCSF** is rapidly becoming the lingua franca for security event schemas, replacing vendor-specific JSON shapes. Designing the agent's event model around OCSF (with extensions where needed) reduces integration friction with SIEMs and downstream tooling.
- **Sigma** and **MITRE ATT&CK** together form the open detection-content baseline; rules authored in Sigma can be cross-compiled to many backends and aligned to ATT&CK techniques without licensing concerns.
- **OpenC2** and **CACAO** are emerging as the response-action and playbook standards, providing a path away from proprietary SOAR formats.
- **MCP** is an emerging standard for safely exposing tools to LLM-driven analyst workflows; an EDR MCP server is a credible AI-native differentiator and an area where standards are still being shaped.

Patent-dense areas (ransomware rollback via journaling, storyline-style automatic incident correlation, deep-learning-based malware classifiers) require legal review before implementation and should be approached via well-documented prior-art techniques (file backups, graph-based event correlation over OCSF, Sigma + YARA rule chaining) rather than clean-room copies of proprietary methods.
