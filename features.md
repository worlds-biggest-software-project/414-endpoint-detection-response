# Endpoint Detection & Response (EDR) for SMBs — Feature & Functionality Survey

> Candidate #414 · Researched: 2026-05-06

This document surveys leading EDR products targeting (or accessible to) small and medium-sized businesses, extracts their feature sets, and identifies cross-cutting themes that inform the scope of an AI-native open-source EDR for SMBs.

---

## Solutions Analysed

| Tool | Type | Licence / Model | URL |
|------|------|-----------------|-----|
| Huntress Managed EDR | Commercial / Managed | Subscription per endpoint | https://www.huntress.com/ |
| SentinelOne Singularity | Commercial SaaS | Tiered per endpoint | https://www.sentinelone.com/ |
| CrowdStrike Falcon Go | Commercial SaaS | Per-endpoint, SMB tier | https://www.crowdstrike.com/products/bundles/falcon-go/ |
| Microsoft Defender for Business | Commercial SaaS | Bundled with M365 Business Premium | https://www.microsoft.com/security/business/endpoint-security/microsoft-defender-business |
| Malwarebytes EDR | Commercial SaaS | Per-endpoint subscription | https://www.malwarebytes.com/business/edr |
| Sophos Intercept X | Commercial SaaS | Per-endpoint, tiered | https://www.sophos.com/en-us/products/endpoint-antivirus |
| Acronis Cyber Protect | Commercial / MSP | Per-endpoint + storage | https://www.acronis.com/en-us/products/cyber-protect/ |
| Bitdefender GravityZone | Commercial SaaS | Per-endpoint | https://www.bitdefender.com/business/products/gravityzone-platform.html |
| Cortex XDR (Palo Alto) | Commercial SaaS | Enterprise-priced; SMB tier | https://www.paloaltonetworks.com/cortex/cortex-xdr |
| Wazuh | Open Source | GPLv2 | https://wazuh.com/ |
| OSSEC | Open Source | GPLv2 | https://www.ossec.net/ |
| LimaCharlie | Commercial / Pay-as-you-go | Usage-based | https://limacharlie.io/ |
| Velociraptor | Open Source | AGPLv3 | https://docs.velociraptor.app/ |

---

## Feature Analysis by Solution

### Huntress Managed EDR

**Core features**
- Lightweight agent for Windows, macOS, with persistent foothold detection
- 24/7 human-led security operations centre (SOC) overlay
- Process and persistence monitoring (registry run keys, scheduled tasks, services)
- Ransomware canaries and behavioural detection
- Plain-English incident reports tailored to non-specialist IT
- Host isolation and assisted remediation
- Microsoft 365 identity threat detection (ITDR add-on)

**Differentiating features**
- Human threat hunters review telemetry, not just AI/automation
- Strong MSP partner channel and multi-tenant console
- "Managed by default" posture aimed squarely at understaffed SMBs

**UX patterns**
- Reports written for IT generalists, not SOC analysts
- Guided remediation with one-click actions
- Minimal configuration; opinionated defaults

**Integration points**
- PSA/RMM integrations (ConnectWise, Datto, Kaseya, NinjaOne)
- SIEM forwarding via syslog/webhook
- Microsoft 365 OAuth integration

**Known gaps**
- Limited Linux coverage historically
- Less customisable detection logic than analyst-driven EDRs
- Pricing opaque without sales contact

**Licence / IP notes**
- Proprietary; commercial subscription. No open-source components offered.

---

### SentinelOne Singularity

**Core features**
- Autonomous AI-driven detection and response (Static AI + Behavioural AI engines)
- Ransomware rollback via Volume Shadow Copy and proprietary journaling
- Cross-platform agent (Windows, macOS, Linux, Kubernetes)
- Storyline correlation: automatically links related events into attack narratives
- Threat-hunting query language (Deep Visibility / PowerQuery)
- Network and USB device control
- Vulnerability and application inventory

**Differentiating features**
- "Storyline" automatic event correlation reduces analyst workload
- One-click rollback of file-system changes after ransomware
- Strong Linux and cloud workload story

**UX patterns**
- Console centred on "incidents" rather than raw alerts
- Guided remediation steps with confidence scoring
- Role-based dashboards (analyst, manager, MSP)

**Integration points**
- Singularity Marketplace with 100+ integrations
- REST API and GraphQL for telemetry export
- SIEM, SOAR, XDR connectors

**Known gaps**
- Higher resource consumption than minimalist agents
- Cost can exceed SMB budgets at lower-volume tiers
- Configuration complexity for custom rules

**Licence / IP notes**
- Proprietary. Several patents around behavioural AI and rollback technology — clean-room implementation required for similar features.

---

### CrowdStrike Falcon Go

**Core features**
- Cloud-native lightweight sensor (~30 MB)
- Next-gen AV with ML-based prevention
- USB device control
- Express Support and guided onboarding for SMBs
- Threat intelligence reports tailored to SMB severity
- Identity protection (in higher tiers)

**Differentiating features**
- Industry-leading threat intelligence feed (Falcon Intel)
- Sensor architecture proven at massive enterprise scale
- Real-time response shell for live forensics

**UX patterns**
- Simplified Falcon Go UI hiding enterprise complexity
- Guided "next best action" prompts

**Integration points**
- CrowdStrike Store (apps and partner integrations)
- API for telemetry, IOCs, and response actions
- Falcon LogScale (CrowdStrike's SIEM) integration

**Known gaps**
- Linux distro coverage variable
- Pricing still high relative to bundled options like Defender for Business
- Real-time response shell can be intimidating for non-specialists

**Licence / IP notes**
- Proprietary. CrowdStrike holds significant patent portfolio around sensor architecture and threat-graph correlation.

---

### Microsoft Defender for Business

**Core features**
- Next-gen antivirus, EDR, and automated investigation
- Threat and vulnerability management
- Attack surface reduction rules
- Web content filtering
- Mobile threat defence (iOS, Android)
- Centralised configuration in Microsoft 365 admin centre

**Differentiating features**
- Bundled with Microsoft 365 Business Premium — effectively "free" for many SMBs
- Deepest possible integration with Windows, Office, Entra ID, and Intune
- Automated investigation and remediation (AIR) with Copilot for Security overlay

**UX patterns**
- Microsoft 365 admin-style UI familiar to SMB admins
- Unified incident view across email, identity, endpoint
- Security recommendations expressed as a single Secure Score

**Integration points**
- Microsoft Sentinel (SIEM), Intune, Entra ID, Purview
- Graph Security API
- Power Automate playbooks

**Known gaps**
- Best-of-breed on Windows; weaker on macOS and Linux
- AIR transparency is limited compared to specialist EDRs
- Tied to Microsoft 365 licensing complexity

**Licence / IP notes**
- Proprietary. Microsoft contributes to standards (MITRE ATT&CK, OpenC2) but core product code is closed.

---

### Malwarebytes EDR

**Core features**
- Endpoint protection plus EDR detection and response
- 72-hour ransomware rollback for Windows
- Brute force and DNS filtering
- Managed Detection and Response (MDR) tier with analyst overlay
- Cloud-managed console (Nebula)

**Differentiating features**
- Strong consumer brand recognition lowers buying friction
- Lightweight agent and simple deployment for non-technical buyers
- Aggressive SMB pricing

**UX patterns**
- Simple wizard-driven onboarding
- Threat cards summarising each detection in plain language
- Default-on protections to reduce configuration burden

**Integration points**
- API access for partners
- Syslog/SIEM forwarding
- ConnectWise, Datto, NinjaOne RMM connectors

**Known gaps**
- Less mature behavioural analytics than CrowdStrike or SentinelOne
- macOS and Linux EDR feature parity still developing
- Limited custom-rule authoring

**Licence / IP notes**
- Proprietary; Malwarebytes ThreatDown brand for business.

---

### Sophos Intercept X with XDR

**Core features**
- Deep learning malware detection and CryptoGuard ransomware protection
- Exploit prevention (60+ techniques) and active adversary mitigations
- XDR data lake with 30–90 day retention
- Cross-product correlation with Sophos Firewall and email
- Managed Detection and Response (MDR) tier
- Live Discover query language for hunts

**Differentiating features**
- Synchronised security with Sophos network products (heartbeat)
- "Active Adversary" mitigations targeting hands-on-keyboard attacks
- MDR strongly positioned for SMBs

**UX patterns**
- Sophos Central single-pane management
- Threat case management with timeline graph
- Pre-built hunt queries for common TTPs

**Integration points**
- Sophos Central API
- Splunk, Microsoft Sentinel, IBM QRadar connectors
- ConnectWise PSA integration

**Known gaps**
- Linux coverage less robust than Windows/macOS
- Live Discover queries require SQL familiarity

**Licence / IP notes**
- Proprietary. Patents around CryptoGuard rollback and deep-learning model architecture.

---

### Acronis Cyber Protect

**Core features**
- Unified backup, anti-malware, EDR, and patch management agent
- Forensic backups (collect evidence as part of normal backup)
- Anti-ransomware with rollback using existing backups
- Vulnerability assessment and patch management
- MSP-native multi-tenant console

**Differentiating features**
- One agent for backup, AV, EDR, patch, and DLP
- Backup-driven rollback rather than dedicated journaling
- Strong MSP RMM integration

**UX patterns**
- MSP-tenant view with per-customer dashboards
- Cyber Protection score across all defensive layers
- Workload-centric (server, workstation, M365 mailbox)

**Integration points**
- Acronis Cyber Cloud APIs
- ConnectWise, Kaseya, N-able, NinjaOne integrations
- M365 and Google Workspace backup connectors

**Known gaps**
- EDR detection sophistication trails specialist vendors
- Console UX criticised for density and speed
- Linux EDR feature parity lags

**Licence / IP notes**
- Proprietary; agent contains both Acronis and licensed third-party engines.

---

### Bitdefender GravityZone Business Security Premium

**Core features**
- HyperDetect tunable ML and anti-exploit
- EDR with incident visualisation
- Risk Analytics for endpoint configuration drift
- Ransomware mitigation with automatic file recovery
- Patch management and full disk encryption modules

**Differentiating features**
- Strong independent test results (AV-Comparatives, MITRE Evals) at competitive price
- Risk Analytics surfaces misconfigurations as risk score
- Modular pricing — pay only for needed capabilities

**UX patterns**
- Centralised GravityZone console with role-based access
- Incident graph visualises attack timeline
- Tunable detection sensitivity (HyperDetect levels)

**Integration points**
- API for telemetry and policy management
- SIEM connectors and CEF/syslog export
- ConnectWise, Datto integrations

**Known gaps**
- Console can be overwhelming for small IT teams
- Fewer guided remediation prompts than Huntress/SentinelOne
- Limited native MDR offering compared to peers

**Licence / IP notes**
- Proprietary. Bitdefender engine is also OEM-licensed inside many third-party products.

---

### Palo Alto Cortex XDR

**Core features**
- Behavioural Threat Protection across endpoint, network, cloud
- Causality chain analysis (Cortex Analytics)
- Identity threat detection
- Managed Threat Hunting service
- Forensics module with full investigation telemetry

**Differentiating features**
- True XDR correlation across endpoint, network firewall, and cloud telemetry
- Behavioural Indicators of Compromise (BIOCs) authoring language
- Strong reputation against advanced persistent threats

**UX patterns**
- Causality View for incident reconstruction
- Investigation queries with saved hunts
- Pre-canned playbooks via Cortex XSOAR

**Integration points**
- XSOAR (SOAR) tightly integrated
- Palo Alto NGFW and Prisma Cloud telemetry sources
- Broad SIEM/IT ecosystem connectors

**Known gaps**
- Pricing typically out of SMB reach
- Steep learning curve
- Best ROI requires Palo Alto network presence

**Licence / IP notes**
- Proprietary. Multiple patents on causality analytics and BIOC engine.

---

### Wazuh

**Core features**
- Open-source XDR/SIEM with endpoint agent
- File integrity monitoring (FIM)
- Log analysis, rootkit detection, and configuration assessment
- MITRE ATT&CK mapping of detections
- Compliance reporting (PCI DSS, HIPAA, NIST 800-53, GDPR)
- Integration with VirusTotal, MISP, AbuseIPDB

**Differentiating features**
- Fully open source under GPLv2
- Combines SIEM, FIM, vulnerability detection, and EDR-like functionality
- Active community and hosted Wazuh Cloud option

**UX patterns**
- OpenSearch/Kibana-derived dashboards
- Rule-based detection with broad ruleset library
- Compliance dashboards out of the box

**Integration points**
- REST API, agent on Windows/macOS/Linux/AIX/Solaris
- Integrates with TheHive, Cortex, Shuffle SOAR
- Active Directory, Office 365 log ingestion

**Known gaps**
- Heavier agent and storage requirements than commercial EDRs
- Detection rules biased toward log-based rather than process behavioural analysis
- Requires tuning expertise; not turnkey for SMBs

**Licence / IP notes**
- GPLv2. Permissive enough to fork; trademark "Wazuh" controlled by Wazuh Inc.

---

### OSSEC

**Core features**
- Host-based intrusion detection (HIDS)
- File integrity monitoring
- Log analysis and active response
- Rootkit detection
- Compliance auditing

**Differentiating features**
- Long-running, mature open-source HIDS
- Lightweight; runs on legacy and embedded systems
- Forms the basis of Wazuh and several commercial offerings

**UX patterns**
- CLI-driven; web UI provided by community projects
- Rule-based with XML configuration

**Integration points**
- Syslog, ELK stack via filebeat
- Active response scripts

**Known gaps**
- No modern process-level behavioural analytics
- Lacks centralised cloud console
- UX dated for SMB use

**Licence / IP notes**
- GPLv2.

---

### LimaCharlie

**Core features**
- Cybersecurity infrastructure as a service: EDR sensor, telemetry pipeline, and detection engine sold separately or together
- Real-time detection and response with D&R rules in YAML
- Multi-platform sensor (Windows, macOS, Linux, ChromeOS)
- One-year telemetry retention by default
- Marketplace of third-party detection content
- Pay-per-event/per-sensor usage pricing

**Differentiating features**
- Composable, API-first model — analysts assemble their own EDR
- Transparent usage-based pricing
- Strong appeal to MSSPs building bespoke service offerings

**UX patterns**
- Web console oriented toward analysts and MSSPs
- D&R rules expressed as YAML, version-controlled
- Live tasking via "Sensor Commands"

**Integration points**
- Webhook outputs to any SIEM or storage
- Native integrations with Tines, Slack, Jira
- Open replicators for telemetry export

**Known gaps**
- Requires analyst expertise to assemble
- Not turnkey; SMBs typically consume via MSSP wrapper
- No managed SOC offering directly

**Licence / IP notes**
- Proprietary platform; many community rules under permissive licences.

---

### Velociraptor

**Core features**
- Endpoint visibility and digital forensics platform
- VQL (Velociraptor Query Language) for fleet-wide hunts
- Live response and triage collection
- Artefact-based detections (community library)
- File integrity, registry, and process monitoring

**Differentiating features**
- Open source under AGPLv3, originally by Rapid7
- Powerful hunt language for fleet-wide queries
- Forensic collection capabilities exceed most commercial EDRs

**UX patterns**
- Web GUI with hunt creation wizards
- VQL editor for advanced users
- Notebook-style investigation workflow

**Integration points**
- Velociraptor server can be self-hosted or cloud-deployed
- Outputs to SIEM via Elastic, Splunk, or generic webhook
- Integrates with TheHive, MISP

**Known gaps**
- No automated response playbooks comparable to commercial EDRs
- Requires DFIR expertise to operate effectively
- AGPLv3 licence may deter some commercial integrations

**Licence / IP notes**
- AGPLv3. Commercial extensions available from Rapid7.

---

## Cross-Cutting Feature Themes

### Table-Stakes Features
- Cross-platform agent (Windows, macOS, Linux) with low CPU/memory footprint
- Process tree, file, registry, and network event capture
- Behavioural detection mapped to MITRE ATT&CK
- Ransomware-specific detection and rollback or recovery
- One-click host isolation preserving management channel
- Cloud-managed multi-tenant console (especially for MSPs)
- Plain-language incident summaries and guided remediation
- Audit logging and tamper resistance of the agent itself
- Telemetry retention of 30+ days for investigation
- Integrations with PSA/RMM tooling (ConnectWise, NinjaOne, Datto, Kaseya)

### Differentiating Features
- Automatic event correlation into "stories" or "incidents" (SentinelOne Storyline, Sophos threat case)
- AI-generated remediation playbooks tailored to each incident
- Identity threat detection layered with endpoint signal
- Decoy/canary techniques for early ransomware detection
- Forensic-grade artefact collection (Velociraptor-class)
- Composable, API-first architecture for MSSP customisation (LimaCharlie)
- Backup-aware rollback that pulls from existing backup snapshots (Acronis)

### Underserved Areas / Opportunities
- Truly open-source EDR with modern behavioural analytics (gap between Wazuh's log-centric model and commercial offerings)
- Transparent, on-prem-deployable detection content for regulated SMBs
- Plain-English LLM-generated incident reports for non-specialist IT (Huntress does this manually with humans; an AI overlay could automate it)
- Affordable Linux-first EDR for SMB Linux server fleets
- Native MSP billing/usage analytics tied to security posture
- Privacy-respecting telemetry where the customer controls data residency

### AI-Augmentation Candidates
- Natural-language alert triage and prioritisation ("explain why this matters")
- LLM-driven remediation guidance personalised to the environment
- Automatic generation of MITRE ATT&CK mappings from raw telemetry
- Anomaly detection over per-host behavioural baselines
- AI authoring of detection rules from analyst hypotheses (text → YAML/Sigma)
- AI-summarised executive reports for SMB owners and cyber-insurance auditors
- Conversational threat-hunting interface ("show me lateral movement candidates")

---

## Legal & IP Summary

EDR is a patent-dense area. SentinelOne, CrowdStrike, Sophos, and Palo Alto each hold patents covering ransomware rollback, causality/storyline correlation, behavioural-AI sensor architectures, and exploit prevention. An open-source AI-native EDR should be designed with patent risk in mind: prefer well-documented prior art (e.g., Sysmon-style telemetry, Sigma rules, MITRE ATT&CK detection content, OSSEC/Wazuh history) and avoid implementations that closely mimic patented techniques without legal review. GPLv2 (Wazuh, OSSEC) and AGPLv3 (Velociraptor) projects can be referenced and extended subject to their copyleft obligations; commercial integrations should be designed so customer code is not pulled under AGPL. Detection content libraries such as Sigma (DRL/MIT-style licence) and the MITRE ATT&CK framework (Apache-2.0-equivalent terms) are safe to build upon. No copyrighted detection content from commercial vendors should be ingested or redistributed.

---

## Recommended Feature Scope

**Must-have (MVP)**
- Lightweight cross-platform agent (Windows, macOS, Linux) with Sysmon/eBPF-derived telemetry
- Cloud-managed multi-tenant console with MSP-friendly tenant model
- Behavioural detection engine driven by Sigma rules and MITRE ATT&CK mappings
- One-click host isolation preserving management channel
- Plain-language LLM-generated incident summaries with recommended actions
- 30-day searchable event timeline per host
- PSA/RMM webhook integrations (ConnectWise, NinjaOne)

**Should-have (v1.1)**
- Ransomware canary files and automatic isolation on tripwire
- File-system journaling with rollback for tripped ransomware events
- Conversational threat-hunting interface backed by an open LLM
- Identity-signal ingestion from Microsoft Entra ID and Google Workspace
- Detection rule authoring from natural language (text → Sigma)
- Compliance-evidence export pack (Cyber Essentials, NIST CSF, HIPAA basic)

**Nice-to-have (backlog)**
- Forensic-grade triage collection (Velociraptor-style artefact packs)
- USB/device control policies
- Vulnerability and patch reporting on top of inventory data
- Cyber-insurance-ready posture scoring and report
- Marketplace of community-contributed detection packs
- On-prem / sovereign-cloud deployment mode for regulated SMBs
