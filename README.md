# Endpoint Detection & Response

> Part of the [worlds-biggest-software-project](https://github.com/worlds-biggest-software-project) initiative.
>
> An AI-native, open-source EDR platform that gives small and medium-sized businesses enterprise-grade endpoint security without enterprise-grade budgets or staffing requirements.

Endpoint Detection & Response (EDR) monitors laptops, desktops, servers, and mobile endpoints for signs of malicious activity, enables rapid investigation of suspicious behaviour, and provides mechanisms to contain and remediate threats. This project targets SMBs -- organisations that increasingly face ransomware campaigns and cyber-insurance mandates but lack dedicated security operations teams. By combining lightweight telemetry collection with LLM-generated incident summaries and guided remediation, the platform closes the gap between heavyweight commercial EDR and the log-centric open-source alternatives available today.

---

## Why Endpoint Detection & Response?

- **SMBs are under-served by current options.** Enterprise EDR tools (CrowdStrike, Palo Alto Cortex XDR) are priced and designed for organisations with full-time SOC analysts. SMBs pay enterprise rates or go without.
- **Open-source alternatives lack modern behavioural detection.** Wazuh and OSSEC provide log-based analysis and file integrity monitoring, but neither offers the process-level behavioural analytics or automated response that modern attacks demand.
- **Managed services are expensive and opaque.** Huntress and SentinelOne offer strong managed detection, but pricing requires sales conversations and lock-in to proprietary platforms with no self-hosted option.
- **Ransomware increasingly targets SMBs.** Attackers deliberately target smaller organisations because their defences lag enterprise standards, yet cyber insurers now mandate EDR coverage as a baseline for policy eligibility.
- **Remote work has dissolved the perimeter.** Endpoints are distributed beyond corporate networks, eliminating the protection previously offered by network-layer controls and making endpoint-level detection essential.

---

## Key Features

### Behavioural Detection & Telemetry

- Lightweight cross-platform agent (Windows, macOS, Linux) built on Sysmon and eBPF-derived telemetry
- Process tree, file system, registry, and network event capture
- Behavioural detection engine driven by Sigma rules and MITRE ATT&CK mappings
- Ransomware canary files and tripwire-based automatic isolation
- Anomaly detection over per-host behavioural baselines

### Automated Response & Containment

- One-click host isolation preserving the management channel for continued investigation
- Automated process killing, file quarantine, and file-system rollback on ransomware detection
- File-system journaling with rollback for tripped ransomware events
- Configurable confidence thresholds for automated versus analyst-approved responses

### Investigation & Forensics

- 30-day searchable event timeline per host with tamper-evident logging
- Automatic event correlation into attack narratives (incident storylines)
- Forensic-grade triage collection with artefact packs
- Conversational threat-hunting interface backed by an open LLM

### AI-Powered Incident Management

- Plain-language LLM-generated incident summaries with recommended remediation actions
- AI-authored detection rules from analyst hypotheses (natural language to Sigma)
- AI-summarised executive reports for SMB owners and cyber-insurance auditors
- Automatic generation of MITRE ATT&CK mappings from raw telemetry

### Multi-Tenant Management & Integrations

- Cloud-managed multi-tenant console designed for MSP workflows
- PSA/RMM integrations (ConnectWise, NinjaOne, Datto, Kaseya)
- Identity-signal ingestion from Microsoft Entra ID and Google Workspace
- SIEM forwarding via syslog, webhook, and standard connectors
- Compliance-evidence export packs (Cyber Essentials, NIST CSF, HIPAA)

---

## AI-Native Advantage

Unlike incumbents that bolt AI onto legacy detection engines, this project builds AI into the core workflow. LLM-generated incident reports replace the human threat-hunter overlay that vendors like Huntress provide manually -- delivering plain-English remediation guidance at machine speed rather than analyst speed. Natural-language threat hunting lets IT generalists query endpoint telemetry conversationally instead of learning vendor-specific query languages (SentinelOne's PowerQuery, Sophos's Live Discover SQL, Velociraptor's VQL). AI-driven detection-rule authoring lowers the barrier from writing Sigma YAML to describing a hypothesis in plain text, making custom detection accessible to teams without dedicated security engineers.

---

## Tech Stack & Deployment

The platform is designed for cloud-managed deployment with an MSP-native multi-tenant architecture. A lightweight agent collects telemetry using Sysmon on Windows and eBPF on Linux, keeping CPU and memory impact low enough for older SMB hardware. Detection content builds on established open standards: Sigma rules for detection logic, MITRE ATT&CK for technique classification, and syslog/CEF for telemetry export. A sovereign-cloud or on-premises deployment mode is planned for regulated SMBs that require data residency control.

---

## Market Context

The SMB endpoint security market is driven by converging forces: targeted ransomware campaigns, cyber-insurance EDR mandates, and the dissolution of the corporate network perimeter through remote work. Commercial EDR pricing ranges from opaque per-endpoint subscriptions (Huntress, CrowdStrike Falcon Go) to bundled offerings like Microsoft Defender for Business, while open-source options (Wazuh, OSSEC) lack the behavioural detection and usability that SMBs need. The primary buyers are managed service providers (MSPs) serving SMB clients and in-house IT generalists at organisations with 10-500 endpoints.

---

## Project Status

> This project is in the **research and specification phase**.  
> Contributions, feedback, and domain expertise are welcome.

---

## Contributing

We welcome contributions from developers, domain experts, and potential users.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important:** All contributions must be your own original work or clearly attributed
open-source material with a compatible licence. Copyright infringement and licence
violations will not be tolerated and will result in immediate removal of the offending
contribution. If you are unsure whether a piece of code, text, or other material is
safe to contribute, open an issue and ask before submitting.

---

## Licence

Licence to be determined. See [discussion](#) for context.
