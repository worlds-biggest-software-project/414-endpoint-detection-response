# Endpoint Detection & Response (EDR) for SMBs — Phased Development Plan

> Project: 414-endpoint-detection-response · Created: 2026-05-30
> Purpose: Provide sufficient detail for Claude Code (Opus) to implement each phase end-to-end.

This plan synthesizes `research.md`, `features.md`, `standards.md`, `README.md`, and the four `data-model-suggestion-*.md` files into concrete technology decisions, an architecture, and a sequence of buildable phases.

**Core value proposition.** An AI-native, open-source EDR platform giving SMBs and the MSPs that serve them enterprise-grade endpoint detection, investigation, and response — without enterprise budgets or a dedicated SOC. A lightweight cross-platform agent streams OCSF-formatted telemetry to a cloud-managed multi-tenant console; a Sigma-driven behavioural detection engine raises alerts mapped to MITRE ATT&CK; an LLM turns raw incidents into plain-English summaries and guided remediation; analysts (or IT generalists) can isolate hosts, kill processes, quarantine files, and roll back ransomware with one click.

**Primary personas.**
- **MSP technician** — manages many SMB tenants from one console; needs multi-tenancy, opinionated defaults, low alert noise, PSA/RMM integration.
- **In-house IT generalist** (10–500 endpoints) — not a security specialist; needs plain-language incidents and one-click response.
- **SMB owner / cyber-insurance auditor** — consumes executive reports and compliance evidence.

**Key differentiators (AI-native, per `research.md`/`features.md`).** LLM-generated incident reports replacing a human threat-hunter overlay; natural-language threat hunting (no vendor query language); natural-language → Sigma rule authoring; automatic MITRE ATT&CK mapping; truly open-source modern behavioural analytics (the gap between Wazuh's log-centric model and commercial EDR).

**Deployment model.** Cloud-managed multi-tenant SaaS first, packaged as Docker Compose for self-hosting; sovereign-cloud / on-prem mode is a later-phase concern. Agent ships as native binaries for Windows, macOS, Linux.

**Patent caution (from `features.md` Legal & IP Summary).** Ransomware rollback, storyline correlation, and deep-learning malware classifiers are patent-dense. This plan implements only well-documented prior-art techniques: Sysmon/eBPF telemetry, Sigma + YARA rules, MITRE ATT&CK content, file-journaling rollback (filesystem snapshots / copy-on-trip), and graph-over-OCSF correlation. No commercial vendor detection content is ingested or redistributed.

---

## Technology Decisions

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Backend language | **Python 3.12** | LLM/AI workflow is core (incident summaries, NL→Sigma, NL threat hunting); Python has the richest LLM tooling, `pySigma` for Sigma compilation, `yara-python`, and `mitreattack-python`. Detection engine and enrichment are IO-bound, not CPU-bound. |
| Agent language | **Go 1.23** | Single static cross-compiled binary per OS, tiny footprint (critical for older SMB hardware per `research.md` "agent weight"), no runtime dependency, mature eBPF (cilium/ebpf) and Windows ETW bindings. |
| API framework | **FastAPI** | Async, first-class **OpenAPI 3.1** generation (a `standards.md` requirement), Pydantic v2 validation aligns with JSON Schema 2020-12, native dependency-injection for tenant scoping. |
| Primary database | **PostgreSQL 16** | Adopts **data-model-suggestion-3 (hybrid relational + JSONB)** — relational integrity for tenants/endpoints/alerts/incidents, JSONB for OCSF telemetry that evolves without DDL. Single-database simplicity fits SMB ops while keeping a documented growth path to Suggestion 4 (ClickHouse + graph). |
| Telemetry transport | **gRPC over mTLS (RFC 8705)** | High-throughput bidirectional agent↔cloud channel; mTLS gives per-agent cryptographic identity (a `standards.md` mandate). Protobuf wire format (`proto3`) for efficiency from constrained agents. |
| Event schema | **OCSF 1.x** | `standards.md` "Notes": OCSF is the converging lingua franca for security events; designing the agent event model around OCSF maximises SIEM interoperability. |
| Detection format | **Sigma** (via `pySigma`) + **YARA** | Open, license-clean detection content cross-compilable to many backends; ATT&CK mapping built in. |
| Threat classification | **MITRE ATT&CK** (`mitreattack-python` STIX bundle) | Universal technique/tactic taxonomy; loaded as reference data. |
| Task queue / async | **Celery + Redis** | Long-running AI calls, enrichment, retention jobs, webhook fan-out must run off the request path. Redis doubles as dashboard cache and rate limiter. |
| Streaming buffer | **Redis Streams** (MVP) → Kafka/Redpanda (later) | Smooths agent ingestion bursts without standing up Kafka on day one; Suggestion 4 documents the Kafka upgrade. |
| LLM access | **Provider-abstracted client** (Anthropic / OpenAI / self-hosted via Ollama) | `README.md` promises an *open* LLM option; abstraction lets regulated SMBs run a local model for data residency. Default cloud provider behind a single interface. |
| Frontend | **Next.js 15 (App Router) + TypeScript + shadcn/ui + Tailwind** | Multi-tenant console with dashboards, timelines, incident views, graph visualisation. SSR for fast first paint; mature component ecosystem. |
| Graph visualisation | **Cytoscape.js** | Process-tree and attack-chain rendering in the console; recursive CTE results from Postgres feed it. |
| Console auth | **OIDC + OAuth 2.0** (Authlib) + WebAuthn/FIDO2 step-up + SAML 2.0 for MSP IdPs | `standards.md` security section: SSO, phishing-resistant MFA, enterprise IdP support. |
| Agent auth | **mTLS client certificates** issued at enrolment | Per-agent identity; revocable; survives even when an endpoint is isolated. |
| ORM / migrations | **SQLAlchemy 2.0 + Alembic** | Battle-tested; JSONB payload changes need no migration (Suggestion 3 benefit). |
| Containerisation | **Docker + Docker Compose** | Self-hosting story; one-command stand-up of Postgres, Redis, API, worker, console. |
| Backend tests | **pytest + pytest-asyncio + testcontainers** | Real Postgres/Redis in integration tests; mocks for LLM and external APIs. |
| Agent tests | **Go `testing` + testify** | Standard. |
| Frontend tests | **Vitest + Playwright** | Unit + e2e console flows. |
| Lint / format / types | **ruff + mypy** (Py), **golangci-lint + gofmt** (Go), **eslint + prettier + tsc** (TS) | Standard per ecosystem. |
| Package managers | **uv** (Py), **go mod**, **pnpm** (TS) | Fast, reproducible. |
| CI | **GitHub Actions** | Lint, type-check, test matrix, Docker build, agent cross-compile. |

### Standards adopted by name (from `standards.md`)

- **OCSF** — event schema for all telemetry.
- **Sigma**, **MITRE ATT&CK**, **YARA** — detection content.
- **OpenAPI 3.1** + **JSON Schema 2020-12** — management API contract.
- **mTLS (RFC 8705)**, **TLS 1.3 (RFC 8446)**, **JWT (RFC 7519)**, **OAuth 2.0 / OIDC** — auth.
- **RFC 5424 syslog** + **CEF** — SIEM forwarding.
- **OpenC2** — structured response-action vocabulary (isolate/contain).
- **STIX 2.1 / TAXII 2.1** — threat-intel ingestion (later phase).
- **MCP** — EDR MCP server exposing scoped tools to LLM analyst workflows (differentiating, later phase).
- **OWASP API Security Top 10 (2023)** + **ASVS 4.0** — security baseline for the API and console.
- **NIST SP 800-61r3** (incident lifecycle), **ISO 27035** — incident workflow state machine.
- **ISO 27037 / NIST SP 800-86** — forensic triage and tamper-evident timeline.

### Project Structure

```
edr-platform/
├── docker-compose.yml
├── docker-compose.dev.yml
├── README.md
├── .github/workflows/
│   ├── backend.yml
│   ├── agent.yml
│   └── console.yml
│
├── proto/                              # shared protobuf definitions (agent <-> cloud)
│   └── telemetry/v1/telemetry.proto
│
├── agent/                              # Go cross-platform agent
│   ├── go.mod
│   ├── cmd/edr-agent/main.go
│   ├── internal/
│   │   ├── collector/                  # platform telemetry sources
│   │   │   ├── windows_etw.go          # ETW / Sysmon event subscription
│   │   │   ├── linux_ebpf.go           # eBPF process/file/net probes
│   │   │   ├── macos_endpoint.go       # EndpointSecurity framework
│   │   │   └── collector.go            # platform-agnostic interface
│   │   ├── ocsf/                       # map raw events -> OCSF
│   │   ├── transport/                  # gRPC client, mTLS, buffering, backpressure
│   │   ├── enrol/                      # enrolment + CSR + cert storage
│   │   ├── response/                   # isolate, kill, quarantine, rollback executors
│   │   ├── journal/                    # copy-on-write file journal for rollback
│   │   ├── canary/                     # ransomware canary file watcher
│   │   └── config/                     # agent config + remote config sync
│   └── packaging/                      # MSI, pkg, deb/rpm, systemd unit
│
├── backend/                            # Python control plane
│   ├── pyproject.toml
│   ├── alembic/
│   ├── src/edr/
│   │   ├── main.py                     # FastAPI app factory
│   │   ├── config.py                   # Pydantic Settings
│   │   ├── db/
│   │   │   ├── models/                 # SQLAlchemy models (Suggestion 3 schema)
│   │   │   ├── session.py              # tenant-scoped session (RLS GUC)
│   │   │   └── repositories/
│   │   ├── ocsf/                       # OCSF Pydantic models + JSON Schema validation
│   │   ├── api/
│   │   │   ├── deps.py                 # auth, tenant scoping, pagination
│   │   │   ├── v1/
│   │   │   │   ├── endpoints.py
│   │   │   │   ├── alerts.py
│   │   │   │   ├── incidents.py
│   │   │   │   ├── rules.py
│   │   │   │   ├── events.py           # timeline + threat-hunt query
│   │   │   │   ├── response.py
│   │   │   │   ├── ai.py               # summaries, NL->Sigma, NL hunt
│   │   │   │   ├── integrations.py
│   │   │   │   └── compliance.py
│   │   ├── ingest/
│   │   │   ├── grpc_server.py          # telemetry gRPC service
│   │   │   ├── pipeline.py             # validate -> enrich -> persist -> publish
│   │   │   └── enrichment/             # geoip, threat-intel, ATT&CK tagging
│   │   ├── detection/
│   │   │   ├── sigma_engine.py         # pySigma -> SQL backend
│   │   │   ├── evaluator.py            # streaming + scheduled rule evaluation
│   │   │   ├── anomaly.py              # per-host baseline anomaly detection
│   │   │   └── correlation.py          # alert -> incident grouping
│   │   ├── response/
│   │   │   ├── orchestrator.py         # action lifecycle + OpenC2 mapping
│   │   │   └── tasking.py              # push commands to agents
│   │   ├── ai/
│   │   │   ├── client.py               # provider-abstracted LLM client
│   │   │   ├── prompts.py              # prompt templates
│   │   │   ├── summariser.py
│   │   │   ├── rule_author.py          # NL -> Sigma
│   │   │   └── threat_hunt.py          # NL -> safe SQL
│   │   ├── integrations/
│   │   │   ├── siem.py                 # syslog/CEF forwarder
│   │   │   ├── psa_rmm.py              # ConnectWise, NinjaOne webhooks
│   │   │   └── identity.py             # Entra ID, Google Workspace signals
│   │   ├── mcp/                        # EDR MCP server
│   │   ├── compliance/                 # evidence pack generation
│   │   ├── workers/                    # Celery tasks
│   │   └── audit/                      # tamper-evident audit log (chained hash)
│   └── tests/
│       ├── unit/
│       ├── integration/
│       └── fixtures/                   # sample OCSF events, Sigma rules, diffs
│
├── console/                            # Next.js multi-tenant web UI
│   ├── package.json
│   ├── app/
│   │   ├── (auth)/
│   │   └── (dash)/[tenant]/
│   │       ├── overview/
│   │       ├── endpoints/
│   │       ├── alerts/
│   │       ├── incidents/[id]/
│   │       ├── hunt/
│   │       └── rules/
│   ├── components/
│   ├── lib/api/                        # generated OpenAPI client
│   └── tests/
│
└── content/
    ├── sigma/                          # curated built-in Sigma ruleset
    ├── mitre/                          # ATT&CK STIX bundle (pinned version)
    └── compliance/                     # control->rule mappings (NIST CSF, CIS v8)
```

---

## Phase 1: Foundation, Schema & Multi-Tenant Skeleton

### Purpose
Establish the control-plane scaffold: the FastAPI app, PostgreSQL schema (data-model-suggestion-3), tenant-scoped access with row-level security, console authentication, and Docker Compose stand-up. After this phase the system can enrol tenants and users and serve an empty but secured, multi-tenant API and console shell. Nothing detects yet — but the spine everything attaches to exists.

### Tasks

#### 1.1 — Repository, tooling, and Docker Compose stand-up

**What**: Create the monorepo skeleton with `backend/`, `agent/`, `console/`, `proto/`, `content/`, and a `docker-compose.yml` that brings up Postgres 16, Redis, the API, a Celery worker, and the console.

**Design**:
- `docker-compose.yml` services: `db` (postgres:16), `cache` (redis:7), `api` (FastAPI/uvicorn), `worker` (Celery), `console` (Next.js). Healthchecks gate `api` on `db`.
- `backend/src/edr/config.py` — Pydantic `Settings` loaded from env:

```python
class Settings(BaseSettings):
    database_url: PostgresDsn
    redis_url: RedisDsn
    jwt_secret: SecretStr
    oidc_issuer: str | None = None
    llm_provider: Literal["anthropic", "openai", "ollama"] = "anthropic"
    llm_api_key: SecretStr | None = None
    llm_model: str = "claude-sonnet-4-6"
    event_retention_days_default: int = 30
    environment: Literal["dev", "prod"] = "dev"
    model_config = SettingsConfigDict(env_prefix="EDR_")
```

- `backend/src/edr/main.py` — `create_app()` factory mounting `/api/v1`, `/health`, OpenAPI at `/openapi.json`. CORS restricted to console origin.

**Testing**:
- `Unit: Settings loads with EDR_* env vars set → correct typed values; missing DATABASE_URL → ValidationError`.
- `Integration: docker compose up → GET /health returns {"status":"ok","db":"up","redis":"up"}`.
- `Integration: GET /openapi.json → valid OpenAPI 3.1 document (validate with openapi-spec-validator)`.

#### 1.2 — Database schema & migrations (Suggestion 3)

**What**: Implement the hybrid relational + JSONB schema as SQLAlchemy models and an initial Alembic migration.

**Design**: Adopt data-model-suggestion-3 verbatim for the relational core and the unified `events` table. Core tables: `tenants`, `users`, `endpoints`, `agents`, `detection_rules` (Sigma/YARA + `mitre_techniques VARCHAR(20)[]` + `rule_metadata JSONB`), `events` (partitioned by `event_time`, structured index columns + `payload JSONB` + `raw_event_hash`), `alerts`, `alert_events`, `incidents`, `response_actions`, `audit_log`, plus `mitre_techniques` and `threat_indicators` reference tables. Use the exact DDL from suggestion-3 §"Unified Event Table", §"Alert and Incident Tables", and §"Response Actions and Audit Trail".

Key model excerpt:

```python
class Tenant(Base):
    __tablename__ = "tenants"
    tenant_id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str]
    slug: Mapped[str] = mapped_column(unique=True)
    tier: Mapped[str] = mapped_column(default="standard")
    data_retention_days: Mapped[int] = mapped_column(default=30)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
```

- Alembic migration `0001_initial` creates all tables, enums (as VARCHAR + CHECK), GIN indexes on `events.payload`, `alerts.detection_context`, `detection_rules.mitre_techniques`, and the first two monthly `events` partitions.
- `pg_partman`-style partition helper documented; MVP uses an Alembic-managed function `create_event_partition(month)`.

**Testing**:
- `Integration (testcontainers Postgres): run all migrations up then down → no errors, schema matches`.
- `Integration: insert event with class_uid=1007 + valid OCSF payload → row persists; query by tenant_id+event_time uses idx_events_tenant_time (EXPLAIN)`.
- `Integration: insert two events into different months → land in correct partitions`.

#### 1.3 — Tenant-scoped sessions & row-level security

**What**: Enforce multi-tenant isolation at the database via RLS plus an application-layer tenant-scoped session.

**Design**:
- Enable RLS on `endpoints`, `events`, `alerts`, `incidents`, `response_actions`, `audit_log` with policies `USING (tenant_id = current_setting('app.current_tenant_id')::uuid)` (from suggestion-1 §RLS).
- `db/session.py`: `tenant_session(tenant_id)` async context manager runs `SET LOCAL app.current_tenant_id = :tid` at transaction start.
- FastAPI dependency `get_tenant_db()` resolves tenant from the JWT/path and yields a scoped session.

**Testing**:
- `Integration: session scoped to tenant A cannot SELECT tenant B's endpoints (returns 0 rows even with explicit WHERE)`.
- `Integration: INSERT into endpoints without app.current_tenant_id set → RLS rejects`.
- `Unit: get_tenant_db raises 403 when JWT tenant != path tenant`.

#### 1.4 — Console authentication (OIDC + JWT + WebAuthn step-up)

**What**: Implement user auth: OIDC SSO, local password fallback, JWT session tokens, role-based access (owner/admin/analyst/viewer), optional WebAuthn step-up for response actions.

**Design**:
- `POST /api/v1/auth/login` (local), `GET /api/v1/auth/oidc/start` + `/callback` (Authlib). Issues JWT (RFC 7519) with claims `{sub, tenant_id, role, exp}`.
- Roles enforced by `require_role(min_role)` dependency; ordering viewer < analyst < admin < owner.
- WebAuthn registration/assertion endpoints; response-action routes require a fresh WebAuthn assertion when tenant policy `require_step_up_for_response = true`.
- All login attempts and role changes written to `audit_log`.

**Testing**:
- `Unit: JWT with role=viewer → require_role(analyst) raises 403`.
- `Integration: valid login → JWT; expired JWT → 401`.
- `Integration (mocked OIDC): callback with valid code → user provisioned, JWT issued`.
- `Integration: isolate-host call without step-up when policy requires it → 401 step_up_required`.

---

## Phase 2: OCSF Event Model & Telemetry Ingestion

### Purpose
Define the canonical OCSF event model shared by agent and backend, and build the ingestion pipeline that validates, enriches, persists, and republishes telemetry. After this phase the backend can receive events over gRPC/mTLS, store them, and stream them onward — the data foundation for all detection and investigation.

### Tasks

#### 2.1 — Protobuf + OCSF event contract

**What**: Define the `telemetry.proto` envelope and Pydantic OCSF models (process 1007, file 1001, network 4001, registry, scheduled-task, script).

**Design**:
- `proto/telemetry/v1/telemetry.proto`:

```proto
service TelemetryService {
  rpc StreamEvents(stream EventBatch) returns (stream Ack);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}
message EventBatch { string agent_id = 1; repeated OcsfEvent events = 2; }
message OcsfEvent {
  uint32 class_uid = 1; uint32 category_uid = 2; uint32 activity_id = 3;
  uint32 severity_id = 4; int64 time_unix_ms = 5;
  bytes payload_json = 6;        // canonical OCSF JSON
  string raw_event_hash = 7;     // SHA-256 hex
}
```

- Pydantic OCSF models mirror suggestion-3 §"JSONB Payload Structure" (device, actor, process, file, network, enrichments). `OcsfEvent.validate()` checks against a pinned **JSON Schema 2020-12** per class_uid.

**Testing**:
- `Unit: valid OCSF process-launch JSON → ProcessActivity model; missing process.pid → ValidationError naming the field`.
- `Unit: round-trip OcsfEvent -> protobuf -> OcsfEvent preserves payload and hash`.
- `Fixture: every sample event in tests/fixtures/ocsf/ validates against its class schema`.

#### 2.2 — gRPC telemetry server with mTLS

**What**: Implement the streaming gRPC ingestion server authenticating agents by client certificate.

**Design**:
- `ingest/grpc_server.py` serves `TelemetryService`. mTLS: server validates client cert chain to the per-tenant enrolment CA; cert CN encodes `agent_id`; reject revoked certs (CRL/OCSF check against `agents`).
- `StreamEvents` consumes `EventBatch`, resolves `agent_id → endpoint_id/tenant_id`, hands each event to the pipeline, returns `Ack{seq, accepted}`. Backpressure: bounded queue; on overflow return `Ack{retry_after_ms}`.
- Update `endpoints.last_seen_at` and `agents.last_checkin_at` on each batch.

**Testing**:
- `Integration: agent with valid cert streams batch of 50 → all persisted, Acks returned`.
- `Integration: connection with cert for revoked agent → TLS handshake/authz rejected`.
- `Integration: batch with one invalid event → valid events persisted, invalid one NACKed with reason`.

#### 2.3 — Ingestion pipeline: validate → enrich → persist → publish

**What**: The pipeline that turns an accepted event into a stored, enriched row and a Redis Stream message.

**Design**:
- `pipeline.py` steps: (1) OCSF validate; (2) verify `raw_event_hash == sha256(canonical_payload)` for tamper evidence (ISO 27037); (3) enrich — GeoIP on IPs, threat-intel lookup against `threat_indicators`, ATT&CK technique tagging via a static heuristic map (full detection happens in Phase 3); (4) extract structured columns (`process_name`, `file_path`, `src_ip`, `dst_ip`, `dst_port`, `actor_user`) from payload; (5) INSERT into `events`; (6) XADD to `telemetry:{tenant_id}` Redis Stream for downstream consumers.
- Idempotency: dedupe on `(endpoint_id, raw_event_hash, event_time)` within a short window.

**Testing**:
- `Integration: ingest process-launch → events row has extracted process_name AND payload JSONB; XADD published`.
- `Unit: payload hash mismatch → event rejected, audit_log entry written`.
- `Integration: duplicate event within window → single row`.
- `Integration: event with dst_ip matching a threat_indicator → enrichments includes threat_intel match`.

#### 2.4 — Endpoint enrolment & agent certificate issuance

**What**: REST flow for enrolling an endpoint and issuing its mTLS client certificate.

**Design**:
- `POST /api/v1/endpoints/enrol` body `{enrolment_token, hostname, os_type, os_version, csr_pem}` → validates token (tenant-scoped, single-use, TTL), signs CSR with tenant CA, creates `endpoints` + `agents` rows, returns `{agent_id, certificate_pem, ca_chain_pem, grpc_endpoint}`.
- Enrolment tokens minted by admins via `POST /api/v1/endpoints/enrolment-tokens`.
- Endpoint lifecycle: `active → isolated → active`, `active → offline` (no checkin > threshold via worker), `* → decommissioned` (cert revoked).

**Testing**:
- `Integration: enrol with valid token + CSR → cert returned, endpoint active`.
- `Integration: reuse single-use token → 409`.
- `Integration: expired token → 401`.
- `Unit: decommission endpoint → cert added to revocation list, status=decommissioned`.

---

## Phase 3: Detection Engine (Sigma + MITRE ATT&CK)

### Purpose
This is the heart of the product. Build the Sigma-driven behavioural detection engine that evaluates rules against the OCSF event stream, raises alerts mapped to MITRE ATT&CK, and ships a curated built-in ruleset. After this phase the platform detects real attacker behaviour (e.g., Office spawning a shell) and produces actionable alerts.

### Tasks

#### 3.1 — MITRE ATT&CK reference loader

**What**: Load the pinned ATT&CK STIX bundle into `mitre_techniques`.

**Design**:
- `content/mitre/enterprise-attack.json` pinned version; `workers/load_mitre.py` parses via `mitreattack-python`, upserts `technique_id, tactic, technique_name, sub_technique, platform[]`. Idempotent; run on first boot and on content update.

**Testing**:
- `Integration: load bundle → row count matches expected; T1059.001 present with tactic=execution`.
- `Unit: re-run loader → no duplicates (upsert)`.

#### 3.2 — Sigma → SQL compilation

**What**: Compile Sigma YAML rules to executable SQL against the `events` table.

**Design**:
- `detection/sigma_engine.py` wraps **pySigma** with a custom backend that targets the Suggestion-3 events schema: maps Sigma fields (`Image`, `ParentImage`, `CommandLine`, `DestinationPort`, etc.) to JSONB paths (`payload->'process'->>'name'`) or extracted columns where available. Always scopes generated SQL to `tenant_id` and a time window.
- `compile_rule(sigma_yaml) -> CompiledRule{sql, params, mitre_techniques, severity, title}`. Extract ATT&CK tags from the rule's `tags:` (`attack.t1059.003`).

**Testing**:
- `Unit: Sigma "Office spawns cmd/powershell" → SQL filtering class_uid=1007, parent in office set; mitre_techniques=[T1059.003]`.
- `Unit: unsupported Sigma field → clear UnsupportedFieldError`.
- `Fixture: compile every rule in content/sigma/ → all produce valid SQL (dry-run EXPLAIN)`.

#### 3.3 — Streaming + scheduled rule evaluation

**What**: Evaluate enabled rules against incoming events (near-real-time) and on a schedule (windowed correlation rules).

**Design**:
- `detection/evaluator.py`: a Celery worker consumes the `telemetry:{tenant}` Redis Stream; for low-latency rules, match each event against compiled single-event rules in memory. For correlation/aggregation rules (`count() by host > N`), a periodic Celery beat task runs the compiled windowed SQL every N seconds.
- On match → `RaiseAlert`: create `alerts` row with `severity`, `confidence`, `title`, `mitre_techniques[]`, `detection_context JSONB` (matched fields + rule conditions), and link matched events in `alert_events` (relevance = trigger/contributing).
- Deduplicate: suppress identical (rule, endpoint, key-fields) alerts within a configurable window; increment a count instead.

**Testing**:
- `Integration: ingest winword→cmd.exe sequence with Office-shell rule enabled → exactly one alert, severity=high, T1059.003, alert_events links the launch event`.
- `Integration: same pattern twice in dedup window → one alert, occurrence count 2`.
- `Integration: scheduled "brute force" rule (10 failed logons/min) fires only above threshold`.
- `Unit: disabled rule never evaluated`.

#### 3.4 — Built-in Sigma ruleset & per-tenant rule management

**What**: Ship a curated, license-clean built-in ruleset and CRUD for tenant-custom rules.

**Design**:
- `content/sigma/` curated rules (mapped to common ATT&CK techniques: T1059 execution, T1547 persistence, T1003 credential dumping, T1021 lateral movement, T1486 ransomware impact). All authored in-house or sourced from Sigma's permissively-licensed community repo with attribution (no commercial vendor content).
- API: `GET/POST/PUT/DELETE /api/v1/rules`, `POST /api/v1/rules/{id}/enable|disable`. Built-in rules are `source=built-in` and `tenant_id=NULL` (global, read-only); tenant rules override by title.
- On create/update, validate via `compile_rule` before persisting.

**Testing**:
- `Integration: POST invalid Sigma → 422 with compiler error`.
- `Integration: POST valid custom rule → persisted, immediately evaluated against new events`.
- `Integration: tenant A's custom rule not visible to tenant B; built-ins visible to all`.

---

## Phase 4: Investigation — Timeline, Threat Hunting & Attack-Chain Correlation

### Purpose
Give analysts the tools to investigate. Build the searchable 30-day per-host event timeline, a structured threat-hunting query API, and process-tree / attack-chain reconstruction. After this phase, an alert can be pivoted into a full investigation. This satisfies the forensic requirements of ISO 27037 / NIST SP 800-86.

### Tasks

#### 4.1 — Event timeline & search API

**What**: Per-host time-ordered event timeline with filtering and full-text search.

**Design**:
- `GET /api/v1/endpoints/{id}/timeline?from&to&class_uid&severity_min&q&cursor&limit` — cursor-paginated, ordered `event_time DESC`, scoped by RLS. `q` does `pg_trgm` fuzzy match on `process_name`/`file_path`/payload `message`.
- Response items: `{event_id, event_time, class_uid, summary, severity_id, mitre_technique, details}` where `summary` is a human one-liner derived from the OCSF payload.

**Testing**:
- `Integration: timeline for host with 1000 events → cursor paginates, stable ordering`.
- `Integration: q="powershell" → trigram match returns relevant events`.
- `Integration: timeline respects retention window and tenant isolation`.

#### 4.2 — Structured threat-hunting query API

**What**: A safe, parameterised query interface over events (the foundation the AI NL-hunt of Phase 6 compiles into).

**Design**:
- `POST /api/v1/hunt` body = a constrained query DSL (JSON): `{filters:[{field, op, value}], time_range, group_by?, order_by?, limit}`. Allowed fields are an allowlist mapped to columns/JSONB paths; ops ∈ {eq, in, contains, cidr, gt, lt}. Compiled to parameterised SQL — never string-interpolated. Hard `limit` cap (e.g. 10k) and statement timeout.
- Ships saved hunts (Office-spawned shells, lateral-movement candidates on 445/3389, beaconing to external IPs) mirroring suggestion-3 §"Threat Hunting Queries".

**Testing**:
- `Unit: DSL with disallowed field → 422; never reaches SQL`.
- `Integration: lateral-movement saved hunt over seeded data → expected rows`.
- `Integration: query exceeding limit → capped; statement timeout enforced`.
- `Security: attempted SQL injection via value → treated as literal parameter, no execution`.

#### 4.3 — Process-tree & attack-chain reconstruction

**What**: Reconstruct process ancestry and cross-host attack chains for an alert/incident.

**Design**:
- `GET /api/v1/alerts/{id}/process-tree` — recursive CTE over process events (`actor.process.pid` → `process.pid`, same `endpoint_id`, temporal ordering) building parent→child tree from the triggering process to its root.
- `GET /api/v1/incidents/{id}/chain` — assembles a timeline-ordered narrative across the incident's alerts and their linked events, including network connections that bridge endpoints (lateral movement: outbound conn from host A to host B's IP followed by new process on B within a short window).
- Output shaped for **Cytoscape.js** (nodes/edges). This is the prior-art graph-over-OCSF technique (avoiding patented storyline methods).

**Testing**:
- `Integration: seeded winword→cmd→powershell→net.exe → process-tree returns 4-node chain rooted at winword`.
- `Integration: cross-host conn + subsequent remote process → chain includes lateral-movement edge`.
- `Unit: cyclic/missing-parent data → tree terminates, no infinite recursion`.

---

## Phase 5: Response & Containment

### Purpose
Close the loop from detection to action. Build the response orchestrator and the agent-side executors for host isolation, process killing, file quarantine, and ransomware rollback, plus the confidence-threshold policy that decides automated vs analyst-approved response. After this phase the platform can contain an active threat — the capability cyber-insurers mandate.

### Tasks

#### 5.1 — Response orchestrator & action lifecycle

**What**: Backend orchestration of response actions with an approval state machine and OpenC2-style vocabulary.

**Design**:
- `POST /api/v1/response` body `{endpoint_id, action_type, parameters, incident_id?}` where `action_type ∈ {isolate, release_isolation, kill_process, quarantine_file, rollback, restore}`.
- State machine (per suggestion-3 `response_actions`): `pending → approved → executing → completed | failed`. Auto-initiated actions skip to `approved` only if confidence ≥ tenant `auto_response_threshold`; otherwise wait for analyst approval (`initiated_by ∈ {auto, analyst, ai_recommended}`).
- Map action to an **OpenC2** command for the audit record. Every transition appended to `audit_log` with chained hash.
- Tasking delivered to the agent over the existing gRPC channel (`response/tasking.py`); result written back updates `result JSONB` and status.

**Testing**:
- `Unit: auto action, confidence 0.9 ≥ threshold 0.8 → approved automatically; 0.5 < 0.8 → stays pending`.
- `Integration: isolate request → command queued for agent, status=executing; agent ack → completed, audit_log chain valid`.
- `Integration: response on offline endpoint → queued, delivered on reconnect`.

#### 5.2 — Agent response executors

**What**: Go agent executors for isolate, kill, quarantine, restore, preserving the management channel during isolation.

**Design**:
- `agent/internal/response/`:
  - **isolate** — apply OS firewall rules (Windows Filtering Platform / nftables / pf) blocking all traffic *except* the cloud gRPC endpoint (so investigation/response continues — a table-stakes requirement from `features.md`).
  - **kill_process** — terminate by pid+start-time (guard against pid reuse).
  - **quarantine_file** — move to a protected store, record original path + hash in `result`.
  - **restore** — reverse quarantine / re-enable network.
- Commands authenticated over mTLS; agent verifies command signature.

**Testing**:
- `Go integration (test harness/VM): isolate → all egress blocked except cloud endpoint; release → connectivity restored`.
- `Unit: kill_process with stale pid (reused) → no-op + failure result, never kills wrong process`.
- `Unit: quarantine → file moved, original hash recorded, reversible`.

#### 5.3 — Ransomware canaries, journaling & rollback

**What**: Canary tripwires and copy-on-write file journaling enabling rollback after a ransomware trip — using prior-art techniques only.

**Design**:
- `agent/internal/canary/` plants canary files in watched directories; on modify/rename/encrypt of a canary, immediately fire a high-severity `RansomwareCanaryTripped` event and (if policy allows) auto-isolate.
- `agent/internal/journal/` — before a watched-directory file is overwritten by a flagged process, copy the original to a local journal (copy-on-write). On a confirmed ransomware trip, `rollback` restores journaled originals. This is documented prior art (file backup/journaling), explicitly **not** a clone of patented VSS-based vendor rollback.
- Journal capped by size/age; rollback result records `{files_restored, journal_entries_applied}`.

**Testing**:
- `Go integration: process mass-encrypts a directory containing a canary → canary trip event + auto-isolate fires`.
- `Go integration: rollback after trip → journaled originals restored, hashes match pre-encryption`.
- `Unit: journal respects size cap (oldest evicted); rollback with missing journal entry → partial restore reported, not crash`.

---

## Phase 6: AI-Native Layer

### Purpose
Deliver the differentiating AI capabilities promised in `README.md`/`features.md`: plain-English incident summaries with remediation, natural-language → Sigma rule authoring, conversational threat hunting, and AI-summarised executive reports. After this phase the platform delivers analyst-speed insight at machine speed — the core wedge against incumbents.

### Tasks

#### 6.1 — Provider-abstracted LLM client

**What**: A single LLM interface supporting cloud and self-hosted providers, with structured output, retries, and cost/usage logging.

**Design**:
- `ai/client.py`: `class LLMClient: async def complete(system, user, schema=None) -> str | dict`. Backends: Anthropic, OpenAI, Ollama (local — supports data-residency promise). `schema` enables JSON-mode/tool-use for structured returns. Token usage logged to `audit_log` per tenant for cost attribution.
- All prompts centralised in `ai/prompts.py` with versioned templates.

**Testing**:
- `Unit (mocked provider): complete() returns parsed dict when schema given; retries on transient 429`.
- `Integration (Ollama in CI optional): local model returns non-empty completion`.

#### 6.2 — Incident summarisation & guided remediation

**What**: Generate plain-language incident summaries and step-by-step remediation from incident context.

**Design**:
- On `IncidentCreated`/significant update, a Celery task builds context: incident metadata, member alerts, MITRE techniques, the attack chain (Phase 4.3), affected endpoints. Serialise compactly (graph + key events, not raw dumps).
- Prompt template (structure):

```
System: You are an EDR analyst assistant for non-specialist SMB IT staff.
Given the incident below, produce: (1) a 3-5 sentence plain-English summary
of what happened and why it matters, (2) the likely MITRE ATT&CK techniques,
(3) a prioritised, numbered remediation checklist with concrete steps,
(4) a one-line severity justification. Avoid jargon. Output JSON matching
the provided schema.
User: <incident_context_json>
```

- Output validated against a schema; written to `incidents.ai_summary` and `incidents.ai_remediation`. Always surfaced as *suggested* — analyst confirms before any auto-action.

**Testing**:
- `Integration (mocked LLM): incident with Office→shell→ransomware chain → ai_summary populated, ai_remediation has ≥3 steps, mentions isolation`.
- `Unit: malformed LLM output → schema validation fails gracefully, retried, error logged (no crash)`.

#### 6.3 — Natural-language → Sigma rule authoring

**What**: Turn an analyst's plain-text hypothesis into a valid, compilable Sigma rule.

**Design**:
- `POST /api/v1/ai/author-rule` body `{hypothesis_text}`. LLM produces Sigma YAML constrained by the supported-field allowlist (from 3.2) injected into the prompt. Result is run through `compile_rule`; on failure, the compiler error is fed back to the LLM for up to N self-correction rounds. Returns the rule **unsaved** (draft) for analyst review + ATT&CK tags.

**Testing**:
- `Integration (mocked LLM): "detect PowerShell downloading from the internet" → valid Sigma that compiles, tagged T1059.001/T1105`.
- `Integration: LLM first attempt uses unsupported field → self-correction loop yields compilable rule or returns explained failure after N tries`.

#### 6.4 — Conversational threat hunting

**What**: Natural-language questions compiled to safe hunt-DSL queries (Phase 4.2), executed, and answered with results + explanation.

**Design**:
- `POST /api/v1/ai/hunt` body `{question, time_range?}`. LLM emits a **hunt-DSL JSON** (never raw SQL) constrained to the allowlisted fields; backend validates and executes via the 4.2 engine; LLM then summarises the result set in plain English. The DSL boundary guarantees no arbitrary SQL ever reaches the database.

**Testing**:
- `Integration (mocked LLM): "show me lateral movement candidates in the last day" → DSL with dst_port in {445,3389}, internal cidr → executes → NL answer`.
- `Security: LLM coerced to emit raw SQL → rejected by DSL validator, no execution`.

#### 6.5 — Executive & compliance-auditor reports

**What**: AI-summarised executive reports for SMB owners and cyber-insurance auditors.

**Design**:
- `POST /api/v1/ai/executive-report` over a time range → aggregates incidents/alerts/posture, LLM produces a non-technical narrative (threats faced, actions taken, residual risk) written to `incidents.ai_executive_report` or a standalone report record. Exportable to PDF.

**Testing**:
- `Integration (mocked LLM): month with 3 incidents → report names incidents, actions, and a risk posture statement; renders to PDF`.

---

## Phase 7: Anomaly Detection & Alert Quality

### Purpose
Reduce false positives (a make-or-break concern per `research.md` build considerations) and catch signatureless behaviour via per-host baselines. After this phase, alert volume is tuned to what an understaffed SMB team can actually triage.

### Tasks

#### 7.1 — Per-host behavioural baselines

**What**: Build rolling baselines of normal behaviour per endpoint and flag deviations.

**Design**:
- `detection/anomaly.py`: nightly Celery task computes per-host baselines from `events` (e.g., hourly process-launch rate, distinct external IPs contacted, unusual parent→child pairs) using simple, explainable statistics (rolling mean/stddev, rarity scores) — no patented ML classifier. Deviations beyond a z-score threshold raise low/medium `AnomalyDetected` alerts with `detection_context` explaining the deviation.

**Testing**:
- `Integration: host with stable baseline then 10x launch spike → anomaly alert; explanation cites the metric and baseline`.
- `Unit: insufficient baseline history → no alert (avoid cold-start noise)`.

#### 7.2 — Alert tuning, suppression & risk scoring

**What**: Tools to suppress noisy rules, mark false positives, and compute endpoint risk scores.

**Design**:
- Mark alert `false_positive` → feeds a per-tenant suppression list (rule + matched-field signature). Endpoint risk score = function of open-alert count and max severity over 30 days (suggestion-3 `mv_endpoint_risk` materialized view, refreshed by worker).
- `GET /api/v1/endpoints?sort=risk_desc` for triage prioritisation.

**Testing**:
- `Integration: mark alert false_positive → matching future alerts auto-suppressed`.
- `Integration: endpoint with 1 critical + 3 high alerts → higher risk score than quiet endpoint; mv refresh updates it`.

---

## Phase 8: Multi-Tenant Console (Web UI)

### Purpose
Deliver the MSP-native multi-tenant console — the primary distribution surface per `research.md` ("building an MSP-native multi-tenant management console is essential"). After this phase, technicians and IT generalists can operate the platform without touching the API.

### Tasks

#### 8.1 — Console shell, tenant switching & auth

**What**: Next.js app with login (OIDC/local), tenant switcher for MSPs, role-gated navigation.

**Design**:
- App Router under `(dash)/[tenant]/`; server-side session from JWT; MSP users see a tenant picker; generated OpenAPI TS client in `lib/api/`. shadcn/ui + Tailwind.

**Testing**:
- `Playwright: login → land on overview; switch tenant → data scoped correctly`.
- `Playwright: viewer role → response-action buttons hidden/disabled`.

#### 8.2 — Endpoints, alerts & incident views

**What**: Fleet list with status/risk, alert queue, incident detail with AI summary, attack-chain graph, and one-click response.

**Design**:
- Endpoints table (status, isolation state, risk, last seen). Alert queue (severity, status, MITRE, assignee). Incident page: AI summary + remediation checklist, member alerts, **Cytoscape.js** attack-chain graph (from 4.3), response buttons (isolate/kill/quarantine/rollback) with WebAuthn step-up where required.

**Testing**:
- `Playwright: open incident → AI summary + chain graph render; click Isolate (with step-up) → action created, status reflects executing`.
- `Playwright: alert queue filters by severity and MITRE technique`.

#### 8.3 — Timeline, threat-hunt & rule authoring UI

**What**: Investigation timeline view, conversational hunt box, and the NL→Sigma rule draft/review screen.

**Design**:
- Timeline (4.1) with filters + trigram search. Hunt page: NL question box (6.4) showing generated DSL + results. Rules page: list/enable/disable + "Author with AI" (6.3) opening a draft editor showing generated Sigma + compile status before save.

**Testing**:
- `Playwright: type NL hunt → results table + plain-English answer`.
- `Playwright: author rule from text → draft Sigma shown, compile status green, save adds enabled rule`.

---

## Phase 9: Integrations & Interoperability

### Purpose
Connect the platform to the SMB/MSP ecosystem — the integrations that make it adoptable: SIEM forwarding, PSA/RMM webhooks, identity signals, and the MCP server. After this phase the platform is a good citizen in existing toolchains.

### Tasks

#### 9.1 — SIEM forwarding (syslog/CEF) & STIX/TAXII intel ingestion

**What**: Forward alerts/events to SIEMs and ingest threat-intel feeds.

**Design**:
- `integrations/siem.py`: per-tenant forwarders emitting **RFC 5424 syslog** and **CEF** for alerts (and optionally high-severity events); transport TCP+TLS or webhook. Configured via `POST /api/v1/integrations/siem`.
- **STIX 2.1 / TAXII 2.1** poller populates `threat_indicators` (used by ingest enrichment, 2.3).

**Testing**:
- `Integration: alert raised → well-formed CEF line delivered to a mock syslog sink`.
- `Integration (mock TAXII): poll → indicators upserted; new matching event enriched`.

#### 9.2 — PSA/RMM webhooks (ConnectWise, NinjaOne)

**What**: Push incidents/alerts to PSA/RMM tools as tickets (MVP integration set from `features.md`).

**Design**:
- `integrations/psa_rmm.py`: outbound webhook with provider-specific payload mappers (ConnectWise Manage, NinjaOne); signed, retried via Celery with backoff and a dead-letter record. Configured per tenant; events: incident created/contained/resolved.

**Testing**:
- `Integration (mock endpoint): incident created → ConnectWise-shaped payload posted, signature valid; 5xx → retried then dead-lettered`.

#### 9.3 — Identity signals (Entra ID / Google Workspace) & EDR MCP server

**What**: Ingest identity risk signals and expose scoped EDR tools to LLM agents via MCP.

**Design**:
- `integrations/identity.py`: OAuth to Microsoft Graph / Google Workspace; ingest risky-sign-in / suspicious-login signals as OCSF events, correlatable with endpoint activity.
- `mcp/`: **MCP server** exposing audited, scoped tools — `query_timeline`, `run_hunt`, `get_incident`, `isolate_host` (gated by role + step-up). Follows MCP reference patterns from `standards.md`; every tool call written to `audit_log`. This is the AI-native differentiator flagged in `standards.md` Notes.

**Testing**:
- `Integration (mock Graph): risky sign-in → OCSF identity event ingested and correlatable`.
- `Integration: MCP client calls query_timeline → scoped results; isolate_host without privilege → denied + audited`.

---

## Phase 10: Compliance, Hardening & Release

### Purpose
Make the platform deployable, auditable, and defensible: compliance-evidence packs, security hardening against OWASP API Top 10 / ASVS, tamper-evident audit verification, retention automation, and packaged self-hosted release. After this phase the platform is production-ready for SMB/MSP deployment and cyber-insurance scrutiny.

### Tasks

#### 10.1 — Compliance-evidence export packs

**What**: Generate evidence packs mapping platform activity to control frameworks.

**Design**:
- `content/compliance/` control→rule mappings for **NIST CSF 2.0**, **CIS Controls v8** (8/10/13), Cyber Essentials, HIPAA-basic. `POST /api/v1/compliance/export?framework&from&to` → bundle: coverage map (which controls have active detections), incident summaries, response actions taken, retention attestation. Output PDF + JSON.

**Testing**:
- `Integration: export NIST CSF over a month → bundle lists Detect/Respond controls with mapped active rules and incident evidence`.

#### 10.2 — Tamper-evident audit log & retention automation

**What**: Verify the chained-hash audit log and automate per-tenant retention.

**Design**:
- `audit/`: each `audit_log` row stores `checksum = sha256(prev_checksum || canonical(row))`; a `verify_audit_chain(tenant)` endpoint detects any break (ISO 27037 / NIST SP 800-92).
- Retention worker drops `events` partitions older than each tenant's `data_retention_days`; **legal-hold** flag on an incident excludes its linked events from purge.

**Testing**:
- `Integration: tamper with one audit row → verify_audit_chain reports the break at that row`.
- `Integration: retention job drops expired partition but preserves legal-held incident's events`.

#### 10.3 — Security hardening (OWASP API Top 10 / ASVS) & rate limiting

**What**: Harden the API surface and console.

**Design**:
- Apply OWASP API Security Top 10 (2023) controls: object-level authz tests on every tenant-scoped route (BOLA), function-level authz (role checks), input validation (Pydantic + JSON Schema), Redis-backed rate limiting per principal, security headers, secrets via env/secret store. ASVS 4.0 checklist gates release.

**Testing**:
- `Security: cross-tenant object access attempts on all resource routes → 403/404, never data leak`.
- `Security: unauthenticated/over-privileged calls rejected; rate limit returns 429 with Retry-After`.
- `CI: ZAP/dependency scan in pipeline, no high-severity findings`.

#### 10.4 — Packaging, agent installers & release

**What**: Production Docker images, agent installers, and a one-command self-host quickstart.

**Design**:
- Multi-stage Dockerfiles (API, worker, console); `docker-compose.yml` for self-host with TLS termination guidance. Agent packaging: signed MSI (Windows), notarised pkg (macOS), deb/rpm + systemd unit (Linux). Versioned release with migration runbook.

**Testing**:
- `CI: docker build all images; agent cross-compiles for windows/amd64, darwin/arm64, linux/amd64`.
- `E2E: fresh docker compose up + enrol a real agent on a test VM → telemetry flows, a seeded attack triggers an alert, isolate works end-to-end`.

---

## Phase Summary & Dependencies

```
Phase 1: Foundation, Schema, Multi-Tenancy   ─── required by everything
    │
Phase 2: OCSF Model & Telemetry Ingestion    ─── requires Phase 1
    │
Phase 3: Detection Engine (Sigma + ATT&CK)   ─── requires Phase 2   ◀ core value
    │
    ├── Phase 4: Investigation/Timeline/Hunt  ─── requires Phase 3
    │       │
    │       └── Phase 6: AI-Native Layer      ─── requires Phase 4 (chain context) + 3
    │
    ├── Phase 5: Response & Containment        ─── requires Phase 3 (+ Phase 2 agent channel)
    │
    └── Phase 7: Anomaly & Alert Quality       ─── requires Phase 3 (can parallel with 5)
            │
Phase 8: Multi-Tenant Console                  ─── requires 3,4,5,6 (consumes their APIs)
    │
Phase 9: Integrations & MCP                    ─── requires 3 (SIEM/PSA), 6 (MCP tools)
    │
Phase 10: Compliance, Hardening, Release       ─── requires all prior phases
```

**Parallelism opportunities:**
- After Phase 3: **Phase 4, Phase 5, and Phase 7** can be developed concurrently (independent subsystems sharing only the Phase 1–3 foundation).
- **Phase 6** depends on Phase 4 (needs attack-chain context) but its 6.1 LLM client can be built in parallel with Phase 4/5.
- **Phase 8 (console)** can begin its shell (8.1) as soon as Phase 1 auth exists; feature views (8.2/8.3) trail the APIs they consume.
- **Phase 9** sub-tasks are mutually independent (SIEM, PSA/RMM, identity, MCP) and parallelisable.

**Estimated scope: large** (10 phases, multi-language: Go agent + Python control plane + Next.js console + three storage/queue systems).

---

## Definition of Done (per phase)

Every phase must satisfy all applicable items before it is considered complete:

1. All tasks in the phase implemented.
2. All unit and integration tests for the phase pass; new code has meaningful coverage.
3. Linting and formatting pass — `ruff` + `mypy` (backend), `golangci-lint` + `gofmt` (agent), `eslint` + `prettier` + `tsc` (console).
4. `docker compose up` succeeds and all service healthchecks are green.
5. The phase's capability works end-to-end against a real Postgres/Redis (testcontainers) and, where relevant, a real enrolled test agent.
6. New configuration options documented in `README.md` and surfaced in `config.py` with defaults.
7. New API endpoints appear in the auto-generated **OpenAPI 3.1** spec and validate against it.
8. Database changes ship as a reversible Alembic migration (up + down tested).
9. Tenant isolation verified: no route or query can return another tenant's data (RLS + object-level authz tests).
10. Any LLM-driven feature degrades gracefully on provider failure (retry, then surfaced error — never a crash or an unverified auto-action).
11. Security-relevant actions (auth, response actions, rule changes, AI tool calls) are written to the tamper-evident `audit_log`.
12. No commercial-vendor detection content or patented-technique clones introduced (license/IP review per `features.md` Legal & IP Summary).
```
