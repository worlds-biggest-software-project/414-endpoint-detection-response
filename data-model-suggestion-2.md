# Data Model Suggestion 2: Event-Sourced / CQRS Approach

> Project: Endpoint Detection & Response (EDR) for SMBs
> Approach: Event Sourcing with Command Query Responsibility Segregation (CQRS)
> Generated: 2026-05-25

---

## Summary

This approach treats every piece of telemetry, every detection, every response action, and every state change as an immutable event appended to an event store. The system never updates or deletes records in the write path -- it only appends. Read-side projections (materialized views) are built from the event stream to serve different query patterns: real-time dashboards, investigation timelines, compliance reports, and AI-powered analysis.

This model is a natural fit for EDR because endpoint telemetry is inherently event-driven and append-only. Agents emit a continuous stream of process, file, network, and registry events. Detections are events. Response actions are events. The entire security narrative is reconstructable by replaying the event log -- which is exactly what forensic investigation demands.

The architecture separates the write side (high-throughput event ingestion) from the read side (flexible query projections), allowing each to be independently scaled and optimized.

---

## Architecture Overview

```
                    ┌─────────────┐
                    │   Agents    │
                    │ (endpoints) │
                    └──────┬──────┘
                           │ telemetry events
                           ▼
                    ┌─────────────┐
                    │  Ingestion  │
                    │   Gateway   │
                    └──────┬──────┘
                           │ validated, enriched events
                           ▼
              ┌────────────────────────┐
              │     Event Store        │
              │  (append-only log)     │
              │  Apache Kafka /        │
              │  Redpanda + PostgreSQL │
              └───────────┬────────────┘
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
     ┌────────────┐ ┌──────────┐ ┌───────────┐
     │ Detection  │ │ Timeline │ │ Dashboard │
     │ Projection │ │ Project. │ │ Project.  │
     └─────┬──────┘ └────┬─────┘ └─────┬─────┘
           │              │             │
           ▼              ▼             ▼
     ┌────────────┐ ┌──────────┐ ┌───────────┐
     │  Alert     │ │ Investi- │ │ Analytics │
     │  Store     │ │ gation   │ │  Views    │
     │ (Postgres) │ │ Store    │ │ (Postgres │
     └────────────┘ │(Postgres)│ │  / Redis) │
                    └──────────┘ └───────────┘
```

---

## Key Entities and Event Streams

### Event Store Schema

The event store is the single source of truth. All events are immutable and append-only.

```sql
-- Central event log (write-side, append-only)
CREATE TABLE event_log (
    sequence_id     BIGINT GENERATED ALWAYS AS IDENTITY,
    event_id        UUID NOT NULL DEFAULT gen_random_uuid(),
    stream_type     VARCHAR(30) NOT NULL,       -- endpoint, alert, incident, response_action
    stream_id       UUID NOT NULL,              -- the aggregate root ID
    tenant_id       UUID NOT NULL,
    event_type      VARCHAR(100) NOT NULL,       -- e.g., ProcessLaunched, FileModified, AlertRaised
    event_version   INTEGER NOT NULL DEFAULT 1,
    payload         JSONB NOT NULL,              -- full event data (OCSF-aligned)
    metadata        JSONB NOT NULL DEFAULT '{}', -- correlation IDs, source agent version, etc.
    event_time      TIMESTAMPTZ NOT NULL,        -- when the event occurred at the source
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    checksum        VARCHAR(64) NOT NULL,        -- SHA-256 of payload for tamper evidence
    PRIMARY KEY (sequence_id)
) PARTITION BY RANGE (ingested_at);

-- Append-only constraint: no UPDATE or DELETE via application-level enforcement
-- plus database trigger to reject modifications

CREATE INDEX idx_eventlog_stream ON event_log(stream_type, stream_id, sequence_id);
CREATE INDEX idx_eventlog_tenant_time ON event_log(tenant_id, event_time DESC);
CREATE INDEX idx_eventlog_type ON event_log(event_type, event_time DESC);
```

### Event Types (Write-Side Domain Events)

```yaml
# Telemetry events (from agents)
- ProcessLaunched
- ProcessTerminated
- ProcessInjected
- FileCreated
- FileModified
- FileDeleted
- FileRenamed
- NetworkConnectionOpened
- NetworkConnectionClosed
- DnsQueryResolved
- RegistryKeyModified
- ScheduledTaskCreated
- ScriptExecuted
- KernelModuleLoaded
- PeripheralAttached

# Detection events (from detection engine)
- DetectionRuleMatched
- AnomalyDetected
- ThreatIndicatorMatched
- RansomwareCanaryTripped

# Alert lifecycle events
- AlertRaised
- AlertAcknowledged
- AlertEscalated
- AlertResolvedTrue
- AlertResolvedFalsePositive
- AlertMergedIntoIncident

# Incident lifecycle events
- IncidentCreated
- IncidentSeverityChanged
- IncidentAssigned
- IncidentContained
- IncidentResolved
- IncidentClosed
- IncidentNoteAdded
- IncidentAiSummaryGenerated
- IncidentRemediationRecommended

# Response action events
- HostIsolationRequested
- HostIsolationExecuted
- HostIsolationReleased
- ProcessKillRequested
- ProcessKillExecuted
- FileQuarantineRequested
- FileQuarantineExecuted
- FileRollbackRequested
- FileRollbackExecuted

# Configuration events
- EndpointEnrolled
- EndpointDecommissioned
- AgentUpgraded
- DetectionRuleCreated
- DetectionRuleUpdated
- DetectionRuleDisabled
```

### Read-Side Projections

Projections consume the event stream and build queryable materialized views optimized for specific access patterns.

#### Projection 1: Current Endpoint State

```sql
-- Materialized from EndpointEnrolled, AgentUpgraded, HostIsolation*, 
-- EndpointDecommissioned events
CREATE TABLE projection_endpoints (
    endpoint_id     UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    hostname        VARCHAR(255) NOT NULL,
    os_type         VARCHAR(20) NOT NULL,
    os_version      VARCHAR(100),
    ip_addresses    INET[],
    status          VARCHAR(20) NOT NULL,
    isolation_state VARCHAR(20) NOT NULL DEFAULT 'none',
    agent_version   VARCHAR(30),
    last_event_at   TIMESTAMPTZ,
    last_sequence   BIGINT NOT NULL,            -- watermark for projection rebuild
    open_alert_count INTEGER NOT NULL DEFAULT 0,
    risk_score      REAL NOT NULL DEFAULT 0.0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### Projection 2: Active Alerts

```sql
-- Materialized from AlertRaised, AlertAcknowledged, AlertResolved*, 
-- AlertMergedIntoIncident events
CREATE TABLE projection_alerts (
    alert_id        UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    endpoint_id     UUID NOT NULL,
    rule_id         UUID,
    incident_id     UUID,
    severity        VARCHAR(20) NOT NULL,
    confidence      REAL NOT NULL,
    title           VARCHAR(512) NOT NULL,
    status          VARCHAR(20) NOT NULL,
    assignee_id     UUID,
    mitre_techniques VARCHAR(20)[],
    event_count     INTEGER NOT NULL DEFAULT 0,
    first_event_at  TIMESTAMPTZ NOT NULL,
    last_event_at   TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    resolved_at     TIMESTAMPTZ,
    last_sequence   BIGINT NOT NULL
);

CREATE INDEX idx_proj_alerts_tenant ON projection_alerts(tenant_id, status, created_at DESC);
```

#### Projection 3: Investigation Timeline

```sql
-- Materialized from all telemetry events for a specific endpoint
-- Built on-demand when an analyst opens an investigation
CREATE TABLE projection_timeline (
    timeline_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    endpoint_id     UUID NOT NULL,
    event_id        UUID NOT NULL,
    event_type      VARCHAR(100) NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    severity_id     SMALLINT,
    summary         TEXT NOT NULL,              -- human-readable one-liner
    details         JSONB NOT NULL,             -- key fields for display
    related_alert_id UUID,
    mitre_technique VARCHAR(20),
    sequence_id     BIGINT NOT NULL
);

CREATE INDEX idx_timeline_endpoint ON projection_timeline(endpoint_id, event_time DESC);
```

#### Projection 4: Dashboard Aggregates

```sql
-- Pre-computed aggregates refreshed every minute from the event stream
CREATE TABLE projection_dashboard (
    tenant_id       UUID NOT NULL,
    bucket_time     TIMESTAMPTZ NOT NULL,       -- truncated to 1-minute intervals
    total_events    BIGINT NOT NULL DEFAULT 0,
    process_events  BIGINT NOT NULL DEFAULT 0,
    file_events     BIGINT NOT NULL DEFAULT 0,
    network_events  BIGINT NOT NULL DEFAULT 0,
    alerts_raised   INTEGER NOT NULL DEFAULT 0,
    alerts_resolved INTEGER NOT NULL DEFAULT 0,
    incidents_open  INTEGER NOT NULL DEFAULT 0,
    endpoints_active INTEGER NOT NULL DEFAULT 0,
    endpoints_isolated INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, bucket_time)
);
```

#### Projection 5: Incident Storyline (Attack Narrative)

```sql
-- Materialized when an incident is created; updated as new alerts merge in
CREATE TABLE projection_incident_storyline (
    storyline_entry_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id     UUID NOT NULL,
    tenant_id       UUID NOT NULL,
    entry_type      VARCHAR(30) NOT NULL,       -- telemetry, detection, response, note, ai_summary
    event_time      TIMESTAMPTZ NOT NULL,
    endpoint_id     UUID,
    title           TEXT NOT NULL,
    description     TEXT,
    details         JSONB,
    mitre_tactic    VARCHAR(50),
    mitre_technique VARCHAR(20),
    severity        VARCHAR(20),
    sequence_id     BIGINT NOT NULL
);

CREATE INDEX idx_storyline_incident ON projection_incident_storyline(incident_id, event_time);
```

### Command Handlers (Write-Side)

```python
# Pseudocode for CQRS command handlers

class IngestTelemetryCommand:
    """Accepts raw telemetry from agents, validates, enriches, and appends to event log."""
    
    def handle(self, raw_event: dict) -> None:
        validated = ocsf_validator.validate(raw_event)
        enriched = enrichment_pipeline.enrich(validated)  # GeoIP, threat intel, etc.
        
        event = DomainEvent(
            stream_type="endpoint",
            stream_id=enriched.endpoint_id,
            event_type=enriched.ocsf_class_name,
            payload=enriched.to_ocsf_json(),
            checksum=sha256(enriched.to_ocsf_json()),
            event_time=enriched.time,
        )
        event_store.append(event)


class RaiseAlertCommand:
    """Detection engine raises an alert when a rule matches."""
    
    def handle(self, detection: DetectionMatch) -> None:
        alert_id = uuid4()
        event = DomainEvent(
            stream_type="alert",
            stream_id=alert_id,
            event_type="AlertRaised",
            payload={
                "alert_id": str(alert_id),
                "rule_id": str(detection.rule_id),
                "endpoint_id": str(detection.endpoint_id),
                "severity": detection.severity,
                "confidence": detection.confidence,
                "title": detection.title,
                "matched_events": [str(e) for e in detection.event_ids],
                "mitre_techniques": detection.mitre_techniques,
            },
        )
        event_store.append(event)


class IsolateHostCommand:
    """Analyst or automation requests host isolation."""
    
    def handle(self, endpoint_id: UUID, initiated_by: str, reason: str) -> None:
        # Validate endpoint exists and is not already isolated
        current_state = endpoint_projection.get(endpoint_id)
        if current_state.isolation_state != "none":
            raise AlreadyIsolatedException()
        
        event = DomainEvent(
            stream_type="response_action",
            stream_id=uuid4(),
            event_type="HostIsolationRequested",
            payload={
                "endpoint_id": str(endpoint_id),
                "initiated_by": initiated_by,
                "reason": reason,
            },
        )
        event_store.append(event)
```

---

## Pros

1. **Complete audit trail by design.** Every state change is recorded as an immutable event. No data is ever lost or overwritten. This is ideal for forensic investigation, compliance audits, and cyber-insurance evidence.
2. **Natural fit for EDR telemetry.** Endpoint events are inherently append-only streams. Event sourcing does not fight the domain -- it embraces it.
3. **Temporal queries are first-class.** "What was the state of this endpoint at 14:32 on Tuesday?" is answered by replaying events up to that timestamp -- no need for slowly-changing-dimension hacks.
4. **Independent read/write scaling.** The ingestion pipeline (write) and investigation/dashboard queries (read) scale independently. Kafka/Redpanda handles burst ingestion; read projections can use different storage technologies optimized for their access pattern.
5. **Tamper evidence.** Chained checksums on the event log provide cryptographic tamper evidence, supporting compliance requirements (NIST SP 800-92, ISO 27037) without additional tooling.
6. **Flexible projections.** New query patterns (e.g., a compliance view, an AI training dataset, a threat-hunting interface) can be added by building a new projection from the existing event stream without modifying the write side.
7. **Replay and reprocessing.** When detection rules are updated or new ML models are deployed, historical events can be replayed through the new detection logic to find previously undetected threats.
8. **Event-driven integrations.** SIEM forwarding, webhook notifications, and PSA/RMM integrations are natural consumers of the event stream -- no polling or change-data-capture needed.

## Cons

1. **Operational complexity.** Running Kafka/Redpanda, maintaining projections, handling projection lag, and managing event schema evolution adds significant operational burden compared to a single PostgreSQL database.
2. **Eventual consistency.** Read projections lag behind the event store. An analyst may raise an alert and not immediately see it in the dashboard. For a security product, this latency (even milliseconds to seconds) must be carefully managed.
3. **Projection rebuild cost.** If a projection's logic changes or becomes corrupted, it must be rebuilt by replaying potentially billions of events. For a 30-day retention window at 10K events/sec, that is ~26 billion events.
4. **Query complexity.** Ad-hoc queries across the raw event log require scanning JSONB payloads. Without projections pre-built for a specific question, investigation queries are slow.
5. **Event schema evolution.** As OCSF versions advance or custom event types are added, old events in the store use the old schema. Projection builders must handle all historical schema versions (upcasting).
6. **Higher infrastructure cost.** Kafka cluster + PostgreSQL for projections + potentially separate stores for different read patterns means more moving parts and higher cloud spend than a single-database approach.
7. **Team skill requirements.** Event sourcing and CQRS are less familiar to most developers than traditional CRUD. Hiring and onboarding is harder for an open-source project seeking community contributors.
8. **Debugging difficulty.** Understanding the current state requires mentally replaying events. Bugs in projection logic can produce stale or incorrect read views that are hard to diagnose.

---

## Technology Recommendations

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Event bus / durable log | Apache Kafka or Redpanda | Append-only, partitioned, replicated. Redpanda preferred for operational simplicity (single binary, no ZooKeeper) |
| Event store (cold) | PostgreSQL with append-only event_log table | Queryable archive with checksums; Kafka retention handles hot path |
| Projection databases | PostgreSQL | Projections are just tables; leverage RLS for multi-tenancy |
| Real-time projections | Kafka Streams or Flink | Stream processing to build and maintain projections |
| Dashboard cache | Redis | Sub-second dashboard aggregates |
| Schema registry | Confluent Schema Registry / Redpanda Schema Registry | OCSF event schema versioning and compatibility checks |
| Serialization | JSON (OCSF) for interop; Protobuf for internal high-throughput paths | Balance between human readability and efficiency |

---

## Migration and Scaling Considerations

### Migration Path
- **Event schema versioning**: Every event carries an `event_version` field. When the schema evolves, the version increments. Projection consumers handle upcasting from old versions to new.
- **Projection migrations**: Projections are disposable. To change a projection's schema, deploy the new version and rebuild from the event stream. Run old and new projections in parallel during transition.
- **From relational to event-sourced**: If starting with Suggestion 1 and migrating later, the relational data can be "event-ified" by writing synthetic events from existing records, establishing a migration boundary timestamp.

### Scaling Strategy
- **Kafka/Redpanda partitioning**: Partition event topics by `tenant_id` to ensure tenant-ordered processing and enable per-tenant consumer groups.
- **Projection parallelism**: Each projection can have independent consumer groups, scaling read-side processing independently.
- **Tiered storage**: Kafka tiered storage (or Redpanda's shadow indexing) moves older segments to object storage (S3/GCS) while keeping recent data on fast local disks.
- **Event compaction**: For configuration streams (endpoint state, rule definitions), use log compaction to keep only the latest state per key, reducing replay time.
- **Multi-region**: Event replication across regions supports data-residency requirements for regulated SMBs.

### Data Retention
- **Kafka retention**: Set topic-level retention to match the tenant's data retention policy (30-90 days).
- **Event store archive**: PostgreSQL event_log partitions older than the retention window are dropped, but a summarized projection (incident records, alert history) is preserved indefinitely.
- **Legal hold**: Mark specific event ranges as held; exclude them from retention-based deletion.
- **Compliance export**: Replay events for a specific tenant and time range to generate compliance evidence packs (NIST CSF, Cyber Essentials) on demand.
