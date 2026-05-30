# Data Model Suggestion 1: Normalized Relational (PostgreSQL)

> Project: Endpoint Detection & Response (EDR) for SMBs
> Approach: Fully normalized relational schema with PostgreSQL
> Generated: 2026-05-25

---

## Summary

This approach models the EDR domain as a fully normalized relational database in PostgreSQL, with dedicated tables for each entity type (tenants, endpoints, agents, events, alerts, incidents, detection rules, response actions) and explicit foreign-key relationships between them. The schema enforces referential integrity at the database level and leverages PostgreSQL's mature ecosystem for row-level security (multi-tenancy), partitioning (time-based event data), and full-text search.

The event taxonomy follows the Open Cybersecurity Schema Framework (OCSF) event class structure, with separate tables for each major event class (process_activity, file_activity, network_activity, etc.) sharing a common base through table inheritance or a shared event header.

---

## Key Entities and Relationships

### Entity-Relationship Overview

```
Tenant 1──* Endpoint 1──1 Agent
Tenant 1──* User (console users)
Endpoint 1──* Event (polymorphic: process, file, network, registry, etc.)
Event *──1 EventClass (OCSF class_uid)
Event *──* MitreMapping (ATT&CK technique/tactic)
Alert 1──* Event (correlated events)
Alert *──1 DetectionRule
Alert *──* MitreMapping
Incident 1──* Alert (grouped alerts)
Incident 1──* ResponseAction
Incident 1──* IncidentNote
DetectionRule *──* MitreMapping
ResponseAction *──1 Endpoint
ThreatIntelIndicator *──* Alert
ComplianceFramework 1──* ComplianceControl
ComplianceControl *──* DetectionRule
```

### Core Schema

```sql
-- Multi-tenancy root
CREATE TABLE tenants (
    tenant_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(63) NOT NULL UNIQUE,
    tier            VARCHAR(20) NOT NULL DEFAULT 'standard',  -- standard, premium, enterprise
    data_retention_days INTEGER NOT NULL DEFAULT 30,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Console users (MSP technicians, SMB admins)
CREATE TABLE users (
    user_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255),
    role            VARCHAR(30) NOT NULL DEFAULT 'analyst',  -- owner, admin, analyst, viewer
    idp_subject     VARCHAR(512),  -- SSO identity
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Monitored endpoints
CREATE TABLE endpoints (
    endpoint_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
    hostname        VARCHAR(255) NOT NULL,
    os_type         VARCHAR(20) NOT NULL,   -- windows, macos, linux
    os_version      VARCHAR(100),
    ip_addresses    INET[],
    mac_addresses   MACADDR[],
    status          VARCHAR(20) NOT NULL DEFAULT 'active',  -- active, isolated, offline, decommissioned
    isolation_state VARCHAR(20) NOT NULL DEFAULT 'none',    -- none, full, selective
    last_seen_at    TIMESTAMPTZ,
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    tags            TEXT[]
);

CREATE INDEX idx_endpoints_tenant ON endpoints(tenant_id);
CREATE INDEX idx_endpoints_status ON endpoints(tenant_id, status);

-- Agent installation tracking
CREATE TABLE agents (
    agent_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id     UUID NOT NULL UNIQUE REFERENCES endpoints(endpoint_id),
    version         VARCHAR(30) NOT NULL,
    config_hash     VARCHAR(64),
    last_checkin_at TIMESTAMPTZ,
    telemetry_mode  VARCHAR(20) NOT NULL DEFAULT 'standard', -- minimal, standard, verbose
    installed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Event Tables (OCSF-Aligned)

```sql
-- Base event header (common OCSF fields)
CREATE TABLE events (
    event_id        BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
    endpoint_id     UUID NOT NULL REFERENCES endpoints(endpoint_id),
    class_uid       INTEGER NOT NULL,           -- OCSF class: 1007=process, 1001=file, 4001=network
    category_uid    INTEGER NOT NULL,           -- OCSF category: 1=system, 4=network
    activity_id     SMALLINT NOT NULL,
    severity_id     SMALLINT NOT NULL DEFAULT 1,
    status_id       SMALLINT NOT NULL DEFAULT 1, -- 0=unknown, 1=success, 2=failure
    event_time      TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    message         TEXT,
    raw_event_hash  VARCHAR(64),                -- SHA-256 for tamper evidence
    PRIMARY KEY (event_id, event_time)          -- for partitioning
) PARTITION BY RANGE (event_time);

-- Create monthly partitions
CREATE TABLE events_2026_05 PARTITION OF events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE events_2026_06 PARTITION OF events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_events_tenant_time ON events(tenant_id, event_time DESC);
CREATE INDEX idx_events_endpoint ON events(endpoint_id, event_time DESC);
CREATE INDEX idx_events_class ON events(class_uid, event_time DESC);

-- Process activity (OCSF class 1007)
CREATE TABLE event_process_activity (
    event_id        BIGINT NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    actor_user      VARCHAR(255),
    actor_process_pid   INTEGER,
    actor_process_name  VARCHAR(512),
    process_pid     INTEGER,
    process_name    VARCHAR(512),
    process_cmd_line TEXT,
    process_path    VARCHAR(1024),
    process_hash_sha256 VARCHAR(64),
    parent_process_pid  INTEGER,
    parent_process_name VARCHAR(512),
    parent_process_path VARCHAR(1024),
    launch_type_id  SMALLINT,                   -- 1=spawn, 2=fork, 3=exec
    injection_type_id SMALLINT,
    exit_code       INTEGER,
    FOREIGN KEY (event_id, event_time) REFERENCES events(event_id, event_time)
) PARTITION BY RANGE (event_time);

-- File activity (OCSF class 1001)
CREATE TABLE event_file_activity (
    event_id        BIGINT NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    actor_user      VARCHAR(255),
    actor_process_name VARCHAR(512),
    file_name       VARCHAR(512),
    file_path       VARCHAR(2048),
    file_hash_sha256 VARCHAR(64),
    file_size       BIGINT,
    file_type       VARCHAR(50),
    prev_file_path  VARCHAR(2048),              -- for rename operations
    FOREIGN KEY (event_id, event_time) REFERENCES events(event_id, event_time)
) PARTITION BY RANGE (event_time);

-- Network activity (OCSF class 4001)
CREATE TABLE event_network_activity (
    event_id        BIGINT NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    src_ip          INET,
    src_port        INTEGER,
    dst_ip          INET,
    dst_port        INTEGER,
    protocol_id     SMALLINT,                   -- TCP=6, UDP=17
    direction_id    SMALLINT,                   -- 1=inbound, 2=outbound
    bytes_in        BIGINT,
    bytes_out       BIGINT,
    process_name    VARCHAR(512),
    process_pid     INTEGER,
    dns_query       VARCHAR(512),
    FOREIGN KEY (event_id, event_time) REFERENCES events(event_id, event_time)
) PARTITION BY RANGE (event_time);

-- Registry activity (Windows-specific, OCSF extension)
CREATE TABLE event_registry_activity (
    event_id        BIGINT NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    reg_key         VARCHAR(2048) NOT NULL,
    reg_value_name  VARCHAR(512),
    reg_value_data  TEXT,
    reg_prev_value  TEXT,
    actor_process_name VARCHAR(512),
    FOREIGN KEY (event_id, event_time) REFERENCES events(event_id, event_time)
) PARTITION BY RANGE (event_time);
```

### Detection, Alerting, and Incident Management

```sql
-- Sigma-based detection rules
CREATE TABLE detection_rules (
    rule_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(tenant_id),  -- NULL = global/built-in
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    sigma_yaml      TEXT NOT NULL,
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    author          VARCHAR(255),
    source          VARCHAR(30) NOT NULL DEFAULT 'built-in', -- built-in, community, custom, ai-generated
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- MITRE ATT&CK reference table
CREATE TABLE mitre_techniques (
    technique_id    VARCHAR(20) PRIMARY KEY,     -- e.g., T1059.001
    tactic          VARCHAR(50) NOT NULL,        -- e.g., execution
    technique_name  VARCHAR(255) NOT NULL,
    sub_technique   VARCHAR(255),
    platform        TEXT[]                       -- windows, linux, macos
);

-- Rule-to-MITRE mapping
CREATE TABLE detection_rule_mitre (
    rule_id         UUID NOT NULL REFERENCES detection_rules(rule_id),
    technique_id    VARCHAR(20) NOT NULL REFERENCES mitre_techniques(technique_id),
    PRIMARY KEY (rule_id, technique_id)
);

-- Alerts generated by detection rules
CREATE TABLE alerts (
    alert_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
    endpoint_id     UUID NOT NULL REFERENCES endpoints(endpoint_id),
    rule_id         UUID REFERENCES detection_rules(rule_id),
    incident_id     UUID,                       -- FK added after incidents table
    severity        VARCHAR(20) NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.5,  -- 0.0-1.0
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    status          VARCHAR(20) NOT NULL DEFAULT 'new', -- new, investigating, resolved, false_positive
    assignee_id     UUID REFERENCES users(user_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX idx_alerts_tenant_status ON alerts(tenant_id, status, created_at DESC);

-- Alert-to-event correlation
CREATE TABLE alert_events (
    alert_id        UUID NOT NULL REFERENCES alerts(alert_id),
    event_id        BIGINT NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    relevance_score REAL,
    PRIMARY KEY (alert_id, event_id)
);

-- Incidents (correlated alert groups)
CREATE TABLE incidents (
    incident_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
    title           VARCHAR(512) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'open',  -- open, investigating, contained, resolved, closed
    ai_summary      TEXT,                       -- LLM-generated incident summary
    ai_remediation  TEXT,                       -- LLM-generated remediation guidance
    assignee_id     UUID REFERENCES users(user_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ
);

ALTER TABLE alerts ADD CONSTRAINT fk_alert_incident
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id);

-- Response actions taken
CREATE TABLE response_actions (
    action_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID REFERENCES incidents(incident_id),
    alert_id        UUID REFERENCES alerts(alert_id),
    endpoint_id     UUID NOT NULL REFERENCES endpoints(endpoint_id),
    action_type     VARCHAR(30) NOT NULL,       -- isolate, kill_process, quarantine_file, rollback, restore
    status          VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, approved, executing, completed, failed
    initiated_by    VARCHAR(20) NOT NULL,       -- auto, analyst, ai_recommended
    parameters      JSONB,
    executed_at     TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Incident notes and audit trail
CREATE TABLE incident_notes (
    note_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(incident_id),
    author_id       UUID REFERENCES users(user_id),
    author_type     VARCHAR(20) NOT NULL DEFAULT 'analyst', -- analyst, system, ai
    content         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Threat Intelligence and Compliance

```sql
-- Threat intelligence indicators (STIX-aligned)
CREATE TABLE threat_indicators (
    indicator_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type  VARCHAR(30) NOT NULL,       -- ip, domain, file_hash, url, email
    value           TEXT NOT NULL,
    source          VARCHAR(100) NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.5,
    threat_type     VARCHAR(50),                -- malware, c2, phishing, ransomware
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ,
    stix_id         VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_indicators_type_value ON threat_indicators(indicator_type, value);

-- Compliance framework mapping
CREATE TABLE compliance_frameworks (
    framework_id    VARCHAR(30) PRIMARY KEY,     -- nist_csf, cyber_essentials, hipaa, pci_dss
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(30)
);

CREATE TABLE compliance_controls (
    control_id      VARCHAR(50) PRIMARY KEY,
    framework_id    VARCHAR(30) NOT NULL REFERENCES compliance_frameworks(framework_id),
    control_name    VARCHAR(255) NOT NULL,
    description     TEXT
);

CREATE TABLE control_rule_mapping (
    control_id      VARCHAR(50) NOT NULL REFERENCES compliance_controls(control_id),
    rule_id         UUID NOT NULL REFERENCES detection_rules(rule_id),
    PRIMARY KEY (control_id, rule_id)
);
```

### Row-Level Security for Multi-Tenancy

```sql
-- Enable RLS on all tenant-scoped tables
ALTER TABLE endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

-- Policy example: users see only their tenant's data
CREATE POLICY tenant_isolation_endpoints ON endpoints
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_events ON events
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_alerts ON alerts
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_incidents ON incidents
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
```

---

## Pros

1. **Strong referential integrity.** Foreign keys enforce consistency between events, alerts, incidents, endpoints, and tenants. No orphaned records, no dangling references.
2. **Mature tooling.** PostgreSQL has decades of tooling, monitoring, backup, and replication solutions. ORMs (SQLAlchemy, Prisma, Diesel) and migration tools (Flyway, Alembic) are battle-tested.
3. **Row-level security.** PostgreSQL's built-in RLS provides database-enforced multi-tenant isolation, reducing the risk of cross-tenant data leakage compared to application-layer filtering alone.
4. **ACID compliance.** Critical for an EDR where event integrity, alert state transitions, and response-action coordination must be reliable.
5. **Partitioning for retention.** Native declarative partitioning enables efficient time-based event retention (drop entire monthly partitions) and query performance on recent data.
6. **Standards alignment.** The OCSF-modeled event tables and Sigma-based detection rules align with open industry standards from day one.
7. **Compliance-friendly.** Explicit audit trails, tamper-evident hashes, and structured retention policies support cyber-insurance and regulatory requirements.

## Cons

1. **Schema rigidity.** Adding new event types or fields requires DDL migrations. As the agent captures new telemetry categories, each demands a new table or ALTER TABLE -- risky in a domain where event schemas evolve rapidly.
2. **Write throughput ceiling.** A busy 500-endpoint deployment generating 10K events/sec will stress PostgreSQL's row-oriented write path. Partitioning helps but does not match the throughput of columnar or append-optimized stores.
3. **Storage efficiency.** Row-oriented storage is less space-efficient than columnar formats for repetitive telemetry data. Expect 3-10x more storage than a columnar alternative for the same event volume.
4. **Complex joins at scale.** Correlating events across process, file, and network tables for incident storyline construction requires multi-table joins that become expensive as data grows.
5. **Partitioning management overhead.** Monthly partitions must be created proactively and dropped for retention. This requires operational automation (pg_partman or custom cron).
6. **Limited graph queries.** Building attack-chain correlations and process-tree visualisations with recursive CTEs is possible but awkward and slow compared to a purpose-built graph model.

---

## Technology Recommendations

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Primary database | PostgreSQL 16+ | RLS, declarative partitioning, JSONB for edge cases |
| Connection pooling | PgBouncer | Essential for multi-tenant connection management |
| Partition management | pg_partman | Automated partition creation and retention |
| Migration tool | Flyway or Alembic | Schema versioning across deployments |
| Full-text search | PostgreSQL tsvector + GIN indexes | Alert/event search without external dependency |
| Replication | Streaming replication + pg_basebackup | HA and disaster recovery |
| Monitoring | pg_stat_statements + Prometheus exporter | Query performance tracking |

---

## Migration and Scaling Considerations

### Migration Path
- **Schema versioning**: Use numbered migration files with a tool like Flyway. Every schema change is tracked and reproducible.
- **Zero-downtime migrations**: Use `CREATE INDEX CONCURRENTLY` and careful `ALTER TABLE` sequencing. Large backfill operations should run as background jobs.
- **OCSF version upgrades**: When OCSF releases new event classes, add new event detail tables and update the `class_uid` enum without modifying existing tables.

### Scaling Strategy
- **Vertical first**: PostgreSQL scales well vertically. A 32-core/128GB instance can handle many SMB deployments.
- **Read replicas**: Route investigation queries and dashboard reads to streaming replicas while keeping writes on the primary.
- **Citus for horizontal scaling**: If tenant count or event volume exceeds single-node capacity, Citus (distributed PostgreSQL) provides transparent sharding by `tenant_id` with co-located joins.
- **Archive tier**: Move events older than 30 days to compressed partitions or export to object storage (Parquet format) for long-term forensic access.
- **Event volume thresholds**: This model is comfortable up to ~5K events/sec sustained. Beyond that, consider Suggestion 3 (hybrid) or Suggestion 4 (columnar) for the event pipeline while keeping this schema for configuration, alerts, and incidents.

### Data Retention
- Drop entire monthly partitions for expired data -- O(1) operation regardless of data volume.
- Per-tenant retention policies enforced by checking `tenants.data_retention_days` in the partition-drop job.
- Legal-hold flag on incidents prevents associated events from being purged.
