# Data Model Suggestion 3: Hybrid Relational + JSONB / Document Approach

> Project: Endpoint Detection & Response (EDR) for SMBs
> Approach: PostgreSQL with structured columns for indexed fields and JSONB for flexible event payloads
> Generated: 2026-05-25

---

## Summary

This approach combines the strengths of normalized relational modeling (for entities with stable schemas like tenants, endpoints, alerts, incidents, and users) with JSONB document storage (for high-volume, schema-variable telemetry events). The key insight is that EDR data naturally splits into two categories:

1. **Configuration and workflow data** (tenants, endpoints, agents, detection rules, alerts, incidents, response actions) -- stable schemas, moderate volume, heavy read/write with updates, strong consistency required.
2. **Telemetry event data** -- massive volume, append-only, schema varies by event class and evolves with OCSF versions, queried primarily by time range and a small set of indexed fields.

The hybrid model stores category 1 in fully normalized tables and category 2 in a single unified events table with a handful of indexed columns (tenant, endpoint, time, class, severity) plus a JSONB `payload` column containing the full OCSF event data. This avoids the schema rigidity problem of Suggestion 1 while retaining the relational integrity guarantees that workflow data demands.

---

## Key Entities and Relationships

### Relational Core (Stable Schema)

The configuration and workflow tables are identical to Suggestion 1's normalized schema. Only the key differences in the event storage layer are shown here.

```sql
-- Tenants, users, endpoints, agents: same as Suggestion 1
-- (see data-model-suggestion-1.md for full DDL)

-- Detection rules with JSONB for flexible rule metadata
CREATE TABLE detection_rules (
    rule_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(tenant_id),
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    source          VARCHAR(30) NOT NULL DEFAULT 'built-in',
    rule_format     VARCHAR(20) NOT NULL DEFAULT 'sigma',  -- sigma, yara, custom
    rule_content    TEXT NOT NULL,                          -- Sigma YAML, YARA rule text
    rule_metadata   JSONB NOT NULL DEFAULT '{}',           -- flexible: tags, references, false_positive notes
    mitre_techniques VARCHAR(20)[] NOT NULL DEFAULT '{}',  -- denormalized for fast filtering
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rules_mitre ON detection_rules USING GIN (mitre_techniques);
CREATE INDEX idx_rules_metadata ON detection_rules USING GIN (rule_metadata jsonb_path_ops);
```

### Unified Event Table (JSONB Hybrid)

```sql
-- Single event table: structured index columns + JSONB payload
CREATE TABLE events (
    event_id        BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id       UUID NOT NULL,
    endpoint_id     UUID NOT NULL,
    
    -- OCSF classification (indexed for filtering)
    class_uid       INTEGER NOT NULL,           -- 1007=process, 1001=file, 4001=network, etc.
    category_uid    SMALLINT NOT NULL,           -- 1=system, 2=findings, 4=network
    activity_id     SMALLINT NOT NULL,
    
    -- Key query dimensions (indexed)
    severity_id     SMALLINT NOT NULL DEFAULT 1,
    status_id       SMALLINT NOT NULL DEFAULT 1,
    event_time      TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Commonly filtered fields extracted for indexing
    actor_user      VARCHAR(255),               -- who/what caused the event
    process_name    VARCHAR(512),               -- for process-centric queries
    file_path       VARCHAR(2048),              -- for file-centric queries
    src_ip          INET,                       -- for network-centric queries
    dst_ip          INET,
    dst_port        INTEGER,
    
    -- Full OCSF event as JSONB (the document)
    payload         JSONB NOT NULL,             -- complete OCSF-compliant event data
    
    -- Integrity
    raw_event_hash  VARCHAR(64) NOT NULL,       -- SHA-256 for tamper evidence
    
    PRIMARY KEY (event_id, event_time)
) PARTITION BY RANGE (event_time);

-- Monthly partitions
CREATE TABLE events_2026_05 PARTITION OF events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE events_2026_06 PARTITION OF events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

-- Indexes on structured columns (fast filtering)
CREATE INDEX idx_events_tenant_time ON events(tenant_id, event_time DESC);
CREATE INDEX idx_events_endpoint_time ON events(endpoint_id, event_time DESC);
CREATE INDEX idx_events_class_time ON events(class_uid, event_time DESC);
CREATE INDEX idx_events_severity ON events(tenant_id, severity_id, event_time DESC)
    WHERE severity_id >= 3;  -- partial index: only index notable events
CREATE INDEX idx_events_process ON events(process_name, event_time DESC)
    WHERE process_name IS NOT NULL;
CREATE INDEX idx_events_dst ON events(dst_ip, dst_port, event_time DESC)
    WHERE dst_ip IS NOT NULL;

-- GIN index on JSONB for deep payload queries (threat hunting)
CREATE INDEX idx_events_payload ON events USING GIN (payload jsonb_path_ops);
```

### JSONB Payload Structure (OCSF-Aligned)

```json
{
  "class_uid": 1007,
  "class_name": "Process Activity",
  "category_uid": 1,
  "category_name": "System Activity",
  "activity_id": 1,
  "activity_name": "Launch",
  "severity_id": 2,
  "severity": "Low",
  "status_id": 1,
  "status": "Success",
  "time": "2026-05-25T14:32:01.123Z",
  "message": "cmd.exe spawned by winword.exe",
  "metadata": {
    "version": "1.5.0",
    "product": {
      "name": "EDR Agent",
      "vendor_name": "Project414",
      "version": "0.1.0"
    },
    "profiles": ["endpoint"]
  },
  "device": {
    "hostname": "ACME-WS-042",
    "os": {"name": "Windows", "version": "11 23H2"},
    "ip": "192.168.1.42",
    "type_id": 1
  },
  "actor": {
    "user": {"name": "jsmith", "type_id": 1},
    "process": {
      "pid": 4812,
      "name": "WINWORD.EXE",
      "file": {"path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}
    }
  },
  "process": {
    "pid": 9234,
    "name": "cmd.exe",
    "cmd_line": "cmd.exe /c whoami",
    "file": {
      "path": "C:\\Windows\\System32\\cmd.exe",
      "hashes": [{"algorithm_id": 3, "value": "abc123..."}]
    },
    "parent_process": {
      "pid": 4812,
      "name": "WINWORD.EXE"
    }
  },
  "enrichments": [
    {"name": "mitre_attack", "data": {"technique_id": "T1059.003", "tactic": "execution"}},
    {"name": "threat_intel", "data": {"matched": false}}
  ]
}
```

### Alert and Incident Tables (Relational + JSONB Details)

```sql
-- Alerts: relational core with JSONB for flexible detection context
CREATE TABLE alerts (
    alert_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
    endpoint_id     UUID NOT NULL REFERENCES endpoints(endpoint_id),
    rule_id         UUID REFERENCES detection_rules(rule_id),
    incident_id     UUID,
    
    -- Indexed query fields
    severity        VARCHAR(20) NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.5,
    status          VARCHAR(20) NOT NULL DEFAULT 'new',
    assignee_id     UUID REFERENCES users(user_id),
    
    -- Structured summary
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    mitre_techniques VARCHAR(20)[] NOT NULL DEFAULT '{}',
    
    -- Flexible detection context as JSONB
    detection_context JSONB NOT NULL DEFAULT '{}',
    -- Contains: matched_fields, rule_conditions, anomaly_scores,
    -- related_indicators, process_tree_snapshot, etc.
    
    -- AI-generated content
    ai_summary      TEXT,
    ai_remediation  TEXT,
    ai_confidence   REAL,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    
    CONSTRAINT fk_alert_incident FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE INDEX idx_alerts_tenant_status ON alerts(tenant_id, status, created_at DESC);
CREATE INDEX idx_alerts_mitre ON alerts USING GIN (mitre_techniques);
CREATE INDEX idx_alerts_context ON alerts USING GIN (detection_context jsonb_path_ops);

-- Alert-to-event links
CREATE TABLE alert_events (
    alert_id        UUID NOT NULL REFERENCES alerts(alert_id),
    event_id        BIGINT NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    relevance       VARCHAR(20) NOT NULL DEFAULT 'contributing', -- trigger, contributing, context
    PRIMARY KEY (alert_id, event_id)
);

-- Incidents: relational structure with JSONB for storyline data
CREATE TABLE incidents (
    incident_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
    title           VARCHAR(512) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'open',
    assignee_id     UUID REFERENCES users(user_id),
    
    -- ATT&CK kill chain coverage
    mitre_tactics   VARCHAR(50)[] NOT NULL DEFAULT '{}',
    mitre_techniques VARCHAR(20)[] NOT NULL DEFAULT '{}',
    affected_endpoints UUID[] NOT NULL DEFAULT '{}',
    
    -- JSONB for flexible incident data
    storyline       JSONB NOT NULL DEFAULT '[]',
    -- Array of storyline entries with timestamps, descriptions, event refs
    
    attack_summary  JSONB NOT NULL DEFAULT '{}',
    -- Structured: initial_access, execution, persistence, lateral_movement, impact
    
    -- AI-generated content
    ai_summary          TEXT,
    ai_remediation      TEXT,
    ai_executive_report TEXT,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    contained_at    TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ
);

CREATE INDEX idx_incidents_tenant ON incidents(tenant_id, status, created_at DESC);
CREATE INDEX idx_incidents_tactics ON incidents USING GIN (mitre_tactics);
```

### Response Actions and Audit Trail

```sql
CREATE TABLE response_actions (
    action_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID REFERENCES incidents(incident_id),
    alert_id        UUID REFERENCES alerts(alert_id),
    endpoint_id     UUID NOT NULL REFERENCES endpoints(endpoint_id),
    action_type     VARCHAR(30) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    initiated_by    VARCHAR(20) NOT NULL,
    
    -- JSONB for action-type-specific parameters and results
    parameters      JSONB NOT NULL DEFAULT '{}',
    result          JSONB,
    -- e.g., for quarantine: {file_path, original_hash, quarantine_location}
    -- e.g., for rollback: {files_restored: 42, journal_entries_applied: 108}
    
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    executed_at     TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

-- Tamper-evident audit log (append-only)
CREATE TABLE audit_log (
    log_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    actor_type      VARCHAR(20) NOT NULL,       -- user, system, agent, ai
    actor_id        VARCHAR(255),
    action          VARCHAR(100) NOT NULL,       -- e.g., alert.acknowledge, host.isolate, rule.create
    resource_type   VARCHAR(50) NOT NULL,
    resource_id     VARCHAR(255) NOT NULL,
    details         JSONB,
    ip_address      INET,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    checksum        VARCHAR(64) NOT NULL         -- chained hash for tamper detection
);
```

### Threat Hunting Queries (JSONB Power)

```sql
-- Find all processes spawned by Office applications (threat hunting)
SELECT event_time, 
       payload->'actor'->'process'->>'name' AS parent,
       payload->'process'->>'name' AS child,
       payload->'process'->>'cmd_line' AS cmd_line,
       payload->'device'->>'hostname' AS host
FROM events
WHERE tenant_id = :tenant_id
  AND class_uid = 1007                          -- process activity
  AND activity_id = 1                           -- launch
  AND event_time > now() - INTERVAL '7 days'
  AND payload->'actor'->'process'->>'name' 
      IN ('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE', 'OUTLOOK.EXE')
ORDER BY event_time DESC
LIMIT 100;

-- Find lateral movement candidates: SMB + RDP to internal IPs
SELECT event_time, src_ip, dst_ip, dst_port,
       payload->'process'->>'name' AS process,
       payload->'device'->>'hostname' AS host
FROM events
WHERE tenant_id = :tenant_id
  AND class_uid = 4001                          -- network activity
  AND dst_port IN (445, 3389)                   -- SMB, RDP
  AND dst_ip << '10.0.0.0/8'::inet             -- internal destination
  AND event_time > now() - INTERVAL '24 hours'
ORDER BY event_time DESC;

-- Deep payload search: any event mentioning a specific hash
SELECT event_time, class_uid, process_name, file_path,
       payload->>'message' AS message
FROM events
WHERE tenant_id = :tenant_id
  AND event_time > now() - INTERVAL '30 days'
  AND payload @> '{"process":{"file":{"hashes":[{"value":"abc123..."}]}}}'::jsonb;
```

### Materialized Views for Dashboards

```sql
-- Refreshed every 60 seconds by a background worker
CREATE MATERIALIZED VIEW mv_tenant_dashboard AS
SELECT 
    tenant_id,
    date_trunc('hour', event_time) AS hour,
    class_uid,
    count(*) AS event_count,
    count(*) FILTER (WHERE severity_id >= 4) AS high_severity_count
FROM events
WHERE event_time > now() - INTERVAL '7 days'
GROUP BY tenant_id, date_trunc('hour', event_time), class_uid;

CREATE UNIQUE INDEX idx_mv_dashboard 
    ON mv_tenant_dashboard(tenant_id, hour, class_uid);

-- Endpoint risk scoring view
CREATE MATERIALIZED VIEW mv_endpoint_risk AS
SELECT 
    e.endpoint_id,
    e.tenant_id,
    count(DISTINCT a.alert_id) FILTER (WHERE a.status = 'new') AS open_alerts,
    max(CASE a.severity 
        WHEN 'critical' THEN 5 WHEN 'high' THEN 4 
        WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END
    ) AS max_severity,
    count(DISTINCT a.alert_id) AS total_alerts_30d
FROM endpoints e
LEFT JOIN alerts a ON a.endpoint_id = e.endpoint_id 
    AND a.created_at > now() - INTERVAL '30 days'
WHERE e.status = 'active'
GROUP BY e.endpoint_id, e.tenant_id;
```

---

## Pros

1. **Schema flexibility where it matters.** JSONB payloads accommodate OCSF schema evolution, custom event types, and vendor-specific telemetry extensions without DDL migrations. New fields appear automatically.
2. **Indexed performance where it matters.** The extracted columns (tenant_id, endpoint_id, class_uid, severity_id, event_time, process_name, dst_ip) provide fast B-tree filtering for the most common query patterns, while GIN indexes on JSONB handle deep payload searches.
3. **Single database simplicity.** The entire system runs on PostgreSQL -- no Kafka, no separate document store, no projection infrastructure. This dramatically reduces operational complexity for SMB-targeted software.
4. **Relational integrity for workflow data.** Alerts, incidents, response actions, and user assignments benefit from foreign keys, constraints, and ACID transactions.
5. **Best-of-both-worlds queries.** Analysts can combine relational joins (alert -> rule -> MITRE mapping) with JSONB path queries (payload->'process'->>'cmd_line') in a single SQL statement.
6. **Partitioning for retention.** Time-based partitioning on the events table provides efficient retention management, just as in Suggestion 1.
7. **Gradual schema evolution.** Start with a few extracted columns and add more as query patterns emerge. No need to design the perfect schema upfront.
8. **Lower storage than fully normalized.** One row per event (vs. one header row + one detail row in Suggestion 1) reduces join overhead and per-row storage overhead.

## Cons

1. **JSONB storage overhead.** JSONB stores field names with every row, consuming more space than a columnar format or normalized columns. Compression (TOAST) helps but does not close the gap with columnar storage.
2. **GIN index size.** The JSONB GIN index can grow very large for high-volume event tables, impacting write throughput and increasing storage costs.
3. **Query planner complexity.** PostgreSQL's query planner may struggle with complex queries that combine B-tree index scans on structured columns with GIN scans on JSONB payloads, sometimes producing suboptimal plans.
4. **No schema validation at the database level.** JSONB accepts any valid JSON. Schema validation of OCSF compliance must happen in the application layer (or with CHECK constraints using jsonb_typeof, which are limited).
5. **Write throughput limits.** Still row-oriented PostgreSQL under the hood. The GIN index on JSONB adds write amplification. Practical limit is ~5-8K events/sec sustained on a well-provisioned instance.
6. **JSONB query syntax.** JSONB path operators (`->`, `->>`, `@>`, `?`, `jsonb_path_query`) are less intuitive than plain SQL columns, creating a learning curve for analysts writing threat-hunting queries.
7. **Partial denormalization risks.** Having both extracted columns (process_name) and the same data inside JSONB (payload->'process'->>'name') creates a consistency risk if they diverge. The application must ensure both are set correctly.

---

## Technology Recommendations

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Primary database | PostgreSQL 16+ | JSONB, partitioning, RLS, GIN indexes all mature |
| Connection pooling | PgBouncer | Multi-tenant connection management |
| Partition management | pg_partman | Automated monthly partition lifecycle |
| Full-text search | pg_trgm + GIN on extracted text fields | Fuzzy search on process names, file paths, hostnames |
| JSONB validation | Application-layer OCSF schema validation (JSON Schema) | Validate before INSERT; database is the last line of defense |
| Caching | Redis | Dashboard aggregates, session state, rate limiting |
| Background workers | pg_cron or application-level scheduler | Materialized view refresh, partition management, retention |
| Migration | Alembic (Python) or Flyway (Java) | Track relational schema changes; JSONB payload changes need no migration |

---

## Migration and Scaling Considerations

### Migration Path
- **From Suggestion 1**: Merge the per-class event tables (event_process_activity, event_file_activity, etc.) into a single events table. Move detail columns into a JSONB payload. This is a one-time data migration that consolidates tables.
- **OCSF upgrades**: When OCSF releases new event classes or adds fields, no database migration is needed. Update the application-layer validator and the agent. Old events retain their original payload shape.
- **Adding extracted columns**: When a new query pattern emerges (e.g., frequent filtering by DNS query domain), add a new extracted column and backfill it from the JSONB payload. This is a targeted optimization, not a schema overhaul.

### Scaling Strategy
- **Vertical scaling**: PostgreSQL handles 3-5K events/sec comfortably on a 16-core/64GB instance. For most SMB deployments (10-500 endpoints), a single instance is sufficient.
- **Read replicas**: Route investigation queries and dashboard reads to streaming replicas. The primary handles only ingestion and alert/incident writes.
- **Citus sharding**: For large MSP deployments with hundreds of tenants, Citus distributes the events table by tenant_id with co-located alerts and endpoints tables, providing linear horizontal scaling.
- **Hot/warm/cold tiers**: Recent partitions (0-7 days) on fast NVMe; older partitions (7-30 days) on cheaper SSD; partitions beyond retention exported to Parquet on object storage for long-term forensic access.
- **Selective GIN indexing**: Only create the GIN index on recent partitions (e.g., last 7 days). Older partitions rely on sequential scans over extracted columns, trading query speed for reduced index maintenance cost.

### Data Retention
- Drop monthly partitions for retention, identical to Suggestion 1.
- JSONB payload compression via TOAST provides ~2-3x compression automatically.
- For tenants requiring extended retention, export events to Parquet format on S3/GCS using COPY with a Parquet extension (pg_parquet or DuckDB foreign data wrapper).

### When to Graduate to a Different Model
If event volume consistently exceeds 10K events/sec or if the GIN index becomes a write bottleneck, consider:
- Moving the event pipeline to ClickHouse (Suggestion 4) while keeping the relational core in PostgreSQL.
- Adding Kafka as a buffer between agents and PostgreSQL to smooth ingestion bursts.
- These are additive changes -- the relational core for alerts, incidents, and configuration remains in PostgreSQL regardless.
