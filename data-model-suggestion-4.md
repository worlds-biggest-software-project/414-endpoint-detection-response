# Data Model Suggestion 4: Columnar Telemetry Store + Graph Correlation Engine

> Project: Endpoint Detection & Response (EDR) for SMBs
> Approach: ClickHouse for high-throughput telemetry analytics, Neo4j for attack-graph correlation, PostgreSQL for operational state
> Generated: 2026-05-25

---

## Summary

This approach is inspired by the architecture behind CrowdStrike's Threat Graph and SentinelOne's Storyline engine -- purpose-built data layers optimized for the two dominant EDR query patterns:

1. **Telemetry analytics**: "Show me all DNS queries to newly-registered domains across all endpoints in the last 24 hours." This requires scanning billions of events by time range, filtering on specific columns, and aggregating results. Columnar storage (ClickHouse) excels here with 10-100x compression and sub-second analytical queries at millions of events per second.

2. **Attack-graph correlation**: "Trace the full attack chain from initial phishing email to lateral movement to ransomware detonation." This requires traversing relationships between processes, files, network connections, users, and endpoints -- a graph traversal problem where relational JOINs become impractical at depth. A property graph database (Neo4j) makes multi-hop relationship queries natural and fast.

PostgreSQL serves as the operational database for configuration, workflow state (alerts, incidents, response actions), multi-tenant management, and user authentication -- the same role it plays in Suggestions 1-3.

This is the most architecturally complex suggestion but delivers the highest performance ceiling and the richest analytical capability, matching the data architecture of enterprise-grade EDR platforms.

---

## Architecture Overview

```
                    ┌─────────────┐
                    │   Agents    │
                    │ (endpoints) │
                    └──────┬──────┘
                           │ telemetry (OCSF events)
                           ▼
                    ┌─────────────┐
                    │   Kafka /   │
                    │  Redpanda   │
                    └──┬──────┬───┘
                       │      │
            ┌──────────┘      └──────────┐
            ▼                            ▼
     ┌─────────────┐             ┌─────────────┐
     │ ClickHouse  │             │   Graph     │
     │ (telemetry  │             │  Enricher   │
     │  analytics) │             │  (service)  │
     └─────────────┘             └──────┬──────┘
                                        │
                                        ▼
                                 ┌─────────────┐
                                 │   Neo4j     │
                                 │  (attack    │
                                 │   graph)    │
                                 └─────────────┘

     ┌─────────────┐
     │ PostgreSQL  │ ← alerts, incidents, rules, tenants, users
     │ (operations)│
     └─────────────┘
```

---

## Key Entities and Storage Layers

### Layer 1: ClickHouse -- Telemetry Analytics

ClickHouse stores all raw telemetry events in a columnar format optimized for analytical queries over large time ranges. Events follow the OCSF schema.

```sql
-- ClickHouse DDL

-- Process activity events (OCSF class 1007)
CREATE TABLE events_process
(
    event_id        UUID DEFAULT generateUUIDv4(),
    tenant_id       UUID,
    endpoint_id     UUID,
    
    -- OCSF classification
    class_uid       UInt16 DEFAULT 1007,
    activity_id     UInt8,                      -- 1=launch, 2=terminate, 3=open, 4=inject
    severity_id     UInt8 DEFAULT 1,
    status_id       UInt8 DEFAULT 1,
    
    -- Temporal
    event_time      DateTime64(3, 'UTC'),
    ingested_at     DateTime64(3, 'UTC') DEFAULT now64(3),
    
    -- Actor (parent process / user)
    actor_user      LowCardinality(String),
    actor_process_pid   UInt32,
    actor_process_name  LowCardinality(String),
    actor_process_path  String,
    
    -- Target process
    process_pid         UInt32,
    process_name        LowCardinality(String),
    process_cmd_line    String,
    process_path        String,
    process_hash_sha256 FixedString(64),
    
    -- Parent process
    parent_process_pid  UInt32,
    parent_process_name LowCardinality(String),
    parent_process_path String,
    
    -- Device context
    hostname        LowCardinality(String),
    os_type         LowCardinality(String),
    
    -- Launch/injection details
    launch_type_id  UInt8 DEFAULT 0,
    injection_type_id UInt8 DEFAULT 0,
    exit_code       Int32 DEFAULT 0,
    
    -- Enrichment
    mitre_technique_id LowCardinality(String) DEFAULT '',
    mitre_tactic       LowCardinality(String) DEFAULT '',
    threat_intel_match  UInt8 DEFAULT 0,        -- boolean flag
    
    -- Full OCSF payload for completeness
    payload_json    String,                     -- compressed JSON for full fidelity
    raw_event_hash  FixedString(64)
)
ENGINE = MergeTree()
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, endpoint_id, event_time, event_id)
TTL event_time + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- File activity events (OCSF class 1001)
CREATE TABLE events_file
(
    event_id        UUID DEFAULT generateUUIDv4(),
    tenant_id       UUID,
    endpoint_id     UUID,
    class_uid       UInt16 DEFAULT 1001,
    activity_id     UInt8,
    severity_id     UInt8 DEFAULT 1,
    event_time      DateTime64(3, 'UTC'),
    ingested_at     DateTime64(3, 'UTC') DEFAULT now64(3),
    
    actor_user      LowCardinality(String),
    actor_process_name LowCardinality(String),
    actor_process_pid  UInt32,
    
    file_name       String,
    file_path       String,
    file_hash_sha256 FixedString(64),
    file_size       UInt64,
    file_type       LowCardinality(String),
    prev_file_path  String DEFAULT '',
    
    hostname        LowCardinality(String),
    os_type         LowCardinality(String),
    
    mitre_technique_id LowCardinality(String) DEFAULT '',
    is_canary_file     UInt8 DEFAULT 0,         -- ransomware canary flag
    
    payload_json    String,
    raw_event_hash  FixedString(64)
)
ENGINE = MergeTree()
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, endpoint_id, event_time, event_id)
TTL event_time + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- Network activity events (OCSF class 4001)
CREATE TABLE events_network
(
    event_id        UUID DEFAULT generateUUIDv4(),
    tenant_id       UUID,
    endpoint_id     UUID,
    class_uid       UInt16 DEFAULT 4001,
    activity_id     UInt8,
    severity_id     UInt8 DEFAULT 1,
    event_time      DateTime64(3, 'UTC'),
    ingested_at     DateTime64(3, 'UTC') DEFAULT now64(3),
    
    src_ip          IPv4,
    src_port        UInt16,
    dst_ip          IPv4,
    dst_port        UInt16,
    protocol_id     UInt8,                      -- TCP=6, UDP=17
    direction_id    UInt8,                      -- 1=inbound, 2=outbound
    
    bytes_in        UInt64 DEFAULT 0,
    bytes_out       UInt64 DEFAULT 0,
    
    process_name    LowCardinality(String),
    process_pid     UInt32,
    
    dns_query       String DEFAULT '',
    dns_response    String DEFAULT '',
    
    hostname        LowCardinality(String),
    os_type         LowCardinality(String),
    
    mitre_technique_id LowCardinality(String) DEFAULT '',
    threat_intel_match UInt8 DEFAULT 0,
    
    payload_json    String,
    raw_event_hash  FixedString(64)
)
ENGINE = MergeTree()
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, endpoint_id, event_time, event_id)
TTL event_time + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- Unified event view across all classes
CREATE VIEW events_all AS
SELECT event_id, tenant_id, endpoint_id, class_uid, activity_id, 
       severity_id, event_time, ingested_at, hostname, os_type,
       mitre_technique_id, raw_event_hash, payload_json
FROM events_process
UNION ALL
SELECT event_id, tenant_id, endpoint_id, class_uid, activity_id,
       severity_id, event_time, ingested_at, hostname, os_type,
       mitre_technique_id, raw_event_hash, payload_json
FROM events_file
UNION ALL
SELECT event_id, tenant_id, endpoint_id, class_uid, activity_id,
       severity_id, event_time, ingested_at, hostname, os_type,
       mitre_technique_id, raw_event_hash, payload_json
FROM events_network;
```

#### ClickHouse Analytical Queries

```sql
-- Threat hunting: processes spawned by Office apps across all endpoints
SELECT 
    hostname,
    actor_process_name,
    process_name,
    process_cmd_line,
    event_time,
    mitre_technique_id
FROM events_process
WHERE tenant_id = '...'
  AND activity_id = 1                           -- launch
  AND actor_process_name IN ('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE')
  AND event_time > now() - INTERVAL 7 DAY
ORDER BY event_time DESC
LIMIT 1000;
-- Scans millions of rows in milliseconds due to columnar storage

-- Aggregate: top 20 most connected external IPs in the last 24h
SELECT 
    dst_ip,
    count() AS connection_count,
    uniqExact(endpoint_id) AS endpoint_count,
    groupArray(DISTINCT process_name) AS processes
FROM events_network
WHERE tenant_id = '...'
  AND direction_id = 2                          -- outbound
  AND NOT isIPAddressInRange(toString(dst_ip), '10.0.0.0/8')
  AND NOT isIPAddressInRange(toString(dst_ip), '172.16.0.0/12')
  AND NOT isIPAddressInRange(toString(dst_ip), '192.168.0.0/16')
  AND event_time > now() - INTERVAL 1 DAY
GROUP BY dst_ip
ORDER BY connection_count DESC
LIMIT 20;

-- Anomaly baseline: hourly process launch rate per endpoint over 30 days
SELECT 
    endpoint_id,
    toStartOfHour(event_time) AS hour,
    count() AS launches
FROM events_process
WHERE tenant_id = '...'
  AND activity_id = 1
  AND event_time > now() - INTERVAL 30 DAY
GROUP BY endpoint_id, hour
ORDER BY endpoint_id, hour;
```

### Layer 2: Neo4j -- Attack Graph and Correlation

Neo4j stores a property graph of relationships between security entities, enabling multi-hop traversal queries for attack-chain reconstruction, process-tree analysis, and lateral-movement detection.

```cypher
// Node types (labels)

// (:Endpoint {endpoint_id, tenant_id, hostname, os_type, status})
// (:Process {pid, name, cmd_line, path, hash, start_time, end_time, endpoint_id})
// (:File {path, hash, size, type, endpoint_id})
// (:NetworkConnection {src_ip, src_port, dst_ip, dst_port, protocol, timestamp})
// (:User {name, domain, sid, type})
// (:Alert {alert_id, title, severity, confidence, status, rule_id, timestamp})
// (:Incident {incident_id, title, severity, status, timestamp})
// (:MitreTechnique {technique_id, tactic, name})
// (:ThreatIndicator {type, value, source, threat_type})
// (:DetectionRule {rule_id, title, severity, source})

// Relationship types

// (:Process)-[:SPAWNED]->(:Process)               -- parent-child process tree
// (:Process)-[:INJECTED_INTO]->(:Process)         -- code injection
// (:Process)-[:WROTE]->(:File)                     -- file creation/modification
// (:Process)-[:READ]->(:File)                      -- file access
// (:Process)-[:DELETED]->(:File)                   -- file deletion
// (:Process)-[:CONNECTED_TO]->(:NetworkConnection) -- outbound connection
// (:Process)-[:LISTENED_ON]->(:NetworkConnection)  -- inbound listener
// (:Process)-[:EXECUTED_BY]->(:User)               -- process-to-user attribution
// (:Process)-[:RAN_ON]->(:Endpoint)                -- process-to-host
// (:File)-[:STORED_ON]->(:Endpoint)                -- file location
// (:NetworkConnection)-[:FROM]->(:Endpoint)        -- connection origin
// (:NetworkConnection)-[:TO_EXTERNAL]->(:ThreatIndicator) -- IOC match
// (:Alert)-[:TRIGGERED_BY]->(:Process)             -- detection-to-process link
// (:Alert)-[:MATCHED_RULE]->(:DetectionRule)        -- rule attribution
// (:Alert)-[:MAPS_TO]->(:MitreTechnique)           -- ATT&CK mapping
// (:Alert)-[:PART_OF]->(:Incident)                  -- incident grouping
// (:Incident)-[:AFFECTS]->(:Endpoint)               -- blast radius
// (:DetectionRule)-[:DETECTS]->(:MitreTechnique)    -- rule coverage mapping
```

#### Graph Construction Service

A stream processor consumes telemetry events from Kafka and materializes them into graph nodes and relationships in Neo4j.

```python
# Pseudocode: Graph enricher service

class GraphEnricher:
    """Consumes telemetry events and builds the attack graph in Neo4j."""
    
    def handle_process_launch(self, event: dict) -> None:
        """Create process node and parent-child relationship."""
        tx = neo4j_session.begin_transaction()
        
        # Create or merge the process node
        tx.run("""
            MERGE (p:Process {pid: $pid, endpoint_id: $endpoint_id, start_time: $time})
            SET p.name = $name, p.cmd_line = $cmd_line, 
                p.path = $path, p.hash = $hash
        """, pid=event['process']['pid'], ...)
        
        # Create parent relationship
        tx.run("""
            MATCH (parent:Process {pid: $parent_pid, endpoint_id: $endpoint_id})
            WHERE parent.start_time <= $time
            MATCH (child:Process {pid: $child_pid, endpoint_id: $endpoint_id, 
                                  start_time: $time})
            MERGE (parent)-[:SPAWNED {timestamp: $time}]->(child)
        """, ...)
        
        # Link to endpoint
        tx.run("""
            MATCH (p:Process {pid: $pid, endpoint_id: $endpoint_id, start_time: $time})
            MATCH (e:Endpoint {endpoint_id: $endpoint_id})
            MERGE (p)-[:RAN_ON]->(e)
        """, ...)
        
        tx.commit()
    
    def handle_network_connection(self, event: dict) -> None:
        """Create network connection node linked to process."""
        tx = neo4j_session.begin_transaction()
        
        tx.run("""
            CREATE (nc:NetworkConnection {
                src_ip: $src_ip, src_port: $src_port,
                dst_ip: $dst_ip, dst_port: $dst_port,
                protocol: $protocol, timestamp: $time
            })
            WITH nc
            MATCH (p:Process {pid: $pid, endpoint_id: $endpoint_id})
            WHERE p.start_time <= $time
            MERGE (p)-[:CONNECTED_TO {timestamp: $time}]->(nc)
        """, ...)
        
        # Check for threat intel match
        tx.run("""
            MATCH (nc:NetworkConnection {dst_ip: $dst_ip, timestamp: $time})
            MATCH (ti:ThreatIndicator {type: 'ip', value: $dst_ip})
            MERGE (nc)-[:TO_EXTERNAL]->(ti)
        """, ...)
        
        tx.commit()
```

#### Attack Graph Queries

```cypher
// Full process tree from an alert
MATCH (a:Alert {alert_id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
MATCH path = (root:Process)-[:SPAWNED*0..10]->(p)
WHERE NOT ()-[:SPAWNED]->(root)  // find the tree root
RETURN path

// Lateral movement detection: process on Host A connects to Host B,
// then a new process appears on Host B
MATCH (p1:Process)-[:RAN_ON]->(e1:Endpoint)
MATCH (p1)-[:CONNECTED_TO]->(nc:NetworkConnection)
MATCH (nc)-[:FROM]->(e2:Endpoint)
WHERE e1 <> e2
MATCH (p2:Process)-[:RAN_ON]->(e2)
WHERE p2.start_time > nc.timestamp
  AND p2.start_time < nc.timestamp + duration('PT5M')
RETURN e1.hostname AS source, e2.hostname AS target,
       p1.name AS source_process, p2.name AS target_process,
       nc.dst_port AS port, nc.timestamp AS connection_time

// Attack chain: trace from initial access to impact
MATCH (incident:Incident {incident_id: $incident_id})
MATCH (incident)-[:AFFECTS]->(endpoint:Endpoint)
MATCH path = (initial:Process)-[:SPAWNED|INJECTED_INTO|CONNECTED_TO|WROTE*1..15]->(target)
WHERE initial.endpoint_id = endpoint.endpoint_id
  AND NOT ()-[:SPAWNED]->(initial)
RETURN path
ORDER BY length(path) DESC
LIMIT 5

// MITRE ATT&CK coverage map for a tenant's detection rules
MATCH (r:DetectionRule)-[:DETECTS]->(t:MitreTechnique)
WHERE r.tenant_id = $tenant_id OR r.tenant_id IS NULL
RETURN t.tactic, t.technique_id, t.name, count(r) AS rule_count
ORDER BY t.tactic, t.technique_id

// Find all endpoints touched by a specific threat indicator
MATCH (ti:ThreatIndicator {value: $ioc_value})
MATCH (ti)<-[:TO_EXTERNAL]-(nc:NetworkConnection)<-[:CONNECTED_TO]-(p:Process)-[:RAN_ON]->(e:Endpoint)
RETURN DISTINCT e.hostname, e.endpoint_id, p.name, nc.timestamp
ORDER BY nc.timestamp
```

### Layer 3: PostgreSQL -- Operational State

PostgreSQL handles the same operational entities as in previous suggestions (tenants, users, endpoints, agents, detection rules, alerts, incidents, response actions). The schema is structurally identical to the relational core in Suggestion 3, with the key difference that:

- **Events are NOT stored in PostgreSQL** -- they live in ClickHouse.
- **Alert-to-event references** use event IDs that point into ClickHouse rather than PostgreSQL foreign keys.
- **Incident storylines** are assembled by the application layer from Neo4j graph queries + ClickHouse event lookups.

```sql
-- PostgreSQL: operational state (abbreviated, see Suggestions 1/3 for full DDL)

-- Alert-to-event references (cross-store)
CREATE TABLE alert_events (
    alert_id        UUID NOT NULL REFERENCES alerts(alert_id),
    event_store     VARCHAR(20) NOT NULL DEFAULT 'clickhouse', -- clickhouse, neo4j
    event_id        UUID NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    event_class_uid INTEGER,
    relevance       VARCHAR(20) NOT NULL DEFAULT 'contributing',
    PRIMARY KEY (alert_id, event_id)
);

-- Graph reference for incident storylines
CREATE TABLE incident_graph_refs (
    incident_id     UUID NOT NULL REFERENCES incidents(incident_id),
    graph_root_node VARCHAR(255) NOT NULL,      -- Neo4j node ID or property reference
    graph_query     TEXT,                        -- Cypher query to reconstruct the storyline
    snapshot_json   JSONB,                       -- cached graph snapshot for offline access
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Data Flow

1. **Agent -> Kafka**: Agents emit OCSF-formatted telemetry events to Kafka topics partitioned by tenant_id.
2. **Kafka -> ClickHouse**: A ClickHouse Kafka engine table (or a dedicated ingestion service) consumes events and inserts them into the appropriate ClickHouse table. This path is optimized for throughput.
3. **Kafka -> Graph Enricher -> Neo4j**: A separate consumer builds graph nodes and relationships from the event stream. This path extracts entities and relationships, applying deduplication and temporal logic.
4. **Detection Engine**: Reads from ClickHouse (for rule evaluation over recent events) and Neo4j (for graph-pattern detections like lateral movement). When a rule matches, it writes an AlertRaised record to PostgreSQL and creates corresponding graph nodes/edges in Neo4j.
5. **Investigation UI**: Queries Neo4j for attack-chain visualization, ClickHouse for event timeline and threat hunting, and PostgreSQL for alert/incident workflow state.

---

## Pros

1. **Highest query performance.** ClickHouse handles billions of events with sub-second analytical queries. Neo4j traverses multi-hop attack chains in milliseconds. Each store is purpose-built for its access pattern.
2. **CrowdStrike-class architecture.** This mirrors the Threat Graph architecture that powers the industry's most capable EDR, providing a foundation for enterprise-grade detection and investigation capabilities.
3. **Natural attack-chain modeling.** Graph relationships between processes, files, network connections, and users make lateral movement detection, process tree reconstruction, and blast radius analysis natural queries rather than complex multi-JOIN SQL.
4. **Extreme compression.** ClickHouse's columnar storage with LZ4/ZSTD compression achieves 10-100x compression on telemetry data compared to row-oriented storage, dramatically reducing storage costs.
5. **Independent scaling.** Each layer scales independently: ClickHouse scales horizontally for telemetry volume; Neo4j scales for graph complexity; PostgreSQL scales for operational workload.
6. **Graph-native AI integration.** The Neo4j graph is a natural input for LLM-powered analysis: the attack graph can be serialized as context for AI-generated incident summaries, providing structured relationships rather than raw event dumps.
7. **MITRE ATT&CK as first-class graph.** The entire ATT&CK framework (tactics, techniques, sub-techniques, mitigations, groups) can be loaded as a reference graph in Neo4j, enabling coverage-gap analysis and detection-rule-to-technique mapping as native graph queries.
8. **Built-in TTL.** ClickHouse's native TTL mechanism automatically expires data based on the tenant's retention policy without manual partition management.

## Cons

1. **Highest operational complexity.** Three database systems (ClickHouse, Neo4j, PostgreSQL) plus Kafka, each requiring monitoring, backup, scaling, and upgrades. This is a significant operational burden for a project targeting SMBs.
2. **Cross-store consistency.** No distributed transactions across ClickHouse, Neo4j, and PostgreSQL. The system is eventually consistent, and failure in one pipeline leg can create data divergence.
3. **Cross-store queries.** "Show me the alert details (PostgreSQL) with the attack chain (Neo4j) and the raw events (ClickHouse)" requires the application to query three stores and join the results -- no single query language spans all three.
4. **Neo4j licensing.** Neo4j Community Edition is GPLv3 (copyleft). Neo4j Enterprise requires a commercial license. For an open-source EDR, the Community Edition's clustering and performance limitations may be restrictive. Alternatives (Memgraph, Apache AGE on PostgreSQL) reduce this concern.
5. **Graph data volume management.** The Neo4j graph grows continuously with every process launch, file operation, and network connection. Aggressive pruning, archival, and time-based graph partitioning are required to keep the graph performant.
6. **Development complexity.** Developers must be proficient in SQL (PostgreSQL), ClickHouse SQL dialect, Cypher (Neo4j), and the stream-processing framework. This raises the bar for contributors significantly.
7. **Infrastructure cost.** Three database clusters plus Kafka is substantially more expensive than a single PostgreSQL instance, particularly for small deployments.
8. **Cold-start bootstrapping.** New deployments require seeding the MITRE ATT&CK graph, configuring Kafka topics, setting up ClickHouse schemas, and initializing PostgreSQL -- a complex onboarding process compared to "run one migration."

---

## Technology Recommendations

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Telemetry store | ClickHouse (self-hosted or ClickHouse Cloud) | Columnar, compressed, sub-second analytics at scale |
| Attack graph | Neo4j Community / Apache AGE (PostgreSQL extension) | Property graph model; AGE eliminates separate database if scaling allows |
| Operational DB | PostgreSQL 16+ | RLS, ACID, mature ecosystem |
| Event bus | Redpanda (preferred) or Apache Kafka | Append-only, partitioned, lower ops than Kafka |
| Graph enrichment | Flink or Kafka Streams | Stream processing for graph construction |
| Visualization | D3.js / vis.js for graph rendering | Attack chain visualization in the console |
| AI integration | Neo4j graph serialization -> LLM context | Structured attack narrative for AI summarization |

### Apache AGE as Neo4j Alternative

For deployments where operational simplicity is paramount, Apache AGE (a PostgreSQL extension) provides Cypher query support within PostgreSQL itself, eliminating the need for a separate Neo4j instance:

```sql
-- Apache AGE: graph queries inside PostgreSQL
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

SELECT * FROM cypher('attack_graph', $$
    MATCH (a:Alert {alert_id: 'abc-123'})-[:TRIGGERED_BY]->(p:Process)
    MATCH path = (root:Process)-[:SPAWNED*0..10]->(p)
    WHERE NOT ()-[:SPAWNED]->(root)
    RETURN path
$$) AS (path agtype);
```

This reduces the architecture from three databases to two (PostgreSQL with AGE + ClickHouse), trading some graph query performance for operational simplicity.

---

## Migration and Scaling Considerations

### Migration Path
- **From Suggestion 3 (hybrid PostgreSQL)**: Extract the events table data into ClickHouse. Build the graph enricher to consume Kafka and populate Neo4j/AGE. Keep the PostgreSQL operational tables unchanged. This migration can be done incrementally -- run both systems in parallel, switch reads to ClickHouse when validated.
- **Phased deployment**: Start with PostgreSQL + AGE (two-layer architecture). Add ClickHouse when event volume exceeds PostgreSQL's comfortable range (~10K events/sec). This provides a smooth growth path from Suggestion 3 to Suggestion 4.

### Scaling Strategy
- **ClickHouse**: Horizontal sharding by tenant_id across ClickHouse cluster nodes. Each shard holds complete tenant data for query locality. ClickHouse Cloud provides managed auto-scaling.
- **Neo4j**: Graph sharding is challenging. Prefer vertical scaling (larger instance) and time-based graph pruning (keep only the last 7-14 days of process/connection nodes; archive older relationships). For extreme scale, Neo4j Fabric provides federated graph queries across shards.
- **PostgreSQL**: Same as Suggestions 1/3 -- read replicas, Citus for horizontal scaling if needed.
- **Kafka/Redpanda**: Add partitions and brokers as tenant count and event volume grow. Topic-per-tenant or partition-by-tenant-hash, depending on tenant count.

### Data Retention
- **ClickHouse TTL**: Automatic per-table or per-partition expiration based on `event_time`. No manual partition management needed.
- **Neo4j pruning**: Background job removes process/file/connection nodes older than the configured retention window. Alert and incident graph nodes are retained indefinitely as they represent workflow state.
- **PostgreSQL**: Standard partition-based retention for audit logs. Operational tables (alerts, incidents) retained indefinitely.
- **Compliance exports**: ClickHouse's Parquet export + Neo4j's APOC export library generate compliance evidence packs combining event data and attack-chain graphs.

### Deployment Tiers

| Tier | Architecture | Target |
|------|-------------|--------|
| Starter | PostgreSQL + AGE (no ClickHouse) | <100 endpoints, self-hosted SMB |
| Standard | PostgreSQL + AGE + ClickHouse | 100-1000 endpoints, MSP |
| Enterprise | PostgreSQL + Neo4j + ClickHouse + Kafka | 1000+ endpoints, large MSP or enterprise |

This tiered approach lets the project start simple and adopt more sophisticated data infrastructure as deployment scale demands it, without requiring a rewrite.
