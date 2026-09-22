# NIDS ARC — Detailed Design Document

This document captures implementation-level design decisions for the NIDS ARC platform.

---

## 1. Frontend Design

### 1.1 Layout
- **Dark theme** with high-contrast accents for alert severity
- **Sidebar navigation** (collapsible) on the left
- **Top bar** with: system mode indicator (SIMULATION/LIVE/REPLAY), user info, notifications bell, settings gear
- **Main content area** with breadcrumbs
- **Footer** with system health summary strip

### 1.2 Navigation Structure
```
├── Overview (/)
├── Monitoring
│   ├── Live Alerts (/alerts)
│   ├── Event Explorer (/events)
│   ├── Incidents (/incidents)
│   ├── Attack Timeline (/timeline)
│   └── Network Activity (/network)
├── Infrastructure
│   ├── Sensors (/sensors)
│   ├── Detection Engines (/engines)
│   └── System Health (/health)
├── Intelligence
│   ├── Threat Intelligence (/threat-intel)
│   ├── Models (/models)
│   └── Rules (/rules)
├── Operations
│   ├── Response Actions (/responses)
│   └── Audit Logs (/audit)
└── Settings (/settings)
```

### 1.3 Dashboard Components

#### Overview Page
- **Mode Banner**: Large, clear indicator showing SIMULATION/LIVE/REPLAY
- **Key Metrics Row**: Total events (24h), Active alerts, Open incidents, Risk score (system-wide)
- **Alert Severity Distribution**: Donut chart (critical/high/medium/low)
- **Event Rate Chart**: Line chart showing events/minute over last hour
- **Top Sources**: Table of top 10 source IPs by event count
- **Detection Engine Status**: Grid showing each engine's status (active/inactive/error)
- **Recent Alerts**: Live-updating list of 10 most recent alerts
- **Sensor Status**: Grid of sensor cards with connectivity status

#### Live Alerts Page
- **Filter bar**: Severity, status, detector, time range, source IP
- **Alert cards/table**: Sortable, paginated list
- **Alert detail panel**: Slide-out with full context, evidence, risk factors, response options
- **Triage controls**: Acknowledge, investigate, resolve, false positive buttons
- **Auto-refresh**: Configurable polling interval

#### Event Explorer
- **Search bar**: Full-text and field-specific search
- **Filter chips**: Protocol, severity, event_type, sensor_id, time range
- **Results table**: Paginated, sortable by any column
- **Event detail modal**: Full event data, raw event, detection results
- **Export button**: JSON download

#### Incidents Page
- **Incident cards**: Grouped by status (active, investigating, resolved)
- **Incident detail**: Timeline of constituent events, attack stage mapping, MITRE ATT&CK overlay
- **Incident actions**: Assign, escalate, resolve

#### Attack Timeline
- **Horizontal timeline**: Events plotted on time axis, colored by severity
- **Zoom controls**: Hour, day, week views
- **Entity filter**: Filter by source/destination IP
- **Attack chain overlay**: Lines connecting related events

#### Network Activity
- **Traffic rate chart**: Bytes/packets over time
- **Protocol distribution**: Pie chart
- **Top talkers**: Source and destination tables
- **Connection map**: Simple grid/matrix of src→dst connections
- **Anomaly highlights**: Visually mark anomalous data points

#### Sensors Page
- **Sensor cards**: Name, type, status (real/simulation/replay/unavailable/error), last_seen, event rate
- **Health indicators**: Green/yellow/red status dots
- **Sensor detail**: Configuration, event history, health metrics

#### Detection Engines Page
- **Engine status cards**: Each engine with active/inactive/error status
- **Detection rate**: Events processed, detections generated, false positive rate
- **Confidence distribution**: Histogram of detection confidence values
- **Rule/model counts**: Active rules per engine

#### Threat Intelligence Page
- **IOC summary**: Counts by type (IP, domain, URL, hash)
- **Recent matches**: Events matched against IOCs
- **Feed status**: Active feeds with last update time
- **IOC search**: Search by value

#### Response Actions Page
- **Pending approvals**: Actions awaiting manual approval
- **Action history**: Executed actions with status
- **Policy overview**: Active response policies
- **Approve/reject controls**: For manual approval mode

#### Models Page
- **Model cards**: Name, version, status (active/staging/retired)
- **Performance metrics**: Accuracy, precision, recall, F1
- **Inference stats**: Avg latency, predictions/sec
- **Deploy/rollback controls**: Admin only

#### Rules Page
- **Rule table**: ID, name, severity, status (enabled/disabled), engine, version
- **Rule editor**: View/edit rule definition
- **Enable/disable toggle**: Per rule
- **Reload button**: Reload rules from source

#### Audit Logs Page
- **Log table**: Timestamp, actor, action, target, result, source IP
- **Filters**: Actor, action type, time range
- **No edit/delete controls**: Append-only viewing

#### System Health Page
- **Component grid**: API, Database, Redis, Message Bus, each detector
- **Status indicators**: Healthy/degraded/down
- **Metrics charts**: CPU, memory, event rate, queue lag
- **Uptime**: Per component

#### Settings Page
- **General**: System mode, default behavior
- **Detection**: Thresholds, engine enable/disable
- **Response**: Default mode, policies
- **Retention**: Data retention periods
- **Users**: User management (admin only)
- **About**: Version info, documentation links

### 1.4 Color Palette
```
Background:        #0f1117
Surface:           #1a1d27
Surface Elevated:  #242836
Border:            #2d3248
Text Primary:      #e4e6f0
Text Secondary:    #8b8fa3
Accent Primary:    #6366f1 (Indigo)
Accent Secondary:  #06b6d4 (Cyan)
Success:           #22c55e
Warning:           #f59e0b
Error/Critical:    #ef4444
High Severity:     #f97316
Medium Severity:   #eab308
Low Severity:      #3b82f6
Info:              #8b5cf6
```

### 1.5 Typography
- **Primary Font**: Inter (Google Fonts)
- **Monospace**: JetBrains Mono (for IPs, hashes, code)
- **Heading Scale**: 2rem, 1.5rem, 1.25rem, 1.1rem, 1rem
- **Body**: 0.9rem

---

## 2. Backend Design

### 2.1 Service Boundaries

The backend is a modular monolith with clear internal boundaries:

```
backend/
├── app.py                  # Application factory
├── config.py               # Configuration management
├── database.py             # Database connection, session
├── __init__.py
│
├── api/                    # API layer (thin controllers)
│   └── v1/
│       ├── auth.py
│       ├── users.py
│       ├── sensors.py
│       ├── events.py
│       ├── alerts.py
│       ├── incidents.py
│       ├── detections.py
│       ├── threat_intel.py
│       ├── risk.py
│       ├── response.py
│       ├── models.py
│       ├── rules.py
│       ├── audit.py
│       ├── health.py
│       └── ingestion.py
│
├── middleware/              # Cross-cutting concerns
│   ├── auth.py             # JWT validation
│   ├── rbac.py             # Permission checking
│   ├── rate_limit.py       # Rate limiting
│   ├── error_handler.py    # Exception → HTTP response
│   ├── logging.py          # Request/response logging
│   └── security_headers.py # Security headers
│
├── services/               # Business logic
│   ├── auth_service.py
│   ├── user_service.py
│   ├── sensor_service.py
│   ├── event_service.py
│   ├── alert_service.py
│   ├── ingestion_service.py
│   └── ...
│
├── detection/              # Detection engines
│   ├── base.py             # Detector interface
│   ├── orchestrator.py     # Detection routing
│   ├── signature.py        # Signature detector
│   ├── anomaly.py          # Anomaly detector
│   ├── behavioral.py       # Behavioral detector
│   ├── ml_detector.py      # ML detector
│   ├── baseline.py         # Baseline tracking
│   ├── features.py         # Feature extraction
│   ├── patterns.py         # Behavioral patterns
│   └── sequence.py         # Sequence analysis
│
├── ml/                     # ML subsystem
│   ├── model_interface.py  # Abstract model interface
│   ├── model_registry.py   # Model versioning
│   ├── inference.py        # Inference service
│   ├── training.py         # Training pipeline
│   ├── features.py         # ML feature engineering
│   └── models/             # Model artifacts
│
├── threat_intel/           # Threat intelligence
│   ├── provider.py         # TI provider interface
│   ├── store.py            # IOC store
│   ├── matcher.py          # IOC matcher
│   └── mock_adapter.py     # Mock TI feed (labeled)
│
├── correlation/            # Correlation engine
│   ├── engine.py           # Correlation logic
│   ├── rules.py            # Correlation rules
│   └── incident.py         # Incident builder
│
├── risk/                   # Risk engine
│   ├── engine.py           # Risk calculator
│   ├── factors.py          # Risk factor definitions
│   └── explainer.py        # Risk explanation
│
├── response/               # Response engine
│   ├── engine.py           # Response orchestrator
│   ├── policy.py           # Policy evaluation
│   ├── actions.py          # Action implementations
│   └── approval.py         # Manual approval workflow
│
├── sensors/                # Sensor adapters
│   ├── base.py             # SensorAdapter interface
│   ├── manager.py          # Sensor lifecycle management
│   ├── simulation.py       # Simulation sensor
│   ├── pcap.py             # PCAP replay sensor
│   ├── suricata.py         # Suricata adapter (interface)
│   └── zeek.py             # Zeek adapter (interface)
│
├── bus/                    # Message bus
│   ├── base.py             # MessageBus interface
│   ├── redis_bus.py        # Redis Streams implementation
│   └── memory_bus.py       # In-memory bus for testing
│
├── models/                 # SQLAlchemy ORM models
│   ├── user.py
│   ├── sensor.py
│   ├── event.py
│   ├── alert.py
│   ├── incident.py
│   ├── detection.py
│   ├── rule.py
│   ├── ml_model.py
│   ├── threat_intel.py
│   ├── response_action.py
│   ├── audit_log.py
│   └── system_health.py
│
├── schemas/                # Pydantic schemas
│   ├── events.py
│   ├── alerts.py
│   ├── detections.py
│   ├── auth.py
│   ├── users.py
│   ├── sensors.py
│   ├── incidents.py
│   ├── threat_intel.py
│   ├── risk.py
│   ├── response.py
│   ├── rules.py
│   ├── ml_models.py
│   ├── audit.py
│   ├── health.py
│   └── common.py
│
├── repositories/           # Data access layer
│   ├── base.py             # Base repository
│   ├── user_repo.py
│   ├── event_repo.py
│   ├── alert_repo.py
│   └── ...
│
└── ingestion/              # Ingestion pipeline
    ├── service.py          # Ingestion orchestrator
    ├── normalizer.py       # Event normalization
    ├── flow_aggregator.py  # Flow aggregation
    └── worker.py           # Ingestion worker
```

### 2.2 API Structure

All APIs are versioned under `/api/v1/`.

#### Request/Response Patterns

**List Response**:
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total": 1234,
    "total_pages": 25
  },
  "meta": {
    "request_id": "uuid",
    "timestamp": "ISO-8601",
    "mode": "simulation"
  }
}
```

**Single Item Response**:
```json
{
  "data": {...},
  "meta": {
    "request_id": "uuid",
    "timestamp": "ISO-8601"
  }
}
```

**Error Response**:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable message",
    "details": [
      {"field": "src_ip", "message": "Invalid IP address format"}
    ]
  },
  "meta": {
    "request_id": "uuid",
    "timestamp": "ISO-8601"
  }
}
```

### 2.3 Validation Strategy
- **Request validation**: Pydantic models with field validators
- **Path parameters**: Type-checked by FastAPI
- **Query parameters**: Validated with defaults
- **Request body**: Full Pydantic model validation
- **Business validation**: Service layer (e.g., user exists, rule is valid)

### 2.4 Authentication Flow
```
1. POST /api/v1/auth/login { username, password }
2. Server validates credentials (bcrypt verify)
3. Server returns { access_token (15min), refresh_token (7d) }
4. Client includes Authorization: Bearer <access_token>
5. Middleware validates JWT, extracts user context
6. On expiry: POST /api/v1/auth/refresh { refresh_token }
7. Server issues new access_token, rotates refresh_token
```

### 2.5 Authorization Flow
```
1. AuthMiddleware extracts user from JWT
2. RBACMiddleware checks user.role against endpoint permission
3. If allowed → proceed to handler
4. If denied → 403 Forbidden with error response
```

### 2.6 Error Handling Strategy
| Exception | HTTP Status | Error Code |
|---|---|---|
| ValidationError | 400 | VALIDATION_ERROR |
| AuthenticationError | 401 | AUTHENTICATION_ERROR |
| AuthorizationError | 403 | AUTHORIZATION_ERROR |
| NotFoundError | 404 | NOT_FOUND |
| ConflictError | 409 | CONFLICT |
| RateLimitError | 429 | RATE_LIMIT_EXCEEDED |
| InternalError | 500 | INTERNAL_ERROR |

---

## 3. Data Design

### 3.1 Entity Definitions

#### User
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| username | String(50) | Unique, not null |
| email | String(255) | Unique, not null |
| password_hash | String(255) | Not null |
| role | Enum(admin, analyst, viewer, system) | Not null, default=viewer |
| is_active | Boolean | Default=true |
| failed_login_attempts | Integer | Default=0 |
| locked_until | DateTime | Nullable |
| last_login | DateTime | Nullable |
| created_at | DateTime | Auto |
| updated_at | DateTime | Auto |

#### Sensor
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| name | String(100) | Not null |
| sensor_type | Enum(simulation, suricata, zeek, pcap, ebpf) | Not null |
| status | Enum(active, inactive, error, unavailable) | Not null |
| host | String(255) | Nullable |
| port | Integer | Nullable |
| config | JSON | Nullable |
| last_seen | DateTime | Nullable |
| events_total | BigInteger | Default=0 |
| created_at | DateTime | Auto |
| updated_at | DateTime | Auto |

#### SecurityEvent
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| timestamp | DateTime | Not null, indexed |
| source_type | Enum(real, simulation, replay) | Not null |
| sensor_id | UUID | FK → Sensor, indexed |
| src_ip | String(45) | Indexed |
| src_port | Integer | Nullable |
| dst_ip | String(45) | Indexed |
| dst_port | Integer | Nullable |
| protocol | String(20) | Nullable |
| event_type | String(50) | Indexed |
| raw_data | JSON | Nullable |
| metadata | JSON | Nullable |
| bytes_sent | BigInteger | Default=0 |
| bytes_received | BigInteger | Default=0 |
| packets_sent | Integer | Default=0 |
| packets_received | Integer | Default=0 |
| duration_ms | Integer | Default=0 |
| created_at | DateTime | Auto |

#### DetectionResult
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| event_id | UUID | FK → SecurityEvent |
| detector | String(50) | Not null |
| detector_version | String(20) | Not null |
| rule_id | String(50) | Nullable |
| model_id | String(50) | Nullable |
| model_version | String(20) | Nullable |
| severity | Enum(critical, high, medium, low, info) | Not null |
| confidence | Float | 0.0–1.0, not null |
| attack_category | String(100) | Nullable |
| evidence | JSON | Not null |
| mitre_attack | JSON | Nullable |
| tags | JSON | Nullable |
| created_at | DateTime | Auto |

#### Alert
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| title | String(255) | Not null |
| description | Text | Nullable |
| severity | Enum(critical, high, medium, low, info) | Not null |
| status | Enum(new, acknowledged, investigating, resolved, false_positive) | Default=new |
| source_type | Enum(real, simulation, replay) | Not null |
| event_ids | JSON | Array of event UUIDs |
| detection_ids | JSON | Array of detection UUIDs |
| risk_score | Float | Nullable |
| risk_factors | JSON | Nullable |
| assigned_to | UUID | FK → User, nullable |
| resolved_by | UUID | FK → User, nullable |
| resolved_at | DateTime | Nullable |
| notes | Text | Nullable |
| created_at | DateTime | Auto |
| updated_at | DateTime | Auto |

#### Incident
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| title | String(255) | Not null |
| description | Text | Nullable |
| severity | Enum(critical, high, medium, low) | Not null |
| status | Enum(active, investigating, contained, resolved, closed) | Default=active |
| attack_stage | String(50) | Nullable |
| mitre_tactics | JSON | Array of MITRE tactic IDs |
| alert_ids | JSON | Array of alert UUIDs |
| event_count | Integer | Default=0 |
| first_seen | DateTime | Not null |
| last_seen | DateTime | Not null |
| src_entities | JSON | Array of source IPs/hosts |
| dst_entities | JSON | Array of destination IPs/hosts |
| assigned_to | UUID | FK → User, nullable |
| created_at | DateTime | Auto |
| updated_at | DateTime | Auto |

#### ThreatIntelRecord
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| indicator_type | Enum(ip, domain, url, hash, email) | Not null |
| value | String(500) | Not null, indexed |
| source | String(100) | Not null |
| confidence | Float | 0.0–1.0 |
| severity | Enum(critical, high, medium, low, info) | Nullable |
| tags | JSON | Nullable |
| first_seen | DateTime | Nullable |
| last_seen | DateTime | Nullable |
| expiry | DateTime | Nullable |
| is_active | Boolean | Default=true |
| metadata | JSON | Nullable |
| created_at | DateTime | Auto |

#### ResponseAction
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| action_type | Enum(alert_only, notify, increase_monitoring, temporary_block, firewall_rule, host_quarantine, session_terminate) | Not null |
| status | Enum(pending, approved, rejected, executing, executed, failed, rolled_back) | Default=pending |
| requested_by | String(50) | Not null (system or user_id) |
| policy_id | String(50) | Nullable |
| alert_id | UUID | FK → Alert, nullable |
| incident_id | UUID | FK → Incident, nullable |
| target | JSON | Target details (IP, host, etc.) |
| confidence | Float | 0.0–1.0 |
| parameters | JSON | Action-specific parameters |
| result | JSON | Execution result |
| approved_by | UUID | FK → User, nullable |
| executed_at | DateTime | Nullable |
| rollback_id | UUID | Nullable, FK → ResponseAction |
| is_dry_run | Boolean | Default=false |
| created_at | DateTime | Auto |
| updated_at | DateTime | Auto |

#### AuditLog
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| timestamp | DateTime | Not null, indexed |
| actor_id | UUID | Nullable (system actions) |
| actor_username | String(50) | Nullable |
| action | String(100) | Not null, indexed |
| resource_type | String(50) | Not null |
| resource_id | String(255) | Nullable |
| details | JSON | Action-specific details |
| source_ip | String(45) | Nullable |
| result | Enum(success, failure, error) | Not null |
| created_at | DateTime | Auto |

#### ModelVersion
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| model_name | String(100) | Not null |
| version | String(50) | Not null |
| status | Enum(training, validating, staging, active, retired) | Not null |
| algorithm | String(100) | Nullable |
| training_data_hash | String(64) | Nullable |
| metrics | JSON | Accuracy, precision, recall, F1, etc. |
| parameters | JSON | Hyperparameters |
| artifact_path | String(500) | Path to model file |
| deployed_at | DateTime | Nullable |
| deployed_by | UUID | FK → User, nullable |
| created_at | DateTime | Auto |

#### RuleVersion
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| rule_name | String(100) | Not null |
| version | Integer | Not null |
| engine | String(50) | Not null (signature, anomaly, behavioral) |
| severity | Enum(critical, high, medium, low, info) | Not null |
| content | Text | Rule definition |
| is_enabled | Boolean | Default=true |
| metadata | JSON | Tags, MITRE mapping, description |
| created_by | UUID | FK → User, nullable |
| created_at | DateTime | Auto |

#### SystemHealth
| Field | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| component | String(100) | Not null |
| status | Enum(healthy, degraded, down, unknown) | Not null |
| details | JSON | Component-specific metrics |
| last_check | DateTime | Not null |
| created_at | DateTime | Auto |

---

## 4. Canonical Event Schema

The canonical normalized event schema is the core data structure that flows through the entire pipeline. All sensor outputs are normalized to this schema before processing.

```python
class SecurityEventSchema:
    # Identity
    event_id: UUID                          # Unique event identifier
    timestamp: datetime                     # Event occurrence time (UTC)
    ingested_at: datetime                   # Ingestion time (UTC)

    # Provenance
    source_type: Literal["real", "simulation", "replay"]
    sensor_id: UUID                         # Originating sensor
    sensor_name: str                        # Sensor display name

    # Network 5-tuple
    src_ip: str                             # Source IP (v4 or v6)
    src_port: Optional[int]                 # Source port
    dst_ip: str                             # Destination IP
    dst_port: Optional[int]                 # Destination port
    protocol: Optional[str]                 # TCP, UDP, ICMP, etc.

    # Flow metrics
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration_ms: int = 0

    # Classification
    event_type: str                         # connection, dns_query, http_request, etc.
    attack_category: Optional[str]          # port_scan, brute_force, malware, etc.
    severity: Severity                      # critical, high, medium, low, info

    # Detection (populated by detection pipeline)
    detections: List[DetectionResult] = []
    confidence: Optional[float]             # Aggregate confidence (0.0–1.0)
    risk_score: Optional[float]             # Calculated risk score

    # Enrichment
    tags: List[str] = []
    mitre_attack: Optional[dict]            # {"tactic": "...", "technique": "..."}

    # References
    raw_reference: Optional[str]            # Reference to raw event/pcap
    related_event_ids: List[UUID] = []

    # Response
    response_state: Optional[str]           # none, alerted, responded, blocked

    # Metadata
    metadata: Optional[dict]                # Additional sensor-specific data
```

### DetectionResult Schema
```python
class DetectionResultSchema:
    detection_id: UUID
    event_id: UUID
    detector: str                           # "signature", "anomaly", "behavioral", "ml"
    detector_version: str                   # "1.0.0"
    rule_id: Optional[str]                  # For signature detector
    model_id: Optional[str]                 # For ML detector
    model_version: Optional[str]
    severity: Severity
    confidence: float                       # 0.0–1.0
    attack_category: Optional[str]
    evidence: dict                          # Detector-specific evidence
    explanation: Optional[str]              # Human-readable explanation
    mitre_attack: Optional[dict]
    tags: List[str] = []
    timestamp: datetime
```

### RiskAssessment Schema
```python
class RiskAssessmentSchema:
    assessment_id: UUID
    entity: str                             # IP, host, user
    entity_type: str                        # "ip", "host", "user"
    risk_score: float                       # 0.0–100.0
    risk_level: str                         # "critical", "high", "medium", "low"
    risk_factors: List[RiskFactor]
    risk_explanation: str                   # Human-readable summary
    detection_count: int
    detector_agreement: int                 # How many detectors flagged
    timestamp: datetime

class RiskFactor:
    factor: str                             # "detection_confidence", "asset_criticality", etc.
    value: float                            # Factor value
    weight: float                           # Configured weight
    contribution: float                     # Weighted contribution to total
    description: str                        # Human-readable description
```

---

## 5. Technology Decisions

### Decision Log

| ID | Decision | Rationale | Alternatives Considered |
|---|---|---|---|
| TD-01 | Python 3.12 + FastAPI | Async-first, excellent ecosystem for security/ML, rapid development | Go (better perf, less ML ecosystem), Node.js (less suitable for security tooling) |
| TD-02 | SQLAlchemy + SQLite (dev) / PostgreSQL (prod) | ORM portability, SQLite zero-config for dev | Raw SQL (less portable), MongoDB (less relational) |
| TD-03 | Redis Streams (dev message bus) | Lightweight, familiar, good for dev; Kafka interface for prod | RabbitMQ (more complex), direct Kafka (requires Java infra) |
| TD-04 | Pydantic v2 for schemas | FastAPI native, excellent validation, good perf | marshmallow, attrs |
| TD-05 | bcrypt for passwords | Industry standard, resistant to GPU attacks | argon2 (better but less portable) |
| TD-06 | PyJWT for tokens | Lightweight, well-maintained | python-jose, authlib |
| TD-07 | scikit-learn for ML | Lightweight, no GPU needed, good for tabular data | PyTorch (overkill for tabular), XGBoost (additional dep) |
| TD-08 | Vanilla HTML/CSS/JS for frontend | Per workspace guidelines, no framework dependency | React, Vue, Svelte |
| TD-09 | Docker Compose for development | Easy local setup, reproducible | Kubernetes (overkill for dev) |
| TD-10 | Modular monolith architecture | Faster development, can be split later | Microservices (premature at this scale) |

---

## 6. Directory Structure

```
NIDS/
├── PRD.md
├── ARCHITECTURE.md
├── RULES.md
├── PHASES.md
├── DESIGN.md
├── README.md
├── .gitignore
├── .env.example
├── pyproject.toml
├── docker-compose.yml
│
├── backend/
│   ├── __init__.py
│   ├── app.py
│   ├── config.py
│   ├── database.py
│   ├── api/
│   ├── middleware/
│   ├── services/
│   ├── detection/
│   ├── ml/
│   ├── threat_intel/
│   ├── correlation/
│   ├── risk/
│   ├── response/
│   ├── sensors/
│   ├── bus/
│   ├── ingestion/
│   ├── models/
│   ├── schemas/
│   └── repositories/
│
├── frontend/
│   ├── index.html
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   ├── app.js
│   │   ├── router.js
│   │   ├── api.js
│   │   ├── auth.js
│   │   └── pages/
│   └── assets/
│
├── configs/
│   ├── detection/
│   │   ├── signature_rules.yaml
│   │   ├── anomaly_config.yaml
│   │   ├── behavioral_patterns.yaml
│   │   └── ml_config.yaml
│   ├── response/
│   │   └── policies.yaml
│   └── threat_intel/
│       └── mock_iocs.yaml
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── api/
│   ├── security/
│   ├── detection/
│   └── performance/
│
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── nginx.conf
│
├── scripts/
│   ├── setup.py
│   ├── seed_data.py
│   └── generate_sample_pcap.py
│
├── data/
│   └── sample/
│       └── sample_traffic.pcap
│
└── monitoring/
    └── health_checks.py
```

---

## 6. Deviations from Suggested Structure

| Suggested | Actual | Reason |
|---|---|---|
| Separate `anomaly/`, `behavior/` top-level dirs | `backend/detection/` unified | All detectors share the same interface and are tightly related; unified module reduces import complexity |
| Separate `storage/` dir | `backend/repositories/` + `backend/models/` | Repository pattern is more specific and follows clean architecture naming |
| Separate `schemas/` top-level | `backend/schemas/` | Schemas are Python Pydantic models, belong with backend |
| `rules/` top-level | `configs/detection/` | Rules are configuration, not code; belong in configs |
| `models/` top-level (ML) | `backend/ml/models/` | ML model artifacts belong with ML subsystem |
