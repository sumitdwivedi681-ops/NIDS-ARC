# NIDS ARC — Phased Implementation Roadmap

Each phase is gated: a phase is COMPLETE only when its acceptance criteria pass. Do not proceed to the next phase until the current phase is done.

---

## PHASE 0 — Repository Bootstrap

### Objective
Set up the project structure, tooling, configuration, and development environment so that all subsequent phases have a solid foundation.

### Dependencies
None (first phase)

### Inputs
- Architecture decisions from ARCHITECTURE.md and DESIGN.md
- Technology stack decisions

### Outputs
- Project directory structure
- Python project configuration (pyproject.toml, requirements)
- Docker configuration (Dockerfile, docker-compose.yml)
- Environment template (.env.example)
- Git configuration (.gitignore)
- Base logging setup
- Configuration management module
- Empty test scaffold

### Components Created
- `backend/` — empty FastAPI scaffold
- `frontend/` — empty HTML scaffold
- `configs/` — sample configuration files
- `docker/` — Docker and compose files
- `scripts/` — utility scripts
- `tests/` — test directory structure

### API Changes
None

### Database Changes
None

### Tests
- Verify project imports work
- Verify Docker build succeeds

### Acceptance Criteria
- [ ] Directory structure matches DESIGN.md
- [ ] `pip install -e .` succeeds
- [ ] Docker build succeeds
- [ ] `.env.example` exists with all required variables (no real secrets)
- [ ] `.gitignore` covers Python, env, IDE, Docker artifacts
- [ ] Logging produces structured JSON output

### Security Considerations
- No secrets committed
- `.env` in .gitignore

### Performance Considerations
None for this phase

### Rollback Strategy
Delete and recreate directory structure

### Definition of Done
All acceptance criteria pass; another developer can clone and set up the project

---

## PHASE 1 — Core Backend

### Objective
Build the FastAPI application shell with configuration, logging, health endpoints, error handling, CORS, and API router structure.

### Dependencies
Phase 0

### Inputs
- Project structure from Phase 0
- API design from DESIGN.md

### Outputs
- Running FastAPI application
- Health endpoints (/health, /ready, /live)
- Structured logging middleware
- Error handling middleware
- CORS configuration
- Security headers middleware
- Base API router with version prefix (/api/v1/)

### Components Created
- `backend/app.py` — Application factory
- `backend/config.py` — Configuration management
- `backend/middleware/` — Logging, error handling, security headers
- `backend/api/v1/` — Router structure
- `backend/api/v1/health.py` — Health endpoints

### API Changes
```
GET /health — System health summary
GET /ready — Readiness check
GET /live — Liveness check
```

### Database Changes
None

### Tests
- Health endpoints return correct status codes
- Error handler returns structured error responses
- Security headers present on responses
- CORS headers correct

### Acceptance Criteria
- [ ] `uvicorn` starts the application successfully
- [ ] GET /health returns 200 with JSON body
- [ ] GET /ready returns 200 or 503 based on dependency status
- [ ] GET /live returns 200
- [ ] Unhandled exceptions return structured 500 response (no stack trace in production)
- [ ] Security headers present on all responses
- [ ] Request logging includes method, path, status, duration

### Security Considerations
- No sensitive data in health endpoint responses
- Security headers configured per RULES.md SR-08

### Performance Considerations
- Async request handling
- Lightweight middleware

### Rollback Strategy
Revert to Phase 0 scaffold

### Definition of Done
API server starts, health endpoints work, error handling is structured, headers are secure

---

## PHASE 2 — Data Models and Event Schema

### Objective
Define all database models, the canonical event schema, and the repository pattern for data access.

### Dependencies
Phase 1

### Inputs
- Entity definitions from DESIGN.md
- Event schema from DESIGN.md

### Outputs
- SQLAlchemy ORM models for all entities
- Pydantic schemas for API request/response
- Canonical SecurityEvent schema
- DetectionResult schema
- Database initialization and migration support
- Repository pattern implementation

### Components Created
- `backend/models/` — SQLAlchemy models
- `backend/schemas/` — Pydantic schemas
- `backend/repositories/` — Repository pattern classes
- `backend/database.py` — Database connection and session management

### API Changes
None (models only)

### Database Changes
- Create all tables: users, roles, sensors, events, alerts, incidents, detection_results, rules, models, threat_intel, audit_logs, response_actions, system_health

### Tests
- Model creation and validation
- Schema serialization/deserialization
- Repository CRUD operations
- Database initialization

### Acceptance Criteria
- [ ] All entity models defined with proper relationships
- [ ] Canonical event schema validates correct events and rejects malformed ones
- [ ] DetectionResult schema enforces required fields (detector, confidence, evidence)
- [ ] Repository pattern provides CRUD for all entities
- [ ] Database tables created on first run
- [ ] Pydantic schemas validate API inputs/outputs

### Security Considerations
- Password field never serialized in user response schema
- Audit log model is append-only (no update/delete methods)

### Performance Considerations
- Indexes defined on query-heavy columns
- Efficient serialization

### Rollback Strategy
Drop and recreate tables

### Definition of Done
All models, schemas, and repositories are defined and tested

---

## PHASE 3 — Telemetry Ingestion

### Objective
Build the ingestion pipeline: message bus abstraction, event normalization, flow aggregation, and the simulation data generator.

### Dependencies
Phase 2

### Inputs
- Canonical event schema from Phase 2
- Message bus design from ARCHITECTURE.md

### Outputs
- Message bus interface and Redis Streams implementation
- Event normalizer
- Flow aggregator
- Simulation data generator (MODE A)
- PCAP replay adapter (MODE B)
- Ingestion worker that reads from bus and processes events

### Components Created
- `backend/ingestion/` — Ingestion service, normalizer, flow aggregator
- `backend/bus/` — Message bus interface and Redis implementation
- `backend/simulation/` — Synthetic traffic generator
- `backend/pcap/` — PCAP replay adapter

### API Changes
```
POST /api/v1/ingestion/start — Start ingestion (simulation/replay)
POST /api/v1/ingestion/stop — Stop ingestion
GET  /api/v1/ingestion/status — Current ingestion status
POST /api/v1/ingestion/replay — Start PCAP replay
```

### Database Changes
- Events stored in events table

### Tests
- Simulation generator produces valid events
- Normalizer converts raw events to canonical schema
- Flow aggregator correctly groups packets
- Message bus publish/subscribe works
- Ingestion worker processes events end-to-end

### Acceptance Criteria
- [ ] Simulation mode generates events at configurable rate
- [ ] Every simulated event has `source_type = "simulation"`
- [ ] Events are published to message bus
- [ ] Ingestion worker consumes and normalizes events
- [ ] Flow aggregation groups related packets
- [ ] Events stored in database
- [ ] PCAP replay reads from file and publishes events

### Security Considerations
- Ingestion endpoints require authentication
- Event validation rejects malformed inputs

### Performance Considerations
- Batch processing for high-throughput ingestion
- Async message bus operations
- Configurable batch size and worker count

### Rollback Strategy
Stop ingestion, clear event queue, revert code

### Definition of Done
Simulation mode generates events, events flow through bus to database

---

## PHASE 4 — Sensor Integration

### Objective
Build the sensor adapter abstraction and implement simulation and PCAP sensors, with interface stubs for Suricata and Zeek.

### Dependencies
Phase 3

### Inputs
- Sensor layer design from ARCHITECTURE.md

### Outputs
- SensorAdapter interface
- SimulationSensor implementation
- PcapSensor implementation
- SuricataAdapter interface + documentation
- ZeekAdapter interface + documentation
- SensorManager for lifecycle and health tracking
- Sensor API endpoints

### Components Created
- `backend/sensors/` — Adapter interface, implementations, manager
- `backend/api/v1/sensors.py` — Sensor management API

### API Changes
```
GET    /api/v1/sensors — List all sensors
GET    /api/v1/sensors/{id} — Get sensor details
POST   /api/v1/sensors — Register sensor
PUT    /api/v1/sensors/{id} — Update sensor config
DELETE /api/v1/sensors/{id} — Remove sensor
GET    /api/v1/sensors/{id}/health — Sensor health
```

### Database Changes
- Sensor records in sensors table

### Tests
- SensorAdapter interface contract
- SimulationSensor generates events
- SensorManager tracks health
- API CRUD operations

### Acceptance Criteria
- [ ] SensorAdapter interface defined with clear contract
- [ ] SimulationSensor implements interface and generates events
- [ ] PcapSensor reads PCAP and produces events
- [ ] SuricataAdapter interface documented with production integration guide
- [ ] SensorManager tracks registered sensors and last-seen timestamps
- [ ] Sensor API returns correct status: real, simulation, replay, unavailable, error

### Security Considerations
- Sensor registration requires admin role
- Sensor API validates sensor_id format

### Performance Considerations
- Sensor health checks are lightweight
- Batch event publishing from sensors

### Rollback Strategy
Deregister sensors, revert to direct ingestion

### Definition of Done
Sensors are registered, tracked, and produce events through the pipeline

---

## PHASE 5 — Signature Detection

### Objective
Implement the Detector interface and the first detection engine: signature-based detection with rule management.

### Dependencies
Phase 3

### Inputs
- Detector interface design from DESIGN.md
- Detection pipeline from ARCHITECTURE.md

### Outputs
- Detector base interface
- SignatureDetector implementation
- Rule loading and validation
- Rule versioning
- Rule management API
- DetectionResult objects with full provenance

### Components Created
- `backend/detection/` — Detector interface
- `backend/detection/signature.py` — Signature detector
- `backend/rules/` — Rule definitions and samples
- `backend/api/v1/rules.py` — Rule management API
- `backend/api/v1/detections.py` — Detection results API

### API Changes
```
GET    /api/v1/rules — List rules
POST   /api/v1/rules — Create rule
PUT    /api/v1/rules/{id} — Update rule
DELETE /api/v1/rules/{id} — Disable rule
POST   /api/v1/rules/reload — Reload rules
GET    /api/v1/detections — List detection results
```

### Database Changes
- Rules table populated with sample rules
- Detection results stored

### Tests
- Detector interface contract tests
- Signature detector matches known patterns
- Rule loading and validation
- Rule enable/disable
- Detection results contain required fields

### Acceptance Criteria
- [ ] Detector interface defined with `detect(event) → DetectionResult[]`
- [ ] SignatureDetector loads rules and matches events
- [ ] Every DetectionResult contains: detector, version, confidence, evidence, timestamp
- [ ] Rules can be enabled/disabled without restart
- [ ] Rule changes are versioned
- [ ] Sample rules detect: port scan, brute force, suspicious DNS
- [ ] Rule management API works with proper auth

### Security Considerations
- Rule changes logged in audit trail
- Only admin can modify rules

### Performance Considerations
- Efficient rule matching (compiled patterns)
- Rules cached in memory, reloaded on change

### Rollback Strategy
Disable new rules, revert to previous version

### Definition of Done
Signature detector processes events and produces correctly formed DetectionResults

---

## PHASE 6 — Anomaly Detection

### Objective
Implement statistical anomaly detection with baselines, deviation scoring, and explanations.

### Dependencies
Phase 5 (Detector interface)

### Inputs
- Anomaly detection design from spec
- Feature list from DESIGN.md

### Outputs
- AnomalyDetector implementing Detector interface
- Statistical baseline engine
- Feature extraction for anomaly detection
- Configurable thresholds
- Explanatory anomaly results

### Components Created
- `backend/detection/anomaly.py` — Anomaly detector
- `backend/detection/baseline.py` — Baseline tracking
- `backend/detection/features.py` — Feature extraction

### API Changes
```
GET /api/v1/anomaly/baselines — View current baselines
PUT /api/v1/anomaly/config — Update anomaly config
```

### Database Changes
- Baseline statistics stored

### Tests
- Baseline calculation from normal traffic
- Anomaly scoring for deviating traffic
- Explanation contains: baseline, current, deviation, score
- Threshold configuration works

### Acceptance Criteria
- [ ] AnomalyDetector implements Detector interface
- [ ] Tracks baselines for: connection frequency, bytes, destination diversity, port diversity
- [ ] Returns: baseline_value, current_value, deviation, anomaly_score, explanation
- [ ] Configurable sensitivity thresholds
- [ ] Detects: traffic spike, unusual destination, port scan pattern
- [ ] Baseline learning period is configurable

### Security Considerations
- Anomaly config changes logged
- Only admin can modify thresholds

### Performance Considerations
- Baseline updates are incremental (running statistics)
- Feature extraction is lightweight

### Rollback Strategy
Reset baselines, revert config

### Definition of Done
Anomaly detector produces explainable results with baseline comparison

---

## PHASE 7 — Behavioral Detection

### Objective
Implement sequence analysis and contextual attack pattern detection.

### Dependencies
Phase 5 (Detector interface), Phase 6

### Inputs
- Behavioral detection design from spec
- Attack sequence patterns

### Outputs
- BehavioralDetector implementing Detector interface
- Event sequence analysis
- Attack pattern definitions
- Multi-stage detection

### Components Created
- `backend/detection/behavioral.py` — Behavioral detector
- `backend/detection/patterns.py` — Attack pattern definitions
- `backend/detection/sequence.py` — Sequence analysis engine

### API Changes
None (uses existing detection API)

### Database Changes
- Behavioral patterns stored

### Tests
- Port scan → connection → auth attempt sequence detected
- Event grouping by source
- Attack stage classification
- Multi-stage pattern matching

### Acceptance Criteria
- [ ] BehavioralDetector implements Detector interface
- [ ] Detects multi-stage patterns: recon → access → persistence
- [ ] Groups related events by entity and time window
- [ ] Returns attack stage and confidence
- [ ] Configurable behavioral rules
- [ ] Does not assume every sequence is an attack

### Security Considerations
- Behavioral rules audited on change

### Performance Considerations
- Windowed analysis (don't hold unlimited history)
- Efficient sequence matching

### Rollback Strategy
Disable behavioral rules, revert patterns

### Definition of Done
Behavioral detector identifies multi-stage patterns with correct grouping

---

## PHASE 8 — ML Detection

### Objective
Build the ML detection subsystem with model interface, registry, inference, and explainability.

### Dependencies
Phase 5 (Detector interface)

### Inputs
- ML design from spec and DESIGN.md

### Outputs
- MLDetector implementing Detector interface
- Model interface (pluggable)
- Model registry
- Feature extraction pipeline for ML
- Pre-trained model (on synthetic data)
- Inference with explainability
- Model versioning

### Components Created
- `backend/detection/ml_detector.py` — ML detector
- `backend/ml/` — Model interface, registry, training, inference
- `backend/ml/models/` — Pre-trained model artifacts
- `backend/api/v1/models.py` — Model management API

### API Changes
```
GET    /api/v1/models — List models
GET    /api/v1/models/{id} — Model details
POST   /api/v1/models/{id}/deploy — Deploy model
POST   /api/v1/models/{id}/rollback — Rollback model
GET    /api/v1/models/{id}/metrics — Model performance
```

### Database Changes
- Model metadata stored

### Tests
- Model inference produces predictions
- Model versioning works
- Feature extraction is consistent
- Explainability metadata present
- Model registry tracks versions

### Acceptance Criteria
- [ ] MLDetector implements Detector interface
- [ ] Model interface supports pluggable models
- [ ] Model registry tracks versions with metadata
- [ ] Inference returns: prediction, confidence, feature_importances, model_version
- [ ] Pre-trained model included (clearly labeled as trained on synthetic data)
- [ ] Model deployment and rollback work
- [ ] Training and inference paths are separate

### Security Considerations
- Model deployment requires admin role
- Model changes logged in audit trail

### Performance Considerations
- Inference latency tracked
- Batch inference support
- Model loaded once, reused

### Rollback Strategy
Roll back to previous model version

### Definition of Done
ML detector produces predictions with explanations, models are versioned

---

## PHASE 9 — Threat Intelligence

### Objective
Build the threat intelligence subsystem with IOC storage, matching, and mock adapter.

### Dependencies
Phase 3

### Inputs
- TI design from spec

### Outputs
- TI provider interface
- IOC store
- Mock TI adapter (labeled as mock)
- IOC matching service
- TI management API

### Components Created
- `backend/threat_intel/` — TI interface, store, matcher, mock adapter
- `backend/api/v1/threat_intel.py` — TI management API

### API Changes
```
GET    /api/v1/threat-intel/iocs — List IOCs
POST   /api/v1/threat-intel/iocs — Add IOC
DELETE /api/v1/threat-intel/iocs/{id} — Remove IOC
GET    /api/v1/threat-intel/matches — Recent matches
POST   /api/v1/threat-intel/feeds — Add feed source
```

### Database Changes
- IOC records stored

### Tests
- IOC CRUD operations
- IOC matching against events
- Mock adapter provides sample IOCs

### Acceptance Criteria
- [ ] TI provider interface defined
- [ ] IOC store supports IP, domain, URL, hash indicators
- [ ] IOC matching identifies events with known bad indicators
- [ ] Mock adapter clearly labeled as mock data
- [ ] IOC metadata: source, confidence, first_seen, last_seen, expiry
- [ ] STIX/TAXII integration interface defined (implementation optional)

### Security Considerations
- TI management requires admin role
- IOC source tracked

### Performance Considerations
- IOC lookup is indexed for fast matching
- IOC cache for frequently queried indicators

### Rollback Strategy
Remove IOCs, disable TI matching

### Definition of Done
TI subsystem stores IOCs and matches incoming events

---

## PHASE 10 — Correlation Engine

### Objective
Build the correlation engine that groups related detections into incidents.

### Dependencies
Phase 5, 6, 7, 8, 9

### Inputs
- Correlation design from spec

### Outputs
- Correlation rules engine
- Incident/attack chain abstraction
- Time-window correlation
- MITRE ATT&CK mapping

### Components Created
- `backend/correlation/` — Correlation engine, rules, incident builder
- `backend/api/v1/incidents.py` — Incident API

### API Changes
```
GET /api/v1/incidents — List incidents
GET /api/v1/incidents/{id} — Incident details with timeline
PUT /api/v1/incidents/{id} — Update incident status
```

### Tests
- Related events are correlated
- Incidents contain ordered event timeline
- MITRE mapping works
- Configurable correlation rules

### Acceptance Criteria
- [ ] Events correlated by: same source, same destination, time window, attack pattern
- [ ] Incident objects group correlated events with timeline
- [ ] Attack stages mapped (recon, access, persistence, lateral, exfil)
- [ ] MITRE ATT&CK technique IDs attached where applicable
- [ ] Correlation rules are configurable
- [ ] Incidents have severity calculated from constituent events

### Security Considerations
- Correlation does not auto-escalate without confidence threshold

### Rollback Strategy
Dissolve incidents, reprocess events

### Definition of Done
Correlation engine groups related detections into meaningful incidents

---

## PHASE 11 — Risk Engine

### Objective
Build the contextual risk scoring engine with multi-factor calculation and explainability.

### Dependencies
Phase 10

### Inputs
- Risk engine design from spec

### Outputs
- Multi-factor risk calculator
- Risk explanation object
- Asset criticality configuration
- Risk API

### Components Created
- `backend/risk/` — Risk engine, factors, calculator
- `backend/api/v1/risk.py` — Risk API

### API Changes
```
GET /api/v1/risk/assessments — List risk assessments
GET /api/v1/risk/assessments/{id} — Risk details with factors
PUT /api/v1/risk/config — Update risk weights
```

### Tests
- Risk calculation from multiple factors
- Explanation contains factors and weights
- Asset criticality affects score
- Multi-detector agreement increases score

### Acceptance Criteria
- [ ] Risk score calculated from: confidence, asset criticality, TI match, behavioral score, ML score, attack stage, frequency, multi-detector agreement
- [ ] Returns: risk_score, risk_factors[], risk_explanation
- [ ] Risk weights are configurable
- [ ] Risk score changes tracked over time
- [ ] Explainable output (not a black box)

### Security Considerations
- Risk config changes audited

### Rollback Strategy
Revert risk weights, recalculate

### Definition of Done
Risk engine produces explainable, multi-factor risk scores

---

## PHASE 12 — Response/Automation Engine

### Objective
Build the policy-controlled response engine with dry-run, manual approval, and audit trail.

### Dependencies
Phase 11

### Inputs
- Response engine design from spec

### Outputs
- Response action interface
- Policy engine
- Dry-run mode
- Manual approval workflow
- Response audit trail
- Response API

### Components Created
- `backend/response/` — Response engine, policy, actions
- `backend/api/v1/response.py` — Response API

### API Changes
```
GET    /api/v1/response/actions — List response actions
GET    /api/v1/response/actions/{id} — Action details
POST   /api/v1/response/actions/{id}/approve — Approve pending action
POST   /api/v1/response/actions/{id}/reject — Reject pending action
GET    /api/v1/response/policies — List policies
POST   /api/v1/response/policies — Create policy
PUT    /api/v1/response/policies/{id} — Update policy
```

### Tests
- Policy evaluation selects correct response
- Dry-run logs but doesn't execute
- Manual approval queues actions
- Every action logged in audit trail
- Default mode is alert_only

### Acceptance Criteria
- [ ] Response types: alert_only, notify, increase_monitoring, temporary_block
- [ ] Policy engine matches risk levels to response types
- [ ] Dry-run mode available
- [ ] Manual approval mode available
- [ ] Every action has full audit trail
- [ ] Default is SAFE (alert_only)
- [ ] No automatic blocking from single ML prediction

### Security Considerations
- Response execution requires appropriate permissions
- All actions audited

### Rollback Strategy
Rollback executed actions, disable policies

### Definition of Done
Response engine evaluates policies and executes/queues actions safely

---

## PHASE 13 — SIEM/Logging

### Objective
Implement event storage, search, audit logging, and retention policies.

### Dependencies
Phase 2, Phase 3

### Inputs
- Storage design from ARCHITECTURE.md

### Outputs
- Event search API with filtering, sorting, pagination
- Audit log storage and retrieval
- Data retention policy engine
- Log export

### Components Created
- `backend/api/v1/events.py` — Event search API
- `backend/api/v1/audit.py` — Audit log API
- `backend/storage/retention.py` — Retention policy

### API Changes
```
GET /api/v1/events — Search events (filter, sort, paginate)
GET /api/v1/events/{id} — Event details
GET /api/v1/audit — Search audit logs
```

### Tests
- Event search with filters
- Pagination works
- Audit log retrieval
- Retention policy execution

### Acceptance Criteria
- [ ] Events searchable by: time range, IP, port, severity, event_type, sensor_id
- [ ] Pagination with configurable page size
- [ ] Sorting by timestamp, severity, risk_score
- [ ] Audit logs retrievable with time range filter
- [ ] Retention policy configurable

### Definition of Done
Events and audit logs are searchable and manageable

---

## PHASE 14 — Frontend / SOC Dashboard

### Objective
Build the SOC-style web dashboard with all 15 required pages.

### Dependencies
Phase 1-13 (API backend)

### Inputs
- Frontend design from DESIGN.md
- API endpoints from all phases

### Outputs
- Complete SOC dashboard with 15 pages
- Responsive layout
- Real-time alert feed
- Data mode indicators
- Professional visual design

### Components Created
- `frontend/` — Complete dashboard application

### Pages
1. Overview — Key metrics, recent alerts, system status
2. Live Alerts — Real-time alert feed with triage controls
3. Event Explorer — Search, filter, sort events
4. Incidents — Correlated incident view
5. Attack Timeline — Temporal visualization
6. Network Activity — Traffic and flow visualization
7. Sensors — Sensor status and health
8. Detection Engines — Engine status and analytics
9. Threat Intelligence — IOC overview and matches
10. Response Actions — Action history and approvals
11. Models — ML model status and metrics
12. Rules — Rule management
13. Audit Logs — Audit trail viewer
14. System Health — Infrastructure health
15. Settings — Configuration management

### Tests
- All pages render without errors
- Navigation works
- Data mode labels displayed correctly
- Alert lifecycle works through UI

### Acceptance Criteria
- [ ] All 15 pages implemented and functional
- [ ] Professional, modern dark-theme design
- [ ] Simulation mode clearly labeled on all pages
- [ ] Responsive layout
- [ ] Alert triage workflow functional
- [ ] Event search and filter works
- [ ] Real-time updates for alerts

### Definition of Done
Complete, professional SOC dashboard with all pages functional

---

## PHASE 15 — Authentication / RBAC / Security Hardening

### Objective
Implement JWT authentication, user management, RBAC, and security hardening.

### Dependencies
Phase 1

### Inputs
- Security architecture from ARCHITECTURE.md
- Security rules from RULES.md

### Outputs
- JWT authentication
- User management API
- RBAC middleware
- Rate limiting
- Password hashing
- Login/logout UI

### Components Created
- `backend/auth/` — Authentication service
- `backend/api/v1/auth.py` — Auth endpoints
- `backend/api/v1/users.py` — User management
- `backend/middleware/auth.py` — Auth middleware
- `backend/middleware/rbac.py` — RBAC middleware

### API Changes
```
POST /api/v1/auth/login — Authenticate
POST /api/v1/auth/refresh — Refresh token
POST /api/v1/auth/logout — Logout
GET  /api/v1/users — List users (admin)
POST /api/v1/users — Create user (admin)
```

### Tests
- Login produces valid JWT
- Invalid credentials rejected
- Expired tokens rejected
- RBAC enforced per role
- Rate limiting works
- Password hashing verified

### Acceptance Criteria
- [ ] JWT authentication on all API endpoints
- [ ] RBAC enforced per RULES.md SR-02 permission matrix
- [ ] bcrypt password hashing
- [ ] Rate limiting on auth endpoints
- [ ] Account lockout after failed attempts
- [ ] Audit logging for auth events

### Definition of Done
Authentication and authorization fully functional

---

## PHASE 16 — Scalability

### Objective
Implement horizontal scaling patterns, message bus partitioning, and worker pool management.

### Dependencies
Phase 3, Phase 5-8

### Outputs
- Worker pool management
- Configurable parallel processing
- Message bus partitioning
- Back-pressure handling

### Acceptance Criteria
- [ ] Multiple workers can process events in parallel
- [ ] Back-pressure prevents memory overflow
- [ ] Worker count configurable

### Definition of Done
System handles increased load through parallelism

---

## PHASE 17 — High Availability

### Objective
Document and implement HA patterns including health-based recovery, reconnection, and circuit breakers.

### Dependencies
Phase 16

### Outputs
- Circuit breaker implementation
- Automatic reconnection
- Graceful degradation

### Acceptance Criteria
- [ ] System continues operating when individual components fail
- [ ] Circuit breaker opens on repeated failures
- [ ] Reconnection uses exponential backoff
- [ ] Health endpoints reflect component status accurately

### Definition of Done
System degrades gracefully under failure conditions

---

## PHASE 18 — Testing

### Objective
Comprehensive test suite covering all categories.

### Dependencies
Phase 1-15

### Outputs
- Complete unit test suite
- Integration tests
- API tests
- Security tests
- Detection tests
- Performance benchmarks

### Acceptance Criteria
- [ ] Unit tests for all core engines pass
- [ ] Integration tests validate full pipeline
- [ ] API tests cover auth, permissions, validation
- [ ] Security tests verify access control
- [ ] Detection tests validate known patterns
- [ ] Performance benchmarks documented

### Definition of Done
All test suites pass, coverage meets targets

---

## PHASE 19 — Performance Optimization

### Objective
Measure performance, identify bottlenecks, and optimize critical paths.

### Dependencies
Phase 18

### Outputs
- Performance benchmark results
- Optimized critical paths
- Performance documentation

### Acceptance Criteria
- [ ] Ingestion throughput measured
- [ ] Detection latency measured
- [ ] API latency measured
- [ ] Bottlenecks identified and addressed
- [ ] Results documented (no false claims)

### Definition of Done
Performance measured and documented honestly

---

## PHASE 20 — Final Documentation and Packaging

### Objective
Complete all documentation, create README, package for distribution.

### Dependencies
Phase 1-19

### Outputs
- Complete README.md
- Updated all documentation files
- Docker Compose verified end-to-end
- Sample datasets included
- Troubleshooting guide

### Acceptance Criteria
- [ ] README covers all required sections
- [ ] `docker-compose up` produces working system
- [ ] All documentation is current
- [ ] Final quality gate checklist passes
- [ ] No exaggerated claims

### Definition of Done
Project is complete, documented, and ready for use
