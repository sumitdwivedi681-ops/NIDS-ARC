# NIDS ARC — Product Requirements Document

## 1. Product Overview

### Product Name
**NIDS ARC** — Autonomous Scalable Hybrid NIDS/NDR Security Platform

### Purpose
NIDS ARC is an extensible, modular network intrusion detection and response platform that combines multiple complementary detection techniques to identify, correlate, assess, and respond to network security threats.

### Problem Statement
Modern network environments face sophisticated, multi-stage attacks that cannot be detected by any single technique. Signature-based IDS systems miss zero-day attacks; anomaly-based systems generate excessive false positives; behavioral systems lack context. Security teams need a unified platform that combines these approaches, correlates findings, assesses risk contextually, and supports policy-controlled response — all while maintaining transparency about detection confidence and data provenance.

### Target Users
| User | Role |
|---|---|
| **SOC Analyst** | Monitors alerts, investigates incidents, triages events, reviews attack chains |
| **Security Administrator** | Configures detection rules, manages sensors, sets response policies, reviews threat intel |
| **System Administrator** | Deploys/maintains infrastructure, monitors system health, manages users and access |
| **Security Researcher** | Trains/evaluates ML models, analyzes detection efficacy, studies attack patterns |
| **Developer** | Extends detection engines, builds integrations, develops custom adapters |

### Intended Environments
- **Development/Research**: Single-node Docker Compose deployment with SQLite/Redis
- **Lab/Academic**: Multi-container deployment with PostgreSQL, sensor simulators
- **Production**: Distributed deployment with Kafka, PostgreSQL cluster, real sensor integration

### Major Use Cases
1. **Real-time network threat detection** using signature, anomaly, behavioral, and ML engines
2. **Incident investigation** with correlated event timelines and attack chain visualization
3. **Automated response** with policy-controlled actions (alert, block, quarantine)
4. **Security research** using simulation mode and PCAP replay for controlled experimentation
5. **SOC operations** with a professional dashboard for monitoring, triage, and reporting
6. **Threat intelligence** integration for IOC matching and enrichment
7. **Compliance and audit** through comprehensive audit logging and reporting

---

## 2. Functional Requirements

### FR-01: Network Data Ingestion
- Accept network telemetry from multiple sensor types (Suricata, Zeek, eBPF, custom)
- Support flow-level and packet-metadata-level ingestion
- Handle high-volume streaming ingestion via message bus
- Support batch ingestion from PCAP files
- Generate synthetic traffic in simulation mode
- Tag every event with source_type (real, simulation, replay)

### FR-02: Packet/Flow Processing
- Aggregate packets into flows (5-tuple + temporal grouping)
- Extract metadata: protocols, headers, payload indicators, DNS queries, HTTP methods
- Compute flow-level features: duration, byte counts, packet counts, inter-arrival times
- Normalize heterogeneous sensor outputs into canonical event schema
- Support configurable flow timeout and aggregation windows

### FR-03: Signature Detection
- Load and manage detection rules (Suricata-compatible format where practical)
- Validate rules on load
- Enable/disable individual rules
- Version rules and track changes
- Match events against active ruleset
- Return matched rule ID, metadata, confidence, and evidence
- Support rule reload without service restart

### FR-04: Anomaly Detection
- Maintain statistical baselines per entity (IP, subnet, service)
- Track features: connection frequency, bytes sent/received, destination diversity, port diversity, connection duration, DNS query rate, failed connection rate, temporal patterns
- Compute anomaly scores with configurable sensitivity
- Return: baseline value, current value, deviation, anomaly score, human-readable explanation
- Support configurable baseline learning period and update frequency

### FR-05: Behavioral Detection
- Detect multi-stage attack patterns: reconnaissance → exploitation → persistence → lateral movement → exfiltration
- Group related events by source, destination, time window, and attack pattern
- Support configurable behavioral rules defining suspicious sequences
- Return attack stage classification and confidence
- Never assume correlation implies causation — use configurable confidence thresholds

### FR-06: ML Detection
- Extract features from normalized events for model input
- Support pluggable model interface (scikit-learn, PyTorch, custom)
- Maintain model registry with versioning
- Run inference with latency tracking
- Return prediction, confidence, feature importances/explanation
- Track model performance metrics
- Support model rollback
- Detect basic data drift (feature distribution shift)
- Keep training and inference paths separate

### FR-07: Threat Intelligence
- Store and query Indicators of Compromise (IOCs): IP, domain, URL, hash
- Support indicator metadata: source, confidence, first_seen, last_seen, expiry, tags
- Match incoming events against active IOC database
- Support STIX/TAXII-compatible integration interface
- Provide mock adapter for development (clearly labeled)
- Support multiple TI feed sources with deduplication

### FR-08: Correlation
- Correlate events by: same source, same destination, same time window, same attack pattern, related detection techniques
- Build incident/attack chain abstractions grouping correlated events
- Map to MITRE ATT&CK stages where applicable
- Support configurable correlation rules and time windows
- Calculate incident-level severity from constituent events
- Never auto-escalate to incident without configurable confidence threshold

### FR-09: Risk Scoring
- Calculate contextual risk from: detection confidence, asset criticality, threat intelligence match, behavioral score, ML score, attack stage, event frequency, historical behavior, multi-detector agreement
- Produce explainable risk object: risk_score, risk_factors[], risk_explanation
- Support configurable risk weights per factor
- Track risk score changes over time per entity

### FR-10: Alert Management
- Generate alerts from detection results exceeding configured thresholds
- Support alert states: new, acknowledged, investigating, resolved, false_positive
- Support alert assignment to analysts
- Provide alert enrichment with context (related events, TI matches, risk score)
- Support alert suppression/deduplication
- Track alert lifecycle with timestamps

### FR-11: Response Actions
- Support response types: alert_only, notify, increase_monitoring, temporary_block, firewall_rule, host_quarantine, session_terminate
- Implement policy engine with configurable rules mapping risk levels to response types
- Provide dry-run mode (log what would happen without executing)
- Provide manual approval mode (queue actions for human review)
- Provide automatic policy-based execution mode
- Log every response action with full audit trail
- Support response rollback where possible
- Default to SAFE configuration (alert_only)

### FR-12: Dashboard
- Provide SOC-style web dashboard with 15+ pages (see Design spec)
- Display real-time alert feed
- Show event explorer with search/filter/sort
- Visualize attack timelines and incident chains
- Show sensor status and health
- Display detection engine status and analytics
- Show threat intelligence overview
- Provide system health monitoring
- Clearly label simulation vs. real data in all views

### FR-13: Authentication
- Username/password authentication with bcrypt hashing
- JWT token-based session management
- Token refresh mechanism
- MFA-ready architecture (interface defined, implementation optional for v1)
- Account lockout after configurable failed attempts
- Secure password requirements enforcement

### FR-14: Authorization (RBAC)
- Role-based access control: admin, analyst, viewer, system
- Permission matrix per API endpoint and UI feature
- Role assignment and management
- Permission inheritance
- API-level authorization enforcement

### FR-15: Audit Logging
- Log all administrative actions (user CRUD, config changes, rule changes)
- Log all authentication events (login, logout, failures)
- Log all response actions
- Log all model deployments
- Include: timestamp, actor, action, target, result, IP address
- Audit logs are append-only (no modification or deletion via application)

### FR-16: Reporting
- Generate summary reports: alerts by severity, top sources, detection engine performance
- Support time-range filtering
- Export data in JSON format
- Track key metrics over time

### FR-17: Health Monitoring
- Expose health endpoints: /health, /ready, /live
- Track per-service health: API, database, message bus, detection engines, ML service
- Track sensor connectivity and last-seen timestamps
- Monitor ingestion rate, event rate, detection rate, queue lag
- Alert on health degradation

---

## 3. Non-Functional Requirements

### NFR-01: Performance
- Ingestion: ≥1,000 events/sec in simulation mode on single node
- Detection: ≤100ms p95 latency per event through fast-path detection
- API: ≤200ms p95 response time for dashboard queries
- ML inference: ≤50ms p95 per event batch
- Database: indexed queries return within 500ms for 1M event dataset
- All benchmarks must be measured, not claimed

### NFR-02: Scalability
- Horizontal scaling of ingestion workers, detection workers, API servers
- Message bus partitioning for parallel processing
- Stateless service design where possible
- Database partitioning/sharding strategy documented
- Support N sensors → message bus → N processors → N detectors

### NFR-03: Availability
- Graceful degradation when components fail (detection continues if TI is down)
- Automatic reconnection to message bus and database
- No single point of failure in production architecture
- Health check-based container orchestration support

### NFR-04: Security
- No secrets in source code or version control
- Encrypted authentication tokens
- RBAC enforcement on all API endpoints
- Rate limiting on authentication endpoints
- Input validation on all API inputs
- Security headers on all HTTP responses
- Secure default configuration
- Dependency pinning

### NFR-05: Observability
- Structured JSON logging on all services
- Request ID propagation across service boundaries
- Metrics exposure for monitoring systems
- Health check endpoints
- Configurable log levels

### NFR-06: Maintainability
- Modular architecture with clear module boundaries
- Consistent code style and naming conventions
- Comprehensive documentation
- Clean dependency management
- Configuration through environment variables and config files

### NFR-07: Reliability
- Retry logic for transient failures
- Circuit breaker pattern for external dependencies
- Dead-letter handling for unprocessable events
- Graceful shutdown with in-flight request completion
- Data durability through persistent message bus and database

### NFR-08: Extensibility
- Plugin-style detector interface for adding new detection engines
- Adapter pattern for sensor integration
- Configurable correlation rules
- Replaceable ML model interface
- Extensible threat intelligence feed system
- Modular response action system

### NFR-09: Testability
- Unit tests for all core engines
- Integration tests for pipeline flows
- API tests for all endpoints
- Security tests for auth/authz
- Detection tests with known attack patterns
- Performance tests for critical paths

---

## 4. Operating Modes

### MODE A — SIMULATION
- System generates controlled synthetic network events
- Events simulate normal traffic and various attack patterns
- Every event tagged: `source_type = "simulation"`
- Dashboard clearly shows "SIMULATION MODE" indicator
- Useful for demonstration, development, and testing

### MODE B — PCAP/REPLAY
- System reads from provided PCAP files or recorded telemetry datasets
- Events processed through full detection pipeline
- Every event tagged: `source_type = "replay"` with replay source identifier
- Dashboard shows "REPLAY MODE" with source file information
- Useful for research, training, and detection validation

### MODE C — REAL TELEMETRY
- System consumes live sensor output (Suricata EVE JSON, Zeek logs, etc.)
- Events tagged: `source_type = "real"` with sensor identifier
- Dashboard shows "LIVE" with actual sensor connectivity status
- Never fabricates "connected" status — shows actual state:
  - **Real** — receiving live data from sensor
  - **Simulation** — generating synthetic data
  - **Replay** — replaying recorded data
  - **Unavailable** — sensor configured but not responding
  - **Error** — sensor communication error with details

---

## 5. User Stories

### SOC Analyst Stories
- **US-A01**: As a SOC analyst, I want to see a real-time alert feed so I can triage incoming threats
- **US-A02**: As a SOC analyst, I want to investigate an alert and see all correlated events so I can understand the full attack context
- **US-A03**: As a SOC analyst, I want to view an attack timeline so I can understand the sequence of events
- **US-A04**: As a SOC analyst, I want to search and filter events by IP, port, protocol, severity, and time range
- **US-A05**: As a SOC analyst, I want to acknowledge, investigate, and resolve alerts with notes
- **US-A06**: As a SOC analyst, I want to see which detection engine(s) flagged an event and their confidence levels
- **US-A07**: As a SOC analyst, I want to see the risk score breakdown so I can prioritize effectively
- **US-A08**: As a SOC analyst, I want to clearly distinguish between simulation data and real data

### Security Administrator Stories
- **US-S01**: As a security admin, I want to manage detection rules (add, edit, enable, disable)
- **US-S02**: As a security admin, I want to configure response policies mapping risk levels to actions
- **US-S03**: As a security admin, I want to manage threat intelligence feeds and review IOC matches
- **US-S04**: As a security admin, I want to configure anomaly detection thresholds and baselines
- **US-S05**: As a security admin, I want to review and approve pending response actions
- **US-S06**: As a security admin, I want to manage user accounts and role assignments

### System Administrator Stories
- **US-Y01**: As a sysadmin, I want to monitor system health (API, DB, message bus, sensors)
- **US-Y02**: As a sysadmin, I want to view ingestion rates, event rates, and queue lag
- **US-Y03**: As a sysadmin, I want to deploy and configure sensors
- **US-Y04**: As a sysadmin, I want to manage data retention policies
- **US-Y05**: As a sysadmin, I want to view audit logs for compliance

### Researcher Stories
- **US-R01**: As a researcher, I want to run the system in simulation mode to study detection algorithms
- **US-R02**: As a researcher, I want to replay PCAP files through the detection pipeline
- **US-R03**: As a researcher, I want to train and evaluate ML models against labeled datasets
- **US-R04**: As a researcher, I want to compare detection engine performance metrics

### Developer Stories
- **US-D01**: As a developer, I want to add a new detection engine by implementing a standard interface
- **US-D02**: As a developer, I want to add a new sensor adapter without modifying core code
- **US-D03**: As a developer, I want clear API documentation for building integrations
- **US-D04**: As a developer, I want to run the full system locally with Docker Compose

---

## 6. Acceptance Criteria

### AC-01: System Startup
- [ ] System starts successfully with `docker-compose up`
- [ ] All health endpoints return healthy status within 60 seconds
- [ ] Dashboard is accessible and renders correctly
- [ ] Default admin account is created on first run

### AC-02: Simulation Mode
- [ ] System generates synthetic events when simulation mode is enabled
- [ ] All simulated events carry `source_type = "simulation"`
- [ ] Dashboard displays "SIMULATION MODE" indicator
- [ ] Detection pipeline processes simulated events and generates alerts
- [ ] At least 3 attack scenarios are simulated (port scan, brute force, data exfiltration)

### AC-03: Detection Pipeline
- [ ] Signature detector matches events against loaded rules
- [ ] Anomaly detector computes baseline and flags deviations with explanation
- [ ] Behavioral detector groups related events and identifies attack stages
- [ ] ML detector produces predictions with confidence and feature importance
- [ ] All detectors return normalized DetectionResult objects
- [ ] Detection results flow through correlation → risk → response pipeline

### AC-04: Security
- [ ] Authentication required for all API endpoints (except /health)
- [ ] RBAC enforced — viewer cannot modify, analyst cannot admin
- [ ] Passwords hashed with bcrypt
- [ ] JWT tokens expire and can be refreshed
- [ ] Audit log captures all admin actions
- [ ] No secrets in source code

### AC-05: Dashboard
- [ ] All 15 required pages render
- [ ] Data mode is clearly labeled on all pages
- [ ] Alert lifecycle works (new → acknowledged → resolved)
- [ ] Event explorer supports search/filter/sort
- [ ] System health page shows component status

### AC-06: Response Engine
- [ ] Default mode is alert_only
- [ ] Dry-run mode logs actions without executing
- [ ] Manual approval mode queues actions for review
- [ ] Every response action is logged in audit trail
- [ ] Response policy is configurable

### AC-07: Testing
- [ ] Unit tests pass for all core engines
- [ ] Integration tests validate detection → correlation → risk flow
- [ ] API tests validate auth, permissions, and error handling
- [ ] Security tests validate unauthorized access prevention
- [ ] Detection tests validate known attack pattern recognition
