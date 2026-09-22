# NIDS ARC — Engineering and Security Rules

This document defines non-negotiable engineering, security, detection, ML, response, and code quality rules for the NIDS ARC platform. These rules are mandatory for all contributors and all phases of development.

---

## 1. General Development Rules

### GR-01: No Hardcoded Secrets
- No passwords, API keys, JWT secrets, database credentials, private keys, or certificates in source code
- Use environment variables or secrets management interfaces
- Provide `.env.example` with placeholder values — never commit `.env`

### GR-02: No Fake Success States
- Never return a success response when an operation actually failed
- Never silently swallow exceptions in security-critical paths
- Log all errors with sufficient context for debugging

### GR-03: No Fake Detection Results
- Never present simulated/synthetic detection results as if they came from real sensors or real traffic
- Every detection result must carry accurate `source_type`, `detector`, and `detector_version`
- Mock data must be labeled as mock in both API responses and UI

### GR-04: No Hidden Magic Values
- All thresholds, timeouts, limits, and weights must be configurable
- Document default values and their rationale
- No unexplained numeric constants in detection logic

### GR-05: No Unnecessary Coupling
- Modules communicate through defined interfaces
- No direct database access from detection engines (use repository pattern)
- No frontend logic in backend code
- No backend business logic in database queries

### GR-06: Modular Architecture
- Each major subsystem is its own Python package/module
- Clear dependency direction: detection → schemas, not schemas → detection
- New detection engines can be added without modifying existing engines

### GR-07: Strong Typing
- Use Python type hints on all function signatures
- Use Pydantic models for API request/response schemas and data validation
- Use enums for finite value sets (severity, status, event_type)

### GR-08: Proper Error Handling
- Use custom exception classes for domain-specific errors
- Handle exceptions at appropriate levels (don't catch too broadly)
- Return structured error responses from APIs with error codes and messages
- Never expose internal stack traces to API clients in production

### GR-09: Structured Logging
- Use structured JSON logging (not print statements)
- Include: timestamp, level, module, message, request_id, correlation_id
- Use appropriate log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Never log secrets, passwords, tokens, or sensitive PII

### GR-10: Configuration Management
- All configuration through environment variables and config files
- Sensible defaults for development
- Explicit overrides for production
- Configuration validation on startup

---

## 2. Security Rules

### SR-01: Least Privilege
- Every service runs with minimum required permissions
- Database connections use role-specific accounts where possible
- API endpoints enforce permission checks
- Default user role is `viewer` (read-only)

### SR-02: RBAC
- Four roles: `admin`, `analyst`, `viewer`, `system`
- Permission matrix:
  | Resource | admin | analyst | viewer | system |
  |---|---|---|---|---|
  | Users/Roles | CRUD | Read | - | - |
  | Alerts | CRUD | Read/Update | Read | Create |
  | Events | CRUD | Read | Read | Create |
  | Rules | CRUD | Read | Read | - |
  | Response Actions | CRUD | Read/Approve | Read | Create |
  | System Config | CRUD | Read | - | Read |
  | Audit Logs | Read | Read | - | Create |
  | Sensors | CRUD | Read | Read | Update |
  | Models | CRUD | Read | Read | - |
  | TI Feeds | CRUD | Read | Read | - |

### SR-03: Authentication Architecture
- Password hashing: bcrypt with cost factor ≥ 12
- JWT access tokens: short-lived (15 minutes default)
- JWT refresh tokens: longer-lived (7 days default), stored securely
- MFA-ready: authentication flow supports optional second factor
- Account lockout: 5 failed attempts → 15 minute lockout

### SR-04: Token Security
- JWTs signed with strong secret (≥256 bits)
- Tokens include: user_id, role, permissions, issued_at, expires_at
- Refresh tokens are single-use (rotate on refresh)
- Token revocation support (via blocklist)

### SR-05: Input Validation
- Validate all API inputs using Pydantic models
- Validate query parameters (type, range, length)
- Sanitize user-provided strings used in queries
- Reject malformed events at ingestion boundary
- Validate file uploads (PCAP) for format and size

### SR-06: Output Validation
- Never include internal error details in production API responses
- Sanitize log output (no credentials, tokens, or keys)
- Validate response schemas before sending

### SR-07: API Security
- Authentication required on all endpoints except /health, /ready, /live
- Authorization checked per endpoint per role
- Rate limiting: 100 req/min for auth endpoints, 1000 req/min for data endpoints
- Request size limits enforced
- CORS configured restrictively (no wildcard in production)

### SR-08: Secure Headers
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` in production
- `Content-Security-Policy` configured appropriately

### SR-09: Secrets Management
- Application reads secrets from environment variables
- Secrets management interface defined for production (Vault, AWS Secrets Manager)
- Local development uses `.env` file (not committed)
- Secrets rotated without application restart where possible

### SR-10: Audit Logging
- Every authentication event logged (success and failure)
- Every admin action logged (user CRUD, config changes)
- Every response action logged
- Every rule change logged
- Every model deployment logged
- Audit logs are append-only
- Audit entries include: timestamp, actor_id, action, target, result, source_ip

### SR-11: Secure Defaults
- Default response mode: alert_only (no automatic blocking)
- Default user role: viewer
- Default CORS: restrictive
- Default rate limits: enabled
- Default logging: no sensitive data
- Default session timeout: 15 minutes

---

## 3. Detection Rules

### DR-01: Multi-Detector Validation
- Never trust a single detector's output for high-severity actions
- Correlation engine must consider multiple detection sources
- Automatic response requires configurable confidence threshold from multiple detectors

### DR-02: Detector Provenance
Every detection result must include:
- `detector` — name of the detection engine
- `detector_version` — version of the engine
- `rule_id` or `model_id` — specific rule or model that triggered
- `rule_version` or `model_version` — version of that rule/model
- `confidence` — 0.0 to 1.0
- `evidence` — supporting data for the detection
- `timestamp` — when the detection occurred
- `source` — what data triggered the detection

### DR-03: Evidence Preservation
- Raw event data referenced (not copied unnecessarily) by detection results
- Detection results stored separately from raw events
- Both raw and normalized events preserved
- Evidence chain must be traceable: raw event → normalized event → detection → correlation → alert

### DR-04: MITRE ATT&CK Mapping
- Detection rules should include MITRE ATT&CK technique IDs where applicable
- Behavioral detections map to ATT&CK tactics (Reconnaissance, Initial Access, etc.)
- Mapping is best-effort — do not force-map every detection

### DR-05: Severity Classification
- Use standardized severity levels: `critical`, `high`, `medium`, `low`, `info`
- Severity is set by the detector, contextual risk is calculated separately by the risk engine
- Do not conflate severity with risk

---

## 4. ML Rules

### MR-01: Model Versioning
- Every model has a unique version identifier
- Model version recorded on every inference result
- Model registry tracks: version, training_date, training_data_hash, metrics, status

### MR-02: No Silent Replacement
- Model deployment requires explicit action (API call or config change)
- Previous model version retained for rollback
- Model change logged in audit trail

### MR-03: Validation Before Deployment
- Models must pass validation suite before production deployment
- Validation metrics: accuracy, precision, recall, F1, false positive rate
- Validation results stored in model registry

### MR-04: Inference Transparency
Every ML inference result must include:
- `model_id`
- `model_version`
- `prediction` — the classification
- `confidence` — probability/score
- `feature_importances` — top contributing features
- `inference_time_ms` — latency
- `input_features` — feature vector used (or hash)

### MR-05: Drift Monitoring
- Track feature distribution statistics over time
- Alert when feature distributions shift significantly from training data
- Track prediction distribution over time
- Log drift metrics periodically

### MR-06: Training/Inference Separation
- Training code is separate from inference code
- Training pipeline produces model artifacts
- Inference service loads model artifacts
- No training occurs during live inference

### MR-07: ML is Not Sole Authority
- ML predictions inform risk scoring but do not directly trigger blocking
- ML results are one input to the correlation and risk engines
- High-confidence ML detection still requires policy-based response evaluation

---

## 5. Response Rules

### RR-01: No Automatic Destructive Actions from Single Detector
- Blocking, quarantine, and session termination require:
  - Policy approval (matching a configured policy rule)
  - Confidence threshold met
  - Preferably corroboration from multiple detectors
- A single ML model prediction with "attack" label is NOT sufficient for automatic blocking

### RR-02: Policy-Based Response
- Response actions are governed by configurable policies
- Policies define: trigger conditions, required confidence, response type, approval mode
- Policies are versioned and changes are audited

### RR-03: Response Modes
1. **Dry-run**: Log the action that would be taken, execute nothing
2. **Manual approval**: Queue the action, wait for analyst/admin approval
3. **Automatic**: Execute immediately per policy (requires explicit opt-in)

### RR-04: Response Audit Trail
Every response action must record:
- `action_id` — unique identifier
- `action_type` — what was done
- `requested_by` — system/user that initiated
- `policy_id` — which policy authorized
- `confidence` — detection confidence at trigger
- `timestamp` — when executed
- `target` — what was affected (IP, host, session)
- `status` — pending, approved, executed, failed, rolled_back
- `result` — outcome details
- `rollback_id` — reference to rollback action if applicable

### RR-05: Idempotent Response
- Re-executing the same response action should not cause duplicate effects
- Block actions should check if block already exists
- Response engine should track active actions to prevent duplication

### RR-06: Safe Defaults
- Default response mode: `alert_only`
- Automatic blocking: disabled by default
- Manual approval: enabled by default for medium+ severity
- Dry-run: always available

---

## 6. Code Quality Rules

### CQ-01: Clean Architecture
- Follow separation of concerns
- API layer → Service layer → Repository layer → Database
- Detection engines are independent of storage implementation
- Configuration separated from business logic

### CQ-02: Module Size
- No single Python file exceeds 500 lines (excluding tests and generated code)
- No single function exceeds 50 lines
- Extract complex logic into well-named helper functions
- Each module has a single, clear responsibility

### CQ-03: Naming Conventions
- Python: snake_case for functions/variables, PascalCase for classes
- API endpoints: kebab-case
- Database tables: snake_case
- Constants: UPPER_SNAKE_CASE
- Meaningful names that describe purpose, not implementation

### CQ-04: No Duplicated Logic
- Shared utilities in common modules
- Detection interface enforces consistent result format
- Event normalization happens once, at ingestion boundary
- Validation logic is centralized in schema definitions

### CQ-05: Testing Requirements
- Unit tests for every detection engine
- Unit tests for risk calculation
- Unit tests for correlation logic
- Integration tests for pipeline flows
- API tests for auth and authorization
- Security tests for access control
- Detection tests with known patterns
- Minimum test coverage target: 70% for core modules

### CQ-06: Documentation
- All public functions have docstrings
- Complex algorithms have inline comments explaining logic
- API endpoints have OpenAPI documentation
- Configuration options documented in .env.example
- Architecture decisions documented in DESIGN.md
