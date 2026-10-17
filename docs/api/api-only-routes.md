# API-only routes

Every route under `/api/v1` is either called by the frontend or listed in this file. `scripts/contract_diff.py` reads it: KEEP-API routes and routes called through a runtime-built path are reported separately, so its "never called" list holds only the EXPOSE and unclassified routes. `tests/unit/test_route_inventory.py` fails when a served route is in neither place, when a row names a route the app no longer serves, or when a KEEP-API row is a route the frontend now calls.

Roles: `viewer` < `analyst` < `admin` inside an organisation; `platform superuser` is the org-less operator. "any authenticated user" means any role of the organisation (read routes); "analyst, admin" excludes viewers. Tenancy "org-scoped" means the route takes the caller's organisation (`OrganizationId`) and filters every query and lookup by it (403 `organization_required` for an org-less caller); "(in handler)" means the filter is applied in the handler body rather than through the dependency.

Classified in wave 5 (W5-B, 2026-10-15) from the uncalled-route tables in `docs/audit/2026-10-08/` and the code as it stands after waves 1-4. Routes graded FAKE, duplicates and superseded aliases were deleted, not listed. Rows are one per method and path; to add a route, add a row in the right section.

## KEEP-API (516 routes)

Real routes with no UI control, kept for integrations, scripts, endpoint agents, probes and API clients.

| Method | Route | Purpose | Roles | Tenancy |
|---|---|---|---|---|
| GET | `/api/v1/openapi.json` | OpenAPI document. | public | none |
| GET | `/api/v1/docs` | Swagger UI. | public | none |
| GET | `/api/v1/redoc` | ReDoc UI. | public | none |
| GET | `/api/v1/` | API root. | public | none |
| GET | `/api/v1/agentic/alerts/{alert_id}/explain` | Natural language explanation of one of the caller's organisation's alerts. | any authenticated user | org-scoped |
| POST | `/api/v1/agentic/hunts` | Run a structured PY-HUNT-001 threat hunt by hypothesis. | analyst, admin (checked in handler) | org-scoped |
| GET | `/api/v1/agentic/investigations/{investigation_id}` | Get investigation details | any authenticated user | org-scoped |
| GET | `/api/v1/agentic/investigations/{investigation_id}/explain` | Get natural language explanation of investigation | any authenticated user | org-scoped |
| GET | `/api/v1/agentic/investigations/{investigation_id}/feedback` | Return corrections recorded for this investigation. | any authenticated user | org-scoped |
| POST | `/api/v1/agentic/tools/{tool_name}/execute` | Execute one tool directly, through the same policy gate as the agent. | any member; role and trust tier enforced by the agent policy gate (viewers refused) | org-scoped |
| POST | `/api/v1/agents/_agent/commands/{command_id}/result` | Agent posts a command result. | enrolled endpoint agent (agent token) | the agent's organisation |
| POST | `/api/v1/agents/_agent/exchange` | Called by a newly installed agent to trade its enrollment token for a long-lived agent token. | enrolled endpoint agent (agent token) | the agent's organisation |
| POST | `/api/v1/agents/_agent/heartbeat` | Agent heartbeat. | enrolled endpoint agent (agent token) | the agent's organisation |
| POST | `/api/v1/agents/_agent/honeypot-interactions` | Accept honeypot interaction reports from a deception agent. | enrolled endpoint agent (agent token) | the agent's organisation |
| POST | `/api/v1/agents/_agent/host_events` | Accept a batch of structured host/endpoint events from an agent. | enrolled endpoint agent (agent token) | the agent's organisation |
| GET | `/api/v1/agents/_agent/poll` | Agent polls for queued commands. | enrolled endpoint agent (agent token) | the agent's organisation |
| POST | `/api/v1/agents/{agent_id}/disable` | Disable an enrolled agent — future commands are rejected until re-enabled. | admin | org-scoped |
| POST | `/api/v1/agents/{agent_id}/enable` | Re-enable a disabled agent. | admin | org-scoped |
| POST | `/api/v1/agents/{agent_id}/revoke` | Permanently revoke an agent's credentials. | admin | org-scoped |
| GET | `/api/v1/agents/{agent_id}/verify-chain` | Verify the agent's hash-chained command/result log. | any authenticated user | org-scoped |
| POST | `/api/v1/ai/analyze/incident/{incident_id}` | Incident analysis through the organisation's LLM; without one the result is DB-derived and labelled `derivation: rule_based`. | analyst, admin | org-scoped |
| POST | `/api/v1/ai/analyze/root-cause/{incident_id}` | Root cause from linked-alert evidence (LLM when configured, else labelled `rule_based`). | analyst, admin | org-scoped |
| GET | `/api/v1/ai/anomalies/stats` | Get anomaly detection statistics from the database. | any authenticated user | org-scoped |
| GET | `/api/v1/ai/anomalies/{anomaly_id}` | Get detailed anomaly information. | any authenticated user | org-scoped |
| POST | `/api/v1/ai/feedback` | Submit feedback on AI analysis results. | analyst, admin | org-scoped |
| POST | `/api/v1/ai/generate/playbook` | Playbook outline from incident history (LLM when configured, else labelled `rule_based`). | analyst, admin | org-scoped |
| DELETE | `/api/v1/ai/models/{model_id}` | Retire ML model from service. | admin | org-scoped |
| GET | `/api/v1/ai/models/{model_id}` | Get ML model details and metrics. | any authenticated user | org-scoped |
| GET | `/api/v1/ai/models/{model_id}/drift` | Check for model drift in deployed model. | any authenticated user | org-scoped |
| GET | `/api/v1/ai/predictions/dashboard` | Get threat prediction dashboard data from the database. | any authenticated user | org-scoped |
| POST | `/api/v1/ai/predictions/entity/{entity_id}` | Threat prediction for an entity from stored UEBA / anomaly signals (labelled `rule_based-v1`). | analyst, admin | org-scoped |
| POST | `/api/v1/ai/recommend/response/{incident_id}` | Response recommendations (LLM when configured, else labelled `rule_based`). | analyst, admin | org-scoped |
| GET | `/api/v1/api-keys/admin/all` | List all API keys across every user (platform superuser only). | platform superuser | platform-wide |
| GET | `/api/v1/api-keys/permissions/available` | List all available permissions (declared early to avoid /{key_id} catchall) | any authenticated user | static scope list |
| GET | `/api/v1/api-keys/{key_id}` | Get an API key by ID | any authenticated user | the caller's own keys |
| PATCH | `/api/v1/api-keys/{key_id}` | Update an API key | any authenticated user | the caller's own keys |
| POST | `/api/v1/api-security/anomalies` | Create a new anomaly detection record | analyst, admin | org-scoped |
| GET | `/api/v1/api-security/anomalies/{anomaly_id}` | Get anomaly by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/api-security/anomalies/{anomaly_id}` | Update an anomaly detection record | analyst, admin | org-scoped |
| GET | `/api/v1/api-security/compliance-checks` | List compliance checks with filtering and pagination | any authenticated user | org-scoped |
| POST | `/api/v1/api-security/compliance-checks` | Create a new compliance check | analyst, admin | org-scoped |
| GET | `/api/v1/api-security/compliance-checks/{check_id}` | Get compliance check by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/api-security/compliance-checks/{check_id}` | Update a compliance check | analyst, admin | org-scoped |
| GET | `/api/v1/api-security/dashboard` | Get API security dashboard | any authenticated user | org-scoped |
| DELETE | `/api/v1/api-security/endpoints/{endpoint_id}` | Delete an API endpoint | analyst, admin | org-scoped |
| GET | `/api/v1/api-security/endpoints/{endpoint_id}` | Get endpoint by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/api-security/endpoints/{endpoint_id}` | Update an API endpoint | analyst, admin | org-scoped |
| POST | `/api/v1/api-security/policies` | Create a new security policy | admin | org-scoped |
| DELETE | `/api/v1/api-security/policies/{policy_id}` | Delete a security policy | admin | org-scoped |
| GET | `/api/v1/api-security/policies/{policy_id}` | Get policy by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/api-security/policies/{policy_id}` | Update a security policy | admin | org-scoped |
| GET | `/api/v1/api-security/reports/compliance` | Get the compliance report for the caller's organization. | any authenticated user | org-scoped |
| POST | `/api/v1/api-security/scan/compliance/{endpoint_id}` | Trigger compliance checks for an endpoint in the caller's organization. | admin | org-scoped |
| POST | `/api/v1/api-security/scan/security/{endpoint_id}` | Queue a security assessment of an endpoint in the caller's organization. | admin | org-scoped |
| POST | `/api/v1/api-security/scan/shadows` | Trigger shadow API detection | analyst, admin | org-scoped |
| POST | `/api/v1/api-security/vulnerabilities` | Create a new vulnerability | analyst, admin | org-scoped |
| POST | `/api/v1/api-security/vulnerabilities/bulk-update` | Bulk update vulnerabilities in the caller's organization. | analyst, admin | org-scoped |
| GET | `/api/v1/api-security/vulnerabilities/{vuln_id}` | Get vulnerability by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/api-security/vulnerabilities/{vuln_id}` | Update a vulnerability | analyst, admin | org-scoped |
| GET | `/api/v1/attack/coverage` | Detection-rule coverage per technique (blind-spot map). | any authenticated user | platform-wide aggregate: counts every tenant's enabled detection rules per technique (residual) |
| GET | `/api/v1/attack/search` | Search the ATT&CK knowledge base. | any authenticated user | platform ATT&CK knowledge base |
| GET | `/api/v1/attack/status` | Loaded ATT&CK dataset version + object counts. | any authenticated user | platform ATT&CK knowledge base |
| POST | `/api/v1/attack/sync` | Download + load the pinned ATT&CK dataset (Enterprise + ICS). | platform superuser | platform ATT&CK knowledge base |
| GET | `/api/v1/attack/techniques` | List ATT&CK techniques (tactic / platform filters). | any authenticated user | platform ATT&CK knowledge base |
| GET | `/api/v1/attack/techniques/{external_id}` | Full context for one technique (tactics, mitigations, groups, software, data sources). | any authenticated user | platform ATT&CK knowledge base |
| GET | `/api/v1/auth/sso/callback` | OIDC redirect target the identity provider sends the browser to (code + state); answers 302 to `/login?sso=<one-time code>` or `/login?sso_error=<reason>`. | public (single-use state from `/auth/sso/{org_slug}/start`) | the organisation named by the stored state |
| GET | `/api/v1/auth/sso/{org_slug}/saml/metadata` | SAML SP metadata (XML EntityDescriptor: SP entity id, ACS URL with HTTP-POST, NameID format, unsigned requests, signed assertions wanted); the administrator gives this URL (shown in Settings > Identity) to the IdP. 404 `saml_not_configured` (I-E). | public | the organisation named by the slug (SAML configuration only) |
| POST | `/api/v1/auth/sso/{org_slug}/saml/acs` | SAML Assertion Consumer Service: the IdP's HTTP-POST of `SAMLResponse` + `RelayState`; signature, status, issuer, conditions, audience, recipient, InResponseTo and replay checked; 303 to `/auth/sso/saml/complete?ticket=` or `/login?sso_error=<reason>` (I-E). | public (IdP-signed response answering a pending AuthnRequest) | the organisation named by the slug; the pending request must belong to it |
| GET | `/api/v1/auth/sso/saml/complete` | Second leg of the SAML login in the starting browser: single-use ticket (60 s) plus the `pysoar_sso` cookie binding, then the shared SSO user resolution; 302 to `/login?sso=<one-time code>` or `/login?sso_error=<reason>` (I-E). | public (ticket from the ACS + browser cookie) | the organisation named by the ticket |
| GET | `/api/v1/audit-evidence/audit/export` | Export audit trail | any authenticated user | org-scoped |
| POST | `/api/v1/audit-evidence/audit/log` | Log an audit event as the calling user. | analyst, admin | org-scoped |
| GET | `/api/v1/audit-evidence/audit/suspicious-activity` | Detect suspicious activity for actor | any authenticated user | org-scoped |
| GET | `/api/v1/audit-evidence/conmon/report` | The latest stored ConMon cycle; when none was ever run, the checks are computed now and returned with `persisted: false`. | any authenticated user | org-scoped |
| POST | `/api/v1/audit-evidence/conmon/run-cycle` | Run a ConMon cycle and store it (its time becomes `lastRun`). | analyst, admin | org-scoped |
| POST | `/api/v1/audit-evidence/evidence/collect` | Run one automated evidence rule. | analyst, admin | org-scoped |
| GET | `/api/v1/audit-evidence/readiness/assessor-package` | Coverage + freshness summary for external assessors. | any authenticated user | org-scoped |
| GET | `/api/v1/audit-evidence/readiness/check` | Audit readiness of one framework, from its control statuses. | any authenticated user | org-scoped |
| GET | `/api/v1/audit-evidence/readiness/coverage` | Evidence coverage per control, from the stored evidence rows. | any authenticated user | org-scoped |
| GET | `/api/v1/audit-evidence/readiness/freshness` | Evidence freshness (collected within a year and unexpired). | any authenticated user | org-scoped |
| GET | `/api/v1/audit-evidence/rules` | List automated evidence collection rules | any authenticated user | org-scoped |
| POST | `/api/v1/audit-evidence/rules/create` | Create automated evidence collection rule (configuration: admin only). | admin | org-scoped |
| DELETE | `/api/v1/backup/backups/{filename}` | Delete a backup file. | platform superuser | platform-wide |
| POST | `/api/v1/backup/create` | Dump the whole database with `pg_dump` into `BACKUP_DIR` as `pysoar_api_YYYYMMDD-HHMMSS.sql.gz`; 503 and no file when `pg_dump` is missing (docs/operations/backup-restore.md). | platform superuser | platform-wide |
| GET | `/api/v1/backup/notifications/test` | Send a test email notification to verify SMTP configuration. | platform superuser | platform-wide |
| POST | `/api/v1/backup/restore` | Always refuses with 409 `restore_not_supported_in_app`: restore from the host with `deploy/restore-db.sh` (docs/operations/backup-restore.md). | platform superuser | platform-wide |
| GET | `/api/v1/backup/status` | List the dump files in `BACKUP_DIR` (names and sizes) and whether `pg_dump` is installed. | admin | platform backup state |
| GET | `/api/v1/collaboration/artifacts/{artifact_id}` | Artifact metadata (no file bytes are stored). | any authenticated user | org-scoped |
| PATCH | `/api/v1/collaboration/messages/{message_id}` | Edit message (only its sender may edit it) | analyst, admin | org-scoped |
| POST | `/api/v1/collaboration/messages/{message_id}/pin` | Pin message in room | analyst, admin | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}` | Get war room details | any authenticated user | org-scoped |
| PATCH | `/api/v1/collaboration/rooms/{room_id}` | Update war room | analyst, admin | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/actions/report` | Get action items report | any authenticated user | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/activity-metrics` | Get activity metrics for room | any authenticated user | org-scoped |
| POST | `/api/v1/collaboration/rooms/{room_id}/artifacts` | Register artifact metadata (name, hash, size) in a war room; no file bytes are stored. | analyst, admin | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/artifacts/index` | Artifact metadata index for a room. | any authenticated user | org-scoped |
| POST | `/api/v1/collaboration/rooms/{room_id}/commander/{user_id}` | Set incident commander for war room (the commander must be in the caller's organisation) | analyst, admin | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/messages/search` | Search messages in room | any authenticated user | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/messages/{message_id}/thread` | Get message thread | any authenticated user | org-scoped |
| POST | `/api/v1/collaboration/rooms/{room_id}/postmortem` | Generate post-mortem report | analyst, admin | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/summary` | Get war room summary with metrics | any authenticated user | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/timeline/export` | Export timeline | any authenticated user | org-scoped |
| GET | `/api/v1/collaboration/rooms/{room_id}/timeline/report` | Get timeline report | any authenticated user | org-scoped |
| GET | `/api/v1/collaboration/search` | Search one of the caller's rooms across messages and artifacts. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/cisa/directives/{directive_id}` | Get CISA directive details. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/controls/cross-map` | Get cross-framework control mapping. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/controls/{control_id}` | Get control details with evidence. | any authenticated user | org-scoped |
| POST | `/api/v1/compliance/controls/{control_id}/assess` | Run automated check for specific control. | analyst, admin | org-scoped |
| GET | `/api/v1/compliance/cui/audit` | CUI handling compliance audit. | any authenticated user | org-scoped |
| PUT | `/api/v1/compliance/cui/{marking_id}` | Update CUI marking. | analyst, admin | org-scoped |
| GET | `/api/v1/compliance/evidence` | List evidence with filtering. | any authenticated user | org-scoped |
| POST | `/api/v1/compliance/evidence` | Register compliance evidence. | analyst, admin | org-scoped |
| GET | `/api/v1/compliance/evidence/{evidence_id}` | Get evidence details. | any authenticated user | org-scoped |
| PUT | `/api/v1/compliance/evidence/{evidence_id}/review` | Review and approve evidence (admin only). | admin | org-scoped |
| GET | `/api/v1/compliance/frameworks/{framework_id}` | Get framework details with control summary. | any authenticated user | org-scoped |
| POST | `/api/v1/compliance/frameworks/{framework_id}/conmon` | Run FedRAMP Continuous Monitoring (ConMon) checks. | analyst, admin | org-scoped |
| GET | `/api/v1/compliance/frameworks/{framework_id}/gaps` | Get control implementation gaps for framework. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/frameworks/{framework_id}/report` | Get comprehensive framework compliance report. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/frameworks/{framework_id}/ssp` | Generate a System Security Plan (SSP) for a framework. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/frameworks/{framework_id}/ssp/download` | Download the SSP as a file. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/poams/overdue` | Get overdue POA&Ms. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/poams/report` | Get POA&M summary report. | any authenticated user | org-scoped |
| GET | `/api/v1/compliance/poams/{poam_id}` | Get POA&M details. | any authenticated user | org-scoped |
| PUT | `/api/v1/compliance/poams/{poam_id}` | Update POA&M. | analyst, admin | org-scoped |
| GET | `/api/v1/compliance/score-history` | Get compliance score history and trends. | any authenticated user | org-scoped |
| GET | `/api/v1/container-security/clusters/{cluster_id}` | Get cluster details. | any authenticated user | org-scoped |
| PATCH | `/api/v1/container-security/clusters/{cluster_id}` | Update the cluster's self-attested configuration. | admin | org-scoped |
| GET | `/api/v1/container-security/clusters/{cluster_id}/compliance-check` | Cluster compliance from the stored CIS check results (read only). | any authenticated user | org-scoped |
| GET | `/api/v1/container-security/clusters/{cluster_id}/findings` | Get security findings for cluster. | any authenticated user | org-scoped |
| PATCH | `/api/v1/container-security/findings/{finding_id}` | Update finding status. | analyst, admin | org-scoped |
| GET | `/api/v1/container-security/images/{image_id}` | Get image details (a pending agent scan is reconciled first). | any authenticated user | org-scoped |
| PATCH | `/api/v1/container-security/images/{image_id}` | Update image metadata. | analyst, admin | org-scoped |
| GET | `/api/v1/container-security/images/{image_id}/risk-assessment` | Get image risk assessment (only meaningful once a scanner reported). | any authenticated user | org-scoped |
| PATCH | `/api/v1/container-security/runtime-alerts/{alert_id}` | Update runtime alert status. | analyst, admin | org-scoped |
| POST | `/api/v1/container-security/runtime-alerts/{alert_id}/investigate` | Investigate runtime alert. | analyst, admin | org-scoped |
| GET | `/api/v1/container-security/scans/{scan_id}` | One scan (a pending agent scan is reconciled first). | any authenticated user | org-scoped |
| PATCH | `/api/v1/darkweb/brand-threats/{threat_id}` | Update brand threat takedown status | analyst, admin | org-scoped |
| PATCH | `/api/v1/darkweb/credentials/{credential_id}` | Update credential leak remediation status | analyst, admin | org-scoped |
| POST | `/api/v1/darkweb/findings` | Create a new dark web finding on one of the caller's monitors | analyst, admin | org-scoped |
| POST | `/api/v1/darkweb/findings/bulk-action` | Perform bulk actions on findings | analyst, admin | org-scoped |
| GET | `/api/v1/darkweb/findings/{finding_id}` | Get finding details with related data | any authenticated user | org-scoped |
| GET | `/api/v1/darkweb/monitors/{monitor_id}` | Get monitor by ID | any authenticated user | org-scoped |
| GET | `/api/v1/data-lake/dashboard/metrics` | Get unified dashboard metrics (real counts from DB, not hardcoded lies). | any authenticated user | org-scoped |
| GET | `/api/v1/data-lake/models` | List unified data models | any authenticated user | org-scoped |
| POST | `/api/v1/data-lake/models` | Register a unified data model (metadata). | admin | org-scoped |
| PATCH | `/api/v1/data-lake/models/{model_id}` | Update unified data model | admin | org-scoped |
| GET | `/api/v1/data-lake/partitions` | List data partitions with filtering | any authenticated user | org-scoped |
| POST | `/api/v1/data-lake/partitions` | Register a partition record (metadata). | admin | org-scoped |
| PATCH | `/api/v1/data-lake/partitions/{partition_id}` | Update partition (e.g., storage tier, indexes) | admin | org-scoped |
| POST | `/api/v1/data-lake/pipelines` | Register a pipeline definition (metadata: no executor runs it). | admin | org-scoped |
| PATCH | `/api/v1/data-lake/pipelines/{pipeline_id}` | Update a pipeline definition (metadata: no executor runs it). | admin | org-scoped |
| GET | `/api/v1/data-lake/queries` | List query jobs | any authenticated user | org-scoped |
| GET | `/api/v1/data-lake/queries/{query_id}` | Get query job details | any authenticated user | org-scoped |
| GET | `/api/v1/data-lake/sources/{source_id}` | Get data source by ID | any authenticated user | org-scoped |
| PATCH | `/api/v1/data-lake/sources/{source_id}` | Update data source | admin | org-scoped |
| GET | `/api/v1/deception/campaigns/{campaign_id}` | Get detailed information about a campaign. | any authenticated user | org-scoped |
| PUT | `/api/v1/deception/campaigns/{campaign_id}/status` | Update campaign status (pause/resume/complete). | analyst, admin | org-scoped |
| GET | `/api/v1/deception/canary/{token_id}` | Record a honeytoken firing. | public (honeytoken callback) | the token's organisation |
| POST | `/api/v1/deception/canary/{token_id}` | Record a honeytoken firing. | public (honeytoken callback) | the token's organisation |
| DELETE | `/api/v1/deception/decoys/{decoy_id}` | Undeploy and delete a decoy (stop_honeypot / remove_decoy goes to its agent first). | admin | org-scoped |
| GET | `/api/v1/deception/decoys/{decoy_id}` | Get detailed information about a specific decoy. | any authenticated user | org-scoped |
| POST | `/api/v1/deception/decoys/{decoy_id}/interactions` | Record an attacker interaction with a deployed decoy. | analyst, admin | org-scoped |
| GET | `/api/v1/deception/interactions/timeline` | Get interaction timeline for a decoy (404 outside the caller's organisation). | any authenticated user | org-scoped |
| GET | `/api/v1/deception/interactions/{interaction_id}` | Get details about a specific interaction. | any authenticated user | org-scoped |
| POST | `/api/v1/deception/interactions/{interaction_id}/investigate` | Trigger deep investigation of an interaction. | analyst, admin | org-scoped |
| GET | `/api/v1/deception/recommendations` | Get recommendations for improving deception coverage. | any authenticated user | org-scoped |
| DELETE | `/api/v1/deception/tokens/{token_id}` | Disable/delete a honeytoken. | admin | org-scoped |
| GET | `/api/v1/dfir/cases/{case_id}` | Get a specific forensic case | any authenticated user | org-scoped |
| POST | `/api/v1/dfir/cases/{case_id}/artifacts` | Create forensic artifact | analyst, admin | org-scoped |
| GET | `/api/v1/dfir/cases/{case_id}/metrics` | Get metrics for a specific case | any authenticated user | org-scoped |
| POST | `/api/v1/dfir/cases/{case_id}/timeline/events` | Add event to case timeline | analyst, admin | org-scoped |
| GET | `/api/v1/dfir/evidence` | Flat list of forensic evidence across all cases in the org. | any authenticated user | org-scoped (in handler) |
| GET | `/api/v1/dfir/evidence/{evidence_id}` | Get a specific evidence item | any authenticated user | org-scoped |
| GET | `/api/v1/dfir/evidence/{evidence_id}/chain-of-custody` | Get chain of custody report | any authenticated user | org-scoped |
| POST | `/api/v1/dfir/evidence/{evidence_id}/chain-of-custody` | Update chain of custody log | analyst, admin | org-scoped |
| GET | `/api/v1/dfir/legal-holds` | Flat list of legal holds for the org. | any authenticated user | org-scoped (in handler) |
| POST | `/api/v1/dlp/classifications` | Create a data classification level | admin | org-scoped |
| POST | `/api/v1/dlp/classifications/classify-document` | Classify a document by content and metadata | analyst, admin | stateless (classifies the posted content) |
| GET | `/api/v1/dlp/classifications/{classification_id}` | Get a data classification by ID | any authenticated user | org-scoped |
| PATCH | `/api/v1/dlp/classifications/{classification_id}` | Update a data classification | admin | org-scoped |
| GET | `/api/v1/dlp/classifications/{classification_id}/handling-requirements` | Get data handling requirements for a classification | any authenticated user | org-scoped |
| GET | `/api/v1/dlp/compliance-status` | Get regulatory compliance status. | any authenticated user | org-scoped |
| GET | `/api/v1/dlp/dashboard` | Get DLP dashboard summary. | any authenticated user | org-scoped |
| GET | `/api/v1/dlp/discovery/data-map` | Get data map showing where sensitive data lives | any authenticated user | org-scoped |
| GET | `/api/v1/dlp/discovery/lineage/{data_id}` | Track data lineage | any authenticated user | none (honest empty structure) |
| GET | `/api/v1/dlp/discovery/scans` | List sensitive data discovery scans | any authenticated user | org-scoped |
| GET | `/api/v1/dlp/discovery/scans/{scan_id}` | Get discovery scan results | any authenticated user | org-scoped |
| POST | `/api/v1/dlp/incidents` | Create a DLP incident | analyst, admin | org-scoped |
| GET | `/api/v1/dlp/incidents/{incident_id}` | Get a DLP incident by ID | any authenticated user | org-scoped |
| POST | `/api/v1/dlp/incidents/{incident_id}/assess-breach` | Assess breach incident and determine regulatory obligations | analyst, admin | org-scoped |
| DELETE | `/api/v1/dlp/policies/{policy_id}` | Delete a DLP policy | admin | org-scoped |
| GET | `/api/v1/dlp/policies/{policy_id}` | Get DLP policy by ID | any authenticated user | org-scoped |
| GET | `/api/v1/dlp/trends` | Get violation trends over a period. | any authenticated user | org-scoped |
| POST | `/api/v1/dlp/violations` | Create a DLP violation record | analyst, admin | org-scoped |
| POST | `/api/v1/dlp/violations/bulk-action` | Perform bulk actions on violations | analyst, admin | org-scoped |
| GET | `/api/v1/dlp/violations/{violation_id}` | Get a DLP violation by ID | any authenticated user | org-scoped |
| PATCH | `/api/v1/dlp/violations/{violation_id}` | Investigate and resolve a violation | analyst, admin | org-scoped |
| POST | `/api/v1/exposure/asset-vulns` | Create asset-vulnerability mapping (both ends must be in the caller's org). | analyst, admin | org-scoped |
| GET | `/api/v1/exposure/asset-vulns/prioritized` | Get prioritized list of asset-vulnerabilities for remediation | any authenticated user | org-scoped |
| PUT | `/api/v1/exposure/asset-vulns/{mapping_id}` | Update asset-vulnerability status (open, in_progress, remediated, accepted, false_positive, mitigated); "remediated" stamps remediated_at. | analyst, admin | org-scoped |
| POST | `/api/v1/exposure/asset-vulns/{mapping_id}/remediate` | Mark asset-vulnerability as remediated | analyst, admin | org-scoped |
| DELETE | `/api/v1/exposure/assets/{asset_id}` | Deactivate an exposure asset | analyst, admin | org-scoped |
| GET | `/api/v1/exposure/assets/{asset_id}` | Get a specific exposure asset with details and vulnerabilities | any authenticated user | org-scoped |
| PUT | `/api/v1/exposure/assets/{asset_id}` | Update an exposure asset (criticality / exposure changes rescore it). | analyst, admin | org-scoped |
| GET | `/api/v1/exposure/assets/{asset_id}/vulnerabilities` | Get vulnerabilities affecting a specific asset | any authenticated user | org-scoped |
| POST | `/api/v1/exposure/attack-surface` | Define an attack surface | analyst, admin | org-scoped |
| GET | `/api/v1/exposure/attack-surface/{surface_id}` | Get attack surface details and composition | any authenticated user | org-scoped |
| PUT | `/api/v1/exposure/attack-surface/{surface_id}` | Update attack surface | analyst, admin | org-scoped |
| POST | `/api/v1/exposure/report` | Generate exposure management report. | any authenticated user | org-scoped |
| GET | `/api/v1/exposure/risk-matrix` | Build a real criticality×severity risk matrix. | any authenticated user | org-scoped |
| GET | `/api/v1/exposure/scans` | List exposure scans with filtering | any authenticated user | org-scoped |
| GET | `/api/v1/exposure/scans/{scan_id}` | Get scan results and details | any authenticated user | org-scoped |
| POST | `/api/v1/exposure/scans/{scan_id}/cancel` | Cancel a running scan | analyst, admin | org-scoped |
| GET | `/api/v1/exposure/tickets/overdue` | Get overdue remediation tickets. | any authenticated user | org-scoped |
| GET | `/api/v1/exposure/tickets/{ticket_id}` | Get a specific remediation ticket | any authenticated user | org-scoped |
| POST | `/api/v1/exposure/tickets/{ticket_id}/verify` | Record an analyst's verification of remediation and close the ticket. | analyst, admin | org-scoped |
| POST | `/api/v1/exposure/vulnerabilities` | Create a new vulnerability record | analyst, admin | org-scoped |
| GET | `/api/v1/exposure/vulnerabilities/kev` | CISA Known Exploited Vulnerabilities list. | any authenticated user | org-scoped |
| POST | `/api/v1/exposure/vulnerabilities/search` | Advanced vulnerability search with complex filtering. | any authenticated user | org-scoped |
| DELETE | `/api/v1/exposure/vulnerabilities/{vuln_id}` | Delete a vulnerability record. | analyst, admin | org-scoped |
| GET | `/api/v1/exposure/vulnerabilities/{vuln_id}` | Get a specific vulnerability with its affected-asset counts | any authenticated user | org-scoped |
| PUT | `/api/v1/exposure/vulnerabilities/{vuln_id}` | Update vulnerability information (linked assets are rescored). | analyst, admin | org-scoped |
| POST | `/api/v1/fedramp/catalog/seed` | Seed the organisation's FedRAMP Moderate control catalogue (admin only). | admin | org-scoped |
| GET | `/api/v1/health/detailed` | Detailed health check endpoint for authenticated admins. | admin | host health |
| GET | `/api/v1/health/ready` | Kubernetes readiness probe — can it accept traffic? | public (probe) | none |
| POST | `/api/v1/hunting/findings` | Create a new hunt finding | analyst, admin | org-scoped |
| GET | `/api/v1/hunting/findings/{finding_id}` | Get a finding by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/hunting/findings/{finding_id}` | Update a finding | analyst, admin | org-scoped |
| GET | `/api/v1/hunting/hypotheses/{hypothesis_id}` | Get a hypothesis by ID | any authenticated user | org-scoped |
| GET | `/api/v1/hunting/notebooks/{notebook_id}` | Get a notebook by ID | any authenticated user | org-scoped |
| POST | `/api/v1/hunting/notebooks/{notebook_id}/publish` | Publish a notebook as a report | analyst, admin | org-scoped |
| GET | `/api/v1/hunting/sessions/{session_id}` | Get a hunt session by ID | any authenticated user | org-scoped |
| GET | `/api/v1/hunting/templates/{template_id}` | Get a template by ID | any authenticated user | platform template catalogue |
| PATCH | `/api/v1/incidents/{incident_id}/notes/{note_id}` | Update a note | analyst, admin | org-scoped |
| POST | `/api/v1/incidents/{incident_id}/timeline` | Create a custom timeline event | analyst, admin | org-scoped |
| GET | `/api/v1/integrations/connectors/{connector_name}` | One catalogue entry: `implementation_status` (implemented / log_ingest / planned), `installable`, `verification`, `test_call`, declared config / credential fields and actions; `install_count` is the caller's organisation's installs (docs/integrations/connectors.md). | any authenticated user | platform connector catalogue |
| GET | `/api/v1/integrations/dashboard/health` | Get integration health overview dashboard. | any authenticated user | org-scoped |
| GET | `/api/v1/integrations/dashboard/stats` | Get execution statistics dashboard. | any authenticated user | org-scoped |
| GET | `/api/v1/integrations/dashboard/summary` | Get complete dashboard summary with real top_connectors + high_error_rate. | any authenticated user | org-scoped |
| GET | `/api/v1/integrations/installed/{integration_id}` | Get details of installed integration | any authenticated user | org-scoped |
| GET | `/api/v1/integrations/installed/{integration_id}/executions` | Get execution history for integration | any authenticated user | org-scoped |
| GET | `/api/v1/integrations/installed/{integration_id}/webhooks` | List webhooks for integration | any authenticated user | org-scoped |
| GET | `/api/v1/integrations/webhooks` | Flat list of webhooks across all integrations. | any authenticated user | org-scoped (in handler) |
| POST | `/api/v1/iocs/bulk` | Bulk create IOCs. | analyst, admin | org-scoped |
| POST | `/api/v1/iocs/search` | Search the organisation's IOCs and platform feed intel by value. | any authenticated user | org-scoped |
| POST | `/api/v1/iocs/{ioc_id}/enrich` | Enrich one of the organisation's IOCs. | analyst, admin | org-scoped |
| GET | `/api/v1/itdr/anomalies/{anomaly_id}` | Get access anomaly details | any authenticated user | org-scoped |
| POST | `/api/v1/itdr/auth-analysis/run` | Analyse this organisation's new authentication log entries now (admin). | admin | org-scoped |
| POST | `/api/v1/itdr/credential-exposures/check` | Check an identity's credentials against known exposure sources. | analyst, admin | org-scoped |
| POST | `/api/v1/itdr/credential-exposures/remediate` | Mark credential exposures as remediated and record the action. | analyst, admin | org-scoped |
| GET | `/api/v1/itdr/credential-exposures/{exposure_id}` | Get credential exposure details | any authenticated user | org-scoped |
| GET | `/api/v1/itdr/identities/{identity_id}` | Get identity profile details | any authenticated user | org-scoped |
| PUT | `/api/v1/itdr/identities/{identity_id}` | Update identity profile | analyst, admin | org-scoped |
| GET | `/api/v1/itdr/identities/{identity_id}/risk-score` | Get identity risk score breakdown | any authenticated user | org-scoped |
| POST | `/api/v1/itdr/privileged-access/request` | Record a privilege elevation request (record-keeping: nothing is granted; PUT /privileged-access/{id} records revocation). | analyst, admin | org-scoped |
| GET | `/api/v1/itdr/threats/{threat_id}` | Get identity threat details | any authenticated user | org-scoped |
| GET | `/api/v1/metrics` | Export metrics in Prometheus text exposition format. | public (Prometheus scrape; restrict at the proxy) | process counters |
| GET | `/api/v1/metrics/agentic` | The agentic counters for THIS process as JSON (platform superuser only). | platform superuser | platform-wide |
| GET | `/api/v1/metrics/alerts/by-severity` | Get alert counts grouped by severity | any authenticated user | org-scoped |
| GET | `/api/v1/metrics/alerts/by-source` | Get alert counts grouped by source | any authenticated user | org-scoped |
| GET | `/api/v1/metrics/alerts/by-status` | Get alert counts grouped by status | any authenticated user | org-scoped |
| GET | `/api/v1/metrics/incidents/by-type` | Get incident counts grouped by type | any authenticated user | org-scoped |
| GET | `/api/v1/metrics/iocs/by-threat-level` | Get IOC counts grouped by threat level | any authenticated user | org-scoped |
| GET | `/api/v1/metrics/playbooks/executions` | Get playbook execution statistics | any authenticated user | org-scoped |
| GET | `/api/v1/organizations/{org_id}` | Get an organization by ID: the caller's own (any role), or any for a platform superuser. | any authenticated user | org-scoped (in handler) |
| DELETE | `/api/v1/organizations/{org_id}/members/{user_id}` | Remove a member from an organization (admin of that organisation or a platform superuser). | admin | org-scoped (in handler) |
| POST | `/api/v1/ot_security/alerts` | Create a new OT alert | analyst, admin | org-scoped |
| POST | `/api/v1/ot_security/alerts/bulk_action` | Perform bulk action on alerts in the caller's organization. | admin | org-scoped |
| GET | `/api/v1/ot_security/alerts/{alert_id}` | Get OT alert by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/ot_security/alerts/{alert_id}` | Update OT alert status | analyst, admin | org-scoped |
| POST | `/api/v1/ot_security/alerts/{alert_id}/investigate` | Start investigation of OT alert | analyst, admin | org-scoped |
| POST | `/api/v1/ot_security/assets` | Create a new OT asset | analyst, admin | org-scoped |
| DELETE | `/api/v1/ot_security/assets/{asset_id}` | Delete OT asset | analyst, admin | org-scoped |
| GET | `/api/v1/ot_security/assets/{asset_id}` | Get OT asset by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/ot_security/assets/{asset_id}` | Update OT asset | analyst, admin | org-scoped |
| POST | `/api/v1/ot_security/assets/{asset_id}/discover` | Actively probe OT ports on the given network ranges (live-network scan). | admin | org-scoped |
| POST | `/api/v1/ot_security/assets/{asset_id}/firmware_check` | CISA ICS advisories that name this asset's vendor and model. | any authenticated user | org-scoped |
| GET | `/api/v1/ot_security/assets/{asset_id}/risk_assessment` | Risk of one asset from its stored fields and the CISA ICS advisories naming it. | any authenticated user | org-scoped |
| GET | `/api/v1/ot_security/assets/{asset_id}/status` | Get current status of OT asset | any authenticated user | org-scoped |
| GET | `/api/v1/ot_security/compliance/report` | ICS compliance report computed from the stored assets and zones. | any authenticated user | org-scoped |
| GET | `/api/v1/ot_security/dashboard` | Get OT security dashboard | any authenticated user | org-scoped |
| POST | `/api/v1/ot_security/discover` | Bulk TCP-connect discovery of OT assets across a CIDR (admin; live-network scan). | admin | org-scoped |
| POST | `/api/v1/ot_security/incidents` | Create a new OT incident | analyst, admin | org-scoped |
| GET | `/api/v1/ot_security/incidents/{incident_id}` | Get OT incident by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/ot_security/incidents/{incident_id}` | Update OT incident | analyst, admin | org-scoped |
| POST | `/api/v1/ot_security/incidents/{incident_id}/containment_strategy` | Set containment strategy for incident | analyst, admin | org-scoped |
| GET | `/api/v1/ot_security/policies` | List OT policy rules | any authenticated user | org-scoped |
| POST | `/api/v1/ot_security/policies` | Create a new OT policy rule | admin | org-scoped |
| DELETE | `/api/v1/ot_security/policies/{policy_id}` | Delete OT policy rule | admin | org-scoped |
| GET | `/api/v1/ot_security/policies/{policy_id}` | Get OT policy rule by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/ot_security/policies/{policy_id}` | Update OT policy rule | admin | org-scoped |
| POST | `/api/v1/ot_security/policies/{policy_id}/disable` | Disable OT policy rule | admin | org-scoped |
| POST | `/api/v1/ot_security/policies/{policy_id}/enable` | Enable OT policy rule | admin | org-scoped |
| GET | `/api/v1/ot_security/policies/{policy_id}/violation_history` | Get policy violation history | any authenticated user | org-scoped |
| GET | `/api/v1/ot_security/risk_assessment` | Get OT risk assessment report | any authenticated user | org-scoped |
| POST | `/api/v1/ot_security/zones` | Create a new OT security zone | analyst, admin | org-scoped |
| DELETE | `/api/v1/ot_security/zones/{zone_id}` | Delete OT zone | analyst, admin | org-scoped |
| GET | `/api/v1/ot_security/zones/{zone_id}` | Get OT zone by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/ot_security/zones/{zone_id}` | Update OT zone | analyst, admin | org-scoped |
| GET | `/api/v1/ot_security/zones/{zone_id}/communication_matrix` | Get zone-to-zone communication policy matrix | any authenticated user | org-scoped |
| POST | `/api/v1/ot_security/zones/{zone_id}/compliance_check` | Check zone compliance with Purdue model | any authenticated user | org-scoped |
| GET | `/api/v1/phishing_sim/awareness-scores/department/{department}` | Get aggregated scores for a department. | any authenticated user | org-scoped |
| GET | `/api/v1/phishing_sim/c/{token}` | Record a `link_clicked` event, then redirect the recipient. | public (recipient tracking token) | the token's campaign organisation |
| GET | `/api/v1/phishing_sim/campaigns/{campaign_id}` | Get campaign details with current metrics. | any authenticated user | org-scoped |
| PATCH | `/api/v1/phishing_sim/campaigns/{campaign_id}` | Update campaign configuration (only in draft status). | analyst, admin | org-scoped |
| POST | `/api/v1/phishing_sim/campaigns/{campaign_id}/clone` | Clone an existing campaign. | analyst, admin | org-scoped |
| GET | `/api/v1/phishing_sim/campaigns/{campaign_id}/events` | List events for a campaign. | any authenticated user | org-scoped |
| POST | `/api/v1/phishing_sim/campaigns/{campaign_id}/events` | Record a campaign event (email open, link click, credential submission, etc.). | analyst, admin | org-scoped |
| GET | `/api/v1/phishing_sim/campaigns/{campaign_id}/events/timeline` | Get event timeline for campaign or specific target. | any authenticated user | org-scoped |
| POST | `/api/v1/phishing_sim/r/{token}` | Record a `reported_as_phishing` event (recipient used the report button). | public (recipient tracking token) | the token's campaign organisation |
| GET | `/api/v1/phishing_sim/reports/risk` | Generate comprehensive risk assessment report. | any authenticated user | org-scoped |
| GET | `/api/v1/phishing_sim/t/{token}.gif` | 1x1 tracking pixel. | public (recipient tracking token) | the token's campaign organisation |
| DELETE | `/api/v1/phishing_sim/target-groups/{group_id}` | Delete a target group. | analyst, admin | org-scoped |
| GET | `/api/v1/phishing_sim/target-groups/{group_id}` | Get a specific target group. | any authenticated user | org-scoped |
| GET | `/api/v1/phishing_sim/templates/{template_id}` | Get a specific phishing template. | any authenticated user | org-scoped |
| PATCH | `/api/v1/phishing_sim/templates/{template_id}` | Update a phishing template. | analyst, admin | org-scoped |
| POST | `/api/v1/phishing_sim/templates/{template_id}/render` | Render template with personalized target data. | any authenticated user | org-scoped |
| POST | `/api/v1/phishing_sim/templates/{template_id}/validate` | Validate template for rendering issues and broken links. | any authenticated user | org-scoped |
| POST | `/api/v1/phishing_sim/training/{user_email}/assign` | Assign training modules to a user. | analyst, admin | org-scoped |
| POST | `/api/v1/phishing_sim/training/{user_email}/certificate` | Generate training certificate. | admin | org-scoped |
| POST | `/api/v1/phishing_sim/training/{user_email}/track-completion` | Track training module completion. | analyst, admin | org-scoped |
| GET | `/api/v1/playbook-builder/dashboard` | Playbook builder dashboard with real execution aggregates. | any authenticated user | org-scoped |
| POST | `/api/v1/playbook-builder/import` | Import a playbook from JSON | analyst, admin | org-scoped |
| PUT | `/api/v1/playbook-builder/{playbook_id}/edges/{edge_id}` | Update an edge | analyst, admin | org-scoped |
| GET | `/api/v1/playbook-builder/{playbook_id}/executions` | List playbook executions | any authenticated user | org-scoped |
| POST | `/api/v1/playbook-builder/{playbook_id}/export` | Export playbook as JSON | any authenticated user | org-scoped |
| GET | `/api/v1/playbooks/executions/recent` | The caller's most recent playbook executions across all their playbooks. | any authenticated user | org-scoped |
| POST | `/api/v1/privacy/consent/records/{record_id}/withdraw` | Withdraw previously given consent (GDPR Article 7(3)). | analyst, admin | org-scoped |
| GET | `/api/v1/privacy/dsr/requests/{request_id}` | Get Data Subject Request by ID. | any authenticated user | org-scoped |
| POST | `/api/v1/privacy/dsr/requests/{request_id}/deadline-alerts` | Deadline alerts for the organisation's open DSRs (kept for compatibility; `GET /privacy/dsr/deadline-alerts` is the read route). | analyst, admin | org-scoped |
| GET | `/api/v1/privacy/incidents/reports/{incident_id}` | Get privacy incident by ID. | any authenticated user | org-scoped |
| POST | `/api/v1/privacy/incidents/reports/{incident_id}/mark-notified` | Mark notifications as sent. | analyst, admin | org-scoped |
| POST | `/api/v1/privacy/monitoring/trigger-consent-expiry-check` | Manually trigger consent expiry check task. | analyst, admin | org-scoped |
| POST | `/api/v1/privacy/monitoring/trigger-dsr-deadline-check` | Manually trigger DSR deadline monitoring task. | analyst, admin | org-scoped |
| POST | `/api/v1/privacy/monitoring/trigger-pia-review-reminder` | Manually trigger PIA review reminder task. | analyst, admin | org-scoped |
| POST | `/api/v1/privacy/monitoring/trigger-retention-check` | Manually trigger retention enforcement task. | analyst, admin | org-scoped |
| GET | `/api/v1/privacy/pia/assessments/{assessment_id}` | Get Privacy Impact Assessment by ID. | any authenticated user | org-scoped |
| POST | `/api/v1/privacy/pia/assessments/{assessment_id}/assess-risks` | Assess risks to data subjects. | analyst, admin | org-scoped |
| POST | `/api/v1/privacy/pia/assessments/{assessment_id}/submit-dpo-review` | Submit PIA for Data Protection Officer review. | analyst, admin | org-scoped |
| GET | `/api/v1/privacy/ropa/generate-ropa` | Generate complete ROPA document per GDPR Article 30. | any authenticated user | org-scoped |
| POST | `/api/v1/privacy/ropa/retention-violations` | Check for data retention compliance violations. | analyst, admin | org-scoped |
| GET | `/api/v1/remediation/effectiveness` | Remediation effectiveness computed from this organisation's execution rows. | any authenticated user | org-scoped |
| POST | `/api/v1/remediation/execute` | Run one registry action against a target without a policy. | admin | org-scoped |
| POST | `/api/v1/remediation/executions/{execution_id}/cancel` | Cancel a running execution. | analyst, admin | org-scoped |
| GET | `/api/v1/remediation/executions/{execution_id}/progress` | Get real-time execution progress. | any authenticated user | org-scoped |
| PUT | `/api/v1/remediation/integrations/{integration_id}` | Update an installed integration's name, config or credentials. | admin | org-scoped |
| GET | `/api/v1/remediation/integrations/{integration_id}/health` | The stored verdict of the last connectivity probe. | any authenticated user | org-scoped |
| GET | `/api/v1/remediation/policies/builtin` | The starter policies `register_builtin_policies` installs (disabled, approval required). | any authenticated user | static starter catalogue |
| DELETE | `/api/v1/remediation/policies/{policy_id}` | Disable a policy (soft delete). | admin | org-scoped |
| GET | `/api/v1/remediation/policies/{policy_id}` | Get a specific policy with execution history. | any authenticated user | org-scoped |
| POST | `/api/v1/remediation/policies/{policy_id}/test` | Test a policy against sample data. | analyst, admin | org-scoped |
| GET | `/api/v1/remediation/timeline` | Get recent remediation timeline. | any authenticated user | org-scoped |
| GET | `/api/v1/risk-quantification/bias` | List Business Impact Assessments | any authenticated user | org-scoped |
| POST | `/api/v1/risk-quantification/bias` | Create a new Business Impact Assessment | analyst, admin | org-scoped |
| DELETE | `/api/v1/risk-quantification/bias/{bia_id}` | Delete a BIA | analyst, admin | org-scoped |
| GET | `/api/v1/risk-quantification/bias/{bia_id}` | Get a BIA by ID | any authenticated user | org-scoped |
| PATCH | `/api/v1/risk-quantification/bias/{bia_id}` | Update a BIA | analyst, admin | org-scoped |
| POST | `/api/v1/risk-quantification/controls` | Create a new risk control | analyst, admin | org-scoped |
| DELETE | `/api/v1/risk-quantification/controls/{control_id}` | Delete a risk control | analyst, admin | org-scoped |
| GET | `/api/v1/risk-quantification/controls/{control_id}` | Get a risk control by ID | any authenticated user | org-scoped |
| PATCH | `/api/v1/risk-quantification/controls/{control_id}` | Update a risk control | analyst, admin | org-scoped |
| POST | `/api/v1/risk-quantification/controls/{control_id}/audit` | Calculate the control's ROI from its stored register ALE, effectiveness and cost. | analyst, admin | org-scoped |
| GET | `/api/v1/risk-quantification/fair-analyses/{analysis_id}` | Get a FAIR analysis by ID | any authenticated user | org-scoped |
| GET | `/api/v1/risk-quantification/fair-analyses/{analysis_id}/loss-exceedance-curve` | Get loss exceedance curve for FAIR analysis | any authenticated user | org-scoped |
| GET | `/api/v1/risk-quantification/risk-registers` | List risk registers | any authenticated user | org-scoped |
| POST | `/api/v1/risk-quantification/risk-registers` | Create a new risk register entry | analyst, admin | org-scoped |
| DELETE | `/api/v1/risk-quantification/risk-registers/{register_id}` | Delete a risk register entry | analyst, admin | org-scoped |
| GET | `/api/v1/risk-quantification/risk-registers/{register_id}` | Get a risk register entry by ID | any authenticated user | org-scoped |
| PATCH | `/api/v1/risk-quantification/risk-registers/{register_id}` | Update a risk register entry | analyst, admin | org-scoped |
| DELETE | `/api/v1/risk-quantification/scenarios/{scenario_id}` | Delete a risk scenario | analyst, admin | org-scoped |
| GET | `/api/v1/risk-quantification/scenarios/{scenario_id}` | Get a risk scenario by ID | any authenticated user | org-scoped |
| PATCH | `/api/v1/risk-quantification/scenarios/{scenario_id}` | Update a risk scenario | analyst, admin | org-scoped |
| PATCH | `/api/v1/settings` | Update application settings (admin only) — persists to DB. | admin | org-scoped |
| GET | `/api/v1/settings/ai/tenants` | One row per organization with an `ai` section (superuser, cross-org). | platform superuser | platform-wide |
| POST | `/api/v1/siem/cloud/poll-all` | Manually poll the organisation's installed cloud-log integrations. | admin | org-scoped |
| GET | `/api/v1/siem/correlations/{correlation_id}` | Get a correlation event by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/siem/correlations/{correlation_id}/status` | Update correlation event status (triage; analysts and admins) | analyst, admin | org-scoped |
| GET | `/api/v1/siem/ingest/status` | Return ingest queue status (host-wide queue; platform superusers only). | platform superuser | platform-wide |
| POST | `/api/v1/siem/logs/backfill` | Copy existing Alert + AuditLog rows into `log_entries`. | platform superuser | platform-wide |
| POST | `/api/v1/siem/logs/batch` | Batch ingest multiple log entries through the full SIEM pipeline. | analyst, admin | org-scoped (superuser passes organization_id) |
| POST | `/api/v1/siem/logs/ingest` | Ingest a single log entry through the full SIEM pipeline. | analyst, admin | org-scoped |
| POST | `/api/v1/siem/logs/ingest/bulk` | Authenticated bulk log ingestion for external forwarders. | API key with the ingest scope | the key owner's organisation |
| GET | `/api/v1/siem/rules/{rule_id}` | Get a detection rule by ID | any authenticated user | org-scoped |
| DELETE | `/api/v1/siem/saved-searches/{search_id}` | Delete a saved search | analyst, admin | org-scoped |
| DELETE | `/api/v1/siem/sources/{source_id}` | Delete a data source | admin | org-scoped |
| GET | `/api/v1/simulation/adversaries/{adversary_id}` | Get adversary profile details. | any authenticated user | org-scoped |
| GET | `/api/v1/simulation/posture/gaps` | Get gap analysis for simulation. | any authenticated user | org-scoped |
| GET | `/api/v1/simulation/simulations/{simulation_id}` | Get detailed simulation information with test results. | any authenticated user | org-scoped |
| POST | `/api/v1/simulation/simulations/{simulation_id}/cancel` | Cancel a simulation. | analyst, admin | org-scoped |
| POST | `/api/v1/simulation/simulations/{simulation_id}/pause` | Pause a running simulation. | analyst, admin | org-scoped |
| GET | `/api/v1/simulation/simulations/{simulation_id}/progress` | Get live progress of a running simulation. | any authenticated user | org-scoped |
| GET | `/api/v1/simulation/simulations/{simulation_id}/report` | Get detailed simulation report. | any authenticated user | org-scoped |
| POST | `/api/v1/simulation/simulations/{simulation_id}/start` | Start executing a simulation. | admin | org-scoped |
| GET | `/api/v1/simulation/techniques/{mitre_id}` | Get technique details. | any authenticated user | org-scoped |
| POST | `/api/v1/stig/remediate/script` | Generate remediation script for findings | analyst, admin | org-scoped |
| POST | `/api/v1/stig/scans/compare` | Compare two STIG scan baselines (read-only computation: viewers allowed). | any authenticated user | org-scoped |
| POST | `/api/v1/stig/scans/fleet` | Run a STIG benchmark on several hosts (admin only; each host as in /scans/launch). | admin | org-scoped |
| POST | `/api/v1/stig/scap/arf-report` | Generate Assessment Results Format (ARF) report (read-only: viewers allowed). | any authenticated user | org-scoped |
| POST | `/api/v1/stig/scap/import` | Import SCAP content (XCCDF, OVAL) from a file already under the STIG content directory (see POST /stig/scap/upload). | analyst, admin | org-scoped |
| GET | `/api/v1/stig/scap/profiles` | List SCAP profiles | any authenticated user | org-scoped |
| POST | `/api/v1/stig/scap/scan` | SCAP profile evaluation (admin only: names a live target). | admin | org-scoped |
| POST | `/api/v1/stig/scap/validate-oval` | Validate OVAL (Open Vulnerability and Assessment Language) definitions | analyst, admin | stateless (validates the posted content) |
| GET | `/api/v1/supplychain/compliance/license-audit` | Audit license compliance across the organisation's stored components. | any authenticated user | org-scoped |
| POST | `/api/v1/supplychain/compliance/validate-sbom` | NTIA minimum-element check of an SBOM's stored components. | any authenticated user | org-scoped |
| GET | `/api/v1/supplychain/components/{component_id}` | Get component details | any authenticated user | org-scoped |
| PATCH | `/api/v1/supplychain/components/{component_id}` | Update component (a name / version change clears the lookup state). | analyst, admin | org-scoped |
| GET | `/api/v1/supplychain/components/{component_id}/dependency-tree` | Get component dependency tree. | any authenticated user | org-scoped |
| GET | `/api/v1/supplychain/dashboard/overview` | Supply chain overview from stored rows (scanned / assessed only for averages). | any authenticated user | org-scoped |
| GET | `/api/v1/supplychain/dashboard/top-risky-components` | Top looked-up components by risk score (highest CVSS of their advisories). | any authenticated user | org-scoped |
| GET | `/api/v1/supplychain/dashboard/vendor-scores` | Vendor scores: security_score from stored answers, risk_score = 100 - it. | any authenticated user | org-scoped |
| POST | `/api/v1/supplychain/risks` | Create supply chain risk record (component must belong to the org). | analyst, admin | org-scoped |
| GET | `/api/v1/supplychain/risks/{risk_id}` | Get risk details | any authenticated user | org-scoped |
| PATCH | `/api/v1/supplychain/risks/{risk_id}` | Update risk status and remediation | analyst, admin | org-scoped |
| POST | `/api/v1/supplychain/sboms/import` | Import an SBOM from inline JSON content (SPDX or CycloneDX). | analyst, admin | org-scoped |
| GET | `/api/v1/supplychain/sboms/{sbom_id}` | Get SBOM details | any authenticated user | org-scoped |
| GET | `/api/v1/teams/{team_id}` | Get a team by ID | any authenticated user | org-scoped (team must be in the caller's organisation; superuser any) |
| GET | `/api/v1/teams/{team_id}/members` | List members of a team | any authenticated user | org-scoped (team must be in the caller's organisation; superuser any) |
| DELETE | `/api/v1/teams/{team_id}/members/{user_id}` | Remove a member from a team | analyst, admin | org-scoped (team must be in the caller's organisation; superuser any) |
| GET | `/api/v1/threat-intel/actors` | List threat actors with filtering and pagination. | any authenticated user | org-scoped |
| POST | `/api/v1/threat-intel/actors` | Create a new threat actor in the caller's organisation. | analyst, admin | org-scoped |
| DELETE | `/api/v1/threat-intel/actors/{actor_id}` | Delete a threat actor. | analyst, admin | org-scoped |
| GET | `/api/v1/threat-intel/actors/{actor_id}` | Get threat actor details with associated campaigns and indicators. | any authenticated user | org-scoped |
| PUT | `/api/v1/threat-intel/actors/{actor_id}` | Update a threat actor. | analyst, admin | org-scoped |
| GET | `/api/v1/threat-intel/campaigns` | List threat campaigns with filtering and pagination. | any authenticated user | org-scoped |
| POST | `/api/v1/threat-intel/campaigns` | Create a new threat campaign in the caller's organisation. | analyst, admin | org-scoped |
| DELETE | `/api/v1/threat-intel/campaigns/{campaign_id}` | Delete a threat campaign. | analyst, admin | org-scoped |
| GET | `/api/v1/threat-intel/campaigns/{campaign_id}` | Get threat campaign details. | any authenticated user | org-scoped |
| PUT | `/api/v1/threat-intel/campaigns/{campaign_id}` | Update a threat campaign. | analyst, admin | org-scoped |
| POST | `/api/v1/threat-intel/feeds` | Create a new threat feed owned by the caller's organisation (admin only). | admin | org-scoped |
| POST | `/api/v1/threat-intel/feeds/poll-all` | Poll every enabled feed of every tenant plus the platform feeds now (platform superuser only). | platform superuser | platform-wide |
| POST | `/api/v1/threat-intel/feeds/register-builtins` | (Re-)register the platform built-in feeds (platform superuser only). | platform superuser | platform-wide |
| DELETE | `/api/v1/threat-intel/feeds/{feed_id}` | Delete one of the caller's threat feeds (admin only; platform feeds 403). | admin | org-scoped |
| GET | `/api/v1/threat-intel/feeds/{feed_id}` | Get threat feed details (own or platform feed). | any authenticated user | org-scoped |
| PUT | `/api/v1/threat-intel/feeds/{feed_id}` | Update one of the caller's threat feeds (admin only; platform feeds 403). | admin | org-scoped |
| GET | `/api/v1/threat-intel/feeds/{feed_id}/stats` | Get statistics for a threat feed (own or platform feed). | any authenticated user | org-scoped |
| POST | `/api/v1/threat-intel/indicators` | Create a new threat indicator. | analyst, admin | org-scoped |
| POST | `/api/v1/threat-intel/indicators/bulk` | Bulk import threat indicators into the caller's organisation. | analyst, admin | org-scoped |
| DELETE | `/api/v1/threat-intel/indicators/{indicator_id}` | Delete a threat indicator. | analyst, admin | org-scoped |
| PUT | `/api/v1/threat-intel/indicators/{indicator_id}` | Update a threat indicator. | analyst, admin | org-scoped |
| GET | `/api/v1/threat-intel/indicators/{indicator_id}/sightings` | Get sightings for a specific threat indicator. | any authenticated user | org-scoped |
| GET | `/api/v1/threat-intel/indicators/{indicator_id}/timeline` | Get the timeline/history for a threat indicator. | any authenticated user | org-scoped |
| POST | `/api/v1/threat-intel/indicators/{indicator_id}/whitelist` | Whitelist a threat indicator. | analyst, admin | org-scoped |
| GET | `/api/v1/threat-intel/reports` | List intel reports with filtering and pagination. | any authenticated user | org-scoped |
| POST | `/api/v1/threat-intel/reports` | Create a new intel report. | analyst, admin | org-scoped |
| DELETE | `/api/v1/threat-intel/reports/{report_id}` | Delete an intel report. | analyst, admin | org-scoped |
| GET | `/api/v1/threat-intel/reports/{report_id}` | Get a specific intel report. | any authenticated user | org-scoped |
| PUT | `/api/v1/threat-intel/reports/{report_id}` | Update an intel report. | analyst, admin | org-scoped |
| POST | `/api/v1/threat-intel/reports/{report_id}/publish` | Publish an intel report. | analyst, admin | org-scoped |
| POST | `/api/v1/threat-intel/sightings` | Record a sighting (stamped with the caller's organisation) of one of the caller's indicators or of a platform indicator. | analyst, admin | org-scoped |
| GET | `/api/v1/threat-modeling/{model_id}` | Get threat model by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/threat-modeling/{model_id}` | Update threat model | analyst, admin | org-scoped |
| GET | `/api/v1/threat-modeling/{model_id}/mitigations/recommendations/{threat_id}` | Get recommended mitigations for threat | any authenticated user | org-scoped |
| DELETE | `/api/v1/threat-modeling/{model_id}/threats/{threat_id}` | Delete threat | analyst, admin | org-scoped |
| GET | `/api/v1/threat-modeling/{model_id}/threats/{threat_id}` | Get threat by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/threat-modeling/{model_id}/threats/{threat_id}` | Update threat | analyst, admin | org-scoped |
| PUT | `/api/v1/threat-modeling/{model_id}/threats/{threat_id}/mitigations/{mitigation_id}` | Update mitigation | analyst, admin | org-scoped |
| POST | `/api/v1/threat-modeling/{model_id}/validate` | Validate threat model completeness | analyst, admin | org-scoped |
| DELETE | `/api/v1/tickethub/automation/rules/{rule_id}` | Delete an automation rule (tenant-scoped). | admin | org-scoped |
| DELETE | `/api/v1/tickethub/comments/{comment_id}` | Delete a comment (tenant-scoped). | analyst, admin | org-scoped |
| GET | `/api/v1/tickethub/tickets/{source_type}/{source_id}` | Get detailed view of a specific ticket with comments and activity. | any authenticated user | org-scoped |
| GET | `/api/v1/tickethub/tickets/{source_type}/{source_id}/links` | Get linked tickets (tenant-scoped). | any authenticated user | org-scoped |
| POST | `/api/v1/tickethub/tickets/{source_type}/{source_id}/links` | Link two of the caller's tickets together (both must exist in the tenant). | analyst, admin | org-scoped |
| GET | `/api/v1/ueba/alerts/{alert_id}` | Get detailed alert information. | any authenticated user | org-scoped |
| POST | `/api/v1/ueba/baselines/rebuild` | Rebuild behavior baselines for entities synchronously. | admin | org-scoped |
| GET | `/api/v1/ueba/baselines/{entity_id}` | Get behavior baselines for an entity. | any authenticated user | org-scoped |
| GET | `/api/v1/ueba/entities/{entity_id}` | Get detailed entity profile with risk information. | any authenticated user | org-scoped |
| GET | `/api/v1/ueba/entities/{entity_id}/peers` | Compare entity behavior to peer group members. | any authenticated user | org-scoped |
| GET | `/api/v1/ueba/entities/{entity_id}/risk` | Get detailed risk information for an entity. | any authenticated user | org-scoped |
| PUT | `/api/v1/ueba/entities/{entity_id}/watch` | Update watchlist status for an entity. | analyst, admin | org-scoped |
| GET | `/api/v1/ueba/events` | Search behavior events with filtering. | any authenticated user | org-scoped |
| POST | `/api/v1/ueba/events` | Ingest and analyze a single behavior event. | analyst, admin | org-scoped |
| POST | `/api/v1/ueba/events/batch` | Ingest and analyze multiple behavior events. | analyst, admin | org-scoped |
| POST | `/api/v1/ueba/peer-groups` | Create a custom peer group. | admin | org-scoped |
| GET | `/api/v1/ueba/peer-groups/{group_id}` | Get peer group details with member information. | any authenticated user | org-scoped |
| GET | `/api/v1/ueba/risk-heatmap` | Get risk heatmap data for visualization. | any authenticated user | org-scoped |
| GET | `/api/v1/vulnmgmt/instances/{instance_id}` | Get vulnerability instance by ID | any authenticated user | org-scoped |
| PUT | `/api/v1/vulnmgmt/instances/{instance_id}` | Update a vulnerability instance. | analyst, admin | org-scoped |
| POST | `/api/v1/vulnmgmt/patch-operations/{patch_id}/rollback` | Record a rollback of a patch deployment. | analyst, admin | org-scoped |
| POST | `/api/v1/vulnmgmt/patch-operations/{patch_id}/schedule` | Record the planned deployment date of a patch operation. | analyst, admin | org-scoped |
| POST | `/api/v1/vulnmgmt/patch-operations/{patch_id}/verify` | Record the caller's verification result for a patch deployment. | analyst, admin | org-scoped |
| GET | `/api/v1/vulnmgmt/report/executive` | Executive summary from stored instances (MTTR None until something is remediated). | any authenticated user | org-scoped |
| GET | `/api/v1/vulnmgmt/report/kev-compliance` | BOD 22-01 report over instances of KEV-listed CVEs only (`compliance_percentage` None when none is tracked). | any authenticated user | org-scoped |
| GET | `/api/v1/vulnmgmt/vulnerabilities/{vuln_id}` | Get vulnerability by ID | any authenticated user | org-scoped |
| POST | `/api/v1/zerotrust/continuous-eval/{session_id}` | Re-evaluate active session for risk changes | analyst, admin | org-scoped |
| GET | `/api/v1/zerotrust/devices/non-compliant` | Get devices below compliance threshold | any authenticated user | org-scoped |
| POST | `/api/v1/zerotrust/devices/{device_id}/assess` | Assess device compliance and trust score | analyst, admin | org-scoped |
| POST | `/api/v1/zerotrust/evaluate` | Evaluate access request and return decision (Policy Decision Point) | analyst, admin | org-scoped |
| GET | `/api/v1/zerotrust/maturity` | Get Zero Trust maturity score and assessment | any authenticated user | org-scoped |
| GET | `/api/v1/zerotrust/maturity/pillars` | Get per-pillar maturity breakdown | any authenticated user | org-scoped |
| DELETE | `/api/v1/zerotrust/policies/{policy_id}` | Delete Zero Trust policy (admin: access-policy configuration) | admin | org-scoped |
| GET | `/api/v1/zerotrust/policies/{policy_id}` | Get policy details | any authenticated user | org-scoped |
| PUT | `/api/v1/zerotrust/policies/{policy_id}` | Update Zero Trust policy (admin: access-policy configuration) | admin | org-scoped |
| POST | `/api/v1/zerotrust/policies/{policy_id}/test` | Test policy against sample access request | analyst, admin | org-scoped |
| GET | `/api/v1/zerotrust/recommendations` | Get improvement recommendations | any authenticated user | org-scoped |
| DELETE | `/api/v1/zerotrust/segments/{segment_id}` | Delete micro-segment (admin: network-policy configuration) | admin | org-scoped |
| GET | `/api/v1/zerotrust/segments/{segment_id}` | Get segment details | any authenticated user | org-scoped |
| PUT | `/api/v1/zerotrust/segments/{segment_id}` | Update micro-segment (admin: network-policy configuration) | admin | org-scoped |
| POST | `/api/v1/zerotrust/segments/{segment_id}/evaluate-traffic` | Evaluate if traffic is allowed within segment | any authenticated user | org-scoped |
| GET | `/api/v1/zerotrust/segments/{segment_id}/violations` | Get policy violations for segment | any authenticated user | org-scoped |
| GET | `/api/v1/zerotrust/topology` | Get network topology visualization | any authenticated user | org-scoped |
| GET | `/api/v1/scim/v2/ServiceProviderConfig` | SCIM 2.0 discovery: patch and filter supported; bulk, sort, etag, changePassword not (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/ResourceTypes` | SCIM 2.0 discovery: User and Group resource types (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/ResourceTypes/{name}` | SCIM 2.0 discovery: one resource type (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/Schemas` | SCIM 2.0 discovery: the User, Group and enterprise-extension attributes PySOAR stores (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/Schemas/{schema_id}` | SCIM 2.0 discovery: one schema (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/Users` | SCIM list/filter users (`userName`, `externalId`, `emails.value`, `id` eq; startIndex/count, cap 200); superuser never listed (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| POST | `/api/v1/scim/v2/Users` | SCIM provision a user (identity_source `scim`, no usable password, default role from the SSO configuration else viewer); 409 `uniqueness` (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/Users/{user_id}` | SCIM read one user; another organisation's id answers 404 (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| PUT | `/api/v1/scim/v2/Users/{user_id}` | SCIM replace a user; `active: false` deactivates and revokes the user's tokens (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| PATCH | `/api/v1/scim/v2/Users/{user_id}` | SCIM PatchOp (Okta / Entra shapes: active, userName, name.*, displayName, externalId, emails, phoneNumbers, enterprise department); deactivation revokes tokens (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| DELETE | `/api/v1/scim/v2/Users/{user_id}` | SCIM delete = deactivate + revoke tokens (204); never a hard delete (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/Groups` | SCIM list/filter groups (`displayName`, `externalId`, `id` eq); groups are role mappings kept in `Organization.settings["scim_groups"]` (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| POST | `/api/v1/scim/v2/Groups` | SCIM create a group (members must be users of the organisation); 409 `uniqueness` on displayName (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| GET | `/api/v1/scim/v2/Groups/{group_id}` | SCIM read one group (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| PUT | `/api/v1/scim/v2/Groups/{group_id}` | SCIM replace a group; members' roles recomputed from mapped groups (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| PATCH | `/api/v1/scim/v2/Groups/{group_id}` | SCIM PatchOp on a group (displayName, externalId, members add/remove/replace, `members[value eq "id"]` remove); roles recomputed (I-C). | SCIM bearer token (identity provider) | the token's organisation |
| DELETE | `/api/v1/scim/v2/Groups/{group_id}` | SCIM delete a group record; members' roles recomputed (I-C). | SCIM bearer token (identity provider) | the token's organisation |

## Called dynamically (9 routes)

Pages call these through a path built at runtime, which the contract diff's call regex cannot see.

| Method | Route | Caller | Roles | Tenancy |
|---|---|---|---|---|
| GET | `/api/v1/fedramp/cmp/generate` | FedRAMP Documents tab. | any authenticated user | org-scoped |
| GET | `/api/v1/fedramp/conmon-plan/generate` | FedRAMP Documents tab. | any authenticated user | org-scoped |
| GET | `/api/v1/fedramp/irp/generate` | FedRAMP Documents tab. | any authenticated user | org-scoped |
| GET | `/api/v1/fedramp/ssp/generate` | FedRAMP Documents tab (FedRAMP.tsx builds the path from its document list). | any authenticated user | org-scoped |
| GET | `/api/v1/ot_security/incidents/{incident_id}/safe_shutdown` | OTSecurityDashboard refreshes the shutdown command state. | any authenticated user | org-scoped |
| POST | `/api/v1/ot_security/incidents/{incident_id}/safe_shutdown` | OTSecurityDashboard action dialog (agent approval queue). | admin | org-scoped |
| GET | `/api/v1/ot_security/zones/{zone_id}/segmentation_audit` | OTSecurityDashboard refreshes the audit command state. | any authenticated user | org-scoped |
| POST | `/api/v1/ot_security/zones/{zone_id}/segmentation_audit` | OTSecurityDashboard action dialog (agent approval queue). | admin | org-scoped |
| GET | `/api/v1/auth/sso/{org_slug}/start` | Login page "Sign in with SSO": the browser navigates (`window.location.assign`) to `login_url` from `POST /auth/sso/discover` (plus `login_hint`); 302 to the IdP. | public | the organisation named by the slug |

## EXPOSE (1 route; the 41 handed to W5-A and the 20 identity routes handed to I-D are called by the UI)

Real routes the UI should call. They stay in the contract diff's "never called" list until a page calls them; then delete the row.

| Method | Route | Note | Roles | Tenancy |
|---|---|---|---|---|
| GET | `/api/v1/roles/me` | The caller's own access: built-in `role`, `custom_role` `{id, name}` or null, `is_superuser`, `is_full_admin`, `tiers` (`{area: tier}` over the area catalogue, computed by the same function the gates use) and `exempt_areas`; never denied by tier (I-F). For the frontend's permission gating (later package). | any authenticated user (platform superuser included) | the caller's own account |
