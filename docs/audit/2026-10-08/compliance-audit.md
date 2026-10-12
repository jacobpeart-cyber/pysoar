# PySOAR semantic audit: Compliance / FedRAMP / Audit & Evidence / Audit Logs / STIG / Data Lake / Privacy / DLP (+ backup)

Read-only review, 2026-10-08, against `main` @ d5ad849. All paths are relative to `C:\Users\jacob\pysoar`.
Backend handler references use `file:line` of the `@router` decorator or the line that does the damage.
Three findings were confirmed by running pure, side-effect-free Python: `ComplianceControl.framework`, `POAM.severity` and `POAM.control_id` do not exist, and `_build_tenant_scoped_sql` accepts `FROM alerts, users`.

Grade counts (88 user-visible features across the 8 pages):

| Grade | Count |
|---|---|
| REAL | 21 |
| PARTIAL | 19 |
| STUB | 1 |
| FAKE | 20 |
| BROKEN | 19 |
| UI-ONLY | 8 |

---

## 1. Page features

### ComplianceDashboard (`frontend/src/pages/ComplianceDashboard.tsx`)

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Compliance | C1 Overall compliance gauge + per-framework score bars | GET /compliance/dashboard | src/api/v1/endpoints/compliance.py:1177 | compliance_frameworks.compliance_score (average) | PARTIAL | The score is never updated by an assessment. `assess_framework` (src/compliance/engine.py:63) writes a ComplianceAssessment row but never sets `framework.compliance_score`. `update_compliance_scores` (src/compliance/tasks.py:235) is not in the beat schedule. The only writer is the boot-time seeder (src/compliance/seeder.py:599), which uses unweighted implemented/total. The number is therefore a snapshot from the last API restart, and it is inflated by the auto-attester (C7). | M |
| Compliance | C2 KPI cards (frameworks, compliant, overdue POA&Ms, CISA, upcoming assessments, X/Y controls implemented) | same | compliance.py:1177-1284 | count queries, org-scoped | REAL | The counts are real. The "implemented" count inherits the attester's unverified statuses (C7). | - |
| Compliance | C3 "Compliance Trend" bar chart | reads `data.trends` | none (the dashboard never returns `trends`) | none | UI-ONLY | The chart is always empty. A real `/compliance/score-history` (compliance.py:1287) exists but is never called. | S |
| Compliance | C4 Controls table | GET /compliance/controls?framework_id&family&status | compliance.py:409 | compliance_controls | PARTIAL | The default `limit=20` is used and the UI has no pagination, so only 20 of roughly 1,000 seeded controls are ever visible. | S |
| Compliance | C5 Framework filter | `framework_id=<fw.name>` | compliance.py:428 | - | BROKEN | The option value is the framework `short_name` (tsx:543), but the backend filters `framework_id == value` (a UUID), so every selection returns 0 rows. | S |
| Compliance | C6 Family and status filters | `family=AC`, `status=partially` | compliance.py:430-433 | - | BROKEN | The family options are codes `['AC','AU',...]` (tsx:519), but stored `control_family` holds names such as "Access Control" (src/fedramp/controls.py:15), so the filter matches nothing. The status option `partially` does not match the stored value `partially_implemented`. | S |
| Compliance | C7 Control status / "implemented" for about 39 controls | written by POST /compliance/frameworks/{id}/attest, and by every GET /frameworks/{id}/ssp, /ssp/download and /report (`generate_ssp(run_attester=True)`, src/compliance/engine.py:202-226) | src/compliance/attester.py:1217-1292 | compliance_controls, compliance_evidence | FAKE | 22 rules return `implemented` with no check at all: AU-8:135, AC-3:187, AC-6:214, AC-7:249, AC-12:272, AU-9:295, IA-5:344, SC-8:368, SC-13:390, IR-6:512, CA-7:695, AU-4:756, AU-6:781, AU-10:804, CM-3:866, CM-7:893, SC-5:917, SC-12:943, SI-3:970, SI-7:996, IR-7:1082, PL-2:1138. Another 7 rules (IA-2, SI-4, IR-4, RA-5, SI-2, AC-2, IR-5) run a count query and return `implemented` whatever the count is (for example, SI-4 is implemented with 0 logs). For each control, `attest_all` sets `implementation_status=100`, sets `last_assessment_result="satisfied"`, overwrites the human-set status, and inserts a `ComplianceEvidence(is_valid=True)` row. That row is re-inserted on every SSP GET. The narratives assert unverified facts: "AWS RDS KMS", "Cloudflare TLS 1.3", "NTP verified by STIG", and AC-6's "viewers are read-only", which is false because none of these modules has a role check. SC-8 marks itself implemented while admitting plaintext internal traffic ("noted as a POAM"). | L |
| Compliance | C8 "Evidence" column and "N files" in the expanded row | `control.evidence_ids` | - | compliance_controls.evidence_ids | UI-ONLY | Nothing in the codebase ever writes `evidence_ids`, so the value is always 0, even when evidence rows exist for the control. | S |
| Compliance | C9 Expanded-row "View Evidence" and "Edit" buttons | none | none | none | UI-ONLY | Both buttons only call `setExpandedControl(null)` (tsx:725-740). A real `PUT /compliance/controls/{id}` exists but is not called. | S |
| Compliance | C10 POA&M list + status/risk filters | GET /compliance/poams | compliance.py:686 | poams | PARTIAL | `limit=20` with no paging. The risk option `medium` does not match the model value `moderate`. The status options omit delayed, cancelled and accepted. | S |
| Compliance | C11 Create POA&M | POST /compliance/poams | compliance.py:727 | poams | BROKEN | The form asks for "Control ID e.g. AC-2" and sends it as `control_id_ref`, which is a FK to `compliance_controls.id` (UUID) (models.py:159). The result is an IntegrityError and a 500. `scheduled_completion_date` is optional in the UI but required by the schema, so leaving it blank gives a 422. Severity `medium`/`critical` are not model values. There is no org check on `control_id_ref`. | S |
| Compliance | C12 Delete POA&M | DELETE /compliance/poams/{id} | none | - | BROKEN | No route exists (405). The mutation has no onError, so the click fails silently. | S |
| Compliance | C13 Overdue POA&M banner | /compliance/dashboard | compliance.py:1220 | poams | REAL | - | - |
| Compliance | C14 CUI list + "Mark as CUI" | GET/POST /compliance/cui | compliance.py:980, 1000 | cui_markings | REAL | Validated and org-scoped. | - |
| Compliance | C15 CISA directives tab | GET /compliance/cisa/directives | compliance.py:1101 | cisa_directives | FAKE (name-only) | No code anywhere creates CISADirective rows. There is no POST and no CISA/KEV feed ingest. `BuiltinFrameworks.load_cisa_directives` (engine.py:1644) returns the constant 20 without inserting anything. The tab is permanently empty and has no explanation. | M |
| Compliance | C16 Directive "Check compliance" button | POST /compliance/cisa/directives/{directive.id}/check | compliance.py:1143 | cisa_directives | BROKEN | The frontend sends the row UUID, but the backend matches `directive_id` (e.g. "BOD 22-01"), so it always 404s. The response is discarded. The "check" only echoes the stored `compliance_status` (engine.py:1496), and `check_kev_compliance` hardcodes `"compliant"` (engine.py:1525). | M |

### FedRAMP (`frontend/src/pages/FedRAMP.tsx`)

| page | feature | frontend call | backend handler | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| FedRAMP | F1 Readiness gauge, badge, gap summary, family breakdown, header score | GET /fedramp/readiness | src/api/v1/endpoints/fedramp.py:107 -> src/fedramp/generator.py:432 | intended: compliance_controls | FAKE | `get_control_implementation_status` queries `ComplianceControl.framework == "FedRAMP"` (generator.py:454). That attribute does not exist (confirmed), so it raises AttributeError, which is swallowed. Every one of the 191 controls is reported as `planned`, the readiness score is a constant 0%, and the DB is never consulted. Even if the query worked, the seeded short_name is `fedramp_moderate` and `evidence_artifacts`, `last_assessed` and `assessor_notes` are not columns. | M |
| FedRAMP | F2 Recommendations list | same | generator.py:312-322 | constants | FAKE | Five static strings are returned for every tenant, whatever the gaps are. | S |
| FedRAMP | F3 "Generate SSP" button | GET /fedramp/ssp/export | fedramp.py:156 -> generator.py:31 | constants + F1 | FAKE | The SSP hardcodes the hosting environment: "AWS GovCloud us-gov-west-1/east-1, RDS Multi-AZ, ElastiCache cluster, ALB+WAF, CloudFront, FIPS 140-2 validated modules, KMS FIPS endpoints" (generator.py:121-149). Prod is a single EC2 docker-compose host. The default org is "PySOAR Inc.". Every control gets the template narrative "PySOAR addresses AC-2 through the <module>" even when it is `planned`. `download_url` points to a route that does not exist. A 3PAO would trace these claims and find them false. | L |
| FedRAMP | F4 Controls tab list + filters | GET /fedramp/controls | fedramp.py:40 | static catalog src/fedramp/controls.py (191) + F1 | FAKE | The catalog is real reference data, but every status is the fabricated `planned`. The status filter option `partial` never matches anything. | M |
| FedRAMP | F5 "Update Status" on a control | POST /fedramp/controls/{id}/update?implementation_status= | fedramp.py:431 (damage at 477) | intended: compliance_controls | FAKE (success without work) | `ComplianceControl.framework` raises, the exception is swallowed, and the endpoint returns 200 with `persisted_to_database:false`. The UI ignores that flag and shows success. The fallback insert uses non-existent kwargs (`framework=`, `family=`, `implementation_narrative=`). It does still fire `on_fedramp_evidence_gap` automation. | S |
| FedRAMP | F6 POA&M report table + summary | GET /fedramp/poam/report | fedramp.py:284 | poams | BROKEN | It reads non-existent POAM attributes (`control_id`, `severity`, `milestones`, `responsible_party`, `comments`) through `getattr` defaults, so columns are blank and every item is severity "low". A `severity` filter calls `POAM.severity`, which raises AttributeError; it is swallowed (fedramp.py:333) and an empty report is returned that reads as "no POA&Ms". | S |
| FedRAMP | F7 POA&M timeline chart | reads `timelineData` | not returned | none | UI-ONLY | Always empty. | S |
| FedRAMP | F8 Export POA&M | same | same | poams | PARTIAL | Exports the blank/defaulted rows described in F6. | S |
| FedRAMP | F9 Evidence coverage per family | GET /fedramp/evidence/status | fedramp.py:394 | intended: compliance_evidence | BROKEN | The page shows 0% coverage forever because `evidence_artifacts` is never populated (F1 root cause), while real uploaded evidence sits in `compliance_evidence` and is ignored. | M |
| FedRAMP | F10 "Collect" evidence per family | POST /audit-evidence/evidence/collect-all {family} | src/api/v1/endpoints/audit_evidence.py:392 -> src/audit_evidence/engine.py:531 | automated_evidence_rules | FAKE (success without work) | All collectors (engine.py:675-717) return `integration_status:"not_integrated"`, and `metric_snapshot` returns `{"metric_snapshot":"data"}`. No evidence row is written; only `last_collected_at` is bumped. `family` is ignored. The UI alerts "Evidence collection completed. N rule(s) run." | M |
| FedRAMP | F11 Documents tab: SSP / IRP / CMP / ConMon Plan generate + download | GET /fedramp/{ssp,irp,cmp,conmon-plan}/generate | fedramp.py:135, 206, 233, 256 -> generator.py:520-771 | constants + F1 | FAKE | Template text is asserted as fact about the customer's system: "Redis TLS enabled", "CIS-hardened Debian 12", "CAB approval required", "deployments signed through CI/CD", "24/7 SOC", "weekly authenticated scans", "Terraform/KMS". Control status is always `planned`. These calls are dynamic, so `contract_diff.json` lists the routes as uncalled. | L |

### AuditEvidence (`frontend/src/pages/AuditEvidence.tsx`)

| page | feature | frontend call | backend handler | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Audit&Evidence | A1 KPI "Audit Events (24h)" | GET /audit-evidence/dashboard/stats | audit_evidence.py:1032 | audit_trails | BROKEN | The UI reads `audit_events_last_24h`, `audit_events_24h` or `audit_events_count` (tsx:146). The schema returns `total_audit_entries` and `audit_entries_this_month`. The value is always 0. | S |
| Audit&Evidence | A2 KPI "Evidence Items" | fallback sum of `evidence_count` over packages | audit_evidence.py:649 | evidence_packages | BROKEN | `total_evidence_items` is not returned, and packages have no `evidence_count`, so the value is always 0 although `/evidence/list` holds real rows. | S |
| Audit&Evidence | A3 KPI "Readiness Score" | fallback `withEv/pkgs*100` | none | evidence_packages | FAKE | Labelled a readiness score, but it is the percentage of packages with evidence, which is always 0 because packages cannot hold evidence (A13). A real `/readiness/check` exists but is not called. | S |
| Audit&Evidence | A4 "Evidence coverage" ring | `withEvidence*3.4` | none | package counts | FAKE | Package counts are drawn as a percentage arc. | S |
| Audit&Evidence | A5 "Recent audit events" | `stats.recent_audit_events` | not returned | none | UI-ONLY | Always empty. | S |
| Audit&Evidence | A6 Audit trail table + filters | POST /audit-evidence/audit/search | audit_evidence.py:89 -> engine.py:325 | audit_trails | BROKEN | Field mismatch: it renders `event.time/type/actor/resource/riskLevel` (tsx:680), while the API returns `created_at/event_type/actor_id/resource_type/risk_level`, so the table shows "Invalid Date" and blank columns. The event-type filter is sent as `type` (tsx:182) and ignored because the schema field is `event_type`. The backend loads every matching row and slices in Python. | S |
| Audit&Evidence | A7 "Export Audit Log" | GET /audit/export?format=csv&days=90 | src/api/v1/endpoints/audit.py:201 | audit_logs | PARTIAL | It exports a different table (`audit_logs`) from the one displayed (`audit_trails`). The route is superuser/admin-only, so analysts get a silent console error. The export is cross-tenant (see AuditLogs). | S |
| Audit&Evidence | A8 Evidence list + filters | GET /audit-evidence/evidence/list | audit_evidence.py:550 | compliance_evidence | REAL | Minor: the type filter `config`/`scan` is compared to raw values (`configuration`, `scan_result`), which the response aliases. | - |
| Audit&Evidence | A9 Upload evidence | POST /audit-evidence/evidence/upload (multipart) | audit_evidence.py:175 | compliance_evidence + `uploads/evidence` volume | REAL | SHA-512 hash; control is org-validated; persistent volume in compose. | - |
| Audit&Evidence | A10 Approve evidence | POST /evidence/{id}/approve | audit_evidence.py:489 | compliance_evidence + audit_trails | REAL | Works, but has no RBAC and no separation of duties: any role, including the uploader, can approve. | S |
| Audit&Evidence | A11 Delete evidence | DELETE /evidence/{id} | audit_evidence.py:431 | same | REAL | Soft delete with a fail-closed audit row. | - |
| Audit&Evidence | A12 "Verify Integrity" | POST /evidence/verify?evidence_id= | audit_evidence.py:411 -> engine.py:612 | intended: compliance_evidence.file_hash | BROKEN | The engine uses `self.db` (the attribute is `self.session`), so it raises AttributeError and always returns `integrity_valid:false`. It also queries `AutomatedEvidenceRule` instead of evidence (engine.py:624), and would return True when no hash is stored. The UI throws the result away, so nothing is ever shown. | S |
| Audit&Evidence | A13 Evidence packages list + create | GET /packages, POST /packages/create | audit_evidence.py:649, 623 | evidence_packages | FAKE (name-only) | The UI says "Bundle evidence artifacts", but no route adds evidence to a package. `evidence_items` is always `{}`, so a package is an empty shell. | M |
| Audit&Evidence | A14 Package "Submit" | POST /packages/{id}/submit | audit_evidence.py:711 | evidence_packages | BROKEN | The button renders only when `pkg.status==='draft'` (tsx:1410), but packages default to `collecting`, so it never appears. The backend looks the package up without an org filter (IDOR). | S |
| Audit&Evidence | A15 Package "View Details" download | GET /packages/{id}/report | audit_evidence.py:742 -> engine.py:643 | evidence_packages | PARTIAL | Metadata only, no evidence. The engine lookup is not org-scoped (cross-tenant read by UUID). | S |
| Audit&Evidence | A16 ConMon status grid | GET /audit-evidence/conmon/status | audit_evidence.py:808 -> engine.py:738 | vulnerability_instances, stig_scan_results, incidents, poams | FAKE | `lastRun` is the request time, not a run time. Absence of data is scored as compliant: 0 vulns gives SI-2 100% "compliant" (engine.py:793), 0 incidents gives IR-4 100% (engine.py:874), and 0 POA&Ms gives 100% "on_track" (engine.py:911). The IR-4 check counts every tenant's incidents (engine.py:850); its comment "Incident does not have organization_id" is false (src/models/incident.py:57). | M |
| Audit&Evidence | A17 "Run ConMon Cycle" | POST /audit-evidence/conmon/run | audit_evidence.py:778 -> engine.py:927 | same | FAKE | Nothing is persisted. `overall_status: "compliant"` is hardcoded (engine.py:939) whatever the checks return. | S |
| Audit&Evidence | A18 "Generate Monthly Report" (FedRAMP ConMon monthly) | GET /audit-evidence/reports/monthly | audit_evidence.py:320 | same | FAKE | Wraps A17, so the hardcoded overall "compliant" ships in the deliverable that goes to the FedRAMP PMO. | S |

### AuditLogs (`frontend/src/pages/AuditLogs.tsx`)

| page | feature | frontend call | backend handler | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| AuditLogs | L1 Audit log table | GET /audit?page&size&... | audit.py:18 (query at 43) | audit_logs | PARTIAL | The data is real, but there is no tenant scope: `AuditLog` has no `organization_id`, and `get_current_superuser` admits any `is_admin` (src/api/deps.py:158). Every tenant admin of an MSSP sees every tenant's audit log. | M |
| AuditLogs | L2 Filters | action/resource_type/success, days=90, search | audit.py:47-80 | audit_logs | PARTIAL | `days` is fixed at 90 and `search` exists in state, but neither has a UI widget. | S |
| AuditLogs | L3 Stats strip | GET /audit/stats | audit.py:152 | audit_logs | PARTIAL | Fetched but never rendered. The backend ignores `days`. Global counts across tenants. | S |
| AuditLogs | L4 Export CSV/JSON/XML | GET /audit/export | audit.py:201 | audit_logs | PARTIAL | XML values are not escaped (injection/malformed XML). No CSV formula-injection guard. Unbounded (365 days loaded into memory). Cross-tenant. `user_email` is not an attribute, so the column falls back to `user_id`. | S |
| AuditLogs | L5 Action / resource-type dropdowns | GET /audit/actions, /audit/resource-types | audit.py:125, 137 | enum / audit_logs | REAL | resource-types is a cross-tenant distinct. | - |
| AuditLogs | L6 Pagination | /audit page/size | audit.py:84-90 | audit_logs | REAL | - | - |

### STIGCompliance (`frontend/src/pages/STIGCompliance.tsx`)

| page | feature | frontend call | backend handler | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| STIG | S1 Dashboard (avg compliance, CAT counts, by-benchmark, recent scans) | GET /stig/dashboard/stats | src/api/v1/endpoints/stig.py:549 | stig_scan_results | PARTIAL | The aggregates are real but poisoned by the fabricated 100% scans from S4. `scans_this_month` compares month only, not year. `low_findings` is always 0. | S |
| STIG | S2 Benchmark cards | GET /stig/benchmarks?platform= | stig.py:54 | stig_benchmarks | BROKEN | It reads `b.name`, but the schema has `title` (tsx:132), so every card shows "Unknown Benchmark". `last_scanned_at` vs `last_scan_at` gives "Invalid Date". The `platform` filter is ignored by the backend. Rule-count CAT I/II/III are labelled as findings. | S |
| STIG | S3 Upload XCCDF | POST /stig/scap/upload | stig.py:406 -> src/stig/engine.py:1051 | stig_benchmarks, stig_rules | REAL | Parses real DISA XCCDF. | - |
| STIG | S4 "Run scan" / Launch Scan modal (agent picker) | POST /stig/scans/launch {host, benchmark_id} | stig.py:192 -> engine.py:156 | stig_scan_results | FAKE | No host is contacted. Every rule is set to `not_reviewed`, but compliance is computed as `(naf + nr) / reviewable` (engine.py:248), so the scan is stored as `completed` at 100% compliant. The benchmark lookup is not org-scoped (engine.py:186-191), so a user can create a scan row owned by another tenant. The UI's agent picker only passes the hostname and never dispatches `run_stig_scan`; only the weekly beat sweep reaches agents. The mutation swallows errors. | M |
| STIG | S5 Scan Results table | GET /stig/scans | stig.py:250 | stig_scan_results | BROKEN | It renders `scan.host/benchmark/compliance/findings.open`, while the API has `target_host/benchmark_id_ref/compliance_percentage` and `findings` is a dict keyed by rule id. `scan.findings.open` throws a TypeError for running/failed scans where `findings` is null (tsx:522, 944), which crashes the tab. | S |
| STIG | S6 Per-rule results (expand) | GET /stig/scans/{id} | stig.py:288 | stig_scan_results.findings | BROKEN | It returns `response.data.results` (tsx:173), a field that does not exist, so the list is always empty. | S |
| STIG | S7 ARF upload | POST /stig/scans/{id}/arf | stig.py:448 -> engine.py:51 | stig_scan_results | REAL | This is the only real result path. It is not org-scoped (`session.get(STIGScanResult, scan_id)`), so it is an IDOR write into another tenant's scan. | S |
| STIG | S8 Remediation tab | GET /stig/scans?severity= | stig.py:250 | stig_scan_results | BROKEN | Scan rows are rendered as remediation rows (finding/assignedTo/dueDate are undefined). `severity` is not a parameter. | M |
| STIG | S9 Auto-remediate | POST /stig/remediate/auto | stig.py:332 -> engine.py:435 | ticket_activities | PARTIAL | The backend is honest: it only logs the fix_text attempt. The UI alerts "Auto-remediate dispatched: N rules submitted". The scan lookup is not org-scoped. | S |

### DataLakeDashboard (`frontend/src/pages/DataLakeDashboard.tsx`)

| page | feature | frontend call | backend handler | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| DataLake | D1 KPIs "Data Sources Active" and "Total Events" | GET /data-lake/sources | src/api/v1/endpoints/data_lake.py:362 | data_sources (auto-seeded built-ins with live COUNT(*) per table) | REAL | - | - |
| DataLake | D2 Sources table | same | same | same | PARTIAL | Ingestion rate is always "0K/sec" because there is no such field. | S |
| DataLake | D3 "Add Data Source" | POST /data-lake/sources | data_lake.py:332 | data_sources | FAKE (name-only) | The UI sends `connection_config`, but the schema field is `connection_config_encrypted`, so the connection string is silently dropped. No ingestion engine reads custom sources; the row stays `initializing` forever. `/sources/{id}/start` always 400s because `DataIngestionEngine()` has an empty in-memory registry (src/data_lake/engine.py:79-93). | M |
| DataLake | D4 Pipelines list + "Active Pipelines" KPI | GET /data-lake/pipelines | data_lake.py:773 (builtins at 270-326) | Celery beat config | FAKE | Each beat entry is reported as `status:"active"` with `last_run: now` (data_lake.py:315-316), a fabricated timestamp. The UI then derives `successRate = error_count>0 ? 0 : 100` (tsx:75), so every task shows 100% success with 0 records processed. | S |
| DataLake | D5 Pipeline health chart | derived from D4 | - | - | FAKE | Charts the fabricated success rates. | S |
| DataLake | D6 Query Engine, SQL | POST /data-lake/query {query} | data_lake.py:1437, guard at 1353-1433 | any table | BROKEN (critical security) | Execution is real, but the tenant guard is bypassable. Only the first FROM table gets the org filter (1415). Comma joins are not parsed, so `SELECT users.email, users.hashed_password FROM alerts, users` passes the whitelist (confirmed by calling `_build_tenant_scoped_sql`). JOIN and subquery tables are unscoped. The column whitelist is never enforced. `pg_read_binary_file` and other functions are not banned. Any authenticated viewer can read every tenant's data and the users table. | M |
| DataLake | D7 KQL / SPL buttons | same, query_language=kql/spl | data_lake.py:1478 | - | STUB | Honest 400: "not yet executable". | - |
| DataLake | D8 Data Catalog | GET /data-lake/catalog | data_lake.py:1136 | information_schema + counts | REAL | Row counts for tables without an org column (audit_logs) are global. | - |
| DataLake | D9 "Total Storage" KPI + Storage Tiers pie | `fetch('/api/v1/data-lake/dashboard/storage-breakdown', {credentials:'include'})` | data_lake.py:1977 | pg_total_relation_size | BROKEN | Raw `fetch` sends no bearer token and the API has no cookie auth, so it 401s; the page shows "0 B" and an empty pie (tsx:101). The backend also attributes the whole table's bytes (all tenants) to the caller, and has no rollback after the failing `audit_logs` query (no organization_id column), so every later table silently fails. | S |
| DataLake | D10 Partitions (log_entries daily) | GET /data-lake/partitions/daily/log_entries?days=30 | data_lake.py:603 | log_entries | PARTIAL | Day buckets are labelled as partitions and tiers by age (documented as synthetic). Bytes are table-total divided by tenant rows, which is inflated. | S |
| DataLake | D11 Ingest trend chart | GET /data-lake/dashboard/ingestion-trend | data_lake.py:2187 | built-in tables, org-scoped | REAL | - | - |

### PrivacyDashboard (`frontend/src/pages/PrivacyDashboard.tsx`)

| page | feature | frontend call | backend handler | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Privacy | P1 Stat cards (DSRs, pending, compliance rate, PIAs) | GET /privacy/dashboard/stats | src/api/v1/endpoints/privacy.py:883 | privacy tables | PARTIAL | `dsr_compliance_rate` is completed/total. It ignores deadlines, and rejected or denied DSRs count as pending. It is not a compliance rate. | S |
| Privacy | P2 DSR list + create | GET/POST /privacy/dsr/requests | privacy.py:131, 77 | data_subject_requests | REAL | `description` is silently dropped. The total count ignores the status filter. | - |
| Privacy | P3 PIA list + create | GET/POST /privacy/pia/assessments | privacy.py:386, 354 -> src/privacy/engine.py:458 | privacy_impact_assessments | PARTIAL | `data_types_processed`, `processing_purposes` and `legal_basis` from the form are discarded; only name, project and type are stored. | S |
| Privacy | P4 Consent lookup + create | GET /privacy/consent/records/{subject}, POST | privacy.py:563, 527 | consent_records | REAL | - | - |
| Privacy | P5 ROPA list + create | GET/POST /privacy/ropa/processing-records | privacy.py:651, 619 -> engine.py:943 | data_processing_records | PARTIAL | `data_subjects`, `recipients` and `retention_period_days` are discarded. These are mandatory GDPR Art. 30 fields. | S |
| Privacy | P6 Privacy incidents list + report | GET /privacy/incidents/reports, POST /privacy/incidents/report | privacy.py:765, 723 | privacy_incidents | REAL | - | - |

### DLPDashboard (`frontend/src/pages/DLPDashboard.tsx`)

| page | feature | frontend call | backend handler | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| DLP | X1 Policies list | GET /dlp/policies | src/api/v1/endpoints/dlp.py:192 | dlp_policies | REAL | - | - |
| DLP | X2 Create / edit policy | POST /dlp/policies, PATCH /dlp/policies/{id} | dlp.py:160, 242 | dlp_policies | REAL | Rows are real. The form captures no data_patterns, and the classification select is not sent. | - |
| DLP | X3 Enable/disable + "Active Policies" KPI | POST /dlp/policies/{id}/enable, /disable | dlp.py:281, 295 | dlp_policies.enabled | FAKE (name-only) | No code path evaluates a DLPPolicy against any traffic, file, email or endpoint. `DLPPolicy` and `DLPEngine` are referenced only inside src/dlp and the dlp endpoint. "Active" protects nothing. | L |
| DLP | X4 "Test policy" | POST /dlp/policies/{id}/test {sample_text} | dlp.py:309 | regex engine | BROKEN | It sends `sample_text` (src/frontend api/endpoints.ts:1071), but the schema requires `sample_content`, so every test returns 422. The backend also evaluates the global built-in patterns rather than the policy's own patterns. | S |
| DLP | X5 Incidents list | GET /dlp/incidents | dlp.py:820 | dlp_incidents | REAL | Nothing ever creates incidents except a manual API POST (no detection pipeline). | - |
| DLP | X6 Incident status/notes update | PATCH /dlp/incidents/{id} | dlp.py:865 | dlp_incidents | PARTIAL | `resolution_notes` is not in `DLPIncidentUpdate`, so the notes are silently dropped. | S |
| DLP | X7 Classifications tab ("policies using", "related incidents") | GET /dlp/classifications | dlp.py:528 | data_classifications | UI-ONLY | The list is real. The counts filter on `p.classification` and `p.dataType`, which do not exist, so they are always 0. | S |
| DLP | X8 KPI "Violations this week" | client count of incidents | - | dlp_incidents | PARTIAL | Counts incidents, not violations. | S |
| DLP | X9 Reports: "Top Offenders" | none | none | none | UI-ONLY | Placeholder text "User-level analytics available in full reports". There are no such reports. | S |
| DLP | X10 Reports: "DLP Summary Report (PDF)" | client Blob | none | page state | UI-ONLY | Downloads JSON while labelled PDF. | S |
| DLP | X11 Reports: incident trend, policy effectiveness, incident CSV | client-side | - | loaded lists | REAL | - | - |

---

## 2. Uncalled backend routes in these domains (from contract_diff.json), with verdicts

Verdict key: **EXPOSE** means a real capability the UI should use. **FIX-then-expose** means a real capability that is wrong today. **FAKE/REMOVE** means it fabricates and should be fixed or deleted. **DEAD** means a duplicate or unused route. **SECURITY** means it is dangerous as written.

| route | handler | verdict | notes |
|---|---|---|---|
| GET /compliance/frameworks/{x} | compliance.py:111 | EXPOSE | Framework detail. |
| GET /compliance/frameworks/{x}/gaps | compliance.py:187 | EXPOSE | Real gaps from control status. |
| GET /compliance/frameworks/{x}/report | compliance.py:335 | FIX-then-expose | A GET that runs the attester (mutates controls and inserts evidence). |
| GET /compliance/frameworks/{x}/ssp, /ssp/download | compliance.py:230, 262 | FIX-then-expose | This is the correct DB-driven SSP and should replace the FedRAMP generator. Today every GET runs the FAKE attester and spams `compliance_evidence`. |
| POST /compliance/frameworks/{x}/attest | compliance.py:312 | FAKE/REMOVE (rewrite) | See C7. |
| POST /compliance/frameworks/{x}/conmon | compliance.py:371 | BROKEN | Requires `short_name=="fedramp"`; the seeded value is `fedramp_moderate`, so it always 404s. FedRAMPManager has the same bug (engine.py:675, 700, 726). |
| GET /compliance/controls/{x} | compliance.py:449 | EXPOSE | - |
| PUT /compliance/controls/{x} | compliance.py:471 | EXPOSE (needs RBAC) | Backs the dead "Edit" button. Auto-creates a POA&M. |
| POST /compliance/controls/{x}/assess | compliance.py:620 -> engine.py:906 | BROKEN | `select(ComplianceControl).where(control_id==...)` has no org or framework filter, so `scalar_one_or_none` raises MultipleResultsFound (AC-2 is seeded in both FedRAMP and NIST 800-53 for every org) and returns 500. The checks themselves (engine.py:956-1350) are real. |
| GET /compliance/controls/cross-map | compliance.py:645 | BROKEN | Shadowed by `/controls/{control_id}` declared earlier (line 449), so it always returns "Control not found". |
| GET /compliance/poams/{x}, PUT /compliance/poams/{x} | compliance.py:797, 819 | EXPOSE | POA&M detail/update; the UI has neither. |
| GET /compliance/poams/overdue, /poams/report | compliance.py:753, 773 | EXPOSE | Real. |
| GET /compliance/evidence, /evidence/{x} | compliance.py:863, 922 | DEAD | Duplicates `/audit-evidence/evidence/list`. |
| POST /compliance/evidence | compliance.py:892 | SECURITY, REMOVE | Accepts an arbitrary `file_path` query param and stores it. GET `/audit-evidence/evidence/{id}/download` (audit_evidence.py:280) then streams that path with `FileResponse`, so any authenticated user can read arbitrary server files (e.g. `/app/.env`). |
| PUT /compliance/evidence/{x}/review | compliance.py:944 | REMOVE | `reviewed_by` is a client-supplied string, so the approver identity can be forged. Superseded by `/audit-evidence/evidence/{id}/approve`. |
| GET /compliance/cui/audit, PUT /compliance/cui/{x} | compliance.py:1071, 1038 | EXPOSE | Real. |
| GET /compliance/cisa/directives/{x} | compliance.py:1121 | FIX | No data source (C15). |
| GET /compliance/score-history | compliance.py:1287 | EXPOSE | Should feed the empty trend chart (C3). |
| GET /fedramp/ssp/generate, /irp/generate, /cmp/generate, /conmon-plan/generate | fedramp.py:135, 206, 233, 256 | FAKE (actually called dynamically by the Documents tab) | See F3/F11. |
| GET /fedramp/documents | aliases.py:123 | BROKEN/DEAD | Built on the broken generator, so it always returns `{items:[]}` and swallows errors. |
| GET /audit-evidence/evidence/{x}/download | audit_evidence.py:280 | EXPOSE (after closing the file_path hole) | The evidence tab has no download; assessors need it. |
| GET /audit-evidence/packages/{x} | audit_evidence.py:672 | EXPOSE | - |
| POST /audit-evidence/packages/{x}/package | audit_evidence.py:695 -> engine.py:556 | FIX | Hashes an always-empty package and is not org-scoped. |
| GET /audit-evidence/readiness/check | audit_evidence.py:856 -> engine.py:958 | EXPOSE | Real readiness from control status. Should replace the A3 KPI once the attester is fixed. |
| GET /audit-evidence/readiness/coverage | audit_evidence.py:872 -> engine.py:1066 | FAKE/REMOVE | Hardcoded 150 / 142 / 94.7% with AC-5/SI-7 missing (engine.py:1078). The gap fan-out reads keys the stub never returns. |
| GET /audit-evidence/readiness/freshness | audit_evidence.py:942 -> engine.py:1088 | FAKE/REMOVE | Hardcoded 128 fresh / 14 stale / 90.1% (engine.py:1101). |
| GET /audit-evidence/readiness/assessor-package | audit_evidence.py:958 -> engine.py:1113 | FAKE/REMOVE | Built from the two stubs above, so `ready_for_assessment` is always true. |
| GET /audit-evidence/conmon/report, POST /conmon/run-cycle | audit_evidence.py:793, 763 | DEAD + FAKE | Duplicates of `/conmon/run` with the hardcoded "compliant". |
| GET /audit-evidence/audit/export | audit_evidence.py:122 | DEAD/PARTIAL | `format` is ignored (always JSON). Duplicates `/audit/export`. |
| GET /audit-evidence/audit/suspicious-activity | audit_evidence.py:154 | EXPOSE | Real heuristic. |
| POST /audit-evidence/audit/log | audit_evidence.py:57 | SECURITY | Any user can write audit entries with an arbitrary `actor_id`, `actor_ip` and `result`, which forges the AU-trail. Restrict to internal use or remove. |
| POST /audit-evidence/evidence/collect | audit_evidence.py:372 | STUB (dishonest) | Returns `"status":"success"` around not_integrated stubs. The rule lookup is not org-scoped. |
| GET /audit-evidence/rules, POST /rules/create | audit_evidence.py:1005, 979 | name-only | Rules persist, but every collector is a stub. |
| GET /stig/benchmarks/{x} | stig.py:76 | FIX-then-expose | Matches only the XCCDF `benchmark_id` string, while the UI holds UUIDs. |
| GET /stig/benchmarks/{x}/rules, /rules/{x}, /rules/search | stig.py:99, 164, 148 | EXPOSE | Real rule browser; the UI has none. |
| GET /stig/remediations | aliases.py:163 | DEAD | Returns scan rows, not findings. |
| POST /stig/remediate/script | stig.py:351 -> engine.py:520 | EXPOSE | Real, from DISA fix_text. The rule lookup by `rule_id` is not org-scoped. |
| POST /stig/scans/compare | stig.py:311 -> engine.py:361 | FIX-then-expose | Not org-scoped (IDOR). |
| POST /stig/scans/fleet | stig.py:230 | FAKE | Runs the in-process 100%-compliant scan for N hosts. |
| POST /stig/scap/import | stig.py:380 | SECURITY | Any user can make the server parse an arbitrary server-side path. Remove (upload covers it). |
| POST /stig/scap/scan | stig.py:471 -> engine.py:950 | PARTIAL/remove | Reports "completed" from rule default_status, not an execution. The note is honest, but the status is not. |
| POST /stig/scap/arf-report | stig.py:506 -> engine.py:1395 | FIX | Real data, not org-scoped. |
| POST /stig/scap/validate-oval, GET /stig/scap/profiles | stig.py:490, 522 | EXPOSE (profiles); validate-oval not verified in depth | - |
| GET /data-lake/sources/{x}, PATCH /sources/{x} | data_lake.py:420, 439 | EXPOSE | - |
| POST /data-lake/sources/{x}/start, /stop | data_lake.py:469, 500 | BROKEN | Always 400 (empty in-memory engine). Start would also stamp `last_event_received=now`, a fabricated timestamp. |
| GET/POST/PATCH /data-lake/partitions, /models, POST/PATCH /pipelines | data_lake.py:533-996 | name-only | Metadata rows that nothing executes or consumes. Expose only with an executor. |
| POST /data-lake/queries, GET /queries, /queries/{x} | data_lake.py:996, 1057, 1095 | EXPOSE (history), POST not verified in depth | `/query` already writes QueryJob rows; the UI shows no history. |
| POST /data-lake/queries/{x}/estimate-cost | data_lake.py:1114 -> engine.py:906 | FAKE | Hardcoded BigQuery $6.25/TB pricing for a Postgres store. |
| GET /data-lake/catalog/datasets | data_lake.py:1663 | BROKEN | New in-memory `DataCatalog()` on every call, so the result is always empty. |
| GET /data-lake/catalog/lineage/{x}, /catalog/quality/{x} | data_lake.py:1677, 1786 | EXPOSE | Real, from DB metadata. |
| GET /data-lake/dashboard/metrics, /pipeline-status | data_lake.py:1887, 2089 | EXPOSE with fix | `success_rate` = active/total pipelines (mislabelled). pipeline-status counts builtin beat entries as active. |
| GET /privacy/dsr, /pia, /consent, /ropa, /incidents (flat aliases) | aliases.py:187-275 | DEAD | Duplicates; `_safe_list` swallows errors and returns an empty list. |
| GET /privacy/dsr/requests/{x}, PATCH /dsr/requests/{x} | privacy.py:185, 216 | EXPOSE | The UI has no DSR workflow at all. |
| POST /privacy/dsr/requests/{x}/verify-identity | privacy.py:260 -> engine.py:88 | FAKE | Sets IDENTITY_VERIFIED with no verification performed. |
| POST /privacy/dsr/requests/{x}/search-systems | privacy.py:287 -> engine.py:112 | FAKE | Reports caller-supplied systems as "searched" without querying them; only scans privacy tables. |
| POST /privacy/dsr/requests/{x}/compile-data | privacy.py:309 -> engine.py:211 | FAKE | The "data package" contains category labels, not data. |
| POST /privacy/dsr/requests/{x}/deadline-alerts | privacy.py:331 | EXPOSE (should be GET) | - |
| GET /privacy/pia/assessments/{x}, POST /submit-dpo-review | privacy.py:419, 496 | EXPOSE | - |
| POST /privacy/pia/assessments/{x}/assess-risks | privacy.py:450 -> engine.py:571 | PARTIAL | Heuristic. Lowered by the boilerplate mitigations below. |
| POST /privacy/pia/assessments/{x}/mitigations | privacy.py:475 -> engine.py:672 | FAKE | Writes the same 8 boilerplate mitigations into every PIA, which then lowers its risk score. |
| POST /privacy/consent/records/{x}/withdraw | privacy.py:588 | EXPOSE | Real; GDPR right. |
| POST /privacy/ropa/retention-violations, GET /ropa/generate-ropa | privacy.py:682, 700 | EXPOSE (not verified in depth) | - |
| GET /privacy/incidents/reports/{x}, POST /mark-notified | privacy.py:798, 852 | EXPOSE | - |
| POST /privacy/incidents/reports/{x}/notification-deadlines | privacy.py:831 -> engine.py:1273 | FAKE | Deadlines are computed from now(), not discovery time, so they move on every call. GDPR+CCPA are always implicated. |
| POST /privacy/monitoring/trigger-* (4) | privacy.py:1021-1080 | EXPOSE + schedule | Real Celery dispatch, but none of these tasks is in beat (src/workers/celery_app.py), so DSR deadlines are never monitored automatically. |
| DELETE /dlp/policies/{x}, GET /dlp/policies/{x} | dlp.py:269, 231 | EXPOSE | The UI has no delete. |
| GET/POST/PATCH /dlp/classifications(/{x}) | dlp.py:495-571 | EXPOSE | - |
| POST /dlp/classifications/classify-document | dlp.py:600 | EXPOSE | Real regex classification. `confidence` defaults to 0.75. |
| GET /dlp/classifications/{x}/handling-requirements | dlp.py:625 | EXPOSE | Static reference table by level. |
| GET/POST/PATCH /dlp/violations, POST /violations/bulk-action | dlp.py:338-449 | EXPOSE (manual) | No detection source exists. |
| POST /dlp/discovery/scan, GET /discovery/scans(/{x}) | dlp.py:651, 673, 709 | FAKE (name-only) | Inserts a `pending` row that nothing ever processes. |
| GET /dlp/discovery/data-map, /discovery/lineage/{x} | dlp.py:729, 739 | STUB (honest) | Empty structure with a truthful note. |
| POST /dlp/incidents, GET /incidents/{x} | dlp.py:753, 854 | EXPOSE | - |
| POST /dlp/incidents/{x}/assess-breach | dlp.py:890 | PARTIAL | Heuristic; persists results. |
| GET /dlp/incidents/{x}/notification-tracking | dlp.py:934 | FAKE | Echoes `notified_count` and `total_required` from query params. Never loads the incident. No org check. |
| GET /dlp/dashboard, /dlp/trends, /dlp/compliance-status | dlp.py:958, 1154, 1239 | EXPOSE | Spot-checked real. compliance-status inherits the framework scores (C1). |
| GET /backup/status | backup.py:38 | PARTIAL/FAKE fields | `auto_backup_enabled: True`, `retention_days: 7` hardcoded (backup.py:59). No backup task is scheduled. Any user can read it. |
| POST /backup/create, /backup/restore, DELETE /backup/backups/{x} | backup.py:64, 170, 228 | SECURITY then expose | Real pg_dump/pg_restore of the entire multi-tenant DB, gated only by `is_admin` (any tenant admin). Restore returns 200 "completed_with_warnings" on failure. The plain-SQL fallback cannot be restored with pg_restore. The `.sql.gz` name on custom format is misleading. Restrict to a platform superuser. |
| GET /backup/notifications/test | backup.py:242 | FIX | A GET with a side effect (sends email) that any user can trigger. Make it POST and admin-only. |
| `complianceApi.getControls`, `stigApi.runScan/getFindings`, `auditEvidenceApi.*` in frontend/src/api/endpoints.ts:381-480 | - | DEAD frontend code | Call non-existent routes (the 7 "no backend route" entries). No page uses them. Delete. |

---

## 3. Multi-tenant and RBAC findings found while tracing

1. **Data-lake SQL guard bypass** (critical): see D6, data_lake.py:1353-1433. Cross-tenant reads, plus reads of the `users` table, by any authenticated user.
2. **Arbitrary file read** (critical): POST /compliance/evidence (compliance.py:892) stores a caller-supplied `file_path`, and GET /audit-evidence/evidence/{id}/download (audit_evidence.py:280) streams it.
3. **Audit logs are global** (high for MSSPs): `AuditLog` has no `organization_id` (src/models/audit.py:54). `/audit`, `/audit/stats`, `/audit/export` and `/audit/resource-types` return every tenant's rows to any `is_admin`.
4. **Backup/restore of the whole platform by any tenant admin** (backup.py:64, 170, 228).
5. **Unscoped lookups (IDOR)**:
   - STIG: `scan_host` benchmark lookup (stig/engine.py:186) can write a scan into another tenant; `ingest_arf_result` (engine.py:66); `auto_remediate` (engine.py:452); `get_scan_comparison` (engine.py:375); `generate_arf_report` (engine.py:1407); `generate_remediation_script` rule lookup (engine.py:584).
   - Audit-evidence: `submit_evidence_package` (audit_evidence.py:723); `package_evidence` and `generate_evidence_report` (engine.py:568, 652); `collect_evidence` rule (engine.py:494).
   - ConMon IR-4 incident count (engine.py:850).
   - `NISTManager.automated_control_check` (compliance/engine.py:913).
   - Data-lake storage-breakdown and partitions attribute whole-table byte sizes, and catalog/partitions fall back to global counts for tables without an org column.
6. **No RBAC anywhere in these domains**: compliance, fedramp, audit_evidence, stig, data_lake, privacy and dlp have zero role checks (grep for AdminUser, require_role and get_current_superuser returns 0 in each file). A viewer can mark controls implemented, approve their own evidence, delete evidence, run "remediation", create DSRs, toggle DLP policies and run SQL. There is no separation of duties on evidence approval. The attester's AC-6 narrative claims the opposite.
7. POA&M auto-create duplicate check (compliance.py:525) and the POAM create `control_id_ref` (compliance.py:733) are not org-validated.

---

## 4. Prioritised fix list

1. **(Security, S)** Close the arbitrary file read: delete POST /compliance/evidence or drop `file_path`, and make the download route refuse paths outside `EVIDENCE_UPLOAD_DIR/<org>`.
2. **(Security, M)** Replace the data-lake SQL guard with a real parser (e.g. sqlglot): every table must be in the whitelist and scoped, columns must be whitelisted, functions blocked. Alternatively, run queries as a read-only DB role with row-level security on organization_id.
3. **(Security, M)** Tenant-scope AuditLog (add organization_id plus a migration and backfill). Restrict backup/restore to a platform superuser. Add org filters to every IDOR in section 3.5.
4. **(Fake compliance claims, L)** Rewrite the ControlAutoAttester so a rule may set `implemented`/`satisfied` only when a live check passes. For code-exists-but-unverified controls, write `partially_implemented` plus a narrative marked "provider-asserted, unverified". Stop overwriting human-set status. Stop running it on GET. Stop inserting `is_valid=True` evidence rows on every SSP view.
5. **(Fake, M)** FedRAMP module: point `get_control_implementation_status` and `update_control_status` at the real `framework_id` of the `fedramp_moderate` framework and the real columns, and surface DB errors instead of swallowing them. Remove the hardcoded environment, boilerplate narratives and recommendations from the SSP/IRP/CMP/ConMon generators, or render those sections from tenant-supplied system-profile data marked as "to be completed". Better still, retire the FedRAMP generator and use `/compliance/frameworks/{id}/ssp`.
6. **(Fake, S)** ConMon: remove the hardcoded `overall_status:"compliant"`. Treat "no data" as `not_assessed`, not 100%. Scope incidents by org. Persist cycle results with a real `lastRun`.
7. **(Fake, S)** Delete or rewrite `check_evidence_coverage`, `check_evidence_freshness` and `generate_assessor_package` (audit_evidence/engine.py:1066-1135) to compute from `compliance_evidence`. Fix `verify_evidence_integrity` to use `self.session` and ComplianceEvidence.file_hash, and to return "unverifiable" when there is no hash.
8. **(Fake, S)** STIG in-process scan: either refuse (honest 409 "requires agent; dispatched run_stig_scan task") and actually dispatch `run_stig_scan.delay`, or compute compliance as `naf / (total - na)`, with not_reviewed counted as non-compliant, and set status `pending_results`. Remove `/stig/scans/fleet` in-process.
9. **(Broken UI, S each)** Fix the field-name contracts:
   - STIG benchmarks/scans/per-rule/remediations (S2, S5, S6, S8).
   - AuditEvidence dashboard keys and audit trail fields (A1, A2, A6).
   - Compliance filters (C5, C6).
   - POA&M create (control picker that sends the UUID, required date) and delete route (C11, C12).
   - CISA check by directive_id (C16).
   - DLP test `sample_content` (X4); DLP incident `resolution_notes` (X6).
   - Data-lake storage-breakdown via the `api` client (D9).
   - FedRAMP POAM report attributes (F6).
10. **(Fake, S)** Data-lake built-in pipelines: drop `last_run: now` and `status:"active"`, report "scheduled" and the cadence only, and stop the UI defaulting success to 100%. Remove "Add Data Source" until a connector exists, or label it as a registration only.
11. **(Name-only, M-L)** Decide on DLP enforcement. Either wire `DLPEngine` plus policies into a real inspection point (agent file events, email, SIEM log scanning) or label the module "policy registry, no enforcement". Do the same for discovery scans, evidence packages (add an "attach evidence" route), and CISA directives (ingest from the CISA KEV/BOD feed).
12. **(RBAC, M)** Add role gates: viewer read-only across these modules, analyst for CRUD, admin for control status/attest/approve. Enforce separation of duties so the uploader cannot approve their own evidence.
13. **(Partial, S)** Wire `/compliance/score-history` to the trend chart. Have `assess_framework` update `framework.compliance_score` and schedule `update_compliance_scores`. Paginate controls/POA&Ms. Persist the dropped PIA/ROPA fields. Schedule the privacy monitoring tasks. Make `/backup/status` report real schedule state.
14. **(Dead code, S)** Delete `complianceApi.getControls`, `stigApi.*` and `auditEvidenceApi.*` from frontend/src/api/endpoints.ts, the privacy/fedramp/stig aliases in aliases.py, `BuiltinFrameworks` (constant counts), and `STIGLibrary.load_builtin_benchmarks` (hardcoded benchmark shells with invented rule counts, reachable via the `update_stig_benchmarks` task).
