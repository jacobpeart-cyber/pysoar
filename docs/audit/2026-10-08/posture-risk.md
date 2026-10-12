# Semantic audit: posture and risk pages (2026-10-08)

Pages audited: VulnManagement, ExposureManagement, ContainerSecurity, SupplyChainDashboard, ThreatModeling, RiskQuantification, ZeroTrustDashboard, APISecurityDashboard, OTSecurityDashboard.

Method: every feature was traced from the TSX through the API helper, the route, the engine or task, and the table or integration. The audit was read-only. Three parallel slice audits were merged with my own tracing, and the top findings were re-verified by hand, including:
- the ZT session lockout;
- the OT simulated CVE dict;
- FAIR default inputs and the PERT bug;
- the vulnmgmt field mismatches;
- `scan_parser` `name=`/`is_monitored=`;
- the `selectedAsset` dead state;
- the exposure exploit filter;
- the compliance-trend flatline;
- `bulk_action` with no org filter;
- container cross-tenant vuln copy.

Grade key:
- **REAL**: backed by the DB or an integration, and errors surface honestly.
- **PARTIAL**: works but is materially incomplete.
- **STUB**: honest empty or not-implemented state.
- **FAKE**: fabricated, made up from nothing, or success returned without work.
- **BROKEN**: calls a missing or mis-shaped route, or crashes.
- **UI-ONLY**: a visual element with no data behind it that pretends to have data.

Cross-cutting facts, which apply to every row below:
- **RBAC.** None of the 9 endpoint modules uses `require_role`/`AdminUser` (`src/api/deps.py:180`). Counts were taken with grep. The 149 POST/PUT/PATCH/DELETE routes are:

  | module | mutating routes |
  |---|---|
  | api_security | 17 |
  | container_security | 12 |
  | exposure | 22 |
  | ot_security | 24 |
  | risk_quant | 16 |
  | supplychain | 13 |
  | threat_modeling | 14 |
  | vulnmgmt | 15 |
  | zerotrust | 16 |

  There is no router-level dependency (`src/api/v1/router.py:85-115`) and no RBAC middleware (`src/middleware/` only has audit_logging and tenant_isolation). Any authenticated user, including a viewer, can trigger OT safe-shutdown, network sweeps, SSRF-capable header checks, ZT policy deletes, and marking a device as fully trusted.
- **Unscheduled or unregistered workers.** `src/vulnmgmt/tasks.py`, `src/container_security/tasks.py`, `src/risk_quant/tasks.py`, `src/zerotrust/tasks.py` and `src/ot_security/tasks.py` are not in the Celery `include` list (`src/workers/celery_app.py:14-65`). Of the exposure tasks, only `run_asset_discovery` and `detect_attack_surface_changes` are on beat (`celery_app.py:376,380`).
- **Two disjoint vulnerability stores.**
  - VulnMgmt: `vulnerabilities` and `vulnerability_instances`.
  - Exposure: `exposure_vulnerabilities` and `asset_vulnerabilities`.
  - Data imported on one page never shows on the other.
- **Pagination.** Almost every page loads page 1 only (backend default size 20 or 50) and computes its KPI cards client-side from that page. Every KPI is therefore capped at the page size.

---

## 1. Feature table

### VulnManagement

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| VulnMgmt | Card "Critical Vulns" | `GET /vulnmgmt/dashboard` (VulnManagement.tsx:122) | vulnmgmt.py:852 | `vulnerability_instances` | BROKEN | Reads `by_severity.critical` (tsx:147), which `DashboardMetrics` never returns (schemas/vulnmgmt.py:364-373). Falls back to counting page 1 (20 rows). | S |
| VulnMgmt | Card "Open Findings" | same | vulnmgmt.py:852 | same | BROKEN | Reads `total_vulnerabilities` (tsx:149), which is not returned, so it shows `vulnerabilities.length`, capped at 20. | S |
| VulnMgmt | Card "MTTR" | same | vulnmgmt.py:852 | none | BROKEN | `mean_time_to_remediate_days`/`mttr_days` are never returned, so it always shows "—". The engine method exists (vulnmgmt/engine.py:738) but is unused. | S |
| VulnMgmt | Card "SLA Compliance" | same | vulnmgmt.py:874 → engine.py:502 | `vulnerability_instances.sla_status` | FAKE | 0 instances renders a confident "0%". The only updater of `sla_status` is `check_sla_breaches` (exposure/tasks.py:677), which is unscheduled, so any org with instances reads 100% whatever their age. No automated path ever creates instances (scan import writes only catalog rows, vulnmgmt/engine.py:322-362). | M |
| VulnMgmt | CVSS distribution / severity / patch-status widgets | client over loaded rows | vulnmgmt.py:88 | `vulnerabilities` | PARTIAL | Page 1 only. A null CVSS is counted in the 0.0-3.9 bucket (tsx:261). "KEV Listed" is always 0 (next row). | S |
| VulnMgmt | KEV indicator, KEV count, CISA KEV tab | `normalizeVuln` (tsx:65) | vulnmgmt.py:88 | `vulnerabilities.kev_listed` | BROKEN | Reads `is_kev ?? kev`, but the backend field is `kev_listed` (schemas/vulnmgmt.py:32), so KEV is always false and the tab is always empty. Once fixed, `vuln.cvss.toFixed(1)` (tsx:565) will crash on KEV rows with a null CVSS. Nothing syncs KEV server-side: `/sync-kev` needs a client-posted feed, and `sync_kev_database` writes ThreatIndicator only and is unscheduled. | M |
| VulnMgmt | Vulns table "Assets" / "Days open" / "EPSS" | `normalizeVuln` (tsx:66-67) | vulnmgmt.py:88 | — | BROKEN | `affected_instance_count`/`days_open` are never returned, so they show 0 and blank. A null EPSS shows "0%" (tsx:329). | M |
| VulnMgmt | Search box | client filter (tsx:165-168) | — (backend `search` at vulnmgmt.py:94 is unused) | loaded rows | PARTIAL | Searches only 20 rows; there is no pagination UI. | S |
| VulnMgmt | Filter button | `setShowFilterPanel` (tsx:295) | — | — | UI-ONLY | `showFilterPanel` is never read (it only appears at tsx:108 and 295). | S |
| VulnMgmt | View details modal | local row | — | loaded row | REAL | Shows the loaded row. | — |
| VulnMgmt | New Vulnerability | `POST /vulnmgmt/vulnerabilities` (tsx:773) | vulnmgmt.py:148 | `vulnerabilities` | PARTIAL | Persists and fires automation. `cvss_v3_score: parseFloat(..) \|\| 0` (tsx:777) stores a fabricated CVSS of 0.0 when left blank. Errors only go to the console. | S |
| VulnMgmt | Edit vulnerability | `PUT /vulnmgmt/vulnerabilities/{id}` (tsx:635) | vulnmgmt.py:190 | `vulnerabilities` | REAL | Org-checked. Errors only go to the console. | — |
| VulnMgmt | Scan Profiles list | `GET /vulnmgmt/scan-profiles` (endpoints.ts:661) | vulnmgmt.py:470 | `scan_profiles` | BROKEN | Reads `schedule`, `status`, `last_run`, `next_run` and `avg_duration_seconds` (tsx:72-74, 390-407). The backend returns `schedule_cron`, `enabled`, `last_scan_date` and `next_scan_date`, so schedule and status are blank and both dates show "Invalid Date". | S |
| VulnMgmt | New Scan Profile | `POST /vulnmgmt/scan-profiles` (tsx:838) | vulnmgmt.py:504 | `scan_profiles` | BROKEN | Sends `scan_type`, `schedule`, `is_active` and `target_filters`; the schema expects `scanner_type`, `schedule_cron` and `enabled` (schemas/vulnmgmt.py:121-131). Pydantic drops them silently. | S |
| VulnMgmt | Edit Scan Profile | `PUT /vulnmgmt/scan-profiles/{id}` (tsx:708) | vulnmgmt.py:521 | same | PARTIAL | `schedule` is ignored; only `name` saves. | S |
| VulnMgmt | Scan profile "Run Now" | `POST /vulnmgmt/vulnerabilities/import-scan` `{scan_profile_id}` (endpoints.ts:675) | vulnmgmt.py:209 | — | BROKEN | `ScanImportRequest.scan_format` is required (schemas/vulnmgmt.py:388), so the call returns 422 and the error is swallowed (tsx:416). There is no scanner integration. The "scheduled scan" task `run_vuln_scan` (exposure/tasks.py:351) stamps `last_scan_date`/`next_scan_date` without scanning (FAKE, and unscheduled). | L |
| VulnMgmt | Patch Operations tab | `GET /vulnmgmt/patch-operations` | vulnmgmt.py:543 | `patch_operations` | BROKEN | Reads `name`, `vulnerability_count`, `total_instances`, `progress_percentage`, `started_at`, `scheduled_date` and `severity` (tsx:77-85, 445-478), none of which exist in `PatchOperationResponse` (schemas/vulnmgmt.py:167-208). The only creator is the broken Remediate flow. | M |
| VulnMgmt | Exceptions table | `GET /vulnmgmt/exceptions` | vulnmgmt.py:772 | `vulnerability_exceptions` | BROKEN | Reads `vulnerability_id`, `reason` and `status`; the model has `vulnerability_instance_id` and `justification` and no status (models.py:352-394). CVE, Reason and Status are blank. | S |
| VulnMgmt | New Exception | `POST /vulnmgmt/exceptions` (tsx:887) | vulnmgmt.py:813 | same | BROKEN | Sends `vulnerability_id`, but the schema field `vulnerability_instance_id` defaults to "" (schemas/vulnmgmt.py:215). That violates the FK to `vulnerability_instances.id` (models.py:358-363), so the insert fails. | M |
| VulnMgmt | Edit Exception | `PUT /vulnmgmt/exceptions/{id}` (tsx:674) | vulnmgmt.py:830 | same | PARTIAL | `reason` is not a schema field and is ignored; only `expiry_date` saves. | S |
| VulnMgmt | Remediate → Apply Patch | `POST /vulnmgmt/patch-operations/create-plan` (tsx:747) | vulnmgmt.py:577 | `vulnerability_instances` | BROKEN | Sends a Vulnerability id as an instance id (tsx:743-746), which returns 404 "No instances found" (vulnmgmt.py:597). It is reachable only from the always-empty KEV tab. | M |
| VulnMgmt | Remediate → Apply Compensating Control | `POST /vulnmgmt/instances/bulk-action` (tsx:757) | vulnmgmt.py:431 | same | BROKEN | Same id confusion; the 404 is swallowed. | M |

### ExposureManagement

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Exposure | Cards "Total Assets" / "Internet-Facing" | `GET /exposure/dashboard` (ExposureManagement.tsx:193) | exposure.py:1431 | `exposure_assets` | PARTIAL | Real counts, but they include deactivated (soft-deleted) assets because there is no `is_active` filter (exposure.py:1440-1460). | S |
| Exposure | Card "Critical Vulns" | same | exposure.py:1469-1472 | `exposure_vulnerabilities` | PARTIAL | Counts catalog rows by severity, not open asset exposures. Remediated items still count. | S |
| Exposure | Card "Overdue Tickets" | same | exposure.py:1475-1484 | `remediation_tickets` | REAL | — | — |
| Exposure | Overall Risk Score | same | exposure.py:1524-1529 | catalog severities ÷ asset count | FAKE | Weighted catalog severities divided by total assets, ignoring status and linkage. With 0 assets, the cap is 10, so one critical CVE scores 100. It never drops on remediation. Renders `\|\| 0` (tsx:421-425). | M |
| Exposure | Mean Time to Remediate | same | exposure.py:1505-1522 | closed tickets | FAKE | The backend honestly returns null. The UI renders `\|\| 0` as "0 days" (tsx:435). Tickets cannot be closed from the UI, so it is effectively always 0. | S |
| Exposure | Pie "Vulnerabilities by Severity" | `GET /exposure/vulnerabilities` (tsx:219) | exposure.py:503 | `exposure_vulnerabilities` | PARTIAL | Page 1 only (50 rows). Colours are assigned by index, not by severity (tsx:459). | S |
| Exposure | Bar "Top 10 Vulnerable Assets" + asset Risk/Vulns columns | assets list, client sort | exposure.py:236 | `exposure_assets.risk_score`/`vulnerability_count` | FAKE | No code ever writes these columns. Only the model defaults exist (exposure/models.py:204-205). The chart and columns are constant zeros. | M |
| Exposure | Area "Exposure Trend (30 days)" | dashboard `exposure_trend` | exposure.py:1550-1567 | `exposure_vulnerabilities.created_at` | PARTIAL | Real daily counts, but of new catalog rows, labelled "exposures". | S |
| Exposure | Assets table + filters | `GET /exposure/assets` (tsx:202) | exposure.py:236 | `exposure_assets` (SIEM discovery, exposure/tasks.py:77-208) | PARTIAL | Filters are honoured. Deactivated rows are listed. The type dropdown values do not match discovered `asset_type="host"`. The Status column reads `asset.status`, which is not in the schema. | S |
| Exposure | Asset "View Details" | `setSelectedAsset` (tsx:617) | — | — | UI-ONLY | `selectedAsset` is declared (tsx:187) and set, but never rendered. | S |
| Exposure | Vulns table + severity multi-select | `GET /exposure/vulnerabilities?severity=a,b` (tsx:221) | exposure.py:503,510 | `exposure_vulnerabilities` | BROKEN | Comma-joined, but the backend takes a repeated `list[str]`, so it gets `["critical,high"]` and returns 0 rows. The Status column is not in the schema. "Affected" shows the `affected_products` length. | S |
| Exposure | Exploit filter | `has_exploit=has_exploit` or `=kev` (tsx:222, 675-676) | exposure.py:512 (`Optional[bool]`) | — | BROKEN | A non-boolean string returns 422, so the table shows an empty state. There is no KEV param. | S |
| Exposure | Import Scan Results | `POST /exposure/scans/import` (tsx:1082) | exposure.py:922 → scan_parser.py:299/441 | `exposure_*` | BROKEN | For every host that is not already an asset, `_get_or_create_asset` builds `ExposureAsset(name=..., is_monitored=True)` (scan_parser.py:376-385). Those columns do not exist, so it raises TypeError and each finding is recorded as an "Ingest error". The UI offers formats the parser does not support (rapid7/custom). It ignores the `errors` array and closes the modal as a success. | M |
| Exposure | Remediation tickets + filters | `GET /exposure/tickets` | exposure.py:1036 | `remediation_tickets` | PARTIAL | Multi-select priority and status are comma-joined against `==` (exposure.py:1053-1057), so they return 0 rows. There is no status-change UI, and the Assets column is always 0. | S |
| Exposure | Remediation quick stats | client | — | loaded rows | PARTIAL | "Closed This Week" has no date filter (tsx:774-776). "Avg SLA" shows "0%" with no tickets. | S |
| Exposure | Create Ticket | `POST /exposure/tickets` | exposure.py:994 | `remediation_tickets` | REAL | Tenancy bug: a user with no org writes the ticket into the first org in the DB (exposure.py:1001-1007). | S |
| Exposure | Attack Surface cards | `GET /exposure/attack-surface` | exposure.py:1215 | `attack_surfaces` (nightly snapshot task, exposure/tasks.py:1131-1146) | BROKEN | `AttackSurfaceResponse` (schemas/exposure.py:374-386) strips the model's `total_assets`, `exposed_assets`, `critical_exposures` and `last_assessed_at`. The UI reads `type`/`total_assets`/... and gets blanks and "Invalid Date". The computed delta (`findings`) is never shown. There is no create UI. | M |
| Exposure | Overall Attack Surface Score | client average (tsx:912) | — | snapshot rows | FAKE | Averages never-scored `risk_score` values (always 0), rendered as a confident 0. | S |
| Exposure | Assess Now | `POST /exposure/attack-surface/assess` (tsx:948) | exposure.py:1284 | assets + asset_vulns | PARTIAL | Real computation. Invalidates the wrong query key (tsx:949), so the UI does not refresh. Run on a snapshot row, it overwrites `metrics`/`last_assessed_at` (exposure.py:1400-1410), which corrupts the next nightly diff baseline (tasks.py:1113-1121). | M |
| Exposure | Compliance framework cards | `GET /exposure/compliance` | exposure.py:1674 | compliance tables | REAL | Real pass %. The unused `total_compliance_checks` falls back to the asset count (exposure.py:1748-1752). | S |
| Exposure | Compliance Trend chart | client (tsx:993) | — | — | FAKE | Plots today's average compliance as a flat line across 30 dates, presented as a history. | S |
| Exposure | Refresh | invalidate queries | — | — | REAL | — | — |

### ContainerSecurity

The page cannot create clusters or images. `POST /container-security/clusters` (:473) and `POST /images` (:118) are never called. The only `ContainerImage(`/`KubernetesCluster(` constructors in `src/` are at container_security.py:125 and :480. So the page shows data only if rows arrive through the API directly.

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Container | Summary cards | `GET /container-security/dashboard/overview` (ContainerSecurity.tsx:77) | container_security.py:934 | container tables | REAL | Org-scoped counts; always 0 in practice (see above). | — |
| Container | Overview lists | images/findings/runtime-alerts lists | container_security.py:80/699/807 | container tables | PARTIAL | Capped at 20/50 with no pagination. | S |
| Container | Images table "Vulnerabilities" column + "Clean" badge | `GET /container-security/images` | container_security.py:80 | `container_images` | FAKE | The UI reads `critical_count`/`high_count`/... (tsx:388, 399-402), but the response has `vulnerability_count_*` (schemas/container_security.py). The total is always 0 and every image shows a green "Clean" (tsx:406), even one with criticals. | S |
| Container | Image "Scanned" date | same | container_security/models.py:48-50 | `scanned_at` | FAKE | NOT NULL with a default of now at insert, so a never-scanned image shows a scan date. | S |
| Container | Image "Rescan" | `POST /images/{id}/scan` (tsx:127) | container_security.py:201 → engine.py:47 | `image_vulnerabilities` | FAKE | No Trivy/Grype. The backend honestly returns `status:"no_scanner_backend"`, but the UI discards it. The handler then sets `compliance_status="compliant"` and a risk score when 0 crit/high (container_security.py:290-307), certifying an unscanned image. The engine copies vulns by repo:tag from **all orgs** (engine.py:66-74). | M |
| Container | Image details modal | local row | — | — | BROKEN | Same `critical_count` mismatch, so the counts are always 0. | S |
| Container | Clusters table | `GET /container-security/clusters` | container_security.py:450 | `kubernetes_clusters` | PARTIAL | Feature badges come from DB booleans with defaults (`rbac_enabled` defaults to True), so "RBAC" shows without observation. Node, pod and namespace counts are never populated. There is no create UI. | M |
| Container | Cluster "Audit" | `POST /clusters/{id}/audit` (tsx:139) | container_security.py:548 → engine.py:296,328 | stored booleans only | FAKE | There is no Kubernetes API call. A "CIS Kubernetes 1.8" % comes from 8 self-attested fields. CIS 1.1.1 (anonymous-auth), 3.1.1 and 4.1.1 are all checked through `rbac_enabled` (engine.py:243-286). Each run re-inserts duplicate findings (container_security.py:581-594). `risk_score = findings*15`. | L |
| Container | Cluster details modal | local row | — | DB | REAL | Stored fields only. | — |
| Container | Findings table | `GET /container-security/findings` | container_security.py:699 | `k8s_security_findings` | REAL | The query is honest, but its only source is the fake audit. | — |
| Container | Finding "Remediate" | `POST /findings/{id}/remediate` (tsx:152) | container_security.py:726 → engine.py:697 | — | FAKE | Builds a generic YAML the UI discards, then sets `status="remediated"` (container_security.py:758) with nothing applied. | M |
| Container | Runtime Alerts tab | `GET /runtime-alerts` | container_security.py:807 | `runtime_alerts` | STUB | No active writer exists. The `container_security/tasks.py:433+` creator is not in Celery `include`, and `monitor_container_runtime` receives no events. The empty state does not say that no sensor exists. | L |
| Container | Search box | client | — | loaded rows | PARTIAL | Only the loaded rows. | S |

### SupplyChainDashboard

No code anywhere in `src/` writes `SoftwareComponent.known_vulnerabilities_count`/`risk_score` or `SBOM.components_count`/`vulnerability_risk_score`/`compliance_status` (except a manual PATCH). There is no OSV or NVD call anywhere.

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| SupplyChain | Data load (4 lists) | SupplyChainDashboard.tsx:114-119 | supplychain.py:483, :933, :831, :624 | 4 tables | PARTIAL | No `size` is sent, so every tab and card sees ≤20 rows. List `total` counts are not org-filtered (:504, :652, :855, :954). The components call swallows errors (tsx:118). | S |
| SupplyChain | Card Total Components | client (tsx:135) | :624 | `software_components` | PARTIAL | Capped at 20. | S |
| SupplyChain | Card Critical Risks | client (tsx:136) | :831 | `supply_chain_risks` | PARTIAL | First page only, and closed risks are included. The sweep only ever emits "high" typosquats, so this is effectively always 0. | S |
| SupplyChain | Card Vendor Score Avg | client (tsx:137-139) | :933 | user-typed `security_score` | PARTIAL | No engine scores vendors (`VendorRiskManager.score_vendor`, engine.py:979, is uncalled). The UI cannot create vendors. Shows "0.0" with no vendors. | M |
| SupplyChain | Card SBOM Compliance % | client (tsx:140-144) | — | `sboms.compliance_status` | FAKE | Nothing computes it; it is only set by manual PATCH, and the Edit modal pre-selects "compliant" (tsx:735). | M |
| SupplyChain | Upload SBOM (SPDX/CycloneDX) | `POST /supplychain/sboms/upload` (tsx:157) | supplychain.py:327 → :155 | sboms, components | PARTIAL | Real parse and persistence with honest errors. However: (1) the purl dedupe has **no org filter** (:199-201), so a tenant's SBOM links another tenant's component, which then appears in its export; (2) `components_count` is never set; (3) dependency edges are dropped; (4) no vulnerability lookup runs afterwards. | M |
| SupplyChain | Generate SBOM | `POST /supplychain/sboms/generate` (tsx:663) | supplychain.py:137 | `sboms` header only | FAKE | Reports success but inserts only a header row (:144-152): no components, no scan, no content. | L |
| SupplyChain | SBOM card "Components" | `sbom.components_count` (tsx:331) | — | never written | BROKEN | Always 0, even after uploading N components. | S |
| SupplyChain | SBOM card compliance score % + bar | `complianceScoreFromSbom` (tsx:33-38) | — | `vulnerability_risk_score` (always 0.0) | FAKE | 100 − 0 means every SBOM shows "100%". | S |
| SupplyChain | SBOM Download | `POST /sboms/{id}/export` (endpoints.ts:723) | supplychain.py:387 | sbom_components | REAL | Real CycloneDX output with an org check. May include another tenant's components (see Upload). | S |
| SupplyChain | SBOM Edit | `PATCH /sboms/{id}` (tsx:718) | supplychain.py:545 | `sboms` | PARTIAL | The compliance select defaults to "compliant" (tsx:735), so a rename silently marks the SBOM compliant. | S |
| SupplyChain | SBOM "View" | `setSelectedSBOM` (tsx:350) | — | — | UI-ONLY | State is never rendered. | S |
| SupplyChain | New Component | `POST /supplychain/components` (tsx:628) | supplychain.py:593 → automation.py:818 | components, alerts, tickets | FAKE | `license` is dropped by the schema. **Every manual add fires `on_supply_chain_vuln` with severity="high" and an empty CVE** (:611-617), creating a HIGH Alert with no `organization_id` (automation.py:827) plus a remediation ticket. | S |
| SupplyChain | Components table Vulns/Risk/Score | list (tsx:435-450) | :624 | never-written columns | FAKE | Always 0 / none / 0.0 as if scanned. There is no OSV/NVD lookup anywhere. | L |
| SupplyChain | Components search | client (tsx:180-183) | — (backend `search` unused) | 20 rows | PARTIAL | — | S |
| SupplyChain | Components Filter button | `setShowFilter` (tsx:407) | — | — | UI-ONLY | State is never read. | S |
| SupplyChain | Components Eye/Edit | `setSelectedComponent` (tsx:453,459) | — | — | UI-ONLY | State is never rendered; PATCH is unused. | S |
| SupplyChain | Supply Chain Risks tab | list (tsx:496-528) | :831; sweep tasks.py:826 (beat celery_app.py:274) | `supply_chain_risks` | PARTIAL | Typosquat risks are a real Levenshtein check against a static popular-package list. The CVE branch (tasks.py:~715-760) needs `known_vulnerabilities_count > 0`, which never happens. The empty state promises CVE risks (tsx:492). There is no triage UI. | M |
| SupplyChain | Vendor Assessments tab | list (tsx:555-611) | :933 | `vendor_assessments` | STUB | Honest rendering, but there is no create/edit UI, so it is always empty. The tier defaults to "medium" in the UI (tsx:565). | M |
| SupplyChain | Vendor "View Full Assessment" | `setSelectedVendor` (tsx:603) | — | — | UI-ONLY | Never rendered. | S |

### ThreatModeling

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| ThreatModel | Models list + pagination | `GET /threat-modeling` (ThreatModeling.tsx:227) | threat_modeling.py:165 | `threat_models` | REAL | — | — |
| ThreatModel | Models list Risk Score column | `m.risk_score` (tsx:555-557) | :165 | `ThreatModel.risk_score` (never written) | FAKE | Always a green "0". | S |
| ThreatModel | New model | `POST /threat-modeling` (tsx:279) | :140 | `threat_models` | REAL | — | — |
| ThreatModel | Delete model | `DELETE /threat-modeling/{id}` (tsx:291) | :270 | `threat_models` | REAL | No RBAC. | S |
| ThreatModel | Detail dashboard cards | `GET /{id}/dashboard` (tsx:237) | :809 | threats, mitigations | BROKEN | The UI reads `open_threats`, `mitigated_threats`, `status` and `methodology` (tsx:632-646), which are not in `ThreatModelDashboard`. Open/Mitigated show 0 and Status shows "- / -". The handler hardcodes `total_models=1` and `models_by_status={}` (:845,:851). | S |
| ThreatModel | Components CRUD | GET/POST/PUT/DELETE `/{id}/components` (tsx:246,367,386,404) | :312, :284, :329, :348 | components | REAL | Org-scoped. Update/delete ignore `model_id` (within tenant). | S |
| ThreatModel | Run STRIDE | `POST /{id}/analyze/stride` (tsx:328) | :642 → engine.py:365 | `identified_threats` | PARTIAL | Deterministic per-component templates from a static catalogue (STRIDE + CWE + MITRE), with likelihood and impact taken from component trust level and data classification. Nothing is random. But each re-run inserts a full duplicate set (:687-691), `component_ids` is ignored, and the UI does not label the rows as catalogue templates. | S |
| ThreatModel | Threats table | `GET /{id}/threats?size=100` (tsx:255) | :420 | threats | BROKEN | Shows `t.title`/`t.severity` (tsx:782,790), which are not in `ThreatResponse`, so every row's Title and Severity are "-". | S |
| ThreatModel | Add Threat | `POST /{id}/threats` (tsx:304) | :363 → automation.py:728 | threats, tickets | BROKEN | `title`/`severity` are discarded. The UI impact options `negligible`/`critical` are not `ImpactLevel` values, so they score as medium (engine.py:410-415). Every threat opens a remediation ticket. | S |
| ThreatModel | Mitigations panel | `GET /{id}/threats/{tid}/mitigations` (tsx:268) | :571 | `threat_mitigations` | STUB | There is no create UI (POST :534 is uncalled), so it always shows "No mitigations". It would also show "-" for effectiveness (`effectiveness` vs `effectiveness_score`). | S |

### RiskQuantification

The coordinator asked whether the Analyze button reaches `/risk-quantification/analyze`. **It does.** The per-row Analyze button (RiskQuantification.tsx:428-433) and "Run Monte Carlo Simulation" (:557-562) call `runMonteCarlo` (:149), which calls `riskquantApi.runAnalysis` (endpoints.ts:1111), which posts to `/risk-quantification/analyze` (risk_quant.py:1033). The UI has no way to create a FAIRAnalysis with real inputs, because `POST /fair-analyses` is never called. So **every** ALE the page ever shows comes from `_default_fair_inputs_from_scenario` (risk_quant.py:1055-1097):
- TEF mode 1/yr; vuln 0.3 (which the engine ignores anyway); TCap and RS 0.3/0.5/0.8;
- primary loss 25% of asset value; secondary loss 10%; SLEF 0.3;
- asset value defaults to $10,000 when 0 or unset, and the UI sends 0 for a blank field (tsx:808).

These defaults are saved as an ordinary `FAIRAnalysis` row (:1166-1179) with no flag. In addition, the PERT sampler is mathematically wrong: `p=(mu-min)/range` and `q=(max-mu)/range` (risk_quant/engine.py:86-87) sum to 1, which gives a U-shaped Beta. The mean is preserved, but p10, p50, p90, p99 and the loss-exceedance curve are distorted. Standard PERT is α = 1+4(mode−min)/range, β = 1+4(max−mode)/range.

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| RiskQuant | Load scenarios | `GET /risk-quantification/scenarios` (endpoints.ts:1088) | risk_quant.py:160 | `risk_scenarios` | PARTIAL | No `size` is sent, so ≤20 scenarios load. | S |
| RiskQuant | Load FAIR analyses | `GET /fair-analyses?size=100` (endpoints.ts:1131) | :309 | `fair_analyses` | PARTIAL | With several analyses per scenario, the oldest wins (tsx:129-131). | S |
| RiskQuant | Scenario "Probability" column | `probability = confidence_level` (tsx:97) | — | analyst confidence | FAKE | The analyst's confidence (default 0.5) is displayed as event probability. | S |
| RiskQuant | Scenario "Impact" column | `impact = asset_value_usd` (tsx:98) | — | user input | PARTIAL | Asset value is shown as impact, which is not FAIR loss magnitude. | S |
| RiskQuant | Scenario "ALE" column | `fair?.ale_mean ?? probability*impact*0.3` (tsx:99) | — | invented | FAKE | Without an analysis: confidence × asset value × 0.3, shown as dollars. With one: the defaults-driven simulation. | S |
| RiskQuant | Risk Score badge | `computeRiskScore` (tsx:61-72) | — | formula | FAKE | Confidence × value tier (1, 0.7 or 0.4) × 100, or ALE/asset value. Both are invented scales labelled Critical/High. | S |
| RiskQuant | Per-row Analyze | `POST /analyze` (tsx:429 → endpoints.ts:1111) | risk_quant.py:1033 → :1055 → engine.py:245 | invented PERT inputs saved as `fair_analyses` | FAKE | See above. If a scenario has 2 analyses, `scalar_one_or_none` returns a 500 (:1154). | M |
| RiskQuant | Run Monte Carlo Simulation + banner | same with all ids (tsx:557, 163-167) | :1033; portfolio VaR engine.py:467 | as above | FAKE | Same invented inputs. The banner errors are honest. | M |
| RiskQuant | Card Risk Scenarios | `scenarios.length` | :160 | scenarios | PARTIAL | Capped at 20. | S |
| RiskQuant | Cards Avg Risk Score / High Risk Items | client (tsx:190-193) | — | invented scores | FAKE | Built on `computeRiskScore`. | S |
| RiskQuant | Card Total Controls | `dashboard?.number_of_controls ?? ...` (tsx:199) | :930 | none | UI-ONLY | No such field exists, and scenarios have no `controls`, so it is always 0. | S |
| RiskQuant | Dashboard fetch | `GET /dashboard` (endpoints.ts:1124) | :930 | `risk_registers` | UI-ONLY | The UI cannot create registers, so the response is always zeros. `totalAleAggregate` (tsx:197) is never rendered. | S |
| RiskQuant | Loss-exceedance fetch | `GET /loss-exceedance` (endpoints.ts:1119) | :1213 | `fair_analyses` | UI-ONLY | The portfolio curve is computed but never charted; it only reaches the Export JSON. | S |
| RiskQuant | Analysis tab: Risk Distribution | client (tsx:457-476) | — | invented scores | FAKE | — | S |
| RiskQuant | Analysis tab: Loss Exceedance panel | client (tsx:484-512) | — | `fair_analyses` | FAKE | Sums percentiles across scenarios (statistically invalid). A missing p10 becomes `p50/2`, and `/analyze` never returns p10. The p10/p90 labels are inverted. | S |
| RiskQuant | Analysis tab: Aggregate Exposure | client (tsx:515-541) | — | mixed | FAKE | Includes the invented ALEs. "Max Single Loss" is really the largest asset value. | S |
| RiskQuant | Export / Export Analysis | client Blob (tsx:240-248, 565-574) | — | client state | PARTIAL | Exports the invented probability, ALE and score fields as data. | S |
| RiskQuant | Risk Register tab | client filter (tsx:218) | — (backend `/risk-registers` :502 unused) | — | UI-ONLY | Not the backend register. Its buttons set unused state. | M |
| RiskQuant | Controls tab | client (tsx:221-227) | — (backend `/controls` :638 unused) | — | UI-ONLY | Always empty. A full backend CRUD plus ROI exists but is not wired. | M |
| RiskQuant | New Scenario | `POST /scenarios` (tsx:803) | :214 → automation.py:754 | scenarios, incidents | PARTIAL | The create is real. An asset value ≥ $100k opens an Incident claiming "loss expectancy of $X", where X is the asset value (:248-252), with no `organization_id` (automation.py:763). | S |
| RiskQuant | Search / Filter / Eye / Edit | client and dead state (tsx:349, 413-426, 598) | — | — | UI-ONLY | Filter state is never read, and the selected-item state is never rendered. | S |

### ZeroTrustDashboard

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| ZeroTrust | Maturity banner + pillar counts | `GET /zerotrust/dashboard` (ZeroTrustDashboard.tsx:142) | zerotrust.py:1078 → engine.py:1277 | DB counts + hardcoded baselines | FAKE | Free base points with nothing configured: identity 20 (engine.py:1339), networks 10 (1377), apps 15 (1397), data 10 (1417), visibility 10 (1465), automation 10 (1518). The visibility and automation counts use `DetectionRule`/`LogEntry`/`Playbook` **with no org filter** (1435-1446, 1481-1485), so a new tenant is credited with other tenants' assets. | M |
| ZeroTrust | Pillar cards | same | engine.py:1288-1296 | same | FAKE | Same baselines. The status is `>=70 ? healthy : at-risk` client-side (tsx:390). | M |
| ZeroTrust | "Access Decisions (24h)" | dashboard (tsx:487-511) | zerotrust.py:1134-1169 | `AccessDecision` | PARTIAL | Counts all time; there is no 24h filter. | S |
| ZeroTrust | Overview "Recent Access Decisions" | none | — | — | UI-ONLY | `OverviewTab` never receives `recentDecisions` (tsx:323-326), so it always shows empty. | S |
| ZeroTrust | Real-Time Access Evaluation form | `POST /zerotrust/evaluate-access` (tsx:238) | zerotrust.py:156 → :58 → engine.py:75 | PDP over DB policies | BROKEN (dangerous) | The handler injects the **analyst's own JWT jti** as `session_id` (zerotrust.py:80-98). With no matching policy the default is `deny` (engine.py:127-128). `invalidate_session_cache(jti,"deny")` (engine.py:241-245) writes `zt:session:<jti>=deny` with `CACHE_TTL_DENY=86400` (session_gate.py:67,111), and `ZeroTrustSessionMiddleware` (main.py:372) then returns 403 on every later request. **One "what-if" test on a fresh org locks the analyst out for 24h.** A deny also fires real violation automation (zerotrust.py:123-133). Risk baselines are 20/30 with no IdP/UEBA input. | M |
| ZeroTrust | Access decisions table | `GET /zerotrust/decisions?size=50` (tsx:177) | zerotrust.py:213 | `AccessDecision` | BROKEN | The UI reads `subject_id`/`resource_id`/`reason`; the backend returns `subject`/`resource` and no reason (251-260), so rows show the literal fallbacks "user" and "resource". `size` is ignored (the backend uses `limit`, default 20). | S |
| ZeroTrust | Decision filter | none | `decision_filter` (zerotrust.py:219) unused | — | UI-ONLY | Filter state is never applied. | S |
| ZeroTrust | Device stat cards | `GET /zerotrust/device-stats` (tsx:152) | zerotrust.py:489 | `DeviceTrustProfile` | PARTIAL | Real counts. Agent-created profiles stay `trust_level="unknown"` (engine.py:784), so they count in Total but in no bucket. | S |
| ZeroTrust | Device cards (compliant, checks, last seen) | `GET /zerotrust/devices` (tsx:162) | zerotrust.py:598 | `DeviceTrustProfile` | FAKE | The response has no `is_compliant`/`compliance_checks`/`os_type` (634-644), so **every device renders red "Non-Compliant" with all 4 checks failed**, a fabricated negative posture. `last_seen_at` is never written, so "Invalid Date". Capped at 20. | M |
| ZeroTrust | Device "View Details" | `GET /zerotrust/devices/${id}` (tsx:961) | zerotrust.py:674 | `DeviceTrustProfile` | BROKEN | The UI passes the PK; the handler filters on `device_id` (685), so 404. Once fixed, it would crash rendering the `compliance_status` dict. | S |
| ZeroTrust | "Assess All Devices" | `POST /zerotrust/assess-devices` (tsx:212) | zerotrust.py:553 → engine.py:666 | stored posture | PARTIAL | Recomputes from stored posture only; there is no MDM/EDR pull. `failed` counts are not shown. | S |
| ZeroTrust | Per-device "Re-assess" | `POST /assess-devices {device_ids:[id]}` (tsx:974) | engine.py:680-698 | DB | FAKE | The PK vs `device_id` mismatch means the assessor **creates a phantom blocked device** (engine.py:692-698), then the UI shows "Re-assessed". | S |
| ZeroTrust | Device posture source | agent heartbeat | agents.py:577-591 → engine.py:758 | agent telemetry | PARTIAL | `certificate_valid: True` and `jailbroken: False` are hardcoded (agents.py:588-589), adding 10 unearned points to every score. | S |
| ZeroTrust | Micro-segment cards | `GET /zerotrust/segments` (tsx:192) | zerotrust.py:756 | `MicroSegment` | BROKEN | The UI reads `type`/`status`/`member_count`; the response has `segment_type`/`member_assets` and no status. `violation_count` is never incremented. | S |
| ZeroTrust | Create Segment | `POST /zerotrust/segments` (tsx:1066) | zerotrust.py:737 | DB | REAL | Persists, and errors surface. Nothing ever evaluates traffic against segments. | S |
| ZeroTrust | Policies table | `GET /zerotrust/policies` (tsx:203) | zerotrust.py:309 | `ZeroTrustPolicy` | BROKEN | The UI reads `type`/`mfa_required`/`device_trust_required`/`decision_count`/`status`; the schema has `policy_type`/`requires_mfa`/`requires_device_trust`/`hit_count`. The default `enabled_only=True` hides disabled policies, while `total` still counts them. | S |
| ZeroTrust | Create Policy | `POST /zerotrust/policies` (tsx:1210) | zerotrust.py:270 | DB | PARTIAL | Always saves `conditions:[]` and `actions:[]` (tsx:1218-1219), so every match falls through to deny (engine.py:191-201). The promised editor does not exist. | M |

### APISecurityDashboard

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| APISec | Summary cards | `/api-security/endpoints`, `/vulnerabilities`, `/anomalies` (endpoints.ts:1336-1357) | api_security.py:89, 237, 532 | DB | PARTIAL | Page-1 lengths, not `total` (APISecurityDashboard.tsx:58-64). "OWASP Violations" includes remediated vulns. `/dashboard` is unused. | S |
| APISec | Inventory table + scatter "API Risk by Endpoints" | `GET /api-security/endpoints` | api_security.py:89 | `APIEndpointInventory` | FAKE | There is no `risk_score` in the schema, so it is always 0 (tsx:42). `endpoints` falls back to the constant 1 (tsx:37). Every API plots at (1,0) with a green 0. `engine.calculate_risk_score` (engine.py:1016) is never persisted. | M |
| APISec | Public/Private filter | client | — | 20 rows | PARTIAL | — | S |
| APISec | Register API | `POST /api-security/endpoints` (tsx:585) | api_security.py:157 | DB | PARTIAL | Name and Type are discarded (tsx:586-589). Errors only go to the console. Success triggers a full page reload. | S |
| APISec | Severity Risk Trend | `GET /api-security/dashboard/risk-trend` (endpoints.ts:1373) | api_security.py:939 | `APIVulnerability` | REAL | Org-scoped with an honest empty state. | — |
| APISec | Vulnerability cards | `GET /api-security/vulnerabilities` | api_security.py:237 | `APIVulnerability` | BROKEN | The UI reads `category`/`api`/`count`; the backend has `vulnerability_type`/`endpoint_id`. The case-sensitive severity and status compares never match. The title is blank. | S |
| APISec | Policies table | `GET /api-security/policies` | api_security.py:399 | `APISecurityPolicy` | BROKEN | Reads `apis`/`enforced`/`lastUpdated`, which do not exist, so it shows "undefined/N" and always "Pending". Policies are never enforced (`APIPolicyEnforcer` is never invoked). | M |
| APISec | Anomalies tab + trend | `GET /api-security/anomalies` | api_security.py:532 | `APIAnomalyDetection` | BROKEN | Field mismatch (`type` vs `anomaly_type`, etc.); the trend buckets everything under "Unknown". No detector ever runs; rows only come from manual POST. | M |
| APISec | Compliance tab (OWASP chart, Pass Rate) | client from vulns (tsx:78-103, 541-562) | — | — | FAKE | Reads `owasp_category`, which does not exist, so the buckets are 0 and the Pass Rate shows a confident "0.0%". The backend types are OWASP-2019 slugs and can never match the "A01..A10" labels. The real `/compliance-checks` data is never fetched. | M |
| APISec | Detail modal | state | — | — | PARTIAL | Shows `method` labelled as "Type", risk 0, endpoints 1. | S |

### OTSecurityDashboard

**Prefix verdict.** The UI uses `/ot_security` (underscore) exclusively (endpoints.ts:1151-1170). The only "ot-security" strings in the frontend are the SPA route (App.tsx:200, Layout.tsx:141) and the export filename. On the dash side, the list and purdue-map aliases (aliases.py:783, 801, 819, 837) are dead duplicates. The dash `/discover` (aliases.py:975) and `/export` (aliases.py:1104) have **no underscore equivalent**. The page should call them, or they should be moved under `/ot_security`.

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| OT | Data load | `Promise.all` of 4 calls (OTSecurityDashboard.tsx:95-100) | ot_security.py:150, 391, 565, 1098 | DB | BROKEN (fragile) | One failure blanks everything, and the error only goes to the console (tsx:106-107). The working dash discovery inserts `asset_type="unknown"` (engine.py:229), which fails `OTAssetResponse` enum validation (verified), so after one discovery `/ot_security/assets` returns 500 and the whole page shows "No data". | S |
| OT | Summary cards | same | same | DB | PARTIAL | Page-1 lengths. `is_online` is only ever set True, by discovery; nothing marks an asset offline. `/ot_security/dashboard` is unused. | S |
| OT | Asset Types / Protocols breakdown | client | — | 20 rows | PARTIAL | — | S |
| OT | Firmware Status (Up to Date / Update Needed / Known Vulns) | client (tsx:266-280) | — | never-written fields | FAKE | Nothing writes `firmware_current`/`known_vulnerabilities_count`/`risk_score`. The default False makes every asset "Update Needed", which presents unknown firmware as outdated. | M |
| OT | Asset table + search | `/ot_security/assets` | ot_security.py:150 | `OTAsset` | PARTIAL | Client search over 20 rows. The backend filters are unused. Status comes from the never-maintained `is_online`. | S |
| OT | Asset detail drawer | row state | — | row | PARTIAL | Shows "Risk Score 0", "Firmware Current No" and "Known Vulns 0" from defaults. | S |
| OT | Alerts cards + table + drawer | `/ot_security/alerts` | ot_security.py:391 | `OTAlert` | STUB | Shape matches. There is no passive sensor (Modbus/DNP3 DPI), and the `OTMonitor.detect_*` methods are never invoked; rows come only from manual POST. No actions are exposed. Capped at 20. | M |
| OT | Zone cards | `/ot_security/zones` | ot_security.py:565 | `OTZone` | FAKE | `assets_count` is never updated and `compliance_status` is never set. The "Verified" badge comes from `/segmentation_audit`, which sets `segmentation_verified=True` with no audit (ot_security.py:684-698). | M |
| OT | Purdue Model tab | `/ot_security/purdue-map` | ot_security.py:1098 | `OTAsset.purdue_level` | PARTIAL | Real grouping of user-entered levels. Unknown or null levels are silently placed at L3 (:1110), L3.5 is collapsed into L3, and L5 is labelled "DMZ / Cloud" in the UI vs `level5_internet`. `segmentation_complete` = "≥4 levels populated" (:1136), which is not a segmentation check. | S |
| OT | Export Report button | client Blob (tsx:152) | — (server `/ot-security/export`, aliases.py:1104, unused) | browser state | FAKE | Dumps the truncated 20-row page state plus client KPIs as "ot-security-report.json". The real, complete server export is never called. | S |
| OT | Create asset / zone / alert / discover | none | — | — | UI-ONLY gap | No create or discover UI exists, so data can only arrive through the API. | M |

---

## 2. Backend routes in these domains that the UI never calls

Verdicts: **expose** = a real capability that should be wired into the UI. **fix+expose** = real, but has a defect to fix first. **dead** = a duplicate or useless route. **fake** = success without work, or fabricated output. **broken** = crashes or cannot be reached.

### vulnmgmt

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| GET /instances, GET /instances/{id}, PUT /instances/{id} | vulnmgmt.py:315 / 397 / 410 | Instance list/get/update | expose | The `severity` param is accepted but never applied (:322). |
| POST /instances | vulnmgmt.py:380 | Create instance | expose (critical) | **The only creator of VulnerabilityInstance in the repo.** Without it, SLA, patch, exception, KEV-compliance and the risk matrix all run on an empty table. |
| GET /report/executive | :932 | Instance aggregates | fix+expose | MTTR uses first_seen→last_seen (not remediation) and returns 0.0 with no data. |
| GET /report/kev-compliance | :946 | "BOD 22-01 report" | fake | Not KEV-filtered (engine.py:1068); 100% compliant with no instances (engine.py:1007). |
| GET /vulnerabilities/{id} | :179 | Get | dead | The UI uses the loaded row. |
| POST /patch-operations/{id}/schedule | :609 | Schedules and queues an agent command | fake | The dispatched command is literally `echo '[pysoar] patch operation ... scheduled'` (:689-692). Instance and Asset lookups are not org-filtered (:651-660). |
| POST /patch-operations/{id}/verify, /rollback | :719 / :744 | Status flips from the caller's boolean or reason | expose as record-keeping, labelled honestly | No verification or rollback is performed. |
| POST /vulnerabilities/sync-kev | :284 | Upserts from a client-posted KEV JSON | fix+expose | Creates a Vulnerability for every KEV CVE (~1,400) in the tenant, which inflates counts. It should fetch the feed server-side and only flag existing CVEs. |

### exposure

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| POST /assets, GET/PUT /assets/{id}, DELETE /assets/{id} | exposure.py:197 / 307 / 318 / 339 | CRUD | expose | Delete is a soft-deactivate, but the list and dashboard ignore `is_active`. |
| GET /assets/{id}/vulnerabilities | :420 | Asset vulns | expose | The `severity` param is ignored. |
| POST /assets/discover | :351 | Inserts a scan with `status="running"` and returns zeros | fake | Never dispatches discovery; the scan stays "running" forever. |
| POST /assets/import | :381 | "Bulk import" | fake | Iterates `import_data.assets`, which the schema does not have (schemas/exposure.py:477-481), so it always imports 0 and returns success. |
| POST/PUT/GET/DELETE /vulnerabilities[/{id}] | :468 / 614 / 603 / 634 | CRUD | expose | Delete has no cascade for the asset_vulns FK. |
| GET /vulnerabilities/kev | :564 | "KEV" list | broken | `v.cvss_score` does not exist (the model has `cvss_v3_score`), so it returns 500 once any row matches. Nothing sets `is_exploited_in_wild` from a feed. |
| POST /vulnerabilities/search | :650 | Advanced search | broken | Checks `has_exploit`, but the schema field is `has_exploits`. Most filters are ignored. |
| POST /asset-vulns, PUT /asset-vulns/{id}, POST /asset-vulns/{id}/remediate, GET /asset-vulns/prioritized | :705 / 732 / 752 / 773 | Asset↔vuln links | fix+expose | Create does not validate the org on `asset_id`/`vulnerability_id` (cross-tenant link). Remediate is a status flip with no rescan. |
| POST /scans, GET /scans, GET /scans/{id}, POST /scans/{id}/cancel | :817 / 843 / 889 / 900 | Scan records | GET: expose (import history and errors); POST and cancel: fake | POST inserts a `pending` row that the `import_scanner_results` task later flips to "completed" without doing anything (exposure/tasks.py:442-494). |
| GET /tickets/{id}, PUT /tickets/{id}, POST /tickets/{id}/verify | :1091 / 1102 / 1122 | Ticket detail, update, close | expose (PUT is critical: tickets cannot be closed otherwise) | `verify` performs no verification; label it honestly. |
| GET /tickets/overdue | :1151 | Overdue list | broken / dead | Declared after `/tickets/{ticket_id}` (:1091), so "overdue" is captured as an id and returns 404. It duplicates `?overdue_only=true`. |
| POST /attack-surface, GET/PUT /attack-surface/{id} | :1193 / 1253 / 1264 | Define and get surfaces | fix+expose | Same schema field-stripping bug as the list. |
| GET /risk-matrix | :1612 | Criticality × severity grid | expose | Real data with no UI. |
| POST /report | :1764 | Exposure report | broken | References `RemediationTicket.completed_at` and `ExposureAsset.name`, which do not exist, so it returns 500 on every call. |

### container-security

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| POST /clusters, POST /images | container_security.py:473 / 118 | Create | expose (required for the page to ever show data) | Image create requires a ≥64-character digest. |
| PATCH /clusters/{id} | :519 | Sets the security booleans | expose, labelled "self-attested" | This is the only input to the "audit". |
| PATCH /images/{id}, /findings/{id}, /runtime-alerts/{id} | :168 / 771 / 834 | Updates | expose | — |
| GET /clusters/{id}, GET /images/{id} | :497 / 146 | Get | dead | Modals use the loaded row. |
| GET /clusters/{id}/findings, GET /images/{id}/vulnerabilities | :654 / 335 | Child lists | expose | Real queries, but nothing populates the data. |
| GET /clusters/{id}/compliance-check | :619 → engine.py:802 | "NSA/CISA, DoD STIG, SOC 2" | fake | Framework scores come from 4-5 stored booleans. It is a GET that also writes. |
| GET /images/{id}/risk-assessment | :405 | Risk summary | broken | Subtracting the naive `utcnow()` from the tz-aware `scanned_at` raises TypeError (500). |
| POST /images/{id}/verify-signature | :369 → engine.py:146 | "cosign verify" | broken + fake | Wrong signature in the call (TypeError). Even if fixed, it echoes DB booleans and fabricates a `key_id` from a digest hash (engine.py:152-161). |
| POST /runtime-alerts/{id}/investigate | :865 | Status flip | expose | — |
| POST /runtime-alerts/{id}/quarantine-pod | :897 → engine.py:583 | Returns "quarantined" plus a NetworkPolicy dict | fake | Never applied (no K8s client). The alert is marked `contained` (:924). |
| GET /container-security/alerts | aliases.py:755 | Duplicate of runtime-alerts | dead | — |

### supplychain

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| POST /vendors, PATCH /vendors/{id}, GET /vendors/{id} | supplychain.py:915 / 989 / 974 | Vendor CRUD | expose (critical) | The Vendor tab can never show data without these. The score is free-typed. |
| POST /risks, GET/PATCH /risks/{id} | :813 / 875 / 890 | Risk CRUD and triage | expose | `component_id` on create is not checked against the org. |
| GET/PATCH /components/{id} | :672 / 687 | Detail and edit | expose | Would back the dead Eye/Edit buttons. |
| GET /components/{id}/dependency-tree | :709 | Recursive walk | broken / dead | A lazy relationship in async code raises MissingGreenlet. Imports never set parents. |
| GET /components/{id}/vulnerabilities | :736 | CVEs from risks with `risk_type=="known_vulnerability"` | dead | Nothing writes that `risk_type`. |
| GET /sboms/{id} | :530 | Detail | expose | — |
| POST /sboms/import | :294 | Paste-in import | expose, or drop as a duplicate of upload | Real parse. |
| POST /sboms/compare | :567 | Compare two SBOMs | fake | Always returns empty added/removed/updated lists (:583-585). |
| POST /compliance/validate-sbom | :1014 | NTIA check | broken | Declares `sbom_id = Path(...)` with no path segment, so it always returns 422. |
| GET /compliance/license-audit | :1039 | GPL vs proprietary conflicts | expose | Real but crude. |
| GET /dashboard/overview | :1121 | Org-scoped counts | expose | Would fix the 20-row cards. Vuln and risk fields are always 0. |
| GET /dashboard/top-risky-components, /dashboard/vendor-scores | :1209 / 1252 | Sort by risk; vendor list | dead | Sorts by an always-0 column. The vendor-scores route relabels a security score as risk. |
| GET /vendor-assessments | aliases.py:896 | Duplicate of /vendors | dead | — |
| task `vulnerability_cross_reference` | supplychain/tasks.py:176 | "Checks NVD, OSV, GitHub" | fake (unreferenced) | Emits fabricated `RISK-xxxxxxxx` "CVE" ids, uses `risk_type` as the severity, and claims databases it never queries (tasks.py:146-208). |

### threat-modeling

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| POST /{id}/threats/{tid}/mitigations, PUT .../mitigations/{mid} | threat_modeling.py:534 / 609 | Mitigation CRUD | expose (critical) | The mitigations panel is otherwise always empty. |
| GET/PUT /{id}, PUT/GET/DELETE /{id}/threats/{tid} | :241 / 252 / 487 / 475 / 514 | Model and threat CRUD | expose | Needed to clean up duplicate STRIDE runs and change status. |
| POST /{id}/validate | :744 | Completeness and coverage report | expose | Real logic. |
| GET /{id}/mitigations/recommendations/{tid} | :783 | Static recommendation catalogue | expose, labelled as a catalogue | Hardcoded `cost_estimate` values ($10k-$25k) drive the priority. Covers 4 of the 6 STRIDE categories. |
| POST /{id}/analyze/pasta | :703 | Runs PASTA, then discards the result | fake | Returns `stages_completed` only, and stage 1 is always non-empty. |
| GET /models | :224 (and aliases.py:348) | Alias of the list | dead | — |

### risk-quantification

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| POST /fair-analyses | risk_quant.py:347 | Create from user PERT inputs | fix+expose (critical: the only honest input path) | Queues `run_fair_simulation`, which is **not registered** with the worker, before commit. That task also swaps falsy inputs for hardcoded ones (risk_quant/tasks.py:58-74). |
| POST /fair-analyses/{id}/run-simulation, GET /fair-analyses/{id}, GET /fair-analyses/{id}/loss-exceedance-curve | :414 / 401 / 478 | Synchronous simulation and detail | fix+expose | PERT math bug (engine.py:86-94); stored `vuln_*`/`lm_*` values are ignored. |
| CRUD /risk-registers, /controls, /bias, plus PATCH/DELETE /scenarios/{id}, GET /scenarios/{id} | :502-623, :638-747, :802-915, :259-294 | Register, controls, BIA and scenario CRUD | expose | Real CRUD. The register ALE is typed in rather than linked to FAIR. `create_risk_control` does not check the org on `risk_register_id` (:693). |
| POST /controls/{id}/audit | :761 | Control ROI | fix+expose | An `inf` payback breaks JSON (500). It marks the control "tested" with no test. |
| GET /heatmap | :993 | 5×5 matrix | fake as written | Likelihood = `inherent_risk_score/100` and impact = ALE/$1M (:1009-1015). |
| GET /analysis | aliases.py:282 | Duplicate of /fair-analyses | dead | — |

### zerotrust

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| GET/PUT/DELETE /policies/{id} | zerotrust.py:349 / 375 / 415 | Policy CRUD | expose (PUT is the missing policy editor) | — |
| POST /policies/{id}/test | :442 | Runs the PDP | fix+expose | A "test" persists a real AccessDecision and increments `hit_count`. It can also trigger the session lockout. |
| POST /evaluate | :58 | Canonical route behind the `/evaluate-access` alias | keep, fix | Same jti lockout bug. |
| POST /continuous-eval/{session_id} | :167 → engine.py:255 | Re-scores a session | dead / tenancy bug | Looks up the session with no org filter (engine.py:267-272). |
| GET/PUT/DELETE /segments/{id}, GET /segments/{id}/violations, GET /topology | :792 / 818 / 858 / 906 / 921 | Segment CRUD, violations, topology | expose | Real. |
| POST /segments/{id}/evaluate-traffic | :885 → engine.py:904 | CIDR/port check | fix+expose | Ignores `segment_id`; defaults to "allowed". |
| GET /devices/non-compliant | :649 | trust < 70 | expose | — |
| POST /devices/{id}/assess | :700 | Rescore | fix+expose | Creates a phantom device for an unknown id. |
| PUT /devices/{id}/compliance | :715 | Sets posture flags | restrict (agent/admin only) | Any user can mark any device fully compliant, defeating the PDP device check. |
| POST /verify, GET /verifications | :938 / 975 | Pending verification rows | dead | Nothing ever completes a verification. |
| POST /step-up/{session_id} | :961 | Returns `challenge_{session_id}` | fake | No challenge is issued. |
| GET /maturity, /maturity/pillars, /recommendations | :1022 / 1042 / 1056 | Same scorer as the dashboard | fake as-is | Baseline points plus cross-tenant counts. |

### api-security

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| GET/PUT/DELETE /endpoints/{id} | api_security.py:174 / 185 / 204 | Endpoint CRUD | expose | — |
| POST /vulnerabilities, GET/PUT /vulnerabilities/{id} | :296 / 326 / 337 | Manual findings and triage | expose | `endpoint_id` ownership is not checked. |
| POST /vulnerabilities/bulk-update | :356 | Bulk status update | fix+expose | **No org filter: cross-tenant write** (:363-364). |
| POST /policies, GET/PUT/DELETE /policies/{id} | :452 / 469 / 480 / 499 | Policy CRUD | expose | `name` is globally unique (models.py:200), so tenants collide. Policies are never enforced. |
| POST /anomalies, GET/PUT /anomalies/{id} | :591 / 608 / 619 | Anomaly CRUD | expose PUT only | A manual POST is not detection. |
| GET/POST /compliance-checks, GET/PUT /compliance-checks/{id} | :659 / 715 / 732 / 743 | Compliance-check CRUD | expose (the real source for the Compliance tab) | — |
| GET /dashboard | :767 | Org-scoped counts | expose | `policy_violations` is actually the policy count. |
| POST /scan/discover | :1004 | Traffic-log discovery | fake | In-memory only; returns hardcoded zeros and "scan_queued". OpenAPI discovery (engine.py:115) is never called. |
| POST /scan/security/{id} | :1026 | Config heuristics | fix+expose | The task loads the endpoint with no org filter (tasks.py:125-127), so a scan can target another tenant's endpoint. |
| POST /scan/compliance/{id} | :1046 | 6 checks including a live HTTP GET | fix+expose | **SSRF**: server-side GET to a user-supplied base_url (tasks.py:400-443). No org check. |
| POST /scan/shadows | :1057 | Persists shadow APIs from posted logs | fix+expose | Duplicates rows on every call. |
| GET /reports/compliance | :1078 | Report | fake + tenancy | No org filter. Per-type pass/fail is hardcoded 0 (:1113-1114). |

### ot_security (underscore) and ot-security (dash aliases)

| route | handler | what it does | verdict | notes |
|---|---|---|---|---|
| POST /assets, GET/PUT/DELETE /assets/{id} | ot_security.py:205 / 236 / 243 / 263 | Asset CRUD | expose (the page has no create) | — |
| POST /assets/{id}/discover | :271 | Intended to TCP-probe | broken + IDOR | Signature mismatch with `discover_assets(network_range)` (engine.py:124), so it always returns "awaiting_network_scanner". The `org_id` query parameter overrides the caller's org (:276,:289). |
| GET /assets/{id}/status | :335 | Echo of stored fields | dead | The fields are never computed. |
| GET /assets/{id}/risk_assessment, POST /assets/{id}/firmware_check, GET /risk_assessment | :351 / 372 / 1181 | CVE and risk scoring | fake | Uses the hardcoded 2-entry `_load_ics_cves` "(simulated)" dict (engine.py:1206-1223). CVE-2021-22911 is labelled Siemens S7-1200, but it is a Rocket.Chat CVE. An empty vendor string matches every entry. A null vendor or model is swallowed by the except (engine.py:1252). Risk never goes below "medium". `ot_security/tasks.py:29` imports the same assessor, but that module is not in Celery `include`. |
| POST /alerts, GET/PUT /alerts/{id}, POST /alerts/{id}/investigate | :437 / 478 / 485 / 505 | Manual alerts and triage | expose | `asset_id` is not validated. |
| POST /alerts/{id}/respond | :517 | Stores free text and sets status "contained" | fake if labelled "respond" | No action is executed. It is org-scoped (`get_alert_or_404` :87-99 applies the org filter when the org is not None), but there is **no RBAC**. |
| POST /alerts/bulk_action | :535 | Resolve or dismiss | broken (tenancy) | `select(OTAlert).where(OTAlert.id.in_(alert_ids))` with **no org filter** (:543-545): a cross-tenant write. Unknown actions report success. |
| POST /zones, GET/PUT/DELETE /zones/{id}, GET /zones/{id}/communication_matrix | :599 / 623 / 630 / 650 / 669 | Zone CRUD and matrix | expose | The matrix is configuration, not observed traffic. |
| POST /zones/{id}/compliance_check | :658 → engine.py:844 | Purdue coverage | PARTIAL; fix+expose | Does not persist the result. |
| POST /zones/{id}/segmentation_audit | :684 | Sets `segmentation_verified=True` | fake | No audit is performed, yet it drives the "Verified" badge. |
| GET/POST /incidents, GET/PUT /incidents/{id}, POST /incidents/{id}/containment_strategy | :704 / 746 / 770 / 777 / 797 | Incident CRUD and strategy | expose | — |
| POST /incidents/{id}/safe_shutdown | :814 → engine.py:1048-1116 | Returns a fixed 5-step template with status "initiated" and persists `safe_shutdown_initiated=True` | **fake (safety-critical)** | No PLC, SIS or OT command is sent. It is org-scoped via `get_incident_or_404`, but **any authenticated user can trigger it (no RBAC)**, and the record falsely claims a shutdown was initiated. |
| GET /incidents/{id}/post_incident | :832 → engine.py:1159 | Post-incident report | fake | Hardcoded "Safety systems verified" / "Physical impact assessment completed". |
| Policies CRUD, enable/disable, violation_history | :848-967 | OT policy CRUD | expose CRUD | Enforcement is name-only; nothing evaluates OT policies. |
| GET /dashboard | :988 | Counts | expose | `compliance_scores.overall` depends on never-set fields, so it is always 0. |
| GET /compliance/report | :1148 → engine.py:1429-1601 | NERC-CIP / IEC 62443 / NIST 800-82 | fake | CIP-007 is always credited (engine.py:1463-1465, "placeholder"). NIST `secure_design`/`operational_controls` are hardcoded True (1565-1569). The IEC SL target is presented as achieved. `validate_all_communications` returns [] (engine.py:896-898, "placeholder for integration"). |
| GET /ot-security/assets, /alerts, /zones | aliases.py:783 / 801 / 819 | `_safe_list` duplicates | dead | Unscoped when the org is None (aliases.py:57). |
| GET /ot-security/purdue-map | aliases.py:837 | Purdue grouping | dead + broken | `int(lvl)` on "level3_operations" raises, and the error is swallowed into an empty map. |
| POST /ot-security/discover | aliases.py:975 | **Real TCP-connect sweep** of a ≤/22 on OT ports, upserting OTAsset rows | expose after fixes | It is the only working discovery and has no underscore twin. Fix first: (1) enum-invalid `asset_type`/`protocol="unknown"` breaks `/ot_security/assets` with a 500; (2) the global `OT_PROBE_PORTS` mutation races between requests; (3) it needs RBAC, because any user can sweep internal ranges from the API host. It is active scanning, not passive OT discovery. |
| GET /ot-security/export | aliases.py:1104 | Real JSON/CSV export | expose (replace the client Blob) | Falls back to all tenants when the org is None (:1127-1139). |

---

## 3. Tenancy and RBAC gaps (consolidated)

**Cross-tenant reads and writes:**
- container_security/engine.py:66-74: the image "scan" copies ImageVulnerability rows from any org with the same repo:tag.
- supplychain.py:199-201: SBOM component dedupe by purl has no org filter, so another tenant's components appear in this tenant's exports.
- ot_security.py:543-545: `alerts/bulk_action` has no org filter (write).
- api_security.py:363-364: `vulnerabilities/bulk-update` has no org filter (write).
- api_security.py:1085-1107: `/reports/compliance` is unscoped.
- api_security/tasks.py:125-127 and 234-236: endpoint lookup by id only, so scans and HTTP probes can target another org's endpoint.
- zerotrust/engine.py:1435-1446 and 1481-1485: maturity counts other tenants' rules, logs and playbooks.
- zerotrust/engine.py:267-272: continuous-eval finds sessions across orgs.
- exposure.py:1001-1007: a ticket from a user with no org lands in the first org in the DB.
- ot_security.py:276,289: the `org_id` query parameter overrides the caller's org.
- supplychain.py:504, 652, 855, 954: list `total` counts are not org-filtered.
- automation.py:763,827: Incidents and Alerts created without `organization_id`, from risk_quant.py:248 and supplychain.py:611.

**"Org is None means no filter" pattern:**
- exposure.py: 248, 516, 580, 855, 1049, 1226, 1440-1546, 1626-1659, 1695-1752;
- vulnmgmt.py:789;
- risk_quant.py:77-147;
- ot_security.py:72-144;
- aliases.py:57, 845-852, 1127-1139.

**Unvalidated foreign ids:**
- exposure.py:705-723 (asset-vulns) and 1012-1027 (ticket links);
- supplychain.py:813 (risk component);
- threat_modeling.py:380 (threat component);
- risk_quant.py:693 (control register);
- zerotrust.py:295 (microsegment);
- api_security.py:303, 598, 716;
- ot_security.py:444, 753.

**403 vs 404 existence oracle:** supplychain `get_*_or_404` helpers (:80-131) return 403 for other tenants' ids.

**RBAC.** There are zero role checks across the 149 mutating routes. The most dangerous ones are:
- OT `safe_shutdown` (ot_security.py:814), `respond` (:517), `containment_strategy` (:797), `segmentation_audit` (:684), policy enable/disable (:945/:956), deletes;
- dash `/ot-security/discover`, a network sweep (aliases.py:975);
- api-security `/scan/compliance`, which is SSRF (api_security.py:1046);
- zerotrust `PUT /devices/{id}/compliance`, a device-trust bypass (:715), plus ZT policy and segment deletes;
- container `quarantine-pod` (:897);
- vulnmgmt patch `schedule`, which dispatches an agent command (:609);
- all deletes.

---

## 4. Prioritised fix list

1. **ZT Evaluate Access self-lockout** (zerotrust.py:80-98, engine.py:241-245). Stop injecting the caller's jti into what-if evaluations, and never push a session-gate verdict from `/evaluate`, `/evaluate-access` or `/policies/{id}/test`. This is an S fix and stops analysts locking themselves out for 24h.
2. **Add RBAC** (`require_role`) to every mutating route in the 9 modules, starting with OT safe_shutdown/respond, network discovery, the SSRF scan, ZT device compliance and the deletes (M).
3. **Close the cross-tenant holes** (S-M each): container scan vuln copy, SBOM purl dedupe, OT bulk_action, API-sec bulk-update and reports/compliance, api_security tasks, ZT maturity counts, the exposure ticket org fallback, the OT `org_id` override, and the org-is-None pattern (fail closed).
4. **Remove fabricated safety and compliance claims** (S-M): OT `safe_shutdown` (return "not supported: no OT control integration" and do not set the flag), `post_incident` text, `segmentation_audit`, CIP-007 and NIST hardcoded passes, `_load_ics_cves` (delete it and report "no ICS advisory feed configured"), container remediate/quarantine status flips, Rescan's "compliant" stamp, the "CIS 1.8" label on self-attested booleans, and Generate SBOM.
5. **Risk Quantification honesty** (M):
   - Delete `_default_fair_inputs_from_scenario` and require a FAIR input form wired to `POST /fair-analyses`.
   - Fix the PERT α/β.
   - Remove the client-side fallback ALE, risk score and "Probability" relabel.
   - Fix the p10 fallback, percentile summing and inverted labels.
   - Register `src.risk_quant.tasks` in Celery, or drop `.delay`.
6. **Supply chain** (L): add a real OSV/NVD component lookup that writes `known_vulnerabilities_count`/`risk_score`, or show "not scanned" instead of 0. Fix the following:
   - remove the HIGH alert on manual component add;
   - remove the SBOM 100% compliance score and the compliant-by-default edit;
   - set `components_count`;
   - delete the fake `vulnerability_cross_reference`.
7. **Response-shape mismatches** (S each). These make real data render as blank, 0 or "Non-Compliant":
   - vulnmgmt dashboard, KEV, scan profiles, patch ops and exceptions;
   - exposure attack-surface schema, severity/ticket multi-select, exploit filter;
   - container `vulnerability_count_*`;
   - threat dashboard and threats;
   - ZT devices, decisions, segments and policies;
   - API-sec vulns, policies, anomalies and compliance.
8. **Broken write paths** (S-M):
   - vulnmgmt Run Now (422), New Exception (FK), Remediate (id confusion), scan profile field names;
   - exposure scan import TypeError for new hosts (scan_parser.py:376-385), with errors surfaced in the UI;
   - OT discovery enum crash;
   - ZT Re-assess phantom devices.
9. **Make the pages reachable** (M): add the create/import UIs the pages lack:
   - vuln instances; exposure assets, surfaces and ticket status; container clusters and images;
   - vendors and risk triage; threat mitigations; FAIR analyses, registers and controls;
   - OT assets, zones and discovery; OT export through the server route.

   Also replace client-side KPIs with the existing dashboard endpoints (`/supplychain/dashboard/overview`, `/api-security/dashboard`, `/ot_security/dashboard`, `/exposure/risk-matrix`).
10. **Stop showing confident zeros for "no data"** (S):
    - Exposure MTTR `|| 0`, overall risk score and attack-surface score;
    - the compliance-trend flatline;
    - the VulnMgmt SLA "0%";
    - API-sec Pass Rate "0.0%";
    - ZT maturity baseline points;
    - OT "Update Needed" for unknown firmware;
    - container `scanned_at` defaulting to now.
11. **Dead or fake backend routes to delete or fix:**
    - exposure `/assets/discover`, `/assets/import`, POST `/scans` plus the `import_scanner_results` status-flip task, `/tickets/overdue` route order, `/report` 500, `/vulnerabilities/kev` 500;
    - vulnmgmt patch schedule `echo` dispatch and `run_vuln_scan` status stamping;
    - supplychain `/sboms/compare`, `/validate-sbom`, `/dependency-tree`;
    - threat `/analyze/pasta`;
    - ZT `/step-up`, `/verify`;
    - api-sec `/scan/discover`;
    - the dash OT list and purdue aliases;
    - duplicate aliases (`/container-security/alerts`, `/supplychain/vendor-assessments`, `/risk-quantification/analysis`, `/threat-modeling/models` in aliases.py).
