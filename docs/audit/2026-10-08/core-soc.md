# Core SOC semantic audit (read-only), 2026-10-08

Scope: Dashboard, Alerts, AlertDetail, Incidents, IncidentDetail, WarRoom, Playbooks, PlaybookBuilder, Remediation, TicketHub, Assets, Reports, Analytics.
Grade counts across the 122 page-feature rows (first grade where a row has two): REAL 39, PARTIAL 43, BROKEN 21, FAKE 14, UI-ONLY 4, STUB 0, missing UI 1.
Grades: REAL / PARTIAL / STUB / FAKE / BROKEN / UI-ONLY. Paths are relative to C:\Users\jacob\pysoar. FE = frontend/src/pages, BE = src/api/v1/endpoints.

Cross-cutting (verified by the lead auditor):
- BE/aliases.py:43-93 `_safe_list` catches every exception and returns `{"items": [], "total": 0}` with only a warning log. DB or query errors look like an empty platform. The same pattern is in `playbooks_executions_recent` (aliases.py:451-470) and about 30 other alias routes. Org scoping in both is conditional (`if org_id is not None and hasattr(...)` at :56, `if org_id and ...` at :461), so a user with no org gets every tenant's rows.
- Earlier flags that turned out to be resolved:
  - FE/Remediation.tsx:1022 is only a comment about an old hardcoded "Block IP 192.168.1.100" display. The code now renders the real `actions_completed`/`actions_failed` arrays (REAL).
  - FE/AlertDetail.tsx:314 `P${alert.priority ?? 3}` is harmless, because `priority` is NOT NULL with a default of 3 (src/models/alert.py:96).
  - BE/playbook_builder.py:223 and :736 are historical comments only.
- Write routes for alerts, incidents and metrics use only `CurrentUser`. No `require_role` / permission check (src/api/deps.py:180), so any authenticated user, viewers included, can delete or bulk-delete alerts and incidents.

## 1. Dashboard / Analytics / Reports

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Dashboard | Load, 30 s refresh, error banner | Dashboard.tsx:112-154, 201-215 | (below) | - | REAL | `capture()` lists failed sources in a red banner instead of silently showing zeros | - |
| Dashboard | Total Alerts / new today | Dashboard.tsx:126 GET /alerts/stats | alerts.py:215-293 | alerts (org) | REAL | - | - |
| Dashboard | Open Incidents / total | Dashboard.tsx:127 GET /incidents/stats | incidents.py:223-305 | incidents (org) | REAL | - | - |
| Dashboard | Critical Alerts "Require attention" | Dashboard.tsx:256-263 | alerts.py:235-240 | alerts (org) | PARTIAL | All-time count including resolved, closed and false-positive alerts | S |
| Dashboard | IOCs Tracked "Active indicators" | Dashboard.tsx:130 GET /iocs?size=1 | iocs.py:131-175 (query at :144) | threat_indicators | BROKEN (tenancy) | No org filter, so the count spans all tenants; also counts inactive IOCs | S |
| Dashboard | Playbooks count | Dashboard.tsx:131 GET /playbooks?size=1 | playbooks.py:88-135 (query at :100) | playbooks | BROKEN (tenancy) | No org filter although the model has organization_id (models/playbook.py:87) | S |
| Dashboard | Resolved Today + MTTR subtitle | Dashboard.tsx:280-291 | alerts.py:273-283; incidents.py:274-295 | alerts.resolved_at (String), incidents | PARTIAL | Single-alert PATCH to `closed` never sets resolved_at (alerts.py:331 only handles RESOLVED), so closes are under-counted; MTTR is real but loads every closed incident with no limit | S |
| Dashboard | 5 charts (severity, status, incident status, source, type) | Dashboard.tsx:164-190, 297-376 | alerts.py:235-256; incidents.py:242-261 | org-scoped | REAL | Honest empty state | - |
| Dashboard | Recent alerts / incidents | Dashboard.tsx:128-129 | alerts.py:60-136; incidents.py:47 | org-scoped | REAL | - | - |
| Analytics | Data load / errors | Analytics.tsx:35-105 | 7 calls | - | FAKE (error-hiding) | `Promise.allSettled` turns every failure into `{}` and `catch` returns null; there is no error UI, so an outage renders as zeros | S |
| Analytics | KPI Total Alerts (30 d) | Analytics.tsx:50, 80 | metrics.py:19-84 | alerts | PARTIAL | /metrics/overview returns `{totals,active,period}`, never `total_alerts`, so the value falls back to the all-time /alerts/stats total | S |
| Analytics | Alert / incident trend % | Analytics.tsx:67-71, 81, 83 | metrics.py:19-84 | - | BROKEN | Always `pct(0,0)` = 0, so the arrow never renders; the comment at :38-44 says this was fixed | M |
| Analytics | KPI "Active Incidents" | Analytics.tsx:82, 133-139 | incidents.py:223 `total` | incidents | PARTIAL | Shows the all-time total under the label "Active"; should use open_count | S |
| Analytics | KPI Avg. MTTR | Analytics.tsx:53, 73, 140-147 | metrics.py:221-278 | incidents | FAKE | UI reads `avg_mttr_hours`/`mean_time_to_resolve_hours`/`avg_resolution_hours`, none of which exist, so it falls back to `?? 0` and shows "0.0h". The backend calls `datetime.fromisoformat()` on a datetime at metrics.py:255, which raises TypeError, so it always returns None. No org filter | S |
| Analytics | MTTR trend % | Analytics.tsx:74, 85-87 | none | - | UI-ONLY | `prior_avg_mttr_hours` is never returned | M |
| Analytics | KPI Active IOCs | Analytics.tsx:88, 148-153 | metrics.py:19-84 | - | FAKE | `active_iocs` is never returned, so it is always 0 | S |
| Analytics | "Alert Trends (7 Days)" chart | Analytics.tsx:52, 158-165 | metrics.py:160-196 | alerts, ALL TENANTS | BROKEN | Asks for 30 days under a "7 Days" title; the query has no org filter, so other tenants' volume is drawn | S |
| Analytics | Severity distribution | Analytics.tsx:91, 167-177 | alerts.py:235-240 | alerts (org) | REAL | All-time | - |
| Analytics | Top Alert Sources | Analytics.tsx:93-95 | alerts.py:251-256 (dict) | - | BROKEN | `Array.isArray(dict)` is false, so the panel always says "No data available" | S |
| Analytics | Top Attackers | Analytics.tsx:51, 76, 96-100 | metrics.py:354-378 | alerts.source_ip, ALL TENANTS | BROKEN | Backend key `top_attackers` vs UI `items`/`attackers`, so always empty; the count key `alert_count` is not read. Fixing only the keys would leak other tenants' attacker IPs | S |
| Analytics | Incident types | Analytics.tsx:101, 248-273 | incidents.py:256-261 | org | REAL | - | - |
| Reports | Type selector | Reports.tsx:119-174 | reports.py:17-20 | - | REAL | - | - |
| Reports | Date range 7/30/90 | Reports.tsx:182-192, 44 | reports.py:32 | - | PARTIAL | Honoured only by the CSV/PDF export; preview, quick stats and JSON ignore it | S |
| Reports | "Custom range" option | Reports.tsx:191, 44 | - | - | UI-ONLY | No date picker; silently becomes 30 days | S |
| Reports | Export CSV | Reports.tsx:43-47 -> lib/api.ts:185-195 | reports.py:28-53 -> services/report_generator.py:65-106 | alerts/incidents (org) | REAL | Formula-injection safe; silent 10,000-row cap (report_generator.py:74, 87) | S |
| Reports | Export PDF | Reports.tsx:209-216 | reports.py:55-65 -> report_generator.py:110-231 | org | REAL | Same row cap | S |
| Reports | Export error handling | Reports.tsx:37-97 | - | - | PARTIAL | `try/finally` with no `catch`; failures are silent | S |
| Reports | Export JSON | Reports.tsx:50-93 | cached /alerts/stats, /incidents/stats | client-side | FAKE (mislabelled) | Stamps `date_range: "7d"` and similar on all-time stats | S |
| Reports | Preview + Quick stats | Reports.tsx:232-378 | alerts/incidents stats | org | PARTIAL | All-time and ignore the range; "Resolution rate" excludes `closed` | S |
| Reports | Export RBAC/audit | - | reports.py:28 | - | PARTIAL | Any viewer can bulk-export 10k rows; no audit event | S |

## 2. Alerts / AlertDetail / Incidents / IncidentDetail

No hardcoded, sample or random data is rendered. All four pages use lib/api.ts only.

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Alerts | List, pagination, total | Alerts.tsx:67 GET /alerts | alerts.py:60-136 | alerts (org :78) | REAL | Real count via subquery. Backend accepts `start_date`/`end_date` (:71-72) but never applies them | S |
| Alerts | Search, severity and status filters | Alerts.tsx:67-73 | alerts.py:81-94 | DB | REAL | - | - |
| Alerts | Sorting | none | alerts.py:73-121 | - | missing UI | Backend supports sort; no sortable headers | S |
| Alerts | Refresh + 30 s poll | Alerts.tsx:92 | alerts.py:60 | DB | REAL | - | - |
| Alerts | Bulk ack / in-progress / resolve / close / delete | Alerts.tsx:142 -> lib/api.ts:173 POST /alerts/bulk | alerts.py:377-486 | DB (org per id :417-421), audit summary | REAL | Toast says "in_progressd"; FE falls back to `success_count ?? selectedIds.size` (Alerts.tsx:147), harmless while BE returns it. Bulk "assign" exists in BE only. No role check: a viewer can bulk-delete | S |
| Alerts | Row delete | Alerts.tsx:111 | alerts.py:362-371 | DB | PARTIAL | No AuditLog row on single delete (bulk and incident delete do write one); no role check | S |
| Alerts | Create alert modal | Alerts.tsx:530 | alerts.py:138-212 -> services/automation.py on_alert_created | DB + automation | PARTIAL | Insert is real. The automation it fires: IOC matching unscoped (automation.py:930-936), so another tenant's IOCs escalate this alert and bump their sighting counters; repeat-alert threshold unscoped (:1272-1278); playbook auto-trigger is FAKE (next row) | M |
| Alerts | Automation "N playbooks triggered" | (side effect of create) | automation.py:1412-1442, recorded at :172-180 | - | FAKE | `_auto_trigger_playbooks` only logs "Auto-triggering playbook" and returns IDs. Nothing executes, yet the TicketActivity records "N playbooks". It also queries Playbook with no org filter | M |
| AlertDetail | Load | AlertDetail.tsx:66 | alerts.py:296 | DB | REAL | `get_alert_or_404` (:45-50) drops the org filter when org_id is None | S |
| AlertDetail | Status dropdown, quick actions (resolve / FP / ack) | AlertDetail.tsx:289, 328-342 | alerts.py:307-359 | DB + audit before/after | REAL | Only `resolved` stamps resolved_at (:331); closed/false_positive do not. Status and severity are free strings (schemas/alert.py:44-45) | S |
| AlertDetail | Indicators, tags, details, priority | AlertDetail.tsx:222-316 | AlertResponse | DB | REAL | P3 fallback is harmless (NOT NULL default 3). "Assigned to" shows a raw UUID; no assign control | S |
| AlertDetail | Timeline card | AlertDetail.tsx:253-276 | created/updated/resolved/incident_id columns | DB | REAL (thin) | Not a real history; AuditLog trail not surfaced | M |
| AlertDetail | Create incident (escalate) | AlertDetail.tsx:94-101 | incidents.py:130 (link org-scoped :170-180) | DB | REAL | - | - |
| AlertDetail | Run Playbook picker + execute | AlertDetail.tsx:72, 109 | playbooks.py:88 (list, unscoped :100), :215 (execute) -> services/playbook_engine.py | DB + engine | PARTIAL / tenancy hole | Lists and executes other tenants' playbooks (`get_playbook_or_404` :48 unscoped). The execution row has no organization_id (:250-258). The engine adopts the playbook's org (playbook_engine.py:917). The picker filters `is_enabled` only, so non-active playbooks 400. The containment steps it can run are FAKE (see section 3) | M |
| AlertDetail | Delete | AlertDetail.tsx:86 | alerts.py:362 | DB | PARTIAL | No audit, no role check | S |
| Incidents | List / search / filters / pagination | Incidents.tsx:75 | incidents.py:47-128 | DB (org :66) | REAL | alert_count loads every linked alert row just to count | S |
| Incidents | "Informational" severity | Incidents.tsx:231, 561 | models/incident.py:18-24 (no such value) | - | BROKEN (minor) | Stored unvalidated; alerts use `info`, incidents `informational` | S |
| Incidents | Inline status change | Incidents.tsx:148 | incidents.py:321-376 | DB + audit | PARTIAL | No CaseTimeline STATUS_CHANGE event (enum at models/case.py:134 never emitted) | S |
| Incidents | Delete | Incidents.tsx:128 | incidents.py:379 | DB + audit | REAL | No role check | - |
| Incidents | Create + link alerts | Incidents.tsx:91, 501 | incidents.py:130 | DB | PARTIAL | Picker offers alerts already linked elsewhere (no `incident_id IS NULL` filter) and silently re-links them; first 100 only | S |
| IncidentDetail | Load | IncidentDetail.tsx:126 | incidents.py:308 | DB | REAL | - | - |
| IncidentDetail | Related Alerts card + Unlink | IncidentDetail.tsx:358-408, 250 | incidents.py:308 -> IncidentResponse (schemas/incident.py, no `alerts` field) | - | BROKEN | `incident.alerts` is always undefined, so the card always says "No alerts linked" while the title shows alert_count N. Unlink (:392) is unreachable | S |
| IncidentDetail | Link Alert modal | IncidentDetail.tsx:161, 239 | incidents.py:436-463 | DB, org on both sides | PARTIAL | Lists already-linked alerts; linking writes no audit or timeline event, though the UI refreshes the timeline | S |
| IncidentDetail | Status / severity / quick actions | IncidentDetail.tsx:708-768 | incidents.py:321 | DB + audit | PARTIAL | No timeline event; offers invalid "informational"; no assignee control | S |
| IncidentDetail | Notes list / add / delete | IncidentDetail.tsx:132, 186, 197 | case_management.py:226, 267, 383 | case_notes (org via parent :178-192) | REAL | Pin shown but cannot be set; delete writes no timeline event | S |
| IncidentDetail | Tasks list / add / toggle | IncidentDetail.tsx:138, 207, 220 | case_management.py:425, 473, 543 | tasks | PARTIAL | Toggle writes no timeline event; un-complete keeps completed_at; assignee can be any user in any tenant (:491, :578), and the response leaks their full_name | S |
| IncidentDetail | Timeline tab | IncidentDetail.tsx:144 | case_management.py:885-926 | case_timeline | PARTIAL | Only notes, tasks and attachments emit events; status, severity, alert link and playbook runs never do. Capped at limit=50 (:890), so "Timeline (n)" maxes at 50 | M |
| IncidentDetail | Attachments list / upload / download | IncidentDetail.tsx:150, 229, 667 | case_management.py:646, 686, 792 | local disk + case_attachments | REAL | Extension allowlist + SHA-256; no malware scan (`is_malware` always false); download failure only goes to console.error | S |
| IncidentDetail | Run Playbook | IncidentDetail.tsx:156, 259 | playbooks.py:88, 215 | - | PARTIAL / tenancy hole | Same as AlertDetail; no PLAYBOOK_EXECUTED timeline event | M |
| IncidentDetail | Delete | IncidentDetail.tsx:177 | incidents.py:379 | DB | REAL | - | - |

## 3. WarRoom / Playbooks / PlaybookBuilder

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Playbooks | List + filters | Playbooks.tsx:61 GET /playbooks | playbooks.py:88-135 | playbooks | PARTIAL | No org filter (:100) although the column exists, so every tenant sees all playbooks. The "Archived" filter can never match, because Archive sets `draft` (:107) | S |
| Playbooks | Create | Playbooks.tsx:359 | playbooks.py:141 (AdminUser) | playbooks | PARTIAL | organization_id is never set (NULL-tenant rows). UI trigger `schedule` does not equal enum `scheduled` (models/playbook.py:30), so scheduled playbooks never fire. No parameter inputs (steps sent with `parameters:{}`) | M |
| Playbooks | Step action catalog | Playbooks.tsx:485-493 (hardcoded options) | services/playbook_engine.py:27-43 | - | BROKEN | Verified: 5 of 9 options (enrich_ip, enrich_domain, enrich_hash, send_notification which is the default, create_incident) are not in the handler map, so they fall to `_unknown_action` (:850). Real implementations exist in src/playbooks/actions.py but that registry is never wired in | M |
| Playbooks | Publish / Archive / Delete | Playbooks.tsx:83, 97, 107 | playbooks.py:177, 207 | playbooks | PARTIAL | `get_playbook_or_404` (:48) is unscoped, so a tenant admin can edit or delete another tenant's playbooks | S |
| Playbooks | Run (execute) | Playbooks.tsx:698 | playbooks.py:215-285 -> BackgroundTasks -> playbook_engine.py:876 | playbook_executions + step side effects | PARTIAL / FAKE | Any user (viewer included) can run any tenant's playbook. The execution row has no org. Steps returning `success:false` don't raise, so the run is marked COMPLETED (:1052); a run made entirely of unknown actions shows "completed". Condition `on_success:"skip"` loops forever (:1001-1008). The modal never polls | M |
| Playbooks | Engine action block_ip / isolate_host | (engine) | playbook_engine.py:130-172, 175-215 | ticket_activities only | FAKE | Verified: writes the text "Blocked IP ... on firewall" / "Isolated host via edr" and returns `success:True`. No firewall or EDR call | L |
| Playbooks | Engine action create_ticket | (engine) | playbook_engine.py:278-343 | local rows | FAKE | Claims `system:"jira"` but writes only local rows; fabricated `TICKET-<timestamp>` fallback id (:340) | M |
| Playbooks | Engine action disable_user | (engine) | playbook_engine.py:218-275 | users | FAKE / dangerous | Verified: labelled "in active_directory" but deactivates a PySOAR login by email with no org filter (cross-tenant lockout); returns `success:True` even when no user was found | M |
| Playbooks | Engine action enrich_ioc | (engine) | playbook_engine.py:346-418 | threat_indicators | PARTIAL | Local lookup only, unscoped; when there is no match it reports a default confidence of 50 / "unknown" | S |
| Playbooks | Engine actions send_email / send_slack / http_request / update_alert / wait / run_script | (engine) | playbook_engine.py:49, 91, 499, 562, 803, 420 | real | REAL (security issues) | update_alert is unscoped (cross-tenant writes). run_script runs bash/powershell/python on the API host (:450-466); any tenant admin can author it | M |
| Playbooks | Details modal: executions | Playbooks.tsx:542 | playbooks.py:288 | playbook_executions | PARTIAL | Scoped via `triggered_by` in org users, so system/auto runs are always hidden | S |
| Playbooks | Auto-trigger "On Alert/Incident/Webhook" | trigger select | services/alert_correlation.py:466-473; services/automation.py:1412-1442 | - | FAKE / cross-tenant | alert_correlation selects active alert playbooks with no org filter, and empty conditions match every alert, so one tenant's playbook fires on every tenant's alerts. automation's trigger never executes. No incident or webhook trigger implementation | L |
| PlaybookBuilder | List + stat cards | PlaybookBuilder.tsx:419, 442-445 | playbook_builder.py:60 | visual_playbooks (org) | PARTIAL | "Total" is page-1 length (size 20); the /dashboard route is unused | S |
| PlaybookBuilder | Create / edit / delete | PlaybookBuilder.tsx:174, 1359, 738 | playbook_builder.py:119, 312, 346 | visual_playbooks | REAL | No RBAC (any user); category hyphen/underscore mismatch in icons | S |
| PlaybookBuilder | "Run"/"Pause" button | PlaybookBuilder.tsx:698-716 | playbook_builder.py:312 (status only) | - | FAKE (labelling) | Titled "Run" but only sets status=active. The page has no working execute entry point | S |
| PlaybookBuilder | Duplicate | PlaybookBuilder.tsx:722 | playbook_builder.py:377 (org from body :391) | - | REAL (security bug) | Honours a body-supplied organization_id, so a caller can plant a clone in another tenant | S |
| PlaybookBuilder | Templates tab | PlaybookBuilder.tsx:420 | playbook_builder.py:167 -> src/playbook_builder/engine.py:690-960 | hardcoded dicts | FAKE (13/15) | Verified in Python: only phishing_response (5 nodes) and malware_triage (4) have content. The other 13 (ransomware_ir, brute_force_response, ...) have 0 nodes / 0 edges and exist in name only. Cards render `nodeCount`/`popularity` the API never returns (:800, :804) | M |
| PlaybookBuilder | Template "Use" | PlaybookBuilder.tsx:825 | playbook_builder.py:739 (org from body :758) | - | PARTIAL | 13/15 produce empty playbooks; body-supplied org honoured | S |
| PlaybookBuilder | Template "Preview" | PlaybookBuilder.tsx:841 | - | - | UI-ONLY | previewTemplate state is never rendered | S |
| PlaybookBuilder | Executions tab + metric cards | PlaybookBuilder.tsx:422 GET /playbook-builder/executions | none (falls into GET /{playbook_id} :301, returns 404) | - | BROKEN | Verified: `.catch` returns `[]`, so the tab is always empty and the cards read 0. The frontend type is camelCase (playbookName...) vs backend snake_case, so it would crash at :466 once a route exists. The mechanical diff missed this because `{x}` matched | M |
| PlaybookBuilder | Re-run / View details | PlaybookBuilder.tsx:1047, 1065 | playbook_builder.py:612 | - | BROKEN / UI-ONLY | Unreachable (empty list); `playbookId` is undefined; selectedExecution is never rendered | S |
| PlaybookBuilder | Canvas load / node add-move-delete / edge add-remove | PlaybookBuilder.tsx:225, 261, 331, 365, 383, 394 | playbook_builder.py:301, 448-611 | playbook_nodes / edges (org) | PARTIAL | Persists, but node `config` is always null with no UI to choose an action or set params, and the edge type is fixed to `success`. Nodes are labels only | M |
| PlaybookBuilder | Graph execution engine | (no UI entry) | playbook_builder.py:612 -> src/playbook_builder/tasks.py:14-104 -> engine.py:403 | - | BROKEN + FAKE | Verified: `PlaybookExecutionEngine(db)` (tasks.py:69) raises TypeError (`__init__` takes no args, engine.py:383), so every run fails and is retried 3 times. Even if fixed: action returns `{"result":"success"}` (:502-507), notification returns `sent:True` with nothing sent (:540-545), api_call returns `status:200` with no request (:560-565), enrichment returns `{}` (:535), human_approval returns "pending" and continues (:529), subplaybook returns "executed" (:547). The engine result is never persisted and the task stamps "completed" regardless (tasks.py:79-82) | L |
| WarRoom | Room list | WarRoom.tsx:122 -> endpoints.ts:1421 | collaboration.py:156 | war_rooms (org) | REAL | Size 20, later rooms dropped | S |
| WarRoom | Create room | WarRoom.tsx:164 | collaboration.py:130 -> collaboration/engine.py:34 | war_rooms + audit | REAL | - | - |
| WarRoom | Summary cards | WarRoom.tsx:157 | collaboration.py:813 | DB counts | PARTIAL | "Action Items" shows pending only; overdue includes cancelled items (:837) | S |
| WarRoom | Chat read/send | WarRoom.tsx:147, 196 | collaboration.py:351, 325 | war_room_messages | PARTIAL | Persisted but not real-time: no websocket, no refetchInterval, staleTime 5 min (App.tsx:89). The only war-room WS handler is in the unmounted ws.py:109. Pin, edit, thread and search are not exposed | M |
| WarRoom | Enter room / join | WarRoom.tsx:411-416 (`apiAny.joinRoom`) | collaboration.py:266 (exists) | - | BROKEN | `collaborationApi.joinRoom` is undefined, so join never fires; participant counts reflect the creator only | S |
| WarRoom | Action Items tab | WarRoom.tsx:130 -> endpoints.ts:1447 (N+1 over 50 rooms) | collaboration.py:585 | action_items | PARTIAL | Read-only (no status/assignee update); priority sorted alphabetically | S |
| WarRoom | Create action item | WarRoom.tsx:178 | collaboration.py:560 | action_items | REAL | No due date or assignee in the form | S |
| WarRoom | Archive / Archived tab | WarRoom.tsx:209, 138 | collaboration.py:239, 156 | war_rooms | REAL | Any user can archive | S |

## 4. Remediation / TicketHub / Assets

| page | feature | frontend call | backend handler (file:line) | data source | grade | evidence / what is wrong | fix |
|---|---|---|---|---|---|---|---|
| Remediation | KPI Total / Success / Pending / Avg time | Remediation.tsx:182-191, 391-423 | remediation.py:1819 | remediation_executions | REAL | Org filter conditional (`if org_id`, :1832) | S |
| Remediation | KPI "Active Policies", "Actions Today" | Remediation.tsx:415, 420 | remediation.py:1819 (fields absent from RemediationDashboardStats) | - | FAKE (permanent 0) | Backend never returns these fields; the UI falls back to 0 | S |
| Remediation | Dashboard "Recent Executions" | Remediation.tsx:549 | remediation.py:1819 | - | BROKEN | Reads `recent_executions`, which is never returned, so always empty | S |
| Remediation | Charts "Execution Timeline (7 Days)", "Actions by Type" | Remediation.tsx:335-360, 459-512 | /executions (only fetched on the Executions tab, :222) | - | PARTIAL | Empty on a cold dashboard; "by type" groups by trigger_source and ignores backend `actions_by_type` | S |
| Remediation | Policies list + Type/Enabled filters | Remediation.tsx:194-209 | remediation.py:112 | remediation_policies | BROKEN | UI sends `type`/`enabled`; BE expects `policy_type`/`enabled_only` (default True), so both filters are ignored and disabled policies never return | S |
| Remediation | Enable/disable toggle | Remediation.tsx:699-707 | remediation.py:180 | DB | PARTIAL | A disabled policy vanishes and cannot be re-enabled from the UI; no RBAC | S |
| Remediation | Policy Executions / Success Rate columns | Remediation.tsx:725-740 | remediation/engine.py:345-349 | policy row | PARTIAL | success_rate stored 0-1 but printed as a percent (100% shows "1%"); automation.py:1565 bumps execution_count when nothing ran | S |
| Remediation | "Built-in Policies: 8 pre-configured policies" | Remediation.tsx:642 | none | hardcoded text | FAKE | Static claim; the backend catalogue has 3 and nothing installs them | S |
| Remediation | Create Policy modal | Remediation.tsx:1506 | remediation.py:70 | DB | BROKEN (functionally) | Sends `actions:[{type:"auto_block"}]`, but executors are keyed firewall_block/host_isolate... (remediation/engine.py:64-82), so every UI-made policy action fails "Unknown action type". "Severity threshold" stored as an equality match | M |
| Remediation | Executions list + filters | Remediation.tsx:211-223 | remediation.py:337 | DB | PARTIAL | `trigger` ignored (BE wants `trigger_source`) and option values don't match stored values; hidden 7-day window; a playbook execution's string `details` fails `ExecutionActionResult.details: dict` and 500s the whole list | S |
| Remediation | Expanded "Action Results" | Remediation.tsx:1005-1045 | same | actions_completed | PARTIAL | Now real (the old hardcoded demo trio was removed, per the comment at :1015-1022), but `actions_failed` is not in the schema and labels fall back to raw JSON (`action_type` vs `action`/`name`) | S |
| Remediation | Pending Approvals panel | Remediation.tsx:226-235, 795-845 | remediation.py:366 | DB | PARTIAL | UI reads `approval.policy`/`target` (BE: `policy_id`/`target_entity`), so names are blank; alert-triggered executions never set approval_status=pending, so they never appear | S |
| Remediation | Approve / Reject | Remediation.tsx:818-829, 1673 | remediation.py:447, 475 -> remediation/engine.py:839, 872 | DB, then executors | BROKEN (likely) | `approved_by` = client `approver_id:''` against an FK to users.id (remediation/models.py:169), so Postgres should reject it (not run against a DB). current_user is ignored, no self-approval check, no RBAC; actions run synchronously in the request | S |
| Remediation | Mark Complete / Failed | Remediation.tsx:1705, 1738 | remediation.py:536, 623 | DB + audit | REAL | Honest manual lifecycle | - |
| Remediation | Quick Block IP | Remediation.tsx:281, 1110 | remediation.py:1005-1137 | IOC + InstalledIntegration dispatch | PARTIAL / BROKEN | Honest `awaiting_integration` when no integration. UI sends `duration` (BE `duration_hours`, ignored). With an integration installed, `_dispatch_via_integration` reads `.auth_config`/`.endpoint_url` (:876-881), which InstalledIntegration lacks (verified), so AttributeError -> 500. Vendor URL shapes aren't the real APIs. The FE mutation swallows errors (`catch{return null}`, :278-312) | M |
| Remediation | Quick Isolate Host | Remediation.tsx:290 | remediation.py:1139 | EDR / agent | PARTIAL / BROKEN | Same AttributeError with an EDR integration; the agent path issues a real command but the execution sits in `awaiting_approval` forever (no result sync) | M |
| Remediation | Quick Disable Account | Remediation.tsx:299 | remediation.py:1262 | IdP / agent | PARTIAL / BROKEN | force_password_reset ignored; same IdP crash; agent fallback picks any IR agent in the org (`request.hostname` doesn't exist, :1301) | M |
| Remediation | Quick Quarantine File | Remediation.tsx:305-309, 339 | remediation.py:1388 -> `_find_ir_agent` :955-971 | agent command | BROKEN (dangerous) | Verified: UI sends `host`, schema expects `hostname` (schemas/remediation.py:237), so it arrives as "". `_find_ir_agent` then skips the hostname filter and sends a real quarantine command to an arbitrary org agent | S |
| Remediation | Recent Quick Actions table | Remediation.tsx:238-247 | remediation.py:387-397 | DB | BROKEN | Filters `trigger_source IN ('manual','quick_action')` but quick actions write `manual_quick_action` (:987), so always empty | S |
| Remediation | Integrations tab grid | Remediation.tsx:250-259 | remediation.py:1712 | remediation_integrations | PARTIAL + secret leak | Response includes `auth_config` credentials for any org user; is_connected/health never updated (health task not registered with Celery) | S |
| Remediation | Add Integration | Remediation.tsx:1587 | integrations.py:217 | installed_integrations | BROKEN | Writes a different table from the one the tab lists, so it never appears; errors go to the console only | M |
| Remediation | Test Connection | Remediation.tsx:1399 | integrations.py:432 | - | BROKEN | Passes a RemediationIntegration id to the InstalledIntegration route, so always 404 | S |
| TicketHub | KPI tiles + source chips | TicketHub.tsx:820-826 | tickethub.py:554 -> tickethub/engine.py:186 | union of incidents, case tasks, remediation tickets, action items, POAMs | PARTIAL | Real aggregation but each source capped at 200 rows (engine.py:239-284), so totals undercount silently; docstring claims 8 sources, actually 5; incidents have no due_date, so they are never overdue | M |
| TicketHub | List + filters + pagination | TicketHub.tsx:841-848 | tickethub.py:23 | same | PARTIAL | In-memory paging after the cap; priority filter (critical/high...) never matches int priorities or POAM "moderate" | S |
| TicketHub | Comments list/add; activity | TicketHub.tsx:325-360, 335-343 | tickethub.py:294, 315, 379 | ticket_comments / ticket_activity | REAL | POST doesn't verify the source ticket belongs to the org | S |
| TicketHub | Change status; Kanban + move | TicketHub.tsx:365, 490, 850-857, 882 | tickethub.py:146, 219, 230 | writes source rows | REAL with tenancy hole | `Task` has no organization_id and the `hasattr` guard skips scoping (:163-165, :259-261), so any user can change any tenant's case task; no RBAC | S |
| TicketHub | Automation rules list/create/toggle | TicketHub.tsx:859-928, 1331-1430 | tickethub.py:406, 421, 447 | ticket_automation_rules | FAKE (name only) | Verified: `AutomationRule` is referenced nowhere outside the endpoint and model, with no evaluator, task or hook. UI shows execution_count/last_triggered columns that are forever 0/"never" | L |
| Assets | List + search/filters/pagination | Assets.tsx:69-88 | assets.py:74-128 | assets (org) | REAL | - | - |
| Assets | Create | Assets.tsx:367 | assets.py:130 | DB | REAL | - | - |
| Assets | Delete | Assets.tsx:93 | assets.py:205 | DB | REAL | No RBAC | S |
| Assets | Details: Security Score / Last Scan | Assets.tsx:674-690 | - | asset.security_score | UI-ONLY | Nothing in src/ ever writes security_score or last_scan; null renders as "/100". No risk, vuln or related-alert view; no edit UI (`assetsApi.update` unused) | S |

## 5. Backend routes in these domains the UI never calls (and FE calls with no route)

| method path | handler file:line | real? org-scoped? | verdict | note |
|---|---|---|---|---|
| POST /alerts/bulk-update (FE only) | none; caller endpoints.ts:100 | - | dead FE code: delete | Unused; live path is POST /alerts/bulk |
| POST /remediation/actions/{id}/approve, /execute (FE only) | none; endpoints.ts:369-377, hooks useApi.ts:308-314 | - | dead FE code: delete | Hooks are imported by no component |
| GET /playbooks/{id}/nodes (FE only) | none; endpoints.ts:1001 | - | dead FE code: delete | Unused |
| GET /playbook-builder/executions (FE calls, not flagged by diff) | none | - | ADD ROUTE | PlaybookBuilder.tsx:422; declare above /{playbook_id}, org-scoped |
| GET /metrics (Prometheus) | monitoring.py:31 | real, platform-wide | keep internal | - |
| GET /metrics/agentic | health.py:216 | real, platform-wide | keep ops; make superuser-only | AdminUser is a per-org admin |
| GET /metrics/alerts/by-severity, by-status; /incidents/by-type | metrics.py:87, 139, 199 | real, NO org filter | duplicate: delete or org-scope | Duplicates /alerts/stats and /incidents/stats |
| GET /metrics/alerts/by-source, /iocs/by-type, /iocs/by-threat-level, /playbooks/executions | metrics.py:116, 319, 337, 281 | real, NO org filter | expose after org filter | Would fix Analytics Top Sources / Active IOCs / automation KPI |
| PATCH /incidents/{id}/notes/{note_id} | case_management.py:326 | real, scoped, author-or-admin | expose (edit + pin) | - |
| POST /incidents/{id}/timeline | case_management.py:928 | real, scoped | expose; and emit events server-side on status/link/playbook | - |
| GET /playbooks/executions/recent | aliases.py:451 | real but swallows errors; playbooks.py never sets execution org, so it is always empty | fix writer, then expose | - |
| GET /playbook-builder/dashboard | playbook_builder.py:215 | real, scoped | expose | Duration math on String columns, so avg is always 0 |
| GET /playbook-builder/executions/{id}, /{id}/executions | :686, :646 | real, scoped | expose (after engine fix) | Node executions never persisted |
| POST /playbook-builder/{id}/validate, /{id}/export | :360, :411 | real | expose | - |
| POST /playbook-builder/import | :426 | real; likely lazy-load MissingGreenlet on response | fix, then expose | - |
| PUT /playbook-builder/{id}/edges/{edge_id} | :566 | real, scoped | expose (edge type / condition editor) | - |
| PATCH /collaboration/actions/{id}; GET/PATCH rooms/{id}; POST rooms/{id}/join, /leave | collaboration.py:627, 200, 211, 266, 287 | real, scoped | expose (fixes join) | PATCH room has no RBAC |
| POST rooms/{id}/commander/{uid} | :301 | real | expose with RBAC + org check on uid | - |
| GET rooms/{id}/messages/search; PATCH messages/{id}; POST messages/{id}/pin | :410, :372, :392 | real, scoped | expose | Edit has no sender check |
| GET rooms/{id}/messages/{mid}/thread | :425 | real query, but send never sets parent_message_id | dead until fixed | - |
| GET+POST rooms/{id}/timeline; timeline/report; timeline/export | :676, :702, :732, :745 | real, scoped | expose | - |
| POST rooms/{id}/postmortem; GET summary, activity-metrics, actions/report | :764, :253, :884, :658 | mostly real | expose | Postmortem appends 3 fixed recommendation strings and hardcodes priority/effort "medium" (collaboration/engine.py:968-970; collaboration.py:803-804); label them as a checklist |
| GET+POST rooms/{id}/artifacts, artifacts/index, GET artifacts/{id}, POST artifacts/{id}/download | :452, :479, :542, :517, :528 | metadata only | do NOT expose as-is (FAKE) | No bytes stored; "download" just increments a counter |
| GET /collaboration/search | :965 | BROKEN (verified) | fix or delete | `room_id: Path(...)` with no path param, so every call 422s |
| POST /remediation/actions, GET /actions/{id} | remediation.py:269, 300 | real CRUD; engine never uses these rows | dead | - |
| POST /remediation/actions/{id}/test | :313 | FAKE (returns "success" with no work, :330) | delete or make real | - |
| GET /remediation/effectiveness | :1994-2010 | FAKE (verified hardcoded zeros) | delete or 501 | - |
| GET /remediation/timeline | :1967 | STUB (events=[] always) | fix or delete | - |
| POST /remediation/execute | :754 | BROKEN (policy_id=None leads to ValueError -> 500, remediation/engine.py:182-184) | fix, then expose | - |
| POST /executions/{id}/cancel | :732 | status flip only | PARTIAL; add state guard / real cancel | - |
| GET /executions/{id}/progress | :416 | real; percent can exceed 100 | expose after fix | - |
| POST /executions/{id}/rollback | :711 | real reversal (remediation/engine.py:427), no-op for quick-action rows | expose after fix | - |
| POST/PUT /remediation/integrations | :1731, :1756 | real, scoped | merge with InstalledIntegration, then expose | Two integration tables used inconsistently |
| POST /remediation/integrations/{id}/test | :1777-1794 | FAKE (success, no network call) | make real | - |
| GET /remediation/integrations/{id}/health | :1796 | stored fields never updated | PARTIAL | - |
| GET/POST/PUT /remediation/playbooks(/{id}) | :1456, :1477, :1505, :1518 | real CRUD, scoped | expose | - |
| POST /remediation/playbooks/{id}/execute | :1541 | FAKE success (awaiting_integration steps still end `overall_result=success`, :1676-1683) | fix before exposing | - |
| GET /remediation/policies/builtin | :140 | hardcoded catalogue of 3 | replace with the real seeder (`register_builtin_policies`, remediation/tasks.py:564) | - |
| GET/DELETE /remediation/policies/{id}; POST /{id}/test | :167, :202, :218 | real, scoped | expose | - |
| DELETE /tickethub/automation/rules/{id} | tickethub.py:479 | real, scoped | expose once rules do something | - |
| DELETE /tickethub/comments/{id} | :353 | real, scoped, no author check | expose with author check | - |
| GET /tickethub/tickets/{type}/{id}; GET/POST .../links | :53, :530, :505 | real, scoped | expose (links); ticket detail is redundant | Link POST doesn't validate the target |

## 6. Tenancy and RBAC (noticed while tracing)

1. **Unscoped reads and writes.**
   - Every handler in BE/metrics.py (:29-373) runs across all tenants. Analytics shows other tenants' alert volume and attacker IPs.
   - GET /iocs (iocs.py:144) is unscoped.
   - /playbooks list/get/patch/delete/execute (playbooks.py:48, 100) are unscoped, and executions never get an org.
   - Alert auto-trigger is unscoped (alert_correlation.py:467) and fires one tenant's playbooks on every tenant's alerts.
   - IOC matching on alert create (automation.py:930) and the repeat-alert threshold (:1272) are unscoped.
   - Engine actions update_alert, disable_user and enrich_ioc are unscoped.
   - TicketHub case_task status and kanban writes are unscoped (tickethub.py:163, 259).
   - Task assignees can be any user in any tenant (case_management.py:491, 578).
2. **Body-supplied organization_id is honoured** by builder clone and create-from-template (playbook_builder.py:391, 758).
3. **Null-org bypass.**
   - The per-id `get_*_or_404` helpers drop the org filter when the user has no org: alerts.py:48, incidents.py:35, case_management.py:183, collaboration.py:80.
   - Remediation lists use `if org_id:`, and aliases.py does the same at :56 and :461.
4. **No RBAC on any write** in alerts, incidents, case, collaboration, playbook-builder, remediation, tickethub or assets. `require_role` (src/api/deps.py:180) is used nowhere. Viewers can delete alerts and incidents, execute playbooks, isolate hosts, quarantine files, and approve executions (approver is taken from the client body).
5. **RCE surface.** run_script (playbook_engine.py:420) plus per-org AdminUser playbook authoring lets any tenant admin execute code on the shared API host.
6. **Secrets.** GET /remediation/integrations returns `auth_config` credentials.
7. **Audit and exports.** AuditLog has no organization_id. Single alert delete writes no audit row. Report export writes no audit row.

## 7. Prioritised fix list

1. **Tenant isolation, first.**
   - Add org filters to all of metrics.py, iocs.py:144, and playbooks.py (list/get/execute; also set `PlaybookExecution.organization_id`).
   - Scope alert_correlation auto-trigger, the automation IOC match and the repeat threshold.
   - Scope the tickethub case_task writes.
   - Stop honouring body organization_id in builder clone/template.
   - Make the null-org helpers fail closed. (M)
2. **Remove or neutralise dangerous behaviour.**
   - Fix the quarantine `host` vs `hostname` mismatch (Remediation.tsx:308), and make `_find_ir_agent` refuse an empty hostname.
   - Gate or remove `run_script` (playbook_engine.py:420).
   - Fix `_disable_user` (org filter; fail when not found; do not label it AD). (S-M)
3. **Delete fake successes in the classic playbook engine.**
   - block_ip / isolate_host / create_ticket (playbook_engine.py:130, 175, 278) must dispatch via a real integration or agent, or return `success:false, awaiting_integration`, mirroring the honest quick-action path at remediation.py:1005.
   - Make a failed step fail the run (:1052).
   - Wire src/playbooks/actions.py enrich_* / send_notification / create_incident into the handler map, or remove those options from Playbooks.tsx:485-493. (M)
4. **Visual builder execution.**
   - Fix the TypeError (playbook_builder/tasks.py:69).
   - Replace the fake executors (engine.py:502-567) with real dispatch, or raise "not implemented".
   - Persist node executions, and mark the DB row from the engine result.
   - Add GET /playbook-builder/executions and a real Run button.
   - Delete the 13 empty templates. (L)
5. **Automation honesty.**
   - `_auto_trigger_playbooks` (automation.py:1412) must enqueue `run_playbook_execution` or stop reporting "N playbooks".
   - TicketHub AutomationRule needs an evaluator, or the tab must be removed or labelled inactive.
   - Remediation alert-triggered executions must run or be queued for approval.
   - Register src.remediation.tasks in Celery. (M-L)
6. **Analytics page.**
   - Org-scope metrics.py and make the UI read the real keys (`totals`/`period`, `top_attackers`/`alert_count`, `mttr_hours`, by_source dict).
   - Fix the metrics.py:255 datetime TypeError, surface errors instead of `allSettled -> {}`, and remove the fake 0 tiles (Active IOCs, MTTR %). (S-M)
7. **Remediation contract mismatches.**
   - Policy filter param names, dashboard fields (active_policies, actions_today, recent_executions), and the quick-actions trigger_source value.
   - Approve/reject should use current_user, not `''`.
   - Create Policy action types; one integration table (Add/Test currently hit the wrong table).
   - Make `_dispatch_via_integration` work with InstalledIntegration.
   - Drop `auth_config` from responses.
   - Remove "8 pre-configured policies" text; delete the fake /integrations/{id}/test, /actions/{id}/test and /effectiveness. (M)
8. **IncidentDetail and timeline.** Return linked alerts so Related Alerts and Unlink work. Emit timeline events for status, severity, link and playbook. Lift the 50-event cap. (S-M)
9. **WarRoom.** Real-time via the mounted websocket or polling, fix join, fix /collaboration/search, and don't expose artifacts until bytes are stored. (M)
10. **RBAC.** Apply `require_role` to destructive and containment routes across these domains. Approval must enforce separation of duties. (M)
11. **Small honesty fixes.**
    - Reports: "Custom range" (remove or implement), JSON export labelled with a range it ignores, the missing catch.
    - Assets security_score "/100".
    - Remediation success_rate shown x100 wrong.
    - Delete the dead FE helpers (bulkUpdateAlerts, remediation approveAction/executeAction, playbookApi.getNodes, and the unused useApi hooks). (S)
