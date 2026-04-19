# PySOAR — Page & Function Reference

Per-page summary of every sidebar route in PySOAR. For each page: a one-paragraph purpose describing what the page does and who uses it, followed by a one-sentence synopsis of every top-level function and sub-component inside the file.

---

## Core & Auth

### Login
**Purpose:** Unauthenticated entry point where SOC users sign in with email and password. Renders the PySOAR brand, a single sign-in form, and routes the user to the dashboard on success or an inline error on failure.

**Functions:**
- `Login` — Renders the centered email/password form and manages local form/loading/error state for the authentication flow.
- `handleSubmit` — Submits credentials to the auth context and navigates to `/` on success or surfaces the API error message.

### Dashboard
**Purpose:** Landing page that gives SOC analysts and managers a real-time security overview after login. Aggregates alerts, incidents, IOCs, and playbook totals into stat cards, severity/status charts, and recent-activity feeds with 30-second auto-refresh.

**Functions:**
- `Dashboard` — Top-level page that fetches stats from alerts/incidents/iocs/playbooks APIs in parallel and renders the metric grid, charts, and recent-activity feeds.
- `fetchData` — Pulls alert and incident stats plus recent items in one `Promise.all` batch, falling back to empty data on per-endpoint failure.
- `ChartCard` — Reusable card wrapper showing a titled recharts container or an "No data yet" placeholder when empty.
- `StatCard` — Reusable colored-icon metric tile showing a title, big value, and subtitle, optionally wrapped in a Link for drill-down.

### Profile
**Purpose:** Personal account page where the logged-in user views their avatar, name, email, and role and edits their profile or security settings. Has two tabs for profile information and security, including password change and two-factor authentication toggle.

**Functions:**
- `Profile` — Renders the profile header, tab switcher, profile-edit form, and security tab with password change, sessions, and MFA enable.
- `updateProfileMutation` — Mutation that PATCHes `/users/{id}` with edited profile fields and shows a success or error banner.
- `updatePasswordMutation` — Mutation that POSTs to `/auth/change-password` with the current and new password, clearing the form on success.
- `handleProfileSubmit` — Form handler that triggers the profile-update mutation with the local form state.
- `handlePasswordSubmit` — Form handler that validates new vs. confirm password match before triggering the password-change mutation.

### Settings
**Purpose:** Admin-facing configuration page with a left sidebar of tabs (General, Notifications, Email/SMTP, Integrations, Security). Admins save changes per section, test SMTP delivery, and configure third-party integrations like VirusTotal, Slack, Splunk, MISP, and Cortex.

**Functions:**
- `Settings` — Top-level container that fetches settings, renders the tab sidebar, and routes the active tab to the matching sub-component.
- `GeneralSettings` — Form for application name, timezone, date format, and time format that PATCHes `/settings/general`.
- `NotificationSettings` — Toggle panel for email/Slack/Teams channels with connected-state indicators that PATCHes `/settings/notifications`.
- `EmailSettings` — SMTP host/port/credentials/TLS form with a Test Connection button that PATCHes `/settings/smtp`.
- `IntegrationSettings` — Grouped catalog of integrations with Configure/Edit/Test actions and a dynamic credential modal driven by `integrationConfigs`.
- `SecuritySettings` — Form for session timeout, login lockout, and alert-correlation parameters that PATCHes `/settings/security`.

### Users
**Purpose:** Admin user-management screen listing every PySOAR account with avatar, role, active/inactive status, and join date. Supports search, pagination, view-details, role/status edit, and delete with superuser protection.

**Functions:**
- `Users` — Page component that lists users via `usersApi.list`, renders search/table/pagination, and orchestrates the create and details modals.
- `fetchUsers` — Loads the paginated user list applying the current search filter and updates total count.
- `handleDelete` — Confirms then calls `usersApi.delete(id)` and refreshes the list.
- `handleViewDetails` — Stores the clicked user and opens the details modal.
- `CreateUserModal` — Form modal for adding a new user (email, password, name, role) calling `usersApi.create`.
- `UserDetailsModal` — Modal showing user info plus role and active/inactive selects that call `usersApi.update`, locked for superusers.

### Organizations
**Purpose:** Multi-tenant admin page with Organizations and Teams tabs for managing tenant orgs, plan tiers, member rosters, and teams. Admins create organizations, edit names/descriptions, invite members, and manage teams.

**Functions:**
- `Organizations` — Top-level page rendering the header, tab switcher, contextual create button, and the list/detail modals for both orgs and teams.
- `OrganizationsList` — Card grid that fetches `/organizations`, shows plan badge and member count, and exposes settings and delete actions.
- `TeamsList` — Table of teams with edit, add-member, and delete actions, including modals for editing a team and adding members.
- `CreateModal` — Generic creation modal that posts either a new organization or a new team.
- `OrganizationDetailModal` — Modal with Members and Settings tabs for one org, listing members with role badges and editing name/description.

### ApiKeys
**Purpose:** Developer/admin page for issuing and managing API keys that grant programmatic access to PySOAR. Lists existing keys with prefix, scoped permissions, last-used time, and supports create, regenerate, and delete.

**Functions:**
- `ApiKeys` — Page component that fetches `/api-keys`, renders the key table, the one-time-reveal banner, and orchestrates create/regenerate/delete mutations.
- `deleteMutation` — Mutation that DELETEs an API key by id and invalidates the cache.
- `regenerateMutation` — Mutation that POSTs to `/api-keys/{id}/regenerate` and surfaces the new plaintext key for one-time copy.
- `CreateKeyModal` — Modal form for naming a key, picking expiration, and toggling permissions, then POSTing to `/api-keys`.

### NotFound
**Purpose:** Static 404 fallback page shown for any unknown route. Displays a shield-off icon, "Page Not Found" heading, and a button to return to the dashboard.

**Functions:**
- `NotFound` — Renders the centered 404 layout with a Return to Dashboard link back to `/`.

---

## Alerts & Incidents

### Alerts
**Purpose:** Primary alert triage queue for SOC analysts listing security alerts with severity/status badges, source, and timestamp. Supports debounced search, multi-filter, auto-refresh, multi-select bulk actions, manual create, and per-row delete/detail navigation.

**Functions:**
- `Alerts` — Page component holding list state, filters, selection set, toasts, and rendering header/filters/bulk toolbar/table/pagination/create modal.
- `fetchAlerts` — Calls `alertsApi.list` with current page, size, and filters, populating items and total with optional spinner state.
- `showToast` — Displays a transient success/error toast in the top-right that auto-dismisses after four seconds.
- `handleDelete` — Confirms then deletes a single alert via `alertsApi.delete` and refreshes the list.
- `toggleSelect` — Adds or removes a single alert ID from the selected-set used for bulk actions.
- `toggleSelectAll` — Selects every alert on the current page or clears the selection if all were already selected.
- `handleBulkAction` — Calls `alertsApi.bulkAction` with the selected IDs and chosen action, reporting counts via toast.
- `CreateAlertModal` — Modal form for manually creating an alert (title, description, severity, source, IP, hostname).

### AlertDetail
**Purpose:** Detail and triage workspace for a single alert showing description, indicators, tags, and a timeline. Lets analysts change status/severity, escalate to an incident, run a SOAR playbook, or delete it.

**Functions:**
- `AlertDetail` — Page that fetches one alert by URL id and renders header, indicators, tags, timeline, sidebar details, and playbook modals.
- `showToast` — Displays a transient top-right success/error toast for mutation feedback.
- `updateMutation` — Mutation to PATCH the alert for status changes and quick-action buttons.
- `deleteMutation` — Mutation to delete the current alert and navigate back to the alerts list.
- `createIncidentMutation` — Mutation that creates a new incident pre-populated from the alert and navigates to it.
- `executePlaybookMutation` — Mutation that runs a chosen playbook against this alert and closes the picker modal.
- `Card` — Reusable titled section wrapper used for description, indicators, tags, timeline, details, quick actions.
- `ContextField` — Labeled indicator value display with optional monospace styling.
- `SidebarField` — Small icon-label-value row used in the sidebar Details card.
- `QuickAction` — Disabled-aware button row used in Quick Actions to fire status-update mutations.
- `TimelineItem` — Round-icon timeline entry showing label and date for lifecycle events.

### Incidents
**Purpose:** Incident queue page where analysts coordinate investigation and response across security incidents. Lists title, severity, kill-chain status, type, linked-alert count, and creation time, with filters, 30-second auto-refresh, and create-with-link-alert flow.

**Functions:**
- `Incidents` — Page component holding list/filter/search/modal state and rendering header, filters, table, pagination, create modal.
- `showToast` — Shows a transient top-right success or error toast.
- `fetchIncidents` — Loads paginated incidents from `incidentsApi.list` with applied filters and search.
- `fetchAvailableAlerts` — Loads up to 100 new-status alerts so the create modal can offer them for linking.
- `handleDelete` — Confirms then deletes the incident and refreshes the list.
- `Th` — Tiny table-header cell helper that handles left/right alignment.
- `FilterSelect` — Reusable labeled select used by all the filter dropdowns.
- `CreateIncidentModal` — Form modal for creating an incident with title, description, severity, type, and a checklist of alerts to link.

### IncidentDetail
**Purpose:** Full case-management workspace for a single incident used by SOC responders to drive an investigation through its lifecycle. Tabbed case panel for notes, tasks, timeline, and attachments plus sidebar controls for status, quick actions, playbook runs, and alert linking.

**Functions:**
- `IncidentDetail` — Page that fetches the incident, notes, tasks, timeline, and attachments and orchestrates every mutation and modal.
- `showToast` — Transient top-right toast for mutation feedback.
- `updateMutation` — PATCHes the incident for status, severity, and quick-action buttons.
- `deleteMutation` — Deletes the incident and navigates back to the incidents list.
- `addNoteMutation` — Posts a new case note and refreshes notes plus timeline caches.
- `deleteNoteMutation` — Deletes a single case note and refreshes notes and timeline.
- `addTaskMutation` — Creates a new case task from the inline task title input.
- `updateTaskMutation` — Toggles a task between pending and completed via the checkbox.
- `uploadFileMutation` — Uploads a selected file as an incident attachment.
- `linkAlertMutation` — Links a chosen alert to the incident from the Link Alert modal.
- `unlinkAlertMutation` — Removes a linked alert from the incident.
- `executePlaybookMutation` — Runs a selected playbook scoped to this incident and closes the picker.
- `Card` — Reusable titled section wrapper with optional right-aligned action.
- `TabButton` — Tab nav button used to switch between Notes, Tasks, Timeline, Attachments.
- `SidebarField` — Icon-label-value row used in the sidebar Details card.
- `QuickAction` — Sidebar row-button that triggers a status update (Start Investigation, Mark Containment, Mark Closed).
- `Modal` — Generic dismissible modal shell used for the playbook and alert pickers.

### Assets
**Purpose:** Asset inventory page where security and IT staff catalog protected systems (servers, workstations, network devices, databases, cloud instances). Supports search, type/status/criticality filters, pagination, create, view details, and delete.

**Functions:**
- `Assets` — Page component holding asset list state, filters, and modals.
- `fetchAssets` — Calls `assetsApi.list` with current filters/search/page and updates items and total.
- `handleDelete` — Confirms then calls `assetsApi.delete` and refreshes the list.
- `CreateAssetModal` — Large form modal for adding an asset with full metadata.
- `AssetDetailsModal` — Read-only modal showing network info, org, technical details, security score, cloud metadata, and timestamps.

---

## Compliance & Audit

### ComplianceDashboard
**Purpose:** Central federal-compliance workspace where GRC analysts track posture across multiple frameworks (FedRAMP, NIST, CMMC). Tabs for Overview, Controls, POA&Ms, CUI, and CISA directives show an overall score, control implementation status, remediation plans, CUI assets, and active emergency directives.

**Functions:**
- `getScoreColor` — Returns a Tailwind text color class (green/yellow/red) for a compliance score using 80/60 thresholds.
- `ComplianceDashboard` — Top-level page that fetches dashboard/controls/POAMs/CUI/CISA data and renders the tabbed UI with create/delete POA&M mutations.
- `OverviewTab` — Renders the overall compliance gauge ring, overdue POA&M banner, KPI cards, and per-framework score breakdown.
- `ControlsTab` — Renders a filterable list of security controls with framework/family/status filters and expand-to-detail rows.
- `ControlExpandedDetails` — Shows a single control's description, related controls, and evidence linkage when expanded.
- `POAMsTab` — Renders the POA&M list with risk-level/status filters, overdue counter, create form, and delete actions.
- `CUITab` — Renders the inventory of CUI-tagged assets with category, designation, dissemination controls, and refresh.
- `CISATab` — Renders active CISA BOD/ED directives with deadlines, status, and actions taken.
- `StatCard` — Reusable colored KPI card showing label, numeric value, and icon.

### AuditLogs
**Purpose:** Forensic audit log viewer for security officers satisfying FedRAMP AU-6. Shows a paginated, filterable table of audit events (timestamp, user, action, resource, IP, success/fail) and supports CSV export of the last 90 days.

**Functions:**
- `AuditLogs` — Top-level page that queries paginated audit logs plus action/resource enum lists, renders the filterable table, and triggers a CSV blob download.
- `formatDate` — Converts an ISO timestamp string into a localized display string.
- `getActionColor` — Maps an audit-action string to a colored badge class by substring-matching known action keys.

### AuditEvidence
**Purpose:** Compliance workspace for managing the evidence lifecycle — collecting artifacts, viewing audit-trail events, organizing into assessment packages, and running continuous monitoring (ConMon). Five tabs cover KPIs, audit history, evidence approval, package tracking, and on-demand ConMon execution.

**Functions:**
- `getStatusColor` — Returns the badge color class for an evidence/package status from a static map.
- `getRiskColor` — Returns the text color class for a risk level from a static map.
- `AuditEvidence` — Top-level page that loads all tab data and wires mutations for ConMon run, evidence delete, and evidence approve.
- `DashboardTab` — Renders KPI cards (audit events, evidence items, active packages, readiness score) and evidence-coverage breakdown.
- `AuditTrailTab` — Renders a filterable table of audit events with expandable detail rows.
- `EvidenceTab` — Renders the evidence-item list with status/type filters and approve/delete actions.
- `PackagesTab` — Renders assessment packages with framework, status, evidence count, due date, and assessor.
- `ConMonTab` — Renders continuous-monitoring check statuses and a button to trigger an on-demand ConMon run.
- `KPICard` — Reusable colored KPI tile showing label, value, and icon.

### FedRAMP
**Purpose:** FedRAMP authorization workspace tracking readiness for ATO across the full controls catalog. Five tabs provide a readiness gauge with family breakdown, a filterable controls list, a POA&M tracker, evidence progress by family, and downloadable SSP/SAP/SAR documents.

**Functions:**
- `statusColor` — Returns badge color classes for an implementation status.
- `statusLabel` — Returns the human-readable label for an implementation status.
- `riskColor` — Returns badge color classes for a POA&M risk level.
- `poamStatusColor` — Returns badge color classes for a POA&M status.
- `badgeVariant` — Returns badge styling for an overall readiness badge.
- `scoreGaugeColor` — Returns a hex color for the readiness gauge based on score thresholds.
- `downloadBlob` — Triggers a browser download of a Blob with the given filename via an anchor click.
- `LoadingState` — Reusable centered spinner with an optional loading message.
- `EmptyState` — Reusable empty placeholder with icon, title, and description.
- `ErrorState` — Reusable centered error display with alert icon and message.
- `ScoreGauge` — Renders the circular SVG readiness gauge showing percent-complete with a color-coded ring.
- `ReadinessTab` — Fetches readiness data and renders the score gauge, gap summary, family breakdown, and recommendations.
- `ControlsTab` — Fetches and renders a searchable, filterable list of FedRAMP controls.
- `ControlRow` — Renders a single control row that expands to show description, guidance, role, and required evidence.
- `POAMTab` — Fetches the POA&M report and renders summary counts, monthly timeline, and a table of items.
- `EvidenceTab` — Renders evidence-collection progress by control family with collected/required ratios and per-control status.
- `DocumentsTab` — Lists FedRAMP authorization documents with availability and download/generate actions.
- `FedRAMP` — Top-level page that renders the header and tab navigation, dispatching to each tab component.

### STIGCompliance
**Purpose:** DISA STIG benchmark, scan, and finding manager for DoD compliance teams. Four tabs show CAT I/II/III finding counts and average compliance, the benchmark catalog with scan launches, scan results with rule-level outcomes, and a remediation queue with auto-remediate for CAT I findings.

**Functions:**
- `STIGCompliance` — Top-level page that fetches dashboard/benchmarks/scans/results/remediations and wires `runScan` and `autoRemediate` mutations.
- `DashboardTab` — Renders KPI cards, finding-by-severity breakdowns, compliance-by-benchmark bars, recent scans, and top failing rules.
- `BenchmarksTab` — Lists STIG benchmarks with platform/version/finding counts and a per-benchmark Run Scan button.
- `ScanResultsTab` — Renders the scan history with expandable rows showing per-rule pass/fail/NA results.
- `RemediationTab` — Renders the remediation queue with severity filter and a button to auto-remediate CAT I findings.
- `KPICard` — Reusable colored KPI tile showing label, value, and icon.
- `FindingSummary` — Reusable card displaying a single severity bucket's count with severity styling.
- `getSeverityColor` — Returns badge color classes for STIG severity (CAT I / CAT II / CAT III).
- `getStatusColor` — Returns badge color classes for scan and rule statuses.

### PrivacyDashboard
**Purpose:** GDPR/CCPA workspace for privacy and DPO teams. Five tabs let users intake and track Data Subject Requests, run Privacy Impact Assessments, look up consent records, maintain Records of Processing Activities, and report data breaches/incidents.

**Functions:**
- `statusBadgeClass` — Maps a workflow status to a colored badge class.
- `riskBadgeClass` — Maps a risk level to a colored badge class.
- `severityBadgeClass` — Maps an incident severity to a colored badge class.
- `extractItems` — Internal helper that normalizes an API response into an array.
- `PrivacyDashboard` — Top-level page that holds form state for all five workflows and runs create mutations for DSR/PIA/Consent/ROPA/Incident.

### DLPDashboard
**Purpose:** Data-protection console for managing DLP end-to-end. Four tabs show enforced policies, open data-exfiltration incidents, configured classification categories, and reporting, with export and a New Policy modal.

**Functions:**
- `getSeverityColor` — Returns Tailwind classes for DLP severity badges.
- `getStatusColor` — Returns Tailwind classes for DLP status pills.
- `DLPDashboard` — Top-level page that loads policies, incidents, and classifications, derives summary metrics, and renders the four tabs with create/export.

### RiskQuantification
**Purpose:** FAIR-style cyber risk quantification workspace. Four tabs let risk managers browse scenarios, view loss-exceedance analysis, review the scored risk register, and inspect mitigating controls per scenario with JSON export and a New Scenario modal.

**Functions:**
- `getSeverityColor` — Returns Tailwind classes for severity badges.
- `getRiskColor` — Returns Tailwind classes for a numeric risk score using 80/60/40 thresholds.
- `getRiskLabel` — Returns a textual risk label for a numeric risk score.
- `formatCurrency` — Formats a dollar value into compact `$X.XM` / `$XK` / `$X` strings.
- `RiskQuantification` — Top-level page that loads scenarios and loss-exceedance analysis and renders the four tabs.

### Reports
**Purpose:** Executive reporting workspace for SOC managers. Users pick one of three report types (Alerts, Incidents, Executive Summary), choose a date range, preview inline, and export as CSV, PDF (browser print), or JSON.

**Functions:**
- `Reports` — Top-level page that fetches stats, manages report state, renders previews, and triggers exports.
- `handleExport` — Builds the report payload for the selected type/range and exports as JSON, CSV, or printable HTML.
- `downloadBlob` — Triggers a browser download of a Blob with the given filename via an anchor click.
- `convertToCSV` — Flattens the report payload into a CSV string.

### Analytics
**Purpose:** SOC metrics and KPI view with total alerts, active incidents, MTTR, and active IOCs as KPI cards plus a 7-day alert-trends chart, severity distribution, top sources, top attackers, and incident-type counts.

**Functions:**
- `Analytics` — Top-level page that fetches and merges alerts/incidents stats into a unified metrics shape.
- `KPICard` — Reusable KPI tile showing title, value, change indicator with optional inverted polarity, and a colored icon.
- `SeverityBar` — Renders a single severity row with a proportional progress bar.
- `AlertTrendsChart` — Renders the 7-day alert-trends visualization from `{date, count}` points.

---

## Security Operations

### WarRoom
**Purpose:** Incident response coordination page where SOC commanders spin up "war rooms" tied to incidents, run real-time chat with responders, track action items with priorities and due dates, and archive rooms after response. Keeps stakeholders aligned and produces an auditable timeline of decisions.

**Functions:**
- `formatTime` — Internal helper for rendering a date string as an HH:MM clock time.
- `formatDateTime` — Internal helper for rendering a date string as a short month/day/time label.
- `WarRoom` — Top-level page rendering tabs for active rooms, action items, and archived rooms plus modals to create rooms, post chat, and assign actions.
- `handleSendMessage` — Sends the typed chat input into the selected room via the sendMessage mutation and clears the input.

### Remediation
**Purpose:** Hub for automated and manual remediation actions. Analysts browse policies, monitor execution history, approve or reject pending actions, fire quick actions (block IP, isolate host, disable account, quarantine file), and configure integrations like firewalls, EDR, AD, and ticketing.

**Functions:**
- `Remediation` — Top-level page rendering dashboard/policies/executions/quick-actions/integrations tabs.
- `blockIPMutation` — Mutation that POSTs to `/remediation/block-ip` to push a temporary firewall block.
- `isolateHostMutation` — Mutation that POSTs to `/remediation/isolate-host` to network-isolate a host via EDR.
- `disableAccountMutation` — Mutation that POSTs to `/remediation/disable-account` to disable an AD user.
- `quarantineFileMutation` — Mutation that POSTs to `/remediation/quarantine-file` to remove a file from a host.
- `handleBlockIP` — Validates IP input and triggers the block-IP mutation with chosen duration.
- `handleIsolateHost` — Validates hostname and triggers host isolation with an optional reason.
- `handleDisableAccount` — Validates username and triggers account disable with optional password-reset flag.
- `handleQuarantineFile` — Validates host and file path and triggers the quarantine-file mutation.
- `renderDashboard` — Renders summary stat cards plus execution-timeline and action-type charts.
- `renderPolicies` — Renders the policy list with filters, enable/disable toggles, and a create-policy modal trigger.
- `renderExecutions` — Renders the execution history table with filters, expansion rows, and pending-approval queue.
- `renderQuickActions` — Renders the four manual quick-action panels.
- `renderIntegrations` — Renders configured integrations with health status and a test/add modal.
- `renderLoading` — Shared loading spinner block used across tabs.
- `LoadingState` — Presentational component showing a centered spinner used as the dashboard fallback.

### ThreatHunting
**Purpose:** Workspace for proactive threat hunters to track hunt sessions, manage hypotheses (MITRE-tagged, prioritized), review findings, maintain Jupyter-style notebooks, and instantiate hunts from templates. Covers the full hunt lifecycle from hypothesis through escalation.

**Functions:**
- `formatDuration` — Internal helper that converts a seconds value into a compact human-readable duration.
- `ThreatHunting` — Top-level page rendering hunts/hypotheses/findings/notebooks/templates tabs with associated CRUD modals.
- `toggleHuntMutation` — Pauses or resumes a hunt session via the sessions endpoint.
- `cancelHuntMutation` — Cancels an in-progress hunt session.
- `createHuntMutation` — Spawns a new hunt session from a chosen hypothesis ID.
- `createHypothesisMutation` — Creates a new hunting hypothesis with title, description, and priority.
- `instantiateTemplateMutation` — Creates a hypothesis from a template and switches to the hypotheses tab.
- `escalateFindingMutation` — Escalates a hunt finding into an incident.
- `updateHypothesisMutation` — Updates an existing hypothesis with edited fields.
- `deleteHypothesisMutation` — Deletes a hypothesis by ID and refetches the list.
- `activateHypothesisMutation` — Marks a hypothesis active so it can drive a new hunt.
- `createNotebookMutation` — Creates a new hunting notebook tied to a session ID.
- `duplicateNotebookMutation` — Clones a notebook, appending "(Copy)" to its title.
- `StatsCard` — Presentational sub-component displaying a labeled metric with icon and color.

### ThreatIntel
**Purpose:** Threat-intelligence console where analysts look up indicators (IP, domain, URL, hash, email) against aggregated feeds, browse the IOC database with filters, and manage external feed subscriptions including manual sync.

**Functions:**
- `IndicatorDetailContent` — Sub-component fetching and rendering full metadata for a selected IOC.
- `ThreatIntel` — Top-level page rendering Lookup, Feeds, and IOC database tabs with search and feed sync.
- `lookupMutation` — POSTs an indicator value and type to `/threat-intel/lookup` and renders the reputation result.
- `syncFeedMutation` — Triggers a manual sync on a single threat feed and refetches.
- `handleSearch` — Form-submit handler that fires the lookup mutation when the input is non-empty.
- `getReputationColor` — Internal helper for picking a Tailwind class based on reputation verdict.

### ThreatModeling
**Purpose:** Application threat-modeling tool where security architects create models (STRIDE, PASTA, attack tree), enumerate components, capture identified threats with risk scoring, attach mitigations, and run automated STRIDE analysis.

**Functions:**
- `riskColor` — Internal helper mapping a numeric risk score to a text color class.
- `riskBg` — Internal helper mapping a numeric risk score to a background color class.
- `formatDate` — Internal helper for short locale date strings.
- `capitalize` — Internal helper turning snake_case into Title Case.
- `ThreatModeling` — Top-level page handling the model list, detail view, and creation/add-threat modals.
- `createModelMutation` — Creates a new threat model with name, application, methodology, and description.
- `deleteModelMutation` — Deletes a threat model and resets detail view if selected.
- `addThreatMutation` — Adds a threat to the selected model with STRIDE category, severity, likelihood, impact.
- `runStrideMutation` — Calls the backend STRIDE analyzer to auto-generate threats for the current model.
- `openModel` — Selects a model ID and switches the page into detail view.

### DFIRDashboard
**Purpose:** Digital forensics and incident response workspace where investigators create cases, attach evidence, view case timelines, manage legal holds with custodians, and review metrics like active cases and average resolution time.

**Functions:**
- `getSeverityColor` — Internal helper returning a Tailwind class for a severity label.
- `getStatusColor` — Internal helper returning a Tailwind class for a case status.
- `safeUpper` — Internal helper that uppercases a value, tolerating null.
- `safeLocale` — Internal helper that formats a value as a locale date string with fallback.
- `formatBytes` — Internal helper converting a byte count into a human-readable size.
- `extractItems` — Internal helper that normalizes a paginated or array API response.
- `DFIRDashboard` — Top-level page rendering Cases, Evidence, Timeline, Artifacts, and Legal Holds tabs plus CRUD modals.
- `createCaseMutation` — Creates a new DFIR case and invalidates the cases query.
- `editCaseMutation` — Updates a case's title, description, severity, and status.
- `editHoldMutation` — Updates a legal hold's type, status, and custodians list.
- `resetNewCaseForm` — Resets the New Case modal fields and error message.
- `handleCreateCase` — Validates and triggers the create-case mutation.
- `handleViewCase` — Opens a case's detail panel and stores it as the active case.
- `handleEditCase` — Loads a case into the edit form and opens the edit modal.
- `handleViewEvidence` — Opens the evidence detail viewer for a chosen item.
- `handleDownloadEvidence` — Downloads the evidence blob, parses content-disposition, and triggers a browser save.
- `handleViewHold` — Opens the legal hold detail viewer.
- `handleEditHold` — Loads a legal hold into the edit form and opens the modal.
- `computeAvgResolution` — Computes mean resolution days from closed cases when no dashboard value is available.

### AttackSimulation
**Purpose:** Breach-and-attack-simulation console where red and purple teams launch atomic, chain, adversary-emulation, or purple simulations, browse the MITRE ATT&CK technique library, manage adversary profiles, and track posture/detection trends.

**Functions:**
- `formatDuration` — Internal helper producing an "Xh Ym" string from start/end timestamps or raw seconds.
- `showNotification` — Lightweight toast stub that logs success/error messages to the console.
- `AttackSimulation` — Top-level page with dashboard/simulations/techniques/adversaries/posture tabs plus a new-simulation modal.

### Playbooks
**Purpose:** Operator-facing catalog for runtime SOAR playbooks. Lists playbooks with status and trigger-type filters and lets analysts create, view, execute, or delete playbooks with basic execution metadata.

**Functions:**
- `Playbooks` — Top-level page that fetches paginated playbooks and orchestrates the create/details/execute modals.
- `fetchPlaybooks` — Calls `playbooksApi.list` with current filters and pagination.
- `handleDelete` — Confirms then deletes a playbook and refreshes the list.
- `handleExecute` — Sets the selected playbook and opens the execution modal.
- `CreatePlaybookModal` — Sub-component modal that collects new-playbook fields and submits via the API.
- `PlaybookDetailsModal` — Sub-component modal displaying full playbook metadata, steps, and run history.
- `ExecutePlaybookModal` — Sub-component modal that captures execution inputs and triggers a run.

### PlaybookBuilder
**Purpose:** Visual workflow designer landing page showing a Playbooks tab, a curated Templates library, and an Executions tab. Automation engineers create new playbooks via prompt, browse templates, search across categories, and review past runs.

**Functions:**
- `getStatusColor` — Internal helper returning a Tailwind class for a playbook or execution status.
- `getCategoryIcon` — Internal helper returning the lucide icon matching a playbook category.
- `PlaybookBuilder` — Top-level page that loads playbooks, templates, and executions and renders create/preview/detail UIs.

### AgenticSOC
**Purpose:** Operator console for autonomous AI agents running inside the SOC. Shows live agents, ongoing AI investigations, the OODA-style reasoning chain, approval queue, AI alert triage, anomaly detection, predictions, managed ML models, and an interactive chat panel.

**Functions:**
- `AgenticSOC` — Top-level page rendering agents/investigations/reasoning/approvals/triage/anomalies/predictions/models tabs and chat panel.
- `showStatus` — Displays a transient success/error toast for four seconds.
- `handleTriage` — Triggers an AI alert-triage run and refreshes the triaged-alerts list.
- `handleAnomalyAction` — Confirms or dismisses an anomaly and updates local state.
- `handleTrainModel` — Kicks off a training run for the selected ML model.
- `handleChatSend` — Sends the operator's chat input to the agentic backend and appends the streamed response.
- `handleApprove` — Approves a pending agent action and removes it from the queue.
- `handleDeny` — Denies a pending agent action and removes it from the queue.

### PurpleTeam
**Purpose:** Live purple-team workbench where a red operator picks an agent and a safe MITRE technique, fires it as an atomic test, and watches a real-time WebSocket timeline correlating SIEM detections against fired techniques.

**Functions:**
- `PurpleTeam` — Top-level page maintaining the WebSocket subscription, fired-technique set, and the selector/fire/timeline UI.
- `firedTechniquesRef` — Mutable ref holding MITRE technique IDs fired this session, used to flag correlated events.
- `fireTechnique` — Looks up the chosen technique's test command and POSTs `run_atomic_test` to the selected agent.

### LiveResponse
**Purpose:** Live forensics and IR console where responders pick an active agent, choose an IR action (collect processes, kill PID, isolate host, quarantine file, memory dump), and issue commands with high-risk actions held in a pending-approval queue.

**Functions:**
- `ageText` — Internal helper converting an ISO timestamp into a "Xs/m/h/d ago" relative label.
- `LiveResponse` — Top-level page rendering agent picker, action selector, pending-approval queue, recent commands, and reject modal.
- `issueCommand` — Validates the JSON payload and POSTs an agent command to `/agents/{id}/commands`.
- `approve` — Approves a pending command via the approve endpoint with an optional reason.
- `reject` — Rejects a pending command via the reject endpoint with the supplied reason.

---

## Telemetry & Intelligence

### SIEMDashboard
**Purpose:** Central SIEM console for ingesting, searching, and triaging log events. SOC analysts run ad-hoc and saved queries, manage Sigma-style detection rules, monitor data-source connectors, view correlated incidents, and watch a live tail.

**Functions:**
- `SIEMDashboard` — Top-level page owning tab state, queries, mutations, and rendering for the six SIEM tabs.
- `fetchLiveLogs` — Polls `/siem/logs/search` every 3 seconds while live tailing is on.
- `toggleRuleMutation` — PUTs an enabled/disabled flag to a detection rule and refreshes caches.
- `saveSearchMutation` — Saves the current query plus filters to `/siem/saved-searches`.
- `runSavedSearchMutation` — Executes a stored saved search by ID.
- `importRuleMutation` — POSTs pasted Sigma YAML to bulk-load detection rules.
- `collectorStartMutation` / `collectorStopMutation` — Start or stop the SIEM log collector daemon.

### DataLakeDashboard
**Purpose:** Operations console for the security data lake. Data engineers register sources, monitor ingestion rates, run ad-hoc SQL/KQL/SPL queries, browse the catalog, and inspect storage tier capacity (Hot/Warm/Cold/Archived).

**Functions:**
- `DataLakeDashboard` — Top-level page holding tab state, modals, and React Query hooks for sources/pipelines/catalog plus query execution.
- `stats` — Derives active source count, events/sec, estimated storage TB, and active pipeline count.
- `storageBreakdown` — Distributes total estimated storage across the four tiers and formats labels.
- `ingestTrendData` — Builds a 5-point hourly ingestion-rate series for the chart.
- `pipelineHealthData` — Maps pipelines into a bar-chart series of success vs failure percentages.
- Inline query submit handler — POSTs the typed query to `/data-lake/query` and renders the JSON response.
- Inline new-source form handler — POSTs source fields to `/data-lake/sources`.

### UEBADashboard
**Purpose:** User and Entity Behavior Analytics console for SOC analysts and insider-threat teams to spot risky users, hosts, and service accounts. Users review risk stats, top high-risk entities, filterable inventory, triage risk alerts, manage peer groups, and inspect per-entity behavior timelines.

**Functions:**
- `UEBADashboard` — Top-level component managing tab state, filters, selection, and React Query data for dashboard/entities/alerts/peer-groups.
- Inline alert Investigate handler — PUTs status `investigating` to `/ueba/alerts/{id}/status`.
- Inline alert Escalate handler — POSTs `/ueba/alerts/{id}/escalate` to link the alert to a SOAR incident.
- Inline Auto-Cluster handler — POSTs `/ueba/peer-groups/auto-cluster` to regenerate peer groupings.

### ITDRDashboard
**Purpose:** Identity Threat Detection and Response page for IAM and SOC teams. Shows active identity threats mapped to MITRE, exposed credentials, anomalous access events, and privileged access activity with MFA coverage KPI.

**Functions:**
- `ITDRDashboard` — Top-level component owning all state for tabs, records, modals, and detail selection.
- `getSeverityColor` / `getStatusColor` — Map severity and lifecycle status strings to Tailwind badge classes.
- `loadData` — Fetches threats, credential exposures, access anomalies, privileged access, and identities in parallel.
- `handleCreateThreat` — Submits the new-threat form and prepends the result to the list.
- `handleViewThreat` / `handleEditThreat` — Open a threat in the detail drawer.
- `handleViewExposure` / `handleViewAnomaly` / `handleViewAccess` / `handleEditAccess` — Open records in the appropriate modal.
- `renderEmptyState` — Returns a centered shield-icon empty state with a custom message.

### DarkWebMonitor
**Purpose:** Dark web threat intelligence console for brand and threat-intel analysts. Users create keyword monitors, review findings on illicit marketplaces and forums, track exposed corporate credentials, and follow brand impersonation threats.

**Functions:**
- `DarkWebMonitor` — Top-level component holding monitor/finding/credential/threat lists and modal state.
- `getSeverityColor` / `getStatusColor` — Tailwind class mappers for severity and status badges.
- `loadData` — Parallel fetch of alerts, credential leaks, brand monitors, and monitors.
- Inline monitor delete handler — Confirms then calls `darkwebApi.deleteMonitor`.
- Inline Take Action / Details finding buttons — Open the action or detail modal.

### DeceptionTech
**Purpose:** Deception technology console for deploying and operating honeypots, honey tokens, honeyfiles, and deception campaigns. Shows stats, recent interactions, decoy management, token generation, attacker interaction triage, and campaign effectiveness.

**Functions:**
- `DeceptionTech` — Top-level component owning tab state, modal state, form state, and React Query hooks.
- Query hooks (dashboard, decoys, tokens, interactions, campaigns) — Each fetches a `/deception/*` endpoint with try/catch fallback.

### ContainerSecurity
**Purpose:** Container and Kubernetes security console for cloud-native engineers. Reviews fleet KPIs, high-risk images with vuln breakdowns and signing status, K8s cluster audits, misconfiguration findings, and runtime alerts with scan/audit/remediate actions.

**Functions:**
- `ContainerSecurity` — Top-level component managing tab state, search, selection, and all queries/mutations.
- `severityColor` / `complianceColor` / `alertStatusColor` / `findingStatusColor` — Tailwind class mappers for badges.
- `scanImageMutation` — POSTs to trigger a fresh image scan and invalidates caches.
- `auditClusterMutation` — POSTs to run a cluster compliance/security audit.
- `remediateFindingMutation` — POSTs to auto-remediate a finding.

### OTSecurityDashboard
**Purpose:** OT/ICS security console for industrial control system defenders monitoring PLCs, RTUs, HMIs, SCADA, and engineering workstations. Shows assets with vendor/protocol/zone metadata, triages OT-specific alerts, visualizes the Purdue model, and exports inventory + alerts.

**Functions:**
- `OTSecurityDashboard` — Top-level component holding assets/alerts/zones/Purdue map state.
- `getSeverityColor` / `getStatusColor` — Tailwind class mappers for severity and status.
- `getPurdueLevel` — Returns label, color, and description for Purdue model levels 0-5.
- `loadData` — Parallel fetch of assets, alerts, zones, and Purdue map via `otsecurityApi`.
- Inline export button handler — Bundles data into a JSON blob and triggers a download as `ot-security-report.json`.

### APISecurityDashboard
**Purpose:** API security posture console focused on OWASP API Top 10 compliance and runtime anomaly detection. Shows KPIs, API inventory with risk scatter plot, vulnerability cards, enforcement policies, anomaly detection trends, and OWASP compliance bars.

**Functions:**
- `APISecurityDashboard` — Top-level component owning tab/filter/modal state and queries for inventory/vulnerabilities/policies/anomalies.
- `stats` — Computes total APIs, shadow count, OWASP violation count, and anomaly count.
- `filteredAPIs` — Filters the API inventory by public/private/all selection.
- `owaspCompliance` — Buckets vulnerabilities into OWASP API Top 10 categories with pass/fail counts.
- `riskTrendData` — Builds a 4-week trend of critical/high/medium vulnerability counts.
- `apiScatterData` — Maps APIs to `{endpoints, riskScore}` points for the scatter chart.
- `anomalyTrendData` — Bins anomalies by hour for the trend line chart.
- Inline new-API form submit handler — POSTs service name, base URL, method, and path to register an API.

### SupplyChainDashboard
**Purpose:** Software supply chain security console for AppSec and procurement teams. Browses SBOMs with format/version/component count, downloads CycloneDX JSON, manages components, reviews supply chain risks, and tracks vendor assessments.

**Functions:**
- `SupplyChainDashboard` — Top-level component holding SBOMs/components/vendors/risks state and managing tab/search/modal flow.
- `getSeverityColor` / `getStatusColor` — Tailwind class mappers for severity and status badges.
- `loadData` — Parallel fetch of SBOMs, vendor assessments, risks, and components.
- Inline SBOM Download handler — Calls `supplychainApi.downloadSBOM` and triggers a browser download.
- Inline new-component form submit handler — POSTs name/version/license to `/supplychain/components`.

---

## Exposure, Risk & Workflow

### ExposureManagement
**Purpose:** Single-pane exposure-management console with six tabs (dashboard, assets, vulnerabilities, remediation, attack surface, compliance). Supports search, filters, charts of exposure trends, top risky hosts, and modals to import data or open remediation tickets.

**Functions:**
- `getSeverityColor` — Maps severity to Tailwind badge classes.
- `getRiskColor` — Maps a numeric 0-100 risk score to a colored bucket.
- `getStatusColor` — Maps status strings to a colored pill.
- `ExposureManagement` — Top-level page holding tab/filter state, running loaders for all `/exposure/*` endpoints, and rendering all six tabs plus modals.

### VulnManagement
**Purpose:** Dedicated vulnerability-lifecycle workspace where vuln managers track CVE findings, scan profiles, patch operations, exceptions, and CISA KEV entries. Summarizes critical vuln count, open findings, MTTR, and SLA compliance with modals to create/edit records.

**Functions:**
- `getSeverityColor` — Returns Tailwind class keyed by severity.
- `getStatusColor` — Returns Tailwind class for scan/patch operation status.
- `VulnManagement` — Top-level page loading vulnerabilities and patch operations, computing breakdowns, and rendering five tabs plus modals.

### ZeroTrustDashboard
**Purpose:** Operations dashboard for a zero-trust program showing CISA-style maturity score, pillar health, device trust scores, access decisions, micro-segmentation, and policies across five tabs.

**Functions:**
- `getMaturityColor` — Returns a Tailwind class for a maturity level.
- `getStatusColor` — Returns a Tailwind class for status pills across tabs.
- `ZeroTrustDashboard` — Top-level page loading dashboard/device/devices/segments/policies queries and owning assess-devices and evaluate-access mutations.
- `OverviewTab` — Renders maturity score, pillar breakdown, and KPIs.
- `AccessControlTab` — Shows recent access decisions with filtering and the evaluate-access form.
- `DeviceTrustTab` — Lists devices with trust scores and compliance checks, triggers bulk reassessment.
- `SegmentationTab` — Lists micro-segments with members, protocols, and violation counts.
- `PoliciesTab` — Lists zero-trust policies with type, risk threshold, MFA/device-trust requirements, and state.
- `DecisionChart` — Visualizes the allowed/denied/challenged access decision split.
- `StatCard` — Reusable KPI tile showing a labeled number with icon and accent.
- `CheckItem` — Tiny row showing a compliance check label with pass/fail indicator.

### IntegrationMarketplace
**Purpose:** Connector marketplace and lifecycle manager where SOC engineers browse, install, configure, test, and monitor third-party integrations (SIEM, EDR, ticketing) and the webhooks they expose. Four tabs cover catalog, installed, executions, and webhooks.

**Functions:**
- `getHealthColor` — Maps a connector health string to a Tailwind badge class.
- `getStatusColor` — Maps execution/webhook status to a Tailwind badge class.
- `IntegrationMarketplace` — Top-level page loading connectors and installed integrations, computing KPIs, driving install/test/delete calls, and rendering all four tabs plus modal.

### TicketHub
**Purpose:** Cross-module unified ticketing console aggregating incidents, remediation tickets, POAMs, case tasks, and action items into one list view, kanban board, and automation-rule editor. Drives cross-module visibility and workflow automation.

**Functions:**
- `sourceIcon` — Returns the lucide icon for a given source type.
- `formatDate` — Formats an ISO date string into "Mon D, YYYY".
- `formatDateTime` — Formats an ISO date string into "Mon D, HH:MM".
- `sourceLabel` — Returns the human-readable label for a source type slug.
- `StatCard` — Reusable KPI tile with label, value, icon, and accent.
- `Badge` — Small inline pill for priority, status, and source-type labels.
- `Spinner` — Centered loading spinner used while queries are fetching.
- `EmptyState` — Centered message block shown when a list or column has no tickets.
- `DetailPanel` — Slide-over panel showing a selected ticket's full detail, comments, and activity timeline.
- `KanbanCard` — Card representing one ticket on the kanban board with view button and Move dropdown.
- `CreateRuleModal` — Modal form to create an automation rule with name, trigger, JSON conditions, and JSON actions.
- `TicketHub` — Top-level page owning tab/filter/pagination state, running dashboard/list/kanban/rules queries and mutations.

### PhishingSimulation
**Purpose:** Phishing-simulation and security-awareness console. Users see active campaigns, click/report rates, and average awareness as KPI tiles, then drill into five tabs for campaigns, templates, target groups, awareness scores, and training modules.

**Functions:**
- `extractData` — Internal helper that unwraps a paginated `{items: [...]}` response.
- `safeRate` — Computes a percentage from numerator/denominator, returning "0.0" when denominator is zero.
- `PhishingSimulation` — Top-level page loading campaigns, templates, target groups, and awareness scores and owning create mutations.

### AgentManagement
**Purpose:** Endpoint-agent control plane for managing PySOAR's unified BAS, IR, and Purple Team agents installed on customer hosts. Shows active/offline counts, capability breakdowns, commands in flight, approval queue, agent table, and recent commands with live WebSocket updates.

**Functions:**
- `formatAge` — Converts an ISO timestamp into a "Ns/Nm/Nh/Nd ago" relative-time string.
- `AgentManagement` — Top-level page loading dashboard and agent-list with 5-second polling and WebSocket invalidation.
- `submitEnroll` — Handler that POSTs the enrollment form to `/agents/enroll` and stores the returned one-time token.
- `copyToken` — Copies the issued enrollment token to the clipboard and flashes a "Copied!" confirmation.
- `StatTile` — Reusable KPI tile showing label, value, and accent-colored icon.

---

*Generated against `main` at commit `37c6c7a` — 52 pages documented. Updates should be made alongside the page source so this file stays in sync.*
