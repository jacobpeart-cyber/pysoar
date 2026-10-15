# Making PySOAR real: fix plan from the 2026-10-08 audit

Audience: JP and whoever executes the waves. Source: `README.md` in this folder (the matrix) and the per-area tables beside it. Grades: 736 features traced; 184 real, 214 partial, 153 broken, 134 fake, 41 UI-only, 10 stub.

Two rules govern every wave. Nothing ships that pretends: a feature is either backed by real data or a real integration, or it says so plainly (`NotImplementedError("Pending real integration with X")`, a disabled control with a truthful message, an empty state that names what is missing). And every change passes the repository's GTM checklist, with the lint ratchet, the runtime-defect lint gate, the contract diff (`scripts/contract_diff.py`) and the full test suite green.

## Wave 0, done 2026-10-08/09: live vulnerabilities

Two arbitrary file reads (DFIR evidence, compliance evidence), the data-lake SQL guard bypass (raw SQL now platform-superuser only), the Zero Trust self-lockout, forged audit-log writes, the STIG import path, backups open to tenant admins, cross-tenant WebSocket channels and teams, cross-tenant batch triage, SSRF through the generic HTTP connector and two scan routes, and cross-tenant bulk writes. Commits `57fdd49`, `fd7c339`, `80580c1`, `29df08e`, `fb334e1`.

Residuals carried into wave 1: the four default WebSocket channels still broadcast to every tenant; `/ai/triage/{id}` skips the organisation filter for users without one; the SSRF DNS check is pre-request (rebinding window).

## Wave 1: foundations (cross-cutting, before any module work)

1. **Tenant scoping is mandatory, not conditional.** Replace every `if org_id:` guard with a dependency that yields the caller's organisation or fails (403 `organization_required`); superusers pass an explicit organisation. Add `organization_id` where models lack it (AuditLog, HuntNotebook) with migrations and backfill rules; make row creation always stamp the organisation (SIEM rules, sources, hypotheses, sessions, findings, feed indicators, playbook executions, incidents created by escalation). Per-tenant default WebSocket channels.
2. **Roles on every write route.** Router-level dependencies: viewer read-only everywhere; analyst for operational writes; admin for configuration, scans against live hosts, phishing sends, containment; platform superuser for cross-tenant and host-level actions. `require_role` exists; `get_current_superuser` admits tenant admins and must not gate platform actions (`PlatformSuperUser` does). Tests per router.
3. **Errors surface.** Remove `_safe_list` and every `.catch(() => [])` / `allSettled -> {}` that turns failures into empty states; the UI shows a failure card with the error key. Fix the handlers that always 500 (UEBA entity risk/peers/baselines, correlation insert, FedRAMP control query, evidence schemas) rather than hiding them.
4. **Background work wired.** Add the missing task modules to the Celery include list (vulnmgmt, container_security, risk_quant, zerotrust, ot_security) and schedule or delete each task; delete tasks that return hard-coded zeros (intel tasks, deception stubs). The simulation task app and `src.database` import are fixed or removed.
5. **Settings are per tenant.** Stop writing tenant settings into the shared in-process config; persist per organisation and read where consumed (SMTP, Slack/Teams, enrichment keys, session timeout, security tab).
6. **Contract hygiene.** Delete the 31 dead frontend helpers and hooks; add the one missing route (`/playbook-builder/executions`); fix every field-name mismatch listed in the tables (Analytics, SIEM collector/stats, VulnManagement KEV and dashboard, Container image badges, Integration cards, ITDR summary, Simulation posture); the contract diff must report zero missing routes.

Gate: full suite green, contract diff zero missing, every mutating route has a role test, tenant-isolation suite extended to each router.

**Status, 2026-10-12: landed.** Kit `2bfbd39` (mandatory `OrganizationId`, migration 023, audit rows stamped, Celery include list, tenancy fixtures); fixtures `918aa7a`; detection `21c744d`; posture `9c1ecde`; core SOC `cc38185`; platform `1d121a6`; frontend `19eb02c`; transcript redaction performance `63015df`. 25 `tests/unit/test_tenancy_*.py` files; contract diff 0 missing; style debt 6829 against the 6974 baseline.

Decisions taken while landing it, for JP to confirm or reverse: agent action approve and rollback are admin-only (analysts could approve write-tier proposals before); viewers cannot run agent tools directly; OT active discovery is disabled until `OT_DISCOVERY_ALLOWED_CIDRS` is set, and even then confined to the tenant's zones with loopback, link-local and cloud-metadata ranges refused; a NULL `organization_id` on indicators and SIEM rules means a platform row (read-only for tenants); SIEM data-source configuration is admin-only.

Residuals carried into wave 2: `device_trust_profiles.device_id` is globally unique (per-tenant uniqueness needs a migration), so compliance overrides no longer create profiles; case child tables (notes, tasks, attachments, timeline) are scoped only through the parent incident; `itdr.py` still builds its agent context without an explicit organisation; the ATT&CK sync and the hunting template catalogue are platform-wide by design; the `Authorization: Bearer` redaction covers the header form only.

## Wave 2: core SOC made real

* Classic playbooks: containment steps call the endpoint agents or installed integrations (block IP, isolate host, disable user through the configured identity provider) or report `awaiting_integration`; failed steps fail the run; executions carry the organisation; `run_script` removed or sandboxed to admin with audit.
* Visual playbook builder: the engine constructor fixed; node handlers execute (HTTP action, agent command, integration action, notify) or are honest stubs; templates with zero nodes removed; the Run button starts a real execution.
* Remediation: schema fields aligned (`hostname`), integrations read the real installed-integration model, approve/reject bound to the logged-in approver with roles, effectiveness and timeline computed from executions, quick actions scoped and audited.
* Automation and TicketHub rules evaluated by a task, or removed.
* Analytics and metrics organisation-scoped, MTTR computed correctly, Dashboard IOC tile scoped.

## Wave 3: detection and intel made real

* SIEM: correlation events persisted correctly (the model fields), rule engine and correlation buffers keyed by organisation, log search and stats scoped, overview metrics derived from data (events per second from a real window), pipeline status from the collector and queue, rule validation that parses YAML, Create Rule that stores detection logic, data-source counters written by ingest.
* Hunting: pause/resume/cancel honoured by the executor; executor queries scoped; notebooks tenant-scoped; priority filter typed correctly.
* Threat intel: feed indicators stamped per organisation (or a platform scope the UI understands), lookups decrypt credentials, enrichment runs (VirusTotal, AbuseIPDB, OTX where keys exist) or reports `not_configured`, dark-web monitors search their own terms (HIBP is real; the global feeds are relabelled honestly as feed intel, not paste sites), IOC routes scoped.
* UEBA and ITDR: an ingestion path that creates entities and identities (SIEM bridge for UEBA; Okta/Entra/AD sync or CSV import for ITDR), the 500s fixed, ITDR actions call the identity provider or report `awaiting_integration`, metrics computed.
* DFIR and deception: evidence upload with real bytes and hashes, verify re-hashes, custody actor from the session; honeytokens that are real (value returned once, canary callback endpoint, trigger counts), decoys deployed through agents or honest about not being deployed; tasks real or removed.
* Simulation and phishing: posture per tactic computed from runs, BAS detection lookups scoped, Purple Team correlation with time window and host, phishing tracking endpoints (pixel and click) that exist, awareness scores derived from events, training catalogue real or removed.

**Status, 2026-10-14: wave 2 and wave 3 landed.** Wave 2 (core SOC): containment service `08fb5ea`, automation rules `9a07cc6`, remediation registry `9af9f30`, frontend `9ccb17d`, plus the review hardening (`51e1dc6`, `fd6ab93`, `928400a`, `bdbff10` outbound pinning). Wave 3 (detection and intel): intel/dark web `2ccfb82`, SIEM/hunting `8ee9d5d`, UEBA/ITDR with the guarded identity tool `96f7e42`, simulation/phishing `19d5004`, DFIR/deception `1737103`, hardening and task registration through `3a22b64`, frontend `907f9b2`. Migrations 024 to 029. Local suite 2467 green; CI green on the heads.

Decisions and residuals for JP: rule-triggered and policy-triggered containment never actuates an integration unattended (`manual_required`); identity-provider actions execute only after an admin approves the proposal; the Sigma engine refuses aggregations and `1 of` / `all of` constructs instead of importing inert rules; SIEM data-source and rule names are still unique platform-wide (schema change pending); honeytokens are real for url_canary, api_key, jwt_token and aws_key only; decoy deployment needs the `deploy_decoy` handler in the agent binary; Active Directory identities arrive by CSV (no LDAP connector); phishing tracking needs `PYSOAR_PUBLIC_URL` in prod; deployments behind an HTTPS proxy would fail TLS with the pinned transport.

## Wave 4: posture, risk and compliance made honest

* Vulnerability management: instances created by scanner import (the import fixed), KEV and dashboard fields aligned, patch and exception flows against instance ids.
* Exposure: scan import constructs the real model, discovery and import report real counts, risk scores written, charts from time series.
* Container security: cluster and image creation in the UI, scans scoped, CIS checks against the Kubernetes API or clearly marked as self-attested, findings deduplicated.
* Supply chain: OSV/NVD lookups for components, SBOM generation from real sources, compliance derived from checks.
* Risk quantification: FAIR analyses require stored inputs (no invented defaults), sampler corrected, page figures from the API only.
* Zero Trust: maturity from real configuration, device compliance fields returned, posture from agents.
* OT: simulated CVE catalogue replaced by a real feed (CISA ICS advisories) or removed; safe shutdown and segmentation audit either command real devices through agents or are honest stubs; dash-prefixed duplicates deleted.
* Compliance: attester asserts only what it checks (counts, configuration, evidence rows) and records "not assessed" otherwise; FedRAMP page reads the real control table; SSP and plans generated from stored system facts, not a template of a different architecture; ConMon status computed; readiness endpoints computed; STIG scans run through agents or are marked not run.
* Privacy and DLP: policies evaluated by a task over real data or marked inactive; DSR workflows real.

## Wave 5: expose what is already real

The uncalled-route tables mark routes as EXPOSE where the backend is real and the UI lacks the control: agentic run timeline, usage, policy events, evidence export, trust acknowledgement, SOC agent management; evidence upload with hashing; war-room join/leave and timeline; remediation playbooks and rollback; data-lake lineage and quality; STIG rule browser; and the create endpoints the posture pages need to ever show data.

## Wave 6: JP's extra features

To be filled in from JP's list. Each item gets the same treatment: real backend, real UI, tests, honest states, and a place in the compliance control map.

## Sizing and order

Wave 1 is the largest single piece and blocks the rest; it is cross-cutting and best done by two or three agents working router by router with a shared test pattern. Waves 2 to 4 are independent of each other and can run in parallel once wave 1 lands. Each wave ends with a deploy. Progress is measured by rerunning the audit grading on the touched pages and the contract diff, and the matrix in `README.md` is updated at the end of each wave.
