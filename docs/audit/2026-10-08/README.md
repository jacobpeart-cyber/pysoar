# Frontend-to-backend feature audit, 2026-10-08

Every page in the frontend was traced feature by feature (tab, widget, table, chart, button, form, action) from its API call to the backend handler to the table or integration behind it, and graded:

* REAL: backed by stored data or a real integration; errors surface honestly.
* PARTIAL: works but materially incomplete (ignored filters, wrong counts, status changed without the work).
* STUB: honest not-implemented or empty state.
* FAKE: hardcoded, synthetic, computed from nothing, or success returned without work.
* BROKEN: calls a missing route, wrong shape, or crashes.
* UI-ONLY: a visual element with no data behind it that pretends to have data.

The mechanical contract diff that preceded it is in `../frontend-backend-contract-2026-10-08.json` (rerun with `scripts/contract_diff.py`): 1134 served routes, 486 distinct frontend calls, 31 frontend calls with no route, 677 routes with no UI.

| Area | Features | REAL | PARTIAL | STUB | FAKE | BROKEN | UI-ONLY | Table |
|---|---|---|---|---|---|---|---|---|
| Core SOC (Dashboard, Alerts, Incidents, WarRoom, Playbooks, PlaybookBuilder, Remediation, TicketHub, Assets, Reports, Analytics) | 142 | 57 | 44 | 1 | 14 | 22 | 4 | [core-soc.md](core-soc.md) |
| Threat Intel, Dark Web | 47 | 19 | 14 | 0 | 2 | 9 | 3 | [intel-detection-A.md](intel-detection-A.md) |
| SIEM, Threat Hunting | 54 | 5 | 19 | 1 | 8 | 21 | 0 | [intel-detection-B.md](intel-detection-B.md) |
| UEBA, ITDR | 32 | 11 | 14 | 0 | 1 | 4 | 2 | [intel-detection-C.md](intel-detection-C.md) |
| DFIR, Deception | 31 | 6 | 10 | 0 | 4 | 11 | 0 | [intel-detection-D.md](intel-detection-D.md) |
| Attack Simulation, Purple Team, Phishing | 42 | 10 | 17 | 0 | 5 | 10 | 0 | [intel-detection-E.md](intel-detection-E.md) |
| Compliance, FedRAMP, Audit Evidence, Audit Logs, STIG, Data Lake, Privacy, DLP | 118 | 24 | 24 | 4 | 32 | 25 | 9 | [compliance-audit.md](compliance-audit.md) |
| Vuln Mgmt, Exposure, Container Security, Supply Chain, Threat Modeling, Risk Quant, Zero Trust, API Security, OT Security | 179 | 21 | 45 | 4 | 53 | 41 | 15 | [posture-risk.md](posture-risk.md) |
| Agentic SOC, Agents, Live Response, Integrations, Settings, Users, Organizations, API Keys, Profile, Login | 91 | 31 | 27 | 0 | 15 | 10 | 8 | [platform-agentic.md](platform-agentic.md) |
| **Total** | **736** | **184** | **214** | **10** | **134** | **153** | **41** | |

Real features: 25%. Each table ends with its uncalled-route verdicts (expose, dead, fake-backend, broken) and a prioritised fix list; tenant-scoping and role-check gaps are listed per area.

## Cross-cutting findings

1. **No role checks on write routes** in most endpoint modules (`require_role` in `src/api/deps.py` is defined but almost never used); viewers can delete, approve, run scans, send phishing mail and isolate hosts.
2. **Tenant scoping is conditional**: the common `if org_id:` guard means a user with no organisation sees and writes every tenant's data; several modules (SIEM, hunting, playbooks, metrics, IOCs, teams, WebSocket channels) have no organisation filter at all; rows are often created without an organisation and then invisible to their creators.
3. **Errors are hidden as "no data"** (`aliases.py` `_safe_list`, many `.catch(() => [])` in pages), so failures look like empty states.
4. **Field-name mismatches** between pages and responses leave widgets permanently at zero or blank.
5. **Background work is not wired**: several task modules are not in the Celery include list or never scheduled; pages whose data only a task would create stay empty.
6. **Security defects found and fixed the same day**: DFIR evidence arbitrary file read (57fdd49), Zero Trust self-lockout (fd7c339); the compliance-evidence file read, data-lake SQL guard bypass, STIG import path parsing, forged audit-log writes, cross-tenant WebSocket channels and teams, SSRF via the generic HTTP connector and two scan routes, cross-tenant alert triage writes, and backup restore open to tenant admins are in the follow-on security wave.
