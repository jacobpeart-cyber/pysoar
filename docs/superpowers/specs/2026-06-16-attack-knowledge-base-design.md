# MITRE ATT&CK Knowledge Base + Agent-Driven Threat Hunting — Design

**Date:** 2026-06-16
**Status:** Draft (awaiting review)

## Goal

Replace the 8-entry hardcoded `MITRE_TECHNIQUE_PATTERNS` dict with the
**full MITRE ATT&CK knowledge base** (Enterprise + ICS domains), stored
as a real queryable graph, and build an agent-driven structured threat
hunt (PY-HUNT-001) on top of it.

This is two layers: **A — the ATT&CK KB foundation**, then **B — the
hunt capability** that consumes it.

---

## Layer A: ATT&CK Knowledge Base

### Why DB-backed (not in-memory)

The raw STIX is large (Enterprise 50 MB + ICS 3 MB). Loading it into
every process (api/worker/scheduler) on a 4 GB box would reintroduce the
OOM we just fixed. Parsed into normalized tables it's ~2,800 rows total —
cheap shared queries, zero per-process memory, survives restart, and
joinable to detection rules + findings. See [[prod_oom_hang_2026-05-20]].

### Data model (`src/attack/models.py`)

Core object tables (all carry the ATT&CK STIX id + the `Txxxx`/`Gxxxx`
external id, name, description, domain, `is_deprecated`, `version`,
`attack_version` for the dataset release):

- **AttackTactic** — 14 enterprise + ICS tactics (e.g. TA0006 Credential
  Access). Fields: stix_id, external_id, name, shortname, description.
- **AttackTechnique** — techniques AND sub-techniques. Fields: stix_id,
  external_id (`T1110` / `T1110.001`), name, description, domain,
  `is_subtechnique`, `parent_external_id`, `platforms` (JSON),
  `detection` (text), `data_source_refs` (JSON). Indexed on external_id.
- **AttackMitigation** — course-of-action (Mxxxx).
- **AttackGroup** — intrusion-set (Gxxxx) + aliases.
- **AttackSoftware** — malware/tool (Sxxxx) + type, aliases.
- **AttackDataSource** / **AttackDataComponent** — the data sources a
  technique is detectable in (this is what makes the "which data source
  should I hunt this in, and do we even have it?" check real).

Relationship/junction tables (from STIX `relationship` objects):

- **technique_mitigation** (mitigates)
- **group_technique** (intrusion-set uses technique)
- **software_technique** (software uses technique)
- **group_software** (group uses software)
- **technique_datacomponent** (data component detects technique)

A single **AttackSyncState** row tracks the loaded dataset version
(`attack_version`, `domains`, `synced_at`, object counts) so the seeder
is idempotent and we can show "ATT&CK vN loaded".

### Acquisition + seeding (`src/attack/loader.py`)

- Downloads a **version-pinned** release of `enterprise-attack.json` and
  `ics-attack.json` from MITRE's `attack-stix-data` GitHub repo. Pin a
  specific release tag (not `master`) for reproducibility; bump
  deliberately.
- Parses STIX objects → upserts by stix_id (idempotent): attack-pattern→
  technique, x-mitre-tactic→tactic, course-of-action→mitigation,
  intrusion-set→group, malware/tool→software, x-mitre-data-source/
  component→data source, `subtechnique-of`/`uses`/`mitigates`/`detects`
  relationships→junctions.
- **Not auto-run on every boot** (too heavy). Triggered by a management
  command and a `POST /attack/sync` endpoint (superuser only). First-run
  guard logs "ATT&CK KB empty — run sync" so the hunt degrades honestly
  if unseeded. Download failure leaves prior data intact.
- Bundled-gzip fallback is possible later if fully-offline seeding is
  wanted; default is download (prod has egress).

### Query service (`src/attack/service.py`)

- `get_technique(external_id)` → technique + tactics + mitigations +
  groups + data sources (the full context).
- `search(query)` → techniques/groups/software by name/id/alias.
- `extract_technique_ids(text)` → pull `Txxxx[.xxx]` from a hypothesis,
  validated against the KB (drops bogus/deprecated ids, maps deprecated
  → current where ATT&CK provides the revocation).
- `coverage(technique_ids)` → for each, which active DetectionRules list
  it (`detection_rules.mitre_techniques`) → real blind-spot map.

### API (`src/api/v1/endpoints/attack.py`, tenant-agnostic reference data)

- `GET /attack/techniques` (filter by tactic/platform/domain, paged)
- `GET /attack/techniques/{external_id}` (full context)
- `GET /attack/search?q=`
- `GET /attack/coverage` (techniques × detection-rule coverage for the org)
- `POST /attack/sync` (superuser — trigger/refresh load)
- `GET /attack/status` (loaded version + counts)

### Agent tools (`src/services/agent_tools.py`, read-only)

- `lookup_attack_technique(external_id)` — authoritative technique detail.
- `search_attack(query)` — find techniques/groups/software.
- `get_attack_coverage(technique_ids)` — detection-rule coverage/gaps.

Added to `INVESTIGATOR_READONLY_TOOLS`. Behavior→technique *inference*
stays with the LLM (it knows the matrix); these tools ground it with
authoritative data + your real coverage.

### Retire the hardcoded dict

`HuntQueryBuilder.MITRE_TECHNIQUE_PATTERNS` is deleted. Query-term
expansion now pulls technique names + data components from the KB
(authoritative) instead of 8 hand-typed keyword lists.

---

## Layer B: Agent-driven structured hunt (PY-HUNT-001)

Built on Layer A. (Full detail to expand after Layer A lands.)

- **`scope_hunt` tool** — hypothesis → KB technique validation, real
  detection-rule coverage/gaps, data-source availability (flags
  EDR/DNS as *not integrated* honestly), asset criticality for named
  hosts.
- **`structured_threat_hunt` skill** — scope → `run_threat_hunt` (real
  multi-source scan) → enrich IOCs → ATT&CK-map (LLM grounded in KB) →
  evidence-driven score → structured PY-HUNT-001 report with verdict +
  **approval-gated** recommendations (no auto-remediation).
- **`POST /agentic/hunts`** — kick off a hunt by hypothesis (tenant-
  scoped), returns the structured report.

---

## Testing (TDD throughout)

- Loader: parse a small fixture STIX bundle → correct techniques,
  sub-technique parenting, relationships; idempotent re-run; deprecated
  handling.
- Service: get_technique context, extract_technique_ids (valid/bogus/
  deprecated), coverage against seeded detection rules.
- Tools + endpoints: lookup/search/coverage shapes, auth on sync.
- Hunt skill: scope honesty (EDR/DNS flagged), end-to-end structured
  report, recommendations approval-gated.

## Sequencing

1. **Layer A** ships first and standalone (KB is useful on its own —
   powers detection-rule coverage views and grounds the investigator).
2. **Layer B** (hunt skill) lands after, consuming the KB.

Each ships via the corrected deploy procedure (git + `alembic upgrade
head` + restart) — the new tables need a migration. See
[[prod_deploy_via_git_and_migrations]].

## Out of scope (for now)

Mobile domain; ATT&CK Navigator layer export; per-phase analyst gating;
scheduled recurring hunts; auto-update of the ATT&CK version.
