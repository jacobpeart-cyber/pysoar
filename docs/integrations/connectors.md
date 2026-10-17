# Connectors

This page lists every entry in the integration catalogue (`GET /api/v1/integrations/connectors`) and what it can do in this release. The catalogue is built from the code: `BUILTIN_CONNECTORS` in `src/integrations/engine.py` names the vendors, and for a connector with a class in `CONNECTOR_CLASS_MAP` (`src/integrations/connectors/`) the actions, fields, test call and verification statement come from the class attributes `ACTIONS`, `CONFIG_FIELDS`, `CREDENTIAL_FIELDS`, `TEST_CALL` and `VERIFICATION`. `tests/unit/test_connector_catalog_truth.py` fails if the two drift.

## Status

* **implemented** (10): a connector class ships. Install validates the declared required fields (422 `missing_fields` / `invalid_fields`, naming fields, never values), credentials are stored AES-256-GCM encrypted (`enc:v1:` envelope) and never returned, the declared actions are mirrored into `integration_actions` with their real `input_schema`, `POST /installed/{id}/test` runs the connector's read-only call, and `POST /installed/{id}/actions/{action_id}/execute` validates `input_data` against the action's `params_schema` (422 `invalid_parameters`) before calling the vendor.
* **log_ingest** (3): no connector class; the SIEM cloud poller (`src/siem/cloud_poller.py`) reads the stored credentials and pulls events with the vendor SDK on a schedule. Installable, no actions; the connection test answers 501 because the poller records `health_status` on every poll.
* **planned** (32): catalogue entry only, kept so the roadmap is visible. `installable: false`, no actions; install, test and execute answer 501 `{"error": "not_implemented", "detail": "<name> has no connector implementation in this release"}`. A row installed before this release reads `health_status: "unavailable"` and can still be deleted. The hourly health task records it `unavailable` without any network call.

Splunk, QRadar and Elastic are planned even though `src/siem/cloud_poller.py` has pollers for them: those pollers use an unpinned HTTP client with a `verify_tls` opt-out, so new installs are refused until they go through the pinned transport. Rows installed earlier keep being polled.

`rating`, `is_community` and `last_updated` in a catalogue response are not marketplace statistics (there is no marketplace service): they are always `null` / `false` / `null`. `install_count` is the calling organisation's installs of that connector (0 or 1).

## Transport and errors

Every HTTP call of an implemented connector goes through `PinnedTransport` (`src/integrations/netguard.py`): the vendor host is resolved once, internal, loopback, link-local, metadata and reserved addresses are refused, the connection goes to the vetted IP with the hostname in Host and TLS SNI, TLS verification stays on and redirects are not followed. A refused target is reported as `refused: target resolves to an internal address`. AWS Security Hub uses boto3 against AWS regional endpoints; the region is validated against the AWS region format. Only GET and HEAD requests are retried (three attempts) (on 429, 502, 503, 504 and connection errors).

A vendor error is a `failed` execution with the vendor's HTTP status (`http_status`) and a sanitised message (whitespace collapsed, known secret values and bearer / basic tokens redacted, at most 200 characters); an API that reports failure inside a 200 (Slack `ok: false`, a CrowdStrike `errors` list, a PagerDuty event without `status: success`) is also `failed`. An action name the connector does not declare is `failed` with `unknown action X; available: [...]` and no execution row (an execution row needs a real action row).

## Catalogue

`*` marks an action that changes the vendor's state (`side_effect`; its action row has `requires_approval: true`).

| Connector | Status | Verification | Read-only test call | Credentials | Config | Actions (side effect marked *) |
|---|---|---|---|---|---|---|
| AbuseIPDB (`abuseipdb`) | implemented | vendor docs, not verified against a live tenant | GET /api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1 | `api_key` (secret) | none | `check_ip`, `report_ip`*, `get_blacklist`, `check_block` |
| AWS Security Hub (`aws_security_hub`) | implemented | vendor docs, not verified against a live tenant | securityhub:DescribeHub | `access_key_id` (secret), `secret_access_key` (secret), `region` (optional) | none | `get_findings`, `batch_import_findings`*, `update_findings`*, `get_insight_results`, `list_enabled_standards`, `get_guardduty_findings`, `get_cloudtrail_events` |
| CrowdStrike Falcon (`crowdstrike`) | implemented | vendor docs, not verified against a live tenant | POST /oauth2/token (client credentials) | `client_id`, `client_secret` (secret) | `cloud` (optional) | `search_detections`, `get_device`, `search_hosts`, `contain_host`*, `lift_containment`*, `get_indicators`, `search_incidents` |
| Jira (`jira`) | implemented | vendor docs, not verified against a live tenant | GET /rest/api/3/myself | `domain`, `email`, `api_token` (secret) | none | `create_issue`*, `update_issue`*, `transition_issue`*, `add_comment`*, `search_issues`, `get_issue` |
| Microsoft Sentinel (`microsoft_sentinel`) | implemented | vendor docs, not verified against a live tenant | POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token, then GET the workspace (Workspaces - Get) | `tenant_id`, `client_id`, `client_secret` (secret), `subscription_id`, `resource_group`, `workspace_id` | none | `query_logs`, `list_incidents`, `update_incident`*, `list_alert_rules`, `create_bookmark`*, `run_playbook`* |
| PagerDuty (`pagerduty`) | implemented | vendor docs, not verified against a live tenant | GET /abilities | `api_token` (secret), `user_id` (optional) | `from_email` | `create_incident`*, `acknowledge_incident`*, `resolve_incident`*, `trigger_event`*, `list_oncall`, `get_service` |
| ServiceNow (`servicenow`) | implemented | vendor docs, not verified against a live tenant | GET /api/now/table/sys_user?sysparm_limit=1 | `instance`, `username`, `password` (secret) | none | `create_incident`*, `update_incident`*, `get_incident`, `search_incidents`, `create_change_request`*, `get_cmdb_ci` |
| Shodan (`shodan`) | implemented | vendor docs, not verified against a live tenant | GET /api-info | `api_key` (secret) | none | `host_lookup`, `search`, `dns_resolve`, `dns_reverse`, `exploits_search`, `get_ports` |
| Slack (`slack`) | implemented | vendor docs, not verified against a live tenant | POST /api/auth.test | `bot_token` (secret) | none | `send_message`*, `send_alert_notification`*, `create_channel`*, `invite_users`*, `upload_file`*, `list_channels` |
| VirusTotal (`virustotal`) | implemented | vendor docs, not verified against a live tenant | GET /api/v3/ip_addresses/8.8.8.8 | `api_key` (secret) | none | `scan_file`, `scan_url`, `scan_ip`, `scan_domain`, `get_behavior` |
| AWS CloudTrail (`aws_cloudtrail`) | log_ingest | vendor SDK docs, not verified against a live tenant | none | `aws_access_key_id` (secret), `aws_secret_access_key` (secret) | `region` (optional) | none |
| Azure Activity Log (`azure_activity_log`) | log_ingest | vendor SDK docs, not verified against a live tenant | none | `tenant_id` (secret), `client_id` (secret), `client_secret` (secret), `subscription_id` (secret) | none | none |
| GCP Cloud Logging (`gcp_cloud_logging`) | log_ingest | vendor SDK docs, not verified against a live tenant | none | `service_account_json` (secret) | `project_id` (optional), `log_filter` (optional) | none |
| AlienVault OTX (`alienvault_otx`) | planned | not implemented in this release | none | none | none | none |
| Aqua Security (`aqua`) | planned | not implemented in this release | none | none | none | none |
| Azure Active Directory (`azure_ad`) | planned | not implemented in this release | none | none | none | none |
| VMware Carbon Black (`carbon_black`) | planned | not implemented in this release | none | none | none | none |
| Google Chronicle (`chronicle`) | planned | not implemented in this release | none | none | none | none |
| Cisco ASA (`cisco_asa`) | planned | not implemented in this release | none | none | none | none |
| Palo Alto Cortex XDR (`cortex_xdr`) | planned | not implemented in this release | none | none | none | none |
| CyberArk (`cyberark`) | planned | not implemented in this release | none | none | none | none |
| Elastic Security (`elastic`) | planned | not implemented in this release | none | none | none | none |
| Falco (`falco`) | planned | not implemented in this release | none | none | none | none |
| Fortinet FortiGate (`fortinet`) | planned | not implemented in this release | none | none | none | none |
| GCP Security Command Center (`gcp_security_command_center`) | planned | not implemented in this release | none | none | none | none |
| GitHub Actions (`github_actions`) | planned | not implemented in this release | none | none | none | none |
| GitLab CI (`gitlab_ci`) | planned | not implemented in this release | none | none | none | none |
| Graylog (`graylog`) | planned | not implemented in this release | none | none | none | none |
| GreyNoise (`greynoise`) | planned | not implemented in this release | none | none | none | none |
| Jenkins (`jenkins`) | planned | not implemented in this release | none | none | none | none |
| Microsoft Defender for Endpoint (`microsoft_defender`) | planned | not implemented in this release | none | none | none | none |
| Microsoft Teams (`microsoft_teams`) | planned | not implemented in this release | none | none | none | none |
| Nessus (`nessus`) | planned | not implemented in this release | none | none | none | none |
| Okta (`okta`) | planned | not implemented in this release | none | none | none | none |
| OpenVAS (`openvas`) | planned | not implemented in this release | none | none | none | none |
| Palo Alto Networks NGFW (`palo_alto_ngfw`) | planned | not implemented in this release | none | none | none | none |
| IBM QRadar (`qradar`) | planned | not implemented in this release | none | none | none | none |
| Qualys (`qualys`) | planned | not implemented in this release | none | none | none | none |
| Recorded Future (`recorded_future`) | planned | not implemented in this release | none | none | none | none |
| SentinelOne (`sentinelone`) | planned | not implemented in this release | none | none | none | none |
| Email (SMTP) (`smtp_email`) | planned | not implemented in this release | none | none | none | none |
| Splunk Enterprise (`splunk`) | planned | not implemented in this release | none | none | none | none |
| Sumo Logic (`sumo_logic`) | planned | not implemented in this release | none | none | none | none |
| Trivy (`trivy`) | planned | not implemented in this release | none | none | none | none |
| Wazuh (`wazuh`) | planned | not implemented in this release | none | none | none | none |

## Verification

None of these connectors has been exercised against a live vendor tenant in this repository: no vendor credentials are available to the project. Each implemented connector was written from the vendor's public API documentation (the endpoint is cited in a comment on each method) and is tested against faked vendor responses at the network boundary (`tests/unit/test_connector_test_connection.py`, `tests/unit/test_connector_actions_execute.py`). Hence every `verification` field reads "implemented from the vendor's public API documentation; not verified against a live tenant".

An operator verifies a connector in their own tenant like this:

1. Install it from the Integrations page (or `POST /api/v1/integrations/install`) with the fields listed above. Use a least-privilege account: read scopes first.
2. Press Test (`POST /api/v1/integrations/installed/{id}/test`). The response names the read-only call in `details.checked`; `healthy` means the vendor accepted the credential for that call. `unhealthy` carries the HTTP status (`details.http_status`) and a sanitised reason, also stored as the integration's `error_message`.
3. Run one read-only action (no `*` above), for example VirusTotal `scan_ip`, Jira `get_issue` or CrowdStrike `search_hosts`, from `GET /api/v1/integrations/installed/{id}/actions` and `.../actions/{action_id}/execute`, and compare the output with the vendor console. Only then grant write scopes and try a side-effect action on a test object.
