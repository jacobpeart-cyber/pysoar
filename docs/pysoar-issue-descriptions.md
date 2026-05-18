# PySOAR Issue Descriptions

## Issue 1: Implement real connector action execution

### Summary
The current connector runtime path only executes generic HTTP calls based on provided input_data. Installed integration actions should instead use configured connector wrappers so Slack, VirusTotal, and other connectors execute through their real API adapters.

### Why it matters
- turns declarative connector metadata into actionable runtime behavior
- enables safe, reusable support for real integrations
- avoids manual HTTP request shape work in playbooks and agent tools

### What to do
- Load `InstalledIntegration` and associated `IntegrationConnector` from the database
- Decrypt stored credentials from `installed_integrations.auth_credentials_encrypted`
- Instantiate the connector class from `src/integrations/connectors`
- Dispatch `execute_action(action_name, params)` through the connector
- Fall back to generic HTTP request execution only when no connector wrapper exists

### Files
- `src/integrations/engine.py`
- `src/api/v1/endpoints/integrations.py`

### Acceptance criteria
- Slack and VirusTotal actions route through their connector classes
- execution history stores actual connector output
- unknown connectors can still run if explicit `url`/`method` input is provided

---

## Issue 2: Add an AI tool for configured integration actions

### Summary
The agent can identify configured integrations, but it lacks a direct tool for asking the platform to execute an installed integration action with structured inputs.

### Why it matters
- gives the agent a safe path to notify teams, enrich IOCs, and run playbook-integrated connector actions
- prevents the agent from trying to construct raw HTTP requests

### What to do
- Add a tool in `src/services/agent_tools.py` such as `execute_integration_action`
- Accept `installation_id`, `action_name`, and `input_data`
- Use the integration runtime to execute the action and return structured results
- Restrict this to configured, healthy integrations only

### Files
- `src/services/agent_tools.py`
- `src/integrations/engine.py`

### Acceptance criteria
- the agent can ask to execute a configured connector action
- the tool returns success/failure and provider-level output

---

## Issue 3: Build the first end-to-end connector workflow: VirusTotal + Slack

### Summary
Create a proof-of-concept workflow that combines threat intel enrichment and notification using real connector integration plumbing.

### Why it matters
- validates the integration execution path end-to-end
- demonstrates a real SOC workflow for analysts
- shows how external intel and notification connectors work together

### What to do
- Implement a workflow that:
  1. uses VirusTotal to enrich an IOC (IP, domain, hash, or URL)
  2. writes a new IOC record or updates existing threat intel data
  3. sends a Slack alert/notification summarizing the enrichment
  4. optionally raises an incident or ticket based on severity
- Prefer doing this through the existing playbook or agent tool layer

### Files
- `src/services/agent_tools.py`
- `src/integrations/engine.py`
- `src/playbooks/engine.py`

### Acceptance criteria
- a documented workflow exists in the repo
- the workflow can be triggered using configured VirusTotal and Slack integrations
- results are persisted to the platform and notification is sent via Slack

### Example
- The new agent tool `execute_integration_action` can invoke a configured Slack or VirusTotal action by `installation_id` and `action_name`.
- This creates a safe path for agent-driven enrichment and notification without raw HTTP construction.
