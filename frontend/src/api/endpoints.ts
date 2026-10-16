import { api } from './client';
import type { Row } from '../lib/apiRow';
import {
  PaginatedResponse,
  Alert,
  Incident,
  SIEMEvent,
  SIEMRule,
  SIEMDashboard,
  ThreatIndicator,
  ThreatIntelFeed,
  Hunt,
  HuntFinding,
  ExposureAssessment,
  AttackSurface,
  AIPrediction,
  RemediationPolicy,
  ComplianceFramework,
  POAM,
  ZeroTrustPolicy,
  DeviceTrust,
  STIGBenchmark,
  AuditEvidence,
  DFIRCase,
  IdentityThreat,
  Vulnerability,
  PatchOperation,
  SBOM,
  VendorAssessment,
  DarkWebAlert,
  Agent,
  Investigation,
  Playbook,
  DLPPolicy,
  DLPIncident,
  RiskScenario,
  OTAsset,
  OTZone,
  ContainerImage,
  DataSubjectRequest,
  PrivacyImpactAssessment,
  ThreatModel,
  AttackTree,
  PhishingCampaign,
  PhishingResult,
} from './types';

// Auto-extract items from paginated responses
function extractData(data: any): any {
  if (data && typeof data === 'object' && !Array.isArray(data) && 'items' in data) {
    return data.items;
  }
  return data;
}

// Alerts
export const alertsApi = {
  getAlerts: async (params?: {
    page?: number;
    size?: number;
    status?: string;
    severity?: string;
    search?: string;
  }): Promise<PaginatedResponse<Alert>> => {
    const response = await api.get('/alerts', { params });
    return extractData(response.data);
  },

  getAlert: async (id: string): Promise<Alert> => {
    const response = await api.get(`/alerts/${id}`);
    return response.data;
  },

  updateAlert: async (id: string, data: Partial<Alert>): Promise<Alert> => {
    const response = await api.patch(`/alerts/${id}`, data);
    return response.data;
  },
};

// Incidents
export const incidentsApi = {
  getIncidents: async (params?: {
    page?: number;
    size?: number;
    status?: string;
    severity?: string;
    search?: string;
  }): Promise<PaginatedResponse<Incident>> => {
    const response = await api.get('/incidents', { params });
    return extractData(response.data);
  },

  getIncident: async (id: string): Promise<Incident> => {
    const response = await api.get(`/incidents/${id}`);
    return response.data;
  },

  createIncident: async (data: {
    title: string;
    description?: string;
    severity: string;
  }): Promise<Incident> => {
    const response = await api.post('/incidents', data);
    return response.data;
  },

  updateIncident: async (id: string, data: Partial<Incident>): Promise<Incident> => {
    const response = await api.patch(`/incidents/${id}`, data);
    return response.data;
  },
};

// SIEM
export const siemApi = {
  getSIEMEvents: async (params?: {
    page?: number;
    size?: number;
    source?: string;
    severity?: string;
    date_range?: string;
  }): Promise<PaginatedResponse<SIEMEvent>> => {
    const response = await api.post('/siem/logs/search', params);
    return extractData(response.data);
  },

  getSIEMRules: async (): Promise<SIEMRule[]> => {
    const response = await api.get('/siem/rules');
    return extractData(response.data);
  },

  createRule: async (data: {
    name: string;
    description: string;
    query: string;
    severity: string;
  }): Promise<SIEMRule> => {
    const response = await api.post('/siem/rules', data);
    return response.data;
  },

  getSIEMDashboard: async (): Promise<SIEMDashboard> => {
    const response = await api.get('/siem/logs/stats');
    return response.data;
  },
};

// Threat Intelligence
export const threatIntelApi = {
  getFeeds: async (): Promise<ThreatIntelFeed[]> => {
    const response = await api.get('/threat-intel/feeds');
    return extractData(response.data);
  },

  getIndicators: async (params?: {
    page?: number;
    size?: number;
    ioc_type?: string;
    threat_level?: string;
    search?: string;
  }): Promise<PaginatedResponse<ThreatIndicator>> => {
    const response = await api.get('/threat-intel/indicators', { params });
    return extractData(response.data);
  },
};

// Hunting
export const huntingApi = {
  getHunts: async (params?: {
    page?: number;
    size?: number;
    status?: string;
    search?: string;
  }): Promise<PaginatedResponse<Hunt>> => {
    const response = await api.get('/hunting/sessions', { params });
    return extractData(response.data);
  },

  createHunt: async (data: {
    name: string;
    description: string;
    query: string;
  }): Promise<Hunt> => {
    const response = await api.post('/hunting/sessions', data);
    return response.data;
  },

  getHuntFindings: async (huntId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<HuntFinding>> => {
    const response = await api.get(`/hunting/findings`, { params: { ...params, session_id: huntId } });
    return extractData(response.data);
  },
};

// Exposure Management
export const exposureApi = {
  getExposureAssessments: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<ExposureAssessment>> => {
    const response = await api.get('/exposure/assets', { params });
    return extractData(response.data);
  },

  getAttackSurface: async (): Promise<AttackSurface> => {
    const response = await api.get('/exposure/attack-surface');
    return response.data;
  },

  getDashboard: async (): Promise<any> => {
    const response = await api.get('/exposure/dashboard');
    return response.data;
  },

  runScan: async (): Promise<{ task_id: string }> => {
    const response = await api.post('/exposure/scans');
    return response.data;
  },
};

// AI Engine
export const aiApi = {
  getAIPredictions: async (params?: {
    page?: number;
    size?: number;
    type?: string;
  }): Promise<PaginatedResponse<AIPrediction>> => {
    const response = await api.get('/ai/predictions', { params });
    return extractData(response.data);
  },
};

// Remediation
export const remediationApi = {
  getPolicies: async (): Promise<RemediationPolicy[]> => {
    const response = await api.get('/remediation/policies');
    return extractData(response.data);
  },

  /**
   * The engine's action registry (GET /remediation/actions). A policy
   * action's `type` must be one of these `key`s; anything else is 400
   * `unknown_action`.
   */
  getActions: async (params?: { action_type?: string }): Promise<RemediationActionSpec[]> => {
    const response = await api.get('/remediation/actions', { params });
    return response.data;
  },
};

/** One entry of GET /remediation/actions. */
export interface RemediationActionSpec {
  key: string;
  label: string;
  description: string;
  target_type: string;
  /** How it actuates: containment / agent_command / notification. */
  path: string;
  parameters: { name: string; type: string; required: boolean; description?: string }[];
  requires_approval: boolean;
  reversible: boolean;
  risk_level: string;
  aliases: string[];
}

// Compliance
export const complianceApi = {
  getFrameworks: async (): Promise<ComplianceFramework[]> => {
    const response = await api.get('/compliance/frameworks');
    return extractData(response.data);
  },

  runAssessment: async (frameworkId: string): Promise<{ task_id: string }> => {
    const response = await api.post(`/compliance/frameworks/${frameworkId}/assess`);
    return response.data;
  },

  getPOAMs: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<POAM>> => {
    const response = await api.get('/compliance/poams', { params });
    return extractData(response.data);
  },
};

// Zero Trust
export const zerotrustApi = {
  getPolicies: async (): Promise<ZeroTrustPolicy[]> => {
    const response = await api.get('/zerotrust/policies');
    return extractData(response.data);
  },

  getDeviceTrust: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<DeviceTrust>> => {
    const response = await api.get('/zerotrust/devices', { params });
    return extractData(response.data);
  },

  getAccessDecisions: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ device_id: string; access_granted: boolean; reason: string }>> => {
    const response = await api.get('/zerotrust/decisions', { params });
    return extractData(response.data);
  },
};

// STIG
export const stigApi = {
  getBenchmarks: async (): Promise<STIGBenchmark[]> => {
    const response = await api.get('/stig/benchmarks');
    return extractData(response.data);
  },
};

// DFIR
export const dfirApi = {
  getCases: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<DFIRCase>> => {
    const response = await api.get('/dfir/cases', { params });
    return extractData(response.data);
  },

  createCase: async (data: {
    case_number: string;
    title: string;
    description: string;
    severity: string;
    case_type?: string;
  }): Promise<DFIRCase> => {
    const response = await api.post('/dfir/cases', data);
    return response.data;
  },

  getEvidence: async (caseId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<AuditEvidence>> => {
    const response = await api.get(`/dfir/cases/${caseId}/evidence`, { params });
    return extractData(response.data);
  },

  getTimeline: async (caseId: string): Promise<any> => {
    const response = await api.get(`/dfir/cases/${caseId}/timeline`);
    return response.data;
  },

  getLegalHolds: async (caseId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<any> => {
    const response = await api.get(`/dfir/cases/${caseId}/legal-holds`, { params });
    return response.data;
  },

  updateCase: async (caseId: string, data: {
    title?: string;
    description?: string;
    status?: string;
    severity?: string;
  }): Promise<DFIRCase> => {
    const response = await api.put(`/dfir/cases/${caseId}`, data);
    return response.data;
  },

  updateLegalHold: async (holdId: string, data: {
    hold_type?: string;
    status?: string;
    custodians?: string[];
    data_sources?: string[];
    expiry_date?: string;
  }): Promise<any> => {
    const response = await api.put(`/dfir/legal-holds/${holdId}`, data);
    return response.data;
  },

  getDashboardMetrics: async (): Promise<any> => {
    const response = await api.get('/dfir/dashboard/metrics');
    return response.data;
  },
};

// ITDR
export const itdrApi = {
  getIdentityThreats: async (params?: {
    page?: number;
    size?: number;
    severity?: string;
  }): Promise<PaginatedResponse<IdentityThreat>> => {
    const response = await api.get('/itdr/threats', { params });
    return extractData(response.data);
  },

  createThreat: async (data: {
    threat_type: string;
    identity_id: string;
    severity: string;
    confidence_score?: number;
  }): Promise<IdentityThreat> => {
    const response = await api.post('/itdr/threats', data);
    return response.data;
  },

  getCredentialExposures: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/itdr/credential-exposures', { params });
    return extractData(response.data);
  },

  getAccessAnomalies: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/itdr/anomalies', { params });
    return extractData(response.data);
  },

  getIdentities: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/itdr/identities', { params });
    return extractData(response.data);
  },

  getPrivilegedAccess: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/itdr/privileged-access', { params });
    return extractData(response.data);
  },

  updateThreat: async (id: string, data: Record<string, any>): Promise<IdentityThreat> => {
    const response = await api.put(`/itdr/threats/${id}`, data);
    return response.data;
  },

  updateExposure: async (id: string, data: Record<string, any>): Promise<any> => {
    const response = await api.put(`/itdr/credential-exposures/${id}`, data);
    return response.data;
  },

  updateAnomaly: async (id: string, data: Record<string, any>): Promise<any> => {
    const response = await api.put(`/itdr/anomalies/${id}`, data);
    return response.data;
  },

  updatePrivilegedAccess: async (id: string, data: Record<string, any>): Promise<any> => {
    const response = await api.put(`/itdr/privileged-access/${id}`, data);
    return response.data;
  },
};

// Vulnerability Management
export const vulnmgmtApi = {
  getVulnerabilities: async (params?: {
    page?: number;
    size?: number;
    severity?: string;
    status?: string;
    search?: string;
  }): Promise<PaginatedResponse<Vulnerability>> => {
    const response = await api.get('/vulnmgmt/vulnerabilities', { params });
    return extractData(response.data);
  },

  runScan: async (assetId?: string): Promise<{ task_id: string }> => {
    const response = await api.post('/vulnmgmt/vulnerabilities/import-scan', assetId ? { asset_id: assetId } : {});
    return response.data;
  },

  getPatchOperations: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<PatchOperation>> => {
    const response = await api.get('/vulnmgmt/patch-operations', { params });
    return extractData(response.data);
  },

  getScanProfiles: async (): Promise<any[]> => {
    const response = await api.get('/vulnmgmt/scan-profiles');
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items || []);
  },

  createScanProfile: async (data: Record<string, any>): Promise<any> => {
    const response = await api.post('/vulnmgmt/scan-profiles', data);
    return response.data;
  },

  // Import a scanner export (Nessus / OpenVAS / Qualys / CSV / JSON). The
  // response reports instances created / updated / reopened and skipped
  // findings by reason; 422 scan_parse_failed carries `errors`.
  importScan: async (data: { scan_profile_id?: string; scan_format: string; scan_data: string }): Promise<any> => {
    const response = await api.post('/vulnmgmt/vulnerabilities/import-scan', data);
    return response.data;
  },

  // Fetch the CISA KEV feed server-side and flag tracked CVEs (502
  // kev_feed_unavailable when the feed cannot be reached).
  syncKev: async (): Promise<any> => {
    const response = await api.post('/vulnmgmt/vulnerabilities/sync-kev');
    return response.data;
  },

  refreshScores: async (): Promise<any> => {
    const response = await api.post('/vulnmgmt/instances/refresh-scores');
    return response.data;
  },

  getExceptions: async (): Promise<any[]> => {
    const response = await api.get('/vulnmgmt/exceptions');
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items || []);
  },

  createException: async (data: Record<string, any>): Promise<any> => {
    const response = await api.post('/vulnmgmt/exceptions', data);
    return response.data;
  },
};

// Supply Chain
export const supplychainApi = {
  getSBOMs: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<SBOM>> => {
    const response = await api.get('/supplychain/sboms', { params });
    return extractData(response.data);
  },

  getSupplyChainRisks: async (): Promise<{ items: Record<string, any>[]; total: number; page: number; size: number; pages: number }> => {
    const response = await api.get('/supplychain/risks');
    return response.data;
  },

  getVendorAssessments: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<VendorAssessment>> => {
    const response = await api.get('/supplychain/vendors', { params });
    return extractData(response.data);
  },

  addComponent: async (data: { name: string; version: string; license: string }): Promise<any> => {
    const response = await api.post('/supplychain/components', data);
    return response.data;
  },

  /**
   * Download a real spec-compliant SPDX or CycloneDX SBOM file. Backend streams
   * the document with a proper Content-Disposition attachment header; we grab
   * the blob and trigger a browser download so the user sees the file.
   */
  downloadSBOM: async (
    sbomId: string,
    format: 'spdx_json' | 'cyclonedx_json' = 'cyclonedx_json'
  ): Promise<{ blob: Blob; filename: string }> => {
    const response = await api.post(
      `/supplychain/sboms/${sbomId}/export`,
      { export_format: format },
      { responseType: 'blob' }
    );
    // Extract filename from Content-Disposition if present
    let filename = `sbom-${sbomId}.${format === 'spdx_json' ? 'spdx' : 'cdx'}.json`;
    const cd = response.headers?.['content-disposition'];
    if (cd && typeof cd === 'string') {
      const m = cd.match(/filename="?([^"]+)"?/);
      if (m) filename = m[1];
    }
    return { blob: response.data as Blob, filename };
  },
};

// Dark Web
export const darkwebApi = {
  // Backend exposes /findings (the canonical name); the page calls
  // these "alerts" historically. Same idea, real route. Without this fix
  // every page load 404'd silently and the Findings tab rendered blank.
  getAlerts: async (params?: {
    page?: number;
    size?: number;
    type?: string;
    status?: string;
  }): Promise<PaginatedResponse<DarkWebAlert>> => {
    const response = await api.get('/darkweb/findings', { params });
    return extractData(response.data);
  },

  getCredentialLeaks: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ email: string; password_hash: string; source: string; date_found: string }>> => {
    const response = await api.get('/darkweb/credentials', { params });
    return extractData(response.data);
  },

  getBrandMonitors: async (): Promise<{ brand_name: string; mentions: number; alerts: DarkWebAlert[] }[]> => {
    const response = await api.get('/darkweb/brand-threats');
    return extractData(response.data);
  },

  deleteMonitor: async (monitorId: string): Promise<void> => {
    await api.delete(`/darkweb/monitors/${monitorId}`);
  },

  updateMonitor: async (monitorId: string, data: { name?: string; description?: string; search_terms?: string[]; enabled?: boolean }): Promise<any> => {
    const response = await api.patch(`/darkweb/monitors/${monitorId}`, data);
    return response.data;
  },

  updateFinding: async (findingId: string, data: { status?: string; analyst_notes?: string; severity?: string }): Promise<any> => {
    const response = await api.patch(`/darkweb/findings/${findingId}`, data);
    return response.data;
  },

  escalateFinding: async (findingId: string): Promise<{
    incident_id: string;
    finding_id: string;
    status: string;
    incident_status: string;
    incident_severity?: string;
  }> => {
    const response = await api.post(`/darkweb/findings/${findingId}/escalate`);
    return response.data;
  },

  notifyStakeholders: async (findingId: string): Promise<{
    finding_id: string;
    status: string;
    delivery: { sent: string[]; failed: string[]; skipped: string[] };
  }> => {
    const response = await api.post(`/darkweb/findings/${findingId}/notify`);
    return response.data;
  },

  createMonitor: async (data: { name: string; keywords?: string[]; monitor_type?: string; keyword?: string }): Promise<any> => {
    const response = await api.post('/darkweb/monitors', {
      name: data.name,
      keywords: data.keywords || (data.keyword ? [data.keyword] : []),
      monitor_type: data.monitor_type || 'keyword',
    });
    return response.data;
  },

  getMonitors: async (): Promise<any[]> => {
    const response = await api.get('/darkweb/monitors');
    const d = response.data;
    return Array.isArray(d) ? d : (d?.items ?? []);
  },

  requestTakedown: async (threatId: string): Promise<any> => {
    const response = await api.post(`/darkweb/brand-threats/${threatId}/initiate-takedown`);
    return response.data;
  },

  exportReport: async (format: 'csv' | 'pdf' = 'csv'): Promise<void> => {
    // Stream the report as a blob so the browser triggers a real download
    // (replaces the old window.print() hack).
    const response = await api.get('/darkweb/report/export', {
      params: { format },
      responseType: 'blob',
    });
    const contentType =
      (response.headers && (response.headers['content-type'] as string)) || 'text/csv';
    const blob = new Blob([response.data], { type: contentType });
    const url = window.URL.createObjectURL(blob);

    // Extract the server-provided filename when present, else build one.
    let filename = `pysoar_darkweb_report.${format}`;
    const disposition =
      response.headers && (response.headers['content-disposition'] as string);
    if (disposition) {
      const match = disposition.match(/filename\s*=\s*"?([^";]+)"?/i);
      if (match) filename = match[1];
    }

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },
};

// Integrations
export const integrationsApi = {
  getConnectors: async (): Promise<any[]> => {
    const response = await api.get('/integrations/connectors');
    const d = response.data;
    return Array.isArray(d) ? d : (d?.items ?? []);
  },

  getInstalled: async (): Promise<any[]> => {
    const response = await api.get('/integrations/installed');
    const d = response.data;
    return Array.isArray(d) ? d : (d?.items ?? []);
  },
};

// Agentic Automation
export const agenticApi = {
  getAgents: async (): Promise<Agent[]> => {
    const response = await api.get('/agentic/agents');
    return extractData(response.data);
  },

  getInvestigations: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<Investigation>> => {
    const response = await api.get('/agentic/investigations', { params });
    return extractData(response.data);
  },

  startInvestigation: async (data: { description: string; target_data: Record<string, any> }): Promise<Investigation> => {
    const response = await api.post('/agentic/investigations', data);
    return response.data;
  },

  // --- Guarded runtime (design v2 sections 8/9). Contract types live in the
  // "Agentic SOC" block near the bottom of this file. ---

  /** One chat turn against the guarded runtime. */
  chat: async (body: AgenticChatRequest): Promise<AgenticChatResponse> => {
    const response = await api.post('/agentic/chat', body);
    return response.data;
  },

  listPendingApprovals: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PendingApprovalRow[]> => {
    const response = await api.get('/agentic/actions/pending-approval', { params });
    return extractData(response.data) || [];
  },

  /**
   * Approve a proposal. The caller MUST echo the hashes it rendered on the
   * card: a mismatch comes back as 409 `approval_stale` instead of executing
   * something the approver never saw.
   */
  approveAction: async (
    actionId: string,
    body: {
      params_sha256: string;
      evidence_sha256: string;
      acknowledge_suspect?: boolean;
      reason?: string;
      approval_notes?: string;
    },
  ): Promise<ApproveActionResult> => {
    const payload: ApproveActionRequest = { approved: true, ...body };
    const response = await api.post(`/agentic/actions/${actionId}/approve`, payload);
    return response.data;
  },

  denyAction: async (actionId: string, approvalNotes?: string): Promise<unknown> => {
    const payload: ApproveActionRequest = {
      approved: false,
      approval_notes: approvalNotes || undefined,
    };
    const response = await api.post(`/agentic/actions/${actionId}/approve`, payload);
    return response.data;
  },

  rollbackAction: async (actionId: string): Promise<RollbackResult> => {
    const response = await api.post(`/agentic/actions/${actionId}/rollback`);
    return response.data;
  },

  /** Only the tools the caller's role may invoke. */
  listTools: async (): Promise<AgentToolSpec[]> => {
    const response = await api.get('/agentic/tools');
    return response.data?.tools || [];
  },

  // --- SOC agent management and the auditor surface (wave 5) ---

  getAgent: async (agentId: string): Promise<Row> => {
    const response = await api.get(`/agentic/agents/${agentId}`);
    return response.data;
  },

  /** Admin only; the server answers 403 role_not_permitted otherwise. */
  createAgent: async (body: {
    name: string;
    agent_type: string;
    capabilities?: string[];
    llm_model?: string;
    temperature?: number;
    max_reasoning_steps?: number;
    autonomy_level?: string;
  }): Promise<Row> => {
    const response = await api.post('/agentic/agents', body);
    return response.data;
  },

  /** Admin only. Omitted fields are unchanged. */
  updateAgent: async (
    agentId: string,
    body: {
      name?: string;
      status?: string;
      temperature?: number;
      max_reasoning_steps?: number;
      autonomy_level?: string;
    },
  ): Promise<Row> => {
    const response = await api.put(`/agentic/agents/${agentId}`, body);
    return response.data;
  },

  /** Everything recorded about one run (analyst+); 404 run_not_found otherwise. */
  getRun: async (runId: string): Promise<Row> => {
    const response = await api.get(`/agentic/runs/${runId}`);
    return response.data;
  },

  /** LLM token spend for the organisation over `days` (analyst+). */
  getUsage: async (days: number): Promise<Row> => {
    const response = await api.get('/agentic/usage', { params: { days } });
    return response.data;
  },

  /** Policy and tool audit rows, newest first (analyst+). */
  getPolicyEvents: async (params: {
    decision?: string;
    tool?: string;
    reason_code?: string;
    page?: number;
    size?: number;
  }): Promise<Row> => {
    const response = await api.get('/agentic/policy-events', { params });
    return response.data;
  },

  /** Per-decision evidence export (admin). CSV comes back as a Blob. */
  exportEvidence: async (params: { format: 'csv' | 'json'; from?: string; to?: string }) => {
    return api.get('/agentic/evidence/export', { params, responseType: 'blob' });
  },

  /** Downgrade a lockdown to flagged by acknowledging the hits (analyst+). */
  acknowledgeTrust: async (body: {
    session_id?: string;
    investigation_id?: string;
    record_hash?: string;
    reason: string;
  }): Promise<Row> => {
    const response = await api.post('/agentic/trust/acknowledge', body);
    return response.data;
  },
};

// Playbook Builder
export const playbookApi = {
  getPlaybooks: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<Playbook>> => {
    const response = await api.get('/playbooks', { params });
    return extractData(response.data);
  },

  createPlaybook: async (data: {
    name: string;
    description: string;
    trigger_type: string;
  }): Promise<Playbook> => {
    const response = await api.post('/playbooks', data);
    return response.data;
  },

  executePlaybook: async (playbookId: string, input_data?: Record<string, any>): Promise<{ execution_id: string }> => {
    const response = await api.post(`/playbooks/${playbookId}/execute`, { input_data });
    return response.data;
  },
};

// DLP
export const dlpApi = {
  getPolicies: async (): Promise<DLPPolicy[]> => {
    const response = await api.get('/dlp/policies');
    return extractData(response.data);
  },

  getIncidents: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<DLPIncident>> => {
    const response = await api.get('/dlp/incidents', { params });
    return extractData(response.data);
  },

  getClassifications: async (): Promise<string[]> => {
    const response = await api.get('/dlp/classifications');
    return extractData(response.data);
  },

  createPolicy: async (data: {
    name: string;
    description?: string;
    policy_type?: string;
    severity?: string;
    enabled?: boolean;
    data_patterns?: string[];
  }): Promise<DLPPolicy> => {
    const response = await api.post('/dlp/policies', data);
    return response.data;
  },

  updatePolicy: async (
    id: string,
    data: Partial<{
      name: string;
      description: string;
      severity: string;
      policy_type: string;
      enabled: boolean;
      data_patterns: string[];
    }>
  ): Promise<DLPPolicy> => {
    const response = await api.patch(`/dlp/policies/${id}`, data);
    return response.data;
  },

  enablePolicy: async (id: string): Promise<DLPPolicy> => {
    const response = await api.post(`/dlp/policies/${id}/enable`);
    return response.data;
  },

  disablePolicy: async (id: string): Promise<DLPPolicy> => {
    const response = await api.post(`/dlp/policies/${id}/disable`);
    return response.data;
  },

  testPolicy: async (id: string, sampleText?: string): Promise<any> => {
    const body = sampleText ? { sample_text: sampleText } : {};
    const response = await api.post(`/dlp/policies/${id}/test`, body);
    return response.data;
  },

  updateIncident: async (
    id: string,
    data: Partial<{ status: string; resolution_notes: string; assigned_to: string }>
  ): Promise<any> => {
    const response = await api.patch(`/dlp/incidents/${id}`, data);
    return response.data;
  },
};

// Risk Quantification
export const riskquantApi = {
  getScenarios: async (): Promise<RiskScenario[]> => {
    const response = await api.get('/risk-quantification/scenarios');
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items ?? []);
  },

  runAnalysis: async (
    scenarioIds: string[],
    iterations: number = 5000,
  ): Promise<{
    status: string;
    scenarios_analyzed: number;
    total_ale_mean: number;
    portfolio_var_95: number;
    per_scenario: Array<{
      analysis_id: string;
      scenario_id: string;
      ale_mean: number;
      ale_p50: number;
      ale_p90: number;
      ale_p99: number;
    }>;
    timestamp: string;
  }> => {
    const response = await api.post('/risk-quantification/analyze', {
      scenario_ids: scenarioIds,
      iterations,
    });
    return response.data;
  },

  getLossExceedance: async (): Promise<any> => {
    const response = await api.get('/risk-quantification/loss-exceedance');
    return response.data;
  },

  getDashboard: async (): Promise<any> => {
    const response = await api.get('/risk-quantification/dashboard');
    return response.data;
  },

  // List existing FAIR analyses so the page can show real ALE / loss
  // exceedance numbers per scenario instead of placeholder zeros.
  getFairAnalyses: async (): Promise<any[]> => {
    const response = await api.get('/risk-quantification/fair-analyses', {
      params: { size: 100 },
    });
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items ?? []);
  },

  createScenario: async (data: { name: string; description: string; loss_magnitude: number }): Promise<any> => {
    const response = await api.post('/risk-quantification/scenarios', data);
    return response.data;
  },
};

// OT Security
export const otsecurityApi = {
  getAssets: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<OTAsset>> => {
    const response = await api.get('/ot_security/assets', { params });
    return extractData(response.data);
  },

  getAlerts: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<Alert>> => {
    const response = await api.get('/ot_security/alerts', { params });
    return extractData(response.data);
  },

  getZones: async (): Promise<OTZone[]> => {
    const response = await api.get('/ot_security/zones');
    return extractData(response.data);
  },

  getPurdueMap: async (): Promise<any> => {
    const response = await api.get('/ot_security/purdue-map');
    return response.data;
  },
};

// Container Security
export const containerApi = {
  getImages: async (params?: {
    page?: number;
    size?: number;
    compliance_status?: string;
  }): Promise<ContainerImage[]> => {
    const response = await api.get('/container-security/images', { params });
    return response.data;
  },

  getClusters: async (params?: {
    page?: number;
    size?: number;
    provider?: string;
  }): Promise<any[]> => {
    const response = await api.get('/container-security/clusters', { params });
    return response.data;
  },

  getFindings: async (params?: {
    page?: number;
    size?: number;
    severity?: string;
    status?: string;
  }): Promise<any[]> => {
    const response = await api.get('/container-security/findings', { params });
    return response.data;
  },

  getRuntimeAlerts: async (params?: {
    page?: number;
    size?: number;
    severity?: string;
    status?: string;
  }): Promise<any[]> => {
    const response = await api.get('/container-security/runtime-alerts', { params });
    return response.data;
  },

  getDashboard: async (): Promise<any> => {
    const response = await api.get('/container-security/dashboard/overview');
    return response.data;
  },

  scanImage: async (imageId: string): Promise<any> => {
    const response = await api.post(`/container-security/images/${imageId}/scan`);
    return response.data;
  },

  auditCluster: async (clusterId: string): Promise<any> => {
    const response = await api.post(`/container-security/clusters/${clusterId}/audit`);
    return response.data;
  },

  remediateFinding: async (findingId: string): Promise<any> => {
    const response = await api.post(`/container-security/findings/${findingId}/remediate`);
    return response.data;
  },

  getComplianceMatrix: async (): Promise<any> => {
    const response = await api.get('/container-security/dashboard/compliance-matrix');
    return response.data;
  },
};

// Privacy
export const privacyApi = {
  getDSRs: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<DataSubjectRequest>> => {
    const response = await api.get('/privacy/dsr/requests', { params });
    return extractData(response.data);
  },

  createDSR: async (data: {
    request_type: string;
    subject_email: string;
  }): Promise<DataSubjectRequest> => {
    const response = await api.post('/privacy/dsr/requests', data);
    return response.data;
  },

  getPIAs: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<PrivacyImpactAssessment>> => {
    const response = await api.get('/privacy/pia/assessments', { params });
    return extractData(response.data);
  },

  getConsentRecords: async (subjectId: string): Promise<any[]> => {
    const response = await api.get(`/privacy/consent/records/${subjectId}`);
    return response.data;
  },

  getProcessingRecords: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/privacy/ropa/processing-records', { params });
    return response.data;
  },

  getIncidents: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/privacy/incidents/reports', { params });
    return response.data;
  },
};

// Threat Modeling
export const threatmodelApi = {
  getModels: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<ThreatModel>> => {
    const response = await api.get('/threat-modeling', { params });
    return extractData(response.data);
  },

  runSTRIDE: async (modelId: string): Promise<any> => {
    const response = await api.post(`/threat-modeling/${modelId}/analyze/stride`);
    return response.data;
  },

  getAttackTrees: async (modelId: string): Promise<AttackTree[]> => {
    const response = await api.get(`/threat-modeling/${modelId}/components`);
    return extractData(response.data);
  },

  getMitigations: async (modelId: string): Promise<any[]> => {
    const response = await api.get(`/threat-modeling/${modelId}/threats`);
    return extractData(response.data);
  },

  getSTRIDEAnalysis: async (modelId: string): Promise<any[]> => {
    const response = await api.post(`/threat-modeling/${modelId}/analyze/stride`);
    return extractData(response.data);
  },

  getThreats: async (modelId: string): Promise<any[]> => {
    const response = await api.get(`/threat-modeling/${modelId}/threats`);
    return extractData(response.data);
  },

  createModel: async (data: any): Promise<any> => {
    const response = await api.post('/threat-modeling', data);
    return response.data;
  },
};

// API Security
export const apisecurityApi = {
  getAPIs: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/api-security/endpoints', { params });
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items ?? []);
  },

  getVulnerabilities: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/api-security/vulnerabilities', { params });
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items ?? []);
  },

  getAnomalies: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/api-security/anomalies', { params });
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items ?? []);
  },

  getPolicies: async (): Promise<any[]> => {
    const response = await api.get('/api-security/policies');
    const data = response.data;
    return Array.isArray(data) ? data : (data?.items ?? []);
  },

  registerAPI: async (data: { name: string; method: string }): Promise<any> => {
    const response = await api.post('/api-security/endpoints', data);
    return response.data;
  },

  // Daily vulnerability findings by severity over the trailing window.
  // Shape: { window_days, points: [{ date, critical, high, medium, low }], total_findings }
  getRiskTrend: async (days = 30): Promise<any> => {
    const response = await api.get('/api-security/dashboard/risk-trend', { params: { days } });
    return response.data;
  },
};

// Data Lake
export const datalakeApi = {
  getDataSources: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/data-lake/sources', { params });
    return extractData(response.data);
  },

  getPipelines: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/data-lake/pipelines', { params });
    return extractData(response.data);
  },

  /** Counts by status (built-in scheduled tasks counted apart from registered rows). */
  getPipelineStatus: async (): Promise<Row> => {
    const response = await api.get('/data-lake/dashboard/pipeline-status');
    return response.data;
  },

  runQuery: async (query: string): Promise<any> => {
    const response = await api.post('/data-lake/query', { query });
    return response.data;
  },

  getCatalog: async (): Promise<any[]> => {
    const response = await api.get('/data-lake/catalog');
    return extractData(response.data);
  },

  createDataSource: async (data: { name: string; connection_string: string }): Promise<any> => {
    const response = await api.post('/data-lake/sources', data);
    return response.data;
  },

  // Hourly ingested-record counts over the trailing window.
  // Shape: { window_hours, points: [{ time, count }], total_events, by_source }
  getIngestionTrend: async (hours = 24): Promise<any> => {
    const response = await api.get('/data-lake/dashboard/ingestion-trend', { params: { hours } });
    return response.data;
  },
};

// Collaboration
export const collaborationApi = {
  getWarRooms: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/collaboration/rooms', { params });
    return extractData(response.data);
  },

  createWarRoom: async (data: { name: string; description?: string; room_type?: string; severity_level?: string }): Promise<any> => {
    const response = await api.post('/collaboration/rooms', {
      name: data.name,
      room_type: data.room_type || 'incident_response',
      severity_level: data.severity_level || 'medium',
      description: data.description || '',
    });
    return response.data;
  },

  getMessages: async (warRoomId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get(`/collaboration/rooms/${warRoomId}/messages`, { params });
    return extractData(response.data);
  },

  getAllActionItems: async (): Promise<any[]> => {
    // Action items across all active rooms. A failed request propagates so
    // the page shows the error instead of an empty list.
    const roomsRes = await api.get('/collaboration/rooms', { params: { size: 50 } });
    const rooms: any[] = extractData(roomsRes.data) ?? [];
    const perRoom = await Promise.all(
      rooms.map(async (room) => {
        const res = await api.get(`/collaboration/rooms/${room.id}/actions`);
        const items: any[] = extractData(res.data) ?? [];
        return items.map((item) => ({ ...item, _room_name: room.name }));
      }),
    );
    return perRoom.flat();
  },

  getActionItems: async (warRoomId: string): Promise<any[]> => {
    const response = await api.get(`/collaboration/rooms/${warRoomId}/actions`);
    return extractData(response.data);
  },

  createActionItem: async (roomId: string, data: { title: string; priority?: string; description?: string }): Promise<any> => {
    const response = await api.post(`/collaboration/rooms/${roomId}/actions`, data);
    return response.data;
  },

  sendMessage: async (warRoomId: string, data: { content: string; message_type?: string }): Promise<any> => {
    const response = await api.post(`/collaboration/rooms/${warRoomId}/messages`, {
      content: data.content,
      message_type: data.message_type || 'text',
    });
    return response.data;
  },

  archiveWarRoom: async (warRoomId: string): Promise<any> => {
    const response = await api.post(`/collaboration/rooms/${warRoomId}/archive`);
    return response.data;
  },

  // --- wave 5: participation, timeline, action item updates, artifacts ---

  /** Analyst+. 400 when the room is at capacity or not joinable. */
  joinRoom: async (roomId: string): Promise<Row> => {
    const response = await api.post(`/collaboration/rooms/${roomId}/join`);
    return response.data;
  },

  leaveRoom: async (roomId: string): Promise<Row> => {
    const response = await api.post(`/collaboration/rooms/${roomId}/leave`);
    return response.data;
  },

  getTimeline: async (roomId: string, params?: { key_only?: boolean; page?: number; size?: number }): Promise<Row> => {
    const response = await api.get(`/collaboration/rooms/${roomId}/timeline`, { params });
    return response.data;
  },

  addTimelineEvent: async (
    roomId: string,
    body: { event_type: string; description: string; event_time?: string; is_key_event?: boolean; mitre_technique?: string },
  ): Promise<Row> => {
    const response = await api.post(`/collaboration/rooms/${roomId}/timeline`, body);
    return response.data;
  },

  /** Analyst+. Only the fields sent change. */
  updateActionItem: async (actionId: string, body: { status?: string; assigned_to?: string }): Promise<Row> => {
    const response = await api.patch(`/collaboration/actions/${actionId}`, body);
    return response.data;
  },

  /** Metadata registry only (name, hash, size): no bytes are stored. */
  getArtifacts: async (roomId: string, params?: { page?: number; size?: number }): Promise<Row> => {
    const response = await api.get(`/collaboration/rooms/${roomId}/artifacts`, { params });
    return response.data;
  },

  getDashboard: async (): Promise<any> => {
    const response = await api.get('/collaboration/dashboard');
    return response.data;
  },

  getPostMortem: async (roomId: string): Promise<any> => {
    const response = await api.get(`/collaboration/rooms/${roomId}/postmortem/analysis`);
    return response.data;
  },

  getArchivedRooms: async (): Promise<any[]> => {
    const response = await api.get('/collaboration/rooms', { params: { status: 'archived', size: 50 } });
    return extractData(response.data) ?? [];
  },
};

// Phishing Awareness
export const phishingApi = {
  getCampaigns: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<any[]> => {
    const response = await api.get('/phishing_sim/campaigns', { params });
    return extractData(response.data);
  },

  createCampaign: async (data: {
    name: string;
    description?: string;
    targets?: string[];
    campaign_type?: string;
  }): Promise<PhishingCampaign> => {
    const response = await api.post('/phishing_sim/campaigns', {
      ...data,
      campaign_type: data.campaign_type || 'phishing',
      organization_id: localStorage.getItem('organization_id') || '',
    });
    return response.data;
  },

  getResults: async (campaignId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<PhishingResult>> => {
    const response = await api.get(`/phishing_sim/campaigns/${campaignId}/results`, { params });
    return extractData(response.data);
  },

  getAwarenessScores: async (): Promise<{ user_email: string; awareness_score: number }[]> => {
    const response = await api.get('/phishing_sim/awareness-scores');
    return extractData(response.data);
  },

  getTemplates: async (): Promise<any[]> => {
    const response = await api.get('/phishing_sim/templates');
    return extractData(response.data);
  },

  getTargetGroups: async (): Promise<any[]> => {
    const response = await api.get('/phishing_sim/target-groups');
    return extractData(response.data);
  },

  launchCampaign: async (campaignId: string): Promise<any> => {
    const response = await api.post(`/phishing_sim/campaigns/${campaignId}/launch`);
    return response.data;
  },
};

// ---------------------------------------------------------------------------
// Agentic SOC — guarded runtime contracts (design v2 sections 8/9)
// ---------------------------------------------------------------------------

export type ToolTier = 'read' | 'write' | 'destructive' | 'privileged';
export type PolicyDecision = 'allow' | 'deny' | 'propose';
export type TargetProvenance = 'structured' | 'untrusted_text' | 'unknown';
export type TrustTier = 'clean' | 'flagged' | 'lockdown';
export type CredentialSource = 'org' | 'platform';

/** One step of the tool log. decision/tier drive what the UI may claim. */
export interface ToolInvocation {
  step: number;
  tool: string;
  args?: Record<string, unknown> | null;
  tier?: ToolTier | string | null;
  decision?: PolicyDecision | string | null;
  reason_code?: string | null;
  blocked?: boolean | null;
  duration_ms?: number | null;
  result?: unknown;
  proposal_id?: string | null;
  error?: string | null;
}

/** A target the proposal would actually act on, with where it came from. */
export interface EffectiveTarget {
  kind?: string | null;
  value?: string | null;
  resolved_id?: string | null;
  provenance?: TargetProvenance | string | null;
}

export interface AgentProposal {
  id?: string | null;
  tool: string;
  args?: Record<string, unknown> | null;
  effective_targets?: EffectiveTarget[] | null;
  params_sha256?: string | null;
  evidence_sha256?: string | null;
  suspect?: boolean | null;
  expires_at?: string | null;
  /** Present on proposals surfaced through the pending-approval list. */
  injection_tier?: TrustTier | string | null;
}

export interface PolicyEvent {
  step?: number | null;
  tool?: string | null;
  decision?: PolicyDecision | string | null;
  reason_code?: string | null;
  tier?: ToolTier | string | null;
  audit_id?: string | null;
  proposal_id?: string | null;
}

export interface TrustHit {
  family?: string | null;
  /** sha256 of the flagged snippet; what /agentic/trust/acknowledge takes as record_hash. */
  snippet_sha256?: string | null;
  preview?: string | null;
  label?: string | null;
}

export interface TrustAssessment {
  tier?: TrustTier | string | null;
  hits?: TrustHit[] | null;
}

export interface RunUsage {
  input_uncached?: number | null;
  cache_read?: number | null;
  cache_write?: number | null;
  output?: number | null;
  thinking?: number | null;
  total_billable?: number | null;
  estimated?: boolean | null;
}

export interface ChatInterpretation {
  tools_invoked?: ToolInvocation[] | null;
  run_id?: string | null;
  stop_reason?: string | null;
  stop_detail?: string | null;
  steps?: number | null;
  honesty_note_applied?: boolean | null;
}

export interface AgenticChatResponse {
  response: string;
  agent_id?: string;
  agent_name?: string;
  session_id?: string | null;
  run_id?: string;
  interpretation?: ChatInterpretation | null;
  proposals?: AgentProposal[] | null;
  policy_events?: PolicyEvent[] | null;
  trust?: TrustAssessment | null;
  provider?: string;
  model?: string;
  credential_source?: CredentialSource | string;
  usage?: RunUsage | null;
}

/** Error body returned by /agentic/chat on 503 / 429 / 403. */
export interface AgenticChatErrorBody {
  error?: string;
  detail?: unknown;
  source?: string;
  request_id?: string;
  run_id?: string;
}

/** Normalized, render-ready failure for the chat error card. */
export interface AgenticChatFailure {
  status: number | null;
  code: string;
  detail: string | null;
  source?: string | null;
  request_id?: string | null;
  run_id?: string | null;
  retry_after_seconds?: number | null;
}

/** tool_calls as persisted on a stored assistant message. */
export interface StoredRunEnvelope {
  tools_invoked?: ToolInvocation[] | null;
  proposals?: AgentProposal[] | null;
  policy_events?: PolicyEvent[] | null;
  status?: 'ok' | 'failed' | string | null;
  error?: string | null;
  provider?: string | null;
  model?: string | null;
  injection_tier?: TrustTier | string | null;
}

export interface AgenticChatRequest {
  query: string;
  session_id?: string | null;
  agent_id?: string | null;
  propose_actions?: boolean;
}

export interface ApproveActionRequest {
  approved: boolean;
  approval_notes?: string;
  params_sha256?: string;
  evidence_sha256?: string;
  acknowledge_suspect?: boolean;
  reason?: string;
}

/**
 * A row from GET /agentic/actions/pending-approval.
 *
 * Every field beyond the identifier is optional on purpose: rows written
 * before the guarded runtime landed carry none of the integrity binding
 * (params_sha256/evidence_sha256) and must degrade to read-only in the UI
 * rather than being approved blind.
 */
export interface PendingApprovalRow {
  action_id?: string;
  id?: string;
  tool_name?: string | null;
  action_type?: string | null;
  parameters?: Record<string, unknown> | string | null;
  effective_targets?: EffectiveTarget[] | null;
  target?: string | null;
  params_sha256?: string | null;
  evidence_sha256?: string | null;
  suspect?: boolean | null;
  injection_tier?: TrustTier | string | null;
  expires_at?: string | null;
  source?: string | null;
  proposed_by_user_id?: string | null;
  proposed_by_agent_id?: string | null;
  investigation_id?: string | null;
  investigation_title?: string | null;
  agent_id?: string | null;
  agent_name?: string | null;
  confidence_score?: number | null;
  risk_score?: number | null;
  created_at?: string | null;
  /** AC-5: the org requires two distinct approvers for this proposal's tier. */
  requires_second_approver?: boolean | null;
  /** Set once the first of the two approvals is in. */
  first_approved_by?: string | null;
  first_approved_at?: string | null;
}

/** Body of a successful POST /agentic/actions/{id}/approve. */
export interface ApproveActionResult {
  status: 'approved' | 'awaiting_second_approval' | string;
  action_id: string;
  executed?: boolean;
  execution_status?: string;
  approvals_required?: number;
  approvals_received?: number;
  first_approved_by?: string | null;
  first_approved_at?: string | null;
}

export interface RollbackResult {
  status?: string;
  detail?: { reversed?: unknown; problems?: unknown[] } | null;
}

export interface AgentToolSpec {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
  tier?: ToolTier | string;
  min_role?: string;
}

// ---------------------------------------------------------------------------
// AI provider settings + LLM health (design v2 section 9)
// ---------------------------------------------------------------------------

export type AIProviderName = 'anthropic' | 'gemini' | 'openai' | 'ollama';

export interface AICapabilities {
  models_seen_at?: string | null;
  model_count?: number | null;
}

export interface AISettings {
  provider?: AIProviderName | null;
  model?: string | null;
  use_platform_default: boolean;
  configured: boolean;
  source: 'org' | 'platform' | 'none';
  reason?: string | null;
  key_fingerprint?: string | null;
  rotated_at?: string | null;
  last_successful_call_at?: string | null;
  capabilities?: AICapabilities | null;
}

export interface AISettingsUpdate {
  provider: AIProviderName;
  model: string;
  use_platform_default?: boolean;
  /** Write-only. Never echoed back by the API; never pre-filled in the UI. */
  api_key?: string;
}

export interface AIModelsResponse {
  provider: AIProviderName;
  source: 'org' | 'platform';
  models: string[];
  fetched_at: string;
}

/** Top-level error body for PUT /settings/ai (not nested under detail). */
export interface AISettingsErrorBody {
  error?: string;
  detail?: string;
  available?: string[];
}

export interface LLMHealth {
  status?: 'ok' | 'not_configured' | 'degraded' | string;
  organization_id?: string | null;
  configured: boolean;
  provider?: string | null;
  model?: string | null;
  source?: 'org' | 'platform' | 'none' | string;
  reason?: string | null;
  last_successful_call_at?: string | null;
  breaker_open?: boolean | null;
  checked_at?: string;
  cached?: boolean;
}

/** Body of PUT /settings/agentic-policy (omitted fields are unchanged). */
export interface AgenticPolicySettingsUpdate {
  require_second_approver?: boolean;
  llm_call_log_retention_days?: number;
  agent_transcript_retention_days?: number;
}

/** Org agentic policy knobs (GET/PUT /settings/agentic-policy, admin). */
export interface AgenticPolicySettings {
  require_second_approver: boolean;
  /** Days raw LLM call logs are kept (30..1095, default 365). */
  llm_call_log_retention_days: number;
  /** Days agent run transcripts are kept, stamped when written (30..1095, default 365). */
  agent_transcript_retention_days: number;
  retention_min_days?: number;
  retention_max_days?: number;
  updated_at?: string | null;
  updated_by?: string | null;
}

export const settingsApi = {
  getAgenticPolicy: async (): Promise<AgenticPolicySettings> => {
    const response = await api.get('/settings/agentic-policy');
    return response.data;
  },

  /** Partial update: only the fields sent change. */
  putAgenticPolicy: async (body: AgenticPolicySettingsUpdate): Promise<AgenticPolicySettings> => {
    const response = await api.put('/settings/agentic-policy', body);
    return response.data;
  },

  getAi: async (): Promise<AISettings> => {
    const response = await api.get('/settings/ai');
    return response.data;
  },

  putAi: async (body: AISettingsUpdate): Promise<AISettings> => {
    const response = await api.put('/settings/ai', body);
    return response.data;
  },

  aiModels: async (provider: AIProviderName): Promise<AIModelsResponse> => {
    const response = await api.get('/settings/ai/models', { params: { provider } });
    return response.data;
  },
};

export const healthApi = {
  llm: async (): Promise<LLMHealth> => {
    const response = await api.get('/health/llm');
    return response.data;
  },
};

// ============================================================================
// Identity: SSO (OIDC), SCIM token management, custom roles.
// Contracts: src/schemas/identity.py, src/api/v1/endpoints/sso.py, roles.py,
// scim_admin.py. The login-side SSO calls live in api/publicAuth.ts (bare client).
// ============================================================================

export type IdentityTier = 'none' | 'read' | 'write' | 'admin';

export interface SSOConfig {
  id: string;
  organization_id: string;
  organization_slug: string;
  protocol: string;
  display_name: string | null;
  issuer: string;
  client_id: string;
  /** The secret itself is never returned. */
  client_secret_set: boolean;
  scopes: string;
  discovery_url: string | null;
  effective_discovery_url: string;
  /** Register this redirect URI at the identity provider. */
  redirect_uri: string;
  login_url: string;
  email_claim: string;
  name_claim: string;
  groups_claim: string | null;
  group_role_map: Record<string, string>;
  jit_provisioning: boolean;
  default_role: string;
  allowed_email_domains: string[];
  require_email_verified: boolean;
  trust_idp_mfa: boolean;
  enabled: boolean;
  last_tested_at: string | null;
  last_test_status: string | null;
  last_test_detail: string | null;
  updated_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

/** PUT /settings/sso body (full replace). client_secret: omitted/null keeps, "" clears. */
export interface SSOConfigUpdate {
  protocol: string;
  display_name: string | null;
  issuer: string;
  client_id: string;
  client_secret?: string | null;
  scopes: string;
  discovery_url: string | null;
  email_claim: string;
  name_claim: string;
  groups_claim: string | null;
  group_role_map: Record<string, string>;
  jit_provisioning: boolean;
  default_role: string;
  allowed_email_domains: string[];
  require_email_verified: boolean;
  trust_idp_mfa: boolean;
  enabled: boolean;
}

export interface SSOTestResult {
  status: string;
  tested_at: string;
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint: string | null;
  key_count: number;
  key_ids: string[];
  scopes_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  code_challenge_methods_supported: string[];
  id_token_signing_alg_values_supported: string[];
  warnings: string[];
}

export interface BuiltinRole {
  name: string;
  tier: string;
  description: string;
  member_count: number;
}

export interface CustomRole {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  default_tier: IdentityTier;
  area_tiers: Record<string, IdentityTier>;
  member_count: number;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface RoleList {
  builtin: BuiltinRole[];
  custom: CustomRole[];
}

export interface RoleBody {
  name: string;
  description: string | null;
  default_tier: IdentityTier;
  area_tiers: Record<string, IdentityTier>;
}

export interface AreaEntry {
  area: string;
  label: string;
  routes: number;
  write_routes: number;
  admin_routes: number;
  exempt: boolean;
  exempt_reason: string | null;
  builtin_tiers: Record<string, string>;
}

export interface AreaCatalogue {
  tiers: IdentityTier[];
  areas: AreaEntry[];
}

export interface RoleMember {
  id: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
  identity_source: string;
}

export interface RoleMembers {
  role_id: string;
  total: number;
  items: RoleMember[];
}

export interface SCIMToken {
  id: string;
  name: string;
  token_prefix: string;
  /** active | expired | revoked */
  status: string;
  created_by: string | null;
  created_at: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
}

export interface SCIMTokenCreated extends SCIMToken {
  /** Returned once, by the create call only. */
  token: string;
  scim_base_url: string;
}

export interface SCIMTokenList {
  scim_base_url: string;
  items: SCIMToken[];
}

export interface SCIMGroup {
  id: string;
  display_name: string;
  external_id: string | null;
  member_count: number;
  role: string | null;
  mapping_source: string | null;
  mapping_error: string | null;
  created: string | null;
  last_modified: string | null;
}

export interface SCIMUserLinkResult {
  id: string;
  email: string;
  identity_source: string;
  external_id: string | null;
  is_active: boolean;
}

export const identityApi = {
  /** 404 `sso_not_configured` when the organisation has none. */
  getSso: async (): Promise<SSOConfig> => {
    const response = await api.get('/settings/sso');
    return response.data;
  },
  putSso: async (body: SSOConfigUpdate): Promise<SSOConfig> => {
    const response = await api.put('/settings/sso', body);
    return response.data;
  },
  deleteSso: async (): Promise<void> => {
    await api.delete('/settings/sso');
  },
  /** 502 `sso_test_failed` {reason, detail} on failure; never a fake pass. */
  testSso: async (): Promise<SSOTestResult> => {
    const response = await api.post('/settings/sso/test');
    return response.data;
  },

  listRoles: async (): Promise<RoleList> => {
    const response = await api.get('/roles');
    return response.data;
  },
  roleAreas: async (): Promise<AreaCatalogue> => {
    const response = await api.get('/roles/areas');
    return response.data;
  },
  getRole: async (id: string): Promise<CustomRole> => {
    const response = await api.get(`/roles/${encodeURIComponent(id)}`);
    return response.data;
  },
  createRole: async (body: RoleBody): Promise<CustomRole> => {
    const response = await api.post('/roles', body);
    return response.data;
  },
  updateRole: async (id: string, body: RoleBody): Promise<CustomRole> => {
    const response = await api.put(`/roles/${encodeURIComponent(id)}`, body);
    return response.data;
  },
  /** 409 `role_in_use` {members} while anyone holds it. */
  deleteRole: async (id: string): Promise<void> => {
    await api.delete(`/roles/${encodeURIComponent(id)}`);
  },
  roleMembers: async (id: string): Promise<RoleMembers> => {
    const response = await api.get(`/roles/${encodeURIComponent(id)}/members`);
    return response.data;
  },

  listScimTokens: async (): Promise<SCIMTokenList> => {
    const response = await api.get('/settings/scim/tokens');
    return response.data;
  },
  createScimToken: async (body: { name: string; expires_in_days?: number | null }): Promise<SCIMTokenCreated> => {
    const response = await api.post('/settings/scim/tokens', body);
    return response.data;
  },
  revokeScimToken: async (id: string): Promise<void> => {
    await api.delete(`/settings/scim/tokens/${encodeURIComponent(id)}`);
  },
  listScimGroups: async (): Promise<{ items: SCIMGroup[] }> => {
    const response = await api.get('/settings/scim/groups');
    return response.data;
  },
  /** role: built-in name, custom role id or name; null removes the mapping. */
  setScimGroupRole: async (groupId: string, role: string | null): Promise<SCIMGroup> => {
    const response = await api.put(`/settings/scim/groups/${encodeURIComponent(groupId)}`, { role });
    return response.data;
  },
  linkScimUser: async (userId: string, externalId: string | null): Promise<SCIMUserLinkResult> => {
    const response = await api.post(`/settings/scim/users/${encodeURIComponent(userId)}/link`, {
      external_id: externalId,
    });
    return response.data;
  },
  unlinkScimUser: async (userId: string): Promise<SCIMUserLinkResult> => {
    const response = await api.delete(`/settings/scim/users/${encodeURIComponent(userId)}/link`);
    return response.data;
  },
};
