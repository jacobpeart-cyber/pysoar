import { api } from './client';
import {
  PaginatedResponse,
  Alert,
  Incident,
  SIEMEvent,
  SIEMRule,
  SIEMDashboard,
  ThreatIndicator,
  ThreatIntelFeed,
  EnrichmentResult,
  Hunt,
  HuntFinding,
  ExposureAssessment,
  AttackSurface,
  AIPrediction,
  AnalysisResult,
  UserBehavior,
  RiskScore,
  SimulationCampaign,
  SimulationResult,
  Honeypot,
  Honeytoken,
  RemediationPolicy,
  RemediationAction,
  ComplianceFramework,
  ComplianceControl,
  POAM,
  ZeroTrustPolicy,
  DeviceTrust,
  STIGBenchmark,
  STIGFinding,
  AuditEvidence,
  DFIRCase,
  DFIRTimeline,
  IdentityThreat,
  CredentialMonitor,
  Vulnerability,
  PatchOperation,
  SBOM,
  VendorAssessment,
  DarkWebAlert,
  Connector,
  Agent,
  Investigation,
  Playbook,
  PlaybookNode,
  DLPPolicy,
  DLPIncident,
  RiskScenario,
  OTAsset,
  OTZone,
  ContainerImage,
  ContainerScan,
  DataSubjectRequest,
  PrivacyImpactAssessment,
  ThreatModel,
  AttackTree,
  APIEndpoint,
  DataSource,
  DataLakePipeline,
  WarRoom,
  WarRoomMessage,
  ActionItem,
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

  bulkUpdateAlerts: async (ids: string[], data: Partial<Alert>): Promise<void> => {
    await api.post('/alerts/bulk-update', { ids, data });
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

  enrichIOC: async (value: string): Promise<EnrichmentResult> => {
    const response = await api.post('/threat-intel/enrich', { indicator: value });
    return response.data;
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

  runAnalysis: async (data: {
    analysis_type: string;
    input_data: Record<string, any>;
  }): Promise<AnalysisResult> => {
    const response = await api.post('/ai/analyze', data);
    return response.data;
  },

  queryNaturalLanguage: async (query: string): Promise<{ result: string; reasoning: string }> => {
    const response = await api.post('/ai/natural-language', { query });
    return response.data;
  },
};

// UEBA
export const uebaApi = {
  getUserBehaviors: async (params?: {
    page?: number;
    size?: number;
    search?: string;
  }): Promise<PaginatedResponse<UserBehavior>> => {
    const response = await api.get('/ueba/behaviors', { params });
    return extractData(response.data);
  },

  getRiskScores: async (): Promise<RiskScore[]> => {
    const response = await api.get('/ueba/risk-scores');
    return extractData(response.data);
  },

  getAnomalies: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ user_id: string; anomaly_type: string; risk_score: number }>> => {
    const response = await api.get('/ueba/anomalies', { params });
    return extractData(response.data);
  },
};

// Attack Simulation
export const simulationApi = {
  getCampaigns: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<SimulationCampaign>> => {
    const response = await api.get('/simulation/campaigns', { params });
    return extractData(response.data);
  },

  launchSimulation: async (data: {
    name: string;
    type: string;
    targets: string[];
  }): Promise<SimulationCampaign> => {
    const response = await api.post('/simulation/campaigns', data);
    return response.data;
  },

  getResults: async (campaignId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<SimulationResult>> => {
    const response = await api.get(`/simulation/campaigns/${campaignId}/results`, { params });
    return extractData(response.data);
  },
};

// Deception Technology
export const deceptionApi = {
  getHoneypots: async (): Promise<Honeypot[]> => {
    const response = await api.get('/deception/honeypots');
    return extractData(response.data);
  },

  getHoneytokens: async (): Promise<Honeytoken[]> => {
    const response = await api.get('/deception/honeytokens');
    return extractData(response.data);
  },

  getDeceptionAlerts: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ id: string; type: string; timestamp: string; data: Record<string, any> }>> => {
    const response = await api.get('/deception/alerts', { params });
    return extractData(response.data);
  },
};

// Remediation
export const remediationApi = {
  getPolicies: async (): Promise<RemediationPolicy[]> => {
    const response = await api.get('/remediation/policies');
    return extractData(response.data);
  },

  getActions: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<RemediationAction>> => {
    const response = await api.get('/remediation/actions', { params });
    return extractData(response.data);
  },

  approveAction: async (id: string): Promise<RemediationAction> => {
    const response = await api.post(`/remediation/actions/${id}/approve`);
    return response.data;
  },

  executeAction: async (id: string): Promise<RemediationAction> => {
    const response = await api.post(`/remediation/actions/${id}/execute`);
    return response.data;
  },
};

// Compliance
export const complianceApi = {
  getFrameworks: async (): Promise<ComplianceFramework[]> => {
    const response = await api.get('/compliance/frameworks');
    return extractData(response.data);
  },

  getControls: async (frameworkId: string, params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<ComplianceControl>> => {
    const response = await api.get(`/compliance/frameworks/${frameworkId}/controls`, { params });
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

  runScan: async (benchmarkId: string): Promise<{ task_id: string }> => {
    const response = await api.post(`/stig/benchmarks/${benchmarkId}/scan`);
    return response.data;
  },

  getFindings: async (benchmarkId: string, params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<STIGFinding>> => {
    const response = await api.get(`/stig/benchmarks/${benchmarkId}/findings`, { params });
    return extractData(response.data);
  },
};

// Audit Evidence
export const auditEvidenceApi = {
  getEvidence: async (params?: {
    page?: number;
    size?: number;
    type?: string;
  }): Promise<PaginatedResponse<AuditEvidence>> => {
    const response = await api.get('/audit/evidence', { params });
    return extractData(response.data);
  },

  collectEvidence: async (data: {
    type: string;
    description: string;
    source: string;
    evidence_data: Record<string, any>;
  }): Promise<AuditEvidence> => {
    const response = await api.post('/audit/evidence', data);
    return response.data;
  },

  getReadinessScore: async (): Promise<{ score: number; details: Record<string, any> }> => {
    const response = await api.get('/audit/readiness-score');
    return response.data;
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

  getCredentialMonitors: async (): Promise<CredentialMonitor[]> => {
    const response = await api.get('/itdr/credential-monitors');
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

  runScanProfile: async (profileId: string): Promise<any> => {
    // Scan profiles are executed by creating a scan run via the
    // vulnerability scanner. The import-scan endpoint is the realistic
    // trigger — it imports findings from a named scan profile.
    const response = await api.post('/vulnmgmt/vulnerabilities/import-scan', { scan_profile_id: profileId });
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

  installConnector: async (connectorId: string, config: Record<string, any>): Promise<Connector> => {
    const response = await api.post(`/integrations/connectors/${connectorId}/install`, { config });
    return response.data;
  },

  executeAction: async (connectorId: string, action: string, params: Record<string, any>): Promise<any> => {
    const response = await api.post(`/integrations/connectors/${connectorId}/execute`, { action, params });
    return response.data;
  },

  configureConnector: async (connectorId: string, config: Record<string, any>): Promise<any> => {
    const response = await api.put(`/integrations/connectors/${connectorId}/config`, config);
    return response.data;
  },

  testConnector: async (connectorId: string): Promise<any> => {
    const response = await api.post(`/integrations/connectors/${connectorId}/test`);
    return response.data;
  },

  createWebhook: async (data: { name: string; url: string; event: string }): Promise<any> => {
    const response = await api.post('/integrations/webhooks', data);
    return response.data;
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

  getReasoningChain: async (investigationId: string): Promise<{ steps: string[]; conclusion: string }> => {
    const response = await api.get(`/agentic/investigations/${investigationId}/reasoning`);
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

  getNodes: async (playbookId: string): Promise<PlaybookNode[]> => {
    const response = await api.get(`/playbooks/${playbookId}/nodes`);
    return extractData(response.data);
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
    // Get action items across all active rooms
    try {
      const roomsRes = await api.get('/collaboration/rooms', { params: { size: 50 } });
      const rooms = extractData(roomsRes.data) ?? [];
      const allItems: any[] = [];
      for (const room of rooms) {
        try {
          const res = await api.get(`/collaboration/rooms/${room.id}/actions`);
          const items = extractData(res.data) ?? [];
          for (const item of items) {
            allItems.push({ ...item, _room_name: room.name });
          }
        } catch { /* room may have no actions */ }
      }
      return allItems;
    } catch { return []; }
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

  getDashboard: async (): Promise<any> => {
    const response = await api.get('/collaboration/dashboard');
    return response.data;
  },

  getPostMortem: async (roomId: string): Promise<any> => {
    const response = await api.get(`/collaboration/rooms/${roomId}/postmortem/analysis`);
    return response.data;
  },

  getArchivedRooms: async (): Promise<any[]> => {
    try {
      const response = await api.get('/collaboration/rooms', { params: { status: 'archived', size: 50 } });
      return extractData(response.data) ?? [];
    } catch { return []; }
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
