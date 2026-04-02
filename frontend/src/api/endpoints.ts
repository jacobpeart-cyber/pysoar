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
    return response.data;
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
    return response.data;
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
    const response = await api.get('/siem/events', { params });
    return response.data;
  },

  getSIEMRules: async (): Promise<SIEMRule[]> => {
    const response = await api.get('/siem/rules');
    return response.data;
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
    const response = await api.get('/siem/dashboard');
    return response.data;
  },
};

// Threat Intelligence
export const threatIntelApi = {
  getFeeds: async (): Promise<ThreatIntelFeed[]> => {
    const response = await api.get('/threat-intel/feeds');
    return response.data;
  },

  getIndicators: async (params?: {
    page?: number;
    size?: number;
    ioc_type?: string;
    threat_level?: string;
    search?: string;
  }): Promise<PaginatedResponse<ThreatIndicator>> => {
    const response = await api.get('/threat-intel/indicators', { params });
    return response.data;
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
    const response = await api.get('/hunting', { params });
    return response.data;
  },

  createHunt: async (data: {
    name: string;
    description: string;
    query: string;
  }): Promise<Hunt> => {
    const response = await api.post('/hunting', data);
    return response.data;
  },

  getHuntFindings: async (huntId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<HuntFinding>> => {
    const response = await api.get(`/hunting/${huntId}/findings`, { params });
    return response.data;
  },
};

// Exposure Management
export const exposureApi = {
  getExposureAssessments: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<ExposureAssessment>> => {
    const response = await api.get('/exposure', { params });
    return response.data;
  },

  getAttackSurface: async (): Promise<AttackSurface> => {
    const response = await api.get('/exposure/attack-surface');
    return response.data;
  },

  runScan: async (): Promise<{ task_id: string }> => {
    const response = await api.post('/exposure/scan');
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
    return response.data;
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
    return response.data;
  },

  getRiskScores: async (): Promise<RiskScore[]> => {
    const response = await api.get('/ueba/risk-scores');
    return response.data;
  },

  getAnomalies: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ user_id: string; anomaly_type: string; risk_score: number }>> => {
    const response = await api.get('/ueba/anomalies', { params });
    return response.data;
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
    return response.data;
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
    return response.data;
  },
};

// Deception Technology
export const deceptionApi = {
  getHoneypots: async (): Promise<Honeypot[]> => {
    const response = await api.get('/deception/honeypots');
    return response.data;
  },

  getHoneytokens: async (): Promise<Honeytoken[]> => {
    const response = await api.get('/deception/honeytokens');
    return response.data;
  },

  getDeceptionAlerts: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ id: string; type: string; timestamp: string; data: Record<string, any> }>> => {
    const response = await api.get('/deception/alerts', { params });
    return response.data;
  },
};

// Remediation
export const remediationApi = {
  getPolicies: async (): Promise<RemediationPolicy[]> => {
    const response = await api.get('/remediation/policies');
    return response.data;
  },

  getActions: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<RemediationAction>> => {
    const response = await api.get('/remediation/actions', { params });
    return response.data;
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
    return response.data;
  },

  getControls: async (frameworkId: string, params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<ComplianceControl>> => {
    const response = await api.get(`/compliance/frameworks/${frameworkId}/controls`, { params });
    return response.data;
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
    return response.data;
  },
};

// Zero Trust
export const zerotrustApi = {
  getPolicies: async (): Promise<ZeroTrustPolicy[]> => {
    const response = await api.get('/zerotrust/policies');
    return response.data;
  },

  getDeviceTrust: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<DeviceTrust>> => {
    const response = await api.get('/zerotrust/device-trust', { params });
    return response.data;
  },

  getAccessDecisions: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ device_id: string; access_granted: boolean; reason: string }>> => {
    const response = await api.get('/zerotrust/access-decisions', { params });
    return response.data;
  },
};

// STIG
export const stigApi = {
  getBenchmarks: async (): Promise<STIGBenchmark[]> => {
    const response = await api.get('/stig/benchmarks');
    return response.data;
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
    return response.data;
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
    return response.data;
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
    return response.data;
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
    return response.data;
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
    return response.data;
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
    return response.data;
  },

  getAccessAnomalies: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/itdr/anomalies', { params });
    return response.data;
  },

  getCredentialMonitors: async (): Promise<CredentialMonitor[]> => {
    const response = await api.get('/itdr/credential-monitors');
    return response.data;
  },

  getIdentities: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/itdr/identities', { params });
    return response.data;
  },

  getPrivilegedAccess: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/itdr/privileged-access', { params });
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
    return response.data;
  },

  runScan: async (assetId?: string): Promise<{ task_id: string }> => {
    const response = await api.post('/vulnmgmt/scan', assetId ? { asset_id: assetId } : {});
    return response.data;
  },

  getPatchOperations: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<PatchOperation>> => {
    const response = await api.get('/vulnmgmt/patch-operations', { params });
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
    return response.data;
  },

  getSupplyChainRisks: async (): Promise<{ risk_score: number; findings: Record<string, any>[] }> => {
    const response = await api.get('/supplychain/risks');
    return response.data;
  },

  getVendorAssessments: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<VendorAssessment>> => {
    const response = await api.get('/supplychain/vendor-assessments', { params });
    return response.data;
  },

  addComponent: async (data: { name: string; version: string; license: string }): Promise<any> => {
    const response = await api.post('/supplychain/components', data);
    return response.data;
  },

  downloadSBOM: async (sbomId: string): Promise<any> => {
    const response = await api.get(`/supplychain/sboms/${sbomId}/export`);
    return response.data;
  },
};

// Dark Web
export const darkwebApi = {
  getAlerts: async (params?: {
    page?: number;
    size?: number;
    type?: string;
    status?: string;
  }): Promise<PaginatedResponse<DarkWebAlert>> => {
    const response = await api.get('/darkweb/alerts', { params });
    return response.data;
  },

  getCredentialLeaks: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<{ email: string; password_hash: string; source: string; date_found: string }>> => {
    const response = await api.get('/darkweb/credential-leaks', { params });
    return response.data;
  },

  getBrandMonitors: async (): Promise<{ brand_name: string; mentions: number; alerts: DarkWebAlert[] }[]> => {
    const response = await api.get('/darkweb/brand-monitors');
    return response.data;
  },

  deleteMonitor: async (monitorId: string): Promise<void> => {
    await api.delete(`/darkweb/brand-monitors/${monitorId}`);
  },

  updateMonitor: async (monitorId: string, data: { name?: string; keyword?: string }): Promise<any> => {
    const response = await api.put(`/darkweb/brand-monitors/${monitorId}`, data);
    return response.data;
  },

  createMonitor: async (data: { name: string; keyword: string; frequency: string }): Promise<any> => {
    const response = await api.post('/darkweb/brand-monitors', data);
    return response.data;
  },

  requestTakedown: async (threatId: string): Promise<any> => {
    const response = await api.post(`/darkweb/brand-monitors/${threatId}/takedown`);
    return response.data;
  },
};

// Integrations
export const integrationsApi = {
  getConnectors: async (): Promise<Connector[]> => {
    const response = await api.get('/integrations/connectors');
    return response.data;
  },

  getInstalled: async (): Promise<Connector[]> => {
    const response = await api.get('/integrations/installed');
    return response.data;
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
    return response.data;
  },

  getInvestigations: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<Investigation>> => {
    const response = await api.get('/agentic/investigations', { params });
    return response.data;
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
    return response.data;
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
    return response.data;
  },

  getIncidents: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<DLPIncident>> => {
    const response = await api.get('/dlp/incidents', { params });
    return response.data;
  },

  getClassifications: async (): Promise<string[]> => {
    const response = await api.get('/dlp/classifications');
    return response.data;
  },
};

// Risk Quantification
export const riskquantApi = {
  getScenarios: async (): Promise<RiskScenario[]> => {
    const response = await api.get('/riskquant/scenarios');
    return response.data;
  },

  runAnalysis: async (scenarioIds: string[]): Promise<{ analysis_id: string }> => {
    const response = await api.post('/riskquant/analyze', { scenario_ids: scenarioIds });
    return response.data;
  },

  getLossExceedance: async (): Promise<any> => {
    const response = await api.get('/riskquant/loss-exceedance');
    return response.data;
  },

  createScenario: async (data: { name: string; description: string; loss_magnitude: number }): Promise<any> => {
    const response = await api.post('/riskquant/scenarios', data);
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
    const response = await api.get('/otsecurity/assets', { params });
    return response.data;
  },

  getAlerts: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<Alert>> => {
    const response = await api.get('/otsecurity/alerts', { params });
    return response.data;
  },

  getZones: async (): Promise<OTZone[]> => {
    const response = await api.get('/otsecurity/zones');
    return response.data;
  },

  getPurdueMap: async (): Promise<any> => {
    const response = await api.get('/otsecurity/purdue-map');
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
    const response = await api.get('/privacy/dsrs', { params });
    return response.data;
  },

  createDSR: async (data: {
    request_type: string;
    subject_email: string;
  }): Promise<DataSubjectRequest> => {
    const response = await api.post('/privacy/dsrs', data);
    return response.data;
  },

  getPIAs: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<PrivacyImpactAssessment>> => {
    const response = await api.get('/privacy/pias', { params });
    return response.data;
  },

  getConsentRecords: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/privacy/consent-records', { params });
    return response.data;
  },

  getProcessingRecords: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/privacy/processing-records', { params });
    return response.data;
  },

  getIncidents: async (params?: {
    page?: number;
    size?: number;
  }): Promise<any[]> => {
    const response = await api.get('/privacy/incidents', { params });
    return response.data;
  },
};

// Threat Modeling
export const threatmodelApi = {
  getModels: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<ThreatModel>> => {
    const response = await api.get('/threatmodel/models', { params });
    return response.data;
  },

  runSTRIDE: async (data: { application_id: string }): Promise<{ model_id: string }> => {
    const response = await api.post('/threatmodel/stride', data);
    return response.data;
  },

  getAttackTrees: async (modelId: string): Promise<AttackTree[]> => {
    const response = await api.get(`/threatmodel/models/${modelId}/attack-trees`);
    return response.data;
  },

  getMitigations: async (modelId: string): Promise<any[]> => {
    const response = await api.get(`/threatmodel/models/${modelId}/mitigations`);
    return response.data;
  },

  getSTRIDEAnalysis: async (): Promise<any[]> => {
    const response = await api.get('/threatmodel/stride');
    return response.data;
  },

  getThreats: async (): Promise<any[]> => {
    const response = await api.get('/threatmodel/threats');
    return response.data;
  },

  createModel: async (data: any): Promise<any> => {
    const response = await api.post('/threatmodel/models', data);
    return response.data;
  },
};

// API Security
export const apisecurityApi = {
  getAPIs: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<APIEndpoint>> => {
    const response = await api.get('/apisecurity/endpoints', { params });
    return response.data;
  },

  getVulnerabilities: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<Vulnerability>> => {
    const response = await api.get('/apisecurity/vulnerabilities', { params });
    return response.data;
  },

  getAnomalies: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<any>> => {
    const response = await api.get('/apisecurity/anomalies', { params });
    return response.data;
  },

  getPolicies: async (): Promise<any[]> => {
    const response = await api.get('/apisecurity/policies');
    return response.data;
  },

  registerAPI: async (data: { name: string; method: string }): Promise<any> => {
    const response = await api.post('/apisecurity/endpoints', data);
    return response.data;
  },
};

// Data Lake
export const datalakeApi = {
  getDataSources: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<DataSource>> => {
    const response = await api.get('/datalake/sources', { params });
    return response.data;
  },

  getPipelines: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<DataLakePipeline>> => {
    const response = await api.get('/datalake/pipelines', { params });
    return response.data;
  },

  runQuery: async (query: string): Promise<any> => {
    const response = await api.post('/datalake/query', { query });
    return response.data;
  },

  getCatalog: async (): Promise<any[]> => {
    const response = await api.get('/datalake/catalog');
    return response.data;
  },

  createDataSource: async (data: { name: string; connection_string: string }): Promise<any> => {
    const response = await api.post('/datalake/sources', data);
    return response.data;
  },
};

// Collaboration
export const collaborationApi = {
  getWarRooms: async (params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<WarRoom>> => {
    const response = await api.get('/collaboration/warrooms', { params });
    return response.data;
  },

  createWarRoom: async (data: { title: string; description?: string }): Promise<WarRoom> => {
    const response = await api.post('/collaboration/warrooms', data);
    return response.data;
  },

  getMessages: async (warRoomId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<WarRoomMessage>> => {
    const response = await api.get(`/collaboration/warrooms/${warRoomId}/messages`, { params });
    return response.data;
  },

  getActionItems: async (warRoomId: string): Promise<ActionItem[]> => {
    const response = await api.get(`/collaboration/warrooms/${warRoomId}/action-items`);
    return response.data;
  },

  createActionItem: async (data: { title: string; priority: string }): Promise<any> => {
    const response = await api.post('/collaboration/action-items', data);
    return response.data;
  },

  sendMessage: async (warRoomId: string, data: { text: string }): Promise<any> => {
    const response = await api.post(`/collaboration/warrooms/${warRoomId}/messages`, data);
    return response.data;
  },

  closeWarRoom: async (warRoomId: string): Promise<any> => {
    const response = await api.post(`/collaboration/warrooms/${warRoomId}/close`);
    return response.data;
  },
};

// Phishing Awareness
export const phishingApi = {
  getCampaigns: async (params?: {
    page?: number;
    size?: number;
    status?: string;
  }): Promise<PaginatedResponse<PhishingCampaign>> => {
    const response = await api.get('/phishing/campaigns', { params });
    return response.data;
  },

  createCampaign: async (data: {
    name: string;
    description: string;
    targets: string[];
  }): Promise<PhishingCampaign> => {
    const response = await api.post('/phishing/campaigns', data);
    return response.data;
  },

  getResults: async (campaignId: string, params?: {
    page?: number;
    size?: number;
  }): Promise<PaginatedResponse<PhishingResult>> => {
    const response = await api.get(`/phishing/campaigns/${campaignId}/results`, { params });
    return response.data;
  },

  getAwarenessScores: async (): Promise<{ user_email: string; awareness_score: number }[]> => {
    const response = await api.get('/phishing/awareness-scores');
    return response.data;
  },

  getTemplates: async (): Promise<any[]> => {
    const response = await api.get('/phishing/templates');
    return response.data;
  },

  getTargetGroups: async (): Promise<any[]> => {
    const response = await api.get('/phishing/target-groups');
    return response.data;
  },

  launchCampaign: async (groupId: string): Promise<any> => {
    const response = await api.post(`/phishing/campaigns/launch`, { target_group_id: groupId });
    return response.data;
  },
};
