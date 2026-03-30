// Common types
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'new' | 'acknowledged' | 'in_progress' | 'resolved' | 'closed';
export type IncidentStatus = 'open' | 'in_progress' | 'resolved' | 'closed';
export type IOCType = 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'file' | 'process';
export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

// Alerts
export interface Alert {
  id: string;
  title: string;
  description: string | null;
  severity: SeverityLevel;
  status: AlertStatus;
  source: string;
  created_at: string;
  updated_at: string;
  alert_count?: number;
}

// Incidents
export interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: SeverityLevel;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  alert_count?: number;
  alerts?: Alert[];
}

// SIEM
export interface SIEMEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  event_type: string;
  severity: SeverityLevel;
  description: string;
  raw_data: Record<string, any>;
}

export interface SIEMRule {
  id: string;
  name: string;
  description: string;
  query: string;
  severity: SeverityLevel;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface SIEMDashboard {
  events_today: number;
  alerts_today: number;
  critical_alerts: number;
  event_sources: Array<{ name: string; count: number }>;
  event_types: Array<{ type: string; count: number }>;
}

// Threat Intelligence
export interface ThreatIndicator {
  id: string;
  value: string;
  ioc_type: IOCType;
  threat_level: ThreatLevel;
  source: string | null;
  description: string | null;
  tags: string[] | null;
  is_active: boolean;
  first_seen: string;
  last_seen: string | null;
  created_at: string;
  updated_at: string;
}

export interface ThreatIntelFeed {
  id: string;
  name: string;
  description: string;
  source_url: string;
  feed_type: string;
  enabled: boolean;
  last_updated: string;
  indicator_count: number;
}

export interface EnrichmentResult {
  indicator: string;
  ioc_type: IOCType;
  threat_level: ThreatLevel;
  sources: string[];
  related_indicators: ThreatIndicator[];
  last_seen: string | null;
}

// Hunting
export interface Hunt {
  id: string;
  name: string;
  description: string;
  created_by: string;
  created_at: string;
  status: 'draft' | 'active' | 'completed';
  query: string;
  findings_count: number;
}

export interface HuntFinding {
  id: string;
  hunt_id: string;
  event_id: string;
  event_data: Record<string, any>;
  risk_score: number;
  created_at: string;
}

// Exposure Management
export interface ExposureAssessment {
  id: string;
  name: string;
  description: string;
  status: 'draft' | 'in_progress' | 'completed';
  exposure_score: number;
  findings: ExposureItem[];
  created_at: string;
  updated_at: string;
}

export interface ExposureItem {
  id: string;
  type: string;
  severity: SeverityLevel;
  description: string;
  remediation: string;
  status: 'open' | 'in_progress' | 'resolved';
}

export interface AttackSurface {
  total_assets: number;
  exposed_assets: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  exposed_services: Array<{ name: string; count: number }>;
}

// AI/Analytics
export interface AIPrediction {
  id: string;
  type: string;
  prediction: string;
  confidence: number;
  explanation: string;
  created_at: string;
}

export interface AnalysisResult {
  id: string;
  analysis_type: string;
  status: 'in_progress' | 'completed' | 'failed';
  result: Record<string, any>;
  created_at: string;
  completed_at: string | null;
}

// UEBA
export interface UserBehavior {
  user_id: string;
  username: string;
  risk_score: number;
  anomaly_count: number;
  last_activity: string;
  behavior_summary: string;
}

export interface RiskScore {
  user_id: string;
  overall_risk: number;
  authentication_risk: number;
  data_access_risk: number;
  lateral_movement_risk: number;
  last_updated: string;
}

// Attack Simulation
export interface SimulationCampaign {
  id: string;
  name: string;
  type: 'phishing' | 'malware' | 'social_engineering';
  status: 'draft' | 'running' | 'completed';
  target_count: number;
  success_count: number;
  created_at: string;
  completed_at: string | null;
}

export interface SimulationResult {
  campaign_id: string;
  user_email: string;
  result: 'clicked' | 'reported' | 'ignored' | 'failed';
  timestamp: string;
}

// Deception Technology
export interface Honeypot {
  id: string;
  name: string;
  type: string;
  status: 'active' | 'inactive';
  interactions: number;
  last_interaction: string | null;
  created_at: string;
}

export interface Honeytoken {
  id: string;
  name: string;
  type: string;
  status: 'active' | 'triggered';
  placement: string;
  interactions: number;
  created_at: string;
  triggered_at: string | null;
}

// Remediation
export interface RemediationPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  actions: RemediationAction[];
  created_at: string;
}

export interface RemediationAction {
  id: string;
  policy_id: string;
  action_type: string;
  target: string;
  status: 'pending' | 'approved' | 'executed' | 'failed';
  created_at: string;
}

// Compliance
export interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  control_count: number;
  compliance_score: number;
  last_assessed: string;
}

export interface ComplianceControl {
  id: string;
  framework_id: string;
  control_id: string;
  description: string;
  status: 'compliant' | 'non_compliant' | 'in_progress';
  evidence_count: number;
}

export interface POAM {
  id: string;
  description: string;
  severity: SeverityLevel;
  status: 'open' | 'in_progress' | 'closed';
  target_completion_date: string;
  created_at: string;
  updated_at: string;
}

// Zero Trust
export interface ZeroTrustPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rules: Array<Record<string, any>>;
  created_at: string;
}

export interface DeviceTrust {
  device_id: string;
  device_name: string;
  trust_score: number;
  last_assessment: string;
  compliant: boolean;
}

// STIG
export interface STIGBenchmark {
  id: string;
  name: string;
  version: string;
  finding_count: number;
  compliant_count: number;
  last_scan: string | null;
}

export interface STIGFinding {
  id: string;
  benchmark_id: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  status: 'compliant' | 'non_compliant';
}

// Audit Evidence
export interface AuditEvidence {
  id: string;
  type: string;
  description: string;
  source: string;
  collected_at: string;
  evidence_data: Record<string, any>;
}

// DFIR
export interface DFIRCase {
  id: string;
  title: string;
  description: string;
  status: 'open' | 'in_progress' | 'closed';
  severity: SeverityLevel;
  created_at: string;
  created_by: string;
}

export interface DFIRTimeline {
  timestamp: string;
  event_type: string;
  description: string;
  source: string;
  data: Record<string, any>;
}

// ITDR
export interface IdentityThreat {
  id: string;
  user_id: string;
  threat_type: string;
  severity: SeverityLevel;
  description: string;
  detected_at: string;
  status: 'open' | 'mitigated';
}

export interface CredentialMonitor {
  id: string;
  username: string;
  password_age_days: number;
  mfa_enabled: boolean;
  last_login: string;
  risk_score: number;
}

// Vulnerability Management
export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  cvss_score: number;
  affected_asset: string;
  status: 'open' | 'in_progress' | 'resolved';
  discovered_at: string;
}

export interface PatchOperation {
  id: string;
  vulnerability_id: string;
  target_assets: string[];
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  created_at: string;
  completed_at: string | null;
}

// Supply Chain
export interface SBOM {
  id: string;
  application_id: string;
  components: SBOMComponent[];
  generated_at: string;
}

export interface SBOMComponent {
  name: string;
  version: string;
  license: string;
  vulnerabilities: Vulnerability[];
}

export interface VendorAssessment {
  id: string;
  vendor_name: string;
  assessment_date: string;
  risk_score: number;
  compliance_status: string;
}

// Dark Web
export interface DarkWebAlert {
  id: string;
  type: 'credential_leak' | 'brand_mention' | 'data_dump';
  severity: SeverityLevel;
  description: string;
  source: string;
  detected_at: string;
  status: 'new' | 'acknowledged' | 'resolved';
}

// Integrations
export interface Connector {
  id: string;
  name: string;
  type: string;
  status: 'connected' | 'disconnected' | 'error';
  last_sync: string | null;
  config: Record<string, any>;
}

// Agentic Automation
export interface Agent {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  last_execution: string | null;
  success_rate: number;
}

export interface Investigation {
  id: string;
  description: string;
  status: 'in_progress' | 'completed' | 'failed';
  reasoning_steps: string[];
  conclusion: string | null;
  created_at: string;
  completed_at: string | null;
}

// Playbook Builder
export interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger_type: string;
  status: 'draft' | 'active' | 'inactive';
  nodes: PlaybookNode[];
  created_at: string;
  updated_at: string;
}

export interface PlaybookNode {
  id: string;
  type: string;
  config: Record<string, any>;
  position: { x: number; y: number };
}

// DLP
export interface DLPPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rules: DLPRule[];
  created_at: string;
}

export interface DLPRule {
  id: string;
  pattern: string;
  severity: SeverityLevel;
  action: string;
}

export interface DLPIncident {
  id: string;
  policy_id: string;
  user: string;
  action: string;
  severity: SeverityLevel;
  status: 'open' | 'resolved';
  detected_at: string;
}

// Risk Quantification
export interface RiskScenario {
  id: string;
  name: string;
  description: string;
  probability: number;
  impact: number;
  calculated_risk: number;
}

export interface LossExceedanceAnalysis {
  scenarios: RiskScenario[];
  loss_values: number[];
  percentiles: Array<{ percentile: number; loss: number }>;
}

// OT Security
export interface OTAsset {
  id: string;
  name: string;
  asset_type: string;
  status: 'online' | 'offline';
  last_seen: string;
  vulnerabilities: number;
}

export interface OTZone {
  id: string;
  name: string;
  description: string;
  asset_count: number;
  risk_score: number;
}

// Container Security
export interface ContainerImage {
  id: string;
  repository: string;
  tag: string;
  digest: string;
  vulnerabilities: number;
  last_scanned: string | null;
}

export interface ContainerScan {
  id: string;
  image_id: string;
  scan_date: string;
  vulnerabilities: Vulnerability[];
  status: 'in_progress' | 'completed' | 'failed';
}

// Privacy
export interface DataSubjectRequest {
  id: string;
  request_type: 'access' | 'deletion' | 'portability';
  subject_email: string;
  status: 'received' | 'in_progress' | 'completed';
  received_date: string;
  due_date: string;
}

export interface PrivacyImpactAssessment {
  id: string;
  name: string;
  description: string;
  status: 'draft' | 'in_progress' | 'completed';
  risk_level: 'low' | 'medium' | 'high';
  created_at: string;
}

// Threat Modeling
export interface ThreatModel {
  id: string;
  name: string;
  description: string;
  status: 'draft' | 'in_progress' | 'completed';
  methodology: 'stride' | 'pasta';
  created_at: string;
}

export interface AttackTree {
  id: string;
  threat_model_id: string;
  root_node: AttackTreeNode;
}

export interface AttackTreeNode {
  id: string;
  name: string;
  description: string;
  children?: AttackTreeNode[];
}

// API Security
export interface APIEndpoint {
  id: string;
  path: string;
  method: string;
  authentication: string;
  rate_limit: number;
  vulnerabilities: Vulnerability[];
}

// Data Lake
export interface DataSource {
  id: string;
  name: string;
  type: string;
  connection_status: 'connected' | 'disconnected';
  record_count: number;
  last_updated: string;
}

export interface DataLakePipeline {
  id: string;
  name: string;
  source_id: string;
  destination: string;
  status: 'running' | 'paused' | 'error';
  last_execution: string;
}

// Collaboration
export interface WarRoom {
  id: string;
  title: string;
  description: string;
  status: 'active' | 'archived';
  participants: User[];
  created_at: string;
  created_by: string;
}

export interface WarRoomMessage {
  id: string;
  war_room_id: string;
  user_id: string;
  message: string;
  created_at: string;
}

export interface ActionItem {
  id: string;
  war_room_id: string;
  description: string;
  assigned_to: string;
  status: 'open' | 'in_progress' | 'completed';
  due_date: string | null;
}

// Phishing
export interface PhishingCampaign {
  id: string;
  name: string;
  description: string;
  status: 'draft' | 'running' | 'completed';
  targets: number;
  clicks: number;
  submissions: number;
  created_at: string;
  completed_at: string | null;
}

export interface PhishingResult {
  campaign_id: string;
  recipient_email: string;
  action: 'clicked' | 'reported' | 'ignored';
  timestamp: string;
}
