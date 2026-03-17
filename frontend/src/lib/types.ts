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

export interface Alert {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  source: string;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
  alert_count?: number;
  alerts?: Alert[];
}

export interface IOC {
  id: string;
  value: string;
  ioc_type: string;
  threat_level: string;
  source: string | null;
  description: string | null;
  tags: string[] | null;
  is_active: boolean;
  first_seen: string;
  last_seen: string | null;
  created_at: string;
  updated_at: string;
}

export interface PlaybookStep {
  id: string;
  name: string;
  action: string;
  parameters: Record<string, any>;
  on_success?: string;
  on_failure?: string;
  timeout_seconds?: number;
  continue_on_error?: boolean;
}

export interface Playbook {
  id: string;
  name: string;
  description: string | null;
  status: string;
  trigger_type: string;
  trigger_conditions: Record<string, any> | null;
  steps: PlaybookStep[];
  variables: Record<string, any> | null;
  category: string | null;
  tags: string[] | null;
  version: number;
  is_enabled: boolean;
  timeout_seconds: number;
  max_retries: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  incident_id: string | null;
  status: string;
  current_step: number;
  total_steps: number;
  started_at: string | null;
  completed_at: string | null;
  input_data: Record<string, any> | null;
  output_data: Record<string, any> | null;
  step_results: Record<string, any>[] | null;
  error_message: string | null;
  error_step: number | null;
  triggered_by: string | null;
  trigger_source: string | null;
  created_at: string;
  updated_at: string;
}

export interface Asset {
  id: string;
  name: string;
  hostname: string | null;
  asset_type: string;
  status: string;
  ip_address: string | null;
  mac_address: string | null;
  fqdn: string | null;
  criticality: string;
  business_unit: string | null;
  department: string | null;
  owner: string | null;
  location: string | null;
  operating_system: string | null;
  os_version: string | null;
  cloud_provider: string | null;
  cloud_region: string | null;
  cloud_instance_id: string | null;
  security_score: number | null;
  last_scan: string | null;
  description: string | null;
  tags: string[] | null;
  is_monitored: boolean;
  agent_installed: boolean;
  last_seen: string | null;
  created_at: string;
  updated_at: string;
}
