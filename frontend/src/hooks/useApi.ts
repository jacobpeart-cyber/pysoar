import { useQuery, useMutation, UseQueryOptions, UseMutationOptions } from '@tanstack/react-query';
import { useCallback } from 'react';
import {
  alertsApi,
  incidentsApi,
  siemApi,
  threatIntelApi,
  huntingApi,
  exposureApi,
  aiApi,
  uebaApi,
  simulationApi,
  deceptionApi,
  remediationApi,
  complianceApi,
  vulnmgmtApi,
  supplychainApi,
  darkwebApi,
  integrationsApi,
  agenticApi,
  playbookApi,
  dlpApi,
  otsecurityApi,
  containerApi,
  privacyApi,
  apisecurityApi,
  datalakeApi,
  collaborationApi,
  phishingApi,
  Alert,
  Incident,
  SIEMDashboard,
  ThreatIndicator,
  AxiosError,
} from '../api';

// Alerts
export const useAlerts = (
  params?: { page?: number; size?: number; status?: string; severity?: string; search?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => alertsApi.getAlerts(params),
    ...options,
  });
};

export const useAlert = (id: string, options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['alerts', id],
    queryFn: () => alertsApi.getAlert(id),
    enabled: !!id,
    ...options,
  });
};

// Incidents
export const useIncidents = (
  params?: { page?: number; size?: number; status?: string; severity?: string; search?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['incidents', params],
    queryFn: () => incidentsApi.getIncidents(params),
    ...options,
  });
};

export const useIncident = (id: string, options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['incidents', id],
    queryFn: () => incidentsApi.getIncident(id),
    enabled: !!id,
    ...options,
  });
};

// SIEM
export const useSIEMDashboard = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['siem', 'dashboard'],
    queryFn: () => siemApi.getSIEMDashboard(),
    ...options,
  });
};

export const useSIEMEvents = (
  params?: { page?: number; size?: number; source?: string; severity?: string; date_range?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['siem', 'events', params],
    queryFn: () => siemApi.getSIEMEvents(params),
    ...options,
  });
};

export const useSIEMRules = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['siem', 'rules'],
    queryFn: () => siemApi.getSIEMRules(),
    ...options,
  });
};

// Threat Intelligence
export const useThreatIntelIndicators = (
  params?: { page?: number; size?: number; ioc_type?: string; threat_level?: string; search?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['threat-intel', 'indicators', params],
    queryFn: () => threatIntelApi.getIndicators(params),
    ...options,
  });
};

export const useThreatIntelFeeds = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['threat-intel', 'feeds'],
    queryFn: () => threatIntelApi.getFeeds(),
    ...options,
  });
};

// Hunting
export const useHunts = (
  params?: { page?: number; size?: number; status?: string; search?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['hunting', 'hunts', params],
    queryFn: () => huntingApi.getHunts(params),
    ...options,
  });
};

// Exposure
export const useExposureAssessments = (
  params?: { page?: number; size?: number; status?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['exposure', 'assessments', params],
    queryFn: () => exposureApi.getExposureAssessments(params),
    ...options,
  });
};

export const useAttackSurface = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['exposure', 'attack-surface'],
    queryFn: () => exposureApi.getAttackSurface(),
    ...options,
  });
};

// UEBA
export const useUserBehaviors = (
  params?: { page?: number; size?: number; search?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['ueba', 'behaviors', params],
    queryFn: () => uebaApi.getUserBehaviors(params),
    ...options,
  });
};

export const useRiskScores = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['ueba', 'risk-scores'],
    queryFn: () => uebaApi.getRiskScores(),
    ...options,
  });
};

// Compliance
export const useComplianceFrameworks = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['compliance', 'frameworks'],
    queryFn: () => complianceApi.getFrameworks(),
    ...options,
  });
};

export const usePOAMs = (
  params?: { page?: number; size?: number; status?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['compliance', 'poams', params],
    queryFn: () => complianceApi.getPOAMs(params),
    ...options,
  });
};

// Vulnerabilities
export const useVulnerabilities = (
  params?: { page?: number; size?: number; severity?: string; status?: string; search?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['vulnmgmt', 'vulnerabilities', params],
    queryFn: () => vulnmgmtApi.getVulnerabilities(params),
    ...options,
  });
};

// Playbooks
export const usePlaybooks = (
  params?: { page?: number; size?: number; status?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['playbooks', params],
    queryFn: () => playbookApi.getPlaybooks(params),
    ...options,
  });
};

// DLP
export const useDLPPolicies = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['dlp', 'policies'],
    queryFn: () => dlpApi.getPolicies(),
    ...options,
  });
};

export const useDLPIncidents = (
  params?: { page?: number; size?: number; status?: string },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['dlp', 'incidents', params],
    queryFn: () => dlpApi.getIncidents(params),
    ...options,
  });
};

// Integrations
export const useConnectors = (options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>) => {
  return useQuery({
    queryKey: ['integrations', 'connectors'],
    queryFn: () => integrationsApi.getConnectors(),
    ...options,
  });
};

// Collaboration
export const useWarRooms = (
  params?: { page?: number; size?: number },
  options?: Omit<UseQueryOptions, 'queryKey' | 'queryFn'>
) => {
  return useQuery({
    queryKey: ['collaboration', 'warrooms', params],
    queryFn: () => collaborationApi.getWarRooms(params),
    ...options,
  });
};

// Generic mutation hook with toast notifications
export const useMutationWithToast = <TData, TError = AxiosError, TVariables = unknown>(
  mutationFn: (variables: TVariables) => Promise<TData>,
  options?: Omit<UseMutationOptions<TData, TError, TVariables>, 'mutationFn'>
) => {
  return useMutation({
    mutationFn,
    ...options,
  });
};

// Common mutations
export const useUpdateAlert = () => {
  return useMutationWithToast(
    ({ id, data }: { id: string; data: Partial<Alert> }) => alertsApi.updateAlert(id, data)
  );
};

export const useCreateIncident = () => {
  return useMutationWithToast(
    (data: { title: string; description?: string; severity: string }) => incidentsApi.createIncident(data)
  );
};

export const useUpdateIncident = () => {
  return useMutationWithToast(
    ({ id, data }: { id: string; data: Partial<Incident> }) => incidentsApi.updateIncident(id, data)
  );
};

export const useCreateHunt = () => {
  return useMutationWithToast(
    (data: { name: string; description: string; query: string }) => huntingApi.createHunt(data)
  );
};

export const useRunExposureScan = () => {
  return useMutationWithToast(() => exposureApi.runScan());
};

export const useRunVulnerabilityS = () => {
  return useMutationWithToast((assetId?: string) => vulnmgmtApi.runScan(assetId));
};

export const useApproveRemediationAction = () => {
  return useMutationWithToast((id: string) => remediationApi.approveAction(id));
};

export const useExecuteRemediationAction = () => {
  return useMutationWithToast((id: string) => remediationApi.executeAction(id));
};

export const useCreatePlaybook = () => {
  return useMutationWithToast(
    (data: { name: string; description: string; trigger_type: string }) => playbookApi.createPlaybook(data)
  );
};

export const useExecutePlaybook = () => {
  return useMutationWithToast(
    ({ playbookId, input_data }: { playbookId: string; input_data?: Record<string, any> }) =>
      playbookApi.executePlaybook(playbookId, input_data)
  );
};

export const useCreateWarRoom = () => {
  return useMutationWithToast(
    (data: { title: string; description?: string }) => collaborationApi.createWarRoom(data)
  );
};

export const useEnrichIOC = () => {
  return useMutationWithToast((value: string) => threatIntelApi.enrichIOC(value));
};
