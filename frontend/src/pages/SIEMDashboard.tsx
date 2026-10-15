import { useState, useEffect, useRef, useCallback, type ComponentType } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  Activity,
  AlertTriangle,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Play,
  Plus,
  ToggleLeft,
  ToggleRight,
  Zap,
  Server,
  Clock,
  TrendingUp,
  Eye,
  Download,
  Save,
  Upload,
  Pause,
  Square,
  BookmarkPlus,
  CheckCircle,
  BarChart3,
} from 'lucide-react';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import clsx from 'clsx';

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
  informational: 'bg-gray-100 text-gray-700 border-gray-200',
};

const severityRowColors: Record<string, string> = {
  critical: 'bg-red-50',
  high: 'bg-orange-50',
  medium: 'bg-yellow-50',
  low: 'bg-blue-50',
  info: 'bg-white',
};

const chartColors = ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6', '#ec4899'];

// ---------------------------------------------------------------------------
// Shapes returned by src/api/v1/endpoints/siem.py (wave 3)
// ---------------------------------------------------------------------------

interface NameValue {
  name: string;
  value: number;
  [key: string]: string | number;
}

interface RecentDetection {
  id: string;
  kind: string; // correlation | rule_alert
  rule_name?: string;
  severity?: string;
  timestamp?: string;
  status?: string;
}

interface PipelineStage {
  state?: string;
  scope?: string;
  [key: string]: unknown;
}

interface PipelineStatus {
  overall?: string;
  checked_at?: string;
  stages?: Record<string, PipelineStage>;
}

interface SIEMStats {
  total_logs?: number;
  logs_24h?: number;
  window_hours?: number;
  events_per_second?: number;
  events_per_second_window_seconds?: number;
  ingestion_rate_per_hour?: number;
  active_rules?: number;
  alerts_triggered_24h?: number;
  active_data_sources?: number;
  receiving_data_sources?: number;
  active_correlations?: number;
  correlations_24h?: number;
  last_ingest_at?: string | null;
  ingestion_timeline?: { hour: string; count: number }[];
  logs_by_severity?: NameValue[];
  logs_by_source_type?: NameValue[];
  top_rules?: { name: string; count: number; severity?: string | null }[];
  recent_detections?: RecentDetection[];
  pipeline_status?: PipelineStatus | null;
}

interface FieldError {
  field: string;
  message: string;
}

interface RuleValidationResult {
  valid: boolean;
  errors: string[];
  field_errors: FieldError[];
  warnings: string[];
  detection: Record<string, unknown> | null;
}

interface RuleSaveResult {
  name: string;
  action: 'created' | 'updated' | 'imported';
  engine_loaded: boolean | null | undefined;
  warnings: string[];
}

interface AggregateResult {
  field: string;
  aggregations: Record<string, number>;
  null_count: number;
  buckets_total: number;
  truncated: boolean;
  window_start: string;
  window_end: string;
}

type RuleFormMode = 'yaml' | 'logic';

interface RuleForm {
  name: string;
  title: string;
  description: string;
  severity: string;
  mode: RuleFormMode;
  rule_yaml: string;
  detection_logic: string;
  condition: string;
}

const emptyRuleForm: RuleForm = {
  name: '',
  title: '',
  description: '',
  severity: 'medium',
  mode: 'yaml',
  rule_yaml: '',
  detection_logic: '',
  condition: '',
};

/** Pipeline stages in the order /siem/logs/stats reports them. */
const PIPELINE_STAGES = ['ingestion', 'collector', 'queue', 'detection', 'correlation'] as const;

/** Columns /siem/logs/search accepts in field_filters (_LOG_SEARCHABLE_FIELDS minus the time columns). */
const LOG_FILTER_FIELDS = [
  'action', 'destination_address', 'destination_port', 'hostname', 'log_type', 'outcome', 'process_name',
  'protocol', 'severity', 'source_address', 'source_ip', 'source_name', 'source_port', 'source_type', 'username',
];

const stateTone: Record<string, string> = {
  receiving: 'bg-green-100 text-green-700',
  running: 'bg-green-100 text-green-700',
  active: 'bg-green-100 text-green-700',
  idle: 'bg-yellow-100 text-yellow-700',
  no_data: 'bg-gray-100 text-gray-700',
  no_events: 'bg-gray-100 text-gray-700',
  no_rules: 'bg-yellow-100 text-yellow-700',
  stopped: 'bg-gray-100 text-gray-700',
  disabled: 'bg-gray-100 text-gray-700',
  not_started: 'bg-gray-100 text-gray-700',
  degraded: 'bg-red-100 text-red-700',
  unavailable: 'bg-red-100 text-red-700',
  backlogged: 'bg-orange-100 text-orange-700',
  no_consumers: 'bg-orange-100 text-orange-700',
};

function errorStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

/** `detail.field_errors` of a 422 invalid_rule refusal. */
function fieldErrorsFrom(err: unknown): FieldError[] {
  const detail = (err as { response?: { data?: { detail?: { field_errors?: unknown } } } } | null)?.response?.data
    ?.detail;
  return Array.isArray(detail?.field_errors) ? (detail.field_errors as FieldError[]) : [];
}

/** 4xx answers (422 page_out_of_range / window_too_large ...) are final: do not retry them. */
function retryUnlessClientError(failureCount: number, err: unknown): boolean {
  const s = errorStatus(err);
  if (s !== undefined && s >= 400 && s < 500) return false;
  return failureCount < 2;
}

function formatWhen(iso: string | null | undefined): string {
  if (!iso) return 'Not available';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function formatStageValue(value: unknown): string {
  if (value === null || value === undefined) return 'none';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

/** The body a rule form sends to validate / create / update (a JSON error is reported locally). */
function buildRulePayload(form: RuleForm, editing: boolean): { payload?: Record<string, unknown>; error?: string } {
  const payload: Record<string, unknown> = {
    title: form.title,
    description: form.description || undefined,
    severity: form.severity,
  };
  if (!editing) payload.name = form.name;
  if (form.mode === 'yaml') {
    if (form.rule_yaml.trim()) payload.rule_yaml = form.rule_yaml;
  } else {
    if (form.detection_logic.trim()) {
      try {
        const parsed: unknown = JSON.parse(form.detection_logic);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return { error: 'detection_logic must be a JSON object (field -> value, or named selections)' };
        }
        payload.detection_logic = parsed;
      } catch (e) {
        return { error: `detection_logic is not valid JSON: ${e instanceof Error ? e.message : String(e)}` };
      }
    }
    if (form.condition.trim()) payload.condition = form.condition;
  }
  return { payload };
}

/** The form input a validator field path belongs to (`rule_yaml.detection` -> `rule_yaml`). */
function formFieldOf(path: string): string {
  return path.split('.')[0].split('[')[0];
}

const RULE_FORM_FIELDS = ['name', 'title', 'description', 'severity', 'rule_yaml', 'detection_logic', 'condition'];

const INGEST_STATUS_LABELS: Record<string, string> = {
  receiving: 'Receiving',
  idle: 'Idle (no events today)',
  no_events: 'No events received',
  disabled: 'Disabled',
};

/** Data-source `ingest_status` (disabled | no_events | receiving | idle) as written by ingest. */
function ingestStatusLabel(status: string | undefined): string {
  if (!status) return 'Not available';
  return INGEST_STATUS_LABELS[status] || status;
}

/** Field errors of a validate / 422 invalid_rule answer, under the input they belong to. */
function RuleFieldErrors({ errors, showField = false }: { errors: FieldError[]; showField?: boolean }) {
  if (errors.length === 0) return null;
  return (
    <ul className="mt-1 space-y-0.5 text-xs text-red-600">
      {errors.map((fe, i) => (
        <li key={`${fe.field}-${i}`}>
          {showField || fe.field.includes('.') ? <span className="font-mono">{fe.field}: </span> : null}
          {fe.message}
        </li>
      ))}
    </ul>
  );
}

export default function SIEMDashboard() {
  const [activeTab, setActiveTab] = useState<'overview' | 'search' | 'rules' | 'sources' | 'correlation' | 'live'>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [timeRange, setTimeRange] = useState('24h');
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');
  const [sourceTypeFilter, setSourceTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [fieldFilterKey, setFieldFilterKey] = useState('');
  const [fieldFilterValue, setFieldFilterValue] = useState('');
  const [searchPage, setSearchPage] = useState(1);
  const [selectedLogDetail, setSelectedLogDetail] = useState<any>(null);
  const [aggField, setAggField] = useState('source_type');
  const [aggTopN, setAggTopN] = useState(10);
  const [ruleStatusFilter, setRuleStatusFilter] = useState('');
  const [selectedRule, setSelectedRule] = useState<any>(null);
  const [selectedSource, setSelectedSource] = useState<any>(null);
  const [sourceModalMode, setSourceModalMode] = useState<'view' | 'config' | 'add'>('view');
  const [newSourceForm, setNewSourceForm] = useState({ name: '', description: '', source_type: 'syslog' });
  const [sourceActionError, setSourceActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [ruleForm, setRuleForm] = useState<RuleForm>(emptyRuleForm);
  const [ruleFormError, setRuleFormError] = useState<string | null>(null);
  const [ruleValidation, setRuleValidation] = useState<RuleValidationResult | null>(null);
  const [ruleSaveResult, setRuleSaveResult] = useState<RuleSaveResult | null>(null);
  const [ruleActionError, setRuleActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [testLogs, setTestLogs] = useState('');
  const [selectedCorrelation, setSelectedCorrelation] = useState<any>(null);

  // Live Tail state
  const [isTailing, setIsTailing] = useState(false);
  const [liveLogs, setLiveLogs] = useState<any[]>([]);
  const [liveSeverityFilter, setLiveSeverityFilter] = useState<string[]>([]);
  const liveTailRef = useRef<HTMLDivElement>(null);
  const tailIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Saved Searches state
  const [showSaveSearchModal, setShowSaveSearchModal] = useState(false);
  const [saveSearchName, setSaveSearchName] = useState('');
  const [selectedSavedSearch, setSelectedSavedSearch] = useState('');

  // Import Rule state
  const [showImportRuleModal, setShowImportRuleModal] = useState(false);
  const [importYaml, setImportYaml] = useState('');

  const queryClient = useQueryClient();
  const [liveError, setLiveError] = useState<unknown>(null);

  // Fetch dashboard stats (also feeds the search filter options)
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery<SIEMStats>({
    queryKey: ['siem-stats'],
    queryFn: async () => {
      const response = await api.get('/siem/logs/stats');
      return response.data;
    },
  });

  /** The search / aggregation window. Without time_start the backend bounds the query to its 90-day maximum. */
  const searchWindow = (): { time_start?: string; time_end?: string } => {
    if (timeRange === 'custom') {
      return {
        time_start: customStart ? new Date(customStart).toISOString() : undefined,
        time_end: customEnd ? new Date(customEnd).toISOString() : undefined,
      };
    }
    const timeMap: Record<string, number> = { '1h': 1, '6h': 6, '24h': 24, '7d': 168, '30d': 720, '90d': 2160 };
    const hours = timeMap[timeRange] || 24;
    return { time_start: new Date(Date.now() - hours * 3600000).toISOString() };
  };

  // Fetch logs for search
  const { data: logsData, isLoading: logsLoading, error: logsError } = useQuery({
    queryKey: ['siem-logs', searchQuery, timeRange, customStart, customEnd, sourceTypeFilter, severityFilter, fieldFilterKey, fieldFilterValue, searchPage],
    queryFn: async () => {
      const response = await api.post('/siem/logs/search', {
        query: searchQuery || undefined,
        source_types: sourceTypeFilter ? [sourceTypeFilter] : undefined,
        severities: severityFilter ? [severityFilter] : undefined,
        field_filters: fieldFilterKey && fieldFilterValue ? { [fieldFilterKey]: fieldFilterValue } : undefined,
        ...searchWindow(),
        page: searchPage,
        size: 15,
      });
      return response.data;
    },
    enabled: activeTab === 'search',
    retry: retryUnlessClientError,
  });

  // Aggregation over the same window as the search
  const aggregateMutation = useMutation({
    mutationFn: async (): Promise<AggregateResult> => {
      const response = await api.post('/siem/logs/aggregate', {
        field: aggField,
        agg_type: 'count',
        top_n: aggTopN,
        ...searchWindow(),
      });
      return response.data;
    },
  });

  // Fetch detection rules
  const { data: rulesData, isLoading: rulesLoading, error: rulesError } = useQuery({
    queryKey: ['siem-rules'],
    queryFn: async () => {
      const response = await api.get('/siem/rules');
      return response.data;
    },
    enabled: activeTab === 'rules',
  });

  // Fetch data sources
  const { data: sourcesData, isLoading: sourcesLoading, error: sourcesError } = useQuery({
    queryKey: ['siem-sources'],
    queryFn: async () => {
      const response = await api.get('/siem/sources');
      return response.data;
    },
    enabled: activeTab === 'sources',
  });

  // Fetch correlations
  const { data: correlationsData, isLoading: correlationsLoading, error: correlationsError } = useQuery({
    queryKey: ['siem-correlations'],
    queryFn: async () => {
      const response = await api.get('/siem/correlations');
      return response.data;
    },
    enabled: activeTab === 'correlation',
  });

  // Toggle rule mutation
  const toggleRuleMutation = useMutation({
    mutationFn: async ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) => {
      const response = await api.put(`/siem/rules/${ruleId}`, { enabled });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siem-rules'] });
      queryClient.invalidateQueries({ queryKey: ['siem-stats'] });
    },
    onError: (err: unknown) => setRuleActionError({ what: 'change the rule state', error: err }),
  });

  // Validate a rule definition without saving it
  const validateRuleMutation = useMutation({
    mutationFn: async (payload: Record<string, unknown>): Promise<RuleValidationResult> => {
      const response = await api.post('/siem/rules/validate', payload);
      return response.data;
    },
    onSuccess: (data: RuleValidationResult) => setRuleValidation(data),
  });

  // Create / update a rule (422 invalid_rule carries field_errors)
  const saveRuleMutation = useMutation({
    mutationFn: async ({ id, payload }: { id: string | null; payload: Record<string, unknown> }) => {
      const response = id ? await api.put(`/siem/rules/${id}`, payload) : await api.post('/siem/rules', payload);
      return response.data;
    },
    onSuccess: (data: { name?: string; engine_loaded?: boolean | null; validation_warnings?: string[] }, variables) => {
      setRuleSaveResult({
        name: data?.name || '',
        action: variables.id ? 'updated' : 'created',
        engine_loaded: data?.engine_loaded,
        warnings: data?.validation_warnings || [],
      });
      setShowRuleModal(false);
      queryClient.invalidateQueries({ queryKey: ['siem-rules'] });
      queryClient.invalidateQueries({ queryKey: ['siem-stats'] });
    },
  });

  // Dry-run a stored rule against sample logs
  const testRuleMutation = useMutation({
    mutationFn: async ({ ruleId, samples }: { ruleId: string; samples: string[] }) => {
      const response = await api.post(`/siem/rules/${ruleId}/test`, { sample_logs: samples });
      return response.data as { sample_count: number; match_count: number; match_rate: number };
    },
  });

  // Saved searches query
  const { data: savedSearchesData, error: savedSearchesError } = useQuery({
    queryKey: ['siem-saved-searches'],
    queryFn: async () => {
      const response = await api.get('/siem/saved-searches');
      return response.data;
    },
    enabled: activeTab === 'search',
  });
  const savedSearches = Array.isArray(savedSearchesData) ? savedSearchesData : (savedSearchesData?.items || []);

  // Save search mutation
  const saveSearchMutation = useMutation({
    mutationFn: async (name: string) => {
      const response = await api.post('/siem/saved-searches', {
        name,
        query: searchQuery,
        filters: { time_range: timeRange, source_type: sourceTypeFilter, severity: severityFilter },
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siem-saved-searches'] });
      setShowSaveSearchModal(false);
      setSaveSearchName('');
    },
  });

  // Run saved search mutation
  const runSavedSearchMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await api.post(`/siem/saved-searches/${id}/run`);
      return response.data;
    },
  });

  // Import rule mutation (422 invalid_rule for unsupported Sigma constructs)
  const importRuleMutation = useMutation({
    mutationFn: async (yaml: string) => {
      const response = await api.post('/siem/rules/import', { yaml });
      return response.data;
    },
    onSuccess: (data: { name?: string; engine_loaded?: boolean | null; warnings?: string[] }) => {
      setRuleSaveResult({
        name: data?.name || '',
        action: 'imported',
        engine_loaded: data?.engine_loaded,
        warnings: data?.warnings || [],
      });
      queryClient.invalidateQueries({ queryKey: ['siem-rules'] });
      setShowImportRuleModal(false);
      setImportYaml('');
    },
  });

  // Collector status query
  const { data: collectorStatus, error: collectorStatusError } = useQuery<{
    status?: string;
    port?: number | null;
    scope?: string;
    protocol?: string;
    messages_received?: number;
  }>({
    queryKey: ['siem-collector-status'],
    queryFn: async () => {
      const response = await api.get('/siem/collector/status');
      return response.data;
    },
    enabled: activeTab === 'sources',
  });
  const collectorRunning = collectorStatus?.status === 'running';

  // Collector start/stop mutations (refusals rendered with ActionErrorBanner)
  const collectorStartMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/siem/collector/start');
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siem-collector-status'] });
    },
  });

  const collectorStopMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/siem/collector/stop');
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siem-collector-status'] });
    },
  });

  const openRuleModal = (rule?: any) => {
    setRuleValidation(null);
    setRuleFormError(null);
    validateRuleMutation.reset();
    saveRuleMutation.reset();
    if (rule) {
      const logic = rule.detection_logic;
      setEditingRuleId(rule.id);
      setRuleForm({
        name: rule.name || '',
        title: rule.title || '',
        description: rule.description || '',
        severity: rule.severity || 'medium',
        mode: rule.rule_yaml ? 'yaml' : 'logic',
        rule_yaml: rule.rule_yaml || '',
        detection_logic: logic ? (typeof logic === 'string' ? logic : JSON.stringify(logic, null, 2)) : '',
        condition: rule.condition || '',
      });
    } else {
      setEditingRuleId(null);
      setRuleForm(emptyRuleForm);
    }
    setShowRuleModal(true);
  };

  const submitRuleForm = (kind: 'validate' | 'save') => {
    const { payload, error } = buildRulePayload(ruleForm, editingRuleId !== null);
    setRuleFormError(error || null);
    if (!payload) return;
    if (kind === 'validate') {
      // validate takes the full create schema; an edit validates under the rule's stored name
      validateRuleMutation.mutate({ ...payload, name: ruleForm.name });
    } else {
      saveRuleMutation.mutate({ id: editingRuleId, payload });
    }
  };

  // Field errors next to each input: from Validate, or from a refused save.
  const ruleFieldErrors: FieldError[] = [
    ...(ruleValidation?.field_errors || []),
    ...fieldErrorsFrom(saveRuleMutation.error),
  ];
  const fieldErrorsFor = (field: string) => ruleFieldErrors.filter((fe) => formFieldOf(fe.field) === field);
  const otherFieldErrors = ruleFieldErrors.filter((fe) => !RULE_FORM_FIELDS.includes(formFieldOf(fe.field)));

  const exportRule = async (rule: { id: string; name?: string }) => {
    try {
      // GET /siem/rules/{id}/export -> {yaml, title}; 422 no_detection_logic / unreadable_rule
      const response = await api.get(`/siem/rules/${rule.id}/export`);
      const yamlContent: string = typeof response.data?.yaml === 'string' ? response.data.yaml : '';
      const blob = new Blob([yamlContent], { type: 'application/x-yaml' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${rule.name || 'rule'}.yml`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setRuleActionError({ what: `export rule ${rule.name || rule.id}`, error: err });
    }
  };

  const deleteRule = async (rule: { id: string; name?: string }) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    try {
      await api.delete(`/siem/rules/${rule.id}`);
      queryClient.invalidateQueries({ queryKey: ['siem-rules'] });
    } catch (err) {
      setRuleActionError({ what: `delete rule ${rule.name || rule.id}`, error: err });
    }
  };

  const saveSource = async () => {
    try {
      if (sourceModalMode === 'add') {
        await api.post('/siem/sources', newSourceForm);
      } else {
        await api.put(`/siem/sources/${selectedSource.id}`, newSourceForm);
      }
      setSourceActionError(null);
      setSelectedSource(null);
      queryClient.invalidateQueries({ queryKey: ['siem-sources'] });
    } catch (err) {
      setSourceActionError({ what: sourceModalMode === 'add' ? 'create the data source' : 'save the data source', error: err });
    }
  };

  const toggleSource = async () => {
    try {
      const response = await api.put(`/siem/sources/${selectedSource.id}`, { name: selectedSource.name, enabled: !selectedSource.enabled });
      setSourceActionError(null);
      setSelectedSource(response.data ?? { ...selectedSource, enabled: !selectedSource.enabled });
      queryClient.invalidateQueries({ queryKey: ['siem-sources'] });
    } catch (err) {
      setSourceActionError({ what: 'change the data source state', error: err });
    }
  };

  // Live Tail polling — /siem/logs/search is a POST endpoint with a JSON
  // body, so the previous GET call was always 405 Method Not Allowed and
  // the Live Tail tab was completely broken.
  const fetchLiveLogs = useCallback(async () => {
    try {
      const response = await api.post('/siem/logs/search', {
        sort_by: 'timestamp',
        sort_order: 'desc',
        page: 1,
        size: 20,
      });
      const items = response.data?.items || [];
      setLiveLogs(items);
      setLiveError(null);
    } catch (err) {
      setLiveError(err);
    }
  }, []);

  useEffect(() => {
    let initialFetchTimeout: ReturnType<typeof setTimeout> | null = null;
    if (isTailing && activeTab === 'live') {
      initialFetchTimeout = setTimeout(fetchLiveLogs, 0);
      tailIntervalRef.current = setInterval(fetchLiveLogs, 3000);
    }
    return () => {
      if (initialFetchTimeout) {
        clearTimeout(initialFetchTimeout);
      }
      if (tailIntervalRef.current) {
        clearInterval(tailIntervalRef.current);
        tailIntervalRef.current = null;
      }
    };
  }, [isTailing, activeTab, fetchLiveLogs]);

  // Auto-scroll live tail to bottom
  useEffect(() => {
    if (isTailing && liveTailRef.current) {
      liveTailRef.current.scrollTop = liveTailRef.current.scrollHeight;
    }
  }, [liveLogs, isTailing]);

  const filteredLiveLogs = liveSeverityFilter.length > 0
    ? liveLogs.filter((log: any) => liveSeverityFilter.includes(log.severity))
    : liveLogs;

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'search', label: 'Log Search', icon: Search },
    { id: 'rules', label: 'Detection Rules', icon: Zap },
    { id: 'sources', label: 'Data Sources', icon: Server },
    { id: 'correlation', label: 'Correlation', icon: TrendingUp },
    { id: 'live', label: 'Live Tail', icon: Activity },
  ];

  const logs = logsData?.items || [];
  const logTotal = logsData?.total || 0;
  const rules = rulesData?.items || [];
  const sources = Array.isArray(sourcesData) ? sourcesData : (sourcesData?.items || []);
  const correlations = Array.isArray(correlationsData) ? correlationsData : (correlationsData?.items || []);

  const logPages = Math.ceil(logTotal / 15);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-3xl font-bold text-gray-900">SIEM Dashboard</h1>
            {/* "Native SIEM" badge — makes clear this page IS the
                SIEM (log_entries + RuleEngine + CorrelationEngine +
                ingest paths) rather than a view onto Splunk/Elastic/
                QRadar. Install those external-SIEM connectors from
                Integrations only if you want to pull events from an
                incumbent deployment into this same search UI. */}
            <span
              title="PySOAR ships its own SIEM: UDP/TCP 5514 syslog, HTTP bulk ingest, agent heartbeat stream, cloud log pollers, Sigma-style rule engine, correlation engine, and alert generation."
              className="text-xs px-2.5 py-1 bg-emerald-100 text-emerald-800 rounded-full border border-emerald-300 font-semibold uppercase tracking-wide"
            >
              Native SIEM
            </span>
          </div>
          <p className="text-gray-500 mt-1">
            Security information and event management &mdash;
            <span className="text-gray-700"> ingest, parse, correlate, and detect on your own infrastructure.</span>
          </p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="flex border-b border-gray-200">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'flex items-center space-x-2 px-6 py-4 font-medium border-b-2 transition-colors',
                  activeTab === tab.id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-600 hover:text-gray-900'
                )}
              >
                <Icon className="w-5 h-5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <LoadErrorBanner what="SIEM statistics" error={statsError} />
          {/* Stats Cards: every value is computed by GET /siem/logs/stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <StatsCard
              title={`Logs (${stats?.window_hours ?? 24}h)`}
              value={statsLoading ? '-' : stats?.logs_24h != null ? stats.logs_24h.toLocaleString() : 'Not available'}
              subtext={
                stats?.ingestion_rate_per_hour != null
                  ? `${stats.ingestion_rate_per_hour.toLocaleString()} / hour average · ${stats.total_logs?.toLocaleString() ?? '—'} all time`
                  : 'Not available'
              }
              icon={Activity}
            />
            <StatsCard
              title="Events/Second"
              value={statsLoading ? '-' : stats?.events_per_second != null ? stats.events_per_second.toFixed(2) : 'Not available'}
              subtext={
                stats?.events_per_second_window_seconds != null
                  ? `Measured over the last ${Math.round(stats.events_per_second_window_seconds / 60)} min`
                  : 'Measurement window not reported'
              }
              icon={TrendingUp}
            />
            <StatsCard
              title="Active Rules"
              value={statsLoading ? '-' : stats?.active_rules ?? 'Not available'}
              subtext="Enabled rules (own + platform)"
              icon={Zap}
            />
            <StatsCard
              title={`SIEM Alerts (${stats?.window_hours ?? 24}h)`}
              value={statsLoading ? '-' : stats?.alerts_triggered_24h ?? 'Not available'}
              subtext="Raised by rules and correlations"
              icon={AlertTriangle}
            />
            <StatsCard
              title="Data Sources Receiving"
              value={
                statsLoading
                  ? '-'
                  : stats?.receiving_data_sources != null && stats?.active_data_sources != null
                    ? `${stats.receiving_data_sources} / ${stats.active_data_sources}`
                    : 'Not available'
              }
              subtext="Enabled sources with an event in the last hour / enabled"
              icon={Server}
            />
            <StatsCard
              title="Open Correlations"
              value={statsLoading ? '-' : stats?.active_correlations ?? 'Not available'}
              subtext={`Status new / investigating only · ${stats?.correlations_24h ?? '—'} created in ${stats?.window_hours ?? 24}h`}
              icon={TrendingUp}
            />
            <StatsCard
              title="Last Ingest"
              value={statsLoading ? '-' : stats?.last_ingest_at ? new Date(stats.last_ingest_at).toLocaleTimeString() : 'No logs yet'}
              subtext={stats?.last_ingest_at ? formatWhen(stats.last_ingest_at) : 'No log has been ingested for this organisation'}
              icon={Clock}
            />
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Ingestion timeline (hourly, by ingest time) */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Log Ingestion Volume ({stats?.window_hours ?? 24}h, hourly)</h3>
              {stats?.ingestion_timeline && stats.ingestion_timeline.some((b) => b.count > 0) ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart
                    data={stats.ingestion_timeline.map((b) => ({
                      hour: new Date(b.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                      count: b.count,
                    }))}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis dataKey="hour" stroke="#6b7280" />
                    <YAxis stroke="#6b7280" allowDecimals={false} />
                    <Tooltip />
                    <Area type="monotone" dataKey="count" name="Logs" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] bg-gray-50 rounded flex items-center justify-center">
                  <p className="text-gray-500">No logs ingested in the last {stats?.window_hours ?? 24} hours</p>
                </div>
              )}
            </div>

            {/* Events by Severity */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Events by Severity ({stats?.window_hours ?? 24}h)</h3>
              {stats?.logs_by_severity && stats.logs_by_severity.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={stats.logs_by_severity}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis dataKey="name" stroke="#6b7280" />
                    <YAxis stroke="#6b7280" allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="value" name="Logs" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] bg-gray-50 rounded flex items-center justify-center">
                  <p className="text-gray-500">No severity data in the last {stats?.window_hours ?? 24} hours</p>
                </div>
              )}
            </div>

            {/* Events by Source Type */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Events by Source Type ({stats?.window_hours ?? 24}h)</h3>
              {stats?.logs_by_source_type && stats.logs_by_source_type.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={stats.logs_by_source_type}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      label
                    >
                      {stats.logs_by_source_type.map((entry, index) => (
                        <Cell key={entry.name} fill={chartColors[index % chartColors.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] bg-gray-50 rounded flex items-center justify-center">
                  <p className="text-gray-500">No source type data in the last {stats?.window_hours ?? 24} hours</p>
                </div>
              )}
            </div>

            {/* Recent Detections: newest correlations and rule alerts */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Detections</h3>
              {stats?.recent_detections && stats.recent_detections.length > 0 ? (
                <div className="space-y-3">
                  {stats.recent_detections.map((detection) => (
                    <div key={`${detection.kind}-${detection.id}`} className="flex items-start justify-between pb-3 border-b border-gray-100 last:border-0">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={clsx(
                              'px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded',
                              detection.kind === 'correlation' ? 'bg-purple-100 text-purple-700' : 'bg-blue-100 text-blue-700',
                            )}
                          >
                            {detection.kind === 'correlation' ? 'Correlation' : detection.kind === 'rule_alert' ? 'Rule alert' : detection.kind}
                          </span>
                          <p className="text-sm font-medium text-gray-900">{detection.rule_name || 'Unnamed'}</p>
                        </div>
                        <p className="text-xs text-gray-500 mt-1">
                          {formatWhen(detection.timestamp)}
                          {detection.status ? ` · ${detection.status}` : ''}
                        </p>
                      </div>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                          severityColors[detection.severity || ''] || severityColors.info
                        )}
                      >
                        {detection.severity || 'unknown'}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <p>No correlations or rule alerts yet</p>
                </div>
              )}
            </div>
          </div>

          {/* Pipeline Status & Top Alerting Rules */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Pipeline Status: per-stage state from stored rows and live collector / queue state */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-lg font-semibold text-gray-900">Pipeline Status</h3>
                {stats?.pipeline_status?.overall ? (
                  <span className={clsx('px-3 py-1 text-xs font-semibold rounded-full', stateTone[stats.pipeline_status.overall] || 'bg-gray-100 text-gray-700')}>
                    {stats.pipeline_status.overall}
                  </span>
                ) : (
                  <span className="px-3 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-600">Not available</span>
                )}
              </div>
              <p className="text-xs text-gray-500 mb-4">
                Checked {formatWhen(stats?.pipeline_status?.checked_at)}. Collector state is the API process that answered
                this request (process-local); queue depth is host-wide; the other stages are this organisation&apos;s stored data.
              </p>
              {stats?.pipeline_status?.stages ? (
                <div className="space-y-3">
                  {PIPELINE_STAGES.map((stageName) => {
                    const stage = stats.pipeline_status?.stages?.[stageName];
                    if (!stage) {
                      return (
                        <div key={stageName} className="flex items-center justify-between">
                          <span className="text-sm text-gray-600 capitalize">{stageName}</span>
                          <span className="text-xs text-gray-500">Not reported</span>
                        </div>
                      );
                    }
                    const details = Object.entries(stage).filter(([k]) => k !== 'state' && k !== 'scope');
                    return (
                      <div key={stageName} className="border-b border-gray-100 last:border-0 pb-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium text-gray-700 capitalize">{stageName}</span>
                          <span className={clsx('px-2 py-0.5 text-xs font-medium rounded-full', stateTone[stage.state || ''] || 'bg-gray-100 text-gray-700')}>
                            {stage.state || 'unknown'}
                          </span>
                        </div>
                        {details.length > 0 && (
                          <p className="text-xs text-gray-500 mt-1">
                            {details.map(([k, v]) => `${k}: ${formatStageValue(v)}`).join(' · ')}
                          </p>
                        )}
                        {stage.scope && <p className="text-xs text-gray-400 mt-0.5">Scope: {stage.scope}</p>}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-sm text-gray-500">Not available: the stats response carried no pipeline status.</p>
              )}
            </div>

            {/* Top Alerting Rules: this organisation's rule alerts in the window */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Alerting Rules ({stats?.window_hours ?? 24}h)</h3>
              {stats?.top_rules && stats.top_rules.length > 0 ? (
                <div className="space-y-2">
                  {stats.top_rules.map((rule) => (
                    <div key={rule.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={clsx(
                            'px-2 py-0.5 text-xs font-medium rounded-full border capitalize',
                            severityColors[rule.severity || ''] || severityColors.info,
                          )}
                        >
                          {rule.severity || 'unknown'}
                        </span>
                        <span className="text-sm text-gray-900 truncate">{rule.name}</span>
                      </div>
                      <span className="text-sm font-semibold text-gray-900">{rule.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <p>No rule alerts in the last {stats?.window_hours ?? 24} hours</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Log Search Tab */}
      {activeTab === 'search' && (
        <div className="space-y-6">
          {/* 422 page_out_of_range / window_too_large / invalid_window / invalid_field_filter are refusals, not empty results */}
          {errorStatus(logsError) !== undefined && (errorStatus(logsError) as number) < 500 ? (
            <ActionErrorBanner what="search logs" error={logsError} />
          ) : (
            <LoadErrorBanner what="log search results" error={logsError} />
          )}
          <LoadErrorBanner what="saved searches" error={savedSearchesError} />
          <LoadErrorBanner what="saved search run" error={runSavedSearchMutation.error} />
          {/* Search Filters */}
          <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Search Query</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setSearchPage(1);
                  }}
                  placeholder="Enter search query..."
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <button
                  onClick={() => { setSearchPage(1); queryClient.invalidateQueries({ queryKey: ['siem-logs'] }); }}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
                >
                  <Search className="w-5 h-5" />
                  Search
                </button>
                <button
                  onClick={() => { setShowSaveSearchModal(true); setSaveSearchName(''); }}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center gap-2"
                >
                  <BookmarkPlus className="w-5 h-5" />
                  Save Search
                </button>
              </div>
              {/* Saved Searches */}
              <div className="flex items-center gap-2 mt-2">
                <label className="text-sm font-medium text-gray-700">Saved Searches:</label>
                <select
                  value={selectedSavedSearch}
                  onChange={(e) => {
                    const id = e.target.value;
                    setSelectedSavedSearch(id);
                    if (id) {
                      const saved = savedSearches.find((s: any) => s.id === id);
                      if (saved) {
                        setSearchQuery(saved.query || '');
                        if (saved.filters) {
                          if (saved.filters.time_range) setTimeRange(saved.filters.time_range);
                          if (saved.filters.source_type) setSourceTypeFilter(saved.filters.source_type);
                          if (saved.filters.severity) setSeverityFilter(saved.filters.severity);
                        }
                        setSearchPage(1);
                      }
                    }
                  }}
                  className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">-- Select a saved search --</option>
                  {savedSearches.map((s: any) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
                {selectedSavedSearch && (
                  <button
                    onClick={() => runSavedSearchMutation.mutate(selectedSavedSearch)}
                    className="px-3 py-1.5 bg-blue-50 text-blue-600 rounded-lg text-sm font-medium hover:bg-blue-100 flex items-center gap-1"
                  >
                    <Play className="w-4 h-4" />
                    Run
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Time Range</label>
                <select
                  value={timeRange}
                  onChange={(e) => {
                    setTimeRange(e.target.value);
                    setSearchPage(1);
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="1h">Last 1 hour</option>
                  <option value="6h">Last 6 hours</option>
                  <option value="24h">Last 24 hours</option>
                  <option value="7d">Last 7 days</option>
                  <option value="30d">Last 30 days</option>
                  <option value="90d">Last 90 days (maximum)</option>
                  <option value="custom">Custom range</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Source Type</label>
                {/* Options: source types seen in the last 24h (GET /siem/logs/stats logs_by_source_type) */}
                <select
                  value={sourceTypeFilter}
                  onChange={(e) => {
                    setSourceTypeFilter(e.target.value);
                    setSearchPage(1);
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">All Sources</option>
                  {sourceTypeFilter && !(stats?.logs_by_source_type || []).some((s) => s.name === sourceTypeFilter) && (
                    <option value={sourceTypeFilter}>{sourceTypeFilter}</option>
                  )}
                  {(stats?.logs_by_source_type || []).map((s) => (
                    <option key={s.name} value={s.name}>{s.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Severity</label>
                {/* Options: severities seen in the last 24h (GET /siem/logs/stats logs_by_severity) */}
                <select
                  value={severityFilter}
                  onChange={(e) => {
                    setSeverityFilter(e.target.value);
                    setSearchPage(1);
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">All Severities</option>
                  {severityFilter && !(stats?.logs_by_severity || []).some((s) => s.name === severityFilter) && (
                    <option value={severityFilter}>{severityFilter}</option>
                  )}
                  {(stats?.logs_by_severity || []).map((s) => (
                    <option key={s.name} value={s.name}>{s.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Field Filter</label>
                <div className="flex gap-2">
                  <select
                    value={fieldFilterKey}
                    onChange={(e) => {
                      setFieldFilterKey(e.target.value);
                      setSearchPage(1);
                    }}
                    className="w-1/2 px-2 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="">No field</option>
                    {LOG_FILTER_FIELDS.map((f) => (
                      <option key={f} value={f}>{f}</option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={fieldFilterValue}
                    disabled={!fieldFilterKey}
                    onChange={(e) => {
                      setFieldFilterValue(e.target.value);
                      setSearchPage(1);
                    }}
                    placeholder="exact value"
                    className="w-1/2 px-2 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50"
                  />
                </div>
              </div>
            </div>

            {timeRange === 'custom' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">From</label>
                  <input
                    type="datetime-local"
                    value={customStart}
                    onChange={(e) => {
                      setCustomStart(e.target.value);
                      setSearchPage(1);
                    }}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">To (empty = now)</label>
                  <input
                    type="datetime-local"
                    value={customEnd}
                    onChange={(e) => {
                      setCustomEnd(e.target.value);
                      setSearchPage(1);
                    }}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <p className="md:col-span-2 text-xs text-gray-500">
                  A search may cover at most 90 days. Without a start the server searches logs ingested in the last 90 days.
                </p>
              </div>
            )}
          </div>

          {/* Aggregate over the same window */}
          <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
            <div className="flex items-end gap-3 flex-wrap">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Aggregate by</label>
                <select
                  value={aggField}
                  onChange={(e) => setAggField(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  {LOG_FILTER_FIELDS.map((f) => (
                    <option key={f} value={f}>{f}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Top</label>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={aggTopN}
                  onChange={(e) => setAggTopN(Number(e.target.value) || 10)}
                  className="w-24 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <button
                onClick={() => aggregateMutation.mutate()}
                disabled={aggregateMutation.isPending}
                className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 flex items-center gap-2"
              >
                <BarChart3 className="w-4 h-4" />
                {aggregateMutation.isPending ? 'Aggregating...' : 'Aggregate'}
              </button>
            </div>
            <ActionErrorBanner what="aggregate logs" error={aggregateMutation.error} />
            {aggregateMutation.data && (
              <div className="space-y-2">
                <p className="text-xs text-gray-500">
                  {aggregateMutation.data.field} · window {formatWhen(aggregateMutation.data.window_start)} to{' '}
                  {formatWhen(aggregateMutation.data.window_end)} · {aggregateMutation.data.buckets_total} distinct value
                  {aggregateMutation.data.buckets_total === 1 ? '' : 's'} in window
                  {aggregateMutation.data.truncated ? ` (truncated: showing the top ${Object.keys(aggregateMutation.data.aggregations).length})` : ''}
                  {' · '}
                  {aggregateMutation.data.null_count} log{aggregateMutation.data.null_count === 1 ? '' : 's'} with no value
                </p>
                {Object.keys(aggregateMutation.data.aggregations).length === 0 ? (
                  <p className="text-sm text-gray-500">No logs with a {aggregateMutation.data.field} value in this window.</p>
                ) : (
                  <table className="w-full text-sm">
                    <tbody className="divide-y divide-gray-100">
                      {Object.entries(aggregateMutation.data.aggregations).map(([k, v]) => (
                        <tr key={k}>
                          <td className="py-1.5 font-mono text-gray-800">{k}</td>
                          <td className="py-1.5 text-right font-medium text-gray-900">{v.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </div>

          {/* Results Table */}
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {logsLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : logs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <Search className="w-12 h-12 mb-4 text-gray-300" />
                <p>No logs found</p>
              </div>
            ) : (
              <>
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Timestamp
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Source
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Severity
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Message
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Source IP
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Dest IP
                      </th>
                      <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {logs.map((log: any) => (
                      <tr key={log.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 text-sm text-gray-500">
                          {new Date(log.timestamp || "").toLocaleString()}
                        </td>
                        <td className="px-6 py-4 text-sm font-medium text-gray-900">{log.source_name}</td>
                        <td className="px-6 py-4">
                          <span
                            className={clsx(
                              'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                              severityColors[log.severity] || severityColors.info
                            )}
                          >
                            {log.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">{log.message}</td>
                        <td className="px-6 py-4 text-sm font-mono text-gray-600">{log.source_ip}</td>
                        <td className="px-6 py-4 text-sm font-mono text-gray-600">{log.destination_address}</td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={() => setSelectedLogDetail(log)}
                            className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {/* Pagination */}
                {logPages > 1 && (
                  <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
                    <p className="text-sm text-gray-500">
                      Showing {(searchPage - 1) * 15 + 1} to {Math.min(searchPage * 15, logTotal)} of {logTotal}
                    </p>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => setSearchPage(searchPage - 1)}
                        disabled={searchPage === 1}
                        className="p-2 border border-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
                      >
                        <ChevronLeft className="w-5 h-5" />
                      </button>
                      <span className="text-sm text-gray-700">
                        Page {searchPage} of {logPages}
                      </span>
                      <button
                        onClick={() => setSearchPage(searchPage + 1)}
                        disabled={searchPage === logPages}
                        className="p-2 border border-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
                      >
                        <ChevronRight className="w-5 h-5" />
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Log Detail Modal */}
          {selectedLogDetail && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">Log Details</h2>
                  <button
                    onClick={() => setSelectedLogDetail(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    ✕
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Timestamp</label>
                      <p className="text-gray-900">{new Date(selectedLogDetail.timestamp || "").toLocaleString()}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Source</label>
                      <p className="text-gray-900">{selectedLogDetail.source_name}</p>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Severity</label>
                    <span
                      className={clsx(
                        'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                        severityColors[selectedLogDetail.severity]
                      )}
                    >
                      {selectedLogDetail.severity}
                    </span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Message</label>
                    <p className="text-gray-900 text-sm">{selectedLogDetail.message}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Source IP</label>
                      <p className="text-gray-900 font-mono">{selectedLogDetail.source_ip}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Destination IP</label>
                      <p className="text-gray-900 font-mono">{selectedLogDetail.destination_address}</p>
                    </div>
                  </div>
                  {selectedLogDetail.raw_data && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Raw Data</label>
                      <pre className="text-xs text-gray-600 bg-gray-50 p-3 rounded overflow-x-auto">
                        {JSON.stringify(selectedLogDetail.raw_data, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Save Search Modal */}
          {showSaveSearchModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Save Search</h2>
                  <button onClick={() => setShowSaveSearchModal(false)} className="text-gray-400 hover:text-gray-600">
                    ✕
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Search Name *</label>
                    <input
                      type="text"
                      value={saveSearchName}
                      onChange={(e) => setSaveSearchName(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="e.g., Failed SSH Logins"
                    />
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3 text-sm text-gray-600 space-y-1">
                    <p><span className="font-medium">Query:</span> {searchQuery || '(empty)'}</p>
                    <p><span className="font-medium">Time Range:</span> {timeRange}</p>
                    <p><span className="font-medium">Source:</span> {sourceTypeFilter || 'All'}</p>
                    <p><span className="font-medium">Severity:</span> {severityFilter || 'All'}</p>
                  </div>
                  <div className="flex justify-end gap-3 pt-2 border-t">
                    <button
                      onClick={() => setShowSaveSearchModal(false)}
                      className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                    <button
                      disabled={!saveSearchName.trim()}
                      onClick={() => saveSearchMutation.mutate(saveSearchName.trim())}
                      className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 flex items-center gap-2"
                    >
                      <Save className="w-4 h-4" />
                      Save
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Detection Rules Tab */}
      {activeTab === 'rules' && (
        <div className="space-y-6">
          <LoadErrorBanner what="detection rules" error={rulesError} />
          {ruleActionError && <ActionErrorBanner what={ruleActionError.what} error={ruleActionError.error} />}
          {ruleSaveResult && (
            <div
              className={clsx(
                'rounded-lg border p-4 text-sm',
                ruleSaveResult.engine_loaded === false
                  ? 'border-yellow-200 bg-yellow-50 text-yellow-800'
                  : 'border-green-200 bg-green-50 text-green-800'
              )}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-medium">
                    Rule {ruleSaveResult.name || ''} {ruleSaveResult.action}.{' '}
                    {ruleSaveResult.engine_loaded === true
                      ? 'The detection engine loaded it and evaluates it on ingested logs.'
                      : ruleSaveResult.engine_loaded === false
                        ? 'The detection engine did not load it (the rule is disabled or the engine has not picked it up); it does not fire yet.'
                        : 'The engine load state was not reported.'}
                  </p>
                  {ruleSaveResult.warnings.length > 0 && (
                    <ul className="mt-2 list-disc pl-5">
                      {ruleSaveResult.warnings.map((w) => <li key={w}>{w}</li>)}
                    </ul>
                  )}
                </div>
                <button onClick={() => setRuleSaveResult(null)} className="text-gray-500 hover:text-gray-700">✕</button>
              </div>
            </div>
          )}
          {/* Filter Buttons */}
          <div className="flex items-center gap-2 justify-between">
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-500" />
            <button
              onClick={() => setRuleStatusFilter('')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                ruleStatusFilter === '' ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              All
            </button>
            <button
              onClick={() => setRuleStatusFilter('enabled')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                ruleStatusFilter === 'enabled' ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Enabled
            </button>
            <button
              onClick={() => setRuleStatusFilter('disabled')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                ruleStatusFilter === 'disabled' ? 'bg-red-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Disabled
            </button>
          </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setShowImportRuleModal(true); setImportYaml(''); importRuleMutation.reset(); }}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
              >
                <Upload className="w-5 h-5" />
                Import Rule
              </button>
              <button
                onClick={() => openRuleModal()}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                <Plus className="w-5 h-5" />
                Create Rule
              </button>
            </div>
          </div>

          {/* Rules Table */}
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {rulesLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : rules.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <Zap className="w-12 h-12 mb-4 text-gray-300" />
                <p>{rulesError ? 'Detection rules could not be loaded' : 'No detection rules found'}</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Rule Name</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">MITRE Tactic</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Triggered</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hit Count</th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {rules
                    .filter((rule: any) => !ruleStatusFilter || rule.enabled === (ruleStatusFilter === 'enabled'))
                    .map((rule: any) => (
                      <tr key={rule.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 text-sm font-medium text-gray-900">
                          {rule.name}
                          {rule.organization_id == null && (
                            <span className="ml-2 px-1.5 py-0.5 text-[10px] font-medium rounded bg-gray-100 text-gray-600" title="Built-in platform rule, visible to every organisation">
                              built-in
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <span className={clsx('px-2 py-1 text-xs font-medium rounded-full border capitalize', severityColors[rule.severity] || severityColors.info)}>
                            {rule.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600">{Array.isArray(rule.mitre_tactics) && rule.mitre_tactics.length > 0 ? rule.mitre_tactics.join(', ') : '-'}</td>
                        <td className="px-6 py-4">
                          <button
                            onClick={() => {
                              setRuleActionError(null);
                              toggleRuleMutation.mutate({ ruleId: rule.id, enabled: !rule.enabled });
                            }}
                            className="flex items-center gap-2"
                          >
                            {rule.enabled ? (
                              <>
                                <ToggleRight className="w-5 h-5 text-green-600" />
                                <span className="text-sm font-medium text-green-600">Enabled</span>
                              </>
                            ) : (
                              <>
                                <ToggleLeft className="w-5 h-5 text-gray-400" />
                                <span className="text-sm font-medium text-gray-500">Disabled</span>
                              </>
                            )}
                          </button>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600">
                          {rule.last_matched_at ? new Date(rule.last_matched_at).toLocaleString() : 'Never'}
                        </td>
                        <td className="px-6 py-4 text-sm font-medium text-gray-900">{rule.match_count ?? 0}</td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => { setRuleActionError(null); exportRule(rule); }}
                              className="flex items-center gap-1 px-2 py-1 text-sm bg-gray-50 text-gray-600 rounded hover:bg-gray-100"
                              title="Export as YAML"
                            >
                              <Download className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => openRuleModal(rule)}
                              className="flex items-center gap-1 px-3 py-1 text-sm bg-gray-50 text-gray-700 rounded hover:bg-gray-100"
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => { setSelectedRule(rule); setTestLogs(''); testRuleMutation.reset(); }}
                              className="flex items-center gap-1 px-3 py-1 text-sm bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
                            >
                              <Play className="w-4 h-4" />
                              Test
                            </button>
                            <button
                              onClick={() => { setRuleActionError(null); deleteRule(rule); }}
                              className="flex items-center gap-1 px-3 py-1 text-sm bg-red-50 text-red-600 rounded hover:bg-red-100"
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Create / Edit Rule Modal: Validate runs POST /siem/rules/validate; Save returns 422 invalid_rule with field_errors */}
          {showRuleModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">{editingRuleId ? 'Edit Detection Rule' : 'Create Detection Rule'}</h2>
                  <button onClick={() => setShowRuleModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                    <input
                      type="text"
                      value={ruleForm.name}
                      disabled={editingRuleId !== null}
                      onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-50"
                      placeholder="rule_name"
                    />
                    <RuleFieldErrors errors={fieldErrorsFor('name')} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Title *</label>
                    <input
                      type="text"
                      value={ruleForm.title}
                      onChange={(e) => setRuleForm({ ...ruleForm, title: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="Rule Title"
                    />
                    <RuleFieldErrors errors={fieldErrorsFor('title')} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                    <textarea
                      value={ruleForm.description}
                      onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })}
                      rows={2}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <RuleFieldErrors errors={fieldErrorsFor('description')} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                    <select
                      value={ruleForm.severity}
                      onChange={(e) => setRuleForm({ ...ruleForm, severity: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="informational">Informational</option>
                    </select>
                    <RuleFieldErrors errors={fieldErrorsFor('severity')} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Detection logic</label>
                    <div className="flex gap-2 mb-2">
                      {(['yaml', 'logic'] as const).map((m) => (
                        <button
                          key={m}
                          type="button"
                          onClick={() => setRuleForm({ ...ruleForm, mode: m })}
                          className={clsx(
                            'px-3 py-1 rounded-full text-xs font-medium',
                            ruleForm.mode === m ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                          )}
                        >
                          {m === 'yaml' ? 'Sigma-style YAML' : 'Detection JSON + condition'}
                        </button>
                      ))}
                    </div>
                    {ruleForm.mode === 'yaml' ? (
                      <>
                        <textarea
                          rows={10}
                          value={ruleForm.rule_yaml}
                          onChange={(e) => setRuleForm({ ...ruleForm, rule_yaml: e.target.value })}
                          placeholder={"title: Suspicious tool\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    process_name|contains: 'mimikatz'\n  condition: selection\nlevel: high"}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                        />
                        <RuleFieldErrors errors={fieldErrorsFor('rule_yaml')} />
                        <p className="mt-1 text-xs text-gray-500">
                          Aggregations and `1 of` / `all of` conditions are not supported by the engine and are refused.
                        </p>
                      </>
                    ) : (
                      <>
                        <textarea
                          rows={8}
                          value={ruleForm.detection_logic}
                          onChange={(e) => setRuleForm({ ...ruleForm, detection_logic: e.target.value })}
                          placeholder={'{\n  "selection": { "process_name|contains": "mimikatz" }\n}'}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                        />
                        <RuleFieldErrors errors={fieldErrorsFor('detection_logic')} />
                        <input
                          type="text"
                          value={ruleForm.condition}
                          onChange={(e) => setRuleForm({ ...ruleForm, condition: e.target.value })}
                          className="mt-2 w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                          placeholder="condition, e.g. selection and not filter"
                        />
                        <RuleFieldErrors errors={fieldErrorsFor('condition')} />
                      </>
                    )}
                  </div>
                  {ruleFormError && <p className="text-sm text-red-600">{ruleFormError}</p>}
                  {otherFieldErrors.length > 0 && <RuleFieldErrors errors={otherFieldErrors} showField />}
                  {validateRuleMutation.error ? <ActionErrorBanner what="validate the rule" error={validateRuleMutation.error} /> : null}
                  {saveRuleMutation.error ? <ActionErrorBanner what={editingRuleId ? 'update the rule' : 'create the rule'} error={saveRuleMutation.error} /> : null}
                  {ruleValidation && (
                    <div className={clsx('rounded-lg border p-3 text-sm', ruleValidation.valid ? 'border-green-200 bg-green-50 text-green-800' : 'border-red-200 bg-red-50 text-red-800')}>
                      <p className="font-medium">{ruleValidation.valid ? 'Valid: the engine can evaluate this rule.' : 'Not valid: fix the fields marked above.'}</p>
                      {ruleValidation.errors.length > 0 && (
                        <ul className="mt-1 list-disc pl-5">
                          {ruleValidation.errors.map((e) => <li key={e}>{e}</li>)}
                        </ul>
                      )}
                      {ruleValidation.warnings.length > 0 && (
                        <ul className="mt-1 list-disc pl-5 text-yellow-800">
                          {ruleValidation.warnings.map((w) => <li key={w}>Warning: {w}</li>)}
                        </ul>
                      )}
                      {ruleValidation.valid && ruleValidation.detection && (
                        <pre className="mt-2 max-h-40 overflow-auto rounded bg-white/70 p-2 text-xs text-gray-800">
                          {JSON.stringify(ruleValidation.detection, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                  <div className="flex justify-end gap-3 pt-2 border-t">
                    <button onClick={() => setShowRuleModal(false)} className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
                      Cancel
                    </button>
                    <button
                      disabled={!ruleForm.name || !ruleForm.title || validateRuleMutation.isPending}
                      onClick={() => { setRuleValidation(null); submitRuleForm('validate'); }}
                      className="px-4 py-2 border border-blue-300 text-blue-700 rounded-lg hover:bg-blue-50 disabled:opacity-50 flex items-center gap-2"
                    >
                      <CheckCircle className="w-4 h-4" />
                      {validateRuleMutation.isPending ? 'Validating...' : 'Validate'}
                    </button>
                    <button
                      disabled={!ruleForm.name || !ruleForm.title || saveRuleMutation.isPending}
                      onClick={() => submitRuleForm('save')}
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    >
                      {saveRuleMutation.isPending ? 'Saving...' : editingRuleId ? 'Save Rule' : 'Create Rule'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Test Rule Modal: POST /siem/rules/{id}/test is a dry run (no alerts fired) */}
          {selectedRule && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Test Rule: {selectedRule.name}</h2>
                  <button onClick={() => setSelectedRule(null)} className="text-gray-400 hover:text-gray-600">✕</button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Sample logs (one per line; JSON objects are matched field by field)</label>
                    <textarea
                      rows={6}
                      value={testLogs}
                      onChange={(e) => setTestLogs(e.target.value)}
                      placeholder={'{"process_name": "mimikatz.exe", "hostname": "ws-01"}'}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                    />
                  </div>
                  {testRuleMutation.error ? <ActionErrorBanner what="test the rule" error={testRuleMutation.error} /> : null}
                  {testRuleMutation.data && (
                    <div className="bg-gray-50 rounded-lg p-4 space-y-2">
                      <h4 className="text-sm font-semibold text-gray-900">Dry-run result</h4>
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div><span className="text-gray-500">Samples:</span> <span className="font-medium">{testRuleMutation.data.sample_count}</span></div>
                        <div><span className="text-gray-500">Matches:</span> <span className="font-medium">{testRuleMutation.data.match_count}</span></div>
                        <div>
                          <span className="text-gray-500">Match Rate:</span>{' '}
                          <span className="font-medium">
                            {testRuleMutation.data.sample_count > 0 ? `${(testRuleMutation.data.match_rate * 100).toFixed(1)}%` : 'Not available'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                  <div className="flex justify-end gap-3">
                    <button onClick={() => setSelectedRule(null)} className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
                      Close
                    </button>
                    <button
                      disabled={!testLogs.trim() || testRuleMutation.isPending}
                      onClick={() => testRuleMutation.mutate({ ruleId: selectedRule.id, samples: testLogs.split('\n').filter((l: string) => l.trim()) })}
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    >
                      {testRuleMutation.isPending ? 'Running...' : 'Run Test'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Import Rule Modal: 422 invalid_rule lists the unsupported Sigma constructs */}
          {showImportRuleModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Import Rule (Sigma YAML)</h2>
                  <button onClick={() => setShowImportRuleModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Paste YAML Rule Definition</label>
                    <textarea
                      rows={12}
                      value={importYaml}
                      onChange={(e) => setImportYaml(e.target.value)}
                      placeholder={"title: My Detection Rule\nstatus: experimental\ndescription: Detects suspicious activity\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: 'mimikatz'\n  condition: selection\nlevel: high"}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                    />
                  </div>
                  {importRuleMutation.error ? <ActionErrorBanner what="import the rule" error={importRuleMutation.error} /> : null}
                  <div className="flex justify-end gap-3 pt-2 border-t">
                    <button onClick={() => setShowImportRuleModal(false)} className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
                      Cancel
                    </button>
                    <button
                      disabled={!importYaml.trim() || importRuleMutation.isPending}
                      onClick={() => importRuleMutation.mutate(importYaml)}
                      className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 flex items-center gap-2"
                    >
                      <Upload className="w-4 h-4" />
                      {importRuleMutation.isPending ? 'Importing...' : 'Import Rule'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Data Sources Tab */}
      {activeTab === 'sources' && (
        <div className="space-y-6">
          <LoadErrorBanner what="collector status" error={collectorStatusError} />
          <LoadErrorBanner what="data sources" error={sourcesError} />
          {collectorStartMutation.error ? <ActionErrorBanner what="start the syslog collector" error={collectorStartMutation.error} /> : null}
          {collectorStopMutation.error ? <ActionErrorBanner what="stop the syslog collector" error={collectorStopMutation.error} /> : null}
          {/* Syslog Collector Status Card (GET /siem/collector/status: status, port, scope) */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Server className="w-6 h-6 text-purple-600" />
                <div>
                  <h3 className="font-semibold text-gray-900">Syslog Collector</h3>
                  <p className="text-sm text-gray-500">
                    {collectorStatus?.scope === 'api_process'
                      ? 'State of the listener in the API process that answered this request; other API replicas may differ.'
                      : 'Central log collection service'}
                  </p>
                </div>
              </div>
              <span className={clsx('px-3 py-1 text-xs font-semibold rounded-full', collectorRunning ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600')}>
                {collectorStatus == null ? 'Unknown' : collectorRunning ? 'Running' : 'Stopped'}
              </span>
            </div>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div>
                <span className="text-sm text-gray-500">Listening port</span>
                <p className="text-sm font-medium text-gray-900">{collectorStatus?.port ?? 'Not listening'}</p>
              </div>
              <div>
                <span className="text-sm text-gray-500">Protocol</span>
                <p className="text-sm font-medium text-gray-900">{collectorStatus?.protocol ?? 'Not available'}</p>
              </div>
              <div>
                <span className="text-sm text-gray-500">Messages Received</span>
                <p className="text-sm font-medium text-gray-900">
                  {collectorRunning && typeof collectorStatus?.messages_received === 'number' ? collectorStatus.messages_received.toLocaleString() : 'Not available'}
                </p>
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => { collectorStopMutation.reset(); collectorStartMutation.mutate(); }}
                disabled={collectorRunning || collectorStartMutation.isPending}
                className="px-4 py-2 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 disabled:opacity-50 flex items-center gap-2"
              >
                <Play className="w-4 h-4" />
                Start
              </button>
              <button
                onClick={() => { collectorStartMutation.reset(); collectorStopMutation.mutate(); }}
                disabled={!collectorRunning || collectorStopMutation.isPending}
                className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 disabled:opacity-50 flex items-center gap-2"
              >
                <Square className="w-4 h-4" />
                Stop
              </button>
            </div>
          </div>

          <button
            onClick={() => { setSourceActionError(null); setSourceModalMode('add'); setSelectedSource({}); setNewSourceForm({ name: '', description: '', source_type: 'syslog' }); }}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Plus className="w-5 h-5" />
            Add Data Source
          </button>

          {sourcesLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : sources.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-500">
              <Server className="w-12 h-12 mb-4 text-gray-300" />
              <p>{sourcesError ? 'Data sources could not be loaded' : 'No data sources configured'}</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {sources.map((source: any) => (
                <div key={source.id} className="bg-white rounded-lg border border-gray-200 p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Server className="w-6 h-6 text-blue-600" />
                      <div>
                        <h3 className="font-semibold text-gray-900">{source.name}</h3>
                        <p className="text-sm text-gray-500">{source.source_type}</p>
                      </div>
                    </div>
                    <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', stateTone[source.ingest_status] || 'bg-gray-100 text-gray-700')}>
                      {ingestStatusLabel(source.ingest_status)}
                    </span>
                  </div>

                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Events received</span>
                      <span className="text-sm font-medium text-gray-900">{(source.events_received ?? 0).toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Events today</span>
                      <span className="text-sm font-medium text-gray-900">{(source.events_today ?? 0).toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Last event</span>
                      <span className="text-sm text-gray-600">{source.last_event_at ? new Date(source.last_event_at).toLocaleString() : 'No events yet'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600" title="Ingested logs are attributed to this source when this log field equals the source name">Matched on</span>
                      <span className="text-sm font-mono text-gray-600">{source.match_field || 'source_name'}</span>
                    </div>
                    {source.error_count > 0 && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-red-600">Errors</span>
                        <span className="text-sm font-medium text-red-600">{source.error_count}</span>
                      </div>
                    )}
                  </div>

                  <div className="mt-4 flex gap-2">
                    <button
                      onClick={() => { setSourceActionError(null); setSourceModalMode('config'); setSelectedSource(source); setNewSourceForm({ name: source.name, description: source.description || '', source_type: source.source_type || 'syslog' }); }}
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50"
                    >
                      Config
                    </button>
                    <button
                      onClick={() => { setSourceActionError(null); setSourceModalMode('view'); setSelectedSource(source); }}
                      className="flex-1 px-3 py-2 bg-blue-50 text-blue-600 rounded-lg text-sm font-medium hover:bg-blue-100"
                    >
                      View
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Source Modal - View / Config / Add */}
          {selectedSource && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">
                    {sourceModalMode === 'add' ? 'Add Data Source' : sourceModalMode === 'config' ? 'Configure Source' : 'Data Source Details'}
                  </h2>
                  <button onClick={() => setSelectedSource(null)} className="text-gray-400 hover:text-gray-600">✕</button>
                </div>
                <div className="p-6 space-y-5">
                  {sourceActionError && <ActionErrorBanner what={sourceActionError.what} error={sourceActionError.error} />}
                  {(sourceModalMode === 'add' || sourceModalMode === 'config') ? (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Source Name *</label>
                        <input
                          type="text"
                          value={newSourceForm.name}
                          onChange={(e) => setNewSourceForm({ ...newSourceForm, name: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                          placeholder="e.g., Edge Firewall"
                        />
                        <p className="mt-1 text-xs text-gray-500">Logs are counted against this source when their source name equals this name.</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                        <textarea
                          value={newSourceForm.description}
                          onChange={(e) => setNewSourceForm({ ...newSourceForm, description: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                          rows={3}
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Source Type *</label>
                        <select
                          value={newSourceForm.source_type}
                          onChange={(e) => setNewSourceForm({ ...newSourceForm, source_type: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        >
                          <option value="syslog">Syslog</option>
                          <option value="json_api">JSON API</option>
                          <option value="cef">CEF</option>
                          <option value="leef">LEEF</option>
                          <option value="windows_event">Windows Event</option>
                          <option value="cloud_trail">Cloud Trail</option>
                          <option value="custom">Custom</option>
                        </select>
                      </div>
                      {sourceModalMode === 'config' && selectedSource.id && (
                        <div className="border-t pt-4">
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-600">Enabled</span>
                            <button
                              onClick={toggleSource}
                              className={clsx('px-3 py-1 rounded-full text-xs font-medium', selectedSource.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600')}
                            >
                              {selectedSource.enabled ? 'Enabled' : 'Disabled'}
                            </button>
                          </div>
                        </div>
                      )}
                      <div className="flex gap-3 pt-2 border-t">
                        <button
                          onClick={saveSource}
                          disabled={!newSourceForm.name}
                          className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
                        >
                          {sourceModalMode === 'add' ? 'Create Source' : 'Save Changes'}
                        </button>
                        <button onClick={() => setSelectedSource(null)} className="flex-1 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-200">
                          Cancel
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Name</label>
                          <p className="text-gray-900 font-medium">{selectedSource.name}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Type</label>
                          <p className="text-gray-900">{selectedSource.source_type}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Ingest status</label>
                          <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', stateTone[selectedSource.ingest_status] || 'bg-gray-100 text-gray-700')}>
                            {ingestStatusLabel(selectedSource.ingest_status)}
                          </span>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Events received / today</label>
                          <p className="text-gray-900">{(selectedSource.events_received ?? 0).toLocaleString()} / {(selectedSource.events_today ?? 0).toLocaleString()}</p>
                        </div>
                      </div>
                      {selectedSource.description && (
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Description</label>
                          <p className="text-gray-900 text-sm">{selectedSource.description}</p>
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Created</label>
                          <p className="text-gray-900 text-sm">{formatWhen(selectedSource.created_at)}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Last event</label>
                          <p className="text-gray-900 text-sm">{selectedSource.last_event_at ? formatWhen(selectedSource.last_event_at) : 'No events yet'}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Error Count</label>
                          <p className="text-gray-900 text-sm">{selectedSource.error_count ?? 0}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Matched on field</label>
                          <p className="text-gray-900 text-sm font-mono">{selectedSource.match_field || 'source_name'}</p>
                        </div>
                      </div>
                      {selectedSource.last_error && (
                        <div>
                          <label className="block text-sm font-medium text-gray-500 mb-1">Last Error</label>
                          <p className="text-red-600 text-sm bg-red-50 p-3 rounded">{selectedSource.last_error}</p>
                        </div>
                      )}
                      <div className="border-t pt-4">
                        <label className="block text-sm font-medium text-gray-500 mb-1">Source ID</label>
                        <p className="text-gray-600 text-sm font-mono">{selectedSource.id}</p>
                      </div>
                      <div className="flex gap-3 pt-2">
                        <button
                          onClick={() => { setSourceModalMode('config'); setNewSourceForm({ name: selectedSource.name, description: selectedSource.description || '', source_type: selectedSource.source_type || 'syslog' }); }}
                          className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                        >
                          Edit Configuration
                        </button>
                        <button onClick={() => setSelectedSource(null)} className="flex-1 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-200">
                          Close
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Correlation Tab */}
      {activeTab === 'correlation' && (
        <div className="space-y-6">
          <LoadErrorBanner what="correlation events" error={correlationsError} />
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {correlationsLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : correlations.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <TrendingUp className="w-12 h-12 mb-4 text-gray-300" />
                <p>No correlation events</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Time
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Correlation Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Matched Rules
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Related Events
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {correlations.map((correlation: any) => (
                    <tr key={correlation.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {new Date(correlation.created_at || "").toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{correlation.name}</td>
                      <td className="px-6 py-4">
                        <span
                          className={clsx(
                            'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                            severityColors[correlation.severity] || severityColors.info
                          )}
                        >
                          {correlation.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">{correlation.rule_ids?.length || (correlation.rule_id ? 1 : 0)}</td>
                      <td className="px-6 py-4 text-sm text-gray-600">{correlation.event_count || 0}</td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-700">
                          {correlation.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button
                          onClick={() => setSelectedCorrelation(correlation)}
                          className="text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center gap-1 ml-auto"
                        >
                          <Eye className="w-4 h-4" />
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Correlation Detail Modal */}
          {selectedCorrelation && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">Correlation Details</h2>
                  <button
                    onClick={() => setSelectedCorrelation(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    ✕
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Name</label>
                      <p className="text-gray-900 font-medium">{selectedCorrelation.name}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Correlation ID</label>
                      <p className="text-gray-900 font-mono text-sm">{selectedCorrelation.correlation_id}</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Severity</label>
                      <span className={clsx('px-2 py-1 text-xs font-medium rounded-full border capitalize', severityColors[selectedCorrelation.severity] || severityColors.info)}>
                        {selectedCorrelation.severity}
                      </span>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
                      <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-700">
                        {selectedCorrelation.status}
                      </span>
                    </div>
                  </div>
                  {selectedCorrelation.description && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Description</label>
                      <p className="text-gray-900 text-sm">{selectedCorrelation.description}</p>
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Event Count</label>
                      <p className="text-gray-900">{selectedCorrelation.event_count || 0}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Alert Generated</label>
                      <p className="text-gray-900">{selectedCorrelation.alert_generated ? 'Yes' : 'No'}</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Timespan Start</label>
                      <p className="text-gray-900 text-sm">{selectedCorrelation.timespan_start ? new Date(selectedCorrelation.timespan_start || "").toLocaleString() : '-'}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Timespan End</label>
                      <p className="text-gray-900 text-sm">{selectedCorrelation.timespan_end ? new Date(selectedCorrelation.timespan_end || "").toLocaleString() : '-'}</p>
                    </div>
                  </div>
                  {selectedCorrelation.source_addresses && selectedCorrelation.source_addresses.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Source Addresses</label>
                      <p className="text-gray-900 font-mono text-sm">{selectedCorrelation.source_addresses.join(', ')}</p>
                    </div>
                  )}
                  {selectedCorrelation.mitre_tactics && selectedCorrelation.mitre_tactics.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">MITRE Tactics</label>
                      <p className="text-gray-900 text-sm">{selectedCorrelation.mitre_tactics.join(', ')}</p>
                    </div>
                  )}
                  <div className="border-t pt-4">
                    <label className="block text-sm font-medium text-gray-500 mb-1">Created At</label>
                    <p className="text-gray-600 text-sm">{selectedCorrelation.created_at ? new Date(selectedCorrelation.created_at || "").toLocaleString() : '-'}</p>
                  </div>
                  <div className="flex justify-end pt-2">
                    <button onClick={() => setSelectedCorrelation(null)} className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-200">
                      Close
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Live Tail Tab */}
      {activeTab === 'live' && (
        <div className="space-y-6">
          <LoadErrorBanner what="live log tail" error={liveError} />
          {/* Controls */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <button
                  onClick={() => setIsTailing(!isTailing)}
                  className={clsx(
                    'px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2',
                    isTailing
                      ? 'bg-red-600 text-white hover:bg-red-700'
                      : 'bg-green-600 text-white hover:bg-green-700'
                  )}
                >
                  {isTailing ? (
                    <>
                      <Pause className="w-4 h-4" />
                      Stop Tailing
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Start Tailing
                    </>
                  )}
                </button>
                {!isTailing && (
                  <span className="px-3 py-1 text-xs font-semibold rounded-full bg-yellow-100 text-yellow-700">
                    Paused
                  </span>
                )}
                <span className="px-3 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-700">
                  {filteredLiveLogs.length} logs
                </span>
              </div>
            </div>

            {/* Severity Filter Chips */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-gray-600">Filter:</span>
              {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => {
                    setLiveSeverityFilter((prev) =>
                      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
                    );
                  }}
                  className={clsx(
                    'px-3 py-1 rounded-full text-xs font-medium transition-colors capitalize border',
                    liveSeverityFilter.includes(sev)
                      ? severityColors[sev]
                      : 'bg-gray-100 text-gray-500 border-gray-200 hover:bg-gray-200'
                  )}
                >
                  {sev}
                </button>
              ))}
              {liveSeverityFilter.length > 0 && (
                <button
                  onClick={() => setLiveSeverityFilter([])}
                  className="text-xs text-gray-500 hover:text-gray-700 underline ml-1"
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* Live Log Stream */}
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div
              ref={liveTailRef}
              className="max-h-[600px] overflow-y-auto"
            >
              {filteredLiveLogs.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                  <Activity className="w-12 h-12 mb-4 text-gray-300" />
                  <p>{isTailing ? 'Waiting for logs...' : 'Press "Start Tailing" to begin'}</p>
                </div>
              ) : (
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200 sticky top-0">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-48">
                        Timestamp
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-24">
                        Severity
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-32">
                        Source
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Message
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-32">
                        Source IP
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 font-mono text-xs">
                    {filteredLiveLogs.map((log: any, idx: number) => (
                      <tr
                        key={log.id || idx}
                        className={clsx(
                          'transition-colors',
                          severityRowColors[log.severity] || 'bg-white'
                        )}
                      >
                        <td className="px-4 py-2 text-gray-500 whitespace-nowrap">
                          {new Date(log.timestamp || "").toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-2">
                          <span
                            className={clsx(
                              'px-2 py-0.5 text-xs font-medium rounded-full border capitalize',
                              severityColors[log.severity] || severityColors.info
                            )}
                          >
                            {log.severity}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-gray-700">{log.source_name}</td>
                        <td className="px-4 py-2 text-gray-900 truncate max-w-md">{log.message}</td>
                        <td className="px-4 py-2 text-gray-600">{log.source_ip}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatsCard({
  title,
  value,
  subtext,
  icon: Icon,
}: {
  title: string;
  value: string | number;
  subtext: string;
  icon: ComponentType<{ className?: string }>;
}) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
          <p className="text-xs text-gray-500 mt-2">{subtext}</p>
        </div>
        <Icon className="w-8 h-8 text-blue-600 opacity-10" />
      </div>
    </div>
  );
}
