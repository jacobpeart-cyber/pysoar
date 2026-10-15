import { useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Search,
  AlertTriangle,
  BarChart3,
  Clock,
  AlertCircle,
  CheckCircle,
  Loader2,
  RefreshCw,
  Download,
  Upload,
  Plus,
  Zap,
  Target,
  Shield,
  Globe,
  Package,
  Share2,
  Camera,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';
import FormModal from '../components/FormModal';
import { useRoleGate, ANALYST_ONLY_REASON } from '../lib/roles';
import { readableSubmit } from '../lib/formSubmit';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, PieChart, Pie, Cell } from 'recharts';

const NA = 'not available';

// Field names follow src/schemas/exposure.py (ExposureDashboardStats).
interface TrendPoint {
  date: string;
  snapshot_date?: string;
  exposures?: number;
  open_exposures?: number;
  critical?: number;
  high?: number;
  risk_score?: number | null;
  compliance?: number | null;
}

interface DashboardStats {
  total_assets: number;
  active_assets: number;
  inactive_assets: number;
  internet_facing_assets: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  info_vulns: number;
  open_exposures: number;
  assets_with_open_exposures: number;
  catalog_vulnerabilities: number;
  overdue_tickets: number;
  overall_risk_score: number | null;
  risk_score_basis?: string;
  mean_time_to_remediate_days: number | null;
  exposure_trend?: TrendPoint[];
  compliance_trend?: TrendPoint[];
  trend_source?: string;
}

interface Asset {
  id: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string;
  environment: string | null;
  network_zone: string | null;
  criticality: string;
  is_internet_facing: boolean;
  risk_score: number;
  vulnerability_count: number;
  last_scan_at: string | null;
  last_seen: string | null;
  status: string | null;
  owner?: string | null;
  os_type?: string | null;
  os_version?: string | null;
  open_ports?: number[];
}

interface Vulnerability {
  id: string;
  cve_id: string | null;
  title: string;
  severity: string;
  cvss_v3_score: number | null;
  epss_score: number | null;
  exploit_available: boolean;
  is_exploited_in_wild: boolean;
  affected_assets: number | null;
  total_links: number | null;
  patch_available: boolean;
  status: string | null;
}

interface RemediationTicket {
  id: string;
  title: string;
  priority: string;
  status: string;
  assigned_to: string | null;
  affected_assets: string[];
  due_date: string | null;
  sla_status?: 'on_track' | 'at_risk' | 'overdue';
  sla_breach?: boolean | null;
  verification_status?: string | null;
  resolved_at?: string | null;
}

interface AttackSurface {
  id: string;
  name: string;
  type: string | null;
  risk_score: number;
  total_assets: number;
  exposed_assets: number;
  critical_exposures: number;
  last_assessed: string | null;
  assessed: boolean;
}

interface ComplianceFramework {
  id: string;
  name: string;
  pass_percentage: number;
  total_controls: number;
  passed_checks: number;
  failed_checks: number;
  status: string | null;
  last_assessment_at: string | null;
}

interface GraphNode {
  id: string;
  type: 'entry_point' | 'asset' | 'vulnerability';
  label: string;
  criticality?: string;
  is_internet_facing?: boolean;
  risk_score?: number;
  vulnerability_count?: number;
  severity?: string;
  exploited_in_wild?: boolean;
}

interface GraphEdge {
  source: string;
  target: string;
  type: 'exposes' | 'has_vulnerability';
  status?: string;
  risk_score?: number;
}

interface ExposureGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  basis: string;
}

// Formats src/exposure/scan_parser.py SUPPORTED_FORMATS reads.
const EXPOSURE_SCAN_FORMATS: { value: string; label: string }[] = [
  { value: 'auto', label: 'Detect from content' },
  { value: 'nessus', label: 'Nessus (XML / JSON / CSV)' },
  { value: 'tenable', label: 'Tenable.io (JSON)' },
  { value: 'openvas', label: 'OpenVAS / GVM (XML / CSV)' },
  { value: 'qualys', label: 'Qualys (CSV / JSON)' },
  { value: 'rapid7', label: 'Rapid7 (generic parser)' },
  { value: 'json', label: 'Generic JSON' },
  { value: 'csv', label: 'Generic CSV' },
];

const TICKET_STATUSES = ['open', 'assigned', 'in_progress', 'verification', 'closed', 'reopened'];

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
    case 'high':
      return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
    case 'medium':
      return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'low':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400';
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
  }
};

const getRiskColor = (score: number) => {
  if (score >= 80) return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
  if (score >= 60) return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
  if (score >= 40) return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
  return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
};

// Derive SLA status from the actual ticket state rather than trusting
// whatever was stamped on the record at creation time. Backend used to
// write sla_status="on_track" on insert and never recompute it, so a
// ticket whose due_date had long since passed still rendered green.
// Truth source: status + due_date + today.
const deriveSlaStatus = (
  ticket: Pick<RemediationTicket, 'status' | 'due_date' | 'sla_status'>,
): 'on_track' | 'at_risk' | 'overdue' | 'completed' | 'no_due_date' => {
  if (ticket.status === 'closed' || ticket.status === 'verification') {
    return 'completed';
  }
  if (!ticket.due_date) {
    return ticket.sla_status || 'no_due_date';
  }
  const due = new Date(ticket.due_date);
  if (Number.isNaN(due.getTime())) {
    return ticket.sla_status || 'no_due_date';
  }
  const now = Date.now();
  const msToDue = due.getTime() - now;
  // Anything with a due date in the past is overdue — regardless of
  // what the server thinks.
  if (msToDue < 0) return 'overdue';
  // Within 3 days: at risk.
  if (msToDue < 3 * 24 * 60 * 60 * 1000) return 'at_risk';
  return 'on_track';
};

const getStatusColor = (status: string | null | undefined) => {
  switch (status) {
    case 'active':
    case 'open':
    case 'on_track':
      return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
    case 'inactive':
    case 'in_progress':
    case 'at_risk':
      return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'quarantined':
    case 'verification':
      return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
    case 'overdue':
      // Explicit red — an overdue SLA item is a compliance breach, not
      // a warning. Don't share the color of "verification" etc.
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
    case 'completed':
    case 'closed':
    case 'patched':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400';
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
  }
};

type TabId = 'dashboard' | 'assets' | 'vulnerabilities' | 'remediation' | 'attack-surface' | 'graph' | 'compliance';

export default function ExposureManagement() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [assetSearch, setAssetSearch] = useState('');
  const [assetTypeFilter, setAssetTypeFilter] = useState('all');
  const [environmentFilter, setEnvironmentFilter] = useState('all');
  const [criticalityFilter, setCriticalityFilter] = useState('all');
  const [internetFacingFilter, setInternetFacingFilter] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [exploitFilter, setExploitFilter] = useState('all');
  const [priorityFilter, setPriorityFilter] = useState<string[]>([]);
  const [ticketStatusFilter, setTicketStatusFilter] = useState<string[]>([]);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showCreateTicketModal, setShowCreateTicketModal] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [showAddAsset, setShowAddAsset] = useState(false);
  const gate = useRoleGate();
  const [notice, setNotice] = useState<string | null>(null);
  const [scanImportResult, setScanImportResult] = useState<Row | null>(null);
  const [assetImportResult, setAssetImportResult] = useState<Row | null>(null);
  const [discoveryResult, setDiscoveryResult] = useState<Row | null>(null);
  const [trendDays, setTrendDays] = useState(30);
  const [graphMinSeverity, setGraphMinSeverity] = useState('');
  const assetFileInput = useRef<HTMLInputElement>(null);

  const runAction = async (key: string, what: string, fn: () => Promise<void>) => {
    setBusy(key);
    setActionError(null);
    setNotice(null);
    try {
      await fn();
      queryClient.invalidateQueries({ queryKey: ['exposure'] });
    } catch (error) {
      setActionError({ what, error });
    } finally {
      setBusy(null);
    }
  };

  const { data: stats, error: statsError } = useQuery<DashboardStats>({
    queryKey: ['exposure', 'dashboard'],
    queryFn: async () => {
      const response = await api.get('/exposure/dashboard');
      return response.data;
    },
  });

  const { data: assetsData, isLoading: assetsLoading, error: assetsError } = useQuery<Row>({
    queryKey: ['exposure', 'assets', assetSearch, assetTypeFilter, environmentFilter, criticalityFilter, internetFacingFilter, includeInactive],
    queryFn: async () => {
      const response = await api.get('/exposure/assets', {
        params: {
          search: assetSearch,
          asset_type: assetTypeFilter !== 'all' ? assetTypeFilter : undefined,
          environment: environmentFilter !== 'all' ? environmentFilter : undefined,
          criticality: criticalityFilter !== 'all' ? criticalityFilter : undefined,
          is_internet_facing: internetFacingFilter ? true : undefined,
          include_inactive: includeInactive || undefined,
        },
      });
      return response.data;
    },
  });
  const assets: Asset[] = Array.isArray(assetsData) ? assetsData : (assetsData?.items || []);

  // Stored daily snapshots only (exposure_daily_snapshots); days without a
  // snapshot are absent, nothing is interpolated.
  const { data: trendResp, error: trendError } = useQuery<{ points: TrendPoint[]; count: number; source: string }>({
    queryKey: ['exposure', 'trend', trendDays],
    queryFn: async () => (await api.get('/exposure/trend', { params: { days: trendDays } })).data,
  });

  const { data: graph, isLoading: graphLoading, error: graphError } = useQuery<ExposureGraph>({
    queryKey: ['exposure', 'graph', graphMinSeverity],
    queryFn: async () =>
      (await api.get('/exposure/graph', { params: { limit_assets: 100, min_severity: graphMinSeverity || undefined } })).data,
    enabled: activeTab === 'graph',
  });

  const { data: vulnData, isLoading: vulnLoading, error: vulnError } = useQuery<Row>({
    queryKey: ['exposure', 'vulnerabilities', severityFilter, exploitFilter],
    queryFn: async () => {
      const response = await api.get('/exposure/vulnerabilities', {
        params: {
          severity: severityFilter.length > 0 ? severityFilter.join(',') : undefined,
          has_exploit: exploitFilter !== 'all' ? exploitFilter : undefined,
        },
      });
      return response.data;
    },
  });
  const vulnerabilities: Vulnerability[] = Array.isArray(vulnData) ? vulnData : (vulnData?.items || []);

  const { data: ticketData, isLoading: ticketsLoading, error: ticketsError } = useQuery<Row>({
    queryKey: ['exposure', 'tickets', priorityFilter, ticketStatusFilter],
    queryFn: async () => {
      const response = await api.get('/exposure/tickets', {
        params: {
          priority: priorityFilter.length > 0 ? priorityFilter.join(',') : undefined,
          status: ticketStatusFilter.length > 0 ? ticketStatusFilter.join(',') : undefined,
        },
      });
      return response.data;
    },
  });
  const tickets: RemediationTicket[] = Array.isArray(ticketData) ? ticketData : (ticketData?.items || []);

  const { data: surfaceData, error: surfaceError } = useQuery<Row>({
    queryKey: ['exposure', 'attack-surface'],
    queryFn: async () => {
      const response = await api.get('/exposure/attack-surface');
      return response.data;
    },
  });
  const attackSurfaces: AttackSurface[] = Array.isArray(surfaceData) ? surfaceData : (surfaceData?.items || []);

  const { data: compliance, error: complianceError } = useQuery<ComplianceFramework[]>({
    queryKey: ['exposure', 'compliance'],
    queryFn: async () => {
      const response = await api.get('/exposure/compliance');
      const data = response.data;
      // Backend returns ComplianceSummary object; transform frameworks map into array
      // ComplianceSummary.frameworks: {short_name: {...}} from stored controls.
      if (data.frameworks && !Array.isArray(data.frameworks)) {
        return Object.entries(data.frameworks as Record<string, Row>).map(([key, value]) => ({
          id: key,
          name: value.name || key,
          pass_percentage: value.pass_percentage ?? 0,
          total_controls: value.total_controls ?? 0,
          passed_checks: value.passed_checks ?? 0,
          failed_checks: value.failed_checks ?? 0,
          status: value.status ?? null,
          last_assessment_at: value.last_assessment_at ?? null,
        }));
      }
      return [];
    },
  });

  // Open exposures by severity, counted server-side (dashboard).
  const vulnerabilityData = stats
    ? [
        { severity: 'critical', count: stats.critical_vulns },
        { severity: 'high', count: stats.high_vulns },
        { severity: 'medium', count: stats.medium_vulns },
        { severity: 'low', count: stats.low_vulns },
      ].filter((d) => d.count > 0)
    : [];

  const topVulnerableAssets = assets
    ?.slice()
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10)
    .map(a => ({ name: a.hostname || a.ip_address || a.id, risk: a.risk_score })) || [];

  // Stored snapshot points only; an empty series renders an empty state.
  const trendData: TrendPoint[] = trendResp?.points ?? [];
  const complianceTrend: TrendPoint[] = stats?.compliance_trend ?? [];

  const colors = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

  const tabs: { id: TabId; name: string; icon: typeof BarChart3 }[] = [
    { id: 'dashboard', name: 'Dashboard', icon: BarChart3 },
    { id: 'assets', name: 'Assets', icon: Package },
    { id: 'vulnerabilities', name: 'Vulnerabilities', icon: AlertTriangle },
    { id: 'remediation', name: 'Remediation', icon: Zap },
    { id: 'attack-surface', name: 'Attack Surface', icon: Target },
    { id: 'graph', name: 'Exposure Graph', icon: Share2 },
    { id: 'compliance', name: 'Compliance', icon: Shield },
  ];

  const importAssetsFile = async (file: File) => {
    const lower = file.name.toLowerCase();
    const format = lower.endsWith('.json') ? 'json' : 'csv';
    setAssetImportResult(null);
    await runAction('asset-import', `import assets from ${file.name}`, async () => {
      const data = await file.text();
      const res = await api.post('/exposure/assets/import', { format, data });
      setAssetImportResult({ ...res.data, file_name: file.name });
    });
  };

  const graphNodes = graph?.nodes ?? [];
  const graphEdges = graph?.edges ?? [];
  const nodeById = new Map(graphNodes.map((n) => [n.id, n]));
  const exposedAssetIds = new Set(graphEdges.filter((e) => e.type === 'exposes').map((e) => e.target));
  const graphAssets = graphNodes.filter((n) => n.type === 'asset');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Exposure Management</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Comprehensive cyber risk and threat exposure platform
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => runAction('snapshot', 'capture an exposure snapshot', async () => {
              const res = await api.post('/exposure/snapshots/capture');
              const snap = res.data?.snapshot ?? {};
              setNotice(`Snapshot stored for ${snap.snapshot_date ?? 'today'}: ${snap.open_exposures ?? 0} open exposure(s), ${res.data?.rescored?.assets_scored ?? 0} asset(s) rescored.`);
            })}
            disabled={busy !== null}
            title="Rescore assets and store today's snapshot (the nightly task does the same)"
            className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
          >
            <Camera className="w-4 h-4" />
            {busy === 'snapshot' ? 'Capturing...' : 'Capture Snapshot'}
          </button>
          <button
            onClick={() => runAction('risk', 'recalculate exposure risk', async () => {
              const res = await api.post('/exposure/risk/recalculate');
              const r = res.data ?? {};
              setNotice(`Risk recalculated for ${r.assets_scored ?? 0} asset(s); overall risk ${r.overall_risk_score ?? NA}.`);
            })}
            disabled={busy !== null}
            title="Recompute link and asset risk scores from stored rows"
            className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
          >
            <Zap className="w-4 h-4" />
            {busy === 'risk' ? 'Recalculating...' : 'Recalculate Risk'}
          </button>
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['exposure'] })}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-1 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
                )}
              >
                <Icon className="w-4 h-4" />
                {tab.name}
              </button>
            );
          })}
        </nav>
      </div>

      {actionError && !showImportModal && !showCreateTicketModal && (
        <ActionErrorBanner what={actionError.what} error={actionError.error} />
      )}
      {notice && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
          <span>{notice}</span>
          <button onClick={() => setNotice(null)} className="text-xs underline">dismiss</button>
        </div>
      )}

      {/* Dashboard Tab */}

      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          <LoadErrorBanner what="exposure statistics" error={statsError} />
          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <Package className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Active Assets</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats?.total_assets ?? NA}
                  </p>
                  {stats && stats.inactive_assets > 0 && (
                    <p className="text-xs text-gray-500">{stats.inactive_assets} inactive not counted</p>
                  )}
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                  <Globe className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Internet-Facing</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats?.internet_facing_assets ?? 'not available'}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg">
                  <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Open Exposures (critical)</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats ? `${stats.open_exposures} (${stats.critical_vulns})` : NA}
                  </p>
                  {stats && (
                    <p className="text-xs text-gray-500">on {stats.assets_with_open_exposures} asset(s); {stats.catalog_vulnerabilities} catalogue rows</p>
                  )}
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                  <Zap className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Overdue Tickets</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats?.overdue_tickets ?? 'not available'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Risk and MTTA Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Overall Risk Score</p>
                  <p className="text-4xl font-bold text-gray-900 dark:text-white mt-2">
                    {stats?.overall_risk_score == null ? NA : stats.overall_risk_score.toFixed(1)}
                  </p>
                  {stats?.risk_score_basis && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{stats.risk_score_basis}</p>
                  )}
                </div>
                {stats?.overall_risk_score != null && (
                  <div className={clsx('w-20 h-20 rounded-full flex items-center justify-center text-2xl font-bold', getRiskColor(stats.overall_risk_score))}>
                    {Math.round(stats.overall_risk_score)}
                  </div>
                )}
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Mean Time to Remediate</p>
                  <p className="text-4xl font-bold text-gray-900 dark:text-white mt-2">
                    {stats?.mean_time_to_remediate_days == null ? NA : stats.mean_time_to_remediate_days.toFixed(1)}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                    {stats?.mean_time_to_remediate_days == null ? 'no remediation ticket closed yet' : 'days (closed tickets)'}
                  </p>
                </div>
                <Clock className="w-16 h-16 text-gray-400" />
              </div>
            </div>
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Vulnerabilities by Severity */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Open Exposures by Severity</h3>
              {vulnerabilityData.length === 0 ? (
                <p className="text-sm text-gray-500 dark:text-gray-400 py-16 text-center">No open exposure is stored.</p>
              ) : (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={vulnerabilityData}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                  >
                    {vulnerabilityData.map((d) => (
                      <Cell key={d.severity} fill={colors[['critical', 'high', 'medium', 'low'].indexOf(d.severity)]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              )}
            </div>

            {/* Top Vulnerable Assets */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top 10 Assets by Stored Risk</h3>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={topVulnerableAssets}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Bar dataKey="risk" fill="#ef4444" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Exposure Trend */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Open Exposure Trend</h3>
              <select
                value={trendDays}
                onChange={(e) => setTrendDays(Number(e.target.value))}
                aria-label="Trend window"
                className="px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm"
              >
                <option value={7}>7 days</option>
                <option value={30}>30 days</option>
                <option value={90}>90 days</option>
                <option value={365}>365 days</option>
              </select>
            </div>
            <LoadErrorBanner what="the exposure trend" error={trendError} />
            {!trendError && trendData.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400 py-12 text-center">
                No daily snapshot is stored for this window. Snapshots are written nightly; use Capture Snapshot to store today's.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Area type="monotone" dataKey="open_exposures" name="open exposures" stroke="#f97316" fill="#fed7aa" />
                  <Area type="monotone" dataKey="critical" name="critical" stroke="#ef4444" fill="#fecaca" />
                </AreaChart>
              </ResponsiveContainer>
            )}
            <p className="text-xs text-gray-500 mt-2">
              {trendData.length} stored snapshot point(s); days without a snapshot are absent.
            </p>
          </div>
        </div>
      )}

      {/* Assets Tab */}
      {activeTab === 'assets' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex flex-col gap-4">
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    value={assetSearch}
                    onChange={(e) => setAssetSearch(e.target.value)}
                    placeholder="Search by hostname or IP..."
                    className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                <select
                  value={assetTypeFilter}
                  onChange={(e) => setAssetTypeFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                >
                  <option value="all">All Types</option>
                  <option value="server">Server</option>
                  <option value="workstation">Workstation</option>
                  <option value="network">Network Device</option>
                </select>
                <select
                  value={environmentFilter}
                  onChange={(e) => setEnvironmentFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                >
                  <option value="all">All Environments</option>
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
                <select
                  value={criticalityFilter}
                  onChange={(e) => setCriticalityFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                >
                  <option value="all">All Criticalities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <label className="flex items-center gap-2 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={internetFacingFilter}
                    onChange={(e) => setInternetFacingFilter(e.target.checked)}
                    className="w-4 h-4"
                  />
                  <span className="text-sm text-gray-900 dark:text-white">Internet-Facing Only</span>
                </label>
                <label className="flex items-center gap-2 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeInactive}
                    onChange={(e) => setIncludeInactive(e.target.checked)}
                    className="w-4 h-4"
                  />
                  <span className="text-sm text-gray-900 dark:text-white">Include inactive</span>
                </label>
              </div>
              <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => setShowAddAsset(true)}
                  disabled={busy !== null || !gate.isAnalyst}
                  title={gate.isAnalyst ? 'Register one asset by hand' : ANALYST_ONLY_REASON}
                  className="flex items-center gap-2 px-3 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  <Plus className="w-4 h-4" />
                  Add Asset
                </button>
                <button
                  onClick={() => assetFileInput.current?.click()}
                  disabled={busy !== null}
                  title="CSV with a header row or a JSON array: hostname, ip_address, asset_type, criticality, environment, ..."
                  className="flex items-center gap-2 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
                >
                  <Upload className="w-4 h-4" />
                  {busy === 'asset-import' ? 'Importing...' : 'Import Assets (CSV / JSON)'}
                </button>
                <button
                  onClick={() => {
                    setDiscoveryResult(null);
                    runAction('discover', 'discover assets from ingested logs', async () => {
                      const res = await api.post('/exposure/assets/discover', { scan_type: 'siem' });
                      setDiscoveryResult(res.data);
                    });
                  }}
                  disabled={busy !== null}
                  title="Find hosts in the last 24 hours of ingested log entries (admin)"
                  className="flex items-center gap-2 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
                >
                  <Search className="w-4 h-4" />
                  {busy === 'discover' ? 'Discovering...' : 'Discover from Logs'}
                </button>
                <span className="text-xs text-gray-500 dark:text-gray-400 self-center">
                  Network, cloud, Active Directory and DNS discovery are not available (no scanner or directory integration).
                </span>
              </div>
              {!gate.isAnalyst && (
                <p className="text-xs text-gray-500 dark:text-gray-400">Adding, importing and discovering assets: {ANALYST_ONLY_REASON}</p>
              )}
              <FormModal
                open={showAddAsset}
                onClose={() => setShowAddAsset(false)}
                title="Add exposure asset"
                description="Registers the asset as you describe it. Risk score and vulnerability count stay empty until a scan import or assessment fills them."
                submitLabel="Add asset"
                fields={[
                  { name: 'hostname', label: 'Hostname', placeholder: 'web-01.example.com' },
                  { name: 'ip_address', label: 'IP address', placeholder: '10.0.0.5' },
                  {
                    name: 'asset_type', label: 'Asset type', type: 'select', required: true, defaultValue: 'server',
                    options: ['server', 'workstation', 'network', 'database', 'application', 'cloud', 'container', 'iot'].map((v) => ({ value: v, label: v })),
                  },
                  {
                    name: 'environment', label: 'Environment', type: 'select', defaultValue: 'production',
                    options: ['production', 'staging', 'development', 'test'].map((v) => ({ value: v, label: v })),
                  },
                  {
                    name: 'criticality', label: 'Criticality', type: 'select', defaultValue: 'medium',
                    options: ['critical', 'high', 'medium', 'low'].map((v) => ({ value: v, label: v })),
                  },
                  {
                    name: 'is_internet_facing', label: 'Internet facing', type: 'select', defaultValue: 'false',
                    options: [{ value: 'false', label: 'No' }, { value: 'true', label: 'Yes' }],
                  },
                  { name: 'os_type', label: 'OS type', placeholder: 'linux' },
                  { name: 'owner', label: 'Owner' },
                ]}
                onSubmit={async (v) => {
                  if (!v.hostname?.trim() && !v.ip_address?.trim()) {
                    throw new Error('Give a hostname or an IP address.');
                  }
                  await readableSubmit(api.post('/exposure/assets', {
                    hostname: v.hostname?.trim() || null,
                    ip_address: v.ip_address?.trim() || null,
                    asset_type: v.asset_type,
                    environment: v.environment || 'production',
                    criticality: v.criticality || 'medium',
                    is_internet_facing: v.is_internet_facing === 'true',
                    os_type: v.os_type?.trim() || null,
                    owner: v.owner?.trim() || null,
                  }));
                  queryClient.invalidateQueries({ queryKey: ['exposure'] });
                }}
              />
              <input
                ref={assetFileInput}
                type="file"
                accept=".csv,.json,text/csv,application/json"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  e.target.value = '';
                  if (file) importAssetsFile(file);
                }}
              />
            </div>
          </div>

          {assetImportResult && (
            <div className="text-sm bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded p-3 space-y-1">
              <div className="flex justify-between">
                <span className="font-medium">
                  {assetImportResult.file_name}: {assetImportResult.rows_read} row(s) read, {assetImportResult.created} created,{' '}
                  {assetImportResult.updated} updated, {assetImportResult.skipped} skipped, {assetImportResult.failed} failed
                </span>
                <button onClick={() => setAssetImportResult(null)} className="text-xs underline">dismiss</button>
              </div>
              {Array.isArray(assetImportResult.errors) && assetImportResult.errors.length > 0 && (
                <ul className="list-disc ml-5">
                  {assetImportResult.errors.slice(0, 50).map((er: Row, i: number) => (
                    <li key={i}>Row {er.row ?? '?'}: {er.reason ?? er.error ?? JSON.stringify(er)}</li>
                  ))}
                  {assetImportResult.errors.length > 50 && <li>... {assetImportResult.errors.length - 50} more</li>}
                </ul>
              )}
            </div>
          )}
          {discoveryResult && (
            <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
              <span>
                Log discovery: {discoveryResult.log_rows_scanned} log row(s) scanned{discoveryResult.truncated ? ' (truncated)' : ''},{' '}
                {discoveryResult.new_assets} new asset(s), {discoveryResult.updated_assets} known asset(s) seen again.
                {discoveryResult.detail ? ` ${discoveryResult.detail}` : ''}
              </span>
              <button onClick={() => setDiscoveryResult(null)} className="text-xs underline">dismiss</button>
            </div>
          )}

          {/* Assets Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-700/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Hostname</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">IP Address</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Type</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Environment</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Criticality</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Risk Score</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Vulns</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Last Scan</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {assetsLoading ? (
                    <tr><td colSpan={10} className="px-4 py-12 text-center text-gray-500"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading assets...</td></tr>
                  ) : assetsError ? (
                    <tr><td colSpan={10} className="px-4 py-4"><LoadErrorBanner what="assets" error={assetsError} /></td></tr>
                  ) : assets.length === 0 ? (
                    <tr><td colSpan={10} className="px-4 py-12 text-center text-gray-500">No assets found. Add assets to start monitoring exposure.</td></tr>
                  ) : null}
                  {assets?.map((asset) => (
                    <tr key={asset.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white font-medium">
                        {asset.hostname || '-'}
                        {asset.is_internet_facing && <Globe className="inline w-3 h-3 ml-1 text-orange-500" aria-label="internet-facing" />}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{asset.ip_address || '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{asset.asset_type}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{asset.environment || asset.network_zone || '-'}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getSeverityColor(asset.criticality))}>
                          {asset.criticality}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={clsx('h-2 rounded-full', asset.risk_score >= 80 ? 'bg-red-500' : asset.risk_score >= 60 ? 'bg-orange-500' : 'bg-yellow-500')}
                            style={{ width: `${asset.risk_score}%` }}
                          />
                        </div>
                        <span className="text-xs text-gray-500 dark:text-gray-400">{asset.risk_score}</span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">{asset.vulnerability_count}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                        {asset.last_scan_at ? new Date(asset.last_scan_at).toLocaleDateString() : 'never scanned'}
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getStatusColor(asset.status))}>
                          {asset.status ?? NA}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setSelectedAsset(selectedAsset?.id === asset.id ? null : asset)}
                          className="text-blue-600 dark:text-blue-400 hover:text-blue-700 text-sm font-medium"
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          {selectedAsset && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 text-sm space-y-1">
              <div className="flex justify-between">
                <h4 className="font-semibold">{selectedAsset.hostname || selectedAsset.ip_address}</h4>
                <button onClick={() => setSelectedAsset(null)} className="text-xs underline">close</button>
              </div>
              <p>OS: {[selectedAsset.os_type, selectedAsset.os_version].filter(Boolean).join(' ') || NA}</p>
              <p>Owner: {selectedAsset.owner || NA}</p>
              <p>Internet-facing: {selectedAsset.is_internet_facing ? 'yes' : 'no'}</p>
              <p>Open ports: {selectedAsset.open_ports && selectedAsset.open_ports.length > 0 ? selectedAsset.open_ports.join(', ') : NA}</p>
              <p>Last seen: {selectedAsset.last_seen ? new Date(selectedAsset.last_seen).toLocaleString() : NA}</p>
            </div>
          )}
        </div>
      )}

      {/* Vulnerabilities Tab */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-4">
          {/* Filters and Actions */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() =>
                        setSeverityFilter(
                          severityFilter.includes(sev)
                            ? severityFilter.filter(s => s !== sev)
                            : [...severityFilter, sev]
                        )
                      }
                      className={clsx(
                        'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                        severityFilter.includes(sev)
                          ? getSeverityColor(sev)
                          : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                      )}
                    >
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => { setActionError(null); setScanImportResult(null); setShowImportModal(true); }}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
                >
                  <Download className="w-4 h-4" />
                  Import Scan Results
                </button>
              </div>
              <select
                value={exploitFilter}
                onChange={(e) => setExploitFilter(e.target.value)}
                className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm max-w-xs"
              >
                <option value="all">All Vulnerabilities</option>
                <option value="true">Has Known Exploit</option>
                <option value="false">No Known Exploit</option>
                <option value="kev">Exploited in the Wild (KEV)</option>
              </select>
            </div>
          </div>
          {scanImportResult && (
            <div className="text-sm bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded p-3 space-y-2">
              <div className="flex justify-between gap-4">
                <span className="font-medium">
                  Scan import from {scanImportResult.scanner_name}: {scanImportResult.findings_read} finding(s) read ({scanImportResult.status})
                </span>
                <button onClick={() => setScanImportResult(null)} className="text-xs underline">dismiss</button>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                <span>Links created: {scanImportResult.links_created}</span>
                <span>Links updated: {scanImportResult.links_updated}</span>
                <span>Links reopened: {scanImportResult.links_reopened}</span>
                <span>Catalogue rows created: {scanImportResult.vulnerabilities_created}</span>
                <span>Assets matched: {scanImportResult.assets_matched}</span>
                <span>Assets created: {scanImportResult.assets_created}</span>
                <span>Assets rescored: {scanImportResult.assets_rescored}</span>
                <span>Skipped: {scanImportResult.skipped_count}</span>
              </div>
              {Array.isArray(scanImportResult.skipped) && scanImportResult.skipped.length > 0 && (
                <div>
                  <p className="font-medium">Skipped findings by reason</p>
                  <ul className="list-disc ml-5">
                    {scanImportResult.skipped.map((s: Row, i: number) => (
                      <li key={i}>
                        {s.reason}: {s.count}
                        {Array.isArray(s.examples) && s.examples.length > 0 && (
                          <span className="text-gray-600 dark:text-gray-400"> (e.g. {s.examples.map((x: unknown) => (typeof x === 'string' ? x : JSON.stringify(x))).join('; ')})</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {Array.isArray(scanImportResult.errors) && scanImportResult.errors.length > 0 && (
                <ul className="list-disc ml-5 text-orange-700 dark:text-orange-300">
                  {scanImportResult.errors.map((m: unknown, i: number) => <li key={i}>{typeof m === 'string' ? m : JSON.stringify(m)}</li>)}
                </ul>
              )}
            </div>
          )}

          {/* Vulnerabilities Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-700/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">CVE ID</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Title</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">CVSS</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">EPSS</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Exploit</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Assets</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Patch</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {vulnLoading ? (
                    <tr><td colSpan={9} className="px-4 py-12 text-center text-gray-500"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading vulnerabilities...</td></tr>
                  ) : vulnError ? (
                    <tr><td colSpan={9} className="px-4 py-4"><LoadErrorBanner what="vulnerabilities" error={vulnError} /></td></tr>
                  ) : vulnerabilities.length === 0 ? (
                    <tr><td colSpan={9} className="px-4 py-12 text-center text-gray-500">No vulnerabilities found. Import scan results to populate.</td></tr>
                  ) : null}
                  {vulnerabilities?.map((vuln) => (
                    <tr key={vuln.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-white">{vuln.cve_id || '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white max-w-xs truncate">{vuln.title}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getSeverityColor(vuln.severity))}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-white">{vuln.cvss_v3_score == null ? NA : vuln.cvss_v3_score.toFixed(1)}</td>
                      <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-white" title="No EPSS feed is connected; only stored scores are shown">
                        {vuln.epss_score == null ? NA : `${(vuln.epss_score * 100).toFixed(1)}%`}
                      </td>
                      <td className="px-4 py-3">
                        {vuln.is_exploited_in_wild ? (
                          <span className="px-2 py-1 text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-full">
                            In the wild
                          </span>
                        ) : vuln.exploit_available ? (
                          <span className="px-2 py-1 text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-full">
                            Yes
                          </span>
                        ) : (
                          <span className="px-2 py-1 text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-full">
                            No
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">
                        {vuln.affected_assets ?? NA}
                        {vuln.total_links != null && <span className="text-xs text-gray-500"> / {vuln.total_links} linked</span>}
                      </td>
                      <td className="px-4 py-3">
                        {vuln.patch_available ? (
                          <CheckCircle className="w-5 h-5 text-green-500" />
                        ) : (
                          <AlertCircle className="w-5 h-5 text-gray-400" />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getStatusColor(vuln.status))}>
                          {vuln.status ?? NA}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Remediation Tab */}
      {activeTab === 'remediation' && (
        <div className="space-y-4">
          {/* Quick Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Open Tickets</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets?.filter(t => t.status === 'open').length || 0}
              </p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Overdue</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets?.filter(t => deriveSlaStatus(t) === 'overdue').length || 0}
              </p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Not Overdue (listed tickets)</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets && tickets.length > 0
                  ? `${Math.round(tickets.filter(t => deriveSlaStatus(t) !== 'overdue').length / tickets.length * 100)}%`
                  : NA}
              </p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Closed (listed tickets)</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets?.filter(t => t.status === 'closed').length || 0}
              </p>
            </div>
          </div>

          {/* Filters and Actions */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap gap-2">
                  <div>
                    <p className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">Priority:</p>
                    <div className="flex flex-wrap gap-2">
                      {['critical', 'high', 'medium', 'low'].map((pri) => (
                        <button
                          key={pri}
                          onClick={() =>
                            setPriorityFilter(
                              priorityFilter.includes(pri)
                                ? priorityFilter.filter(p => p !== pri)
                                : [...priorityFilter, pri]
                            )
                          }
                          className={clsx(
                            'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                            priorityFilter.includes(pri)
                              ? getSeverityColor(pri)
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                          )}
                        >
                          {pri.charAt(0).toUpperCase() + pri.slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">Status:</p>
                    <div className="flex flex-wrap gap-2">
                      {TICKET_STATUSES.map((stat) => (
                        <button
                          key={stat}
                          onClick={() =>
                            setTicketStatusFilter(
                              ticketStatusFilter.includes(stat)
                                ? ticketStatusFilter.filter(s => s !== stat)
                                : [...ticketStatusFilter, stat]
                            )
                          }
                          className={clsx(
                            'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                            ticketStatusFilter.includes(stat)
                              ? getStatusColor(stat)
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                          )}
                        >
                          {stat.replace('_', ' ').charAt(0).toUpperCase() + stat.replace('_', ' ').slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => { setActionError(null); setShowCreateTicketModal(true); }}
                  className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm"
                >
                  <Plus className="w-4 h-4" />
                  Create Ticket
                </button>
              </div>
            </div>
          </div>

          {/* Tickets Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-700/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Title</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Priority</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Assigned To</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Assets</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Due Date</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">SLA Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {ticketsLoading ? (
                    <tr><td colSpan={7} className="px-4 py-12 text-center text-gray-500"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading tickets...</td></tr>
                  ) : ticketsError ? (
                    <tr><td colSpan={7} className="px-4 py-4"><LoadErrorBanner what="remediation tickets" error={ticketsError} /></td></tr>
                  ) : tickets.length === 0 ? (
                    <tr><td colSpan={7} className="px-4 py-12 text-center text-gray-500">No remediation tickets. Create a ticket to track remediation efforts.</td></tr>
                  ) : null}
                  {tickets?.map((ticket) => (
                    <tr key={ticket.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white font-medium">{ticket.title}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getSeverityColor(ticket.priority))}>
                          {ticket.priority}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <select
                          value={ticket.status}
                          disabled={busy !== null}
                          aria-label="Ticket status"
                          onChange={(e) => {
                            const next = e.target.value;
                            runAction(`ticket-${ticket.id}`, `set ticket "${ticket.title}" to ${next}`, async () => {
                              await api.put(`/exposure/tickets/${ticket.id}`, { status: next });
                            });
                          }}
                          className={clsx('px-2 py-1 text-xs font-medium rounded-full border-0', getStatusColor(ticket.status))}
                        >
                          {(TICKET_STATUSES.includes(ticket.status) ? TICKET_STATUSES : [ticket.status, ...TICKET_STATUSES]).map((s) => (
                            <option key={s} value={s}>{s.replace('_', ' ')}</option>
                          ))}
                        </select>
                        {ticket.verification_status && (
                          <div className="text-xs text-gray-500 mt-1">verification: {ticket.verification_status}</div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{ticket.assigned_to || '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">{Array.isArray(ticket.affected_assets) ? ticket.affected_assets.length : 0}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                        {ticket.due_date ? new Date(ticket.due_date).toLocaleDateString() : 'no due date'}
                      </td>
                      <td className="px-4 py-3">
                        {(() => {
                          const sla = ticket.sla_breach && ticket.status !== 'closed' ? 'overdue' : deriveSlaStatus(ticket);
                          return (
                            <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getStatusColor(sla))}>
                              {sla.replace('_', ' ')}
                            </span>
                          );
                        })()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Attack Surface Tab */}
      {activeTab === 'attack-surface' && (
        <div className="space-y-6">
          <LoadErrorBanner what="attack surfaces" error={surfaceError} />
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Mean Risk of Assessed Surfaces</h3>
            <div className="text-4xl font-bold text-gray-900 dark:text-white">
              {(() => {
                const assessed = attackSurfaces.filter((s) => s.assessed);
                return assessed.length > 0
                  ? Math.round(assessed.reduce((sum, s) => sum + s.risk_score, 0) / assessed.length)
                  : NA;
              })()}
            </div>
          </div>
          {!surfaceError && attackSurfaces.length === 0 && (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
              No attack surface is defined.
            </p>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {attackSurfaces?.map((surface) => (
              <div key={surface.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h4 className="font-semibold text-gray-900 dark:text-white">{surface.name}</h4>
                    <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">{surface.type}</p>
                  </div>
                  {surface.assessed ? (
                    <div className="w-12 h-12 rounded-full flex items-center justify-center text-lg font-bold" style={{ background: surface.risk_score >= 70 ? '#fee2e2' : '#fef3c7', color: surface.risk_score >= 70 ? '#dc2626' : '#d97706' }}>
                      {Math.round(surface.risk_score)}
                    </div>
                  ) : (
                    <span className="px-2 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">not assessed</span>
                  )}
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Total Assets</span>
                    <span className="font-semibold text-gray-900 dark:text-white">{surface.total_assets}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Exposed Assets</span>
                    <span className="font-semibold text-orange-600 dark:text-orange-400">{surface.exposed_assets}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Critical Exposures</span>
                    <span className="font-semibold text-red-600 dark:text-red-400">{surface.critical_exposures}</span>
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400 pt-2 border-t border-gray-200 dark:border-gray-700">
                    Last assessed: {surface.last_assessed ? new Date(surface.last_assessed).toLocaleDateString() : 'never'}
                  </div>
                </div>
                <button
                  disabled={busy !== null}
                  onClick={() => runAction(`assess-${surface.id}`, `assess attack surface "${surface.name}"`, async () => {
                    await api.post('/exposure/attack-surface/assess', null, { params: { surface_id: surface.id } });
                  })}
                  className="w-full mt-4 px-4 py-2 bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/40 text-sm font-medium"
                >
                  Assess Now
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Exposure Graph Tab */}
      {activeTab === 'graph' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Internet entry point, active assets with open exposures and the vulnerabilities open on them, computed from stored rows.
              Multi-hop attack paths are not computed: no asset-to-asset reachability (topology, flows, firewall rules) is stored.
            </p>
            <select
              value={graphMinSeverity}
              onChange={(e) => setGraphMinSeverity(e.target.value)}
              aria-label="Minimum severity"
              className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm"
            >
              <option value="">All severities</option>
              <option value="low">Low and above</option>
              <option value="medium">Medium and above</option>
              <option value="high">High and above</option>
              <option value="critical">Critical only</option>
            </select>
          </div>
          <LoadErrorBanner what="the exposure graph" error={graphError} />
          {graphLoading && <p className="text-sm text-gray-500"><Loader2 className="inline w-4 h-4 animate-spin mr-1" />Loading graph...</p>}
          {graph && graphAssets.length === 0 && (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
              No active asset has an open exposure{graphMinSeverity ? ` at ${graphMinSeverity} or above` : ''}.
            </p>
          )}
          {graph && graphAssets.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs text-gray-500">
                {graphAssets.length} asset(s), {graphNodes.filter((n) => n.type === 'vulnerability').length} vulnerability node(s), {graphEdges.length} edge(s)
                {graph.truncated ? ' (asset list truncated at 100, highest risk first)' : ''}. Basis: {graph.basis}.
              </p>
              {graphAssets.map((asset) => {
                const vulnEdges = graphEdges.filter((e) => e.source === asset.id && e.type === 'has_vulnerability');
                return (
                  <div key={asset.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-3">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      {exposedAssetIds.has(asset.id) ? (
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 text-xs">
                          <Globe className="w-3 h-3" /> Internet &rarr;
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 text-xs">internal</span>
                      )}
                      <span className="font-semibold">{asset.label}</span>
                      {asset.criticality && (
                        <span className={clsx('px-2 py-0.5 text-xs rounded-full', getSeverityColor(asset.criticality))}>{asset.criticality}</span>
                      )}
                      <span className="text-xs text-gray-500">risk {asset.risk_score?.toFixed(1) ?? NA}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2 ml-4">
                      {vulnEdges.map((e) => {
                        const v = nodeById.get(e.target);
                        return (
                          <span
                            key={`${e.source}-${e.target}`}
                            title={`link ${e.status ?? ''}, link risk ${e.risk_score ?? NA}`}
                            className={clsx('px-2 py-0.5 text-xs rounded font-mono', getSeverityColor(v?.severity ?? ''))}
                          >
                            {v?.label ?? e.target}
                            {v?.exploited_in_wild ? ' (exploited)' : ''}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'compliance' && (
        <div className="space-y-6">
          <LoadErrorBanner what="compliance frameworks" error={complianceError} />
          {!complianceError && compliance && compliance.length === 0 && (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
              No compliance framework is enabled for this organisation.
            </p>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {compliance?.map((framework) => (
              <div key={framework.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-semibold text-gray-900 dark:text-white">{framework.name}</h4>
                  <span className={clsx('px-3 py-1 text-sm font-medium rounded-full', framework.pass_percentage >= 80 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400')}>
                    {framework.pass_percentage}%
                  </span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className="h-2 rounded-full bg-green-500"
                    style={{ width: `${framework.pass_percentage}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {framework.passed_checks} of {framework.total_controls} controls implemented, {framework.failed_checks} failing;
                  the rest are planned, not assessed or not applicable.
                  {' '}Last assessed: {framework.last_assessment_at ? new Date(framework.last_assessment_at).toLocaleDateString() : 'never'}
                </p>
              </div>
            ))}
          </div>

          {/* Compliance Trend Chart */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Compliance Trend</h4>
            {complianceTrend.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400 py-12 text-center">
                No stored snapshot carries a compliance figure yet.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={complianceTrend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} domain={[0, 100]} />
                  <Tooltip />
                  <Area type="monotone" dataKey="compliance" stroke="#10b981" fill="#d1fae5" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      )}
      {/* Create Ticket Modal */}
      {showCreateTicketModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Create Remediation Ticket</h2>
              <button onClick={() => setShowCreateTicketModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <form onSubmit={async (e) => {
              e.preventDefault();
              const form = e.target as HTMLFormElement;
              const formData = new FormData(form);
              setActionError(null);
              try {
                await api.post('/exposure/tickets', {
                  title: formData.get('title'),
                  description: formData.get('description'),
                  priority: formData.get('priority'),
                  assigned_to: formData.get('assigned_to') || undefined,
                  due_date: formData.get('due_date') || undefined,
                });
                setShowCreateTicketModal(false);
                queryClient.invalidateQueries({ queryKey: ['exposure'] });
              } catch (err) {
                setActionError({ what: 'create the ticket', error: err });
              }
            }} className="p-6 space-y-4">
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Title *</label>
                <input name="title" required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" placeholder="Remediation ticket title" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <textarea name="description" rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" placeholder="Describe the remediation needed..." />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Priority *</label>
                  <select name="priority" required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium" selected>Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Due Date</label>
                  <input name="due_date" type="date" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Assigned To</label>
                <input name="assigned_to" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" placeholder="Username or email" />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="submit" className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 font-medium">Create Ticket</button>
                <button type="button" onClick={() => setShowCreateTicketModal(false)} className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import Scan Results Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Import Scan Results</h2>
              <button onClick={() => setShowImportModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <form onSubmit={async (e) => {
              e.preventDefault();
              const form = e.target as HTMLFormElement;
              const formData = new FormData(form);
              setActionError(null);
              setBusy('scan-import');
              try {
                // ExternalScannerImportRequest: scanner_name + scan_format +
                // scan_data (raw file text). A file, when chosen, wins over
                // the pasted text.
                const file = formData.get('scan_file');
                const pasted = String(formData.get('scan_data') || '');
                const scanData = file instanceof File && file.size > 0 ? await file.text() : pasted;
                if (!scanData.trim()) {
                  setActionError({ what: 'import scan results', error: new Error('Choose a scanner export file or paste its content.') });
                  return;
                }
                const res = await api.post('/exposure/scans/import', {
                  scanner_name: formData.get('scanner_name'),
                  scan_format: formData.get('scan_format'),
                  scan_data: scanData,
                });
                setScanImportResult(res.data);
                setShowImportModal(false);
                queryClient.invalidateQueries({ queryKey: ['exposure'] });
              } catch (err) {
                setActionError({ what: 'import scan results', error: err });
              } finally {
                setBusy(null);
              }
            }} className="p-6 space-y-4">
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Scanner Name *</label>
                <input
                  name="scanner_name"
                  required
                  placeholder="e.g. corporate-nessus-01"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Scan Format *</label>
                <select name="scan_format" required defaultValue="auto" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                  {EXPOSURE_SCAN_FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Scanner export file</label>
                <input name="scan_file" type="file" className="w-full text-sm" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">...or paste the export</label>
                <textarea name="scan_data" rows={6} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm" placeholder="XML, CSV or JSON as exported by the scanner" />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={busy === 'scan-import'} className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium disabled:opacity-50">
                  {busy === 'scan-import' ? 'Importing...' : 'Import'}
                </button>
                <button type="button" onClick={() => setShowImportModal(false)} className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
