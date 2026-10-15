import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Plus,
  Filter,
  Calendar,
  CheckCircle,
  Clock,
  AlertCircle,
  Loader2,
  X,
  FileText,
  Trash2,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import FormModal from '../components/FormModal';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import { describeLoadError } from '../lib/loadError';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

// Statuses a control can hold (src/schemas/compliance.py ControlStatus plus
// the attester's not_assessed).
const CONTROL_STATUSES = ['implemented', 'partially_implemented', 'planned', 'not_implemented', 'not_applicable', 'not_assessed'];
// Statuses a person can set by hand (PUT /controls/{id}); not_assessed is
// the attester's verdict, not a manual one.
const MANUAL_STATUSES = ['implemented', 'partially_implemented', 'planned', 'not_implemented', 'not_applicable'];
const CONTROL_FAMILIES = ['AC', 'AT', 'AU', 'CA', 'CM', 'CP', 'IA', 'IR', 'MA', 'MP', 'PE', 'PL', 'PM', 'PS', 'PT', 'RA', 'SA', 'SC', 'SI', 'SR'];

const controlStatusColor = (status: string) => {
  switch (status) {
    case 'implemented': return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
    case 'partially_implemented': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'planned': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400';
    case 'not_implemented': return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400';
  }
};

type TabType = 'overview' | 'controls' | 'poams' | 'cui' | 'cisa';

interface DashboardData {
  overall_compliance_score: number;
  frameworks_total: number;
  frameworks_compliant: number;
  framework_scores: Array<{ name: string; score: number }>;
  overdue_poams: number;
  upcoming_poams?: number;
  upcoming_assessments: number;
  control_status_breakdown: Record<string, number>;
  active_cisa_directives: number;
  cui_assets_total: number;
  cui_assets_active?: number;
  // Stored assessment scores (90 days), one point per framework assessment.
  trends: Array<{ date: string; framework_id?: string; score: number; satisfied?: number; failed?: number; controls?: number }>;
  last_updated?: string;
}

interface AssessmentBasis {
  control?: string;
  result?: 'pass' | 'fail' | 'not_assessed' | string;
  summary?: string;
  reason?: string | null;
  basis?: Array<{ kind: string; source: string; value: unknown }>;
  checked_at?: string;
  approved_evidence?: number;
}

interface Control {
  id: string;
  control_id: string;
  framework_id: string;
  title: string;
  control_family: string;
  status: string;
  implementation_status: number;
  implementation_details?: string | null;
  responsible_party?: string | null;
  baseline: string | null;
  last_assessed_at: string | null;
  last_assessment_result?: string | null;
  evidence_ids: string[];
  description?: string | null;
  related_controls?: Record<string, unknown>;
  assessment_basis?: AssessmentBasis | null;
  status_source?: 'seed' | 'attester' | 'manual' | string | null;
}

interface POAM {
  id: string;
  weakness_name: string;
  risk_level: 'high' | 'medium' | 'low';
  status: 'open' | 'in_progress' | 'completed';
  scheduled_completion_date: string;
  assigned_to: string;
}

interface CUIAsset {
  id: string;
  asset_id: string;
  asset_type: string;
  cui_category: string;
  cui_designation: string;
  dissemination_controls: string[];
  classification_authority: string;
}

interface CISADirective {
  id: string;
  title: string;
  compliance_deadline: string;
  status: 'open' | 'in_progress' | 'completed';
  actions_taken: string[];
}

const getScoreColor = (score: number) => {
  if (score >= 80) return 'text-green-600 dark:text-green-400';
  if (score >= 60) return 'text-yellow-600 dark:text-yellow-400';
  return 'text-red-600 dark:text-red-400';
};

export default function ComplianceDashboard() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [frameworkFilter, setFrameworkFilter] = useState<string>('all');
  const [familyFilter, setFamilyFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [poamStatusFilter, setPOAMStatusFilter] = useState<string>('all');
  const [riskLevelFilter, setRiskLevelFilter] = useState<string>('all');
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [attestResult, setAttestResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: frameworks, error: frameworksError } = useQuery<Row[]>({
    queryKey: ['compliance-frameworks'],
    queryFn: async () => (await api.get('/compliance/frameworks')).data,
  });

  const runFrameworkAction = async (fw: Row, kind: 'attest' | 'assess') => {
    setBusy(`${kind}-${fw.id}`);
    setActionError(null);
    try {
      const res = kind === 'attest'
        ? await api.post(`/compliance/frameworks/${fw.id}/attest`)
        : await api.post(`/compliance/frameworks/${fw.id}/assess`);
      setAttestResult({ ...res.data, kind, framework_name: fw.short_name || fw.name });
      queryClient.invalidateQueries({ queryKey: ['compliance-dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['compliance-controls'] });
      queryClient.invalidateQueries({ queryKey: ['compliance-frameworks'] });
    } catch (error) {
      setActionError({ what: kind === 'attest' ? `run the attester on ${fw.short_name || fw.name}` : `assess ${fw.short_name || fw.name}`, error });
    } finally {
      setBusy(null);
    }
  };

  const { data: dashboardData, isLoading: dashboardLoading, error: dashboardError } = useQuery<DashboardData>({
    queryKey: ['compliance-dashboard'],
    queryFn: async () => {
      const response = await api.get('/compliance/dashboard');
      return response.data;
    },
  });

  const { data: controls, isLoading: controlsLoading, error: controlsError } = useQuery<Control[]>({
    queryKey: ['compliance-controls', frameworkFilter, familyFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (frameworkFilter !== 'all') params.append('framework_id', frameworkFilter);
      if (familyFilter !== 'all') params.append('family', familyFilter);
      if (statusFilter !== 'all') params.append('status', statusFilter);
      params.append('limit', '500');
      const response = await api.get(`/compliance/controls?${params}`);
      return response.data;
    },
  });

  const { data: poams, isLoading: poamsLoading, error: poamsError } = useQuery<POAM[]>({
    queryKey: ['compliance-poams', poamStatusFilter, riskLevelFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (poamStatusFilter !== 'all') params.append('status', poamStatusFilter);
      if (riskLevelFilter !== 'all') params.append('risk_level', riskLevelFilter);
      const response = await api.get(`/compliance/poams?${params}`);
      return response.data;
    },
  });

  const { data: cuiAssets, isLoading: cuiLoading, error: cuiError } = useQuery<CUIAsset[]>({
    queryKey: ['compliance-cui'],
    queryFn: async () => {
      const response = await api.get('/compliance/cui');
      return response.data;
    },
  });

  const { data: cisaDirectives, isLoading: cisaLoading, error: cisaError } = useQuery<CISADirective[]>({
    queryKey: ['compliance-cisa'],
    queryFn: async () => {
      const response = await api.get('/compliance/cisa/directives');
      return response.data;
    },
  });

  const createPOAMMutation = useMutation({
    mutationFn: async (data: Partial<POAM>) => {
      const response = await api.post('/compliance/poams', data);
      return response.data;
    },
    onSuccess: () => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['compliance-poams'] });
    },
    onError: (err: unknown) => setActionError({ what: 'create the POA&M', error: err }),
  });

  const getStatusBadgeColor = (status: string) => {
    const colors: Record<string, string> = {
      compliant: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      partially: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
      'non-compliant': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      open: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      in_progress: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
      completed: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      'implemented': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      'partially_implemented': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
      'planned': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
      'not_implemented': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400',
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Compliance Dashboard</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Federal compliance framework tracking and management
        </p>
      </div>

      {actionError && (
        <div className="flex items-start gap-2">
          <div className="flex-1"><ActionErrorBanner what={actionError.what} error={actionError.error} /></div>
          <button
            onClick={() => setActionError(null)}
            className="text-red-700 hover:text-red-900"
            aria-label="Dismiss"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}
      {attestResult && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 space-y-1">
          <div className="flex justify-between gap-4">
            <span className="font-medium">
              {attestResult.kind === 'attest'
                ? `Attester on ${attestResult.framework_name}: ${attestResult.attested} control(s) checked, ${attestResult.passed} pass, ${attestResult.failed} fail, ${attestResult.not_assessed} not assessed; ${attestResult.manual_status_kept} manually set status(es) kept.`
                : `Assessment of ${attestResult.framework_name}: score ${attestResult.compliance_score ?? NA}, ${attestResult.not_assessed ?? 0} control(s) not assessed, ${attestResult.other_than_satisfied ?? 0} other than satisfied.`}
            </span>
            <button onClick={() => setAttestResult(null)} className="text-xs underline">dismiss</button>
          </div>
          {attestResult.kind === 'attest' && Array.isArray(attestResult.controls) && (
            <details>
              <summary className="cursor-pointer text-xs">Per-control results</summary>
              <ul className="text-xs max-h-48 overflow-y-auto mt-1">
                {attestResult.controls.map((c: Row) => (
                  <li key={c.control_record_id ?? c.control_id}>
                    <span className="font-mono">{c.control_id}</span>: {c.result} → {String(c.status).replace(/_/g, ' ')}{c.reason ? ` (${c.reason})` : ''}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-8 -mb-px" aria-label="Tabs">
          {(['overview', 'controls', 'poams', 'cui', 'cisa'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={clsx(
                'py-2 px-1 border-b-2 font-medium text-sm transition-colors',
                activeTab === tab
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
              )}
            >
              {tab === 'overview' && 'Overview'}
              {tab === 'controls' && 'Controls'}
              {tab === 'poams' && 'POA&Ms'}
              {tab === 'cui' && 'CUI Management'}
              {tab === 'cisa' && 'CISA Directives'}
            </button>
          ))}
        </nav>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && dashboardError && (
        <LoadErrorBanner what="the compliance dashboard" error={dashboardError} />
      )}
      {activeTab === 'overview' && !dashboardError && (
        <>
          <LoadErrorBanner what="compliance frameworks" error={frameworksError} />
          <OverviewTab
            data={dashboardData}
            loading={dashboardLoading}
            frameworks={frameworks ?? []}
            busy={busy}
            onFrameworkAction={runFrameworkAction}
          />
        </>
      )}

      {/* Controls Tab */}
      {activeTab === 'controls' && controlsError && (
        <LoadErrorBanner what="controls" error={controlsError} />
      )}
      {activeTab === 'controls' && !controlsError && (
        <ControlsTab
          controls={controls || []}
          loading={controlsLoading}
          expandedControl={expandedControl}
          setExpandedControl={setExpandedControl}
          frameworkFilter={frameworkFilter}
          setFrameworkFilter={setFrameworkFilter}
          familyFilter={familyFilter}
          setFamilyFilter={setFamilyFilter}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          frameworkScores={dashboardData?.framework_scores || []}
          onSaved={() => {
            queryClient.invalidateQueries({ queryKey: ['compliance-controls'] });
            queryClient.invalidateQueries({ queryKey: ['compliance-dashboard'] });
          }}
        />
      )}

      {/* POA&Ms Tab */}
      {activeTab === 'poams' && poamsError && (
        <LoadErrorBanner what="POA&Ms" error={poamsError} />
      )}
      {activeTab === 'poams' && !poamsError && (
        <POAMsTab
          poams={poams || []}
          loading={poamsLoading}
          statusFilter={poamStatusFilter}
          setStatusFilter={setPOAMStatusFilter}
          riskLevelFilter={riskLevelFilter}
          setRiskLevelFilter={setRiskLevelFilter}
          overduePOAMs={dashboardData?.overdue_poams ?? null}
        />
      )}

      {/* CUI Management Tab */}
      {activeTab === 'cui' && cuiError && (
        <LoadErrorBanner what="CUI assets" error={cuiError} />
      )}
      {activeTab === 'cui' && !cuiError && (
        <CUITab
          assets={cuiAssets || []}
          loading={cuiLoading}
          onRefresh={() => queryClient.invalidateQueries({ queryKey: ['compliance-cui'] })}
        />
      )}

      {/* CISA Directives Tab */}
      {activeTab === 'cisa' && cisaError && (
        <LoadErrorBanner what="CISA directives" error={cisaError} />
      )}
      {activeTab === 'cisa' && !cisaError && (
        <CISATab
          directives={cisaDirectives || []}
          loading={cisaLoading}
        />
      )}
    </div>
  );
}

function OverviewTab({
  data,
  loading,
  frameworks,
  busy,
  onFrameworkAction,
}: {
  data?: DashboardData;
  loading: boolean;
  frameworks: Row[];
  busy: string | null;
  onFrameworkAction: (fw: Row, kind: 'attest' | 'assess') => void;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Overall Compliance Gauge */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Overall Compliance Score
        </h2>
        <div className="flex items-center gap-8">
          <div className="flex-shrink-0">
            <div className="relative w-32 h-32">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 120 120">
                <circle
                  cx="60"
                  cy="60"
                  r="54"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="8"
                  className="text-gray-200 dark:text-gray-700"
                />
                <circle
                  cx="60"
                  cy="60"
                  r="54"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="8"
                  strokeDasharray={`${(data?.overall_compliance_score || 0) * 3.4} 340`}
                  className={clsx(
                    'transition-all duration-500',
                    (data?.overall_compliance_score || 0) >= 80
                      ? 'text-green-500'
                      : (data?.overall_compliance_score || 0) >= 60
                      ? 'text-yellow-500'
                      : 'text-red-500'
                  )}
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="text-3xl font-bold text-gray-900 dark:text-white">
                    {data && data.frameworks_total > 0 ? data.overall_compliance_score : '—'}
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">{data && data.frameworks_total > 0 ? '%' : NA}</div>
                </div>
              </div>
            </div>
          </div>
          <div className="flex-1">
            <p className="text-gray-600 dark:text-gray-400 mb-2">
              Mean of the stored framework scores. A score moves only when a framework is assessed; controls the
              attester cannot check stay &quot;not assessed&quot; and are never counted as implemented.
            </p>
            {data?.control_status_breakdown && (
              <div className="flex flex-wrap gap-2 text-xs">
                {Object.entries(data.control_status_breakdown).filter(([k]) => k !== 'total').map(([k, v]) => (
                  <span key={k} className={clsx('px-2 py-0.5 rounded-full', controlStatusColor(k))}>
                    {k.replace(/_/g, ' ')}: {v}
                  </span>
                ))}
                <span className="px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-700">total: {data.control_status_breakdown.total ?? 0}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Overdue POA&Ms Alert */}
      {data && data.overdue_poams > 0 && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-semibold text-red-800 dark:text-red-400">Overdue POA&Ms</h3>
            <p className="text-sm text-red-700 dark:text-red-300">
              {data.overdue_poams} Plan of Action and Milestones are overdue. Review and update schedules immediately.
            </p>
          </div>
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Frameworks" value={data?.frameworks_total ?? 0} icon={FileText} color="blue" />
        <StatCard label="Compliant" value={data?.frameworks_compliant ?? 0} icon={CheckCircle} color="green" />
        <StatCard label="Overdue POA&Ms" value={data?.overdue_poams ?? 0} icon={AlertTriangle} color="red" />
        <StatCard label="CISA Directives" value={data?.active_cisa_directives ?? 0} icon={AlertCircle} color="orange" />
      </div>

      {/* Framework Score Cards */}
      {frameworks.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
          No compliance framework is enabled for this organisation.
        </p>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {frameworks.map((f): Row => ({ ...f, name: f.short_name || f.name, score: Number(f.compliance_score ?? 0) })).map((fw) => (
          <div
            key={fw.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-5"
          >
            <div className="flex items-start justify-between mb-2">
              <h3 className="font-semibold text-gray-900 dark:text-white">
                {fw.name}
              </h3>
              <span className="text-xs text-gray-500">{String(fw.status || '').replace(/_/g, ' ')}</span>
            </div>
            <p className="text-xs text-gray-500 mb-3">
              {fw.implemented_controls}/{fw.total_controls} implemented · last assessed {fw.last_assessment_at ? new Date(fw.last_assessment_at).toLocaleDateString() : 'never'}
            </p>

            <div className="space-y-3">
              {/* Score Gauge */}
              <div>
                <div className="flex items-end justify-between mb-1">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Score</span>
                  <span className={clsx('text-lg font-bold', getScoreColor(fw.score ?? 0))}>
                    {fw.score ?? 0}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={clsx(
                      'h-full rounded-full transition-all duration-300',
                      (fw.score ?? 0) >= 80
                        ? 'bg-green-500'
                        : (fw.score ?? 0) >= 60
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    )}
                    style={{ width: `${fw.score ?? 0}%` }}
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => onFrameworkAction(fw, 'attest')}
                  disabled={busy !== null}
                  title="Check every control the attester has a rule for against platform facts (admin)"
                  className="flex-1 inline-flex items-center justify-center gap-1 px-2 py-1.5 text-xs bg-blue-600 text-white rounded disabled:opacity-50"
                >
                  <ShieldCheck className="w-3 h-3" />
                  {busy === `attest-${fw.id}` ? 'Running...' : 'Run Attester'}
                </button>
                <button
                  onClick={() => onFrameworkAction(fw, 'assess')}
                  disabled={busy !== null}
                  title="Recompute the framework score from the stored control statuses"
                  className="flex-1 px-2 py-1.5 text-xs border border-gray-300 dark:border-gray-600 rounded disabled:opacity-50"
                >
                  {busy === `assess-${fw.id}` ? 'Assessing...' : 'Assess'}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Compliance Trend Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Compliance Trend (90 Days, stored assessments)
        </h2>
        {(data?.trends || []).length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-12">
            No framework assessment is stored for the last 90 days.
          </p>
        ) : (
          <div className="h-64 flex items-end justify-between gap-1">
            {(data?.trends || []).map((point, idx) => {
              const fwName = frameworks.find((f) => f.id === point.framework_id)?.short_name ?? point.framework_id ?? '';
              return (
                <div key={idx} className="flex-1 flex flex-col items-center h-full justify-end">
                  <div
                    className="w-full bg-blue-500 dark:bg-blue-600 rounded-t"
                    style={{ height: `${Math.min(100, Math.max(point.score, 0))}%`, minHeight: '4px' }}
                    title={`${fwName} ${point.score}% on ${point.date}${point.controls != null ? ` (${point.satisfied ?? 0} satisfied / ${point.failed ?? 0} failed of ${point.controls})` : ''}`}
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Upcoming Assessments */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Upcoming Assessments
        </h2>
        <div className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
          <Calendar className="w-5 h-5 text-blue-600 dark:text-blue-400" />
          <div>
            <div className="font-medium text-gray-900 dark:text-white">
              {data?.upcoming_assessments ?? 0} planned assessments
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              Controls: {data?.control_status_breakdown?.implemented ?? 0}/{data?.control_status_breakdown?.total ?? 0} implemented
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ControlsTab({
  controls,
  loading,
  expandedControl,
  setExpandedControl,
  frameworkFilter,
  setFrameworkFilter,
  familyFilter,
  setFamilyFilter,
  statusFilter,
  setStatusFilter,
  frameworkScores,
  onSaved,
}: {
  controls: Control[];
  loading: boolean;
  expandedControl: string | null;
  setExpandedControl: (id: string | null) => void;
  frameworkFilter: string;
  setFrameworkFilter: (value: string) => void;
  familyFilter: string;
  setFamilyFilter: (value: string) => void;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  frameworkScores: Array<{ name: string; score: number }>;
  onSaved: () => void;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const controlFamilies = CONTROL_FAMILIES;
  const controlStatuses = CONTROL_STATUSES;

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filters</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Framework Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Framework
            </label>
            <select
              value={frameworkFilter}
              onChange={(e) => setFrameworkFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Frameworks</option>
              {frameworkScores.map((fw) => (
                <option key={fw.name} value={fw.name}>
                  {fw.name}
                </option>
              ))}
            </select>
          </div>

          {/* Family Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Family
            </label>
            <select
              value={familyFilter}
              onChange={(e) => setFamilyFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Families</option>
              {controlFamilies.map((family) => (
                <option key={family} value={family}>
                  {family}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Statuses</option>
              {controlStatuses.map((status) => (
                <option key={status} value={status}>
                  {status.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Controls Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Control ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Title
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Family
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Attester Result
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Baseline
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Evidence
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {controls.length === 0 && (
              <tr><td colSpan={7} className="px-6 py-8 text-center text-sm text-gray-500">No control matches these filters.</td></tr>
            )}
            {controls.map((control) => (
              <tr
                key={control.id}
                className="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer transition-colors"
                onClick={() =>
                  setExpandedControl(expandedControl === control.id ? null : control.id)
                }
              >
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {expandedControl === control.id ? (
                    <ChevronDown className="w-4 h-4 inline mr-2" />
                  ) : (
                    <ChevronRight className="w-4 h-4 inline mr-2" />
                  )}
                  {control.control_id || control.id}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {control.title}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {control.control_family ?? ''}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span className={clsx('inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium', controlStatusColor(control.status))}>
                    {control.status.replace(/_/g, ' ')}
                  </span>
                  {control.status_source && (
                    <div className="text-xs text-gray-500 mt-1">
                      {control.status_source === 'manual' ? 'set by a person' : control.status_source === 'attester' ? 'set by the attester' : 'catalogue seed (unassessed)'}
                    </div>
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {control.assessment_basis?.result
                    ? <span title={control.assessment_basis.summary ?? ''}>{String(control.assessment_basis.result).replace(/_/g, ' ')}</span>
                    : 'no rule run'}
                </td>
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {control.baseline || '—'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {control.evidence_ids?.length ?? 0}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Expanded Control Details */}
      {expandedControl && (
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
          {controls.find((c) => c.id === expandedControl) && (
            <ControlExpandedDetails
              control={controls.find((c) => c.id === expandedControl)!}
              onClose={() => setExpandedControl(null)}
              onSaved={onSaved}
            />
          )}
        </div>
      )}
    </div>
  );
}

function ControlExpandedDetails({ control, onClose, onSaved }: { control: Control; onClose: () => void; onSaved: () => void }) {
  const [saveError, setSaveError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const basis = control.assessment_basis;
  const related = Object.entries(control.related_controls ?? {});
  return (
    <div className="space-y-4">
      <div>
        <h3 className="font-semibold text-gray-900 dark:text-white">{control.control_id}: {control.title}</h3>
        <p className="text-sm text-gray-700 dark:text-gray-300 mt-1">
          {control.description || 'No description available'}
        </p>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-lg p-3 text-sm space-y-1">
        <h4 className="font-medium text-gray-700 dark:text-gray-300">Assessment basis</h4>
        {!basis ? (
          <p className="text-gray-500">The attester has not evaluated this control (no rule has run for it).</p>
        ) : (
          <>
            <p>
              Result: <span className="font-medium">{String(basis.result ?? 'not_assessed').replace(/_/g, ' ')}</span>
              {basis.checked_at ? ` · checked ${new Date(basis.checked_at).toLocaleString()}` : ''}
              {basis.approved_evidence != null ? ` · ${basis.approved_evidence} approved evidence item(s)` : ''}
            </p>
            {basis.summary && <p className="text-gray-700 dark:text-gray-300">{basis.summary}</p>}
            {basis.reason && <p className="text-orange-700 dark:text-orange-300">Reason: {basis.reason}</p>}
            {Array.isArray(basis.basis) && basis.basis.length > 0 && (
              <ul className="list-disc ml-5 text-xs text-gray-600 dark:text-gray-400">
                {basis.basis.map((b, i) => (
                  <li key={i}>{b.kind} · {b.source}: {typeof b.value === 'object' ? JSON.stringify(b.value) : String(b.value)}</li>
                ))}
              </ul>
            )}
          </>
        )}
        <p className="text-xs text-gray-500">
          Status source: {control.status_source ?? NA}
          {control.status_source === 'manual' ? ' (the attester records its result here but does not overwrite a status a person set)' : ''}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Last Assessed</h4>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {control.last_assessed_at ? new Date(control.last_assessed_at || "").toLocaleDateString() : 'Never'}
          </p>
        </div>
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Evidence Items</h4>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {control.evidence_ids?.length ?? 0} files
          </p>
        </div>
      </div>

      {related.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Related Controls</h4>
          <div className="flex flex-wrap gap-2 mt-2">
            {related.map(([k, v]) => (
              <span
                key={k}
                className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 text-gray-700 dark:text-gray-300"
              >
                {k}{Array.isArray(v) ? `: ${v.join(', ')}` : typeof v === 'string' ? `: ${v}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}

      <form
        className="pt-4 border-t border-blue-200 dark:border-blue-800 space-y-2"
        onSubmit={async (e) => {
          e.preventDefault();
          const fd = new FormData(e.currentTarget);
          const impl = String(fd.get('implementation_status') || '').trim();
          setSaving(true);
          setSaveError(null);
          try {
            await api.put(`/compliance/controls/${control.id}`, {
              status: fd.get('status'),
              implementation_status: impl === '' ? undefined : Number(impl),
              responsible_party: fd.get('responsible_party') || undefined,
              implementation_details: fd.get('implementation_details') || undefined,
            });
            onSaved();
            onClose();
          } catch (err) {
            setSaveError(err);
          } finally {
            setSaving(false);
          }
        }}
      >
        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Mark status manually (admin)</h4>
        <p className="text-xs text-gray-500">A manually set status is recorded as such and the attester will not overwrite it.</p>
        <ActionErrorBanner what="save the control status" error={saveError} />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <select name="status" defaultValue={MANUAL_STATUSES.includes(control.status) ? control.status : 'planned'} className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm">
            {MANUAL_STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
          </select>
          <input name="implementation_status" type="number" min={0} max={100} step="any" defaultValue={control.implementation_status ?? ''} placeholder="% implemented" className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm" />
          <input name="responsible_party" defaultValue={control.responsible_party ?? ''} placeholder="Responsible party" className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm" />
        </div>
        <textarea name="implementation_details" rows={2} defaultValue={control.implementation_details ?? ''} placeholder="Implementation narrative" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm" />
        <div className="flex gap-2">
          <button type="submit" disabled={saving} className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium disabled:opacity-50">
            <FileText className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save Status'}
          </button>
          <button type="button" onClick={onClose} className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium">
            Close
          </button>
        </div>
      </form>
    </div>
  );
}

function POAMsTab({
  poams,
  loading,
  statusFilter,
  setStatusFilter,
  riskLevelFilter,
  setRiskLevelFilter,
  overduePOAMs,
}: {
  poams: POAM[];
  loading: boolean;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  riskLevelFilter: string;
  setRiskLevelFilter: (value: string) => void;
  overduePOAMs: number | null;
}) {
  const queryClient = useQueryClient();
  const [showCreatePOAM, setShowCreatePOAM] = useState(false);
  const [deleteError, setDeleteError] = useState<unknown>(null);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const poamStatuses = ['open', 'in_progress', 'delayed', 'completed', 'cancelled', 'accepted'];
  const riskLevels = ['high', 'medium', 'low'];

  // Calculate stats
  const stats = {
    open: poams.filter((p) => p.status === 'open').length,
    // The overdue count comes from the dashboard endpoint; without it there is no number to show.
    overdue: overduePOAMs ?? 'not available',
    high_risk: poams.filter((p) => p.risk_level === 'high').length,
    completed: poams.filter((p) => p.status === 'completed').length,
  };

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Open POA&Ms"
          value={stats.open}
          icon={AlertCircle}
          color="red"
        />
        <StatCard
          label="Overdue"
          value={stats.overdue}
          icon={Clock}
          color="orange"
        />
        <StatCard
          label="High Risk"
          value={stats.high_risk}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          label="Completed (listed)"
          value={stats.completed}
          icon={CheckCircle}
          color="green"
        />
      </div>
      <ActionErrorBanner what="delete the POA&M" error={deleteError} />

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filters</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Statuses</option>
              {poamStatuses.map((status) => (
                <option key={status} value={status}>
                  {status.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Risk Level
            </label>
            <select
              value={riskLevelFilter}
              onChange={(e) => setRiskLevelFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Risk Levels</option>
              {riskLevels.map((level) => (
                <option key={level} value={level}>
                  {level.charAt(0).toUpperCase() + level.slice(1)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* POA&Ms Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Weakness
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Risk Level
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Scheduled Date
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Assigned To
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Days Remaining
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {poams.map((poam) => (
              <tr key={poam.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {poam.id}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {poam.weakness_name ?? ''}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      poam.risk_level === 'high'
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : poam.risk_level === 'medium'
                        ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                        : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    )}
                  >
                    {poam.risk_level}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      poam.status === 'open'
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : poam.status === 'in_progress'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                        : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    )}
                  >
                    {(poam.status || '').replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {poam.scheduled_completion_date ? new Date(poam.scheduled_completion_date || "").toLocaleDateString() : 'N/A'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {poam.assigned_to ?? ''}
                </td>
                <td className="px-6 py-4 text-sm">
                  {(() => {
                    if (!poam.scheduled_completion_date) return <span className="text-gray-400">N/A</span>;
                    const daysRemaining = Math.ceil(
                      (new Date(poam.scheduled_completion_date || "").getTime() - Date.now()) / (1000 * 60 * 60 * 24)
                    );
                    return (
                      <span
                        className={clsx(
                          'font-medium',
                          daysRemaining < 0
                            ? 'text-red-600 dark:text-red-400'
                            : daysRemaining < 7
                            ? 'text-orange-600 dark:text-orange-400'
                            : 'text-gray-600 dark:text-gray-400'
                        )}
                      >
                        {daysRemaining < 0
                          ? `${Math.abs(daysRemaining)} days overdue`
                          : `${daysRemaining} days`}
                      </span>
                    );
                  })()}
                </td>
                <td className="px-6 py-4 text-sm">
                  <button
                    onClick={async () => {
                      if (!window.confirm(`Delete POA&M "${poam.weakness_name}"?`)) return;
                      setDeleteError(null);
                      try {
                        await api.delete(`/compliance/poams/${poam.id}`);
                        queryClient.invalidateQueries({ queryKey: ['compliance-poams'] });
                      } catch (err) {
                        setDeleteError(err);
                      }
                    }}
                    className="text-red-600 hover:text-red-800"
                    title="Delete POA&M (analyst / admin)"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create POA&M Button */}
      <button
        onClick={() => setShowCreatePOAM(true)}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Plus className="w-5 h-5" />
        Create POA&M
      </button>

      <FormModal
        open={showCreatePOAM}
        onClose={() => setShowCreatePOAM(false)}
        title="Create POA&M Item"
        description="Plan of Action & Milestones — document an identified weakness and track remediation."
        submitLabel="Create POA&M"
        fields={[
          {
            name: 'title',
            label: 'Title',
            required: true,
            placeholder: 'Short summary of the weakness',
          },
          {
            name: 'weakness_description',
            label: 'Weakness Description',
            type: 'textarea',
            required: true,
            placeholder: 'Detailed description of the control deficiency',
          },
          {
            name: 'control_id',
            label: 'Control ID',
            required: true,
            placeholder: 'e.g. AC-2, SI-4, IA-5(1)',
            help: 'NIST 800-53 / FedRAMP control identifier',
          },
          {
            name: 'severity',
            label: 'Severity',
            type: 'select',
            required: true,
            defaultValue: 'medium',
            options: [
              { value: 'low', label: 'Low' },
              { value: 'medium', label: 'Medium' },
              { value: 'high', label: 'High' },
              { value: 'critical', label: 'Critical' },
            ],
          },
          {
            name: 'scheduled_completion_date',
            label: 'Scheduled Completion Date',
            type: 'date',
          },
          {
            name: 'responsible_party',
            label: 'Responsible Party',
            placeholder: 'Team or individual accountable',
          },
        ]}
        onSubmit={async (values) => {
          // Map UI fields → backend POAMCreateRequest schema
          //  title                → weakness_name
          //  control_id           → control_id_ref
          //  severity             → risk_level
          // weakness_source defaults to 'self_identified' (assessment, audit,
          // self_identified, vulnerability_scan, etc.)
          await api.post('/compliance/poams', {
            weakness_name: values.title,
            weakness_description: values.weakness_description,
            control_id_ref: values.control_id,
            weakness_source: 'self_identified',
            risk_level: values.severity,
            scheduled_completion_date: values.scheduled_completion_date || undefined,
            assigned_to: values.responsible_party || undefined,
          });
          queryClient.invalidateQueries({ queryKey: ['compliance-poams'] });
        }}
      />
    </div>
  );
}

function CUITab({
  assets,
  loading,
  onRefresh,
}: {
  assets: CUIAsset[];
  loading: boolean;
  onRefresh: () => void;
}) {
  const [showModal, setShowModal] = useState(false);
  const [markError, setMarkError] = useState<string | null>(null);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  // Filter out fully-empty CUI markings — test-seeded records with no
  // asset_id/category/designation would render as a row of dashes and
  // inflate the stat counts.
  const validAssets = assets.filter((a) => a.asset_id || a.cui_category || a.cui_designation);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="CUI Assets" value={validAssets.length} icon={FileText} color="blue" />
        <StatCard label="Active Markings" value={validAssets.filter((a) => a.cui_designation).length} icon={CheckCircle} color="green" />
        <StatCard label="Categories Tracked" value={new Set(validAssets.map((a) => a.cui_category).filter(Boolean)).size} icon={AlertTriangle} color="orange" />
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">Asset</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">Type</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">CUI Category</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">Designation</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">Dissemination Controls</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">Authority</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {validAssets.length === 0 ? (
              <tr><td colSpan={6} className="px-6 py-8 text-center text-gray-500">No CUI markings yet. Click "Mark as CUI" to add one.</td></tr>
            ) : validAssets.map((asset) => (
              <tr key={asset.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">{asset.asset_id || '-'}</td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{asset.asset_type || '-'}</td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{asset.cui_category || '-'}</td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{asset.cui_designation || '-'}</td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{Array.isArray(asset.dissemination_controls) ? asset.dissemination_controls.join(', ') : ''}</td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{asset.classification_authority || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <button onClick={() => setShowModal(true)} className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium">
        <Plus className="w-5 h-5" /> Mark as CUI
      </button>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setShowModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h2 className="text-lg font-semibold">Mark Asset as CUI</h2>
              <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <form className="p-6 space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              setMarkError(null);
              try {
                await api.post('/compliance/cui', {
                  asset_id: fd.get('asset_id'),
                  asset_type: fd.get('asset_type'),
                  cui_category: fd.get('cui_category'),
                  cui_designation: fd.get('cui_designation'),
                  classification_authority: fd.get('classification_authority'),
                  dissemination_controls: (fd.get('dissemination_controls') as string || '').split(',').map(s => s.trim()).filter(Boolean),
                  handling_instructions: fd.get('handling_instructions') || null,
                });
                setShowModal(false);
                onRefresh();
              } catch (err) { setMarkError(`Could not mark asset as CUI. ${describeLoadError(err)}`); }
            }}>
              {markError && (
                <div role="alert" className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
                  {markError}
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Asset ID</label>
                  <input name="asset_id" required className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm" placeholder="e.g., SRV-001" />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Asset Type</label>
                  <select name="asset_type" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm">
                    <option value="server">Server</option>
                    <option value="database">Database</option>
                    <option value="application">Application</option>
                    <option value="document">Document</option>
                    <option value="network">Network Device</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">CUI Category</label>
                  <select name="cui_category" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm">
                    <option value="CTI">CTI (Controlled Technical Information)</option>
                    <option value="ITAR">ITAR (Export Controlled)</option>
                    <option value="PRVCY">PRVCY (Privacy)</option>
                    <option value="PROPIN">PROPIN (Proprietary)</option>
                    <option value="LES">LES (Law Enforcement Sensitive)</option>
                    <option value="SP-CTI">SP-CTI (Specified CTI)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Designation</label>
                  <select name="cui_designation" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm">
                    <option value="CUI">CUI (Basic)</option>
                    <option value="CUI//SP">CUI//SP (Specified)</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Classification Authority</label>
                <input name="classification_authority" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm" placeholder="e.g., NIST SP 800-171" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Dissemination Controls (comma-separated)</label>
                <input name="dissemination_controls" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm" placeholder="e.g., NOFORN, REL TO USA" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Handling Instructions</label>
                <textarea name="handling_instructions" rows={2} className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm" placeholder="Special handling requirements..." />
              </div>
              <div className="flex gap-3 pt-4">
                <button type="button" onClick={() => setShowModal(false)} className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg">Mark as CUI</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function CISATab({
  directives,
  loading,
}: {
  directives: CISADirective[];
  loading: boolean;
}) {
  const [checks, setChecks] = useState<Record<string, Row>>({});
  const [checkError, setCheckError] = useState<{ what: string; error: unknown } | null>(null);
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
          Active CISA Binding Operational Directives
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Directives the org is tracking. Click “Check Compliance” to run the
          automated check against platform state.
        </p>
      </div>
      {checkError && <ActionErrorBanner what={checkError.what} error={checkError.error} />}
      {directives.length === 0 ? (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-8 text-center text-sm text-gray-500 dark:text-gray-400">
          No CISA directives are being tracked yet. Directives are seeded per
          framework activation or can be added through the API.
        </div>
      ) : null}
      {/* Active Directives Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {directives.map((directive) => (
          <div
            key={directive.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {directive.id}
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  {directive.title}
                </p>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  directive.status === 'open'
                    ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                    : directive.status === 'in_progress'
                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                    : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                )}
              >
                {(directive.status ?? '').replace(/_/g, ' ')}
              </span>
            </div>

            <div className="space-y-2 mb-4">
              <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                <Calendar className="w-4 h-4" />
                Deadline: {directive.compliance_deadline ? new Date(directive.compliance_deadline || "").toLocaleDateString() : 'N/A'}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {Array.isArray(directive.actions_taken) ? directive.actions_taken.length : 0} actions taken
              </div>
            </div>

            {checks[directive.id] && (() => {
              const c = checks[directive.id];
              return (
                <div className="mb-3 text-sm bg-gray-50 dark:bg-gray-700/50 rounded p-3 space-y-1">
                  <p>
                    Result: <span className="font-medium">{String(c.compliance_status ?? 'not_assessed').replace(/_/g, ' ')}</span>
                    {c.assessed === false && ' (stored status; this directive has no automated check)'}
                  </p>
                  {c.basis && <p className="text-xs text-gray-500">{typeof c.basis === 'string' ? c.basis : JSON.stringify(c.basis)}</p>}
                  {c.kev && Array.isArray(c.kev.overdue_cves) && c.kev.overdue_cves.length > 0 && (
                    <p className="text-xs text-red-700">Overdue KEV CVEs: {c.kev.overdue_cves.slice(0, 20).join(', ')}{c.kev.overdue_cves.length > 20 ? '…' : ''}</p>
                  )}
                </div>
              );
            })()}

            <button
              onClick={async () => {
                setCheckError(null);
                try {
                  const res = await api.post(`/compliance/cisa/directives/${directive.id}/check`);
                  setChecks((prev) => ({ ...prev, [directive.id]: res.data }));
                } catch (err) {
                  setCheckError({ what: `check ${directive.title}`, error: err });
                }
              }}
              className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium"
            >
              Check Compliance
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number | string;
  icon: React.ComponentType<{ className?: string }>;
  color: 'red' | 'orange' | 'green' | 'blue';
}) {
  const colorClasses: Record<string, string> = {
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
    orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">{label}</div>
        </div>
        <div className={clsx('p-3 rounded-lg', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}
