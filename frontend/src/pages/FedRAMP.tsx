import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Download,
  FileText,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Loader2,
  BarChart3,
  ClipboardList,
  FolderOpen,
  FileDown,
  RefreshCw,
  Info,
  AlertCircle,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import { describeLoadError } from '../lib/loadError';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

// Generated documents mark every fact the platform does not hold with this
// prefix (src/compliance/system_facts.py); count them so nobody mistakes a
// draft for a finished document.
const PLACEHOLDER_PREFIX = '[TO BE COMPLETED';

function countPlaceholders(doc: unknown): number {
  try {
    return (JSON.stringify(doc).match(/\[TO BE COMPLETED/g) || []).length;
  } catch {
    return 0;
  }
}

// ─── Types ───────────────────────────────────────────────────────────────────

type TabType = 'readiness' | 'controls' | 'poam' | 'evidence' | 'documents';

type ImplementationStatus =
  | 'implemented'
  | 'partial'
  | 'partially_implemented'
  | 'not_implemented'
  | 'planned'
  | 'alternative'
  | 'not_applicable'
  | 'not_assessed';
type Priority = 'P1' | 'P2' | 'P3';
type RiskLevel = 'critical' | 'high' | 'moderate' | 'low';
type ReadinessBadge = 'Ready' | 'In Progress' | 'Not Ready' | 'Not Assessed';

interface ReadinessData {
  score: number;
  badge: ReadinessBadge;
  lastAssessmentDate: string;
  controlFamilyBreakdown: ControlFamilyScore[];
  gapSummary: {
    implemented: number;
    partial: number;
    not_implemented: number;
    planned: number;
    total: number;
  };
  recommendations: Recommendation[];
}

interface ControlFamilyScore {
  family: string;
  label: string;
  percentImplemented: number;
  total: number;
  implemented: number;
}

interface Recommendation {
  id: string;
  priority: Priority;
  title: string;
  description: string;
  controlFamily: string;
  effort: 'low' | 'medium' | 'high';
}

interface FedRAMPControl {
  id: string;
  controlId: string;
  family: string;
  title: string;
  priority: Priority;
  status: ImplementationStatus;
  pysoarMapping: string | null;
  description?: string;
  guidance?: string;
  responsibleRole?: string;
  evidenceRequired?: string[];
}

// GET /fedramp/poam/report (FedRAMPGenerator.generate_poam_report).
interface POAMReport {
  items: Row[];
  summary: {
    total_items: number;
    status_breakdown: Record<string, number>;
    severity_breakdown: Record<string, number>;
    overdue_items: number;
  };
  timeline: { month: string; due: number; completed: number; open: number }[];
  overdue_items?: Row[];
}

// GET /fedramp/evidence/status.
interface EvidenceStatus {
  families: Row[];
  total_controls: number;
  controls_with_evidence: number;
  overall_evidence_coverage_pct: number;
}

interface FedRAMPDocument {
  id: string;
  name: string;
  description: string;
  lastGenerated: string | null;
  available: boolean;
  type: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const TABS: { key: TabType; label: string; icon: React.ReactNode }[] = [
  { key: 'readiness', label: 'Readiness Dashboard', icon: <BarChart3 className="w-4 h-4" /> },
  { key: 'controls', label: 'Controls', icon: <ShieldCheck className="w-4 h-4" /> },
  { key: 'poam', label: 'POA&M Report', icon: <ClipboardList className="w-4 h-4" /> },
  { key: 'evidence', label: 'Evidence', icon: <FolderOpen className="w-4 h-4" /> },
  { key: 'documents', label: 'Documents', icon: <FileText className="w-4 h-4" /> },
];

const CONTROL_FAMILIES = [
  'AC', 'AT', 'AU', 'CA', 'CM', 'CP', 'IA', 'IR', 'MA', 'MP',
  'PE', 'PL', 'PM', 'PS', 'RA', 'SA', 'SC', 'SI',
];

// NIST SP 800-53 family names as the FedRAMP catalogue stores them
// (src/fedramp/controls.py FAMILY_CODES); evidence collection filters by code.
const FAMILY_CODE_BY_NAME: Record<string, string> = {
  'Access Control': 'AC', 'Awareness and Training': 'AT', 'Audit and Accountability': 'AU',
  'Security Assessment and Authorization': 'CA', 'Configuration Management': 'CM', 'Contingency Planning': 'CP',
  'Identification and Authentication': 'IA', 'Incident Response': 'IR', 'Maintenance': 'MA', 'Media Protection': 'MP',
  'Physical and Environmental Protection': 'PE', 'Planning': 'PL', 'Personnel Security': 'PS', 'Risk Assessment': 'RA',
  'System and Services Acquisition': 'SA', 'System and Communications Protection': 'SC',
  'System and Information Integrity': 'SI', 'Program Management': 'PM',
};
const familyCode = (family: string) => FAMILY_CODE_BY_NAME[family] ?? family;

const STATUS_OPTIONS: { value: ImplementationStatus | ''; label: string }[] = [
  { value: '', label: 'All Statuses' },
  { value: 'implemented', label: 'Implemented' },
  { value: 'partially_implemented', label: 'Partial' },
  { value: 'not_implemented', label: 'Not Implemented' },
  { value: 'planned', label: 'Planned' },
  { value: 'not_assessed', label: 'Not Assessed' },
  { value: 'not_applicable', label: 'Not Applicable' },
];

const PRIORITY_OPTIONS: { value: Priority | ''; label: string }[] = [
  { value: '', label: 'All Priorities' },
  { value: 'P1', label: 'P1 - High' },
  { value: 'P2', label: 'P2 - Moderate' },
  { value: 'P3', label: 'P3 - Low' },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function statusColor(status: ImplementationStatus): string {
  switch (status) {
    case 'implemented': return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
    case 'partial':
    case 'partially_implemented':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'planned': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400';
    case 'alternative': return 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400';
    case 'not_applicable': return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
    case 'not_assessed': return 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 border border-dashed border-gray-300';
    case 'not_implemented':
    default:
      return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
  }
}

function statusLabel(status: ImplementationStatus): string {
  switch (status) {
    case 'implemented': return 'Implemented';
    case 'partial':
    case 'partially_implemented':
      return 'Partial';
    case 'planned': return 'Planned';
    case 'alternative': return 'Alternative';
    case 'not_applicable': return 'Not Applicable';
    case 'not_assessed': return 'Not Assessed';
    case 'not_implemented':
    default:
      return 'Not Implemented';
  }
}

function riskColor(level: RiskLevel | string): string {
  switch (level) {
    case 'critical':
    case 'very_high': return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
    case 'high': return 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400';
    case 'moderate':
    case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'low': return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
    default: return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
  }
}

function poamStatusColor(status: string): string {
  switch (status) {
    case 'open': return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
    case 'in_progress': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'completed':
    case 'closed': return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
    case 'delayed': return 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400';
    default: return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
  }
}

function badgeVariant(badge: ReadinessBadge): string {
  switch (badge) {
    case 'Ready': return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 border-green-300 dark:border-green-700';
    case 'In Progress': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400 border-yellow-300 dark:border-yellow-700';
    case 'Not Ready': return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 border-red-300 dark:border-red-700';
    case 'Not Assessed': return 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 border-gray-300 dark:border-gray-600';
  }
}

function scoreGaugeColor(score: number): string {
  if (score >= 80) return '#22c55e';
  if (score >= 50) return '#eab308';
  return '#ef4444';
}

function downloadBlob(data: Blob, filename: string) {
  const url = URL.createObjectURL(data);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── Shared UI Components ────────────────────────────────────────────────────

function LoadingState({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-gray-500 dark:text-gray-400">
      <Loader2 className="w-8 h-8 animate-spin mb-3" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

function EmptyState({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-gray-500 dark:text-gray-400">
      {icon}
      <h3 className="mt-3 text-lg font-medium text-gray-700 dark:text-gray-300">{title}</h3>
      <p className="mt-1 text-sm">{description}</p>
    </div>
  );
}

function ErrorState({ message, error }: { message: string; error?: unknown }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-red-500">
      <AlertCircle className="w-8 h-8 mb-3" />
      <p className="text-sm">{message}</p>
      {error ? <p className="text-xs mt-1">{describeLoadError(error)}</p> : null}
    </div>
  );
}

function ScoreGauge({ score, size = 180 }: { score: number; size?: number }) {
  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = scoreGaugeColor(score);

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="10"
          className="text-gray-200 dark:text-gray-700"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-4xl font-bold text-gray-900 dark:text-white">{score}%</span>
        <span className="text-xs text-gray-500 dark:text-gray-400 mt-1">Readiness</span>
      </div>
    </div>
  );
}

// ─── Tab: Readiness Dashboard ────────────────────────────────────────────────

function ReadinessTab() {
  const { data: rawData, isLoading, error } = useQuery<Row>({
    queryKey: ['fedramp', 'readiness'],
    queryFn: async () => {
      const r = await api.get('/fedramp/readiness');
      return r.data;
    },
    retry: 1,
  });

  const exportSSP = useMutation({
    mutationFn: async () => {
      const res = await api.get('/fedramp/ssp/export');
      return res.data;
    },
    onSuccess: (data) => {
      const json = JSON.stringify(data?.document ?? data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      downloadBlob(blob, data?.filename ?? 'FedRAMP_SSP_Export.json');
    },
  });
  const sspDoc = exportSSP.data?.document ?? null;

  if (isLoading) return <LoadingState message="Calculating readiness..." />;
  if (error) return <ErrorState message="Failed to load readiness data." error={error} />;
  if (!rawData) return <EmptyState icon={<BarChart3 className="w-10 h-10" />} title="No Data" description="No readiness assessment has been performed yet." />;

  // FedRAMPGenerator.generate_readiness_report (snake_case keys).
  const data = rawData;
  const score = Number(data?.overall_readiness_score ?? 0) || 0;
  const totalControls = Number(data?.total_controls ?? 0) || 0;
  const assessmentStatus: string = data?.assessment_status ?? 'not_assessed';

  const familyData = (data?.family_readiness ?? {}) as Record<string, Row>;
  const controlFamilyBreakdown: { family: string; percentImplemented: number; implemented: number; total: number; notAssessed: number }[] =
    Object.entries(familyData).map(([key, val]) => ({
      family: key,
      percentImplemented: Number(val?.readiness_pct ?? 0) || 0,
      implemented: Number(val?.implemented ?? 0) || 0,
      total: Number(val?.total ?? 0) || 0,
      notAssessed: Number(val?.not_assessed ?? 0) || 0,
    }));

  const gapSummary = (data?.status_breakdown ?? {}) as Record<string, number>;
  const gap = {
    implemented: Number(gapSummary.implemented ?? 0) || 0,
    partially_implemented: Number(gapSummary.partially_implemented ?? 0) || 0,
    planned: Number(gapSummary.planned ?? 0) || 0,
    not_implemented: Number(gapSummary.not_implemented ?? 0) || 0,
    not_assessed: Number(gapSummary.not_assessed ?? 0) || 0,
  };
  const gaps: Row[] = Array.isArray(data?.gap_analysis?.gaps) ? data.gap_analysis.gaps : [];

  // Computed from the gaps (recommendations_basis: computed_from_gaps).
  const rawRecs: Row[] = Array.isArray(data?.recommendations) ? data.recommendations : [];
  const recommendations = rawRecs.map((rec, i) => ({
    id: rec?.id ?? `rec-${i}`,
    priority: rec?.priority ?? '',
    title: rec?.title ?? rec?.action ?? 'Recommendation',
    description: rec?.action ?? '',
    controlFamily: rec?.control_family ?? '',
    effort: rec?.effort ?? '',
  }));

  const maxBarWidth = 100;

  return (
    <div className="space-y-6">
      {/* Top row: gauge + gap summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 flex flex-col items-center justify-center">
          <ScoreGauge score={score} />
          <p className="mt-3 text-xs text-center text-gray-500 dark:text-gray-400">
            {assessmentStatus === 'not_assessed'
              ? 'No control has been assessed yet; the score counts not-assessed controls as not implemented.'
              : assessmentStatus === 'partially_assessed'
              ? `${data?.not_assessed_controls ?? 0} control(s) not assessed (counted as not implemented).`
              : 'Every control has an assessed status.'}
          </p>
          <button
            onClick={() => exportSSP.mutate()}
            disabled={exportSSP.isPending}
            className={clsx(
              'mt-4 flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-colors',
              'bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed'
            )}
          >
            {exportSSP.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            Generate SSP
          </button>
          {exportSSP.error && <div className="mt-3 w-full"><ActionErrorBanner what="generate the SSP" error={exportSSP.error} /></div>}
          {sspDoc && (
            <p className="mt-3 text-xs text-gray-600 dark:text-gray-400 text-center">
              Draft built from stored facts: {countPlaceholders(sspDoc)} placeholder(s) to complete
              {Array.isArray(sspDoc.missing_facts) && sspDoc.missing_facts.length > 0 ? ` (missing: ${sspDoc.missing_facts.join(', ')})` : ''}.
            </p>
          )}
        </div>

        <div className="lg:col-span-2 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Gap Summary</h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
            {[
              { label: 'Implemented', count: gap.implemented, color: 'text-green-600 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-900/20' },
              { label: 'Partial', count: gap.partially_implemented, color: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-900/20' },
              { label: 'Planned', count: gap.planned, color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-900/20' },
              { label: 'Not Implemented', count: gap.not_implemented, color: 'text-red-600 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/20' },
              { label: 'Not Assessed', count: gap.not_assessed, color: 'text-gray-600 dark:text-gray-300', bg: 'bg-gray-50 dark:bg-gray-900/40' },
            ].map((item) => (
              <div key={item.label} className={clsx('rounded-lg p-4 text-center', item.bg)}>
                <p className={clsx('text-2xl font-bold', item.color)}>{item.count}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{item.label}</p>
              </div>
            ))}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            Total Controls: <span className="font-semibold text-gray-700 dark:text-gray-300">{totalControls}</span>
            {data?.assessment_basis && <p className="mt-1">{data.assessment_basis}</p>}
          </div>
          {gaps.length > 0 && (
            <details className="mt-4">
              <summary className="cursor-pointer text-xs font-medium text-gray-700 dark:text-gray-300">
                {data?.gap_analysis?.total_gaps ?? gaps.length} gap(s), highest priority first
              </summary>
              <ul className="mt-2 max-h-56 overflow-y-auto text-xs space-y-1">
                {gaps.slice(0, 100).map((g) => (
                  <li key={g.control_id} className="flex gap-2">
                    <span className="font-mono w-16 shrink-0">{g.control_id}</span>
                    <span className="w-8 shrink-0">{g.priority}</span>
                    <span className={clsx('px-1.5 rounded shrink-0', statusColor(g.current_status))}>{statusLabel(g.current_status)}</span>
                    <span className="text-gray-500 truncate" title={g.reason ?? ''}>{g.reason || g.title}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      </div>

      {/* Control family breakdown */}
      {controlFamilyBreakdown.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Control Family Breakdown</h3>
          <div className="space-y-3">
            {controlFamilyBreakdown.map((cf, idx) => (
              <div key={cf.family || idx} className="flex items-center gap-3">
                <span className="w-10 text-xs font-mono font-semibold text-gray-600 dark:text-gray-400">{cf.family}</span>
                <div className="flex-1 bg-gray-100 dark:bg-gray-700 rounded-full h-5 overflow-hidden">
                  <div
                    className={clsx(
                      'h-full rounded-full transition-all duration-500',
                      cf.percentImplemented >= 80 ? 'bg-green-500' : cf.percentImplemented >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                    )}
                    style={{ width: `${Math.min(cf.percentImplemented, maxBarWidth)}%` }}
                  />
                </div>
                <span className="w-14 text-xs text-right font-medium text-gray-600 dark:text-gray-400">
                  {cf.percentImplemented}%
                </span>
                <span className="w-28 text-xs text-right text-gray-400 dark:text-gray-500" title="implemented / total (not assessed)">
                  {cf.implemented}/{cf.total}{cf.notAssessed ? ` (${cf.notAssessed} n/a)` : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">
          Recommendations <span className="font-normal text-xs text-gray-400">(computed from the gaps above)</span>
        </h3>
        {recommendations.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">No recommendations at this time.</p>
        ) : (
          <div className="space-y-3">
            {recommendations.map((rec) => (
              <div
                key={rec.id}
                className="flex items-start gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-900/40 border border-gray-100 dark:border-gray-700"
              >
                <span
                  className={clsx(
                    'shrink-0 mt-0.5 inline-flex items-center justify-center px-2 py-1 rounded text-xs font-bold',
                    rec.priority === 'Critical' || rec.priority === 'P1' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                    rec.priority === 'High' || rec.priority === 'P2' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                    rec.priority === 'Medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                    'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                  )}
                >
                  {rec.priority}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-800 dark:text-gray-200">{rec.title}</p>
                  {rec.description && rec.description !== rec.title && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{rec.description}</p>
                  )}
                  {(rec.controlFamily || rec.effort) && (
                    <div className="flex items-center gap-3 mt-1.5">
                      {rec.controlFamily && (
                        <span className="text-xs text-gray-400 dark:text-gray-500">Family: {rec.controlFamily}</span>
                      )}
                      {rec.effort && (
                        <span className={clsx(
                          'text-xs px-1.5 py-0.5 rounded',
                          rec.effort === 'low' ? 'bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-400' :
                          rec.effort === 'medium' ? 'bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400' :
                          'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400'
                        )}>
                          {rec.effort} effort
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Tab: Controls ───────────────────────────────────────────────────────────

function ControlsTab() {
  const queryClient = useQueryClient();
  const [familyFilter, setFamilyFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState<ImplementationStatus | ''>('');
  const [priorityFilter, setPriorityFilter] = useState<Priority | ''>('');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: controlsRaw, isLoading, error } = useQuery<Row>({
    queryKey: ['fedramp', 'controls'],
    queryFn: async () => (await api.get('/fedramp/controls', { params: { limit: 500 } })).data,
  });
  const controls: Row[] = useMemo(
    () => (Array.isArray(controlsRaw) ? controlsRaw : (controlsRaw?.controls || [])),
    [controlsRaw],
  );

  const updateStatus = useMutation({
    // Backend expects implementation_status (and the optional narrative) as
    // query parameters; the change is recorded as a manual status.
    mutationFn: ({ id, status, narrative }: { id: string; status: ImplementationStatus; narrative?: string }) => {
      const backendStatus = status === 'partial' ? 'partially_implemented' : status;
      return api.post(
        `/fedramp/controls/${id}/update`,
        null,
        { params: { implementation_status: backendStatus, implementation_narrative: narrative || undefined } }
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fedramp', 'controls'] });
      queryClient.invalidateQueries({ queryKey: ['fedramp', 'readiness'] });
    },
  });

  const filtered = useMemo(() => {
    if (!controls) return [];
    return controls.filter((c: Row) => {
      const cFamily = c.family || '';
      const cStatus = c.implementation_status || c.status || '';
      const cPriority = c.priority || '';
      const cId = c.controlId || c.id || '';
      const cTitle = c.title || '';
      // Family filter: backend returns full name like "Access Control", filter uses short code like "AC"
      if (familyFilter && !cId.startsWith(familyFilter + '-') && cFamily !== familyFilter) return false;
      if (statusFilter && cStatus !== statusFilter) return false;
      if (priorityFilter && cPriority !== priorityFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        if (!cId.toLowerCase().includes(term) && !cTitle.toLowerCase().includes(term)) return false;
      }
      return true;
    });
  }, [controls, familyFilter, statusFilter, priorityFilter, searchTerm]);

  if (isLoading) return <LoadingState message="Loading controls..." />;
  if (error) return <ErrorState message="Failed to load controls." error={error} />;

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by control ID or title..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        <select
          value={familyFilter}
          onChange={(e) => setFamilyFilter(e.target.value)}
          className="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"
        >
          <option value="">All Families</option>
          {CONTROL_FAMILIES.map((f) => (
            <option key={f} value={f}>{f}</option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as ImplementationStatus | '')}
          className="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"
        >
          {STATUS_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <select
          value={priorityFilter}
          onChange={(e) => setPriorityFilter(e.target.value as Priority | '')}
          className="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"
        >
          {PRIORITY_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <div className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400">
          <Filter className="w-3.5 h-3.5" />
          {filtered.length} of {controls?.length ?? 0}
        </div>
      </div>

      {updateStatus.error && <ActionErrorBanner what="update the control status" error={updateStatus.error} />}

      {/* Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 dark:bg-gray-900/50 text-left">
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400 w-8" />
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Control ID</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Family</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Title</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Priority</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Status</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">PySOAR Mapping</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400 w-10" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-gray-400 dark:text-gray-500">
                    No controls match the current filters.
                  </td>
                </tr>
              ) : (
                filtered.map((control) => {
                  const isExpanded = expandedId === control.id;
                  return (
                    <ControlRow
                      key={control.id}
                      control={control as FedRAMPControl & Row}
                      isExpanded={isExpanded}
                      onToggle={() => setExpandedId(isExpanded ? null : control.id)}
                      onUpdateStatus={(status, narrative) => updateStatus.mutate({ id: control.id, status, narrative })}
                      isUpdating={updateStatus.isPending}
                    />
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function ControlRow({
  control,
  isExpanded,
  onToggle,
  onUpdateStatus,
  isUpdating,
}: {
  control: FedRAMPControl & Row;
  isExpanded: boolean;
  onToggle: () => void;
  onUpdateStatus: (status: ImplementationStatus, narrative?: string) => void;
  isUpdating: boolean;
}) {
  const [pendingStatus, setPendingStatus] = useState<ImplementationStatus | ''>('');
  const [narrative, setNarrative] = useState('');
  const basis = control.assessment_basis as Row | null | undefined;

  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors"
      >
        <td className="px-4 py-3 text-gray-400">
          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </td>
        <td className="px-4 py-3 font-mono font-medium text-gray-900 dark:text-gray-100">{control.controlId || control.id}</td>
        <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{control.family}</td>
        <td className="px-4 py-3 text-gray-800 dark:text-gray-200 max-w-xs truncate">{control.title || 'Untitled'}</td>
        <td className="px-4 py-3">
          <span
            className={clsx(
              'inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold',
              control.priority === 'P1' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
              control.priority === 'P2' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
              'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
            )}
          >
            {control.priority}
          </span>
        </td>
        <td className="px-4 py-3">
          <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', statusColor(control.implementation_status || control.status))}>
            {statusLabel(control.implementation_status || control.status)}
          </span>
          {control.status_source && (
            <div className="text-[10px] text-gray-400 mt-0.5">{control.status_source === 'manual' ? 'set manually' : control.status_source}</div>
          )}
        </td>
        <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-xs">
          {control.pysoar_mapping || <span className="text-gray-300 dark:text-gray-600">--</span>}
        </td>
        <td className="px-4 py-3">
          <Info className="w-4 h-4 text-gray-400" />
        </td>
      </tr>
      {isExpanded && (
        <tr className="bg-gray-50 dark:bg-gray-900/30">
          <td colSpan={8} className="px-6 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <h4 className="font-semibold text-gray-700 dark:text-gray-300 mb-1">Description</h4>
                <p className="text-gray-600 dark:text-gray-400 text-xs leading-relaxed">
                  {control.description || 'No description available.'}
                </p>
              </div>
              <div>
                <h4 className="font-semibold text-gray-700 dark:text-gray-300 mb-1">Implementation Guidance</h4>
                <p className="text-gray-600 dark:text-gray-400 text-xs leading-relaxed">
                  {control.guidance || 'No guidance available.'}
                </p>
              </div>
              <div className="md:col-span-2">
                <h4 className="font-semibold text-gray-700 dark:text-gray-300 mb-1">Assessment Basis</h4>
                {!basis ? (
                  <p className="text-xs text-gray-500">
                    {control.implementation_status === 'not_assessed'
                      ? 'Not assessed: no control record has been evaluated by the attester or set by a person.'
                      : 'No attester result stored for this control.'}
                  </p>
                ) : (
                  <div className="text-xs text-gray-600 dark:text-gray-400 space-y-0.5">
                    <p>Result: {String(basis.result ?? 'not_assessed').replace(/_/g, ' ')}{basis.checked_at ? ` · ${new Date(basis.checked_at).toLocaleString()}` : ''}</p>
                    {basis.summary && <p>{basis.summary}</p>}
                    {basis.reason && <p className="text-orange-700 dark:text-orange-300">Reason: {basis.reason}</p>}
                  </div>
                )}
                <p className="text-xs text-gray-500 mt-1">
                  Framework: {control.framework ?? 'not tracked'} · Responsible party: {control.responsible_party || '—'} · Last result: {control.last_assessment_result || '—'}
                </p>
              </div>
              {control.responsible_role && (
                <div>
                  <h4 className="font-semibold text-gray-700 dark:text-gray-300 mb-1">Responsible Role</h4>
                  <p className="text-gray-600 dark:text-gray-400 text-xs">{control.responsible_role}</p>
                </div>
              )}
              {Array.isArray(control.evidence_required) && control.evidence_required.length > 0 && (
                <div>
                  <h4 className="font-semibold text-gray-700 dark:text-gray-300 mb-1">Required Evidence</h4>
                  <ul className="list-disc list-inside text-xs text-gray-600 dark:text-gray-400 space-y-0.5">
                    {(control.evidence_required as string[]).map((ev: string, i: number) => (
                      <li key={i}>{ev}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="md:col-span-2 flex items-center gap-3 pt-2 border-t border-gray-200 dark:border-gray-700">
                <label className="text-xs font-medium text-gray-600 dark:text-gray-400">Update Status:</label>
                <select
                  value={pendingStatus}
                  onClick={(e) => e.stopPropagation()}
                  onChange={(e) => setPendingStatus(e.target.value as ImplementationStatus)}
                  className="text-xs border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                >
                  <option value="">Select...</option>
                  {/* Values must match backend FedRAMPGenerator.IMPLEMENTATION_STATUSES.
                      'partial' is locally remapped to 'partially_implemented' inside
                      the updateStatus mutation. */}
                  <option value="implemented">Implemented</option>
                  <option value="partial">Partial</option>
                  <option value="planned">Planned</option>
                  <option value="not_implemented">Not Implemented</option>
                  <option value="alternative">Alternative</option>
                  <option value="not_applicable">Not Applicable</option>
                </select>
                <input
                  value={narrative}
                  onClick={(e) => e.stopPropagation()}
                  onChange={(e) => setNarrative(e.target.value)}
                  placeholder="Implementation narrative (optional)"
                  className="flex-1 text-xs border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                />
                <button
                  disabled={!pendingStatus || isUpdating}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (pendingStatus) onUpdateStatus(pendingStatus as ImplementationStatus, narrative);
                  }}
                  className={clsx(
                    'px-3 py-1 text-xs rounded font-medium transition-colors',
                    'bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed'
                  )}
                >
                  {isUpdating ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Update Status'}
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Tab: POA&M Report ───────────────────────────────────────────────────────

function POAMTab() {
  const { data, isLoading, error } = useQuery<POAMReport>({
    queryKey: ['fedramp', 'poam', 'report'],
    queryFn: async () => (await api.get('/fedramp/poam/report')).data,
  });

  const exportPOAM = useMutation({
    mutationFn: async () => {
      const res = await api.get('/fedramp/poam/report');
      return res.data;
    },
    onSuccess: (data) => {
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      downloadBlob(blob, 'FedRAMP_POAM_Report.json');
    },
  });

  if (isLoading) return <LoadingState message="Loading POA&M report..." />;
  if (error) return <ErrorState message="Failed to load POA&M report." error={error} />;
  if (!data) return <EmptyState icon={<ClipboardList className="w-10 h-10" />} title="No POA&Ms" description="No plan of action and milestones items found." />;

  const items: Row[] = Array.isArray(data?.items) ? data.items : [];
  const statusCounts = data?.summary?.status_breakdown ?? {};
  const summary = {
    total: data?.summary?.total_items ?? 0,
    open: statusCounts.open ?? 0,
    inProgress: statusCounts.in_progress ?? 0,
    closed: (statusCounts.completed ?? 0) + (statusCounts.closed ?? 0),
    delayed: statusCounts.delayed ?? 0,
    overdue: data?.summary?.overdue_items ?? 0,
  };
  // timeline: [{month: YYYY-MM, due, completed, open}] by scheduled completion month.
  const timelineData = Array.isArray(data?.timeline) ? data.timeline : [];
  const maxTimelineValue = timelineData.length > 0 ? Math.max(...timelineData.flatMap((t) => [t.open ?? 0, t.completed ?? 0, t.due ?? 0]), 1) : 1;

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: 'Total', value: summary.total, color: 'text-gray-700 dark:text-gray-300' },
          { label: 'Open', value: summary.open, color: 'text-red-600 dark:text-red-400' },
          { label: 'In Progress', value: summary.inProgress, color: 'text-yellow-600 dark:text-yellow-400' },
          { label: 'Closed', value: summary.closed, color: 'text-green-600 dark:text-green-400' },
          { label: 'Delayed', value: summary.delayed, color: 'text-orange-600 dark:text-orange-400' },
          { label: 'Overdue', value: summary.overdue, color: 'text-red-700 dark:text-red-500' },
        ].map((s) => (
          <div key={s.label} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 text-center">
            <p className={clsx('text-2xl font-bold', s.color)}>{s.value}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Timeline chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">POA&M Timeline</h3>
          <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-500" /> Due</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-green-500" /> Completed</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500" /> Still open</span>
          </div>
        </div>
        {timelineData.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-10">No POA&M item has a scheduled completion date.</p>
        ) : (
        <div className="flex items-end gap-2 h-40">
          {timelineData.map((t, i) => (
            <div key={i} className="flex-1 flex flex-col items-center gap-1">
              <div className="flex items-end gap-0.5 w-full h-32">
                <div
                  className="flex-1 bg-blue-500 rounded-t transition-all"
                  style={{ height: `${(t.due / maxTimelineValue) * 100}%` }}
                  title={`Due: ${t.due}`}
                />
                <div
                  className="flex-1 bg-green-500 rounded-t transition-all"
                  style={{ height: `${(t.completed / maxTimelineValue) * 100}%` }}
                  title={`Completed: ${t.completed}`}
                />
                <div
                  className="flex-1 bg-red-500 rounded-t transition-all"
                  style={{ height: `${(t.open / maxTimelineValue) * 100}%` }}
                  title={`Open: ${t.open}`}
                />
              </div>
              <span className="text-[10px] text-gray-400 dark:text-gray-500 truncate w-full text-center">{t.month}</span>
            </div>
          ))}
        </div>
        )}
      </div>

      {/* POA&M Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Open POA&M Items</h3>
          <button
            onClick={() => exportPOAM.mutate()}
            disabled={exportPOAM.isPending}
            className={clsx(
              'flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-medium transition-colors',
              'bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed'
            )}
          >
            {exportPOAM.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />}
            Export POA&M
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 dark:bg-gray-900/50 text-left">
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">POA&M ID</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Control</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Weakness</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Risk</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Status</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Assigned To</th>
                <th className="px-4 py-3 font-semibold text-gray-600 dark:text-gray-400">Due Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
              {items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-gray-400 dark:text-gray-500">
                    No POA&M items found.
                  </td>
                </tr>
              ) : (
                items.map((item: Row, idx: number) => {
                  const rawDue = item.scheduled_completion_date;
                  const dueDate = rawDue && rawDue !== 'None' ? String(rawDue) : '';
                  const itemStatus = item.status ?? 'open';
                  const isOverdue = dueDate && new Date(dueDate) < new Date() && !['completed', 'closed', 'cancelled', 'accepted'].includes(itemStatus);
                  const riskLvl = item.severity || 'unrated';
                  return (
                    <tr key={item.poam_id ?? idx} className="hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors">
                      <td className="px-4 py-3 font-mono text-xs font-medium text-gray-900 dark:text-gray-100">{item.poam_id ?? '-'}</td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-600 dark:text-gray-400">{item.control_id || '-'}</td>
                      <td className="px-4 py-3 text-gray-800 dark:text-gray-200 max-w-xs truncate">{item.weakness_description || '-'}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize', riskColor(riskLvl))}>
                          {riskLvl}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', poamStatusColor(itemStatus))}>
                          {String(itemStatus).replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-600 dark:text-gray-400">{item.responsible_party || '-'}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('text-xs', isOverdue ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-gray-600 dark:text-gray-400')}>
                          {dueDate || '-'}
                          {isOverdue && <AlertTriangle className="w-3 h-3 inline ml-1" />}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Tab: Evidence ───────────────────────────────────────────────────────────

function EvidenceTab() {
  const queryClient = useQueryClient();
  const { data, isLoading, error } = useQuery<EvidenceStatus>({
    queryKey: ['fedramp', 'evidence', 'status'],
    queryFn: async () => (await api.get('/fedramp/evidence/status')).data,
  });

  const collectEvidence = useMutation({
    mutationFn: async (family: string) => {
      // Trigger all enabled automated evidence collection rules.
      // The backend routes by rule config; we pass the family tag as metadata
      // so logs/audit events record which family triggered the run.
      const res = await api.post('/audit-evidence/evidence/collect-all', { family });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fedramp', 'evidence', 'status'] });
    },
  });
  const collectResult = collectEvidence.data as Row | undefined;

  if (isLoading) return <LoadingState message="Loading evidence status..." />;
  if (error) return <ErrorState message="Failed to load evidence status." error={error} />;
  if (!data) return <EmptyState icon={<FolderOpen className="w-10 h-10" />} title="No Evidence Data" description="Evidence collection has not been configured." />;

  const rawFamilies: Row[] = Array.isArray(data?.families) ? data.families : [];
  // Per family: controls with at least one evidence artifact attached.
  const families = rawFamilies.map((f) => ({
    family: f.family || '',
    label: f.family || '',
    totalRequired: Number(f.total_controls ?? 0),
    collected: Number(f.controls_with_evidence ?? 0),
    controls: ((f.evidence_artifacts || []) as Row[]).map((a) => ({
      id: a.id || '',
      controlId: a.title || a.id || '',
      hasEvidence: true,
      reviewStatus: a.review_status as string | undefined,
    })),
  }));
  const overallCollected = Number(data?.controls_with_evidence ?? 0) || 0;
  const overallRequired = Number(data?.total_controls ?? 0) || 0;
  const overallPercent = overallRequired > 0 ? Math.round((overallCollected / overallRequired) * 100) : 0;

  return (
    <div className="space-y-6">
      {collectEvidence.error && <ActionErrorBanner what="collect evidence" error={collectEvidence.error} />}
      {collectResult && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3">
          Evidence collection {String(collectResult.status ?? '').replace(/_/g, ' ')}
          {collectResult.family ? ` for ${collectResult.family}` : ''}: {collectResult.rules_run ?? 0} rule(s) run, {collectResult.collected ?? 0} collected,{' '}
          {collectResult.evidence_written ?? 0} evidence row(s) written, {collectResult.awaiting_integration ?? 0} awaiting an integration,{' '}
          {collectResult.no_matching_controls ?? 0} without matching controls, {collectResult.failed ?? 0} failed.
          {collectResult.reason ? ` ${collectResult.reason}` : ''}
        </div>
      )}
      {/* Overall progress */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Overall Evidence Collection</h3>
          <span className="text-sm font-medium text-gray-600 dark:text-gray-400">
            {overallCollected} / {overallRequired} items ({overallPercent}%)
          </span>
        </div>
        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden">
          <div
            className={clsx(
              'h-full rounded-full transition-all duration-500',
              overallPercent >= 80 ? 'bg-green-500' : overallPercent >= 50 ? 'bg-yellow-500' : 'bg-red-500'
            )}
            style={{ width: `${overallPercent}%` }}
          />
        </div>
      </div>

      {/* Family cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {families.map((fam) => {
          const percent = fam.totalRequired > 0 ? Math.round((fam.collected / fam.totalRequired) * 100) : 0;
          const isCollecting = collectEvidence.isPending && collectEvidence.variables === familyCode(fam.family);

          return (
            <div
              key={fam.family}
              className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-5"
            >
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h4 className="text-sm font-bold text-gray-800 dark:text-gray-200">{fam.family}</h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400">{fam.label}</p>
                </div>
                <span
                  className={clsx(
                    'text-lg font-bold',
                    percent >= 80 ? 'text-green-600 dark:text-green-400' :
                    percent >= 50 ? 'text-yellow-600 dark:text-yellow-400' :
                    'text-red-600 dark:text-red-400'
                  )}
                >
                  {percent}%
                </span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 overflow-hidden mb-2">
                <div
                  className={clsx(
                    'h-full rounded-full transition-all duration-500',
                    percent >= 80 ? 'bg-green-500' : percent >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                  )}
                  style={{ width: `${percent}%` }}
                />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-400 dark:text-gray-500">
                  {fam.collected} / {fam.totalRequired} collected
                </span>
                <button
                  onClick={() => collectEvidence.mutate(familyCode(fam.family))}
                  disabled={isCollecting}
                  className={clsx(
                    'flex items-center gap-1 px-2.5 py-1 text-xs rounded font-medium transition-colors',
                    'bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed'
                  )}
                >
                  {isCollecting ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                  Collect Evidence
                </button>
              </div>

              {/* Control-level detail */}
              {fam.controls.length > 0 && (
                <div className="mt-3 pt-3 border-t border-gray-100 dark:border-gray-700 space-y-1.5 max-h-32 overflow-y-auto">
                  {fam.controls.map((ctrl, idx: number) => (
                    <div key={ctrl.id || idx} className="flex items-center justify-between text-xs gap-2">
                      <span className="text-gray-600 dark:text-gray-400 truncate">{ctrl.controlId || '-'}</span>
                      <span className="flex items-center gap-1 text-green-600 dark:text-green-400 shrink-0">
                        <CheckCircle2 className="w-3 h-3" /> {ctrl.reviewStatus ? ctrl.reviewStatus.replace(/_/g, ' ') : 'attached'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Tab: Documents ──────────────────────────────────────────────────────────

const FEDRAMP_DOCUMENTS: { type: string; name: string; description: string; endpoint: string }[] = [
  {
    type: 'ssp',
    name: 'System Security Plan (SSP)',
    description: 'Comprehensive document describing the security controls, system boundaries, and authorization scope for FedRAMP Moderate.',
    endpoint: '/fedramp/ssp/generate',
  },
  {
    type: 'irp',
    name: 'Incident Response Plan',
    description: 'Defines incident detection, reporting, handling, and recovery procedures aligned with FedRAMP IR controls.',
    endpoint: '/fedramp/irp/generate',
  },
  {
    type: 'cmp',
    name: 'Configuration Management Plan',
    description: 'Establishes policies and procedures for managing configuration baselines and changes for the system.',
    endpoint: '/fedramp/cmp/generate',
  },
  {
    type: 'conmon',
    name: 'Continuous Monitoring Plan',
    description: 'Describes continuous monitoring strategy including vulnerability scanning, log review, and ongoing authorization activities.',
    endpoint: '/fedramp/conmon-plan/generate',
  },
];

function DocumentsTab() {
  const [generatedDocs, setGeneratedDocs] = useState<Record<string, Row>>({});

  const generateDoc = useMutation({
    mutationFn: async ({ endpoint, docType }: { endpoint: string; docType: string }) => {
      const res = await api.get(endpoint);
      return { data: res.data, docType };
    },
    onSuccess: ({ data, docType }) => {
      setGeneratedDocs(prev => ({ ...prev, [docType]: data }));
      // Auto-download
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      downloadBlob(blob, `FedRAMP_${docType}.json`);
    },
  });

  const downloadDoc = useMutation({
    mutationFn: async ({ endpoint, docType }: { endpoint: string; docType: string }) => {
      // If already generated, use cached version
      if (generatedDocs[docType]) {
        return { data: generatedDocs[docType], docType };
      }
      const res = await api.get(endpoint);
      return { data: res.data, docType };
    },
    onSuccess: ({ data, docType }) => {
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      downloadBlob(blob, `FedRAMP_${docType}.json`);
    },
  });

  return (
    <div className="space-y-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-500 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-gray-700 dark:text-gray-300 font-medium">FedRAMP Document Package</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              Generate FedRAMP Moderate drafts from the facts stored for this organisation (organisation, components, integrations,
              policies, control records, playbooks, scans). Every fact that is not recorded is left as an explicit
              &quot;{PLACEHOLDER_PREFIX}: ...]&quot; placeholder; the drafts are not submission-ready until those are completed.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {FEDRAMP_DOCUMENTS.map((doc) => {
          const isGenerating = generateDoc.isPending && generateDoc.variables?.docType === doc.type;
          const isDownloading = downloadDoc.isPending && downloadDoc.variables?.docType === doc.type;
          const generated = generatedDocs[doc.type];
          const failed = (generateDoc.error && generateDoc.variables?.docType === doc.type) ? generateDoc.error
            : (downloadDoc.error && downloadDoc.variables?.docType === doc.type) ? downloadDoc.error : null;

          return (
            <div
              key={doc.type}
              className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-5"
            >
              <div className="flex items-start gap-3">
                <FileText className="w-8 h-8 text-blue-500 dark:text-blue-400 shrink-0" />
                <div className="flex-1 min-w-0">
                  <h4 className="text-sm font-semibold text-gray-800 dark:text-gray-200">{doc.name}</h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 leading-relaxed">{doc.description}</p>
                  <div className="flex items-center gap-2 mt-4">
                    <button
                      onClick={() => generateDoc.mutate({ endpoint: doc.endpoint, docType: doc.type })}
                      disabled={isGenerating}
                      className={clsx(
                        'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
                        'bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed'
                      )}
                    >
                      {isGenerating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                      Generate
                    </button>
                    <button
                      onClick={() => downloadDoc.mutate({ endpoint: doc.endpoint, docType: doc.type })}
                      disabled={isDownloading}
                      className={clsx(
                        'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
                        'bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed'
                      )}
                    >
                      {isDownloading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                      Download
                    </button>
                  </div>
                  {failed && <div className="mt-2"><ActionErrorBanner what={`generate the ${doc.name}`} error={failed} /></div>}
                  {generated && (
                    <div className="mt-3 text-xs text-gray-600 dark:text-gray-400 space-y-1">
                      <p>{countPlaceholders(generated)} placeholder(s) left to complete.</p>
                      {Array.isArray(generated.missing_facts) && generated.missing_facts.length > 0 && (
                        <ul className="list-disc ml-4">
                          {generated.missing_facts.map((m: unknown, i: number) => (
                            <li key={i}>{typeof m === 'string' ? m : JSON.stringify(m)}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function FedRAMP() {
  const [activeTab, setActiveTab] = useState<TabType>('readiness');

  const { data: readinessData, error: readinessError } = useQuery<Row>({
    queryKey: ['fedramp', 'readiness'],
    queryFn: async () => (await api.get('/fedramp/readiness')).data,
    staleTime: 60_000,
  });

  // Derive badge from score since backend doesn't return a badge field
  // A failed or empty readiness load has no score; it must not be shown as "Not Ready".
  const rawReadinessScore = readinessData?.overall_readiness_score ?? readinessData?.score;
  const readinessScore =
    rawReadinessScore == null || !Number.isFinite(Number(rawReadinessScore)) ? null : Number(rawReadinessScore);
  const badge: ReadinessBadge | null =
    readinessScore == null
      ? null
      : readinessData?.assessment_status === 'not_assessed'
      ? 'Not Assessed'
      : readinessScore >= 80 ? 'Ready' : readinessScore >= 40 ? 'In Progress' : 'Not Ready';
  const generatedAt = readinessData?.generated_at ?? readinessData?.lastAssessmentDate;
  const lastAssessment = generatedAt
    ? new Date(generatedAt).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      })
    : readinessData
      ? 'Never'
      : 'not available';

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
              <Shield className="w-7 h-7 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">FedRAMP Compliance</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">FedRAMP Moderate Authorization Tracking</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-xs text-gray-500 dark:text-gray-400">Readiness computed</p>
              <p className="text-sm font-medium text-gray-700 dark:text-gray-300">{lastAssessment}</p>
            </div>
            {badge ? (
              <span
                className={clsx(
                  'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border',
                  badgeVariant(badge)
                )}
              >
                {badge === 'Ready' && <CheckCircle2 className="w-3.5 h-3.5" />}
                {badge === 'In Progress' && <Clock className="w-3.5 h-3.5" />}
                {badge === 'Not Ready' && <ShieldAlert className="w-3.5 h-3.5" />}
                {badge}
              </span>
            ) : (
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border border-gray-300 text-gray-500 dark:border-gray-600 dark:text-gray-400"
                title={readinessError ? describeLoadError(readinessError) : undefined}
              >
                Readiness not available
              </span>
            )}
          </div>
        </div>

        {/* Tab bar */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <nav className="flex overflow-x-auto" role="tablist">
            {TABS.map((tab) => (
              <button
                key={tab.key}
                role="tab"
                aria-selected={activeTab === tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={clsx(
                  'flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-colors',
                  activeTab === tab.key
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400 dark:border-blue-400'
                    : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                )}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab content */}
        <div>
          {activeTab === 'readiness' && <ReadinessTab />}
          {activeTab === 'controls' && <ControlsTab />}
          {activeTab === 'poam' && <POAMTab />}
          {activeTab === 'evidence' && <EvidenceTab />}
          {activeTab === 'documents' && <DocumentsTab />}
        </div>
      </div>
    </div>
  );
}
