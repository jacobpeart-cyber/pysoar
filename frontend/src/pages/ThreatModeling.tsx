import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Plus,
  X,
  Eye,
  Trash2,
  ArrowLeft,
  Zap,
  AlertTriangle,
  ChevronDown,
} from 'lucide-react';
import { api } from '../lib/api';

// --- Types ---

interface ThreatModel {
  id: string;
  name: string;
  application_name: string;
  description: string | null;
  methodology: string;
  status: string;
  risk_score: number | null;
  created_at: string;
  updated_at: string;
}

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

interface Component {
  id: string;
  name: string;
  component_type: string;
  description: string | null;
  trust_level: string | null;
  position: any;
  connections: any;
}

interface Threat {
  id: string;
  title: string;
  description: string | null;
  stride_category: string;
  severity: string | null;
  likelihood: string | null;
  impact: string | null;
  risk_score: number | null;
  status: string;
  mitre_attack_ids: any;
  cwe_ids: any;
}

interface Mitigation {
  id: string;
  title: string;
  description: string | null;
  mitigation_type: string | null;
  implementation_status: string;
  control_reference: any;
  effectiveness: number | null;
}

interface Dashboard {
  total_threats: number;
  mitigated_threats: number;
  open_threats: number;
  risk_distribution: any;
  methodology: string;
  status: string;
}

// --- Constants ---

const METHODOLOGIES = [
  { value: 'stride', label: 'STRIDE' },
  { value: 'pasta', label: 'PASTA' },
  { value: 'attack_tree', label: 'Attack Tree' },
  { value: 'linddun', label: 'LINDDUN' },
  { value: 'vast', label: 'VAST' },
  { value: 'octave', label: 'OCTAVE' },
  { value: 'custom', label: 'Custom' },
];

const MODEL_STATUSES: Record<string, string> = {
  draft: 'bg-gray-700 text-gray-300',
  in_review: 'bg-blue-900/40 text-blue-300',
  approved: 'bg-green-900/40 text-green-300',
  outdated: 'bg-yellow-900/40 text-yellow-300',
  archived: 'bg-gray-900/40 text-gray-400',
};

const STRIDE_CATEGORIES = [
  { value: 'spoofing', label: 'Spoofing' },
  { value: 'tampering', label: 'Tampering' },
  { value: 'repudiation', label: 'Repudiation' },
  { value: 'information_disclosure', label: 'Information Disclosure' },
  { value: 'denial_of_service', label: 'Denial of Service' },
  { value: 'elevation_of_privilege', label: 'Elevation of Privilege' },
];

const THREAT_STATUSES: Record<string, string> = {
  identified: 'bg-red-900/40 text-red-300',
  analyzed: 'bg-blue-900/40 text-blue-300',
  mitigated: 'bg-green-900/40 text-green-300',
  accepted: 'bg-yellow-900/40 text-yellow-300',
  transferred: 'bg-purple-900/40 text-purple-300',
};

const IMPL_STATUSES: Record<string, string> = {
  planned: 'bg-gray-700 text-gray-300',
  in_progress: 'bg-blue-900/40 text-blue-300',
  implemented: 'bg-green-900/40 text-green-300',
  verified: 'bg-emerald-900/40 text-emerald-300',
  not_applicable: 'bg-gray-900/40 text-gray-400',
};

const SEVERITY_OPTIONS = ['low', 'medium', 'high', 'critical'];
const LIKELIHOOD_OPTIONS = ['very_low', 'low', 'medium', 'high', 'very_high'];
const IMPACT_OPTIONS = ['negligible', 'low', 'medium', 'high', 'critical'];

// --- Helpers ---

function riskColor(score: number | null | undefined): string {
  if (score == null) return 'text-gray-400';
  if (score <= 8) return 'text-green-400';
  if (score <= 16) return 'text-yellow-400';
  return 'text-red-400';
}

function riskBg(score: number | null | undefined): string {
  if (score == null) return 'bg-gray-700';
  if (score <= 8) return 'bg-green-900/40';
  if (score <= 16) return 'bg-yellow-900/40';
  return 'bg-red-900/40';
}

function formatDate(d: string | null | undefined): string {
  if (!d) return '-';
  return new Date(d || "").toLocaleDateString();
}

function capitalize(s: string | null | undefined): string {
  if (!s) return '-';
  return s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// --- Component ---

export default function ThreatModeling() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'list' | 'detail'>('list');
  const [selectedModelId, setSelectedModelId] = useState<string | null>(null);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [showCreateModel, setShowCreateModel] = useState(false);
  const [showAddThreat, setShowAddThreat] = useState(false);
  const [page, setPage] = useState(1);
  const pageSize = 20;

  // --- Create Model form state ---
  const [modelForm, setModelForm] = useState({
    name: '',
    application_name: '',
    methodology: 'stride',
    description: '',
  });

  // --- Add Threat form state ---
  const [threatForm, setThreatForm] = useState({
    title: '',
    description: '',
    stride_category: 'spoofing',
    severity: 'medium',
    likelihood: 'medium',
    impact: 'medium',
  });

  // ====== Queries ======

  const modelsQuery = useQuery({
    queryKey: ['threat-models', page],
    queryFn: async () => {
      const res = await api.get<PaginatedResponse<ThreatModel>>('/threat-modeling', {
        params: { page, size: pageSize },
      });
      return res.data;
    },
  });

  const dashboardQuery = useQuery({
    queryKey: ['threat-model-dashboard', selectedModelId],
    queryFn: async () => {
      const res = await api.get<Dashboard>(`/threat-modeling/${selectedModelId}/dashboard`);
      return res.data;
    },
    enabled: !!selectedModelId,
  });

  const componentsQuery = useQuery({
    queryKey: ['threat-model-components', selectedModelId],
    queryFn: async () => {
      const res = await api.get<Component[]>(`/threat-modeling/${selectedModelId}/components`);
      return res.data;
    },
    enabled: !!selectedModelId,
  });

  const threatsQuery = useQuery({
    queryKey: ['threat-model-threats', selectedModelId],
    queryFn: async () => {
      const res = await api.get<PaginatedResponse<Threat>>(
        `/threat-modeling/${selectedModelId}/threats`,
        { params: { page: 1, size: 100 } }
      );
      return res.data;
    },
    enabled: !!selectedModelId,
  });

  const mitigationsQuery = useQuery({
    queryKey: ['threat-mitigations', selectedModelId, selectedThreatId],
    queryFn: async () => {
      const res = await api.get<Mitigation[]>(
        `/threat-modeling/${selectedModelId}/threats/${selectedThreatId}/mitigations`
      );
      return res.data;
    },
    enabled: !!selectedModelId && !!selectedThreatId,
  });

  // ====== Mutations ======

  const createModelMutation = useMutation({
    mutationFn: async (data: typeof modelForm) => {
      const res = await api.post('/threat-modeling', data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] });
      setShowCreateModel(false);
      setModelForm({ name: '', application_name: '', methodology: 'stride', description: '' });
    },
  });

  const deleteModelMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/threat-modeling/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] });
      if (selectedModelId) {
        setSelectedModelId(null);
        setActiveTab('list');
      }
    },
  });

  const addThreatMutation = useMutation({
    mutationFn: async (data: typeof threatForm) => {
      const res = await api.post(`/threat-modeling/${selectedModelId}/threats`, {
        ...data,
        model_id: selectedModelId,
        threat_description: data.description || data.title,
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats', selectedModelId] });
      queryClient.invalidateQueries({ queryKey: ['threat-model-dashboard', selectedModelId] });
      setShowAddThreat(false);
      setThreatForm({
        title: '',
        description: '',
        stride_category: 'spoofing',
        severity: 'medium',
        likelihood: 'medium',
        impact: 'medium',
      });
    },
  });

  const runStrideMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post(`/threat-modeling/${selectedModelId}/analyze/stride`);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats', selectedModelId] });
      queryClient.invalidateQueries({ queryKey: ['threat-model-dashboard', selectedModelId] });
    },
  });

  // ====== Handlers ======

  function openModel(id: string) {
    setSelectedModelId(id);
    setSelectedThreatId(null);
    setActiveTab('detail');
  }

  // ====== Derived data ======

  const models = modelsQuery.data?.items ?? [];
  const totalModels = modelsQuery.data?.total ?? 0;
  const totalPages = Math.ceil(totalModels / pageSize);

  const components = componentsQuery.data ?? [];
  const threats = threatsQuery.data?.items ?? [];
  const mitigations = mitigationsQuery.data ?? [];
  const dashboard = dashboardQuery.data;

  // ====== Render ======

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-1 flex items-center gap-3">
            <Shield className="w-8 h-8 text-red-400" />
            Threat Modeling
          </h1>
          <p className="text-gray-400 text-sm">
            STRIDE Analysis, Components, Threats &amp; Mitigations
          </p>
        </div>

        {/* Tab bar */}
        <div className="mb-6 border-b border-gray-700 flex gap-6">
          <button
            onClick={() => { setActiveTab('list'); setSelectedModelId(null); setSelectedThreatId(null); }}
            className={`pb-3 px-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'list'
                ? 'border-red-400 text-red-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            Models List
          </button>
          <button
            onClick={() => {
              if (!selectedModelId && models.length > 0) {
                openModel(models[0].id);
              } else if (selectedModelId) {
                setActiveTab('detail');
              }
            }}
            className={`pb-3 px-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'detail'
                ? 'border-red-400 text-red-400'
                : 'border-transparent text-gray-400 hover:text-white'
            } ${!selectedModelId && models.length === 0 ? 'opacity-40 cursor-not-allowed' : ''}`}
          >
            Model Detail
          </button>
        </div>

        {/* ==================== MODELS LIST TAB ==================== */}
        {activeTab === 'list' && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <p className="text-gray-400 text-sm">{totalModels} model(s)</p>
              <button
                onClick={() => setShowCreateModel(true)}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded flex items-center gap-2 text-sm transition-colors"
              >
                <Plus className="w-4 h-4" /> New Model
              </button>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-700/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Name</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Application</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Methodology</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Risk Score</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Created</th>
                    <th className="px-4 py-3 text-right text-xs font-semibold text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {models.map((m) => (
                    <tr key={m.id} className="border-t border-gray-700 hover:bg-gray-700/30 cursor-pointer" onClick={() => openModel(m.id)}>
                      <td className="px-4 py-3 text-sm font-medium text-white">{m.name ?? '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-300">{m.application_name ?? '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-300">{capitalize(m.methodology)}</td>
                      <td className="px-4 py-3 text-sm">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${MODEL_STATUSES[m.status] ?? 'bg-gray-700 text-gray-300'}`}>
                          {capitalize(m.status)}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm">
                        <span className={`font-bold ${riskColor(m.risk_score)}`}>
                          {m.risk_score ?? '-'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400">{formatDate(m.created_at)}</td>
                      <td className="px-4 py-3 text-sm text-right">
                        <button
                          onClick={() => openModel(m.id)}
                          className="text-blue-400 hover:text-blue-300 mr-3"
                          title="View"
                        >
                          <Eye className="w-4 h-4 inline" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (confirm('Delete this model?')) deleteModelMutation.mutate(m.id);
                          }}
                          className="text-red-400 hover:text-red-300"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4 inline" />
                        </button>
                      </td>
                    </tr>
                  ))}
                  {models.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-gray-500 text-sm">
                        {modelsQuery.isLoading ? 'Loading...' : 'No threat models found.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex justify-center items-center gap-2 mt-4">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                  className="px-3 py-1 text-sm bg-gray-700 rounded hover:bg-gray-600 disabled:opacity-40"
                >
                  Prev
                </button>
                <span className="text-sm text-gray-400">
                  Page {page} of {totalPages}
                </span>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="px-3 py-1 text-sm bg-gray-700 rounded hover:bg-gray-600 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        )}

        {/* ==================== MODEL DETAIL TAB ==================== */}
        {activeTab === 'detail' && selectedModelId && (
          <div>
            <button
              onClick={() => { setActiveTab('list'); setSelectedModelId(null); setSelectedThreatId(null); }}
              className="flex items-center gap-1 text-gray-400 hover:text-white text-sm mb-4 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" /> Back to list
            </button>

            {/* Dashboard summary */}
            {dashboard && (
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                  <p className="text-gray-400 text-xs mb-1">Total Threats</p>
                  <p className="text-2xl font-bold">{dashboard.total_threats ?? 0}</p>
                </div>
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                  <p className="text-gray-400 text-xs mb-1">Open Threats</p>
                  <p className="text-2xl font-bold text-red-400">{dashboard.open_threats ?? 0}</p>
                </div>
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                  <p className="text-gray-400 text-xs mb-1">Mitigated</p>
                  <p className="text-2xl font-bold text-green-400">{dashboard.mitigated_threats ?? 0}</p>
                </div>
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                  <p className="text-gray-400 text-xs mb-1">Status / Methodology</p>
                  <p className="text-sm font-medium">
                    {capitalize(dashboard.status)} / {capitalize(dashboard.methodology)}
                  </p>
                </div>
              </div>
            )}

            {/* Actions bar */}
            <div className="flex gap-3 mb-6">
              <button
                onClick={() => setShowAddThreat(true)}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded flex items-center gap-2 text-sm transition-colors"
              >
                <Plus className="w-4 h-4" /> Add Threat
              </button>
              <button
                onClick={() => runStrideMutation.mutate()}
                disabled={runStrideMutation.isPending}
                className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded flex items-center gap-2 text-sm transition-colors disabled:opacity-50"
              >
                <Zap className="w-4 h-4" />
                {runStrideMutation.isPending ? 'Running...' : 'Run STRIDE Analysis'}
              </button>
              {runStrideMutation.isSuccess && (
                <span className="text-green-400 text-sm self-center">
                  Generated {(runStrideMutation.data as any)?.threats_generated ?? 0} threats
                </span>
              )}
            </div>

            {/* Components section */}
            <div className="mb-6">
              <h2 className="text-lg font-semibold mb-3">Components</h2>
              {components.length === 0 ? (
                <p className="text-gray-500 text-sm">No components found.</p>
              ) : (
                <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                  {components.map((c) => (
                    <div key={c.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <p className="font-medium text-white text-sm">{c.name ?? '-'}</p>
                      <p className="text-xs text-gray-400 mt-1">Type: {capitalize(c.component_type)}</p>
                      {c.trust_level && (
                        <p className="text-xs text-gray-400">Trust: {c.trust_level}</p>
                      )}
                      {c.description && (
                        <p className="text-xs text-gray-500 mt-1 line-clamp-2">{c.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Threats table */}
            <div className="mb-6">
              <h2 className="text-lg font-semibold mb-3">Threats</h2>
              <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-700/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Title</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">STRIDE</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Severity</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Likelihood</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Impact</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Risk</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threats.map((t) => (
                      <tr
                        key={t.id}
                        onClick={() => setSelectedThreatId(selectedThreatId === t.id ? null : t.id)}
                        className={`border-t border-gray-700 cursor-pointer transition-colors ${
                          selectedThreatId === t.id ? 'bg-gray-700/60' : 'hover:bg-gray-700/30'
                        }`}
                      >
                        <td className="px-4 py-3 text-sm font-medium text-white">
                          <div className="flex items-center gap-2">
                            <ChevronDown
                              className={`w-3 h-3 text-gray-500 transition-transform ${
                                selectedThreatId === t.id ? '' : '-rotate-90'
                              }`}
                            />
                            {t.title ?? '-'}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm">
                          <span className="bg-gray-700 text-gray-200 px-2 py-1 rounded text-xs">
                            {capitalize(t.stride_category)}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-300">{capitalize(t.severity)}</td>
                        <td className="px-4 py-3 text-sm text-gray-300">{capitalize(t.likelihood)}</td>
                        <td className="px-4 py-3 text-sm text-gray-300">{capitalize(t.impact)}</td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-1 rounded text-xs font-bold ${riskBg(t.risk_score)} ${riskColor(t.risk_score)}`}>
                            {t.risk_score ?? '-'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${THREAT_STATUSES[t.status] ?? 'bg-gray-700 text-gray-300'}`}>
                            {capitalize(t.status)}
                          </span>
                        </td>
                      </tr>
                    ))}
                    {threats.length === 0 && (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-gray-500 text-sm">
                          {threatsQuery.isLoading ? 'Loading...' : 'No threats found. Run STRIDE Analysis or add manually.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Mitigations for selected threat */}
            {selectedThreatId && (
              <div>
                <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  Mitigations for: {threats.find((t) => t.id === selectedThreatId)?.title ?? 'Selected Threat'}
                </h2>
                {mitigationsQuery.isLoading ? (
                  <p className="text-gray-500 text-sm">Loading mitigations...</p>
                ) : mitigations.length === 0 ? (
                  <p className="text-gray-500 text-sm">No mitigations for this threat.</p>
                ) : (
                  <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                    <table className="w-full">
                      <thead className="bg-gray-700/50">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Title</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Type</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Status</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Effectiveness</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300">Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mitigations.map((mit) => (
                          <tr key={mit.id} className="border-t border-gray-700 hover:bg-gray-700/30">
                            <td className="px-4 py-3 text-sm font-medium text-white">{mit.title ?? '-'}</td>
                            <td className="px-4 py-3 text-sm text-gray-300">{capitalize(mit.mitigation_type)}</td>
                            <td className="px-4 py-3 text-sm">
                              <span className={`px-2 py-1 rounded text-xs font-medium ${IMPL_STATUSES[mit.implementation_status] ?? 'bg-gray-700 text-gray-300'}`}>
                                {capitalize(mit.implementation_status)}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm">
                              {mit.effectiveness != null ? (
                                <div className="flex items-center gap-2">
                                  <div className="w-16 h-2 bg-gray-700 rounded-full">
                                    <div
                                      className="h-full bg-blue-500 rounded-full"
                                      style={{ width: `${Math.min(100, mit.effectiveness)}%` }}
                                    />
                                  </div>
                                  <span className="text-gray-400 text-xs">{mit.effectiveness}%</span>
                                </div>
                              ) : (
                                <span className="text-gray-500">-</span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-400 max-w-xs truncate">
                              {mit.description ?? '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ==================== CREATE MODEL MODAL ==================== */}
        {showCreateModel && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 w-full max-w-md">
              <div className="flex justify-between items-center mb-5">
                <h2 className="text-lg font-bold">New Threat Model</h2>
                <button onClick={() => setShowCreateModel(false)} className="text-gray-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Name *</label>
                  <input
                    value={modelForm.name}
                    onChange={(e) => setModelForm({ ...modelForm, name: e.target.value })}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    placeholder="e.g., API Security Review"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Application Name *</label>
                  <input
                    value={modelForm.application_name}
                    onChange={(e) => setModelForm({ ...modelForm, application_name: e.target.value })}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    placeholder="e.g., Payment Gateway"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Methodology *</label>
                  <select
                    value={modelForm.methodology}
                    onChange={(e) => setModelForm({ ...modelForm, methodology: e.target.value })}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                  >
                    {METHODOLOGIES.map((m) => (
                      <option key={m.value} value={m.value}>{m.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Description</label>
                  <textarea
                    value={modelForm.description}
                    onChange={(e) => setModelForm({ ...modelForm, description: e.target.value })}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    rows={3}
                    placeholder="Optional description..."
                  />
                </div>
                <div className="flex gap-3 pt-2">
                  <button
                    onClick={() => setShowCreateModel(false)}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => createModelMutation.mutate(modelForm)}
                    disabled={!modelForm.name || !modelForm.application_name || createModelMutation.isPending}
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded text-sm transition-colors disabled:opacity-50"
                  >
                    {createModelMutation.isPending ? 'Creating...' : 'Create'}
                  </button>
                </div>
                {createModelMutation.isError && (
                  <p className="text-red-400 text-xs">
                    Failed: {(createModelMutation.error as any)?.message ?? 'Unknown error'}
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ==================== ADD THREAT MODAL ==================== */}
        {showAddThreat && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 w-full max-w-md">
              <div className="flex justify-between items-center mb-5">
                <h2 className="text-lg font-bold">Add Threat</h2>
                <button onClick={() => setShowAddThreat(false)} className="text-gray-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Title *</label>
                  <input
                    value={threatForm.title}
                    onChange={(e) => setThreatForm({ ...threatForm, title: e.target.value })}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    placeholder="e.g., SQL Injection on login"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Description</label>
                  <textarea
                    value={threatForm.description}
                    onChange={(e) => setThreatForm({ ...threatForm, description: e.target.value })}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    rows={2}
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">STRIDE Category *</label>
                  <select
                    value={threatForm.stride_category}
                    onChange={(e) => setThreatForm({ ...threatForm, stride_category: e.target.value })}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                  >
                    {STRIDE_CATEGORIES.map((c) => (
                      <option key={c.value} value={c.value}>{c.label}</option>
                    ))}
                  </select>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Severity</label>
                    <select
                      value={threatForm.severity}
                      onChange={(e) => setThreatForm({ ...threatForm, severity: e.target.value })}
                      className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    >
                      {SEVERITY_OPTIONS.map((s) => (
                        <option key={s} value={s}>{capitalize(s)}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Likelihood</label>
                    <select
                      value={threatForm.likelihood}
                      onChange={(e) => setThreatForm({ ...threatForm, likelihood: e.target.value })}
                      className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    >
                      {LIKELIHOOD_OPTIONS.map((l) => (
                        <option key={l} value={l}>{capitalize(l)}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Impact</label>
                    <select
                      value={threatForm.impact}
                      onChange={(e) => setThreatForm({ ...threatForm, impact: e.target.value })}
                      className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                    >
                      {IMPACT_OPTIONS.map((i) => (
                        <option key={i} value={i}>{capitalize(i)}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="flex gap-3 pt-2">
                  <button
                    onClick={() => setShowAddThreat(false)}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => addThreatMutation.mutate(threatForm)}
                    disabled={!threatForm.title || addThreatMutation.isPending}
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded text-sm transition-colors disabled:opacity-50"
                  >
                    {addThreatMutation.isPending ? 'Adding...' : 'Add Threat'}
                  </button>
                </div>
                {addThreatMutation.isError && (
                  <p className="text-red-400 text-xs">
                    Failed: {(addThreatMutation.error as any)?.message ?? 'Unknown error'}
                  </p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
