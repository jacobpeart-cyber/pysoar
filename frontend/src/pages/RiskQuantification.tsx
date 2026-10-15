import React, { useState } from 'react';
import {
  BarChart3,
  Shield,
  Activity,
  DollarSign,
  Search,
  Plus,
  Download,
  Target,
  CheckCircle,
  Calculator,
} from 'lucide-react';
import clsx from 'clsx';
import { riskquantApi } from '../api/endpoints';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

const formatCurrency = (value: number | null | undefined) => {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return NA;
  const v = Number(value);
  if (v >= 1000000) return `$${(v / 1000000).toFixed(1)}M`;
  if (v >= 1000) return `$${(v / 1000).toFixed(0)}K`;
  return `$${v.toFixed(0)}`;
};

const inputCls = 'w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100';

// FAIR inputs the analysis stores (src/schemas/risk_quant.py
// FAIRAnalysisBase). Every triple is required and must be ordered
// min <= mode <= max; nothing is defaulted.
const FAIR_TRIPLES: { key: string; label: string; hint: string; max?: number }[] = [
  { key: 'tef', label: 'Threat event frequency', hint: 'events per year' },
  { key: 'vuln', label: 'Vulnerability', hint: 'probability 0-1', max: 1 },
  { key: 'tcap', label: 'Threat capability', hint: '0-1', max: 1 },
  { key: 'rs', label: 'Resistance strength', hint: '0-1', max: 1 },
  { key: 'lm', label: 'Loss magnitude', hint: 'USD per event' },
  { key: 'primary_loss', label: 'Primary loss', hint: 'USD per event' },
  { key: 'secondary_loss', label: 'Secondary loss', hint: 'USD per event' },
];

// The most recent analysis of each scenario (completed ones win over
// drafts so the table shows the figures a simulation actually produced).
const latestByScenario = (analyses: Row[]): Record<string, Row> => {
  const map: Record<string, Row> = {};
  for (const a of analyses) {
    if (!a?.scenario_id) continue;
    const cur = map[a.scenario_id];
    const newer = !cur || String(a.created_at ?? '') > String(cur.created_at ?? '');
    if (!cur || (a.completed_at && !cur.completed_at) || (Boolean(a.completed_at) === Boolean(cur.completed_at) && newer)) {
      map[a.scenario_id] = a;
    }
  }
  return map;
};

const download = (name: string, data: unknown) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
};

export default function RiskQuantification() {
  const [activeTab, setActiveTab] = useState('scenarios');
  const [scenarios, setScenarios] = useState<Row[]>([]);
  const [fairByScenario, setFairByScenario] = useState<Record<string, Row>>({});
  const [lossExceedance, setLossExceedance] = useState<Row | null>(null);
  const [dashboard, setDashboard] = useState<Row | null>(null);
  const [controls, setControls] = useState<Row[]>([]);
  const [analyzeResult, setAnalyzeResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [loading, setLoading] = useState(true);
  const [scenarioError, setScenarioError] = useState<unknown>(null);
  const [loadErrors, setLoadErrors] = useState<{ fair?: unknown; dashboard?: unknown; loss?: unknown; controls?: unknown }>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewScenarioModal, setShowNewScenarioModal] = useState(false);
  const [fairFormScenario, setFairFormScenario] = useState<Row | null>(null);
  const [fairFormError, setFairFormError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [scenariosData, lossData, dashData, fairData, controlData] = await Promise.allSettled([
        api.get('/risk-quantification/scenarios', { params: { size: 100 } }).then((r) => (Array.isArray(r.data) ? r.data : r.data?.items ?? [])),
        riskquantApi.getLossExceedance(),
        riskquantApi.getDashboard(),
        riskquantApi.getFairAnalyses(),
        api.get('/risk-quantification/controls', { params: { size: 100 } }).then((r) => (Array.isArray(r.data) ? r.data : r.data?.items ?? [])),
      ]);
      setScenarioError(scenariosData.status === 'rejected' ? scenariosData.reason : null);
      setLoadErrors({
        fair: fairData.status === 'rejected' ? fairData.reason : undefined,
        dashboard: dashData.status === 'rejected' ? dashData.reason : undefined,
        loss: lossData.status === 'rejected' ? lossData.reason : undefined,
        controls: controlData.status === 'rejected' ? controlData.reason : undefined,
      });
      setScenarios(scenariosData.status === 'fulfilled' ? scenariosData.value : []);
      setFairByScenario(fairData.status === 'fulfilled' ? latestByScenario(fairData.value || []) : {});
      setLossExceedance(lossData.status === 'fulfilled' ? lossData.value ?? null : null);
      setDashboard(dashData.status === 'fulfilled' ? dashData.value ?? null : null);
      setControls(controlData.status === 'fulfilled' ? controlData.value : []);
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadData();
  }, []);

  // Simulate the stored FAIR inputs of the given scenarios. Scenarios
  // without inputs come back under `skipped` (no_fair_inputs); inconsistent
  // stored inputs under `failed` with the field at fault.
  const runAnalysis = async (scenarioIds: string[]) => {
    setBusy('analyze');
    setActionError(null);
    setAnalyzeResult(null);
    try {
      const res = await riskquantApi.runAnalysis(scenarioIds, 5000);
      setAnalyzeResult(res as Row);
      await loadData();
    } catch (error) {
      setActionError({ what: 'run the FAIR simulation', error });
    } finally {
      setBusy(null);
    }
  };

  const scenarioName = (id: string) => scenarios.find((s) => s.id === id)?.name ?? id;

  const fairTotal: number | null = dashboard?.fair_total_ale_mean ?? null;
  const analysesCompleted: number | null = dashboard?.fair_analyses_completed ?? null;
  const withoutInputs: number | null = dashboard?.fair_scenarios_without_inputs ?? null;

  const tabs = [
    { id: 'scenarios', label: 'Scenarios', icon: Target },
    { id: 'analysis', label: 'Analysis', icon: BarChart3 },
    { id: 'risk-register', label: 'Risk Register', icon: Shield },
    { id: 'controls', label: 'Controls', icon: CheckCircle },
  ];

  const filteredScenarios = scenarios.filter((s) =>
    (s.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (s.description || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (s.threat_type || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Risk register = scenarios whose latest analysis has completed.
  const riskRegister = scenarios
    .filter((s) => fairByScenario[s.id]?.completed_at)
    .sort((a, b) => Number(fairByScenario[b.id]?.ale_mean ?? 0) - Number(fairByScenario[a.id]?.ale_mean ?? 0));

  const submitFair = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFairFormError(null);
    setActionError(null);
    const fd = new FormData(e.currentTarget);
    const body: Record<string, number | string> = { scenario_id: String(fd.get('scenario_id') || '') };
    for (const t of FAIR_TRIPLES) {
      const vals = ['min', 'mode', 'max'].map((p) => String(fd.get(`${t.key}_${p}`) ?? '').trim());
      if (vals.some((v) => v === '')) {
        setFairFormError(`${t.label}: min, most likely and max are all required.`);
        return;
      }
      const [mn, md, mx] = vals.map(Number);
      if (!(mn <= md && md <= mx)) {
        setFairFormError(`${t.label}: values must be ordered min <= most likely <= max.`);
        return;
      }
      body[`${t.key}_min`] = mn;
      body[`${t.key}_mode`] = md;
      body[`${t.key}_max`] = mx;
    }
    const slef = String(fd.get('secondary_loss_event_frequency') ?? '').trim();
    if (slef === '') {
      setFairFormError('Secondary loss event frequency is required.');
      return;
    }
    body.secondary_loss_event_frequency = Number(slef);
    body.simulation_iterations = Number(fd.get('simulation_iterations') || 10000);
    const runNow = fd.get('run_now') === 'on';
    setBusy('fair');
    try {
      const created = (await api.post('/risk-quantification/fair-analyses', body)).data;
      if (runNow && created?.id) {
        await api.post(`/risk-quantification/fair-analyses/${created.id}/run-simulation`);
      }
      setFairFormScenario(null);
      await loadData();
    } catch (error) {
      setActionError({ what: runNow ? 'save and simulate the FAIR analysis' : 'save the FAIR analysis', error });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <BarChart3 className="w-8 h-8 text-emerald-600" />
            <h1 className="text-3xl font-bold">Risk Quantification</h1>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => download('risk-quantification-export.json', { scenarios, fair_analyses: fairByScenario, loss_exceedance: lossExceedance })}
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
            <button
              onClick={() => { setActionError(null); setFairFormError(null); setFairFormScenario({}); }}
              className="flex items-center gap-2 px-4 py-2 border border-emerald-600 text-emerald-700 dark:text-emerald-300 rounded-lg hover:bg-emerald-50 dark:hover:bg-emerald-900/30 transition"
            >
              <Calculator className="w-4 h-4" />
              New FAIR Analysis
            </button>
            <button
              onClick={() => { setActionError(null); setShowNewScenarioModal(true); }}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg transition"
            >
              <Plus className="w-4 h-4" />
              New Scenario
            </button>
          </div>
        </div>

        <div className="space-y-2 mb-4 empty:hidden">
          <LoadErrorBanner what="FAIR analyses" error={loadErrors.fair} />
          <LoadErrorBanner what="the risk dashboard" error={loadErrors.dashboard} />
          <LoadErrorBanner what="loss exceedance data" error={loadErrors.loss} />
          {actionError && !fairFormScenario && !showNewScenarioModal && (
            <ActionErrorBanner what={actionError.what} error={actionError.error} />
          )}
        </div>

        {/* Summary Cards: stored rows only */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-emerald-50 to-emerald-100 dark:from-emerald-900 dark:to-emerald-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-emerald-600 dark:text-emerald-300">Risk Scenarios</p>
            <p className="text-3xl font-bold text-emerald-900 dark:text-emerald-100 mt-2">{dashboard?.number_of_scenarios ?? (scenarioError ? NA : scenarios.length)}</p>
            <p className="text-xs text-emerald-600 dark:text-emerald-300 mt-1">
              {withoutInputs === null ? 'FAIR inputs status not available' : `${withoutInputs} without FAIR inputs`}
            </p>
          </div>
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">FAIR Analyses Completed</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{analysesCompleted ?? NA}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">latest simulated analysis per scenario</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Total ALE (mean)</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{formatCurrency(fairTotal)}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">{fairTotal === null ? 'no completed FAIR analysis' : 'sum of per-scenario mean ALE'}</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Controls</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{dashboard?.number_of_controls ?? NA}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">recorded mitigating controls</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6">
        <div className="flex gap-8 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'py-4 px-2 border-b-2 font-medium flex items-center gap-2 transition whitespace-nowrap',
                  activeTab === tab.id
                    ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
                    : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
                )}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Content */}
      <div className="p-6 space-y-4">
        {analyzeResult && (
          <div className="rounded-lg p-4 text-sm bg-emerald-50 dark:bg-emerald-900/30 text-emerald-900 dark:text-emerald-100 border border-emerald-200 dark:border-emerald-800 space-y-1">
            <div className="flex justify-between gap-4">
              <span>
                FAIR simulation {String(analyzeResult.status).replace(/_/g, ' ')}: {analyzeResult.scenarios_analyzed} scenario(s) analysed
                {analyzeResult.scenarios_analyzed > 0 && (
                  <> · total ALE mean {formatCurrency(analyzeResult.total_ale_mean)} · portfolio p90 {formatCurrency(analyzeResult.portfolio_p90)} · p95 {formatCurrency(analyzeResult.portfolio_var_95)} · p99 {formatCurrency(analyzeResult.portfolio_p99)} ({analyzeResult.portfolio_iterations} iterations)</>
                )}
              </span>
              <button onClick={() => setAnalyzeResult(null)} className="text-xs underline">dismiss</button>
            </div>
            {(analyzeResult.skipped ?? []).map((s: Row) => (
              <p key={`s-${s.scenario_id}`} className="text-orange-800 dark:text-orange-200">
                Skipped {scenarioName(s.scenario_id)}: {s.reason === 'no_fair_inputs' ? 'FAIR inputs required (add a FAIR analysis first)' : s.reason}
              </p>
            ))}
            {(analyzeResult.failed ?? []).map((f: Row) => (
              <p key={`f-${f.analysis_id}`} className="text-red-700 dark:text-red-300">
                Failed {scenarioName(f.scenario_id)}: {f.error}{f.field ? ` (${f.field}${f.detail ? `: ${f.detail}` : ''})` : ''}
              </p>
            ))}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center h-64">
            <p className="text-gray-500 dark:text-gray-400">Loading risk quantification data...</p>
          </div>
        ) : scenarioError ? (
          <LoadErrorBanner what="risk scenarios" error={scenarioError} />
        ) : (
          <>
            {/* Scenarios Tab */}
            {activeTab === 'scenarios' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search scenarios by name, description, or threat type..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                {filteredScenarios.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Target className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No risk scenarios found</p>
                    <button
                      onClick={() => setShowNewScenarioModal(true)}
                      className="mt-3 text-emerald-600 dark:text-emerald-400 hover:underline text-sm"
                    >
                      Create your first FAIR scenario
                    </button>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-x-auto border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold">Scenario</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Threat</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Asset Value</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">FAIR Inputs</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">ALE mean / p90</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredScenarios.map((scenario) => {
                          const fair = fairByScenario[scenario.id];
                          return (
                            <tr key={scenario.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                              <td className="px-6 py-4">
                                <p className="text-sm font-medium">{scenario.name}</p>
                                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{scenario.description || 'No description'}</p>
                              </td>
                              <td className="px-6 py-4 text-sm">
                                {scenario.threat_type}
                                <div className="text-xs text-gray-500">{String(scenario.threat_actor || '').replace(/_/g, ' ')} · {String(scenario.loss_type || '').replace(/_/g, ' ')}</div>
                              </td>
                              <td className="px-6 py-4 text-sm">{formatCurrency(scenario.asset_value_usd)}</td>
                              <td className="px-6 py-4 text-sm">
                                {!fair ? (
                                  <span className="px-2 py-1 rounded text-xs bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100">input required</span>
                                ) : fair.completed_at ? (
                                  <span className="px-2 py-1 rounded text-xs bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100">simulated {new Date(fair.completed_at).toLocaleDateString()}</span>
                                ) : (
                                  <span className="px-2 py-1 rounded text-xs bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200">stored, not simulated</span>
                                )}
                              </td>
                              <td className="px-6 py-4 text-sm font-semibold">
                                {fair?.completed_at ? (
                                  <span className="flex items-center gap-1">
                                    <DollarSign className="w-3 h-3" />
                                    {formatCurrency(fair.ale_mean)} / {formatCurrency(fair.ale_p90)}
                                  </span>
                                ) : (
                                  <span className="font-normal text-gray-500">{NA}</span>
                                )}
                              </td>
                              <td className="px-6 py-4 text-sm flex items-center gap-2">
                                <button
                                  onClick={() => { setActionError(null); setFairFormError(null); setFairFormScenario(scenario); }}
                                  className="px-2 py-1 text-xs font-medium rounded border border-emerald-600 text-emerald-700 dark:text-emerald-300"
                                  title="Enter FAIR estimates for this scenario"
                                >
                                  {fair ? 'New inputs' : 'Enter inputs'}
                                </button>
                                <button
                                  disabled={busy !== null || !fair}
                                  onClick={() => runAnalysis([scenario.id])}
                                  className="px-2 py-1 text-xs font-medium rounded bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white"
                                  title={fair ? 'Simulate the stored FAIR inputs' : 'FAIR inputs required first'}
                                >
                                  {busy === 'analyze' ? '…' : 'Simulate'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Analysis Tab */}
            {activeTab === 'analysis' && (
              <div className="space-y-6">
                <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4">
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    FAIR Monte Carlo over the analyst-entered estimates stored for each scenario. Scenarios without stored inputs are
                    not simulated and no default is invented for them.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Portfolio Loss Exceedance</h3>
                    {!lossExceedance || !lossExceedance.analyses_count ? (
                      <p className="text-sm text-gray-500">{lossExceedance?.note ?? 'No completed FAIR analysis.'}</p>
                    ) : (
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between"><span>Mean annual loss</span><span className="font-semibold">{formatCurrency(lossExceedance.total_ale_mean)}</span></div>
                        <div className="flex justify-between"><span>50% chance loss exceeds</span><span className="font-semibold">{formatCurrency(lossExceedance.total_ale_p50)}</span></div>
                        <div className="flex justify-between"><span>10% chance loss exceeds</span><span className="font-semibold">{formatCurrency(lossExceedance.total_ale_p90)}</span></div>
                        <div className="flex justify-between"><span>5% chance loss exceeds</span><span className="font-semibold">{formatCurrency(lossExceedance.total_ale_p95)}</span></div>
                        <div className="flex justify-between"><span>1% chance loss exceeds</span><span className="font-semibold">{formatCurrency(lossExceedance.total_ale_p99)}</span></div>
                        <p className="text-xs text-gray-500 pt-2">
                          {lossExceedance.analyses_count} analysis(es), {lossExceedance.iterations} iterations. {lossExceedance.method}
                        </p>
                      </div>
                    )}
                    {(lossExceedance?.excluded ?? []).length > 0 && (
                      <ul className="text-xs text-orange-700 dark:text-orange-300 mt-2 list-disc ml-4">
                        {lossExceedance?.excluded.map((x: Row) => (
                          <li key={x.analysis_id}>Excluded {scenarioName(x.scenario_id)}: {x.error} ({x.field})</li>
                        ))}
                      </ul>
                    )}
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Coverage</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Scenarios</span><span className="font-semibold">{dashboard?.number_of_scenarios ?? NA}</span></div>
                      <div className="flex justify-between"><span>With a completed analysis</span><span className="font-semibold">{analysesCompleted ?? NA}</span></div>
                      <div className="flex justify-between"><span>FAIR inputs required</span><span className="font-semibold text-orange-600">{withoutInputs ?? NA}</span></div>
                      <div className="flex justify-between"><span>Largest scenario ALE</span><span className="font-semibold">{riskRegister.length ? formatCurrency(fairByScenario[riskRegister[0].id]?.ale_mean) : NA}</span></div>
                    </div>
                  </div>
                </div>

                <div className="flex gap-3">
                  <button
                    disabled={busy !== null || scenarios.length === 0}
                    onClick={() => runAnalysis([])}
                    className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg transition"
                    title="Simulate every stored FAIR analysis of this organisation"
                  >
                    <Activity className={clsx('w-4 h-4', busy === 'analyze' && 'animate-spin')} />
                    {busy === 'analyze' ? 'Running…' : 'Simulate All Stored Analyses'}
                  </button>
                  <button
                    onClick={() => download('risk-analysis-export.json', { loss_exceedance: lossExceedance, analyses: fairByScenario })}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Download className="w-4 h-4" />
                    Export Analysis
                  </button>
                </div>
              </div>
            )}

            {/* Risk Register Tab */}
            {activeTab === 'risk-register' && (
              <div className="space-y-4">
                {riskRegister.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Shield className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No quantified risk yet</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">Enter FAIR inputs for a scenario and simulate it</p>
                  </div>
                ) : (
                  riskRegister.map((risk) => {
                    const fair = fairByScenario[risk.id];
                    return (
                      <div key={risk.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                        <div className="flex justify-between items-start mb-3">
                          <div className="flex-1">
                            <h3 className="font-semibold text-lg">{risk.name}</h3>
                            <p className="text-sm text-gray-600 dark:text-gray-400">{risk.description || 'No description provided'}</p>
                          </div>
                          <div className="text-right ml-4">
                            <p className="text-xs text-gray-500 dark:text-gray-400">ALE (mean)</p>
                            <p className="text-lg font-bold text-red-600 dark:text-red-400">{formatCurrency(fair?.ale_mean)}</p>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                          <div><p className="text-gray-600 dark:text-gray-400">p10</p><p className="font-medium">{formatCurrency(fair?.ale_p10)}</p></div>
                          <div><p className="text-gray-600 dark:text-gray-400">p50</p><p className="font-medium">{formatCurrency(fair?.ale_p50)}</p></div>
                          <div><p className="text-gray-600 dark:text-gray-400">p90</p><p className="font-medium">{formatCurrency(fair?.ale_p90)}</p></div>
                          <div><p className="text-gray-600 dark:text-gray-400">p99</p><p className="font-medium">{formatCurrency(fair?.ale_p99)}</p></div>
                          <div><p className="text-gray-600 dark:text-gray-400">Iterations</p><p className="font-medium">{fair?.simulation_iterations ?? NA}</p></div>
                        </div>
                        <p className="text-xs text-gray-500 mt-2">
                          Inputs: TEF {fair?.tef_min}/{fair?.tef_mode}/{fair?.tef_max} per year, vulnerability {fair?.vuln_min}/{fair?.vuln_mode}/{fair?.vuln_max},
                          loss magnitude {formatCurrency(fair?.lm_min)}/{formatCurrency(fair?.lm_mode)}/{formatCurrency(fair?.lm_max)}; simulated {fair?.completed_at ? new Date(fair.completed_at).toLocaleString() : NA}.
                        </p>
                      </div>
                    );
                  })
                )}
              </div>
            )}

            {/* Controls Tab */}
            {activeTab === 'controls' && (
              <div className="space-y-4">
                <LoadErrorBanner what="risk controls" error={loadErrors.controls} />
                {!loadErrors.controls && controls.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <CheckCircle className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No risk controls recorded</p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-x-auto border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold">Control</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Effectiveness <span className="font-normal text-xs text-gray-500">(analyst-entered)</span></th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Annual Cost</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">ROI</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Last Tested</th>
                        </tr>
                      </thead>
                      <tbody>
                        {controls.map((c) => (
                          <tr key={c.id} className="border-b border-gray-200 dark:border-gray-700">
                            <td className="px-6 py-4 text-sm font-medium">{c.control_name}</td>
                            <td className="px-6 py-4 text-sm capitalize">{c.control_type}</td>
                            <td className="px-6 py-4 text-sm">{String(c.implementation_status || '').replace(/_/g, ' ')}</td>
                            <td className="px-6 py-4 text-sm">{c.effectiveness_score}%</td>
                            <td className="px-6 py-4 text-sm">{formatCurrency(c.cost_annual_usd)}</td>
                            <td className="px-6 py-4 text-sm">{c.roi_percentage == null ? NA : `${Number(c.roi_percentage).toFixed(1)}%`}</td>
                            <td className="px-6 py-4 text-sm">{c.last_tested ? `${new Date(c.last_tested).toLocaleDateString()} (${c.test_result ?? 'no result'})` : 'never'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* FAIR Analysis Modal */}
      {fairFormScenario && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setFairFormScenario(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[640px] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-1">FAIR Analysis Inputs</h2>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
              Every estimate is required as an ordered triple (min, most likely, max). Nothing is defaulted from the asset value.
            </p>
            <form className="space-y-3" onSubmit={submitFair}>
              {fairFormError && (
                <div role="alert" className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">{fairFormError}</div>
              )}
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <label className="block text-sm font-medium">Scenario
                <select name="scenario_id" required defaultValue={fairFormScenario.id ?? ''} className={inputCls}>
                  <option value="" disabled>Choose a scenario...</option>
                  {scenarios.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </label>
              <div className="grid grid-cols-4 gap-2 text-xs font-semibold text-gray-500">
                <span>Input</span><span>Min</span><span>Most likely</span><span>Max</span>
              </div>
              {FAIR_TRIPLES.map((t) => (
                <div key={t.key} className="grid grid-cols-4 gap-2 items-center">
                  <span className="text-sm">{t.label}<span className="block text-xs text-gray-500">{t.hint}</span></span>
                  {['min', 'mode', 'max'].map((p) => (
                    <input key={p} name={`${t.key}_${p}`} type="number" required min={0} max={t.max} step="any" className={inputCls} />
                  ))}
                </div>
              ))}
              <div className="grid grid-cols-2 gap-3">
                <label className="block text-sm">Secondary loss event frequency (0-1)
                  <input name="secondary_loss_event_frequency" type="number" required min={0} max={1} step="any" className={inputCls} />
                </label>
                <label className="block text-sm">Simulation iterations
                  <input name="simulation_iterations" type="number" min={100} max={100000} defaultValue={10000} className={inputCls} />
                </label>
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input name="run_now" type="checkbox" defaultChecked /> Simulate immediately after saving
              </label>
              <div className="flex gap-2 pt-2">
                <button type="button" onClick={() => setFairFormScenario(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" disabled={busy === 'fair'} className="flex-1 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg disabled:opacity-50">
                  {busy === 'fair' ? 'Saving…' : 'Save Analysis'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New Scenario Modal */}
      {showNewScenarioModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create FAIR Risk Scenario</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              setActionError(null);
              try {
                await api.post('/risk-quantification/scenarios', {
                  name: fd.get('name'),
                  description: fd.get('description') || undefined,
                  asset_name: fd.get('asset_name'),
                  asset_value_usd: parseFloat(fd.get('asset_value_usd') as string),
                  threat_actor: fd.get('threat_actor') || 'external_attacker',
                  threat_type: fd.get('threat_type'),
                  vulnerability_exploited: fd.get('vulnerability_exploited'),
                  loss_type: fd.get('loss_type') || 'productivity',
                  confidence_level: parseFloat(fd.get('confidence_level') as string),
                });
                setShowNewScenarioModal(false);
                loadData();
              } catch (err) {
                setActionError({ what: 'create the scenario', error: err });
              }
            }}>
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <div>
                <label className="block text-sm font-medium mb-1">Scenario Name *</label>
                <input name="name" type="text" required placeholder="e.g., Ransomware Attack on ERP" className={inputCls} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea name="description" placeholder="Describe the risk scenario..." rows={3} className={inputCls} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Asset Name *</label>
                <input name="asset_name" type="text" required placeholder="e.g., ERP System" className={inputCls} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Asset Value (USD) *</label>
                <input name="asset_value_usd" type="number" required min="0" step="0.01" className={inputCls} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Threat Type *</label>
                <input name="threat_type" type="text" required placeholder="e.g., Ransomware" className={inputCls} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Vulnerability Exploited *</label>
                <input name="vulnerability_exploited" type="text" required placeholder="e.g., Unpatched software" className={inputCls} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium mb-1">Threat Actor</label>
                  <select name="threat_actor" className={inputCls}>
                    <option value="external_attacker">External Attacker</option>
                    <option value="insider_threat">Insider Threat</option>
                    <option value="nation_state">Nation State</option>
                    <option value="hacktivist">Hacktivist</option>
                    <option value="competitor">Competitor</option>
                    <option value="accidental">Accidental</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Loss Type</label>
                  <select name="loss_type" className={inputCls}>
                    <option value="productivity">Productivity</option>
                    <option value="response">Response</option>
                    <option value="replacement">Replacement</option>
                    <option value="fines">Fines & Judgments</option>
                    <option value="reputation">Reputation</option>
                    <option value="competitive_advantage">Competitive Advantage</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Analyst Confidence (0-1) *</label>
                <input name="confidence_level" type="number" required step="0.1" min="0" max="1" className={inputCls} />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setShowNewScenarioModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg transition">Create Scenario</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
