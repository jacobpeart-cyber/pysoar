import React, { useState } from 'react';
import {
  BarChart3,
  TrendingUp,
  Shield,
  Activity,
  AlertTriangle,
  DollarSign,
  Search,
  Filter,
  Plus,
  Eye,
  Edit,
  Download,
  Target,
  CheckCircle,
} from 'lucide-react';
import clsx from 'clsx';
import { riskquantApi } from '../api/endpoints';

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'high':
      return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-100';
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'low':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const getRiskColor = (score: number) => {
  if (score >= 80) return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
  if (score >= 60) return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-100';
  if (score >= 40) return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
  return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
};

const getRiskLabel = (score: number) => {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
};

const formatCurrency = (value: number) => {
  if (value >= 1000000) return `$${(value / 1000000).toFixed(1)}M`;
  if (value >= 1000) return `$${(value / 1000).toFixed(0)}K`;
  return `$${value.toFixed(0)}`;
};

export default function RiskQuantification() {
  const [activeTab, setActiveTab] = useState('scenarios');
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [analysisResults, setAnalysisResults] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewScenarioModal, setShowNewScenarioModal] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<any | null>(null);
  const [selectedControl, setSelectedControl] = useState<any | null>(null);
  const [showFilter, setShowFilter] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [scenariosData, lossData] = await Promise.allSettled([
        riskquantApi.getScenarios(),
        riskquantApi.getLossExceedance(),
      ]);
      setScenarios(scenariosData.status === 'fulfilled' ? (scenariosData.value || []) : []);
      setAnalysisResults(lossData.status === 'fulfilled' ? (lossData.value || null) : null);
    } catch (err) {
      console.error('Error loading risk quantification data:', err);
      setError('Failed to load risk quantification data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadData();
  }, []);

  const totalScenarios = scenarios.length;
  const avgRiskScore = scenarios.length > 0
    ? Math.round(scenarios.reduce((sum, s) => sum + (s.riskScore || s.risk_score || 0), 0) / (scenarios.length || 1))
    : 0;
  const highRiskItems = scenarios.filter(s => (s.riskScore || s.risk_score || 0) >= 60).length;
  const totalControls = scenarios.reduce((sum, s) => sum + (s.controls?.length || s.controlCount || 0), 0);

  const tabs = [
    { id: 'scenarios', label: 'Scenarios', icon: Target },
    { id: 'analysis', label: 'Analysis', icon: BarChart3 },
    { id: 'risk-register', label: 'Risk Register', icon: Shield },
    { id: 'controls', label: 'Controls', icon: CheckCircle },
  ];

  const filteredScenarios = scenarios.filter(s =>
    (s.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (s.description || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (s.category || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Derive risk register from scenarios that have been analyzed
  const riskRegister = scenarios.filter(s => s.riskScore || s.risk_score);

  // Derive controls from scenarios
  const allControls = scenarios.flatMap(s =>
    (s.controls || []).map((c: any) => ({
      ...c,
      scenarioName: s.name,
      scenarioId: s.id,
    }))
  );

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
              onClick={() => {
                const blob = new Blob([JSON.stringify(scenarios, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'risk-quantification-export.json';
                a.click();
                URL.revokeObjectURL(url);
              }}
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
            <button
              onClick={() => setShowNewScenarioModal(true)}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg transition"
            >
              <Plus className="w-4 h-4" />
              New Scenario
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-emerald-50 to-emerald-100 dark:from-emerald-900 dark:to-emerald-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-emerald-600 dark:text-emerald-300">Risk Scenarios</p>
            <p className="text-3xl font-bold text-emerald-900 dark:text-emerald-100 mt-2">{totalScenarios}</p>
            <p className="text-xs text-emerald-600 dark:text-emerald-300 mt-1">FAIR-based scenarios</p>
          </div>
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Avg Risk Score</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{avgRiskScore}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">across all scenarios</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">High Risk Items</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{highRiskItems}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring attention</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Total Controls</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{totalControls}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">mitigating controls</p>
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
      <div className="p-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <p className="text-gray-500 dark:text-gray-400">Loading risk quantification data...</p>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
              <p className="text-red-600 dark:text-red-400">{error}</p>
              <button
                onClick={() => window.location.reload()}
                className="mt-4 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg transition"
              >
                Retry
              </button>
            </div>
          </div>
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
                      placeholder="Search scenarios by name, description, or category..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button
                    onClick={() => setShowFilter((prev) => !prev)}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
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
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Scenario Name</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Category</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Probability</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Impact</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Risk Score</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">ALE</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Controls</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredScenarios.map((scenario) => {
                          const riskScore = scenario.riskScore || scenario.risk_score || 0;
                          const probability = scenario.probability || scenario.lef || 0;
                          const impact = scenario.impact || scenario.lm || 0;
                          const ale = scenario.ale || scenario.annualized_loss || (probability * impact);
                          return (
                            <tr key={scenario.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                              <td className="px-6 py-4">
                                <div>
                                  <p className="text-sm font-medium">{scenario.name}</p>
                                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{scenario.description || 'No description'}</p>
                                </div>
                              </td>
                              <td className="px-6 py-4 text-sm">{scenario.category || 'Uncategorized'}</td>
                              <td className="px-6 py-4 text-sm font-semibold">{(probability * 100).toFixed(0)}%</td>
                              <td className="px-6 py-4 text-sm font-semibold">{formatCurrency(impact)}</td>
                              <td className="px-6 py-4">
                                <span className={`px-3 py-1 rounded-full text-xs font-medium ${getRiskColor(riskScore)}`}>
                                  {riskScore} - {getRiskLabel(riskScore)}
                                </span>
                              </td>
                              <td className="px-6 py-4 text-sm font-semibold">
                                <span className="flex items-center gap-1">
                                  <DollarSign className="w-3 h-3" />
                                  {formatCurrency(ale)}
                                </span>
                              </td>
                              <td className="px-6 py-4 text-sm">{scenario.controls?.length || scenario.controlCount || 0}</td>
                              <td className="px-6 py-4 text-sm flex gap-2">
                                <button
                                  onClick={() => setSelectedScenario(scenario)}
                                  className="text-blue-600 dark:text-blue-400 hover:underline"
                                >
                                  <Eye className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={() => setSelectedScenario(scenario)}
                                  className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                                >
                                  <Edit className="w-4 h-4" />
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
                <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4 mb-6">
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    FAIR (Factor Analysis of Information Risk) quantification uses Monte Carlo simulation to model probable loss scenarios and estimate annualized loss expectancy (ALE).
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Risk Distribution</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Critical (80-100)</span>
                        <span className="font-semibold text-red-600">{scenarios.filter(s => (s.riskScore || s.risk_score || 0) >= 80).length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>High (60-79)</span>
                        <span className="font-semibold text-orange-600">{scenarios.filter(s => { const r = s.riskScore || s.risk_score || 0; return r >= 60 && r < 80; }).length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Medium (40-59)</span>
                        <span className="font-semibold text-yellow-600">{scenarios.filter(s => { const r = s.riskScore || s.risk_score || 0; return r >= 40 && r < 60; }).length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Low (0-39)</span>
                        <span className="font-semibold text-green-600">{scenarios.filter(s => (s.riskScore || s.risk_score || 0) < 40).length}</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Loss Exceedance</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>10% Probability</span>
                        <span className="font-semibold">{analysisResults?.p10 ? formatCurrency(analysisResults.p10) : '—'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>50% Probability</span>
                        <span className="font-semibold">{analysisResults?.p50 ? formatCurrency(analysisResults.p50) : '—'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>90% Probability</span>
                        <span className="font-semibold">{analysisResults?.p90 ? formatCurrency(analysisResults.p90) : '—'}</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Aggregate Exposure</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Total ALE</span>
                        <span className="font-semibold text-red-600">
                          {formatCurrency(scenarios.reduce((sum, s) => sum + (s.ale || s.annualized_loss || 0), 0))}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Avg per Scenario</span>
                        <span className="font-semibold">
                          {scenarios.length > 0
                            ? formatCurrency(scenarios.reduce((sum, s) => sum + (s.ale || s.annualized_loss || 0), 0) / (scenarios.length || 1))
                            : '—'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Max Single Loss</span>
                        <span className="font-semibold">
                          {scenarios.length > 0
                            ? formatCurrency(Math.max(...scenarios.map(s => s.impact || s.lm || 0)))
                            : '—'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={async () => {
                      if (scenarios.length > 0) {
                        try {
                          await riskquantApi.runAnalysis(scenarios.map(s => s.id));
                        } catch (err) {
                          console.error('Error running analysis:', err);
                        }
                      }
                    }}
                    className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Activity className="w-4 h-4" />
                    Run Monte Carlo Simulation
                  </button>
                  <button
                    onClick={() => {
                      const data = { scenarios, analysisResults };
                      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = 'risk-analysis-export.json';
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
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
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search risk register..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button
                    onClick={() => setShowFilter((prev) => !prev)}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                {riskRegister.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Shield className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No risks in the register yet</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">Create and analyze scenarios to populate the risk register</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-4">
                    {riskRegister
                      .sort((a, b) => (b.riskScore || b.risk_score || 0) - (a.riskScore || a.risk_score || 0))
                      .map((risk) => {
                        const riskScore = risk.riskScore || risk.risk_score || 0;
                        const ale = risk.ale || risk.annualized_loss || 0;
                        return (
                          <div key={risk.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                            <div className="flex justify-between items-start mb-3">
                              <div className="flex-1">
                                <div className="flex items-center gap-3 mb-2">
                                  <h3 className="font-semibold text-lg">{risk.name}</h3>
                                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${getRiskColor(riskScore)}`}>
                                    {riskScore} - {getRiskLabel(riskScore)}
                                  </span>
                                </div>
                                <p className="text-sm text-gray-600 dark:text-gray-400">{risk.description || 'No description provided'}</p>
                              </div>
                              <div className="text-right ml-4">
                                <p className="text-xs text-gray-500 dark:text-gray-400">Annualized Loss</p>
                                <p className="text-lg font-bold text-red-600 dark:text-red-400">{formatCurrency(ale)}</p>
                              </div>
                            </div>
                            <div className="grid grid-cols-4 gap-4 text-sm mt-3">
                              <div>
                                <p className="text-gray-600 dark:text-gray-400">Category</p>
                                <p className="font-medium">{risk.category || 'General'}</p>
                              </div>
                              <div>
                                <p className="text-gray-600 dark:text-gray-400">Probability</p>
                                <p className="font-medium">{((risk.probability || risk.lef || 0) * 100).toFixed(0)}%</p>
                              </div>
                              <div>
                                <p className="text-gray-600 dark:text-gray-400">Impact</p>
                                <p className="font-medium">{formatCurrency(risk.impact || risk.lm || 0)}</p>
                              </div>
                              <div>
                                <p className="text-gray-600 dark:text-gray-400">Controls</p>
                                <p className="font-medium">{risk.controls?.length || risk.controlCount || 0}</p>
                              </div>
                            </div>
                            <div className="flex gap-2 mt-4">
                              <button
                                onClick={() => { setSelectedScenario(risk); setActiveTab('analysis'); }}
                                className="flex-1 px-3 py-2 text-sm bg-emerald-600 hover:bg-emerald-700 text-white rounded transition"
                              >
                                View Analysis
                              </button>
                              <button
                                onClick={() => setSelectedScenario(risk)}
                                className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                              >
                                Edit Risk
                              </button>
                              <button
                                onClick={() => { setSelectedScenario(risk); setActiveTab('controls'); }}
                                className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                              >
                                Add Control
                              </button>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>
            )}

            {/* Controls Tab */}
            {activeTab === 'controls' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Control Effectiveness</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Highly Effective</span><span className="font-semibold text-green-600">{allControls.filter(c => (c.effectiveness || 0) >= 80).length}</span></div>
                      <div className="flex justify-between"><span>Moderately Effective</span><span className="font-semibold text-yellow-600">{allControls.filter(c => { const e = c.effectiveness || 0; return e >= 50 && e < 80; }).length}</span></div>
                      <div className="flex justify-between"><span>Low Effectiveness</span><span className="font-semibold text-red-600">{allControls.filter(c => (c.effectiveness || 0) < 50).length}</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Control Types</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Preventive</span><span className="font-semibold">{allControls.filter(c => c.type === 'preventive').length}</span></div>
                      <div className="flex justify-between"><span>Detective</span><span className="font-semibold">{allControls.filter(c => c.type === 'detective').length}</span></div>
                      <div className="flex justify-between"><span>Corrective</span><span className="font-semibold">{allControls.filter(c => c.type === 'corrective').length}</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Cost-Benefit Summary</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Total Control Cost</span>
                        <span className="font-semibold">{formatCurrency(allControls.reduce((sum, c) => sum + (c.cost || 0), 0))}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Risk Reduction</span>
                        <span className="font-semibold text-green-600">—</span>
                      </div>
                      <div className="flex justify-between">
                        <span>ROI</span>
                        <span className="font-semibold">—</span>
                      </div>
                    </div>
                  </div>
                </div>

                {allControls.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <CheckCircle className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No controls defined yet</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">Add controls to risk scenarios to track mitigation</p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Control Name</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Linked Scenario</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Effectiveness</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Cost</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {allControls.map((control, idx) => (
                          <tr key={`${control.scenarioId}-${idx}`} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4">
                              <p className="text-sm font-medium">{control.name || `Control ${idx + 1}`}</p>
                              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{control.description || ''}</p>
                            </td>
                            <td className="px-6 py-4 text-sm capitalize">{control.type || 'preventive'}</td>
                            <td className="px-6 py-4 text-sm">{control.scenarioName}</td>
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-2">
                                <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                                  <div
                                    className="bg-emerald-600 h-2 rounded-full transition-all"
                                    style={{ width: `${control.effectiveness || 0}%` }}
                                  />
                                </div>
                                <span className="text-sm font-semibold">{control.effectiveness || 0}%</span>
                              </div>
                            </td>
                            <td className="px-6 py-4 text-sm">{control.cost ? formatCurrency(control.cost) : '—'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(control.status || 'low')}`}>
                                {(control.status || 'active').toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => setSelectedControl(control)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => setSelectedControl(control)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                              >
                                <Edit className="w-4 h-4" />
                              </button>
                            </td>
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

      {/* New Scenario Modal */}
      {showNewScenarioModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create FAIR Risk Scenario</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.post('/risk-quantification/scenarios', {
                  name: fd.get('name'),
                  description: fd.get('description') || undefined,
                  asset_name: fd.get('asset_name'),
                  asset_value_usd: parseFloat(fd.get('asset_value_usd') as string) || 0,
                  threat_actor: fd.get('threat_actor') || 'external_attacker',
                  threat_type: fd.get('threat_type'),
                  vulnerability_exploited: fd.get('vulnerability_exploited'),
                  loss_type: fd.get('loss_type') || 'productivity',
                  confidence_level: parseFloat(fd.get('confidence_level') as string) || 0.5,
                });
                setShowNewScenarioModal(false);
                loadData();
              } catch (err) { console.error('Failed to create scenario:', err); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Scenario Name *</label>
                <input name="name" type="text" required placeholder="e.g., Ransomware Attack on ERP" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea name="description" placeholder="Describe the risk scenario..." rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Asset Name *</label>
                <input name="asset_name" type="text" required placeholder="e.g., ERP System, Customer Database" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Asset Value (USD) *</label>
                <input name="asset_value_usd" type="number" required placeholder="e.g., 500000" min="0" step="0.01" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Threat Type *</label>
                <input name="threat_type" type="text" required placeholder="e.g., Ransomware, Data Exfiltration" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Vulnerability Exploited *</label>
                <input name="vulnerability_exploited" type="text" required placeholder="e.g., Unpatched software, Weak credentials" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium mb-1">Threat Actor</label>
                  <select name="threat_actor" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
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
                  <select name="loss_type" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
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
                <label className="block text-sm font-medium mb-1">Confidence Level (0-1)</label>
                <input name="confidence_level" type="number" placeholder="0.5" step="0.1" min="0" max="1" defaultValue="0.5" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  type="button"
                  onClick={() => setShowNewScenarioModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg transition"
                >
                  Create Scenario
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
