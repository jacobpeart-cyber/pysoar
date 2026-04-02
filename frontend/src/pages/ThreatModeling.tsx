import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Map,
  Target,
  GitBranch,
  Shield,
  CheckSquare,
  Plus,
  X,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  TrendingUp,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell } from 'recharts';
import clsx from 'clsx';
import { threatmodelApi } from '../api/endpoints';


export default function ThreatModeling() {
  const [activeTab, setActiveTab] = useState<'models' | 'stride' | 'trees' | 'mitigations'>('models');
  const [selectedModel, setSelectedModel] = useState<ThreatModel | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [expandedTree, setExpandedTree] = useState<string | null>(null);

  const { data: models = [] } = useQuery({ queryKey: ['threatModels'], queryFn: threatmodelApi.getModels });
  const { data: strideData = [] } = useQuery({ queryKey: ['stride'], queryFn: threatmodelApi.getSTRIDEAnalysis });
  const { data: threats = [] } = useQuery({ queryKey: ['threats'], queryFn: threatmodelApi.getThreats });
  const { data: attackTrees = [] } = useQuery({ queryKey: ['attackTrees'], queryFn: threatmodelApi.getAttackTrees });
  const { data: mitigations = [] } = useQuery({ queryKey: ['mitigations'], queryFn: threatmodelApi.getMitigations });

  const stats = useMemo(() => {
    const activeModels = models.filter((m: ThreatModel) => m.status === 'Active').length;
    const identifiedThreats = threats.length;
    const plannedMitigations = mitigations.filter((m: Mitigation) => m.status === 'Planned').length;
    const avgCoverage = (mitigations.reduce((sum: number, m: Mitigation) => sum + m.coverage, 0) / mitigations.length).toFixed(1);
    return { activeModels, identifiedThreats, plannedMitigations, avgCoverage };
  }, [models, threats, mitigations]);

  const strideDistribution = [
    { name: 'Spoofing', value: strideData.filter((s: STRIDEItem) => s.category === 'Spoofing').length, color: '#EF4444' },
    { name: 'Tampering', value: strideData.filter((s: STRIDEItem) => s.category === 'Tampering').length, color: '#F97316' },
    { name: 'Repudiation', value: strideData.filter((s: STRIDEItem) => s.category === 'Repudiation').length, color: '#FBBF24' },
    { name: 'Info Disc.', value: strideData.filter((s: STRIDEItem) => s.category === 'Information Disclosure').length, color: '#3B82F6' },
    { name: 'DoS', value: strideData.filter((s: STRIDEItem) => s.category === 'Denial of Service').length, color: '#8B5CF6' },
    { name: 'Elevation', value: strideData.filter((s: STRIDEItem) => s.category === 'Elevation of Privilege').length, color: '#EC4899' },
  ];

  const mitigationStatus = [
    { name: 'Implemented', count: mitigations.filter((m: Mitigation) => m.status === 'Implemented').length },
    { name: 'In Progress', count: mitigations.filter((m: Mitigation) => m.status === 'In Progress').length },
    { name: 'Planned', count: mitigations.filter((m: Mitigation) => m.status === 'Planned').length },
  ];

  const mitigationTrend = useMemo(() => {
    if (mitigations.length === 0) return [];
    const grouped: Record<string, { implemented: number; planned: number }> = {};
    mitigations.forEach((m: Mitigation) => {
      // Group by month from the mitigation data; fall back to index-based months if no date field
      const monthLabel = m.createdDate
        ? new Date(m.createdDate).toLocaleDateString('en-US', { month: 'short' })
        : 'N/A';
      if (!grouped[monthLabel]) grouped[monthLabel] = { implemented: 0, planned: 0 };
      if (m.status === 'Implemented') grouped[monthLabel].implemented += 1;
      else if (m.status === 'Planned') grouped[monthLabel].planned += 1;
    });
    return Object.entries(grouped).map(([month, counts]) => ({ month, ...counts }));
  }, [mitigations]);

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Map className="w-8 h-8 text-red-400" />
            Threat Modeling
          </h1>
          <p className="text-gray-400">STRIDE Analysis, Attack Trees & Mitigation Tracking</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active Threat Models</p>
                <p className="text-3xl font-bold">{stats.activeModels}</p>
              </div>
              <Map className="w-8 h-8 text-blue-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Identified Threats</p>
                <p className="text-3xl font-bold">{stats.identifiedThreats}</p>
              </div>
              <Target className="w-8 h-8 text-red-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Mitigations Planned</p>
                <p className="text-3xl font-bold">{stats.plannedMitigations}</p>
              </div>
              <Shield className="w-8 h-8 text-green-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Coverage Score</p>
                <p className="text-3xl font-bold">{stats.avgCoverage}%</p>
              </div>
              <TrendingUp className="w-8 h-8 text-purple-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-700">
          <div className="flex gap-8">
            {[
              { id: 'models', label: 'Threat Models', icon: Map },
              { id: 'stride', label: 'STRIDE Analysis', icon: Target },
              { id: 'trees', label: 'Attack Trees', icon: GitBranch },
              { id: 'mitigations', label: 'Mitigations', icon: Shield },
            ].map((tab) => {
              const TabIcon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={clsx(
                    'pb-4 px-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-red-400 text-red-400'
                      : 'border-transparent text-gray-400 hover:text-white'
                  )}
                >
                  <TabIcon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Models Tab */}
        {activeTab === 'models' && (
          <div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => setShowModal(true)}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New Model
              </button>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {models.map((model: ThreatModel) => (
                <div
                  key={model.id}
                  onClick={() => setSelectedModel(model)}
                  className="bg-gray-800 border border-gray-700 rounded-lg p-6 cursor-pointer hover:border-gray-600 transition-colors dark:bg-gray-800 dark:border-gray-700"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">{model.name}</h3>
                      <p className="text-sm text-gray-400">
                        Methodology: <span className="text-blue-400">{model.methodology}</span>
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-3xl font-bold text-orange-400 mb-1">{model.riskScore}</p>
                      <span className={clsx('px-3 py-1 rounded text-xs font-medium', model.status === 'Active' ? 'bg-green-900/40 text-green-300' : model.status === 'In Review' ? 'bg-blue-900/40 text-blue-300' : 'bg-gray-900/40 text-gray-300')}>
                        {model.status}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500">Created: {model.createdDate}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* STRIDE Tab */}
        {activeTab === 'stride' && (
          <div>
            <div className="grid grid-cols-2 gap-8 mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">STRIDE Distribution</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={strideDistribution}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="name" stroke="#9CA3AF" angle={-45} textAnchor="end" height={100} />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Bar dataKey="value" fill="#EF4444" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Category Legend</h3>
                <div className="space-y-3">
                  {strideDistribution.map((item) => (
                    <div key={item.name} className="flex items-center gap-3">
                      <div className="w-4 h-4 rounded" style={{ backgroundColor: item.color }}></div>
                      <span className="text-gray-300">{item.name}</span>
                      <span className="text-gray-500 ml-auto">{item.value} threats</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Component</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Category</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Threat</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Likelihood</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Impact</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Mitigation</th>
                  </tr>
                </thead>
                <tbody>
                  {strideData.map((item: STRIDEItem) => (
                    <tr key={item.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                      <td className="px-6 py-4 text-sm text-white font-medium">{item.component}</td>
                      <td className="px-6 py-4 text-sm">
                        <span className="bg-gray-700 text-gray-200 px-3 py-1 rounded text-xs dark:bg-gray-700">
                          {item.category}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">{item.threat}</td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-2 py-1 rounded text-xs font-medium',
                            item.likelihood === 'High' ? 'bg-red-900/40 text-red-300' : item.likelihood === 'Medium' ? 'bg-yellow-900/40 text-yellow-300' : 'bg-green-900/40 text-green-300'
                          )}
                        >
                          {item.likelihood}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-2 py-1 rounded text-xs font-medium',
                            item.impact === 'Critical' ? 'bg-red-900/40 text-red-300' : item.impact === 'High' ? 'bg-orange-900/40 text-orange-300' : 'bg-yellow-900/40 text-yellow-300'
                          )}
                        >
                          {item.impact}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">{item.mitigation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Attack Trees Tab */}
        {activeTab === 'trees' && (
          <div className="space-y-4">
            {attackTrees.map((tree) => (
              <div key={tree.id} className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
                <button
                  onClick={() => setExpandedTree(expandedTree === tree.id ? null : tree.id)}
                  className="w-full p-6 flex items-center gap-4 hover:bg-gray-700/50 transition-colors"
                >
                  {expandedTree === tree.id ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
                  <div className="flex-1 text-left">
                    <h3 className="text-lg font-semibold text-white">{tree.name}</h3>
                    <p className="text-sm text-gray-400">Root Goal: {tree.root}</p>
                  </div>
                </button>

                {expandedTree === tree.id && (
                  <div className="border-t border-gray-700 p-6 bg-gray-700/30">
                    <div className="space-y-4 font-mono text-sm">
                      {tree.children.map((child, idx) => (
                        <div key={idx}>
                          <div className="text-blue-400 ml-4">├─ {child.name} [{child.gate}]</div>
                          {child.children?.map((grandchild, gIdx) => (
                            <div key={gIdx} className="text-gray-300 ml-8">
                              └─ {grandchild.name}
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Mitigations Tab */}
        {activeTab === 'mitigations' && (
          <div>
            <div className="grid grid-cols-2 gap-8 mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Mitigation Progress</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={mitigationTrend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="month" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Legend />
                    <Line type="monotone" dataKey="implemented" stroke="#10B981" strokeWidth={2} />
                    <Line type="monotone" dataKey="planned" stroke="#FBBF24" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-4">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                  <h4 className="font-semibold mb-4 text-white">Status Breakdown</h4>
                  {mitigationStatus.map((status) => (
                    <div key={status.name} className="flex items-center justify-between mb-3">
                      <span className="text-gray-300">{status.name}</span>
                      <span className="font-semibold text-white">{status.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Threat</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Control</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Reference</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Coverage</th>
                  </tr>
                </thead>
                <tbody>
                  {mitigations.map((mitigation: Mitigation) => (
                    <tr key={mitigation.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                      <td className="px-6 py-4 text-sm text-white font-medium">{mitigation.threat}</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{mitigation.control}</td>
                      <td className="px-6 py-4 text-sm">
                        <span className="bg-gray-700 text-gray-200 px-3 py-1 rounded text-xs dark:bg-gray-700">
                          {mitigation.reference}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-3 py-1 rounded text-xs font-medium',
                            mitigation.status === 'Implemented' ? 'bg-green-900/40 text-green-300' : mitigation.status === 'In Progress' ? 'bg-blue-900/40 text-blue-300' : 'bg-yellow-900/40 text-yellow-300'
                          )}
                        >
                          {mitigation.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-2 bg-gray-700 rounded-full dark:bg-gray-700">
                            <div
                              className="h-full bg-blue-500 rounded-full"
                              style={{ width: `${mitigation.coverage}%` }}
                            />
                          </div>
                          <span className="text-gray-400 text-xs">{mitigation.coverage}%</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New Threat Model</h2>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Model Name</label>
                  <input
                    type="text"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                    placeholder="e.g., API Security Review"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Methodology</label>
                  <select className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white dark:bg-gray-700 dark:border-gray-600">
                    <option>STRIDE</option>
                    <option>Attack Tree</option>
                    <option>PASTA</option>
                  </select>
                </div>

                <div className="flex gap-4 mt-6">
                  <button
                    onClick={() => setShowModal(false)}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={async () => {
                      try {
                        await threatmodelApi.createModel({});
                      } catch (err) {
                        console.error('Create model failed:', err);
                      } finally {
                        setShowModal(false);
                      }
                    }}
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded transition-colors"
                  >
                    Create
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedModel && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">{selectedModel.name}</h2>
                <button
                  onClick={() => setSelectedModel(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <p className="text-sm text-gray-400">Methodology</p>
                  <p className="text-white font-medium">{selectedModel.methodology}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Risk Score</p>
                  <p className="text-3xl font-bold text-orange-400">{selectedModel.riskScore}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Status</p>
                  <p className="text-white font-medium">{selectedModel.status}</p>
                </div>
              </div>

              <button
                onClick={() => setSelectedModel(null)}
                className="w-full bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded mt-6 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
