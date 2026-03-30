import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Database,
  Workflow,
  Search,
  HardDrive,
  Layers,
  Plus,
  X,
  CheckCircle,
  AlertCircle,
  TrendingUp,
  Play,
  Pause,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import clsx from 'clsx';
import { datalakeApi } from '../api/endpoints';


export default function DataLakeDashboard() {
  const [activeTab, setActiveTab] = useState<'sources' | 'pipelines' | 'query' | 'catalog' | 'storage'>('sources');
  const [selectedSource, setSelectedSource] = useState<DataSource | null>(null);
  const [selectedPipeline, setSelectedPipeline] = useState<Pipeline | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [queryLanguage, setQueryLanguage] = useState<'sql' | 'kql' | 'spl'>('sql');

  const { data: sources = [] } = useQuery({ queryKey: ['dataSources'], queryFn: datalakeApi.getDataSources });
  const { data: pipelines = [] } = useQuery({ queryKey: ['pipelines'], queryFn: datalakeApi.getPipelines });
  const { data: catalog = [] } = useQuery({ queryKey: ['dataCatalog'], queryFn: datalakeApi.getCatalog });

  const stats = useMemo(() => {
    const activeSources = sources.filter((s: DataSource) => s.health === 'Healthy').length;
    const totalEventsPerSec = sources.reduce((sum: number, s: DataSource) => sum + s.ingestionRate, 0);
    const totalStorage = (sources.reduce((sum: number, s: DataSource) => sum + (s.events * 0.0002), 0) / 1000000).toFixed(2); // rough estimate in TB
    const activePipelines = pipelines.filter((p: Pipeline) => p.status === 'Running').length;
    return { activeSources, totalEventsPerSec, totalStorage, activePipelines };
  }, [sources, pipelines]);

  const storageBreakdown = [
    { name: 'Hot', value: 120, size: '120GB' },
    { name: 'Warm', value: 450, size: '450GB' },
    { name: 'Cold', value: 2100, size: '2.1TB' },
    { name: 'Archived', value: 15000, size: '15TB' },
  ];

  const STORAGE_COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#8B5CF6'];

  const ingestTrendData = [
    { time: '10:00', rate: 115000 },
    { time: '11:00', rate: 128000 },
    { time: '12:00', rate: 135000 },
    { time: '13:00', rate: 122000 },
    { time: '14:00', rate: 125000 },
  ];

  const pipelineHealthData = [
    { pipeline: 'ETL', success: 99.8, failure: 0.2 },
    { pipeline: 'Quality', success: 98.5, failure: 1.5 },
    { pipeline: 'Aggregation', success: 100, failure: 0 },
    { pipeline: 'ML Features', success: 97.2, failure: 2.8 },
  ];

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Database className="w-8 h-8 text-emerald-400" />
            Data Lake Dashboard
          </h1>
          <p className="text-gray-400">Data Ingestion, Pipeline Orchestration & Query Engine Management</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Data Sources Active</p>
                <p className="text-3xl font-bold">{stats.activeSources}/{sources.length}</p>
              </div>
              <Database className="w-8 h-8 text-blue-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Events/sec</p>
                <p className="text-3xl font-bold">{(stats.totalEventsPerSec / 1000).toFixed(0)}K</p>
              </div>
              <TrendingUp className="w-8 h-8 text-green-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Storage TB</p>
                <p className="text-3xl font-bold">{stats.totalStorage}</p>
              </div>
              <HardDrive className="w-8 h-8 text-purple-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active Pipelines</p>
                <p className="text-3xl font-bold">{stats.activePipelines}</p>
              </div>
              <Workflow className="w-8 h-8 text-orange-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-700">
          <div className="flex gap-8">
            {[
              { id: 'sources', label: 'Data Sources', icon: Database },
              { id: 'pipelines', label: 'Pipelines', icon: Workflow },
              { id: 'query', label: 'Query Engine', icon: Search },
              { id: 'catalog', label: 'Data Catalog', icon: Layers },
              { id: 'storage', label: 'Storage Tiers', icon: HardDrive },
            ].map((tab) => {
              const TabIcon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={clsx(
                    'pb-4 px-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-emerald-400 text-emerald-400'
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

        {/* Sources Tab */}
        {activeTab === 'sources' && (
          <div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => setShowModal(true)}
                className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New Source
              </button>
            </div>

            <div className="mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Ingestion Rate Trend</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={ingestTrendData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="time" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Line type="monotone" dataKey="rate" stroke="#10B981" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Source Name</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Ingestion Rate</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Total Events</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Health</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Last Sync</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map((source: DataSource) => (
                    <tr
                      key={source.id}
                      onClick={() => setSelectedSource(source)}
                      className="border-t border-gray-700 hover:bg-gray-700/50 cursor-pointer"
                    >
                      <td className="px-6 py-4 text-sm font-medium text-white">{source.name}</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{(source.ingestionRate / 1000).toFixed(0)}K/sec</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{(source.events / 1000000).toFixed(1)}M</td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-3 py-1 rounded text-xs font-medium flex items-center gap-2 w-fit',
                            source.health === 'Healthy'
                              ? 'bg-green-900/40 text-green-300'
                              : 'bg-yellow-900/40 text-yellow-300'
                          )}
                        >
                          {source.health === 'Healthy' ? <CheckCircle className="w-3 h-3" /> : <AlertCircle className="w-3 h-3" />}
                          {source.health}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">{source.lastSync}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Pipelines Tab */}
        {activeTab === 'pipelines' && (
          <div>
            <div className="grid grid-cols-2 gap-8 mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Pipeline Success Rates</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={pipelineHealthData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="pipeline" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Legend />
                    <Bar dataKey="success" fill="#10B981" />
                    <Bar dataKey="failure" fill="#EF4444" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-4">
                {pipelines.slice(0, 3).map((pipeline: Pipeline) => (
                  <div key={pipeline.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4 dark:bg-gray-800 dark:border-gray-700">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-semibold text-white">{pipeline.name}</h4>
                      <span
                        className={clsx(
                          'px-2 py-1 rounded text-xs font-medium flex items-center gap-1',
                          pipeline.status === 'Running'
                            ? 'bg-green-900/40 text-green-300'
                            : pipeline.status === 'Completed'
                              ? 'bg-blue-900/40 text-blue-300'
                              : 'bg-gray-900/40 text-gray-300'
                        )}
                      >
                        {pipeline.status === 'Running' ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
                        {pipeline.status}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 mb-2">Success Rate: <span className="text-green-400 font-semibold">{pipeline.successRate}%</span></p>
                    <div className="flex justify-between text-xs text-gray-500">
                      <span>{pipeline.lastRun}</span>
                      <span>{pipeline.duration}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Pipeline Name</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Success Rate</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Last Run</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {pipelines.map((pipeline: Pipeline) => (
                    <tr
                      key={pipeline.id}
                      onClick={() => setSelectedPipeline(pipeline)}
                      className="border-t border-gray-700 hover:bg-gray-700/50 cursor-pointer"
                    >
                      <td className="px-6 py-4 text-sm font-medium text-white">{pipeline.name}</td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-3 py-1 rounded text-xs font-medium',
                            pipeline.status === 'Running' ? 'bg-green-900/40 text-green-300' : pipeline.status === 'Completed' ? 'bg-blue-900/40 text-blue-300' : 'bg-gray-900/40 text-gray-300'
                          )}
                        >
                          {pipeline.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-2 bg-gray-700 rounded-full dark:bg-gray-700">
                            <div className="h-full bg-green-500 rounded-full" style={{ width: `${pipeline.successRate}%` }} />
                          </div>
                          <span className="text-gray-400 text-xs">{pipeline.successRate}%</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">{pipeline.lastRun}</td>
                      <td className="px-6 py-4 text-sm text-gray-400">{pipeline.duration}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Query Engine Tab */}
        {activeTab === 'query' && (
          <div className="space-y-6">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Query Interface</h3>

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-300 mb-2">Query Language</label>
                <div className="flex gap-4">
                  {[
                    { id: 'sql', label: 'SQL' },
                    { id: 'kql', label: 'KQL (Kusto)' },
                    { id: 'spl', label: 'SPL (Splunk)' },
                  ].map((lang) => (
                    <button
                      key={lang.id}
                      onClick={() => setQueryLanguage(lang.id as typeof queryLanguage)}
                      className={clsx(
                        'px-4 py-2 rounded font-medium text-sm transition-colors',
                        queryLanguage === lang.id
                          ? 'bg-emerald-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      )}
                    >
                      {lang.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Query</label>
                <textarea
                  className="w-full bg-gray-700 border border-gray-600 rounded px-4 py-3 text-white font-mono text-sm placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                  placeholder={queryLanguage === 'sql' ? 'SELECT * FROM user_events WHERE date > \'2026-03-20\'' : 'Type your query here...'}
                  rows={6}
                />
              </div>

              <div className="flex gap-4 mt-4">
                <button className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors">
                  Clear
                </button>
                <button className="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-2 rounded transition-colors font-medium">
                  Execute Query
                </button>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
              <h4 className="font-semibold text-white mb-4">Query Results</h4>
              <div className="bg-gray-700/50 rounded p-4 text-gray-300 font-mono text-sm max-h-60 overflow-y-auto">
                <pre>
{`Executing query...
Results will appear here
Estimated execution time: 1.2s
Rows returned: 1,250,400`}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Catalog Tab */}
        {activeTab === 'catalog' && (
          <div>
            <div className="mb-6">
              <input
                type="text"
                placeholder="Search data catalog..."
                className="w-full bg-gray-800 border border-gray-700 rounded px-4 py-3 text-white placeholder-gray-500 dark:bg-gray-800 dark:border-gray-700"
              />
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Table Name</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Schema</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Rows</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Size (GB)</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Owner</th>
                  </tr>
                </thead>
                <tbody>
                  {catalog.map((item: CatalogItem) => (
                    <tr key={item.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                      <td className="px-6 py-4 text-sm font-medium text-white">{item.name}</td>
                      <td className="px-6 py-4 text-sm">
                        <span className="bg-gray-700 text-gray-200 px-3 py-1 rounded text-xs dark:bg-gray-700">
                          {item.schema}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">{(item.rows / 1000).toFixed(0)}K</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{item.size}</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{item.owner}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Storage Tab */}
        {activeTab === 'storage' && (
          <div className="grid grid-cols-2 gap-8">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Storage Tier Breakdown</h3>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={storageBreakdown}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}GB`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {storageBreakdown.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={STORAGE_COLORS[index % STORAGE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="space-y-4">
              {storageBreakdown.map((tier, idx) => (
                <div key={tier.name} className="bg-gray-800 border border-gray-700 rounded-lg p-4 dark:bg-gray-800 dark:border-gray-700">
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-semibold text-white">{tier.name} Storage</h4>
                    <span className="text-sm text-gray-400">{tier.size}</span>
                  </div>
                  <div className="flex justify-between text-xs text-gray-500 mb-2">
                    <span>Capacity Used</span>
                    <span>{Math.round((tier.value / 17670) * 100)}%</span>
                  </div>
                  <div className="w-full h-2 bg-gray-700 rounded-full dark:bg-gray-700">
                    <div
                      className="h-full rounded-full"
                      style={{
                        backgroundColor: STORAGE_COLORS[idx],
                        width: `${Math.round((tier.value / 17670) * 100)}%`,
                      }}
                    />
                  </div>
                </div>
              ))}

              <div className="bg-gray-700/50 rounded-lg p-4 mt-4">
                <p className="text-sm text-gray-400 mb-2">Total Capacity</p>
                <p className="text-3xl font-bold text-emerald-400">17.67 TB</p>
              </div>
            </div>
          </div>
        )}

        {/* Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">Add Data Source</h2>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Source Name</label>
                  <input
                    type="text"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                    placeholder="e.g., Customer Events"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Connection String</label>
                  <input
                    type="text"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                    placeholder="Connection details"
                  />
                </div>

                <div className="flex gap-4 mt-6">
                  <button
                    onClick={() => setShowModal(false)}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => setShowModal(false)}
                    className="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded transition-colors"
                  >
                    Add Source
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedSource && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">{selectedSource.name}</h2>
                <button
                  onClick={() => setSelectedSource(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <p className="text-sm text-gray-400">Ingestion Rate</p>
                  <p className="text-white font-medium">{(selectedSource.ingestionRate / 1000).toFixed(0)}K events/sec</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Total Events</p>
                  <p className="text-white font-medium">{(selectedSource.events / 1000000).toFixed(1)}M</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Health</p>
                  <p className={clsx('font-medium', selectedSource.health === 'Healthy' ? 'text-green-400' : 'text-yellow-400')}>
                    {selectedSource.health}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Last Sync</p>
                  <p className="text-white font-medium">{selectedSource.lastSync}</p>
                </div>
              </div>

              <button
                onClick={() => setSelectedSource(null)}
                className="w-full bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded mt-6 transition-colors"
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
