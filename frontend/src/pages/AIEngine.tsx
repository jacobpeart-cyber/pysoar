import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { api } from '../lib/api';
import {
  Brain,
  Send,
  Zap,
  TrendingUp,
  AlertCircle,
  CheckCircle,
  XCircle,
  Clock,
  Eye,
  RefreshCw,
  Filter,
  Download,
} from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import clsx from 'clsx';

interface AIDashboard {
  alerts_auto_triaged: number;
  triage_accuracy_rate: number;
  false_positive_rate: number;
  avg_triage_time_ms: number;
  anomalies_detected_24h: number;
  active_ml_models: number;
  model_accuracy: number;
  ml_false_positive_rate: number;
  entities_at_risk: number;
  avg_risk_score: number;
}

interface TriagedAlert {
  id: string;
  title: string;
  ai_priority: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  reasoning: string;
  analyst_override?: boolean;
}

interface Anomaly {
  id: string;
  timestamp: string;
  entity_name: string;
  entity_type: string;
  type: string;
  anomaly_score: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  status: 'active' | 'confirmed' | 'dismissed';
}

interface Prediction {
  entity_id: string;
  entity_name: string;
  entity_type: string;
  risk_score: number;
  probability: number;
  time_horizon_days: number;
  contributing_factors: string[];
  recommended_actions: string[];
}

interface MLModel {
  id: string;
  name: string;
  type: string;
  algorithm: string;
  status: 'training' | 'ready' | 'deployed' | 'retired';
  accuracy: number;
  f1_score: number;
  last_trained: string;
  predictions_made: number;
  drift_score: number;
}

interface Query {
  id: string;
  text: string;
  interpreted_intent: string;
  generated_query: string;
  timestamp: string;
  results_count: number;
}

const priorityColors = {
  critical: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20',
  high: 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20',
  medium: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20',
  low: 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20',
};

const severityColors = {
  critical: 'text-red-600 dark:text-red-400',
  high: 'text-orange-600 dark:text-orange-400',
  medium: 'text-yellow-600 dark:text-yellow-400',
  low: 'text-blue-600 dark:text-blue-400',
};

const statusDots = {
  active: 'bg-green-500',
  confirmed: 'bg-orange-500',
  dismissed: 'bg-gray-400',
};

export default function AIEngine() {
  const [activeTab, setActiveTab] = useState<'ask' | 'triage' | 'anomalies' | 'predictions' | 'models'>('ask');
  const [queryInput, setQueryInput] = useState('');
  const [recentQueries, setRecentQueries] = useState<Query[]>([]);
  const [selectedQuery, setSelectedQuery] = useState<Query | null>(null);
  const [anomalyFilter, setAnomalyFilter] = useState<'all' | 'active' | 'confirmed' | 'dismissed'>('all');
  const [predictionFilter, setPredictionFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [entityTypeFilter, setEntityTypeFilter] = useState('all');

  // Fetch dashboard data
  const { data: dashboard } = useQuery({
    queryKey: ['aiDashboard'],
    queryFn: async () => {
      const response = await api.get<AIDashboard>('/ai/dashboard');
      return response.data;
    },
  });

  // Fetch triaged alerts
  const { data: triagedAlerts } = useQuery({
    queryKey: ['triagedAlerts'],
    queryFn: async () => {
      const response = await api.get<TriagedAlert[]>('/ai/alerts/triaged');
      return response.data;
    },
  });

  // Fetch anomalies
  const { data: anomalies } = useQuery({
    queryKey: ['aiAnomalies', anomalyFilter],
    queryFn: async () => {
      const response = await api.get<Anomaly[]>('/ai/anomalies', {
        params: anomalyFilter !== 'all' ? { status: anomalyFilter } : {},
      });
      return response.data;
    },
  });

  // Fetch predictions
  const { data: predictions } = useQuery({
    queryKey: ['predictions', predictionFilter, entityTypeFilter],
    queryFn: async () => {
      const response = await api.get<Prediction[]>('/ai/predictions', {
        params: {
          ...(predictionFilter !== 'all' ? { risk_level: predictionFilter } : {}),
          ...(entityTypeFilter !== 'all' ? { entity_type: entityTypeFilter } : {}),
        },
      });
      return response.data;
    },
  });

  // Fetch ML models
  const { data: models } = useQuery({
    queryKey: ['mlModels'],
    queryFn: async () => {
      const response = await api.get<MLModel[]>('/ai/models');
      return response.data;
    },
  });

  // Submit query mutation
  const queryMutation = useMutation({
    mutationFn: async (query: string) => {
      const response = await api.post<Query>('/ai/query', { query });
      return response.data;
    },
    onSuccess: (data) => {
      setSelectedQuery(data);
      setRecentQueries([data, ...recentQueries.slice(0, 4)]);
      setQueryInput('');
    },
  });

  const handleQuerySubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (queryInput.trim()) {
      queryMutation.mutate(queryInput);
    }
  };

  const exampleQueries = [
    'Show failed logins last 24h',
    'Which assets have critical vulns',
    'Summarize today\'s alerts',
    'Unusual network activity detected',
    'High-risk user activities',
  ];

  const handleAnomalyAction = async (anomalyId: string, action: 'confirm' | 'dismiss') => {
    try {
      await api.post(`/ai/anomalies/${anomalyId}/${action}`);
      // Refetch anomalies
    } catch (error) {
      console.error('Error updating anomaly:', error);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">AI Security Engine</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">Intelligent threat detection and analysis</p>
        </div>
        <Brain className="w-10 h-10 text-blue-600 dark:text-blue-400" />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <div className="flex space-x-8">
          {[
            { id: 'ask', label: 'Ask AI', icon: Send },
            { id: 'triage', label: 'Alert Triage', icon: Zap },
            { id: 'anomalies', label: 'Anomaly Detection', icon: AlertCircle },
            { id: 'predictions', label: 'Threat Predictions', icon: TrendingUp },
            { id: 'models', label: 'ML Models', icon: Brain },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'px-4 py-3 border-b-2 font-medium text-sm transition-colors flex items-center gap-2',
                  activeTab === tab.id
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400'
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

      {/* Tab Content */}

      {/* Ask AI Tab */}
      {activeTab === 'ask' && (
        <div className="space-y-6">
          {/* Search Input */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <form onSubmit={handleQuerySubmit} className="space-y-4">
              <div className="relative">
                <input
                  type="text"
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  placeholder="Ask anything about your security environment..."
                  className="w-full px-4 py-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                  type="submit"
                  disabled={queryMutation.isPending}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-2 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded transition-colors disabled:opacity-50"
                >
                  <Send className="w-5 h-5" />
                </button>
              </div>

              {/* Example queries */}
              <div className="flex flex-wrap gap-2">
                {exampleQueries.map((example) => (
                  <button
                    key={example}
                    type="button"
                    onClick={() => setQueryInput(example)}
                    className="px-3 py-1 rounded-full text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                  >
                    {example}
                  </button>
                ))}
              </div>
            </form>
          </div>

          {/* Query Results */}
          {selectedQuery && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-lg bg-blue-50 dark:bg-blue-900/20">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Interpreted Intent</p>
                  <p className="text-lg font-semibold text-blue-600 dark:text-blue-400 mt-1">{selectedQuery.interpreted_intent}</p>
                </div>
                <div className="p-4 rounded-lg bg-purple-50 dark:bg-purple-900/20">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Results Found</p>
                  <p className="text-lg font-semibold text-purple-600 dark:text-purple-400 mt-1">{selectedQuery.results_count}</p>
                </div>
                <div className="p-4 rounded-lg bg-green-50 dark:bg-green-900/20">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Query Time</p>
                  <p className="text-lg font-semibold text-green-600 dark:text-green-400 mt-1">0.23s</p>
                </div>
              </div>
              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <p className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Generated Query</p>
                <div className="p-3 rounded-lg bg-gray-100 dark:bg-gray-700 font-mono text-sm text-gray-800 dark:text-gray-200 overflow-auto">
                  {selectedQuery.generated_query}
                </div>
              </div>
            </div>
          )}

          {/* Recent Queries */}
          {recentQueries.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Queries</h3>
              <div className="space-y-3">
                {recentQueries.map((query) => (
                  <button
                    key={query.id}
                    onClick={() => setSelectedQuery(query)}
                    className="w-full p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors text-left"
                  >
                    <p className="text-gray-900 dark:text-white font-medium">{query.text}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{query.results_count} results · {new Date(query.timestamp).toLocaleString()}</p>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Alert Triage Tab */}
      {activeTab === 'triage' && (
        <div className="space-y-6">
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Alerts Auto-Triaged</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">{dashboard?.alerts_auto_triaged || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Accuracy Rate</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{dashboard?.triage_accuracy_rate?.toFixed(1) || 0}%</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">False Positive Rate</p>
              <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{dashboard?.false_positive_rate?.toFixed(1) || 0}%</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Avg Triage Time</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{dashboard?.avg_triage_time_ms || 0}ms</p>
            </div>
          </div>

          {/* Alerts Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Alert</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">AI Priority</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Confidence</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Reasoning</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Override</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {triagedAlerts?.slice(0, 10).map((alert) => (
                  <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4">
                      <p className="text-gray-900 dark:text-white font-medium">{alert.title}</p>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-sm font-medium', priorityColors[alert.ai_priority])}>
                        {alert.ai_priority.charAt(0).toUpperCase() + alert.ai_priority.slice(1)}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full"
                            style={{ width: `${alert.confidence * 100}%` }}
                          />
                        </div>
                        <span className="text-sm text-gray-600 dark:text-gray-400">{(alert.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400 truncate">{alert.reasoning}</p>
                    </td>
                    <td className="px-6 py-4">
                      {alert.analyst_override && (
                        <span className="inline-block px-2 py-1 rounded text-xs bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400 font-medium">
                          Overridden
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <button className="px-4 py-2 rounded-lg bg-blue-600 dark:bg-blue-700 text-white hover:bg-blue-700 dark:hover:bg-blue-600 font-medium transition-colors">
            Triage Pending Alerts
          </button>
        </div>
      )}

      {/* Anomalies Tab */}
      {activeTab === 'anomalies' && (
        <div className="space-y-6">
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Anomalies (24h)</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">{dashboard?.anomalies_detected_24h || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Active ML Models</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{dashboard?.active_ml_models || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Model Accuracy</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{dashboard?.model_accuracy?.toFixed(1) || 0}%</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">False Positive Rate</p>
              <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{dashboard?.ml_false_positive_rate?.toFixed(1) || 0}%</p>
            </div>
          </div>

          {/* Filter */}
          <div className="flex gap-2">
            {(['all', 'active', 'confirmed', 'dismissed'] as const).map((status) => (
              <button
                key={status}
                onClick={() => setAnomalyFilter(status)}
                className={clsx(
                  'px-4 py-2 rounded-lg font-medium text-sm transition-colors',
                  anomalyFilter === status
                    ? 'bg-blue-600 dark:bg-blue-700 text-white'
                    : 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-300 dark:hover:bg-gray-600'
                )}
              >
                {status.charAt(0).toUpperCase() + status.slice(1)}
              </button>
            ))}
          </div>

          {/* Anomalies Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Entity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Score</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Description</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {anomalies?.slice(0, 10).map((anomaly) => (
                  <tr key={anomaly.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {new Date(anomaly.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">{anomaly.entity_name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{anomaly.entity_type}</td>
                    <td className="px-6 py-4">
                      <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          className={clsx('h-2 rounded-full', anomaly.anomaly_score > 0.7 ? 'bg-red-500' : anomaly.anomaly_score > 0.5 ? 'bg-yellow-500' : 'bg-blue-500')}
                          style={{ width: `${anomaly.anomaly_score * 100}%` }}
                        />
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx('text-sm font-medium', severityColors[anomaly.severity])}>
                        {anomaly.severity.charAt(0).toUpperCase() + anomaly.severity.slice(1)}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 truncate">{anomaly.description}</td>
                    <td className="px-6 py-4 space-x-2">
                      <button
                        onClick={() => handleAnomalyAction(anomaly.id, 'confirm')}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-900/40 transition-colors"
                      >
                        <CheckCircle className="w-3 h-3" />
                        Confirm
                      </button>
                      <button
                        onClick={() => handleAnomalyAction(anomaly.id, 'dismiss')}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                      >
                        <XCircle className="w-3 h-3" />
                        Dismiss
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Predictions Tab */}
      {activeTab === 'predictions' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="flex flex-wrap gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-white mb-2">Entity Type</label>
              <select
                value={entityTypeFilter}
                onChange={(e) => setEntityTypeFilter(e.target.value)}
                className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Types</option>
                <option value="user">User</option>
                <option value="host">Host</option>
                <option value="service">Service</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-white mb-2">Risk Level</label>
              <select
                value={predictionFilter}
                onChange={(e) => setPredictionFilter(e.target.value as any)}
                className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          {/* Prediction Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {predictions?.slice(0, 9).map((prediction) => (
              <div key={prediction.entity_id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Entity</p>
                  <p className="font-semibold text-gray-900 dark:text-white mt-1">{prediction.entity_name}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">{prediction.entity_type}</p>
                </div>

                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Risk Score</p>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className={clsx(
                          'h-full transition-all',
                          prediction.risk_score > 0.7 ? 'bg-red-500' : prediction.risk_score > 0.5 ? 'bg-orange-500' : 'bg-green-500'
                        )}
                        style={{ width: `${prediction.risk_score * 100}%` }}
                      />
                    </div>
                    <span className="text-lg font-bold text-gray-900 dark:text-white">{(prediction.risk_score * 100).toFixed(0)}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Probability</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{(prediction.probability * 100).toFixed(0)}%</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Time Horizon</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{prediction.time_horizon_days}d</p>
                  </div>
                </div>

                <div>
                  <p className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Factors</p>
                  <ul className="space-y-1">
                    {prediction.contributing_factors.slice(0, 2).map((factor, idx) => (
                      <li key={idx} className="text-xs text-gray-600 dark:text-gray-400 flex items-start gap-2">
                        <span className="text-blue-600 dark:text-blue-400 mt-1">•</span>
                        <span>{factor}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <p className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Recommended Actions</p>
                  <ul className="space-y-1">
                    {prediction.recommended_actions.slice(0, 2).map((action, idx) => (
                      <li key={idx} className="text-xs text-gray-600 dark:text-gray-400 flex items-start gap-2">
                        <span className="text-green-600 dark:text-green-400 mt-1">→</span>
                        <span>{action}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ML Models Tab */}
      {activeTab === 'models' && (
        <div className="space-y-6">
          <button className="px-4 py-2 rounded-lg bg-blue-600 dark:bg-blue-700 text-white hover:bg-blue-700 dark:hover:bg-blue-600 font-medium transition-colors">
            Train New Model
          </button>

          {/* Models Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {models?.map((model) => {
              const statusColor = {
                training: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400',
                ready: 'bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400',
                deployed: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400',
                retired: 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400',
              };

              return (
                <div key={model.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">{model.name}</h3>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">{model.algorithm}</p>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">{model.type}</span>
                    <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', statusColor[model.status])}>
                      {model.status.charAt(0).toUpperCase() + model.status.slice(1)}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                      <p className="text-xs text-gray-600 dark:text-gray-400">Accuracy</p>
                      <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{(model.accuracy * 100).toFixed(1)}%</p>
                    </div>
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                      <p className="text-xs text-gray-600 dark:text-gray-400">F1 Score</p>
                      <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{(model.f1_score * 100).toFixed(1)}%</p>
                    </div>
                  </div>

                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Last Trained</span>
                      <span className="text-gray-900 dark:text-white font-medium">{new Date(model.last_trained).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Predictions</span>
                      <span className="text-gray-900 dark:text-white font-medium">{model.predictions_made}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Drift Score</span>
                      <span className="text-gray-900 dark:text-white font-medium">{(model.drift_score * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
