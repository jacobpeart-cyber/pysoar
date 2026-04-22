'use client';

import React, { useState, useEffect } from 'react';
import {
  Bot,
  Brain,
  MessageSquare,
  CheckSquare,
  Zap,
  Clock,
  TrendingUp,
  AlertCircle,
  Send,
  X,
  CheckCircle,
  XCircle,
  RefreshCw,
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import clsx from 'clsx';
import { api } from '../api/client';

type TabId = 'agents' | 'investigations' | 'reasoning' | 'approvals' | 'triage' | 'anomalies' | 'predictions' | 'models';

const priorityColors: Record<string, string> = {
  critical: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20',
  high: 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20',
  medium: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20',
  low: 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20',
};

const severityColors: Record<string, string> = {
  critical: 'text-red-600 dark:text-red-400',
  high: 'text-orange-600 dark:text-orange-400',
  medium: 'text-yellow-600 dark:text-yellow-400',
  low: 'text-blue-600 dark:text-blue-400',
};

const AgenticSOC: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('agents');
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedInvestigation, setSelectedInvestigation] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<Array<{ role: string; text: string }>>([
    { role: 'system', text: 'Hello! I am your Agentic SOC assistant. How can I help?' },
  ]);
  const [chatInput, setChatInput] = useState('');
  const [approvalModal, setApprovalModal] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [chatLoading, setChatLoading] = useState(false);
  const [statusToast, setStatusToast] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // State for API data
  const [agents, setAgents] = useState<any[]>([]);
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<any[]>([]);
  const [reasoningChain, setReasoningChain] = useState<any[]>([]);
  const [timelineData, setTimelineData] = useState<any[]>([]);
  const [agentMetrics, setAgentMetrics] = useState({
    activeAgents: 0,
    openInvestigations: 0,
    avgConfidenceScore: 0,
    actionsPendingApproval: 0,
  });

  // AI Engine absorbed state
  const [aiDashboard, setAiDashboard] = useState<any>(null);
  const [triagedAlerts, setTriagedAlerts] = useState<any[]>([]);
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [anomalyFilter, setAnomalyFilter] = useState<'all' | 'active' | 'confirmed' | 'dismissed'>('all');
  const [predictions, setPredictions] = useState<any[]>([]);
  const [predictionFilter, setPredictionFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [entityTypeFilter, setEntityTypeFilter] = useState('all');
  const [models, setModels] = useState<any[]>([]);
  const [triageLoading, setTriageLoading] = useState(false);
  const [trainLoading, setTrainLoading] = useState(false);

  const showStatus = (type: 'success' | 'error', text: string) => {
    setStatusToast({ type, text });
    setTimeout(() => setStatusToast(null), 4000);
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [agentsRes, investigationsRes, actionsRes] = await Promise.all([
          api.get('/agentic/agents').catch(() => ({ data: { items: [] } })),
          api.get('/agentic/investigations').catch(() => ({ data: { items: [] } })),
          api.get('/agentic/actions/pending-approval').catch(() => ({ data: { items: [] } })),
        ]);

        const agentList = agentsRes?.data?.items || (Array.isArray(agentsRes?.data) ? agentsRes.data : []);
        const invList = investigationsRes?.data?.items || (Array.isArray(investigationsRes?.data) ? investigationsRes.data : []);
        const actionList = actionsRes?.data?.items || (Array.isArray(actionsRes?.data) ? actionsRes.data : []);

        setAgents(agentList);
        setInvestigations(invList);
        setPendingApprovals(actionList);

        // Compute metrics from real data
        const activeCount = agentList.filter((a: any) => a.status === 'active').length;
        const openInv = invList.filter((i: any) => i.status !== 'completed' && i.status !== 'closed').length;
        const avgConf = invList.length > 0
          ? Math.round(invList.reduce((sum: number, i: any) => sum + (i.confidence_score || 0), 0) / (invList.length || 1) * 10) / 10
          : 0;

        setAgentMetrics({
          activeAgents: activeCount || agentList.length,
          openInvestigations: openInv || invList.length,
          avgConfidenceScore: avgConf,
          actionsPendingApproval: actionList.length,
        });

        // Build timeline from investigation timestamps
        const timelineMap: Record<string, number> = {};
        invList.forEach((inv: any) => {
          if (inv.created_at) {
            const hour = new Date(inv.created_at || "").getHours();
            const bucket = `${String(Math.floor(hour / 4) * 4).padStart(2, '0')}:00`;
            timelineMap[bucket] = (timelineMap[bucket] || 0) + 1;
          }
        });
        const buckets = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
        setTimelineData(
          buckets.map((time) => ({ time, investigationsOpen: timelineMap[time] || 0 }))
        );

        // Fetch reasoning chain from first investigation if available
        if (invList.length > 0) {
          try {
            const stepsRes = await api.get(`/agentic/investigations/${invList[0].id}/reasoning-chain`);
            const steps = stepsRes?.data?.steps || [];
            // Only render real recorded reasoning steps. Previously the
            // frontend fabricated a four-step OODA chain with canned
            // strings ("Correlating with threat intelligence…") and a
            // fixed +80 confidence floor whenever the backend returned
            // no steps — customer-facing lie about the agent's actual
            // reasoning. Show empty-state instead.
            setReasoningChain(
              steps.map((s: any, idx: number) => ({
                step: s.step_number || idx + 1,
                stage: s.step_type || 'Analysis',
                description: s.thought_process || s.observation || 'Processing',
                confidence: typeof s.confidence === 'number'
                  ? s.confidence
                  : (typeof s.confidence_delta === 'number'
                      ? Math.max(0, Math.min(100, s.confidence_delta))
                      : null),
              }))
            );
          } catch {
            setReasoningChain([]);
          }
        }
      } catch (err) {
        setError('Failed to load Agentic SOC data. Please try again.');
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  // Load AI Engine data (dashboard, triage, models) once on mount
  useEffect(() => {
    const loadAi = async () => {
      try {
        const [dash, triaged, mdls] = await Promise.all([
          api.get('/ai/dashboard').catch(() => ({ data: null })),
          api.get('/ai/alerts/triaged').catch(() => ({ data: [] })),
          api.get('/ai/models').catch(() => ({ data: [] })),
        ]);
        setAiDashboard(dash?.data || null);
        setTriagedAlerts(Array.isArray(triaged?.data) ? triaged.data : []);
        setModels(Array.isArray(mdls?.data) ? mdls.data : []);
      } catch {
        /* graceful: tabs will show empty states */
      }
    };
    loadAi();
  }, []);

  // Refetch anomalies when filter changes
  useEffect(() => {
    const loadAnomalies = async () => {
      try {
        const res = await api.get('/ai/anomalies', {
          params: anomalyFilter !== 'all' ? { status: anomalyFilter } : {},
        });
        setAnomalies(res.data?.anomalies ?? []);
      } catch {
        setAnomalies([]);
      }
    };
    loadAnomalies();
  }, [anomalyFilter]);

  // Refetch predictions when filters change
  useEffect(() => {
    const loadPredictions = async () => {
      try {
        const res = await api.get('/ai/predictions', {
          params: {
            ...(predictionFilter !== 'all' ? { risk_level: predictionFilter } : {}),
            ...(entityTypeFilter !== 'all' ? { entity_type: entityTypeFilter } : {}),
          },
        });
        setPredictions(Array.isArray(res.data) ? res.data : []);
      } catch {
        setPredictions([]);
      }
    };
    loadPredictions();
  }, [predictionFilter, entityTypeFilter]);

  const handleTriage = async () => {
    setTriageLoading(true);
    try {
      const alertIds = triagedAlerts.map((a) => a.id);
      const res = await api.post('/ai/triage/batch', { alert_ids: alertIds, limit: 10 });
      const count = res.data?.results?.length || res.data?.triaged_count || 0;
      const refresh = await api.get('/ai/alerts/triaged');
      setTriagedAlerts(Array.isArray(refresh?.data) ? refresh.data : []);
      showStatus('success', `Triaged ${count} alerts successfully`);
    } catch {
      showStatus('error', 'Alert triage failed — check API connection');
    } finally {
      setTriageLoading(false);
    }
  };

  const handleAnomalyAction = async (anomalyId: string, action: 'confirm' | 'dismiss') => {
    try {
      const body = action === 'confirm' ? { is_confirmed: true } : { is_false_positive: true };
      await api.post(`/ai/anomalies/${anomalyId}/feedback`, body);
      const res = await api.get('/ai/anomalies', {
        params: anomalyFilter !== 'all' ? { status: anomalyFilter } : {},
      });
      setAnomalies(res.data?.anomalies ?? []);
      showStatus('success', `Anomaly ${action === 'confirm' ? 'confirmed' : 'dismissed'}`);
    } catch {
      showStatus('error', `Failed to ${action} anomaly`);
    }
  };

  const handleTrainModel = async () => {
    setTrainLoading(true);
    try {
      await api.post('/ai/models/train', {
        model_type: 'anomaly_detection',
        algorithm: 'isolation_forest',
        description: 'Auto-trained anomaly detection model',
      });
      const refresh = await api.get('/ai/models');
      setModels(Array.isArray(refresh?.data) ? refresh.data : []);
      showStatus('success', 'Model training initiated successfully');
    } catch {
      showStatus('error', 'Model training failed — check API connection');
    } finally {
      setTrainLoading(false);
    }
  };

  const handleChatSend = async () => {
    if (!chatInput.trim() || chatLoading) return;
    const userMessage = chatInput;
    setChatMessages((prev) => [...prev, { role: 'user', text: userMessage }]);
    setChatInput('');
    setChatLoading(true);
    try {
      const response = await api.post('/agentic/chat', { query: userMessage });
      const reply = response.data?.response || response.data?.answer || 'No response';
      setChatMessages((prev) => [...prev, { role: 'system', text: reply }]);
    } catch {
      setChatMessages((prev) => [...prev, { role: 'system', text: 'Sorry, something went wrong. Please try again.' }]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleApprove = async (id: string) => {
    try {
      await api.post(`/agentic/actions/${id}/approve`, { approved: true });
      setPendingApprovals(prev => prev.filter(a => (a.action_id || a.id) !== id));
    } catch {
      setError('Failed to approve action.');
    }
    setApprovalModal(null);
  };

  const handleDeny = async (id: string) => {
    try {
      await api.post(`/agentic/actions/${id}/approve`, { approved: false });
      setPendingApprovals(prev => prev.filter(a => (a.action_id || a.id) !== id));
    } catch {
      setError('Failed to deny action.');
    }
    setApprovalModal(null);
  };


  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <Bot className="w-8 h-8 text-blue-600 dark:text-blue-400" />
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Agentic SOC</h1>
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            AI-powered security operations with autonomous agents and intelligent reasoning
          </p>
        </div>

        {/* Error Toast */}
        {error && (
          <div className="mb-4 p-4 bg-red-100 dark:bg-red-900 border border-red-300 dark:border-red-700 rounded-lg flex items-center justify-between">
            <p className="text-red-800 dark:text-red-200 text-sm">{error}</p>
            <button onClick={() => setError(null)} className="text-red-600 dark:text-red-300 hover:text-red-800 dark:hover:text-red-100">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="mb-8 flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            <span className="ml-3 text-gray-600 dark:text-gray-400">Loading Agentic SOC data...</span>
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-600 dark:text-gray-400 text-sm font-medium">Active Agents</p>
                <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  {agentMetrics.activeAgents}
                </p>
              </div>
              <Bot className="w-10 h-10 text-blue-500 dark:text-blue-400 opacity-20" />
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-600 dark:text-gray-400 text-sm font-medium">
                  Open Investigations
                </p>
                <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  {agentMetrics.openInvestigations}
                </p>
              </div>
              <Brain className="w-10 h-10 text-purple-500 dark:text-purple-400 opacity-20" />
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-600 dark:text-gray-400 text-sm font-medium">
                  Avg Confidence Score
                </p>
                <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  {agentMetrics.avgConfidenceScore}%
                </p>
              </div>
              <TrendingUp className="w-10 h-10 text-green-500 dark:text-green-400 opacity-20" />
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-600 dark:text-gray-400 text-sm font-medium">
                  Actions Pending
                </p>
                <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  {agentMetrics.actionsPendingApproval}
                </p>
              </div>
              <AlertCircle className="w-10 h-10 text-orange-500 dark:text-orange-400 opacity-20" />
            </div>
          </div>
        </div>

        {/* Status Toast */}
        {statusToast && (
          <div className={clsx('mb-4 p-4 rounded-lg flex items-center gap-3 text-sm font-medium border',
            statusToast.type === 'success'
              ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800'
              : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800')}>
            {statusToast.type === 'success' ? <CheckCircle className="w-5 h-5" /> : <AlertCircle className="w-5 h-5" />}
            {statusToast.text}
          </div>
        )}

        {/* Tabs */}
        <div className="mb-6 flex gap-2 border-b border-gray-200 dark:border-gray-700 overflow-x-auto">
          {([
            { id: 'agents', label: 'Agents' },
            { id: 'investigations', label: 'Investigations' },
            { id: 'reasoning', label: 'Reasoning' },
            { id: 'approvals', label: 'Approvals' },
            { id: 'triage', label: 'Alert Triage' },
            { id: 'anomalies', label: 'Anomalies' },
            { id: 'predictions', label: 'Predictions' },
            { id: 'models', label: 'ML Models' },
          ] as const).map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'px-4 py-3 font-medium text-sm border-b-2 transition whitespace-nowrap',
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-300'
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 mb-8">
          {/* Agents Tab */}
          {activeTab === 'agents' && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">Active Agents</h2>
              {agents.length === 0 ? (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400 text-sm">
                  No agents registered. Agents come online when the backend
                  workers boot.
                </div>
              ) : null}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {agents.map((agent) => (
                  <div
                    key={agent.id}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg dark:hover:shadow-gray-900 transition cursor-pointer"
                    onClick={() => setSelectedAgent(agent.id)}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h3 className="font-semibold text-gray-900 dark:text-white">
                          {agent.name}
                        </h3>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          {(agent.agent_type || '').replace(/_/g, ' ')}
                        </p>
                      </div>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded',
                          agent.status === 'active'
                            ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                            : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
                        )}
                      >
                        {agent.status}
                      </span>
                    </div>

                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600 dark:text-gray-400">Investigations</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                          {agent.total_investigations ?? 0}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600 dark:text-gray-400">Accuracy</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                          {agent.accuracy_score != null ? `${agent.accuracy_score}%` : 'N/A'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600 dark:text-gray-400">Avg Resolution</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                          {agent.avg_resolution_time_minutes != null ? `${Math.round(agent.avg_resolution_time_minutes)}m` : 'N/A'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Investigations Tab */}
          {activeTab === 'investigations' && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
                Investigations Timeline
              </h2>
              <div className="mb-6">
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={timelineData}>
                    <CartesianGrid stroke="#e5e7eb" strokeDasharray="5 5" />
                    <XAxis dataKey="time" stroke="#9ca3af" />
                    <YAxis stroke="#9ca3af" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '0.5rem',
                      }}
                      labelStyle={{ color: '#fff' }}
                    />
                    <Line
                      type="monotone"
                      dataKey="investigationsOpen"
                      stroke="#3b82f6"
                      dot={{ fill: '#3b82f6' }}
                      strokeWidth={2}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-4">
                {investigations.length === 0 ? (
                  <div className="text-center py-8 text-gray-500 dark:text-gray-400 text-sm">
                    No investigations yet. Kick one off from an alert or run
                    an agent against an incident to see it here.
                  </div>
                ) : null}
                {investigations.map((inv) => (
                  <div
                    key={inv.id}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition cursor-pointer"
                    onClick={() => setSelectedInvestigation(inv.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <h3 className="font-semibold text-gray-900 dark:text-white">
                          {inv.title || 'Untitled Investigation'}
                        </h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                          Started {inv.created_at ? new Date(inv.created_at || "").toLocaleString() : 'Unknown'}
                        </p>
                      </div>
                      <div className="text-right">
                        <div
                          className={clsx(
                            'px-3 py-1 text-xs font-medium rounded mb-2',
                            (inv.confidence_score || 0) >= 95
                              ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                              : (inv.confidence_score || 0) >= 85
                                ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                                : 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200'
                          )}
                        >
                          {inv.confidence_score ?? 0}% Confidence
                        </div>
                        <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                          {inv.status || 'Unknown'}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Reasoning Chain Tab */}
          {activeTab === 'reasoning' && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
                OODA Loop - Reasoning Chain
              </h2>
              {reasoningChain.length === 0 ? (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400 text-sm">
                  No reasoning steps recorded yet. An investigation logs steps
                  here as its agent observes, orients, decides, and acts.
                </div>
              ) : null}
              <div className="space-y-4">
                {reasoningChain.map((item, idx) => (
                  <div key={idx} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className="w-10 h-10 rounded-full bg-blue-600 dark:bg-blue-500 text-white flex items-center justify-center font-bold text-sm">
                        {item.step}
                      </div>
                      {idx < reasoningChain.length - 1 && (
                        <div className="w-1 h-12 bg-blue-300 dark:bg-blue-700 mt-2"></div>
                      )}
                    </div>
                    <div className="flex-1 pt-1">
                      <h3 className="font-semibold text-gray-900 dark:text-white">
                        {item.stage}
                      </h3>
                      <p className="text-gray-600 dark:text-gray-400 text-sm mt-1">
                        {item.description}
                      </p>
                      <div className="mt-2 flex items-center gap-2">
                        <span className="text-xs font-medium text-gray-700 dark:text-gray-300">
                          Confidence:
                        </span>
                        <div className="flex-1 max-w-xs bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-green-600 dark:bg-green-500 h-2 rounded-full"
                            style={{ width: `${item.confidence}%` }}
                          ></div>
                        </div>
                        <span className="text-xs font-medium text-gray-700 dark:text-gray-300">
                          {item.confidence}%
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Alert Triage Tab */}
          {activeTab === 'triage' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">Total Analyses</p>
                  <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">{aiDashboard?.total_analyses ?? 0}</p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">Accuracy Rate</p>
                  <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{((aiDashboard?.accuracy_rate ?? 0) * 100).toFixed(1)}%</p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">False Positive Rate</p>
                  <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{((aiDashboard?.false_positive_rate ?? 0) * 100).toFixed(1)}%</p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">Avg Confidence</p>
                  <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{((aiDashboard?.average_confidence ?? 0) * 100).toFixed(1)}%</p>
                </div>
              </div>

              <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 dark:bg-gray-900">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Alert</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">AI Priority</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Confidence</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Reasoning</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                    {triagedAlerts.slice(0, 10).map((alert) => (
                      <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                        <td className="px-4 py-3 text-gray-900 dark:text-white font-medium">{alert.title}</td>
                        <td className="px-4 py-3">
                          <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', priorityColors[alert.ai_priority ?? 'medium'])}>
                            {(alert.ai_priority ?? 'medium').charAt(0).toUpperCase() + (alert.ai_priority ?? 'medium').slice(1)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                              <div className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full" style={{ width: `${(alert.confidence ?? 0) * 100}%` }} />
                            </div>
                            <span className="text-xs text-gray-600 dark:text-gray-400">{((alert.confidence ?? 0) * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400 truncate max-w-md">{alert.reasoning}</td>
                      </tr>
                    ))}
                    {triagedAlerts.length === 0 && (
                      <tr><td colSpan={4} className="px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">No triaged alerts. Click "Triage Pending Alerts" to run AI triage.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>

              <button
                onClick={handleTriage}
                disabled={triageLoading}
                className="px-4 py-2 rounded-lg bg-blue-600 dark:bg-blue-700 text-white hover:bg-blue-700 dark:hover:bg-blue-600 font-medium transition disabled:opacity-50 flex items-center gap-2"
              >
                {triageLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {triageLoading ? 'Triaging...' : 'Triage Pending Alerts'}
              </button>
            </div>
          )}

          {/* Anomalies Tab */}
          {activeTab === 'anomalies' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">Anomalies Detected</p>
                  <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">{aiDashboard?.total_anomalies_detected ?? 0}</p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">Models Deployed</p>
                  <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{aiDashboard?.models_deployed ?? 0}</p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">Avg Model Drift</p>
                  <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{((aiDashboard?.avg_model_drift ?? 0) * 100).toFixed(1)}%</p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5">
                  <p className="text-gray-600 dark:text-gray-400 text-sm">False Positive Rate</p>
                  <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{((aiDashboard?.false_positive_rate ?? 0) * 100).toFixed(1)}%</p>
                </div>
              </div>

              <div className="flex gap-2">
                {(['all', 'active', 'confirmed', 'dismissed'] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setAnomalyFilter(s)}
                    className={clsx(
                      'px-4 py-2 rounded-lg font-medium text-sm transition',
                      anomalyFilter === s
                        ? 'bg-blue-600 dark:bg-blue-700 text-white'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-300 dark:hover:bg-gray-600'
                    )}
                  >
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </button>
                ))}
              </div>

              <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 dark:bg-gray-900">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Time</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Entity</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Score</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Severity</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Description</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                    {anomalies.slice(0, 10).map((a) => (
                      <tr key={a.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                        <td className="px-4 py-3 text-xs text-gray-600 dark:text-gray-400">{a.created_at ? new Date(a.created_at).toLocaleString() : 'N/A'}</td>
                        <td className="px-4 py-3 text-sm font-medium text-gray-900 dark:text-white">{a.entity_id}</td>
                        <td className="px-4 py-3 text-xs text-gray-600 dark:text-gray-400">{a.entity_type}</td>
                        <td className="px-4 py-3">
                          <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div
                              className={clsx('h-2 rounded-full', a.anomaly_score > 0.7 ? 'bg-red-500' : a.anomaly_score > 0.5 ? 'bg-yellow-500' : 'bg-blue-500')}
                              style={{ width: `${(a.anomaly_score ?? 0) * 100}%` }}
                            />
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={clsx('text-sm font-medium', severityColors[a.severity ?? 'medium'])}>
                            {(a.severity ?? 'medium').charAt(0).toUpperCase() + (a.severity ?? 'medium').slice(1)}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-600 dark:text-gray-400 truncate max-w-xs">{a.description}</td>
                        <td className="px-4 py-3 space-x-2 whitespace-nowrap">
                          <button onClick={() => handleAnomalyAction(a.id, 'confirm')} className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-900/40">
                            <CheckCircle className="w-3 h-3" /> Confirm
                          </button>
                          <button onClick={() => handleAnomalyAction(a.id, 'dismiss')} className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600">
                            <XCircle className="w-3 h-3" /> Dismiss
                          </button>
                        </td>
                      </tr>
                    ))}
                    {anomalies.length === 0 && (
                      <tr><td colSpan={7} className="px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">No anomalies in this category.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Predictions Tab */}
          {activeTab === 'predictions' && (
            <div className="space-y-6">
              <div className="flex flex-wrap gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-900 dark:text-white mb-2">Entity Type</label>
                  <select
                    value={entityTypeFilter}
                    onChange={(e) => setEntityTypeFilter(e.target.value)}
                    className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
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
                    className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  >
                    <option value="all">All Levels</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {predictions.slice(0, 9).map((p) => (
                  <div key={p.id ?? p.entity_id} className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5 space-y-4">
                    <div>
                      <p className="text-xs text-gray-600 dark:text-gray-400">Entity</p>
                      <p className="font-semibold text-gray-900 dark:text-white mt-1">{p.entity_id}</p>
                      <p className="text-xs text-gray-500 mt-1">{p.entity_type}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Risk Score</p>
                      <div className="flex items-center gap-3">
                        <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className={clsx('h-full', (p.risk_score ?? 0) > 70 ? 'bg-red-500' : (p.risk_score ?? 0) > 50 ? 'bg-orange-500' : 'bg-green-500')}
                            style={{ width: `${Math.min(p.risk_score ?? 0, 100)}%` }}
                          />
                        </div>
                        <span className="text-lg font-bold text-gray-900 dark:text-white">{(p.risk_score ?? 0).toFixed(0)}</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-white dark:bg-gray-800">
                        <p className="text-xs text-gray-600 dark:text-gray-400">Probability</p>
                        <p className="text-base font-bold text-gray-900 dark:text-white mt-1">{((p.probability ?? 0) * 100).toFixed(0)}%</p>
                      </div>
                      <div className="p-3 rounded-lg bg-white dark:bg-gray-800">
                        <p className="text-xs text-gray-600 dark:text-gray-400">Horizon</p>
                        <p className="text-base font-bold text-gray-900 dark:text-white mt-1">{p.time_horizon_hours ?? 0}h</p>
                      </div>
                    </div>
                    {(p.contributing_factors ?? []).length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-gray-900 dark:text-white mb-1">Factors</p>
                        <ul className="space-y-1">
                          {(p.contributing_factors ?? []).slice(0, 2).map((f: string, idx: number) => (
                            <li key={idx} className="text-xs text-gray-600 dark:text-gray-400 flex items-start gap-2">
                              <span className="text-blue-600 dark:text-blue-400">•</span>
                              <span>{f}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {(p.recommended_actions ?? []).length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-gray-900 dark:text-white mb-1">Actions</p>
                        <ul className="space-y-1">
                          {(p.recommended_actions ?? []).slice(0, 2).map((a: string, idx: number) => (
                            <li key={idx} className="text-xs text-gray-600 dark:text-gray-400 flex items-start gap-2">
                              <span className="text-green-600 dark:text-green-400">→</span>
                              <span>{a}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
                {predictions.length === 0 && (
                  <div className="col-span-full text-center py-8 text-sm text-gray-500 dark:text-gray-400">No threat predictions for the selected filters.</div>
                )}
              </div>
            </div>
          )}

          {/* ML Models Tab */}
          {activeTab === 'models' && (
            <div className="space-y-6">
              <button
                onClick={handleTrainModel}
                disabled={trainLoading}
                className="px-4 py-2 rounded-lg bg-blue-600 dark:bg-blue-700 text-white hover:bg-blue-700 dark:hover:bg-blue-600 font-medium transition disabled:opacity-50 flex items-center gap-2"
              >
                {trainLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Brain className="w-4 h-4" />}
                {trainLoading ? 'Training...' : 'Train New Model'}
              </button>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {models.map((m) => {
                  const statusColor: Record<string, string> = {
                    training: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400',
                    ready: 'bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400',
                    deployed: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400',
                    retired: 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400',
                  };
                  return (
                    <div key={m.id} className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-5 space-y-3">
                      <div>
                        <h3 className="font-semibold text-gray-900 dark:text-white">{m.name}</h3>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">{m.algorithm}</p>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600 dark:text-gray-400">{m.model_type}</span>
                        <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', statusColor[m.status ?? 'ready'])}>
                          {(m.status ?? 'ready').charAt(0).toUpperCase() + (m.status ?? 'ready').slice(1)}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-3 rounded-lg bg-white dark:bg-gray-800">
                          <p className="text-xs text-gray-600 dark:text-gray-400">Accuracy</p>
                          <p className="text-base font-bold text-gray-900 dark:text-white mt-1">{((m.training_metrics?.accuracy ?? 0) * 100).toFixed(1)}%</p>
                        </div>
                        <div className="p-3 rounded-lg bg-white dark:bg-gray-800">
                          <p className="text-xs text-gray-600 dark:text-gray-400">F1 Score</p>
                          <p className="text-base font-bold text-gray-900 dark:text-white mt-1">{((m.training_metrics?.f1 ?? 0) * 100).toFixed(1)}%</p>
                        </div>
                      </div>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Last Trained</span>
                          <span className="text-gray-900 dark:text-white font-medium text-xs">{m.last_trained_at ? new Date(m.last_trained_at).toLocaleDateString() : 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Predictions</span>
                          <span className="text-gray-900 dark:text-white font-medium text-xs">{m.prediction_count ?? 0}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Drift Score</span>
                          <span className="text-gray-900 dark:text-white font-medium text-xs">{((m.drift_score ?? 0) * 100).toFixed(1)}%</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
                {models.length === 0 && (
                  <div className="col-span-full text-center py-8 text-sm text-gray-500 dark:text-gray-400">No ML models. Click "Train New Model" to create one.</div>
                )}
              </div>
            </div>
          )}

          {/* Approvals Tab */}
          {activeTab === 'approvals' && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
                Pending Approvals
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700">
                      <th className="text-left py-3 px-4 font-semibold text-gray-900 dark:text-white">
                        Action
                      </th>
                      <th className="text-left py-3 px-4 font-semibold text-gray-900 dark:text-white">
                        Investigation
                      </th>
                      <th className="text-left py-3 px-4 font-semibold text-gray-900 dark:text-white">
                        Confidence
                      </th>
                      <th className="text-left py-3 px-4 font-semibold text-gray-900 dark:text-white">
                        Risk Score
                      </th>
                      <th className="text-right py-3 px-4 font-semibold text-gray-900 dark:text-white">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {pendingApprovals.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="py-8 text-center text-gray-500 dark:text-gray-400 text-sm">
                          No actions awaiting approval.
                        </td>
                      </tr>
                    ) : null}
                    {pendingApprovals.map((approval) => (
                      <tr
                        key={approval.action_id || approval.id}
                        className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700"
                      >
                        <td className="py-3 px-4 text-gray-900 dark:text-white">
                          {(approval.action_type || 'Unknown').replace(/_/g, ' ')}
                        </td>
                        <td className="py-3 px-4 text-gray-600 dark:text-gray-400">
                          {approval.investigation_title || 'N/A'}
                        </td>
                        <td className="py-3 px-4">
                          <span className="inline-block px-2 py-1 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 rounded text-xs font-medium">
                            {approval.confidence_score ?? 0}%
                          </span>
                        </td>
                        <td className="py-3 px-4 font-medium text-gray-900 dark:text-white">
                          {/* Risk score — falls back to "—" rather than
                              duplicating Confidence. Previous column
                              rendered confidence_score in both cells,
                              labelled Confidence and Risk Score — one
                              was a lie. */}
                          {typeof approval.risk_score === 'number'
                            ? `${approval.risk_score}`
                            : '—'}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => setApprovalModal(approval.action_id || approval.id)}
                            className="text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-200 font-medium text-xs"
                          >
                            Review
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Chat Interface */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
            <MessageSquare className="w-5 h-5" />
            Natural Language Interface
          </h2>

          <div className="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 h-80 overflow-y-auto mb-4 p-4 space-y-3">
            {chatMessages.map((msg, idx) => (
              <div
                key={idx}
                className={clsx(
                  'flex',
                  msg.role === 'user' ? 'justify-end' : 'justify-start'
                )}
              >
                <div
                  className={clsx(
                    'max-w-xs px-4 py-2 rounded-lg',
                    msg.role === 'user'
                      ? 'bg-blue-600 dark:bg-blue-500 text-white'
                      : 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white'
                  )}
                >
                  {msg.text}
                </div>
              </div>
            ))}
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleChatSend()}
              placeholder="Ask me about investigations, agents, or security events..."
              className="flex-1 px-4 py-3 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
            />
            <button
              onClick={handleChatSend}
              className="px-4 py-3 bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition"
            >
              <Send className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>

      {/* Approval Modal */}
      {approvalModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 dark:bg-opacity-70 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-2xl w-full p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <CheckSquare className="w-6 h-6" />
                Approve Action
              </h2>
              <button
                onClick={() => setApprovalModal(null)}
                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {pendingApprovals
              .filter((a) => (a.action_id || a.id) === approvalModal)
              .map((approval) => (
                <div key={approval.action_id || approval.id} className="space-y-4">
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Action</p>
                    <p className="font-semibold text-gray-900 dark:text-white">
                      {(approval.action_type || 'Unknown').replace(/_/g, ' ')}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Investigation</p>
                      <p className="font-semibold text-gray-900 dark:text-white">
                        {approval.investigation_title || 'N/A'}
                      </p>
                    </div>
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">
                        Confidence Score
                      </p>
                      <p className="font-semibold text-green-600 dark:text-green-400">
                        {approval.confidence_score ?? 0}%
                      </p>
                    </div>
                  </div>

                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Agent</p>
                    <p className="font-semibold text-gray-900 dark:text-white">
                      {approval.agent_name || 'N/A'}
                    </p>
                  </div>

                  <div className="flex gap-3 pt-4">
                    <button
                      onClick={() => handleDeny(approval.action_id || approval.id)}
                      className="flex-1 px-4 py-2 border border-gray-200 dark:border-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition"
                    >
                      Deny
                    </button>
                    <button
                      onClick={() => handleApprove(approval.action_id || approval.id)}
                      className="flex-1 px-4 py-2 bg-green-600 dark:bg-green-500 text-white rounded-lg hover:bg-green-700 dark:hover:bg-green-600 transition"
                    >
                      Approve
                    </button>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default AgenticSOC;
