'use client';

import React, { useState } from 'react';
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
import { agenticApi } from '../api/endpoints';

const mockAgentMetrics = {
  activeAgents: 24,
  openInvestigations: 18,
  avgConfidenceScore: 94.2,
  actionsPendingApproval: 7,
};

const mockAgents = [
  {
    id: 'agent-001',
    name: 'Threat Intel Agent',
    status: 'active',
    type: 'threat_hunting',
    workload: 85,
    accuracy: 96,
    resolutionTime: '2.5h',
  },
  {
    id: 'agent-002',
    name: 'Incident Response Agent',
    status: 'active',
    type: 'incident_response',
    workload: 62,
    accuracy: 94,
    resolutionTime: '1.8h',
  },
  {
    id: 'agent-003',
    name: 'Log Analysis Agent',
    status: 'idle',
    type: 'analysis',
    workload: 22,
    accuracy: 98,
    resolutionTime: '3.2h',
  },
  {
    id: 'agent-004',
    name: 'Malware Detection Agent',
    status: 'active',
    type: 'detection',
    workload: 78,
    accuracy: 92,
    resolutionTime: '2.1h',
  },
  {
    id: 'agent-005',
    name: 'Phishing Analyzer Agent',
    status: 'active',
    type: 'analysis',
    workload: 45,
    accuracy: 99,
    resolutionTime: '0.9h',
  },
  {
    id: 'agent-006',
    name: 'Vulnerability Scout Agent',
    status: 'idle',
    type: 'discovery',
    workload: 18,
    accuracy: 95,
    resolutionTime: '4.5h',
  },
];

const mockInvestigations = [
  {
    id: 'inv-001',
    name: 'SSH Brute Force Campaign',
    confidence: 98,
    status: 'reasoning',
    startTime: '2 hours ago',
    stage: 'Analysis',
  },
  {
    id: 'inv-002',
    name: 'Suspicious API Token Usage',
    confidence: 87,
    status: 'complete',
    startTime: '5 hours ago',
    stage: 'Completed',
  },
  {
    id: 'inv-003',
    name: 'Data Exfiltration Attempt',
    confidence: 92,
    status: 'reasoning',
    startTime: '1 hour ago',
    stage: 'Decision Making',
  },
];

const mockReasoningChain = [
  {
    step: 1,
    stage: 'Observation',
    description: 'Detected 500+ failed SSH login attempts from single IP',
    confidence: 100,
  },
  {
    step: 2,
    stage: 'Orientation',
    description: 'IP traced to known botnet C2 infrastructure',
    confidence: 95,
  },
  {
    step: 3,
    stage: 'Decision',
    description: 'Recommend firewall rule block and threat notification',
    confidence: 92,
  },
  {
    step: 4,
    stage: 'Action',
    description: 'Awaiting approval to implement containment',
    confidence: 92,
  },
];

const mockPendingApprovals = [
  {
    id: 'appr-001',
    action: 'Block IP 192.168.1.100 on firewall',
    investigation: 'SSH Brute Force Campaign',
    confidence: 98,
    riskScore: 9.2,
  },
  {
    id: 'appr-002',
    action: 'Quarantine file hash 7a8f3d...',
    investigation: 'Malware Detection Event',
    confidence: 94,
    riskScore: 8.7,
  },
  {
    id: 'appr-003',
    action: 'Disable user account temporal_admin',
    investigation: 'Suspicious API Token Usage',
    confidence: 87,
    riskScore: 7.5,
  },
];

const mockTimelineData = [
  { time: '00:00', investigationsOpen: 8 },
  { time: '04:00', investigationsOpen: 12 },
  { time: '08:00', investigationsOpen: 15 },
  { time: '12:00', investigationsOpen: 18 },
  { time: '16:00', investigationsOpen: 16 },
  { time: '20:00', investigationsOpen: 18 },
  { time: '24:00', investigationsOpen: 18 },
];

const AgenticSOC: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'agents' | 'investigations' | 'reasoning' | 'approvals'>(
    'agents'
  );
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedInvestigation, setSelectedInvestigation] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<Array<{ role: string; text: string }>>([
    { role: 'system', text: 'Hello! I am your Agentic SOC assistant. How can I help?' },
  ]);
  const [chatInput, setChatInput] = useState('');
  const [approvalModal, setApprovalModal] = useState<string | null>(null);

  const handleChatSend = () => {
    if (chatInput.trim()) {
      setChatMessages([
        ...chatMessages,
        { role: 'user', text: chatInput },
        { role: 'system', text: 'Processing your request...' },
      ]);
      setChatInput('');
    }
  };

  const handleApprove = (id: string) => {
    console.log('Approved:', id);
    setApprovalModal(null);
  };

  const handleDeny = (id: string) => {
    console.log('Denied:', id);
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

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-600 dark:text-gray-400 text-sm font-medium">Active Agents</p>
                <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  {mockAgentMetrics.activeAgents}
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
                  {mockAgentMetrics.openInvestigations}
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
                  {mockAgentMetrics.avgConfidenceScore}%
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
                  {mockAgentMetrics.actionsPendingApproval}
                </p>
              </div>
              <AlertCircle className="w-10 h-10 text-orange-500 dark:text-orange-400 opacity-20" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 flex gap-2 border-b border-gray-200 dark:border-gray-700">
          {(['agents', 'investigations', 'reasoning', 'approvals'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={clsx(
                'px-4 py-3 font-medium text-sm border-b-2 transition',
                activeTab === tab
                  ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-300'
              )}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 mb-8">
          {/* Agents Tab */}
          {activeTab === 'agents' && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">Active Agents</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {mockAgents.map((agent) => (
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
                          {agent.type.replace(/_/g, ' ')}
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
                        <span className="text-gray-600 dark:text-gray-400">Workload</span>
                        <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-blue-600 dark:bg-blue-500 h-2 rounded-full"
                            style={{ width: `${agent.workload}%` }}
                          ></div>
                        </div>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600 dark:text-gray-400">Accuracy</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                          {agent.accuracy}%
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600 dark:text-gray-400">Resolution Time</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                          {agent.resolutionTime}
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
                  <LineChart data={mockTimelineData}>
                    <CartesianGrid stroke="#e5e7eb" strokeDasharray="5 5" />
                    <XAxis stroke="#9ca3af" />
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
                {mockInvestigations.map((inv) => (
                  <div
                    key={inv.id}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition cursor-pointer"
                    onClick={() => setSelectedInvestigation(inv.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <h3 className="font-semibold text-gray-900 dark:text-white">
                          {inv.name}
                        </h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                          Started {inv.startTime}
                        </p>
                      </div>
                      <div className="text-right">
                        <div
                          className={clsx(
                            'px-3 py-1 text-xs font-medium rounded mb-2',
                            inv.confidence >= 95
                              ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                              : inv.confidence >= 85
                                ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                                : 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200'
                          )}
                        >
                          {inv.confidence}% Confidence
                        </div>
                        <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                          {inv.stage}
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
              <div className="space-y-4">
                {mockReasoningChain.map((item, idx) => (
                  <div key={idx} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className="w-10 h-10 rounded-full bg-blue-600 dark:bg-blue-500 text-white flex items-center justify-center font-bold text-sm">
                        {item.step}
                      </div>
                      {idx < mockReasoningChain.length - 1 && (
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
                    {mockPendingApprovals.map((approval) => (
                      <tr
                        key={approval.id}
                        className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700"
                      >
                        <td className="py-3 px-4 text-gray-900 dark:text-white">
                          {approval.action}
                        </td>
                        <td className="py-3 px-4 text-gray-600 dark:text-gray-400">
                          {approval.investigation}
                        </td>
                        <td className="py-3 px-4">
                          <span className="inline-block px-2 py-1 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 rounded text-xs font-medium">
                            {approval.confidence}%
                          </span>
                        </td>
                        <td className="py-3 px-4 font-medium text-gray-900 dark:text-white">
                          {approval.riskScore}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => setApprovalModal(approval.id)}
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

            {mockPendingApprovals
              .filter((a) => a.id === approvalModal)
              .map((approval) => (
                <div key={approval.id} className="space-y-4">
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Action</p>
                    <p className="font-semibold text-gray-900 dark:text-white">
                      {approval.action}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Investigation</p>
                      <p className="font-semibold text-gray-900 dark:text-white">
                        {approval.investigation}
                      </p>
                    </div>
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">
                        Confidence Score
                      </p>
                      <p className="font-semibold text-green-600 dark:text-green-400">
                        {approval.confidence}%
                      </p>
                    </div>
                  </div>

                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Risk Score</p>
                    <p className="font-semibold text-gray-900 dark:text-white">
                      {approval.riskScore}/10
                    </p>
                  </div>

                  <div className="flex gap-3 pt-4">
                    <button
                      onClick={() => handleDeny(approval.id)}
                      className="flex-1 px-4 py-2 border border-gray-200 dark:border-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition"
                    >
                      Deny
                    </button>
                    <button
                      onClick={() => handleApprove(approval.id)}
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
