import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Mail,
  Target,
  Users,
  TrendingUp,
  Award,
  Plus,
  X,
  CheckCircle,
  AlertCircle,
  Clock,
  BarChart3,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell, FunnelChart, Funnel } from 'recharts';
import clsx from 'clsx';
import { phishingApi } from '../api/endpoints';


export default function PhishingSimulation() {
  const [activeTab, setActiveTab] = useState<'campaigns' | 'templates' | 'groups' | 'awareness' | 'training'>('campaigns');
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [selectedTraining, setSelectedTraining] = useState<{ id: string; title: string; completions: number; duration: string; certification: boolean } | null>(null);

  const { data: campaigns = [] } = useQuery({ queryKey: ['campaigns'], queryFn: phishingApi.getCampaigns });
  const { data: templates = [] } = useQuery({ queryKey: ['templates'], queryFn: phishingApi.getTemplates });
  const { data: targetGroups = [] } = useQuery({ queryKey: ['targetGroups'], queryFn: phishingApi.getTargetGroups });
  const { data: awarenessScores = [] } = useQuery({ queryKey: ['awarenessScores'], queryFn: phishingApi.getAwarenessScores });

  const stats = useMemo(() => {
    const activeCampaigns = campaigns.filter((c: Campaign) => c.status === 'Active').length;
    const totalClicked = campaigns.reduce((sum: number, c: Campaign) => sum + c.clicked, 0);
    const totalReported = campaigns.reduce((sum: number, c: Campaign) => sum + c.reported, 0);
    const totalSent = campaigns.reduce((sum: number, c: Campaign) => sum + c.sent, 0);
    const avgClickRate = ((totalClicked / totalSent) * 100).toFixed(1);
    const avgReportRate = ((totalReported / totalSent) * 100).toFixed(1);
    const avgAwareness = (awarenessScores.reduce((sum: number, s: AwarenessScore) => sum + s.score, 0) / awarenessScores.length).toFixed(1);
    return { activeCampaigns, avgClickRate, avgReportRate, avgAwareness };
  }, [campaigns, awarenessScores]);

  const funnelData = campaigns[0]
    ? [
        { name: 'Sent', value: campaigns[0].sent },
        { name: 'Opened', value: campaigns[0].opened },
        { name: 'Clicked', value: campaigns[0].clicked },
        { name: 'Submitted', value: campaigns[0].submitted },
        { name: 'Reported', value: campaigns[0].reported },
      ]
    : [];

  const departmentRiskData = targetGroups.map((group: TargetGroup) => ({
    department: group.name,
    risk: group.avgAwarenessScore,
  }));

  const awarenessData = useMemo(() => {
    // Derive awareness trend from awareness scores grouped by department
    const deptScores: Record<string, number[]> = {};
    awarenessScores.forEach((s: AwarenessScore) => {
      if (!deptScores[s.department]) deptScores[s.department] = [];
      deptScores[s.department].push(s.score);
    });
    const depts = Object.keys(deptScores);
    if (depts.length === 0) return [];
    // Use departments as x-axis points with their average scores
    return depts.map((dept) => ({
      month: dept,
      score: Math.round(deptScores[dept].reduce((a, b) => a + b, 0) / deptScores[dept].length),
    }));
  }, [awarenessScores]);

  const trainingData = useMemo(() => {
    // Derive training data from templates (each template represents a training module)
    return templates.map((t: Template, idx: number) => ({
      id: `TR-${String(idx + 1).padStart(3, '0')}`,
      title: t.name,
      completions: t.used || 0,
      duration: t.difficulty === 'Hard' ? '45 min' : t.difficulty === 'Medium' ? '25 min' : '15 min',
      certification: t.difficulty !== 'Easy',
    }));
  }, [templates]);

  const COLORS = ['#06B6D4', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'];

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Mail className="w-8 h-8 text-red-400" />
            Phishing Simulation
          </h1>
          <p className="text-gray-400">Security Awareness Training & User Risk Assessment</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active Campaigns</p>
                <p className="text-3xl font-bold">{stats.activeCampaigns}</p>
              </div>
              <Mail className="w-8 h-8 text-red-400" />
            </div>
          </div>

          <div className={clsx('border rounded-lg p-6 dark:border-gray-700', parseFloat(stats.avgClickRate as string) > 15 ? 'bg-red-900/20 border-red-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Click Rate %</p>
                <p className="text-3xl font-bold">{stats.avgClickRate}%</p>
              </div>
              <AlertCircle className="w-8 h-8 text-yellow-400" />
            </div>
          </div>

          <div className={clsx('border rounded-lg p-6 dark:border-gray-700', parseFloat(stats.avgReportRate as string) < 5 ? 'bg-yellow-900/20 border-yellow-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Report Rate %</p>
                <p className="text-3xl font-bold">{stats.avgReportRate}%</p>
              </div>
              <Target className="w-8 h-8 text-green-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Avg Awareness Score</p>
                <p className="text-3xl font-bold">{stats.avgAwareness}</p>
              </div>
              <Award className="w-8 h-8 text-blue-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-700">
          <div className="flex gap-8">
            {[
              { id: 'campaigns', label: 'Campaigns', icon: Mail },
              { id: 'templates', label: 'Templates', icon: Target },
              { id: 'groups', label: 'Target Groups', icon: Users },
              { id: 'awareness', label: 'Awareness Scores', icon: TrendingUp },
              { id: 'training', label: 'Training', icon: Award },
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

        {/* Campaigns Tab */}
        {activeTab === 'campaigns' && (
          <div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => setShowModal(true)}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New Campaign
              </button>
            </div>

            <div className="mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Campaign Funnel (Latest)</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <FunnelChart margin={{ top: 20, right: 160, bottom: 20, left: 20 }}>
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Funnel dataKey="value" data={funnelData} fill="#8884d8">
                      {funnelData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Funnel>
                  </FunnelChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="space-y-4">
              {campaigns.map((campaign: Campaign) => (
                <div
                  key={campaign.id}
                  onClick={() => setSelectedCampaign(campaign)}
                  className="bg-gray-800 border border-gray-700 rounded-lg p-6 cursor-pointer hover:border-gray-600 transition-colors dark:bg-gray-800 dark:border-gray-700"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">{campaign.name}</h3>
                      <p className="text-sm text-gray-400">{campaign.templateCount} templates | Sent: {campaign.sent.toLocaleString()}</p>
                    </div>
                    <div className="text-right">
                      <span
                        className={clsx(
                          'px-3 py-1 rounded text-xs font-medium',
                          campaign.status === 'Active'
                            ? 'bg-green-900/40 text-green-300'
                            : campaign.status === 'Completed'
                              ? 'bg-blue-900/40 text-blue-300'
                              : 'bg-gray-900/40 text-gray-300'
                        )}
                      >
                        {campaign.status}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-5 gap-4">
                    <div className="bg-gray-700/50 rounded p-3 text-center">
                      <p className="text-xs text-gray-400 mb-1">Opened</p>
                      <p className="text-xl font-bold text-blue-400">{((campaign.opened / campaign.sent) * 100).toFixed(1)}%</p>
                    </div>
                    <div className="bg-gray-700/50 rounded p-3 text-center">
                      <p className="text-xs text-gray-400 mb-1">Clicked</p>
                      <p className="text-xl font-bold text-yellow-400">{campaign.clickRate.toFixed(1)}%</p>
                    </div>
                    <div className="bg-gray-700/50 rounded p-3 text-center">
                      <p className="text-xs text-gray-400 mb-1">Submitted</p>
                      <p className="text-xl font-bold text-red-400">{((campaign.submitted / campaign.sent) * 100).toFixed(1)}%</p>
                    </div>
                    <div className="bg-gray-700/50 rounded p-3 text-center">
                      <p className="text-xs text-gray-400 mb-1">Reported</p>
                      <p className="text-xl font-bold text-green-400">{campaign.reportRate.toFixed(1)}%</p>
                    </div>
                    <div className="bg-gray-700/50 rounded p-3 text-center">
                      <p className="text-xs text-gray-400 mb-1">Total Emails</p>
                      <p className="text-xl font-bold text-white">{campaign.sent.toLocaleString()}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Templates Tab */}
        {activeTab === 'templates' && (
          <div className="grid grid-cols-1 gap-4">
            {templates.map((template: Template) => (
              <div key={template.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-white mb-2">{template.name}</h3>
                    <p className="text-sm text-gray-400 mb-2">{template.category}</p>
                  </div>
                  <div className="text-right">
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium',
                        template.difficulty === 'Hard'
                          ? 'bg-red-900/40 text-red-300'
                          : template.difficulty === 'Medium'
                            ? 'bg-yellow-900/40 text-yellow-300'
                            : 'bg-green-900/40 text-green-300'
                      )}
                    >
                      {template.difficulty} Difficulty
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Effectiveness</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-gray-700 rounded-full dark:bg-gray-700">
                        <div className="h-full bg-orange-500 rounded-full" style={{ width: `${template.effectiveness}%` }} />
                      </div>
                      <span className="text-sm font-semibold text-white">{template.effectiveness}%</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Times Used</p>
                    <p className="text-xl font-bold text-white">{template.used.toLocaleString()}</p>
                  </div>
                  <button
                    onClick={() => {
                      setShowModal(true);
                    }}
                    className="text-blue-400 hover:text-blue-300 font-medium text-sm transition-colors mt-4"
                  >
                    Use Template →
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Target Groups Tab */}
        {activeTab === 'groups' && (
          <div>
            <div className="mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Department Risk Comparison</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={departmentRiskData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="department" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" label={{ value: 'Awareness Score', angle: -90, position: 'insideLeft' }} />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Bar dataKey="risk" fill="#3B82F6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {targetGroups.map((group: TargetGroup) => (
                <div key={group.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-white mb-2">{group.name}</h3>
                      <p className="text-sm text-gray-400">Size: {group.size} employees | Last campaign: {group.lastCampaign}</p>
                    </div>
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium',
                        group.riskLevel === 'Critical'
                          ? 'bg-red-900/40 text-red-300'
                          : group.riskLevel === 'High'
                            ? 'bg-orange-900/40 text-orange-300'
                            : group.riskLevel === 'Medium'
                              ? 'bg-yellow-900/40 text-yellow-300'
                              : 'bg-green-900/40 text-green-300'
                      )}
                    >
                      {group.riskLevel} Risk
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Awareness Score</p>
                      <p className="text-2xl font-bold text-blue-400">{group.avgAwarenessScore}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Team Size</p>
                      <p className="text-2xl font-bold text-white">{group.size}</p>
                    </div>
                    <button
                      onClick={async () => {
                        try {
                          await phishingApi.launchCampaign(group.id);
                        } catch (err) {
                          console.error('Launch campaign failed:', err);
                        }
                      }}
                      className="text-blue-400 hover:text-blue-300 font-medium text-sm transition-colors mt-4"
                    >
                      Launch Campaign →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Awareness Scores Tab */}
        {activeTab === 'awareness' && (
          <div>
            <div className="mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Awareness Score Trend</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={awarenessData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="month" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Line type="monotone" dataKey="score" stroke="#10B981" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Employee</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Department</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Score</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Trend</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Last Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {awarenessScores.map((score: AwarenessScore) => (
                    <tr key={score.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                      <td className="px-6 py-4 text-sm font-medium text-white">{score.name}</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{score.department}</td>
                      <td className="px-6 py-4 text-sm">
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-2 bg-gray-700 rounded-full dark:bg-gray-700">
                            <div
                              className="h-full bg-blue-500 rounded-full"
                              style={{ width: `${score.score}%` }}
                            />
                          </div>
                          <span className={clsx('font-semibold', score.score >= 75 ? 'text-green-400' : score.score >= 50 ? 'text-yellow-400' : 'text-red-400')}>
                            {score.score}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-2 py-1 rounded text-xs font-medium',
                            score.trend === 'up'
                              ? 'bg-green-900/40 text-green-300'
                              : score.trend === 'down'
                                ? 'bg-red-900/40 text-red-300'
                                : 'bg-gray-900/40 text-gray-300'
                          )}
                        >
                          {score.trend === 'up' ? '↑' : score.trend === 'down' ? '↓' : '→'} {score.trend}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">{score.lastAssessment}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Training Tab */}
        {activeTab === 'training' && (
          <div className="space-y-4">
            {trainingData.map((training) => (
              <div key={training.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-white mb-2">{training.title}</h3>
                    <p className="text-sm text-gray-400">Duration: {training.duration}</p>
                  </div>
                  <div className="text-right">
                    {training.certification && (
                      <span className="px-3 py-1 rounded text-xs font-medium bg-blue-900/40 text-blue-300 flex items-center gap-1 w-fit ml-auto mb-2">
                        <Award className="w-3 h-3" />
                        Certification
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Completions</p>
                    <p className="text-2xl font-bold text-white">{training.completions.toLocaleString()}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-xs text-gray-400 mb-2">Completion Rate</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-3 bg-gray-700 rounded-full dark:bg-gray-700">
                        <div
                          className="h-full bg-green-500 rounded-full"
                          style={{ width: `${Math.min((training.completions / 1500) * 100, 100)}%` }}
                        />
                      </div>
                      <button
                        onClick={() => setSelectedTraining(training)}
                        className="text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors"
                      >
                        View →
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Training Detail Modal */}
        {selectedTraining && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">{selectedTraining.title}</h2>
                <button onClick={() => setSelectedTraining(null)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="space-y-4">
                <div><p className="text-sm text-gray-400">Training ID</p><p className="text-white font-mono">{selectedTraining.id}</p></div>
                <div><p className="text-sm text-gray-400">Duration</p><p className="text-white">{selectedTraining.duration}</p></div>
                <div><p className="text-sm text-gray-400">Completions</p><p className="text-2xl font-bold text-white">{selectedTraining.completions.toLocaleString()}</p></div>
                <div><p className="text-sm text-gray-400">Certification</p><p className="text-white">{selectedTraining.certification ? 'Yes' : 'No'}</p></div>
              </div>
              <button onClick={() => setSelectedTraining(null)} className="w-full bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded mt-6 transition-colors">Close</button>
            </div>
          </div>
        )}

        {/* Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New Campaign</h2>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Campaign Name</label>
                  <input
                    type="text"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                    placeholder="e.g., Invoice Scam Q2"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Template</label>
                  <select className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white dark:bg-gray-700 dark:border-gray-600">
                    <option>Select a template...</option>
                    {templates.map((t) => (
                      <option key={t.id}>{t.name}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Target Group</label>
                  <select className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white dark:bg-gray-700 dark:border-gray-600">
                    <option>Select a group...</option>
                    {targetGroups.map((g) => (
                      <option key={g.id}>{g.name}</option>
                    ))}
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
                        await phishingApi.createCampaign({});
                      } catch (err) {
                        console.error('Create campaign failed:', err);
                      } finally {
                        setShowModal(false);
                      }
                    }}
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded transition-colors"
                  >
                    Create Campaign
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedCampaign && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">{selectedCampaign.name}</h2>
                <button
                  onClick={() => setSelectedCampaign(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <p className="text-sm text-gray-400">Status</p>
                  <p className="text-white font-medium">{selectedCampaign.status}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Click Rate</p>
                  <p className="text-2xl font-bold text-yellow-400">{selectedCampaign.clickRate}%</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Report Rate</p>
                  <p className="text-2xl font-bold text-green-400">{selectedCampaign.reportRate}%</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Total Sent</p>
                  <p className="text-white font-medium">{selectedCampaign.sent.toLocaleString()}</p>
                </div>
              </div>

              <button
                onClick={() => setSelectedCampaign(null)}
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
