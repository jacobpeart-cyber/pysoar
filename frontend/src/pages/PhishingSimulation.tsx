import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Mail,
  Target,
  Users,
  TrendingUp,
  Award,
  Plus,
  X,
  AlertCircle,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, Cell } from 'recharts';
import clsx from 'clsx';
import { api } from '../api/client';

// ---------------------------------------------------------------------------
// Types matching actual backend response schemas
// ---------------------------------------------------------------------------

interface Campaign {
  id: string;
  name: string;
  description: string | null;
  campaign_type: string;
  status: string;
  template_id: string | null;
  target_group_id: string | null;
  difficulty_level: string;
  total_targets: number;
  emails_sent: number;
  emails_opened: number;
  links_clicked: number;
  credentials_submitted: number;
  attachments_opened: number;
  reported_count: number;
  start_date: string | null;
  end_date: string | null;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
}

interface Template {
  id: string;
  name: string;
  description: string | null;
  category: string;
  difficulty: string;
  subject_line: string;
  usage_count: number;
  average_click_rate: number;
  created_at: string | null;
}

interface TargetGroupType {
  id: string;
  name: string;
  description: string | null;
  department: string | null;
  member_count: number;
  risk_level: string;
  avg_click_rate: number;
  campaigns_participated: number;
  last_campaign_date: string | null;
  created_at: string | null;
}

interface AwarenessScore {
  id: string;
  user_email: string;
  user_name: string;
  department: string | null;
  overall_score: number;
  phishing_score: number;
  training_completion_rate: number;
  campaigns_participated: number;
  times_clicked: number;
  times_reported: number;
  times_submitted_credentials: number;
  risk_category: string;
  last_failed_campaign: string | null;
  created_at: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractData(data: any): any {
  if (data && typeof data === 'object' && !Array.isArray(data) && 'items' in data) {
    return data.items;
  }
  return data;
}

function safeRate(numerator: number, denominator: number): string {
  if (!denominator) return '0.0';
  return ((numerator / denominator) * 100).toFixed(1);
}

const COLORS = ['#06B6D4', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'];

export default function PhishingSimulation() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'campaigns' | 'templates' | 'groups' | 'awareness' | 'training'>('campaigns');
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [showGroupModal, setShowGroupModal] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ['phishing-campaigns'],
    queryFn: async () => {
      const res = await api.get('/phishing_sim/campaigns');
      return extractData(res.data) ?? [];
    },
  });

  const { data: templates = [] } = useQuery<Template[]>({
    queryKey: ['phishing-templates'],
    queryFn: async () => {
      const res = await api.get('/phishing_sim/templates');
      return extractData(res.data) ?? [];
    },
  });

  const { data: targetGroups = [] } = useQuery<TargetGroupType[]>({
    queryKey: ['phishing-target-groups'],
    queryFn: async () => {
      const res = await api.get('/phishing_sim/target-groups');
      return extractData(res.data) ?? [];
    },
  });

  const { data: awarenessScores = [] } = useQuery<AwarenessScore[]>({
    queryKey: ['phishing-awareness-scores'],
    queryFn: async () => {
      const res = await api.get('/phishing_sim/awareness-scores');
      return extractData(res.data) ?? [];
    },
  });

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  const createCampaignMutation = useMutation({
    mutationFn: async (data: { name: string; description: string; campaign_type: string; target_group_id: string | null }) => {
      const payload: any = { name: data.name, description: data.description, campaign_type: data.campaign_type };
      if (data.target_group_id) payload.target_group_id = data.target_group_id;
      const res = await api.post('/phishing_sim/campaigns', payload);
      return res.data;
    },
    onSuccess: () => {
      setShowModal(false);
      setCreateError(null);
      queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.detail || err?.message || 'Failed to create campaign';
      setCreateError(typeof msg === 'string' ? msg : JSON.stringify(msg));
    },
  });

  const createGroupMutation = useMutation({
    mutationFn: async (data: { name: string; description: string; department: string }) => {
      const res = await api.post('/phishing_sim/target-groups', data);
      return res.data;
    },
    onSuccess: () => {
      setShowGroupModal(false);
      queryClient.invalidateQueries({ queryKey: ['phishing-target-groups'] });
    },
  });

  // ---------------------------------------------------------------------------
  // Derived Stats
  // ---------------------------------------------------------------------------

  const stats = useMemo(() => {
    const activeCampaigns = campaigns.filter((c) => c.status === 'active' || c.status === 'Active' || c.status === 'running').length;
    const totalSent = campaigns.reduce((sum, c) => sum + (c.emails_sent || 0), 0);
    const totalClicked = campaigns.reduce((sum, c) => sum + (c.links_clicked || 0), 0);
    const totalReported = campaigns.reduce((sum, c) => sum + (c.reported_count || 0), 0);
    const avgClickRate = safeRate(totalClicked, totalSent);
    const avgReportRate = safeRate(totalReported, totalSent);
    const avgAwareness = awarenessScores.length > 0
      ? (awarenessScores.reduce((sum, s) => sum + s.overall_score, 0) / awarenessScores.length).toFixed(1)
      : '0';
    return { activeCampaigns, avgClickRate, avgReportRate, avgAwareness };
  }, [campaigns, awarenessScores]);

  const funnelData = campaigns[0]
    ? [
        { name: 'Sent', value: campaigns[0].emails_sent },
        { name: 'Opened', value: campaigns[0].emails_opened },
        { name: 'Clicked', value: campaigns[0].links_clicked },
        { name: 'Submitted', value: campaigns[0].credentials_submitted },
        { name: 'Reported', value: campaigns[0].reported_count },
      ]
    : [];

  const departmentRiskData = useMemo(() => {
    const deptScores: Record<string, number[]> = {};
    awarenessScores.forEach((s) => {
      const dept = s.department || 'Unknown';
      if (!deptScores[dept]) deptScores[dept] = [];
      deptScores[dept].push(s.overall_score);
    });
    return Object.entries(deptScores).map(([dept, scores]) => ({
      department: dept,
      score: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
    }));
  }, [awarenessScores]);

  // Real training modules from /phishing_sim/training/modules.
  // Previously this derived fake "TR-XXX" training records from email
  // templates with hardcoded durations ('hard' → 45min, 'medium' →
  // 25min, 'easy' → 15min) and a synthetic completion count =
  // template.usage_count divided by 1500. None of that reflected the
  // actual training catalog.
  const { data: trainingModulesRaw } = useQuery({
    queryKey: ['phishing-training-modules'],
    queryFn: async () => {
      try {
        const res = await api.get('/phishing_sim/training/modules');
        return res.data;
      } catch {
        return null;
      }
    },
  });
  const trainingData = useMemo(() => {
    const items = Array.isArray(trainingModulesRaw)
      ? trainingModulesRaw
      : (trainingModulesRaw as any)?.items ?? [];
    return items.map((m: any) => ({
      id: m.id,
      title: m.title ?? m.name ?? 'Training module',
      completions: m.completion_count ?? m.completions ?? 0,
      duration: m.duration_minutes ? `${m.duration_minutes} min` : (m.duration ?? '—'),
      certification: !!(m.is_certification ?? m.certification),
      difficulty: m.difficulty ?? m.difficulty_level ?? null,
    }));
  }, [trainingModulesRaw]);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

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
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active Campaigns</p>
                <p className="text-3xl font-bold">{stats.activeCampaigns}</p>
              </div>
              <Mail className="w-8 h-8 text-red-400" />
            </div>
          </div>

          <div className={clsx('border rounded-lg p-6', parseFloat(stats.avgClickRate) > 15 ? 'bg-red-900/20 border-red-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Click Rate %</p>
                <p className="text-3xl font-bold">{stats.avgClickRate}%</p>
              </div>
              <AlertCircle className="w-8 h-8 text-yellow-400" />
            </div>
          </div>

          <div className={clsx('border rounded-lg p-6', parseFloat(stats.avgReportRate) < 5 ? 'bg-yellow-900/20 border-yellow-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Report Rate %</p>
                <p className="text-3xl font-bold">{stats.avgReportRate}%</p>
              </div>
              <Target className="w-8 h-8 text-green-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
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

        {/* ================================================================= */}
        {/* Campaigns Tab                                                      */}
        {/* ================================================================= */}
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

            {/* Funnel Chart */}
            {funnelData.length > 0 && (
              <div className="mb-8">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4">Campaign Funnel (Latest)</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={funnelData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis type="number" stroke="#9CA3AF" />
                      <YAxis type="category" dataKey="name" stroke="#9CA3AF" width={80} />
                      <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                      <Bar dataKey="value" fill="#3B82F6">
                        {funnelData.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Campaign List */}
            {campaigns.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Mail className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No campaigns yet. Create your first phishing simulation campaign.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {campaigns.map((campaign) => (
                  <div
                    key={campaign.id}
                    onClick={() => setSelectedCampaign(campaign)}
                    className="bg-gray-800 border border-gray-700 rounded-lg p-6 cursor-pointer hover:border-gray-600 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-lg font-semibold text-white mb-2">{campaign.name}</h3>
                        <p className="text-sm text-gray-400">{campaign.campaign_type} | Sent: {(campaign.emails_sent || 0).toLocaleString()}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        {(campaign.status === 'draft' || campaign.status === 'scheduled') && (
                          <button
                            onClick={async (e) => {
                              e.stopPropagation();
                              try {
                                // Resolve total_targets — either from the campaign's
                                // linked target group, a prior field, or prompt the user.
                                let totalTargets = (campaign as any).total_targets || 0;
                                if (!totalTargets) {
                                  const entered = window.prompt('How many targets to include in this launch?', '10');
                                  totalTargets = parseInt(entered || '0', 10);
                                }
                                if (!totalTargets || totalTargets < 1) return;
                                await api.post(`/phishing_sim/campaigns/${campaign.id}/launch`, {
                                  total_targets: totalTargets,
                                });
                                queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
                              } catch (err: any) {
                                const msg = err?.response?.data?.detail || err?.message || 'Failed to launch campaign';
                                alert(msg);
                              }
                            }}
                            className="px-3 py-1 rounded text-xs font-medium bg-green-600 hover:bg-green-700 text-white transition-colors"
                          >
                            Launch
                          </button>
                        )}
                        {/* Pause / Resume / End — backend endpoints
                            have always existed; the UI previously
                            exposed no way to govern a campaign after
                            launch, so once running a campaign could
                            only be watched from the sidelines. */}
                        {(campaign.status === 'active' || campaign.status === 'running') && (
                          <>
                            <button
                              onClick={async (e) => {
                                e.stopPropagation();
                                try {
                                  await api.post(`/phishing_sim/campaigns/${campaign.id}/pause`);
                                  queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
                                } catch (err: any) {
                                  alert(err?.response?.data?.detail || err?.message || 'Failed to pause');
                                }
                              }}
                              className="px-3 py-1 rounded text-xs font-medium bg-yellow-600 hover:bg-yellow-700 text-white transition-colors"
                            >
                              Pause
                            </button>
                            <button
                              onClick={async (e) => {
                                e.stopPropagation();
                                if (!window.confirm('End campaign now? No more emails will be sent.')) return;
                                try {
                                  await api.post(`/phishing_sim/campaigns/${campaign.id}/end`);
                                  queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
                                } catch (err: any) {
                                  alert(err?.response?.data?.detail || err?.message || 'Failed to end');
                                }
                              }}
                              className="px-3 py-1 rounded text-xs font-medium bg-red-600 hover:bg-red-700 text-white transition-colors"
                            >
                              End
                            </button>
                          </>
                        )}
                        {campaign.status === 'paused' && (
                          <button
                            onClick={async (e) => {
                              e.stopPropagation();
                              try {
                                await api.post(`/phishing_sim/campaigns/${campaign.id}/resume`);
                                queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
                              } catch (err: any) {
                                alert(err?.response?.data?.detail || err?.message || 'Failed to resume');
                              }
                            }}
                            className="px-3 py-1 rounded text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors"
                          >
                            Resume
                          </button>
                        )}
                        <span
                          className={clsx(
                            'px-3 py-1 rounded text-xs font-medium',
                            campaign.status === 'active' || campaign.status === 'running'
                              ? 'bg-green-900/40 text-green-300'
                              : campaign.status === 'completed'
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
                        <p className="text-xl font-bold text-blue-400">{safeRate(campaign.emails_opened, campaign.emails_sent)}%</p>
                      </div>
                      <div className="bg-gray-700/50 rounded p-3 text-center">
                        <p className="text-xs text-gray-400 mb-1">Clicked</p>
                        <p className="text-xl font-bold text-yellow-400">{safeRate(campaign.links_clicked, campaign.emails_sent)}%</p>
                      </div>
                      <div className="bg-gray-700/50 rounded p-3 text-center">
                        <p className="text-xs text-gray-400 mb-1">Submitted</p>
                        <p className="text-xl font-bold text-red-400">{safeRate(campaign.credentials_submitted, campaign.emails_sent)}%</p>
                      </div>
                      <div className="bg-gray-700/50 rounded p-3 text-center">
                        <p className="text-xs text-gray-400 mb-1">Reported</p>
                        <p className="text-xl font-bold text-green-400">{safeRate(campaign.reported_count, campaign.emails_sent)}%</p>
                      </div>
                      <div className="bg-gray-700/50 rounded p-3 text-center">
                        <p className="text-xs text-gray-400 mb-1">Total Emails</p>
                        <p className="text-xl font-bold text-white">{(campaign.emails_sent || 0).toLocaleString()}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* Templates Tab                                                      */}
        {/* ================================================================= */}
        {activeTab === 'templates' && (
          <div className="grid grid-cols-1 gap-4">
            {templates.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Target className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No templates configured yet.</p>
              </div>
            ) : (
              templates.map((template) => (
                <div key={template.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-white mb-2">{template.name}</h3>
                      <p className="text-sm text-gray-400 mb-1">{template.category}</p>
                      {template.subject_line && (
                        <p className="text-xs text-gray-500">Subject: {template.subject_line}</p>
                      )}
                    </div>
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium',
                        template.difficulty === 'hard' || template.difficulty === 'Hard'
                          ? 'bg-red-900/40 text-red-300'
                          : template.difficulty === 'medium' || template.difficulty === 'Medium'
                            ? 'bg-yellow-900/40 text-yellow-300'
                            : 'bg-green-900/40 text-green-300'
                      )}
                    >
                      {template.difficulty} Difficulty
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Avg Click Rate</p>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-2 bg-gray-700 rounded-full">
                          <div className="h-full bg-orange-500 rounded-full" style={{ width: `${Math.min(template.average_click_rate * 100, 100)}%` }} />
                        </div>
                        <span className="text-sm font-semibold text-white">{(template.average_click_rate * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Times Used</p>
                      <p className="text-xl font-bold text-white">{(template.usage_count || 0).toLocaleString()}</p>
                    </div>
                    <button
                      onClick={() => setShowModal(true)}
                      className="text-blue-400 hover:text-blue-300 font-medium text-sm transition-colors mt-4"
                    >
                      Use Template &rarr;
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* Target Groups Tab                                                  */}
        {/* ================================================================= */}
        {activeTab === 'groups' && (
          <div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => setShowGroupModal(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New Target Group
              </button>
            </div>
            {/* Department Risk Chart */}
            {departmentRiskData.length > 0 && (
              <div className="mb-8">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4">Department Awareness Comparison</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={departmentRiskData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="department" stroke="#9CA3AF" />
                      <YAxis stroke="#9CA3AF" label={{ value: 'Awareness Score', angle: -90, position: 'insideLeft' }} />
                      <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                      <Bar dataKey="score" fill="#3B82F6" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Group List */}
            {targetGroups.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No target groups configured yet.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-4">
                {targetGroups.map((group) => (
                  <div key={group.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">{group.name}</h3>
                        <p className="text-sm text-gray-400">
                          {group.member_count} members
                          {group.department && ` | ${group.department}`}
                          {group.last_campaign_date && ` | Last campaign: ${new Date(group.last_campaign_date).toLocaleDateString()}`}
                        </p>
                      </div>
                      <span
                        className={clsx(
                          'px-3 py-1 rounded text-xs font-medium',
                          group.risk_level === 'critical'
                            ? 'bg-red-900/40 text-red-300'
                            : group.risk_level === 'high'
                              ? 'bg-orange-900/40 text-orange-300'
                              : group.risk_level === 'medium'
                                ? 'bg-yellow-900/40 text-yellow-300'
                                : 'bg-green-900/40 text-green-300'
                        )}
                      >
                        {group.risk_level || 'Unknown'} Risk
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Avg Click Rate</p>
                        <p className="text-2xl font-bold text-yellow-400">{(group.avg_click_rate * 100).toFixed(1)}%</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Campaigns</p>
                        <p className="text-2xl font-bold text-white">{group.campaigns_participated}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Team Size</p>
                        <p className="text-2xl font-bold text-white">{group.member_count}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* Awareness Scores Tab                                               */}
        {/* ================================================================= */}
        {activeTab === 'awareness' && (
          <div>
            {/* Department Awareness Chart */}
            {departmentRiskData.length > 0 && (
              <div className="mb-8">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4">Awareness Score by Department</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={departmentRiskData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="department" stroke="#9CA3AF" />
                      <YAxis stroke="#9CA3AF" />
                      <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                      <Line type="monotone" dataKey="score" stroke="#10B981" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Scores Table */}
            {awarenessScores.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <TrendingUp className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No awareness scores calculated yet.</p>
              </div>
            ) : (
              <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-700/50 border-b border-gray-700">
                    <tr>
                      <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">User</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Department</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Score</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Risk</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Campaigns</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Clicked</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Reported</th>
                    </tr>
                  </thead>
                  <tbody>
                    {awarenessScores.map((score) => (
                      <tr key={score.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                        <td className="px-6 py-4 text-sm">
                          <div>
                            <p className="font-medium text-white">{score.user_name || score.user_email}</p>
                            <p className="text-xs text-gray-500">{score.user_email}</p>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-300">{score.department || '--'}</td>
                        <td className="px-6 py-4 text-sm">
                          <div className="flex items-center gap-2">
                            <div className="w-20 h-2 bg-gray-700 rounded-full">
                              <div
                                className="h-full bg-blue-500 rounded-full"
                                style={{ width: `${score.overall_score}%` }}
                              />
                            </div>
                            <span className={clsx('font-semibold', score.overall_score >= 75 ? 'text-green-400' : score.overall_score >= 50 ? 'text-yellow-400' : 'text-red-400')}>
                              {score.overall_score}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm">
                          <span
                            className={clsx(
                              'px-2 py-1 rounded text-xs font-medium',
                              score.risk_category === 'high' || score.risk_category === 'critical'
                                ? 'bg-red-900/40 text-red-300'
                                : score.risk_category === 'medium'
                                  ? 'bg-yellow-900/40 text-yellow-300'
                                  : 'bg-green-900/40 text-green-300'
                            )}
                          >
                            {score.risk_category || 'unknown'}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-300">{score.campaigns_participated}</td>
                        <td className="px-6 py-4 text-sm text-red-400">{score.times_clicked}</td>
                        <td className="px-6 py-4 text-sm text-green-400">{score.times_reported}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* Training Tab                                                       */}
        {/* ================================================================= */}
        {activeTab === 'training' && (
          <div className="space-y-4">
            {trainingData.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Award className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No training modules available.</p>
              </div>
            ) : (
              trainingData.map((training) => (
                <div key={training.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-white mb-2">{training.title}</h3>
                      <p className="text-sm text-gray-400">Duration: {training.duration}</p>
                    </div>
                    {training.certification && (
                      <span className="px-3 py-1 rounded text-xs font-medium bg-blue-900/40 text-blue-300 flex items-center gap-1">
                        <Award className="w-3 h-3" />
                        Certification
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Completions</p>
                      <p className="text-2xl font-bold text-white">{training.completions.toLocaleString()}</p>
                    </div>
                    <div className="col-span-2">
                      <p className="text-xs text-gray-400 mb-2">Completion Rate</p>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-3 bg-gray-700 rounded-full">
                          <div
                            className="h-full bg-green-500 rounded-full"
                            style={{ width: `${Math.min((training.completions / 1500) * 100, 100)}%` }}
                          />
                        </div>
                        <span className="text-sm text-gray-400">{Math.min(Math.round((training.completions / 1500) * 100), 100)}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* Campaign Detail Modal                                              */}
        {/* ================================================================= */}
        {selectedCampaign && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">{selectedCampaign.name}</h2>
                <button onClick={() => setSelectedCampaign(null)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <p className="text-sm text-gray-400">Status</p>
                  <p className="text-white font-medium">{selectedCampaign.status}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Type</p>
                  <p className="text-white font-medium">{selectedCampaign.campaign_type}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Click Rate</p>
                  <p className="text-2xl font-bold text-yellow-400">{safeRate(selectedCampaign.links_clicked, selectedCampaign.emails_sent)}%</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Report Rate</p>
                  <p className="text-2xl font-bold text-green-400">{safeRate(selectedCampaign.reported_count, selectedCampaign.emails_sent)}%</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Total Sent</p>
                  <p className="text-white font-medium">{(selectedCampaign.emails_sent || 0).toLocaleString()}</p>
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

        {/* ================================================================= */}
        {/* New Campaign Modal                                                 */}
        {/* ================================================================= */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New Campaign</h2>
                <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              {createError && (
                <div className="bg-red-900/30 border border-red-700 rounded p-3 text-sm text-red-300 mb-4">{createError}</div>
              )}

              <form className="space-y-4" onSubmit={async (e) => {
                e.preventDefault();
                setCreateError(null);
                const fd = new FormData(e.currentTarget);
                const groupVal = fd.get('group') as string;
                createCampaignMutation.mutate({
                  name: fd.get('name') as string,
                  description: (fd.get('description') as string) || '',
                  campaign_type: (fd.get('campaign_type') as string) || 'email_phishing',
                  target_group_id: groupVal || null,
                });
              }}>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Campaign Name</label>
                  <input name="name" required type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="e.g., Invoice Scam Q2" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                  <input name="description" type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="Campaign description" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Campaign Type</label>
                  <select name="campaign_type" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="email_phishing">Email Phishing</option>
                    <option value="spear_phishing">Spear Phishing</option>
                    <option value="smishing">Smishing</option>
                    <option value="vishing">Vishing</option>
                    <option value="business_email_compromise">Business Email Compromise</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Target Group</label>
                  <select name="group" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="">{targetGroups.length === 0 ? 'No groups — create one first' : 'Select a group (optional)...'}</option>
                    {targetGroups.map((g) => (<option key={g.id} value={g.id}>{g.name}</option>))}
                  </select>
                </div>
                <div className="flex gap-4 mt-6">
                  <button type="button" onClick={() => { setShowModal(false); setCreateError(null); }} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors">Cancel</button>
                  <button type="submit" disabled={createCampaignMutation.isPending} className="flex-1 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded transition-colors disabled:opacity-50">
                    {createCampaignMutation.isPending ? 'Creating...' : 'Create Campaign'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Create Target Group Modal */}
        {showGroupModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New Target Group</h2>
                <button onClick={() => setShowGroupModal(false)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <form className="space-y-4" onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                createGroupMutation.mutate({
                  name: fd.get('name') as string,
                  description: (fd.get('description') as string) || '',
                  department: (fd.get('department') as string) || '',
                });
              }}>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Group Name</label>
                  <input name="name" required type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="e.g., Engineering Team" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                  <input name="description" type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="Group description" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Department</label>
                  <input name="department" type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="e.g., Engineering, Finance, HR" />
                </div>
                <div className="flex gap-4 mt-6">
                  <button type="button" onClick={() => setShowGroupModal(false)} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors">Cancel</button>
                  <button type="submit" disabled={createGroupMutation.isPending} className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors disabled:opacity-50">
                    {createGroupMutation.isPending ? 'Creating...' : 'Create Group'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
