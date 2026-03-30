import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  UserCheck,
  FileText,
  Scale,
  Clock,
  AlertTriangle,
  ChevronDown,
  Plus,
  X,
  Download,
  Filter,
  TrendingUp,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import clsx from 'clsx';
import { privacyApi } from '../api/endpoints';


export default function PrivacyDashboard() {
  const [activeTab, setActiveTab] = useState<'dsr' | 'pia' | 'consent' | 'ropa' | 'incidents'>('dsr');
  const [selectedDSR, setSelectedDSR] = useState<DSRRecord | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [filterStatus, setFilterStatus] = useState('All');

  const { data: dsrData = [] } = useQuery({ queryKey: ['dsr'], queryFn: privacyApi.getDSRs });
  const { data: piaData = [] } = useQuery({ queryKey: ['pia'], queryFn: privacyApi.getPIAs });
  const { data: consentData = [] } = useQuery({ queryKey: ['consent'], queryFn: privacyApi.getConsentRecords });
  const { data: processingData = [] } = useQuery({ queryKey: ['processing'], queryFn: privacyApi.getProcessingRecords });
  const { data: incidentData = [] } = useQuery({ queryKey: ['incidents'], queryFn: privacyApi.getIncidents });

  const dsrStats = useMemo(() => {
    const open = dsrData.filter((d: DSRRecord) => d.status !== 'Completed').length;
    const atRisk = dsrData.filter((d: DSRRecord) => d.daysLeft <= 7).length;
    const consentRate = ((consentData.filter((c: ConsentRecord) => c.status === 'Active').length / consentData.length) * 100).toFixed(1);
    const activePIAs = piaData.filter((p: PIARecord) => p.status === 'In Progress').length;
    return { open, atRisk, consentRate, activePIAs };
  }, [dsrData, consentData, piaData]);

  const filteredDSR = useMemo(() => {
    if (filterStatus === 'All') return dsrData;
    return dsrData.filter((d: DSRRecord) => d.status === filterStatus);
  }, [dsrData, filterStatus]);

  const riskDistribution = [
    { risk: 'High', count: piaData.filter((p: PIARecord) => p.risk === 'High').length },
    { risk: 'Medium', count: piaData.filter((p: PIARecord) => p.risk === 'Medium').length },
    { risk: 'Low', count: piaData.filter((p: PIARecord) => p.risk === 'Low').length },
  ];

  const consentTrend = [
    { month: 'Jan', active: 80, withdrawn: 20 },
    { month: 'Feb', active: 85, withdrawn: 15 },
    { month: 'Mar', active: 78, withdrawn: 22 },
  ];

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Scale className="w-8 h-8 text-blue-400" />
            Privacy Dashboard
          </h1>
          <p className="text-gray-400">GDPR, CCPA, LGPD & Data Subject Rights Management</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Open Data Subject Requests</p>
                <p className="text-3xl font-bold">{dsrStats.open}</p>
              </div>
              <UserCheck className="w-8 h-8 text-green-400" />
            </div>
          </div>

          <div className={clsx('border rounded-lg p-6 dark:border-gray-700', dsrStats.atRisk > 2 ? 'bg-red-900/20 border-red-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Deadline Approaching (7d)</p>
                <p className="text-3xl font-bold">{dsrStats.atRisk}</p>
              </div>
              <Clock className="w-8 h-8 text-yellow-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Consent Rate</p>
                <p className="text-3xl font-bold">{dsrStats.consentRate}%</p>
              </div>
              <TrendingUp className="w-8 h-8 text-blue-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active PIAs</p>
                <p className="text-3xl font-bold">{dsrStats.activePIAs}</p>
              </div>
              <FileText className="w-8 h-8 text-purple-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-700">
          <div className="flex gap-8">
            {[
              { id: 'dsr', label: 'Data Subject Requests', icon: UserCheck },
              { id: 'pia', label: 'Privacy Impact Assessments', icon: FileText },
              { id: 'consent', label: 'Consent Records', icon: Scale },
              { id: 'ropa', label: 'Processing Records', icon: Clock },
              { id: 'incidents', label: 'Privacy Incidents', icon: AlertTriangle },
            ].map((tab) => {
              const TabIcon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={clsx(
                    'pb-4 px-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-blue-400 text-blue-400'
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

        {/* DSR Tab */}
        {activeTab === 'dsr' && (
          <div>
            <div className="mb-6 flex justify-between items-center">
              <div className="flex gap-4">
                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="bg-gray-800 border border-gray-700 rounded px-4 py-2 text-white dark:bg-gray-800 dark:border-gray-700"
                >
                  <option>All</option>
                  <option>In Progress</option>
                  <option>Pending</option>
                  <option>At Risk</option>
                  <option>Completed</option>
                </select>
              </div>
              <button
                onClick={() => setShowModal(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New DSR
              </button>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Request ID</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Type</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Regulation</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Deadline</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Days Left</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDSR.map((row: DSRRecord) => (
                    <tr
                      key={row.id}
                      onClick={() => setSelectedDSR(row)}
                      className="border-t border-gray-700 hover:bg-gray-700/50 cursor-pointer transition-colors"
                    >
                      <td className="px-6 py-4 text-sm font-mono text-blue-400">{row.id}</td>
                      <td className="px-6 py-4 text-sm text-white">{row.type}</td>
                      <td className="px-6 py-4 text-sm">
                        <span className="bg-gray-700 text-gray-200 px-3 py-1 rounded text-xs dark:bg-gray-700">
                          {row.regulation}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">{row.deadline}</td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-3 py-1 rounded text-xs font-medium',
                            row.status === 'Completed'
                              ? 'bg-green-900/40 text-green-300'
                              : row.status === 'At Risk'
                                ? 'bg-red-900/40 text-red-300'
                                : row.status === 'In Progress'
                                  ? 'bg-blue-900/40 text-blue-300'
                                  : 'bg-gray-900/40 text-gray-300'
                          )}
                        >
                          {row.status}
                        </span>
                      </td>
                      <td className={clsx('px-6 py-4 text-sm font-semibold', row.daysLeft <= 7 ? 'text-red-400' : 'text-green-400')}>
                        {row.daysLeft}d
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* PIA Tab */}
        {activeTab === 'pia' && (
          <div>
            <div className="grid grid-cols-2 gap-8 mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Risk Distribution</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={riskDistribution}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="risk" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Bar dataKey="count" fill="#3B82F6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-4">
                {piaData.map((pia: PIARecord) => (
                  <div key={pia.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4 dark:bg-gray-800 dark:border-gray-700">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-semibold text-white">{pia.name}</h4>
                      <span
                        className={clsx(
                          'px-2 py-1 rounded text-xs font-medium',
                          pia.risk === 'High'
                            ? 'bg-red-900/40 text-red-300'
                            : pia.risk === 'Medium'
                              ? 'bg-yellow-900/40 text-yellow-300'
                              : 'bg-green-900/40 text-green-300'
                        )}
                      >
                        {pia.risk} Risk
                      </span>
                    </div>
                    <p className="text-sm text-gray-400 mb-2">
                      Status:{' '}
                      <span
                        className={clsx(
                          'font-medium',
                          pia.status === 'Approved' ? 'text-green-400' : 'text-blue-400'
                        )}
                      >
                        {pia.status}
                      </span>
                    </p>
                    <div className="flex justify-between text-xs text-gray-500">
                      <span>Start: {pia.startDate}</span>
                      <span>{pia.completionDate || pia.completionTarget}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Consent Tab */}
        {activeTab === 'consent' && (
          <div>
            <div className="grid grid-cols-2 gap-8 mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Consent Trend</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={consentTrend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="month" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Legend />
                    <Line type="monotone" dataKey="active" stroke="#10B981" strokeWidth={2} />
                    <Line type="monotone" dataKey="withdrawn" stroke="#EF4444" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
                <div className="max-h-96 overflow-y-auto">
                  <table className="w-full">
                    <thead className="bg-gray-700/50 sticky top-0">
                      <tr>
                        <th className="px-4 py-3 text-left text-sm font-semibold text-gray-300">Email</th>
                        <th className="px-4 py-3 text-left text-sm font-semibold text-gray-300">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {consentData.map((record: ConsentRecord) => (
                        <tr key={record.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                          <td className="px-4 py-3 text-sm text-gray-300">{record.email}</td>
                          <td className="px-4 py-3 text-sm">
                            <span
                              className={clsx(
                                'px-2 py-1 rounded text-xs font-medium',
                                record.status === 'Active'
                                  ? 'bg-green-900/40 text-green-300'
                                  : record.status === 'Withdrawn'
                                    ? 'bg-red-900/40 text-red-300'
                                    : 'bg-gray-900/40 text-gray-300'
                              )}
                            >
                              {record.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ROPA Tab */}
        {activeTab === 'ropa' && (
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
            <table className="w-full">
              <thead className="bg-gray-700/50 border-b border-gray-700">
                <tr>
                  <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Processor</th>
                  <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Data Category</th>
                  <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Legal Basis</th>
                  <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Retention</th>
                  <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Purpose</th>
                </tr>
              </thead>
              <tbody>
                {processingData.map((record: ProcessingRecord) => (
                  <tr key={record.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                    <td className="px-6 py-4 text-sm text-white font-medium">{record.processor}</td>
                    <td className="px-6 py-4 text-sm text-gray-300">{record.dataCategory}</td>
                    <td className="px-6 py-4 text-sm text-gray-300">{record.legalBasis}</td>
                    <td className="px-6 py-4 text-sm text-gray-300">{record.retentionPeriod}</td>
                    <td className="px-6 py-4 text-sm text-gray-300">{record.purpose}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Incidents Tab */}
        {activeTab === 'incidents' && (
          <div className="space-y-4">
            {incidentData.map((incident: IncidentRecord) => (
              <div
                key={incident.id}
                className={clsx(
                  'border rounded-lg p-6 dark:border-gray-700',
                  incident.severity === 'Critical'
                    ? 'bg-red-900/20 border-red-700'
                    : incident.severity === 'High'
                      ? 'bg-orange-900/20 border-orange-700'
                      : 'bg-gray-800 border-gray-700'
                )}
              >
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">{incident.title}</h3>
                    <p className="text-sm text-gray-400">Discovered: {incident.discoveredDate}</p>
                  </div>
                  <div className="text-right">
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium',
                        incident.severity === 'Critical'
                          ? 'bg-red-900/60 text-red-200'
                          : incident.severity === 'High'
                            ? 'bg-orange-900/60 text-orange-200'
                            : 'bg-yellow-900/60 text-yellow-200'
                      )}
                    >
                      {incident.severity} Severity
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4 mb-4">
                  <div>
                    <p className="text-xs text-gray-400 mb-1">GDPR Notification Deadline</p>
                    <p className="text-sm font-semibold text-white">{incident.notificationDeadline}</p>
                    <p className={clsx('text-xs mt-1', incident.daysLeft <= 3 ? 'text-red-400' : 'text-green-400')}>
                      {incident.daysLeft === 0 ? 'Notified' : `${incident.daysLeft} days left`}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400 mb-1">CCPA Deadline</p>
                    <p className="text-sm font-semibold text-white">30 days from discovery</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Status</p>
                    <span className={clsx('px-2 py-1 rounded text-xs font-medium', incident.status === 'Notified' ? 'bg-green-900/40 text-green-300' : 'bg-blue-900/40 text-blue-300')}>
                      {incident.status}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New Data Subject Request</h2>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Request Type</label>
                  <select className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white dark:bg-gray-700 dark:border-gray-600">
                    <option>Access</option>
                    <option>Deletion</option>
                    <option>Portability</option>
                    <option>Correction</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Regulation</label>
                  <select className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white dark:bg-gray-700 dark:border-gray-600">
                    <option>GDPR</option>
                    <option>CCPA</option>
                    <option>LGPD</option>
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
                    onClick={() => setShowModal(false)}
                    className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors"
                  >
                    Create
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedDSR && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">DSR Details: {selectedDSR.id}</h2>
                <button
                  onClick={() => setSelectedDSR(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <p className="text-sm text-gray-400">Type</p>
                  <p className="text-white font-medium">{selectedDSR.type}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Regulation</p>
                  <p className="text-white font-medium">{selectedDSR.regulation}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Deadline</p>
                  <p className="text-white font-medium">{selectedDSR.deadline}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Status</p>
                  <p className={clsx('font-medium', selectedDSR.status === 'At Risk' ? 'text-red-400' : 'text-green-400')}>
                    {selectedDSR.status}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setSelectedDSR(null)}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded mt-6 transition-colors"
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
