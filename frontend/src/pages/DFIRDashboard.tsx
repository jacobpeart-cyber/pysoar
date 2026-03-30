import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  FileSearch,
  Clock,
  Scale,
  Database,
  ChevronDown,
  Plus,
  Edit,
  Trash2,
  CheckCircle,
  AlertCircle,
  Search,
  Filter,
  Download,
  Eye,
} from 'lucide-react';
import clsx from 'clsx';
import { dfirApi } from '../api/endpoints';

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

const getStatusColor = (status: string) => {
  switch (status) {
    case 'active':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'in-progress':
      return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100';
    case 'closed':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function DFIRDashboard() {
  const [activeTab, setActiveTab] = useState('cases');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCase, setSelectedCase] = useState<any>(null);
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);

  const { data: cases = [], isLoading: casesLoading, error: casesError } = useQuery({
    queryKey: ['dfir-cases'],
    queryFn: dfirApi.getCases,
  });

  const { data: evidence = [], isLoading: evidenceLoading, error: evidenceError } = useQuery({
    queryKey: ['dfir-evidence'],
    queryFn: dfirApi.getEvidence,
  });

  const { data: timeline = [], isLoading: timelineLoading, error: timelineError } = useQuery({
    queryKey: ['dfir-timeline'],
    queryFn: dfirApi.getTimeline,
  });

  const { data: legalHolds = [], isLoading: holdsLoading, error: holdsError } = useQuery({
    queryKey: ['dfir-legal-holds'],
    queryFn: dfirApi.getLegalHolds,
  });

  const loading = casesLoading || evidenceLoading || timelineLoading || holdsLoading;
  const error = casesError || evidenceError || timelineError || holdsError;

  const activeCases = cases?.filter((c: any) => c?.status === 'active')?.length || 0;
  const evidenceCount = evidence?.length || 0;
  const activeHolds = legalHolds?.filter((h: any) => h?.status === 'active')?.length || 0;
  const avgResolutionTime = '12.5 days';

  const filteredCases = cases?.filter((c: any) =>
    c?.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c?.leadInvestigator?.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  const filteredEvidence = evidence?.filter((e: any) =>
    e?.name?.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  const tabs = [
    { id: 'cases', label: 'Cases', icon: Shield },
    { id: 'evidence', label: 'Evidence', icon: FileSearch },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'artifacts', label: 'Artifacts', icon: Database },
    { id: 'legal-holds', label: 'Legal Holds', icon: Scale },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-red-600" />
            <h1 className="text-3xl font-bold">DFIR Dashboard</h1>
          </div>
          <button
            onClick={() => setShowNewCaseModal(true)}
            className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Case
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Active Cases</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{activeCases}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">of {cases.length} total</p>
          </div>
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Evidence Items</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{evidenceCount}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">collected</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Legal Holds Active</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{activeHolds}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">in effect</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Avg Resolution</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{avgResolutionTime}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">time to close</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6">
        <div className="flex gap-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'py-4 px-2 border-b-2 font-medium flex items-center gap-2 transition',
                  activeTab === tab.id
                    ? 'border-red-600 text-red-600 dark:text-red-400'
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
            <p className="text-gray-500 dark:text-gray-400">Loading...</p>
          </div>
        ) : (
          <>
            {/* Cases Tab */}
            {activeTab === 'cases' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search cases..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Case Name</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Lead</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Evidence</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Legal Hold</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredCases.map((caseItem) => (
                        <tr key={caseItem.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{caseItem.name}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(caseItem.severity)}`}>
                              {caseItem.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(caseItem.status)}`}>
                              {caseItem.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">{caseItem.leadInvestigator}</td>
                          <td className="px-6 py-4 text-sm">{caseItem.evidenceCount}</td>
                          <td className="px-6 py-4">
                            {caseItem.legalHold ? (
                              <CheckCircle className="w-5 h-5 text-green-600" />
                            ) : (
                              <AlertCircle className="w-5 h-5 text-gray-400" />
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button className="text-blue-600 dark:text-blue-400 hover:underline">
                              <Eye className="w-4 h-4" />
                            </button>
                            <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100">
                              <Edit className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Evidence Tab */}
            {activeTab === 'evidence' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search evidence..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Filename</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Size</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Hash</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Verified</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">CoC</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredEvidence.map((item) => (
                        <tr key={item.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{item.name}</td>
                          <td className="px-6 py-4 text-sm">{item.type}</td>
                          <td className="px-6 py-4 text-sm">{item.size}</td>
                          <td className="px-6 py-4 text-xs font-mono text-gray-600 dark:text-gray-400">{item.hash}</td>
                          <td className="px-6 py-4">
                            {item.verified ? (
                              <CheckCircle className="w-5 h-5 text-green-600" />
                            ) : (
                              <AlertCircle className="w-5 h-5 text-orange-600" />
                            )}
                          </td>
                          <td className="px-6 py-4">
                            {item.chainOfCustody ? (
                              <CheckCircle className="w-5 h-5 text-green-600" />
                            ) : (
                              <AlertCircle className="w-5 h-5 text-red-600" />
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button className="text-blue-600 dark:text-blue-400 hover:underline">
                              <Download className="w-4 h-4" />
                            </button>
                            <button className="text-blue-600 dark:text-blue-400 hover:underline">
                              <Eye className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Timeline Tab */}
            {activeTab === 'timeline' && (
              <div className="space-y-6">
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                  <h3 className="font-semibold text-lg mb-6">Timeline of Events</h3>
                  <div className="space-y-4">
                    {timeline.map((event, index) => (
                      <div key={event.id} className="flex gap-4">
                        <div className="flex flex-col items-center">
                          <div className={clsx(
                            'w-4 h-4 rounded-full mt-2',
                            event.pivot ? 'bg-red-600' : 'bg-gray-400 dark:bg-gray-600'
                          )} />
                          {index < timeline.length - 1 && (
                            <div className="w-0.5 h-12 bg-gray-300 dark:bg-gray-600 my-2" />
                          )}
                        </div>
                        <div className="pb-4">
                          <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                            {new Date(event.timestamp).toLocaleString()}
                          </p>
                          <p className="font-medium mt-1">{event.event}</p>
                          <div className="flex gap-2 mt-2">
                            <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(event.severity)}`}>
                              {event.severity}
                            </span>
                            {event.pivot && (
                              <span className="px-2 py-1 rounded text-xs bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100">
                                Pivot Point
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Artifacts Tab */}
            {activeTab === 'artifacts' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">Registry Artifacts</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> MRU Lists</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> TypedURLs</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Installed Programs</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> USB History</li>
                    </ul>
                  </div>
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">File System Artifacts</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Recycle Bin</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Prefetch Files</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Shadow Copies</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Thumbnail Cache</li>
                    </ul>
                  </div>
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">Browser Artifacts</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Chrome History</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Firefox Cookies</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> IE Cache</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Downloaded Files</li>
                    </ul>
                  </div>
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">Event Log Analysis</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Process Creation (4688)</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Logon Events (4624)</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Lateral Movement (4672)</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Privilege Escalation (4673)</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Legal Holds Tab */}
            {activeTab === 'legal-holds' && (
              <div className="space-y-6">
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Hold Name</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Custodians</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Data Size</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Created</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Expires</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {legalHolds.map((hold) => (
                        <tr key={hold.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{hold.name}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(hold.status)}`}>
                              {hold.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">{hold.custodians}</td>
                          <td className="px-6 py-4 text-sm">{hold.dataGBSize} GB</td>
                          <td className="px-6 py-4 text-sm">{hold.createdDate}</td>
                          <td className="px-6 py-4 text-sm">{hold.expiryDate}</td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button className="text-blue-600 dark:text-blue-400 hover:underline">
                              <Eye className="w-4 h-4" />
                            </button>
                            <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100">
                              <Edit className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* New Case Modal */}
      {showNewCaseModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create New Case</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Case Name</label>
                <input type="text" placeholder="Enter case name" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Lead Investigator</label>
                <input type="text" placeholder="Select investigator" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewCaseModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => setShowNewCaseModal(false)}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition"
                >
                  Create
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
