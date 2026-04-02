import React, { useState, useEffect } from 'react';
import {
  Box,
  Shield,
  AlertTriangle,
  CheckCircle,
  Search,
  Filter,
  Plus,
  Eye,
  Edit,
  RefreshCw,
  Activity,
  FileText,
  Download,
  Trash2,
} from 'lucide-react';
import clsx from 'clsx';
import { containerApi } from '../api/endpoints';

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
    case 'running':
    case 'in-progress':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'completed':
    case 'passed':
    case 'clean':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'failed':
    case 'vulnerable':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'active':
    case 'enabled':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'disabled':
    case 'inactive':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    case 'pending':
    case 'queued':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'scanning':
      return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function ContainerSecurity() {
  const [activeTab, setActiveTab] = useState('images');
  const [images, setImages] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [registries, setRegistries] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewPolicyModal, setShowNewPolicyModal] = useState(false);
  const [selectedImage, setSelectedImage] = useState<any>(null);
  const [selectedScan, setSelectedScan] = useState<any>(null);
  const [rescanning, setRescanning] = useState<string | null>(null);
  const [showFilterPanel, setShowFilterPanel] = useState(false);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [imagesData, scansData, policiesData] = await Promise.all([
          containerApi.getImages(),
          containerApi.getScans(),
          containerApi.getK8sPolicies(),
        ]);
        setImages(Array.isArray(imagesData) ? imagesData : (imagesData?.items || imagesData?.data || []));
        setScans(Array.isArray(scansData) ? scansData : (scansData?.items || scansData?.data || []));
        setPolicies(policiesData || []);
        setRegistries([]);
      } catch (error) {
        console.error('Error loading container security data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const totalImages = images.length;
  const vulnerableImages = images.filter(
    (img) => img.vulnerabilities > 0 || img.status === 'vulnerable'
  ).length;
  const activeScans = scans.filter(
    (s) => s.status === 'running' || s.status === 'in-progress' || s.status === 'scanning'
  ).length;
  const activePolicies = policies.filter(
    (p) => p.status === 'active' || p.enabled
  ).length;

  const tabs = [
    { id: 'images', label: 'Images', icon: Box },
    { id: 'scans', label: 'Scans', icon: Activity },
    { id: 'registries', label: 'Registries', icon: FileText },
    { id: 'policies', label: 'Policies', icon: Shield },
  ];

  const filteredImages = images.filter(
    (img) =>
      (img.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (img.tag || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (img.repository || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredScans = scans.filter(
    (scan) =>
      (scan.imageName || scan.image || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (scan.status || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredRegistries = registries.filter(
    (reg) =>
      (reg.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (reg.url || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredPolicies = policies.filter(
    (pol) =>
      (pol.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (pol.description || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Box className="w-8 h-8 text-cyan-600" />
            <h1 className="text-3xl font-bold">Container Security</h1>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowNewPolicyModal(true)}
              className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition"
            >
              <Plus className="w-4 h-4" />
              New Policy
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-cyan-50 to-cyan-100 dark:from-cyan-900 dark:to-cyan-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-cyan-600 dark:text-cyan-300">Total Images</p>
            <p className="text-3xl font-bold text-cyan-900 dark:text-cyan-100 mt-2">{totalImages}</p>
            <p className="text-xs text-cyan-600 dark:text-cyan-300 mt-1">across all registries</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Vulnerable Images</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{vulnerableImages}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">require remediation</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Active Scans</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{activeScans}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">currently in progress</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Policies</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{activePolicies}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">active enforcement rules</p>
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
                    ? 'border-cyan-600 text-cyan-600 dark:text-cyan-400'
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
            <div className="flex flex-col items-center gap-3">
              <RefreshCw className="w-8 h-8 text-cyan-600 animate-spin" />
              <p className="text-gray-500 dark:text-gray-400">Loading container data...</p>
            </div>
          </div>
        ) : (
          <>
            {/* Images Tab */}
            {activeTab === 'images' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search by image name, tag, or repository..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                  <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                    <Download className="w-4 h-4" />
                    Export
                  </button>
                </div>

                {filteredImages.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Box className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-gray-600 dark:text-gray-400 mb-2">No Images Found</h3>
                    <p className="text-sm text-gray-500 dark:text-gray-500">
                      {searchQuery
                        ? 'No images match your search criteria. Try adjusting your filters.'
                        : 'No container images have been scanned yet. Connect a registry to get started.'}
                    </p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 shadow">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Image Name</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Tag</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Registry</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Vulnerabilities</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Last Scanned</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Size</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredImages.map((image) => (
                          <tr key={image.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-mono font-medium">{image.name}</td>
                            <td className="px-6 py-4 text-sm">
                              <span className="px-2 py-1 bg-gray-100 dark:bg-gray-600 rounded text-xs font-mono">
                                {image.tag || 'latest'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{image.registry || 'docker.io'}</td>
                            <td className="px-6 py-4 text-sm">
                              {image.vulnerabilities > 0 ? (
                                <span className="flex items-center gap-1">
                                  <AlertTriangle className="w-4 h-4 text-red-500" />
                                  <span className="font-semibold text-red-600 dark:text-red-400">{image.vulnerabilities}</span>
                                </span>
                              ) : (
                                <span className="flex items-center gap-1">
                                  <CheckCircle className="w-4 h-4 text-green-500" />
                                  <span className="text-green-600 dark:text-green-400">Clean</span>
                                </span>
                              )}
                            </td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(image.status)}`}>
                                {image.status || 'unknown'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {image.lastScanned ? new Date(image.lastScanned).toLocaleDateString() : 'Never'}
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{image.size || 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">
                              <div className="flex gap-2">
                                <button
                                  onClick={(e) => { e.stopPropagation(); setSelectedImage(image); }}
                                  className="text-blue-600 dark:text-blue-400 hover:underline"
                                  title="View Details"
                                >
                                  <Eye className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={async (e) => {
                                    e.stopPropagation();
                                    setRescanning(image.id);
                                    try {
                                      await containerApi.scanImage(image.id);
                                      const scansData = await containerApi.getScans();
                                      setScans(Array.isArray(scansData) ? scansData : (scansData?.items || scansData?.data || []));
                                    } catch (err) {
                                      console.error('Re-scan failed:', err);
                                    } finally {
                                      setRescanning(null);
                                    }
                                  }}
                                  className="text-cyan-600 dark:text-cyan-400 hover:underline"
                                  title="Re-scan"
                                >
                                  <RefreshCw className={`w-4 h-4 ${rescanning === image.id ? 'animate-spin' : ''}`} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Scans Tab */}
            {activeTab === 'scans' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search scans by image or status..."
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

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Scan Summary</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Completed</span>
                        <span className="font-semibold text-green-600">{scans.filter((s) => s.status === 'completed').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Running</span>
                        <span className="font-semibold text-blue-600">{scans.filter((s) => s.status === 'running' || s.status === 'scanning').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Failed</span>
                        <span className="font-semibold text-red-600">{scans.filter((s) => s.status === 'failed').length}</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Vulnerability Breakdown</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Critical</span>
                        <span className="font-semibold text-red-600">{scans.reduce((sum, s) => sum + (s.criticalCount || 0), 0)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>High</span>
                        <span className="font-semibold text-orange-600">{scans.reduce((sum, s) => sum + (s.highCount || 0), 0)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Medium / Low</span>
                        <span className="font-semibold text-yellow-600">{scans.reduce((sum, s) => sum + (s.mediumCount || 0) + (s.lowCount || 0), 0)}</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Scan Coverage</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Images Scanned</span>
                        <span className="font-semibold">{images.filter((i) => i.lastScanned).length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Total Images</span>
                        <span className="font-semibold">{totalImages}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Coverage</span>
                        <span className="font-semibold text-cyan-600">
                          {totalImages > 0 ? Math.round((images.filter((i) => i.lastScanned).length / totalImages) * 100) : 0}%
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {filteredScans.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Activity className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-gray-600 dark:text-gray-400 mb-2">No Scans Found</h3>
                    <p className="text-sm text-gray-500 dark:text-gray-500">
                      {searchQuery
                        ? 'No scans match your search criteria.'
                        : 'No container scans have been run yet. Trigger a scan from the Images tab.'}
                    </p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 shadow">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Scan ID</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Image</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Critical</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">High</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Medium</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Low</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Started</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Duration</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredScans.map((scan) => (
                          <tr key={scan.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-mono font-medium">{scan.id}</td>
                            <td className="px-6 py-4 text-sm">{scan.imageName || scan.image || 'N/A'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                                {scan.status}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm font-semibold text-red-600 dark:text-red-400">{scan.criticalCount || 0}</td>
                            <td className="px-6 py-4 text-sm font-semibold text-orange-600 dark:text-orange-400">{scan.highCount || 0}</td>
                            <td className="px-6 py-4 text-sm font-semibold text-yellow-600 dark:text-yellow-400">{scan.mediumCount || 0}</td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{scan.lowCount || 0}</td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : 'N/A'}
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{scan.duration || 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">
                              <div className="flex gap-2">
                                <button
                                  onClick={(e) => { e.stopPropagation(); setSelectedScan(scan); }}
                                  className="text-blue-600 dark:text-blue-400 hover:underline"
                                  title="View Report"
                                >
                                  <Eye className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={async (e) => {
                                    e.stopPropagation();
                                    try {
                                      const response = await containerApi.getScanReport(scan.id);
                                      const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
                                      const url = URL.createObjectURL(blob);
                                      const a = document.createElement('a');
                                      a.href = url;
                                      a.download = `scan-report-${scan.id}.json`;
                                      a.click();
                                      URL.revokeObjectURL(url);
                                    } catch (err) {
                                      console.error('Download failed:', err);
                                    }
                                  }}
                                  className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                                  title="Download Report"
                                >
                                  <Download className="w-4 h-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Registries Tab */}
            {activeTab === 'registries' && (
              <div className="space-y-6">
                <div className="flex gap-4 justify-between">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search registries..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition">
                    <Plus className="w-4 h-4" />
                    Connect Registry
                  </button>
                </div>

                {filteredRegistries.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-gray-600 dark:text-gray-400 mb-2">No Registries Connected</h3>
                    <p className="text-sm text-gray-500 dark:text-gray-500 mb-4">
                      Connect a container registry to start scanning images for vulnerabilities.
                    </p>
                    <button className="inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition">
                      <Plus className="w-4 h-4" />
                      Connect Your First Registry
                    </button>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 shadow">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Registry Name</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">URL</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Images</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Last Synced</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredRegistries.map((registry) => (
                          <tr key={registry.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{registry.name}</td>
                            <td className="px-6 py-4 text-sm font-mono text-gray-600 dark:text-gray-400">{registry.url}</td>
                            <td className="px-6 py-4 text-sm">
                              <span className="px-2 py-1 bg-gray-100 dark:bg-gray-600 rounded text-xs font-medium">
                                {registry.type || 'Docker Hub'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm font-semibold">{registry.imageCount || 0}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(registry.status)}`}>
                                {registry.status}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {registry.lastSynced ? new Date(registry.lastSynced).toLocaleString() : 'Never'}
                            </td>
                            <td className="px-6 py-4 text-sm">
                              <div className="flex gap-2">
                                <button className="text-cyan-600 dark:text-cyan-400 hover:underline" title="Sync Now">
                                  <RefreshCw className="w-4 h-4" />
                                </button>
                                <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100" title="Edit">
                                  <Edit className="w-4 h-4" />
                                </button>
                                <button className="text-red-600 dark:text-red-400 hover:underline" title="Remove">
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Policies Tab */}
            {activeTab === 'policies' && (
              <div className="space-y-6">
                <div className="flex gap-4 justify-between">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search policies..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button
                    onClick={() => setShowNewPolicyModal(true)}
                    className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Plus className="w-4 h-4" />
                    Create Policy
                  </button>
                </div>

                <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4 mb-6">
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    Container policies enforce security standards across your Kubernetes clusters and container runtimes.
                    Policies can block deployments, generate alerts, or auto-remediate non-compliant workloads.
                  </p>
                </div>

                {filteredPolicies.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-gray-600 dark:text-gray-400 mb-2">No Policies Defined</h3>
                    <p className="text-sm text-gray-500 dark:text-gray-500 mb-4">
                      Create admission control and runtime policies to enforce container security standards.
                    </p>
                    <button
                      onClick={() => setShowNewPolicyModal(true)}
                      className="inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition"
                    >
                      <Plus className="w-4 h-4" />
                      Create Your First Policy
                    </button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-4">
                    {filteredPolicies.map((policy) => (
                      <div key={policy.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6 hover:shadow-lg transition">
                        <div className="flex justify-between items-start mb-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <h3 className="font-semibold text-lg">{policy.name}</h3>
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(policy.status || (policy.enabled ? 'active' : 'disabled'))}`}>
                                {policy.status || (policy.enabled ? 'Active' : 'Disabled')}
                              </span>
                              {policy.severity && (
                                <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(policy.severity)}`}>
                                  {policy.severity}
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-gray-600 dark:text-gray-400">{policy.description || 'No description provided.'}</p>
                          </div>
                          <div className="flex gap-2">
                            <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100" title="Edit Policy">
                              <Edit className="w-4 h-4" />
                            </button>
                            <button className="text-red-600 dark:text-red-400 hover:underline" title="Delete Policy">
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                        <div className="grid grid-cols-4 gap-4 text-sm border-t border-gray-200 dark:border-gray-700 pt-4">
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Type</p>
                            <p className="font-medium">{policy.type || 'Admission Control'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Enforcement</p>
                            <p className="font-medium capitalize">{policy.enforcement || policy.action || 'Block'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Scope</p>
                            <p className="font-medium">{policy.scope || policy.namespace || 'All Namespaces'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Violations (30d)</p>
                            <p className="font-medium">{policy.violationCount || 0}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* Image Detail Modal */}
      {selectedImage && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[480px] max-h-[80vh] overflow-y-auto shadow-xl">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold">Image Details</h2>
              <button onClick={() => setSelectedImage(null)} className="text-gray-400 hover:text-gray-200">
                <Plus className="w-5 h-5 rotate-45" />
              </button>
            </div>
            <div className="space-y-3 text-sm">
              <div><span className="text-gray-400">Name:</span> <span className="font-mono font-medium">{selectedImage.name}</span></div>
              <div><span className="text-gray-400">Tag:</span> <span className="font-mono">{selectedImage.tag || 'latest'}</span></div>
              <div><span className="text-gray-400">Registry:</span> {selectedImage.registry || 'docker.io'}</div>
              <div><span className="text-gray-400">Status:</span> <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(selectedImage.status)}`}>{selectedImage.status}</span></div>
              <div><span className="text-gray-400">Vulnerabilities:</span> <span className="font-semibold">{selectedImage.vulnerabilities || 0}</span></div>
              <div><span className="text-gray-400">Size:</span> {selectedImage.size || 'N/A'}</div>
              <div><span className="text-gray-400">Last Scanned:</span> {selectedImage.lastScanned ? new Date(selectedImage.lastScanned).toLocaleString() : 'Never'}</div>
            </div>
            <button onClick={() => setSelectedImage(null)} className="mt-6 w-full px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition">Close</button>
          </div>
        </div>
      )}

      {/* Scan Report Modal */}
      {selectedScan && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[480px] max-h-[80vh] overflow-y-auto shadow-xl">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold">Scan Report</h2>
              <button onClick={() => setSelectedScan(null)} className="text-gray-400 hover:text-gray-200">
                <Plus className="w-5 h-5 rotate-45" />
              </button>
            </div>
            <div className="space-y-3 text-sm">
              <div><span className="text-gray-400">Scan ID:</span> <span className="font-mono">{selectedScan.id}</span></div>
              <div><span className="text-gray-400">Image:</span> {selectedScan.imageName || selectedScan.image || 'N/A'}</div>
              <div><span className="text-gray-400">Status:</span> <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(selectedScan.status)}`}>{selectedScan.status}</span></div>
              <div><span className="text-gray-400">Critical:</span> <span className="text-red-500 font-semibold">{selectedScan.criticalCount || 0}</span></div>
              <div><span className="text-gray-400">High:</span> <span className="text-orange-500 font-semibold">{selectedScan.highCount || 0}</span></div>
              <div><span className="text-gray-400">Medium:</span> <span className="text-yellow-500 font-semibold">{selectedScan.mediumCount || 0}</span></div>
              <div><span className="text-gray-400">Low:</span> {selectedScan.lowCount || 0}</div>
              <div><span className="text-gray-400">Started:</span> {selectedScan.startedAt ? new Date(selectedScan.startedAt).toLocaleString() : 'N/A'}</div>
              <div><span className="text-gray-400">Duration:</span> {selectedScan.duration || 'N/A'}</div>
            </div>
            <button onClick={() => setSelectedScan(null)} className="mt-6 w-full px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition">Close</button>
          </div>
        </div>
      )}

      {/* New Policy Modal */}
      {showNewPolicyModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[480px] max-h-screen overflow-y-auto shadow-xl">
            <h2 className="text-xl font-bold mb-4">Create Container Policy</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Policy Name</label>
                <input
                  type="text"
                  placeholder="e.g., Block Critical CVEs"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  placeholder="Describe the policy purpose..."
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Policy Type</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="admission">Admission Control</option>
                  <option value="runtime">Runtime Protection</option>
                  <option value="compliance">Compliance Check</option>
                  <option value="network">Network Policy</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Enforcement Action</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="block">Block</option>
                  <option value="alert">Alert Only</option>
                  <option value="audit">Audit</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity Threshold</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="critical">Critical</option>
                  <option value="high">High and above</option>
                  <option value="medium">Medium and above</option>
                  <option value="low">Low and above</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Namespace Scope</label>
                <input
                  type="text"
                  placeholder="e.g., production, default (comma-separated or * for all)"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewPolicyModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => setShowNewPolicyModal(false)}
                  className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition"
                >
                  Create Policy
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
