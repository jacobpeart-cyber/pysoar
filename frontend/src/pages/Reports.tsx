import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileText,
  Download,
  Calendar,
  BarChart3,
  PieChart,
  TrendingUp,
  AlertTriangle,
  FileWarning,
  Shield,
  Loader2,
} from 'lucide-react';
import { alertsApi, incidentsApi } from '../lib/api';
import clsx from 'clsx';

type ReportType = 'alerts' | 'incidents' | 'executive';
type ExportFormat = 'csv' | 'pdf' | 'json';
type DateRange = '7d' | '30d' | '90d' | 'custom';

export default function Reports() {
  const [reportType, setReportType] = useState<ReportType>('alerts');
  const [dateRange, setDateRange] = useState<DateRange>('30d');
  const [isExporting, setIsExporting] = useState(false);

  const { data: alertStats } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => alertsApi.getStats(),
  });

  const { data: incidentStats } = useQuery({
    queryKey: ['incident-stats'],
    queryFn: () => incidentsApi.getStats(),
  });

  const handleExport = async (format: ExportFormat) => {
    setIsExporting(true);

    try {
      // Simulate export delay
      await new Promise((resolve) => setTimeout(resolve, 1500));

      // Create sample data based on report type
      let data: any;
      let filename: string;

      if (reportType === 'alerts') {
        data = {
          report_type: 'Alerts Report',
          date_range: dateRange,
          generated_at: new Date().toISOString(),
          stats: alertStats,
          summary: {
            total_alerts: alertStats?.total || 0,
            by_severity: alertStats?.by_severity || {},
            by_status: alertStats?.by_status || {},
          },
        };
        filename = `alerts-report-${dateRange}`;
      } else if (reportType === 'incidents') {
        data = {
          report_type: 'Incidents Report',
          date_range: dateRange,
          generated_at: new Date().toISOString(),
          stats: incidentStats,
          summary: {
            total_incidents: incidentStats?.total || 0,
            by_severity: incidentStats?.by_severity || {},
            by_status: incidentStats?.by_status || {},
          },
        };
        filename = `incidents-report-${dateRange}`;
      } else {
        data = {
          report_type: 'Executive Summary',
          date_range: dateRange,
          generated_at: new Date().toISOString(),
          alerts: alertStats,
          incidents: incidentStats,
        };
        filename = `executive-summary-${dateRange}`;
      }

      // Export based on format
      if (format === 'json') {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        downloadBlob(blob, `${filename}.json`);
      } else if (format === 'csv') {
        const csv = convertToCSV(data);
        const blob = new Blob([csv], { type: 'text/csv' });
        downloadBlob(blob, `${filename}.csv`);
      } else {
        // For PDF, we'll just export JSON for now
        alert('PDF export coming soon! Downloading JSON instead.');
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        downloadBlob(blob, `${filename}.json`);
      }
    } finally {
      setIsExporting(false);
    }
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const convertToCSV = (data: any): string => {
    const rows: string[] = [];
    rows.push(`Report Type,${data.report_type}`);
    rows.push(`Date Range,${data.date_range}`);
    rows.push(`Generated At,${data.generated_at}`);
    rows.push('');

    if (data.summary) {
      rows.push('Summary');
      Object.entries(data.summary).forEach(([key, value]) => {
        if (typeof value === 'object') {
          rows.push(key);
          Object.entries(value as Record<string, number>).forEach(([k, v]) => {
            rows.push(`${k},${v}`);
          });
        } else {
          rows.push(`${key},${value}`);
        }
      });
    }

    return rows.join('\n');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-gray-500">Generate and export security reports</p>
      </div>

      {/* Report Type Selection */}
      <div className="grid grid-cols-3 gap-4">
        <button
          onClick={() => setReportType('alerts')}
          className={clsx(
            'p-4 rounded-lg border-2 transition-all text-left',
            reportType === 'alerts'
              ? 'border-blue-500 bg-blue-50'
              : 'border-gray-200 hover:border-gray-300'
          )}
        >
          <AlertTriangle
            className={clsx(
              'w-8 h-8 mb-2',
              reportType === 'alerts' ? 'text-blue-500' : 'text-gray-400'
            )}
          />
          <h3 className="font-semibold text-gray-900">Alerts Report</h3>
          <p className="text-sm text-gray-500">Detailed alert analysis</p>
        </button>

        <button
          onClick={() => setReportType('incidents')}
          className={clsx(
            'p-4 rounded-lg border-2 transition-all text-left',
            reportType === 'incidents'
              ? 'border-blue-500 bg-blue-50'
              : 'border-gray-200 hover:border-gray-300'
          )}
        >
          <FileWarning
            className={clsx(
              'w-8 h-8 mb-2',
              reportType === 'incidents' ? 'text-blue-500' : 'text-gray-400'
            )}
          />
          <h3 className="font-semibold text-gray-900">Incidents Report</h3>
          <p className="text-sm text-gray-500">Incident response metrics</p>
        </button>

        <button
          onClick={() => setReportType('executive')}
          className={clsx(
            'p-4 rounded-lg border-2 transition-all text-left',
            reportType === 'executive'
              ? 'border-blue-500 bg-blue-50'
              : 'border-gray-200 hover:border-gray-300'
          )}
        >
          <Shield
            className={clsx(
              'w-8 h-8 mb-2',
              reportType === 'executive' ? 'text-blue-500' : 'text-gray-400'
            )}
          />
          <h3 className="font-semibold text-gray-900">Executive Summary</h3>
          <p className="text-sm text-gray-500">High-level overview</p>
        </button>
      </div>

      {/* Filters and Export */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Date Range</label>
              <select
                value={dateRange}
                onChange={(e) => setDateRange(e.target.value as DateRange)}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="90d">Last 90 days</option>
                <option value="custom">Custom range</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExport('csv')}
              disabled={isExporting}
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {isExporting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Download className="w-4 h-4" />
              )}
              Export CSV
            </button>
            <button
              onClick={() => handleExport('pdf')}
              disabled={isExporting}
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              <FileText className="w-4 h-4" />
              Export PDF
            </button>
            <button
              onClick={() => handleExport('json')}
              disabled={isExporting}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              Export JSON
            </button>
          </div>
        </div>

        {/* Report Preview */}
        <div className="border-t border-gray-200 pt-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Report Preview</h3>

          {reportType === 'alerts' && (
            <div className="grid grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-700">By Severity</h4>
                <div className="space-y-2">
                  {Object.entries(alertStats?.by_severity || {}).map(([severity, count]) => (
                    <div key={severity} className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 capitalize">{severity}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-32 h-2 bg-gray-100 rounded-full overflow-hidden">
                          <div
                            className={clsx(
                              'h-full rounded-full',
                              severity === 'critical'
                                ? 'bg-red-500'
                                : severity === 'high'
                                ? 'bg-orange-500'
                                : severity === 'medium'
                                ? 'bg-yellow-500'
                                : 'bg-blue-500'
                            )}
                            style={{
                              width: `${((count as number) / (alertStats?.total || 1)) * 100}%`,
                            }}
                          />
                        </div>
                        <span className="text-sm font-medium text-gray-900 w-8">
                          {count as number}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-700">By Status</h4>
                <div className="space-y-2">
                  {Object.entries(alertStats?.by_status || {}).map(([status, count]) => (
                    <div key={status} className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 capitalize">{status}</span>
                      <span className="text-sm font-medium text-gray-900">{count as number}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {reportType === 'incidents' && (
            <div className="grid grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-700">By Severity</h4>
                <div className="space-y-2">
                  {Object.entries(incidentStats?.by_severity || {}).map(([severity, count]) => (
                    <div key={severity} className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 capitalize">{severity}</span>
                      <span className="text-sm font-medium text-gray-900">{count as number}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-700">By Status</h4>
                <div className="space-y-2">
                  {Object.entries(incidentStats?.by_status || {}).map(([status, count]) => (
                    <div key={status} className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 capitalize">{status}</span>
                      <span className="text-sm font-medium text-gray-900">{count as number}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {reportType === 'executive' && (
            <div className="grid grid-cols-3 gap-4">
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 text-gray-600 mb-2">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-sm">Total Alerts</span>
                </div>
                <p className="text-2xl font-bold text-gray-900">{alertStats?.total || 0}</p>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 text-gray-600 mb-2">
                  <FileWarning className="w-4 h-4" />
                  <span className="text-sm">Total Incidents</span>
                </div>
                <p className="text-2xl font-bold text-gray-900">{incidentStats?.total || 0}</p>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 text-gray-600 mb-2">
                  <TrendingUp className="w-4 h-4" />
                  <span className="text-sm">Resolution Rate</span>
                </div>
                <p className="text-2xl font-bold text-gray-900">
                  {alertStats?.total
                    ? Math.round(
                        ((alertStats.by_status?.resolved || 0) / alertStats.total) * 100
                      )
                    : 0}
                  %
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-gray-600 mb-2">
            <BarChart3 className="w-4 h-4" />
            <span className="text-sm">Total Alerts</span>
          </div>
          <p className="text-2xl font-bold text-gray-900">{alertStats?.total || 0}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-gray-600 mb-2">
            <PieChart className="w-4 h-4" />
            <span className="text-sm">Total Incidents</span>
          </div>
          <p className="text-2xl font-bold text-gray-900">{incidentStats?.total || 0}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-red-600 mb-2">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-sm">Critical Alerts</span>
          </div>
          <p className="text-2xl font-bold text-red-600">
            {alertStats?.by_severity?.critical || 0}
          </p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-green-600 mb-2">
            <TrendingUp className="w-4 h-4" />
            <span className="text-sm">Resolved</span>
          </div>
          <p className="text-2xl font-bold text-green-600">
            {alertStats?.by_status?.resolved || 0}
          </p>
        </div>
      </div>
    </div>
  );
}
