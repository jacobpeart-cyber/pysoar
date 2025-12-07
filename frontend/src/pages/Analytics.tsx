import { useQuery } from '@tanstack/react-query';
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Clock,
  AlertTriangle,
  Shield,
  Activity,
  Target,
  Loader2,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

interface MetricsData {
  overview: {
    total_alerts: number;
    alerts_change: number;
    total_incidents: number;
    incidents_change: number;
    avg_mttr_hours: number;
    mttr_change: number;
    active_iocs: number;
  };
  alert_trends: Array<{ date: string; count: number }>;
  severity_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  top_sources: Array<{ source: string; count: number }>;
  top_attackers: Array<{ ip: string; count: number; country?: string }>;
  incident_types: Record<string, number>;
}

export default function Analytics() {
  const { data: metrics, isLoading } = useQuery<MetricsData>({
    queryKey: ['metrics'],
    queryFn: async () => {
      const response = await api.get('/metrics');
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Analytics</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Security metrics and performance insights
        </p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <KPICard
          title="Total Alerts"
          value={metrics?.overview.total_alerts || 0}
          change={metrics?.overview.alerts_change || 0}
          icon={AlertTriangle}
          color="orange"
        />
        <KPICard
          title="Active Incidents"
          value={metrics?.overview.total_incidents || 0}
          change={metrics?.overview.incidents_change || 0}
          icon={Shield}
          color="red"
        />
        <KPICard
          title="Avg. MTTR"
          value={`${(metrics?.overview.avg_mttr_hours || 0).toFixed(1)}h`}
          change={metrics?.overview.mttr_change || 0}
          icon={Clock}
          color="blue"
          invertChange
        />
        <KPICard
          title="Active IOCs"
          value={metrics?.overview.active_iocs || 0}
          icon={Target}
          color="purple"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alert Trends */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Alert Trends (7 Days)
          </h2>
          <div className="h-64">
            <AlertTrendsChart data={metrics?.alert_trends || []} />
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Severity Distribution
          </h2>
          <div className="space-y-4">
            {Object.entries(metrics?.severity_distribution || {}).map(([severity, count]) => (
              <SeverityBar key={severity} severity={severity} count={count as number} total={metrics?.overview.total_alerts || 1} />
            ))}
          </div>
        </div>

        {/* Top Alert Sources */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Top Alert Sources
          </h2>
          <div className="space-y-3">
            {metrics?.top_sources?.slice(0, 5).map((source, index) => (
              <div
                key={source.source}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 flex items-center justify-center bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded text-sm font-medium">
                    {index + 1}
                  </span>
                  <span className="text-gray-900 dark:text-white">{source.source}</span>
                </div>
                <span className="text-gray-500 dark:text-gray-400 font-medium">
                  {source.count}
                </span>
              </div>
            ))}
            {(!metrics?.top_sources || metrics.top_sources.length === 0) && (
              <p className="text-gray-500 dark:text-gray-400 text-center py-4">
                No data available
              </p>
            )}
          </div>
        </div>

        {/* Top Attackers */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Top Attackers
          </h2>
          <div className="space-y-3">
            {metrics?.top_attackers?.slice(0, 5).map((attacker, index) => (
              <div
                key={attacker.ip}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 flex items-center justify-center bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded text-sm font-medium">
                    {index + 1}
                  </span>
                  <div>
                    <span className="text-gray-900 dark:text-white font-mono text-sm">
                      {attacker.ip}
                    </span>
                    {attacker.country && (
                      <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                        {attacker.country}
                      </span>
                    )}
                  </div>
                </div>
                <span className="text-gray-500 dark:text-gray-400 font-medium">
                  {attacker.count} alerts
                </span>
              </div>
            ))}
            {(!metrics?.top_attackers || metrics.top_attackers.length === 0) && (
              <p className="text-gray-500 dark:text-gray-400 text-center py-4">
                No data available
              </p>
            )}
          </div>
        </div>

        {/* Incident Types */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 lg:col-span-2">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Incident Types
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(metrics?.incident_types || {}).map(([type, count]) => (
              <div
                key={type}
                className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg text-center"
              >
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {count as number}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                  {type.replace(/_/g, ' ')}
                </div>
              </div>
            ))}
            {(!metrics?.incident_types || Object.keys(metrics.incident_types).length === 0) && (
              <p className="text-gray-500 dark:text-gray-400 col-span-4 text-center py-4">
                No incident data available
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function KPICard({
  title,
  value,
  change,
  icon: Icon,
  color,
  invertChange = false,
}: {
  title: string;
  value: number | string;
  change?: number;
  icon: React.ComponentType<{ className?: string }>;
  color: 'orange' | 'red' | 'blue' | 'purple' | 'green';
  invertChange?: boolean;
}) {
  const colorClasses = {
    orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
    purple: 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
  };

  const isPositive = invertChange ? (change || 0) < 0 : (change || 0) > 0;
  const isNegative = invertChange ? (change || 0) > 0 : (change || 0) < 0;

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between">
        <div className={clsx('p-3 rounded-lg', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
        {change !== undefined && change !== 0 && (
          <div
            className={clsx(
              'flex items-center gap-1 text-sm',
              isPositive && 'text-green-600 dark:text-green-400',
              isNegative && 'text-red-600 dark:text-red-400'
            )}
          >
            {isPositive ? (
              <TrendingUp className="w-4 h-4" />
            ) : (
              <TrendingDown className="w-4 h-4" />
            )}
            {Math.abs(change)}%
          </div>
        )}
      </div>
      <div className="mt-4">
        <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
        <div className="text-sm text-gray-500 dark:text-gray-400">{title}</div>
      </div>
    </div>
  );
}

function SeverityBar({
  severity,
  count,
  total,
}: {
  severity: string;
  count: number;
  total: number;
}) {
  const percentage = total > 0 ? (count / total) * 100 : 0;
  const colorClasses: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300 capitalize">
          {severity}
        </span>
        <span className="text-sm text-gray-500 dark:text-gray-400">{count}</span>
      </div>
      <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full', colorClasses[severity] || 'bg-gray-500')}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

function AlertTrendsChart({ data }: { data: Array<{ date: string; count: number }> }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 dark:text-gray-400">
        No trend data available
      </div>
    );
  }

  const maxCount = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className="flex items-end justify-between h-full gap-2">
      {data.map((point) => {
        const height = (point.count / maxCount) * 100;
        return (
          <div key={point.date} className="flex-1 flex flex-col items-center">
            <div className="w-full flex items-end justify-center h-48">
              <div
                className="w-full max-w-12 bg-blue-500 dark:bg-blue-600 rounded-t"
                style={{ height: `${height}%`, minHeight: point.count > 0 ? '4px' : '0' }}
                title={`${point.count} alerts`}
              />
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
              {new Date(point.date).toLocaleDateString('en-US', { weekday: 'short' })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
