import { useQuery } from '@tanstack/react-query';
import {
  TrendingUp,
  TrendingDown,
  Clock,
  AlertTriangle,
  Shield,
  Target,
  Loader2,
} from 'lucide-react';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import clsx from 'clsx';

// Numbers the backend could not supply stay null and render "not available";
// nothing on this page falls back to 0.
interface MetricsData {
  overview: {
    alerts_30d: number | null;
    alerts_change: number | null;
    open_incidents: number | null;
    avg_mttr_hours: number | null;
    active_iocs: number | null;
  };
  alerts_total: number | null;
  alert_trends: Array<{ date: string; count: number }>;
  severity_distribution: Record<string, number>;
  top_sources: Array<{ source: string; count: number }>;
  top_attackers: Array<{ ip: string; count: number }>;
  incident_types: Record<string, number>;
}

const NOT_AVAILABLE = 'not available';

export default function Analytics() {
  const { data: metrics, isLoading, error } = useQuery<MetricsData>({
    queryKey: ['metrics'],
    queryFn: async () => {
      // Every request must succeed; a failure surfaces as an error banner
      // instead of an outage rendering as zeros. Field names follow
      // src/api/v1/endpoints/metrics.py, alerts.py (/stats) and
      // incidents.py (/stats), all tenant-scoped.
      const [
        overviewRes, overviewPriorRes, topAttackersRes, trendsRes, mttrRes,
        iocsByTypeRes, alertsStatsRes, incidentsStatsRes,
      ] = await Promise.all([
        api.get('/metrics/overview', { params: { days: 30 } }),
        api.get('/metrics/overview', { params: { days: 60 } }),
        api.get('/metrics/top-attackers', { params: { days: 30, limit: 10 } }),
        api.get('/metrics/alerts/trend', { params: { days: 7 } }),
        api.get('/metrics/incidents/mttr', { params: { days: 30 } }),
        api.get('/metrics/iocs/by-type'),
        api.get('/alerts/stats'),
        api.get('/incidents/stats'),
      ]);

      const overview = overviewRes.data;
      const overviewPrior = overviewPriorRes.data;
      const alertStats = alertsStatsRes.data;
      const incidentStats = incidentsStatsRes.data;
      const mttr = mttrRes.data;

      const alerts30: number | null = overview?.period?.alerts_created ?? null;
      const alerts60: number | null = overviewPrior?.period?.alerts_created ?? null;
      // Prior 30 days = (last 60 days) - (last 30 days). No prior volume
      // means no meaningful percentage, so the arrow is hidden.
      const priorAlerts = alerts30 !== null && alerts60 !== null ? alerts60 - alerts30 : null;
      const alertsChange = alerts30 !== null && priorAlerts !== null && priorAlerts > 0
        ? Math.round(((alerts30 - priorAlerts) / priorAlerts) * 100)
        : null;

      const iocTypes: Array<{ type: string; count: number }> | undefined = iocsByTypeRes.data?.by_type;
      const bySource: Record<string, number> = alertStats?.by_source ?? {};

      return {
        overview: {
          alerts_30d: alerts30,
          alerts_change: alertsChange,
          open_incidents: incidentStats?.open_count ?? null,
          avg_mttr_hours: mttr?.mttr_hours ?? null,
          active_iocs: Array.isArray(iocTypes) ? iocTypes.reduce((sum, t) => sum + t.count, 0) : null,
        },
        alerts_total: alertStats?.total ?? null,
        alert_trends: trendsRes.data?.trend ?? [],
        severity_distribution: alertStats?.by_severity ?? {},
        top_sources: Object.entries(bySource)
          .map(([source, count]) => ({ source, count }))
          .sort((a, b) => b.count - a.count),
        top_attackers: (topAttackersRes.data?.top_attackers ?? []).map(
          (a: { ip: string; alert_count: number }) => ({ ip: a.ip, count: a.alert_count }),
        ),
        incident_types: incidentStats?.by_type ?? {},
      };
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const mttrHours = metrics?.overview.avg_mttr_hours ?? null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Analytics</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Security metrics and performance insights
        </p>
      </div>

      <LoadErrorBanner what="analytics metrics" error={error} />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <KPICard
          title="Alerts (30 days)"
          value={metrics?.overview.alerts_30d ?? null}
          change={metrics?.overview.alerts_change ?? null}
          icon={AlertTriangle}
          color="orange"
        />
        <KPICard
          title="Active Incidents"
          value={metrics?.overview.open_incidents ?? null}
          icon={Shield}
          color="red"
        />
        <KPICard
          title="Avg. MTTR (30 days)"
          value={mttrHours !== null ? `${mttrHours.toFixed(1)}h` : null}
          icon={Clock}
          color="blue"
        />
        <KPICard
          title="Active IOCs"
          value={metrics?.overview.active_iocs ?? null}
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
              <SeverityBar key={severity} severity={severity} count={count as number} total={metrics?.alerts_total ?? 0} />
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
}: {
  title: string;
  value: number | string | null;
  change?: number | null;
  icon: React.ComponentType<{ className?: string }>;
  color: 'orange' | 'red' | 'blue' | 'purple' | 'green';
}) {
  const colorClasses = {
    orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
    purple: 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
  };

  const isPositive = change != null && change > 0;
  const isNegative = change != null && change < 0;

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between">
        <div className={clsx('p-3 rounded-lg', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
        {change != null && change !== 0 && (
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
        {value !== null ? (
          <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
        ) : (
          <div className="text-lg text-gray-400 dark:text-gray-500">{NOT_AVAILABLE}</div>
        )}
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
              {new Date(point.date || "").toLocaleDateString('en-US', { weekday: 'short' })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
