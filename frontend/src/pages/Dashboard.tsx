import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { alertsApi, incidentsApi, iocsApi, playbooksApi } from '../lib/api';
import {
  AlertTriangle,
  FileWarning,
  Shield,
  Crosshair,
  Zap,
  CheckCircle,
  RefreshCw,
} from 'lucide-react';
import clsx from 'clsx';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

interface Stats {
  alerts: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    by_source: Record<string, number>;
    new_today: number;
    new_this_week: number;
    resolved_today: number;
  };
  incidents: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    by_type: Record<string, number>;
    open_count: number;
    mttr_hours: number | null;
  };
}

const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const statusColors: Record<string, string> = {
  new: '#3b82f6',
  acknowledged: '#8b5cf6',
  in_progress: '#f59e0b',
  resolved: '#10b981',
  closed: '#6b7280',
  false_positive: '#ec4899',
};

const incidentStatusColors: Record<string, string> = {
  open: '#ef4444',
  investigating: '#f59e0b',
  containment: '#8b5cf6',
  eradication: '#3b82f6',
  recovery: '#10b981',
  closed: '#6b7280',
};

// Dashboard auto-refresh cadence. Every other page uses TanStack Query, but
// Dashboard predates that migration — hand-rolled polling keeps this page
// behaving like "real-time metrics" without a full rewrite.
const REFRESH_INTERVAL_MS = 30_000;

const EMPTY_ALERT_STATS = {
  total: 0,
  by_severity: {},
  by_status: {},
  by_source: {},
  new_today: 0,
  new_this_week: 0,
  resolved_today: 0,
};
const EMPTY_INCIDENT_STATS = {
  total: 0,
  by_severity: {},
  by_status: {},
  by_type: {},
  open_count: 0,
  mttr_hours: null,
};

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [recentIncidents, setRecentIncidents] = useState<any[]>([]);
  const [iocCount, setIocCount] = useState(0);
  const [playbookCount, setPlaybookCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  // Track which data sources failed so the dashboard shows a visible
  // degraded state rather than silently rendering zeros. Previously
  // every data call used .catch(() => EMPTY_STATS) which made a backend
  // outage look identical to a green, empty platform.
  const [fetchErrors, setFetchErrors] = useState<string[]>([]);

  const fetchData = useCallback(async (showSpinner: boolean) => {
    if (showSpinner) setIsLoading(true);
    else setIsRefreshing(true);

    const errors: string[] = [];
    const capture = <T,>(label: string, fallback: T) =>
      (p: Promise<T>) =>
        p.catch((err) => {
          errors.push(`${label}: ${err?.message || 'request failed'}`);
          return fallback;
        });

    try {
      const [alertStats, incidentStats, alertsList, incidentsList, iocsList, playbooksList] = await Promise.all([
        capture('Alert stats', EMPTY_ALERT_STATS)(alertsApi.getStats()),
        capture('Incident stats', EMPTY_INCIDENT_STATS)(incidentsApi.getStats()),
        capture('Recent alerts', { items: [], total: 0 })(alertsApi.list({ size: 5 })),
        capture('Recent incidents', { items: [], total: 0 })(incidentsApi.list({ size: 5 })),
        capture('IOC count', { total: 0 })(iocsApi.list({ size: 1 })),
        capture('Playbook count', { total: 0 })(playbooksApi.list({ size: 1 })),
      ]);

      setStats({ alerts: alertStats, incidents: incidentStats });
      setRecentAlerts(alertsList.items || []);
      setRecentIncidents(incidentsList.items || []);
      setIocCount(iocsList.total || 0);
      setPlaybookCount(playbooksList.total || 0);
      setLastUpdated(new Date());
      setFetchErrors(errors);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      setFetchErrors([`Dashboard fetch: ${(error as Error)?.message || 'unknown error'}`]);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData(true);
    const interval = setInterval(() => fetchData(false), REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
      </div>
    );
  }

  const severityData = Object.entries(stats?.alerts.by_severity || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    color: severityColors[name] || '#6b7280',
  }));

  const alertStatusData = Object.entries(stats?.alerts.by_status || {}).map(([name, value]) => ({
    name: name.replace('_', ' ').charAt(0).toUpperCase() + name.replace('_', ' ').slice(1),
    value,
    color: statusColors[name] || '#6b7280',
  }));

  const incidentStatusData = Object.entries(stats?.incidents.by_status || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    color: incidentStatusColors[name] || '#6b7280',
  }));

  const sourceData = Object.entries(stats?.alerts.by_source || {}).map(([name, value]) => ({
    name: name.toUpperCase(),
    alerts: value,
  }));

  const incidentTypeData = Object.entries(stats?.incidents.by_type || {}).map(([name, value]) => ({
    name: name.replace('_', ' ').charAt(0).toUpperCase() + name.replace('_', ' ').slice(1),
    count: value,
  }));

  const chartTooltipStyle = {
    backgroundColor: 'rgba(31, 41, 55, 0.95)',
    border: '1px solid rgba(75, 85, 99, 0.5)',
    borderRadius: '8px',
    color: '#f3f4f6',
  };

  return (
    <div className="space-y-6">
      {fetchErrors.length > 0 && (
        <div className="rounded-lg border border-red-300 bg-red-50 dark:bg-red-900/20 dark:border-red-800 p-3 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1 text-sm">
            <p className="font-medium text-red-800 dark:text-red-300">
              Dashboard data partially unavailable — {fetchErrors.length} source{fetchErrors.length === 1 ? '' : 's'} failed
            </p>
            <ul className="mt-1 text-red-700 dark:text-red-400 list-disc list-inside">
              {fetchErrors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Security overview and real-time metrics
            {lastUpdated && (
              <span className="ml-2 text-xs text-gray-400 dark:text-gray-500">
                (updated {lastUpdated.toLocaleTimeString()})
              </span>
            )}
          </p>
        </div>
        <button
          onClick={() => fetchData(false)}
          disabled={isRefreshing}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition disabled:opacity-50"
        >
          <RefreshCw className={clsx('w-4 h-4', isRefreshing && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Alerts"
          value={stats?.alerts.total || 0}
          icon={AlertTriangle}
          color="bg-orange-500"
          subtitle={`${stats?.alerts.new_today || 0} new today`}
          href="/alerts"
        />
        <StatCard
          title="Open Incidents"
          value={stats?.incidents.open_count || 0}
          icon={FileWarning}
          color="bg-red-500"
          subtitle={`${stats?.incidents.total || 0} total`}
          href="/incidents"
        />
        <StatCard
          title="Critical Alerts"
          value={stats?.alerts.by_severity?.critical || 0}
          icon={Shield}
          color="bg-purple-500"
          subtitle="Require attention"
          href="/alerts?severity=critical"
        />
        <StatCard
          title="IOCs Tracked"
          value={iocCount}
          icon={Crosshair}
          color="bg-blue-500"
          subtitle="Active indicators"
          href="/threat-intel"
        />
        <StatCard
          title="Playbooks"
          value={playbookCount}
          icon={Zap}
          color="bg-green-500"
          subtitle="Automation rules"
          href="/playbooks"
        />
        <StatCard
          title="Resolved Today"
          value={stats?.alerts.resolved_today || 0}
          icon={CheckCircle}
          color="bg-emerald-500"
          subtitle={
            stats?.incidents.mttr_hours != null
              ? `MTTR ${stats.incidents.mttr_hours.toFixed(1)}h`
              : 'Alerts closed'
          }
          href="/alerts?status=closed"
        />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {/* Alert Severity Pie Chart */}
        <ChartCard title="Alerts by Severity" empty={severityData.length === 0}>
          <PieChart>
            <Pie
              data={severityData}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={80}
              paddingAngle={2}
              dataKey="value"
            >
              {severityData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip contentStyle={chartTooltipStyle} />
            <Legend wrapperStyle={{ color: 'inherit' }} />
          </PieChart>
        </ChartCard>

        {/* Alert Status Distribution */}
        <ChartCard title="Alert Status Distribution" empty={alertStatusData.length === 0}>
          <BarChart data={alertStatusData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} stroke="rgba(156,163,175,0.25)" />
            <XAxis type="number" stroke="currentColor" tick={{ fill: 'currentColor', fontSize: 12 }} />
            <YAxis type="category" dataKey="name" width={90} stroke="currentColor" tick={{ fill: 'currentColor', fontSize: 12 }} />
            <Tooltip contentStyle={chartTooltipStyle} />
            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
              {alertStatusData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ChartCard>

        {/* Incident Status Pie Chart */}
        <ChartCard title="Incident Status" empty={incidentStatusData.length === 0}>
          <PieChart>
            <Pie
              data={incidentStatusData}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={80}
              paddingAngle={2}
              dataKey="value"
            >
              {incidentStatusData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip contentStyle={chartTooltipStyle} />
            <Legend wrapperStyle={{ color: 'inherit' }} />
          </PieChart>
        </ChartCard>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts by Source */}
        <ChartCard title="Alerts by Source" empty={sourceData.length === 0}>
          <BarChart data={sourceData}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(156,163,175,0.25)" />
            <XAxis dataKey="name" stroke="currentColor" tick={{ fill: 'currentColor', fontSize: 12 }} />
            <YAxis stroke="currentColor" tick={{ fill: 'currentColor', fontSize: 12 }} />
            <Tooltip contentStyle={chartTooltipStyle} />
            <Bar dataKey="alerts" fill="#3b82f6" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ChartCard>

        {/* Incidents by Type */}
        <ChartCard title="Incidents by Type" empty={incidentTypeData.length === 0}>
          <BarChart data={incidentTypeData}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(156,163,175,0.25)" />
            <XAxis dataKey="name" stroke="currentColor" tick={{ fill: 'currentColor', fontSize: 12 }} />
            <YAxis stroke="currentColor" tick={{ fill: 'currentColor', fontSize: 12 }} />
            <Tooltip contentStyle={chartTooltipStyle} />
            <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ChartCard>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Alerts */}
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Alerts</h2>
            <Link to="/alerts" className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300">
              View all
            </Link>
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {recentAlerts.length === 0 ? (
              <p className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No alerts yet</p>
            ) : (
              recentAlerts.map((alert) => (
                <div key={alert.id} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <div className="flex items-start">
                    <div
                      className="w-2 h-2 rounded-full mt-2 mr-3 flex-shrink-0"
                      style={{ backgroundColor: severityColors[alert.severity] || '#6b7280' }}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{alert.title}</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        {alert.source} &middot; {alert.created_at ? new Date(alert.created_at).toLocaleString() : '—'}
                      </p>
                    </div>
                    <span
                      className={clsx(
                        'ml-2 px-2 py-1 text-xs font-medium rounded-full whitespace-nowrap',
                        alert.status === 'new'
                          ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                          : alert.status === 'closed'
                          ? 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                          : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                      )}
                    >
                      {alert.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Incidents</h2>
            <Link to="/incidents" className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300">
              View all
            </Link>
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {recentIncidents.length === 0 ? (
              <p className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No incidents yet</p>
            ) : (
              recentIncidents.map((incident) => (
                <div key={incident.id} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <div className="flex items-start">
                    <div
                      className="w-2 h-2 rounded-full mt-2 mr-3 flex-shrink-0"
                      style={{ backgroundColor: severityColors[incident.severity] || '#6b7280' }}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{incident.title}</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        {incident.incident_type || 'Unknown'} &middot; {incident.created_at ? new Date(incident.created_at).toLocaleString() : '—'}
                      </p>
                    </div>
                    <span
                      className={clsx(
                        'ml-2 px-2 py-1 text-xs font-medium rounded-full whitespace-nowrap',
                        incident.status === 'open'
                          ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                          : incident.status === 'closed'
                          ? 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                          : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                      )}
                    >
                      {incident.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ChartCard({ title, empty, children }: { title: string; empty: boolean; children: React.ReactElement }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6 text-gray-700 dark:text-gray-300">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">{title}</h2>
      {empty ? (
        <div className="flex items-center justify-center h-48 text-gray-500 dark:text-gray-400">
          <p>No data yet</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          {children}
        </ResponsiveContainer>
      )}
    </div>
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  color,
  subtitle,
  href,
}: {
  title: string;
  value: number;
  icon: any;
  color: string;
  subtitle: string;
  href?: string;
}) {
  const content = (
    <div
      className={clsx(
        'bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6 transition-shadow',
        href && 'hover:shadow-md cursor-pointer',
      )}
    >
      <div className="flex items-center">
        <div className={clsx('p-3 rounded-lg', color)}>
          <Icon className="w-6 h-6 text-white" />
        </div>
        <div className="ml-4 min-w-0">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">{title}</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{value}</p>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 truncate">{subtitle}</p>
        </div>
      </div>
    </div>
  );

  if (href) {
    return <Link to={href}>{content}</Link>;
  }

  return content;
}
