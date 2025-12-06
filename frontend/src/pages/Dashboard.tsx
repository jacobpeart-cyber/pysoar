import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { alertsApi, incidentsApi, iocsApi, playbooksApi } from '../lib/api';
import {
  AlertTriangle,
  FileWarning,
  Shield,
  Activity,
  TrendingUp,
  Clock,
  CheckCircle,
  XCircle,
  Crosshair,
  Zap,
  Server,
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
  LineChart,
  Line,
  Area,
  AreaChart,
} from 'recharts';

interface Stats {
  alerts: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    by_source: Record<string, number>;
    new_today: number;
    new_this_week: number;
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

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [recentIncidents, setRecentIncidents] = useState<any[]>([]);
  const [iocCount, setIocCount] = useState(0);
  const [playbookCount, setPlaybookCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertStats, incidentStats, alertsList, incidentsList, iocsList, playbooksList] = await Promise.all([
          alertsApi.getStats().catch(() => ({ total: 0, by_severity: {}, by_status: {}, by_source: {}, new_today: 0, new_this_week: 0 })),
          incidentsApi.getStats().catch(() => ({ total: 0, by_severity: {}, by_status: {}, by_type: {}, open_count: 0, mttr_hours: null })),
          alertsApi.list({ size: 5 }),
          incidentsApi.list({ size: 5 }),
          iocsApi.list({ size: 1 }).catch(() => ({ total: 0 })),
          playbooksApi.list({ size: 1 }).catch(() => ({ total: 0 })),
        ]);

        setStats({
          alerts: alertStats,
          incidents: incidentStats,
        });
        setRecentAlerts(alertsList.items || []);
        setRecentIncidents(incidentsList.items || []);
        setIocCount(iocsList.total || 0);
        setPlaybookCount(playbooksList.total || 0);
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  // Prepare chart data
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-500 mt-1">Security overview and real-time metrics</p>
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
          href="/iocs"
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
          value={stats?.alerts.by_status?.closed || 0}
          icon={CheckCircle}
          color="bg-emerald-500"
          subtitle="Alerts closed"
          href="/alerts?status=closed"
        />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {/* Alert Severity Pie Chart */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Alerts by Severity</h2>
          {severityData.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-gray-500">
              <p>No alert data available</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
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
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'white',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Alert Status Distribution */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Alert Status Distribution</h2>
          {alertStatusData.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-gray-500">
              <p>No status data available</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={alertStatusData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} />
                <XAxis type="number" />
                <YAxis type="category" dataKey="name" width={80} tick={{ fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'white',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {alertStatusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Incident Status Pie Chart */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Incident Status</h2>
          {incidentStatusData.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-gray-500">
              <p>No incident data available</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
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
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'white',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts by Source */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Alerts by Source</h2>
          {sourceData.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-gray-500">
              <p>No source data available</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={sourceData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'white',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="alerts" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Incidents by Type */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Incidents by Type</h2>
          {incidentTypeData.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-gray-500">
              <p>No incident type data available</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={incidentTypeData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'white',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Alerts */}
        <div className="bg-white rounded-xl border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Recent Alerts</h2>
            <Link to="/alerts" className="text-sm text-blue-600 hover:text-blue-700">
              View all
            </Link>
          </div>
          <div className="divide-y divide-gray-100">
            {recentAlerts.length === 0 ? (
              <p className="px-6 py-8 text-center text-gray-500">No alerts yet</p>
            ) : (
              recentAlerts.map((alert) => (
                <div key={alert.id} className="px-6 py-4 hover:bg-gray-50">
                  <div className="flex items-start">
                    <div
                      className="w-2 h-2 rounded-full mt-2 mr-3"
                      style={{ backgroundColor: severityColors[alert.severity] || '#6b7280' }}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">{alert.title}</p>
                      <p className="text-sm text-gray-500 mt-1">
                        {alert.source} &middot; {new Date(alert.created_at).toLocaleString()}
                      </p>
                    </div>
                    <span
                      className={clsx(
                        'ml-2 px-2 py-1 text-xs font-medium rounded-full',
                        alert.status === 'new'
                          ? 'bg-blue-100 text-blue-700'
                          : alert.status === 'closed'
                          ? 'bg-gray-100 text-gray-700'
                          : 'bg-yellow-100 text-yellow-700'
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
        <div className="bg-white rounded-xl border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Recent Incidents</h2>
            <Link to="/incidents" className="text-sm text-blue-600 hover:text-blue-700">
              View all
            </Link>
          </div>
          <div className="divide-y divide-gray-100">
            {recentIncidents.length === 0 ? (
              <p className="px-6 py-8 text-center text-gray-500">No incidents yet</p>
            ) : (
              recentIncidents.map((incident) => (
                <div key={incident.id} className="px-6 py-4 hover:bg-gray-50">
                  <div className="flex items-start">
                    <div
                      className="w-2 h-2 rounded-full mt-2 mr-3"
                      style={{ backgroundColor: severityColors[incident.severity] || '#6b7280' }}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">{incident.title}</p>
                      <p className="text-sm text-gray-500 mt-1">
                        {incident.incident_type || 'Unknown'} &middot; {new Date(incident.created_at).toLocaleString()}
                      </p>
                    </div>
                    <span
                      className={clsx(
                        'ml-2 px-2 py-1 text-xs font-medium rounded-full',
                        incident.status === 'open'
                          ? 'bg-red-100 text-red-700'
                          : incident.status === 'closed'
                          ? 'bg-gray-100 text-gray-700'
                          : 'bg-yellow-100 text-yellow-700'
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
    <div className={clsx("bg-white rounded-xl border border-gray-200 p-6 transition-shadow", href && "hover:shadow-md cursor-pointer")}>
      <div className="flex items-center">
        <div className={clsx('p-3 rounded-lg', color)}>
          <Icon className="w-6 h-6 text-white" />
        </div>
        <div className="ml-4">
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
          <p className="text-xs text-gray-400 mt-1">{subtitle}</p>
        </div>
      </div>
    </div>
  );

  if (href) {
    return <Link to={href}>{content}</Link>;
  }

  return content;
}
