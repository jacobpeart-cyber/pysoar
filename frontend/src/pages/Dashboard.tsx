import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { alertsApi, incidentsApi } from '../lib/api';
import {
  AlertTriangle,
  FileWarning,
  Shield,
  Activity,
  TrendingUp,
  Clock,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import clsx from 'clsx';

interface Stats {
  alerts: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    new_count: number;
  };
  incidents: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    open_count: number;
  };
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
};

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [recentIncidents, setRecentIncidents] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertStats, incidentStats, alertsList, incidentsList] = await Promise.all([
          alertsApi.getStats().catch(() => ({ total: 0, by_severity: {}, by_status: {}, new_count: 0 })),
          incidentsApi.getStats().catch(() => ({ total: 0, by_severity: {}, by_status: {}, open_count: 0 })),
          alertsApi.list({ size: 5 }),
          incidentsApi.list({ size: 5 }),
        ]);

        setStats({
          alerts: alertStats,
          incidents: incidentStats,
        });
        setRecentAlerts(alertsList.items || []);
        setRecentIncidents(incidentsList.items || []);
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-500 mt-1">Security overview and recent activity</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Alerts"
          value={stats?.alerts.total || 0}
          icon={AlertTriangle}
          color="bg-orange-500"
          subtitle={`${stats?.alerts.new_count || 0} new`}
        />
        <StatCard
          title="Open Incidents"
          value={stats?.incidents.open_count || 0}
          icon={FileWarning}
          color="bg-red-500"
          subtitle={`${stats?.incidents.total || 0} total`}
        />
        <StatCard
          title="Critical Alerts"
          value={stats?.alerts.by_severity?.critical || 0}
          icon={Shield}
          color="bg-purple-500"
          subtitle="Require attention"
        />
        <StatCard
          title="Resolved Today"
          value={stats?.alerts.by_status?.closed || 0}
          icon={CheckCircle}
          color="bg-green-500"
          subtitle="Alerts closed"
        />
      </div>

      {/* Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Alert Severity Distribution</h2>
          <div className="space-y-3">
            {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
              const count = stats?.alerts.by_severity?.[severity] || 0;
              const total = stats?.alerts.total || 1;
              const percentage = Math.round((count / total) * 100) || 0;
              return (
                <div key={severity} className="flex items-center">
                  <span className="w-20 text-sm text-gray-600 capitalize">{severity}</span>
                  <div className="flex-1 mx-3">
                    <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                      <div
                        className={clsx('h-full rounded-full', severityColors[severity])}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                  <span className="w-12 text-sm text-gray-900 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Incident Status</h2>
          <div className="space-y-3">
            {['open', 'investigating', 'containment', 'eradication', 'recovery', 'closed'].map((status) => {
              const count = stats?.incidents.by_status?.[status] || 0;
              const total = stats?.incidents.total || 1;
              const percentage = Math.round((count / total) * 100) || 0;
              return (
                <div key={status} className="flex items-center">
                  <span className="w-28 text-sm text-gray-600 capitalize">{status.replace('_', ' ')}</span>
                  <div className="flex-1 mx-3">
                    <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-blue-500"
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                  <span className="w-12 text-sm text-gray-900 text-right">{count}</span>
                </div>
              );
            })}
          </div>
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
                      className={clsx(
                        'w-2 h-2 rounded-full mt-2 mr-3',
                        severityColors[alert.severity] || 'bg-gray-400'
                      )}
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
                      className={clsx(
                        'w-2 h-2 rounded-full mt-2 mr-3',
                        severityColors[incident.severity] || 'bg-gray-400'
                      )}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">{incident.title}</p>
                      <p className="text-sm text-gray-500 mt-1">
                        {incident.incident_type} &middot; {new Date(incident.created_at).toLocaleString()}
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
}: {
  title: string;
  value: number;
  icon: any;
  color: string;
  subtitle: string;
}) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
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
}
