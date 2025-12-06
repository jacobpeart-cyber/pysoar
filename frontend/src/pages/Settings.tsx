import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings as SettingsIcon,
  Mail,
  Bell,
  Link,
  Shield,
  Save,
  TestTube,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

interface SettingsData {
  general: {
    app_name: string;
    timezone: string;
    date_format: string;
    time_format: string;
    session_timeout_minutes: number;
    max_login_attempts: number;
    lockout_duration_minutes: number;
  };
  smtp: {
    host: string;
    port: number;
    username: string | null;
    from_address: string;
    use_tls: boolean;
  };
  notifications: {
    email_enabled: boolean;
    slack_enabled: boolean;
    teams_enabled: boolean;
    slack_webhook_url: string | null;
    teams_webhook_url: string | null;
  };
  alert_correlation: {
    enabled: boolean;
    time_window_minutes: number;
    similarity_threshold: number;
    auto_create_incident: boolean;
    min_alerts_for_incident: number;
  };
  integrations: Record<string, { enabled: boolean; configured: boolean }>;
}

const tabs = [
  { id: 'general', name: 'General', icon: SettingsIcon },
  { id: 'notifications', name: 'Notifications', icon: Bell },
  { id: 'email', name: 'Email (SMTP)', icon: Mail },
  { id: 'integrations', name: 'Integrations', icon: Link },
  { id: 'security', name: 'Security', icon: Shield },
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState('general');
  const queryClient = useQueryClient();

  const { data: settings, isLoading } = useQuery<SettingsData>({
    queryKey: ['settings'],
    queryFn: async () => {
      const response = await api.get('/settings');
      return response.data;
    },
  });

  const testEmailMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/settings/test-email');
      return response.data;
    },
  });

  const testIntegrationMutation = useMutation({
    mutationFn: async (integration: string) => {
      const response = await api.post(`/settings/test-integration/${integration}`);
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
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-500">Manage your PySOAR configuration</p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-48 flex-shrink-0">
          <nav className="space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'w-full flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg transition-colors',
                  activeTab === tab.id
                    ? 'bg-blue-50 text-blue-700'
                    : 'text-gray-600 hover:bg-gray-50'
                )}
              >
                <tab.icon className="w-4 h-4" />
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 bg-white rounded-lg border border-gray-200 p-6">
          {activeTab === 'general' && settings && (
            <GeneralSettings settings={settings.general} />
          )}
          {activeTab === 'notifications' && settings && (
            <NotificationSettings settings={settings.notifications} />
          )}
          {activeTab === 'email' && settings && (
            <EmailSettings
              settings={settings.smtp}
              onTest={() => testEmailMutation.mutate()}
              testStatus={testEmailMutation}
            />
          )}
          {activeTab === 'integrations' && settings && (
            <IntegrationSettings
              integrations={settings.integrations}
              onTest={(name) => testIntegrationMutation.mutate(name)}
              testStatus={testIntegrationMutation}
            />
          )}
          {activeTab === 'security' && settings && (
            <SecuritySettings settings={settings.alert_correlation} general={settings.general} />
          )}
        </div>
      </div>
    </div>
  );
}

function GeneralSettings({ settings }: { settings: SettingsData['general'] }) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">General Settings</h2>
        <p className="text-sm text-gray-500">Basic application configuration</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-700">Application Name</label>
          <input
            type="text"
            defaultValue={settings.app_name}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Timezone</label>
          <select
            defaultValue={settings.timezone}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="UTC">UTC</option>
            <option value="America/New_York">Eastern Time</option>
            <option value="America/Chicago">Central Time</option>
            <option value="America/Denver">Mountain Time</option>
            <option value="America/Los_Angeles">Pacific Time</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Date Format</label>
          <select
            defaultValue={settings.date_format}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="YYYY-MM-DD">YYYY-MM-DD</option>
            <option value="MM/DD/YYYY">MM/DD/YYYY</option>
            <option value="DD/MM/YYYY">DD/MM/YYYY</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Time Format</label>
          <select
            defaultValue={settings.time_format}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="HH:mm:ss">24-hour (HH:mm:ss)</option>
            <option value="hh:mm:ss A">12-hour (hh:mm:ss AM/PM)</option>
          </select>
        </div>
      </div>

      <div className="flex justify-end pt-4 border-t border-gray-200">
        <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
          <Save className="w-4 h-4" />
          Save Changes
        </button>
      </div>
    </div>
  );
}

function NotificationSettings({ settings }: { settings: SettingsData['notifications'] }) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Notification Settings</h2>
        <p className="text-sm text-gray-500">Configure how you receive notifications</p>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div>
            <h3 className="font-medium text-gray-900">Email Notifications</h3>
            <p className="text-sm text-gray-500">Receive alerts and updates via email</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              defaultChecked={settings.email_enabled}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div>
            <h3 className="font-medium text-gray-900">Slack Notifications</h3>
            <p className="text-sm text-gray-500">Send alerts to a Slack channel</p>
          </div>
          <div className="flex items-center gap-2">
            {settings.slack_enabled ? (
              <span className="flex items-center gap-1 text-sm text-green-600">
                <CheckCircle className="w-4 h-4" /> Connected
              </span>
            ) : (
              <span className="flex items-center gap-1 text-sm text-gray-500">
                <XCircle className="w-4 h-4" /> Not configured
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div>
            <h3 className="font-medium text-gray-900">Microsoft Teams</h3>
            <p className="text-sm text-gray-500">Send alerts to a Teams channel</p>
          </div>
          <div className="flex items-center gap-2">
            {settings.teams_enabled ? (
              <span className="flex items-center gap-1 text-sm text-green-600">
                <CheckCircle className="w-4 h-4" /> Connected
              </span>
            ) : (
              <span className="flex items-center gap-1 text-sm text-gray-500">
                <XCircle className="w-4 h-4" /> Not configured
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-4 border-t border-gray-200">
        <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
          <Save className="w-4 h-4" />
          Save Changes
        </button>
      </div>
    </div>
  );
}

function EmailSettings({
  settings,
  onTest,
  testStatus,
}: {
  settings: SettingsData['smtp'];
  onTest: () => void;
  testStatus: { isPending: boolean; isSuccess: boolean; isError: boolean };
}) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Email (SMTP) Settings</h2>
        <p className="text-sm text-gray-500">Configure email server for notifications</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-700">SMTP Host</label>
          <input
            type="text"
            defaultValue={settings.host}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">SMTP Port</label>
          <input
            type="number"
            defaultValue={settings.port}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Username</label>
          <input
            type="text"
            defaultValue={settings.username || ''}
            placeholder="Enter SMTP username"
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            placeholder="Enter SMTP password"
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">From Address</label>
          <input
            type="email"
            defaultValue={settings.from_address}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              defaultChecked={settings.use_tls}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-700">Use TLS</span>
          </label>
        </div>
      </div>

      <div className="flex justify-between pt-4 border-t border-gray-200">
        <button
          onClick={onTest}
          disabled={testStatus.isPending}
          className="flex items-center gap-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 disabled:opacity-50"
        >
          {testStatus.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <TestTube className="w-4 h-4" />
          )}
          Test Connection
        </button>
        <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
          <Save className="w-4 h-4" />
          Save Changes
        </button>
      </div>
    </div>
  );
}

function IntegrationSettings({
  integrations,
  onTest,
  testStatus,
}: {
  integrations: Record<string, { enabled: boolean; configured: boolean }>;
  onTest: (name: string) => void;
  testStatus: { isPending: boolean; isSuccess: boolean; isError: boolean };
}) {
  const integrationList = [
    { id: 'virustotal', name: 'VirusTotal', description: 'Malware and URL analysis' },
    { id: 'abuseipdb', name: 'AbuseIPDB', description: 'IP reputation database' },
    { id: 'shodan', name: 'Shodan', description: 'Internet-connected device search' },
    { id: 'greynoise', name: 'GreyNoise', description: 'Internet noise analysis' },
    { id: 'elasticsearch', name: 'Elasticsearch', description: 'Log and event storage' },
    { id: 'splunk', name: 'Splunk', description: 'SIEM integration' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Integrations</h2>
        <p className="text-sm text-gray-500">Connect to external security services</p>
      </div>

      <div className="space-y-4">
        {integrationList.map((integration) => {
          const status = integrations[integration.id];
          return (
            <div
              key={integration.id}
              className="flex items-center justify-between p-4 bg-gray-50 rounded-lg"
            >
              <div>
                <h3 className="font-medium text-gray-900">{integration.name}</h3>
                <p className="text-sm text-gray-500">{integration.description}</p>
              </div>
              <div className="flex items-center gap-3">
                {status?.configured ? (
                  <>
                    <span className="flex items-center gap-1 text-sm text-green-600">
                      <CheckCircle className="w-4 h-4" /> Configured
                    </span>
                    <button
                      onClick={() => onTest(integration.id)}
                      className="text-sm text-blue-600 hover:text-blue-700"
                    >
                      Test
                    </button>
                  </>
                ) : (
                  <button className="text-sm text-blue-600 hover:text-blue-700">
                    Configure
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SecuritySettings({
  settings,
  general,
}: {
  settings: SettingsData['alert_correlation'];
  general: SettingsData['general'];
}) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Security Settings</h2>
        <p className="text-sm text-gray-500">Authentication and alert correlation settings</p>
      </div>

      <div className="space-y-6">
        <div>
          <h3 className="text-sm font-medium text-gray-900 mb-4">Authentication</h3>
          <div className="grid grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Session Timeout (minutes)
              </label>
              <input
                type="number"
                defaultValue={general.session_timeout_minutes}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Max Login Attempts
              </label>
              <input
                type="number"
                defaultValue={general.max_login_attempts}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Lockout Duration (minutes)
              </label>
              <input
                type="number"
                defaultValue={general.lockout_duration_minutes}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
          </div>
        </div>

        <div className="border-t border-gray-200 pt-6">
          <h3 className="text-sm font-medium text-gray-900 mb-4">Alert Correlation</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div>
                <h4 className="font-medium text-gray-900">Enable Alert Correlation</h4>
                <p className="text-sm text-gray-500">
                  Automatically group related alerts into incidents
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  defaultChecked={settings.enabled}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>

            <div className="grid grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Time Window (minutes)
                </label>
                <input
                  type="number"
                  defaultValue={settings.time_window_minutes}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Min Alerts for Incident
                </label>
                <input
                  type="number"
                  defaultValue={settings.min_alerts_for_incident}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-4 border-t border-gray-200">
        <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
          <Save className="w-4 h-4" />
          Save Changes
        </button>
      </div>
    </div>
  );
}
