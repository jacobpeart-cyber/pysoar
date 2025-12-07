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
  X,
  Eye,
  EyeOff,
  ExternalLink,
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

interface IntegrationConfig {
  id: string;
  name: string;
  description: string;
  docUrl: string;
  fields: Array<{
    key: string;
    label: string;
    type: 'text' | 'password' | 'url' | 'number';
    placeholder?: string;
    required?: boolean;
  }>;
}

const integrationConfigs: IntegrationConfig[] = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    description: 'Malware and URL analysis service for threat intelligence',
    docUrl: 'https://docs.virustotal.com/reference/overview',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'Enter your VirusTotal API key', required: true },
    ],
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    description: 'IP reputation database for identifying malicious IPs',
    docUrl: 'https://docs.abuseipdb.com/',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'Enter your AbuseIPDB API key', required: true },
    ],
  },
  {
    id: 'shodan',
    name: 'Shodan',
    description: 'Search engine for Internet-connected devices',
    docUrl: 'https://developer.shodan.io/api',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'Enter your Shodan API key', required: true },
    ],
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    description: 'Analyze and understand Internet background noise',
    docUrl: 'https://docs.greynoise.io/',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'Enter your GreyNoise API key', required: true },
    ],
  },
  {
    id: 'slack',
    name: 'Slack',
    description: 'Send notifications to Slack channels',
    docUrl: 'https://api.slack.com/messaging/webhooks',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', type: 'url', placeholder: 'https://hooks.slack.com/services/...', required: true },
      { key: 'channel', label: 'Default Channel', type: 'text', placeholder: '#security-alerts' },
    ],
  },
  {
    id: 'pagerduty',
    name: 'PagerDuty',
    description: 'Incident management and on-call scheduling',
    docUrl: 'https://developer.pagerduty.com/',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'Enter your PagerDuty API key', required: true },
      { key: 'service_id', label: 'Service ID', type: 'text', placeholder: 'Service ID for incidents' },
    ],
  },
  {
    id: 'elasticsearch',
    name: 'Elasticsearch',
    description: 'Store and search logs and security events',
    docUrl: 'https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html',
    fields: [
      { key: 'host', label: 'Host URL', type: 'url', placeholder: 'https://elasticsearch.example.com:9200', required: true },
      { key: 'username', label: 'Username', type: 'text', placeholder: 'elastic' },
      { key: 'password', label: 'Password', type: 'password', placeholder: 'Password' },
      { key: 'index_prefix', label: 'Index Prefix', type: 'text', placeholder: 'pysoar-' },
    ],
  },
  {
    id: 'splunk',
    name: 'Splunk',
    description: 'SIEM integration for log analysis',
    docUrl: 'https://docs.splunk.com/Documentation/Splunk/latest/RESTUM/RESTusing',
    fields: [
      { key: 'host', label: 'Host URL', type: 'url', placeholder: 'https://splunk.example.com:8089', required: true },
      { key: 'token', label: 'HEC Token', type: 'password', placeholder: 'HTTP Event Collector token', required: true },
      { key: 'index', label: 'Index', type: 'text', placeholder: 'main' },
    ],
  },
  {
    id: 'misp',
    name: 'MISP',
    description: 'Threat intelligence sharing platform',
    docUrl: 'https://www.misp-project.org/documentation/',
    fields: [
      { key: 'url', label: 'MISP URL', type: 'url', placeholder: 'https://misp.example.com', required: true },
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'Enter your MISP API key', required: true },
      { key: 'verify_ssl', label: 'Verify SSL', type: 'text', placeholder: 'true' },
    ],
  },
  {
    id: 'cortex',
    name: 'Cortex',
    description: 'Observable analysis and active response',
    docUrl: 'https://github.com/TheHive-Project/CortexDocs',
    fields: [
      { key: 'url', label: 'Cortex URL', type: 'url', placeholder: 'https://cortex.example.com', required: true },
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'Enter your Cortex API key', required: true },
    ],
  },
];

function IntegrationSettings({
  integrations,
  onTest,
  testStatus,
}: {
  integrations: Record<string, { enabled: boolean; configured: boolean }>;
  onTest: (name: string) => void;
  testStatus: { isPending: boolean; isSuccess: boolean; isError: boolean };
}) {
  const [configModal, setConfigModal] = useState<IntegrationConfig | null>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [testingId, setTestingId] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const saveMutation = useMutation({
    mutationFn: async ({ integrationId, config }: { integrationId: string; config: Record<string, string> }) => {
      const response = await api.post(`/settings/integrations/${integrationId}`, config);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      setConfigModal(null);
      setFormData({});
    },
  });

  const handleConfigure = (integration: IntegrationConfig) => {
    setConfigModal(integration);
    setFormData({});
    setShowPasswords({});
  };

  const handleSave = () => {
    if (configModal) {
      saveMutation.mutate({ integrationId: configModal.id, config: formData });
    }
  };

  const handleTest = (integrationId: string) => {
    setTestingId(integrationId);
    onTest(integrationId);
    setTimeout(() => setTestingId(null), 2000);
  };

  const togglePasswordVisibility = (key: string) => {
    setShowPasswords((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Integrations</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">Connect to external security services and platforms</p>
      </div>

      {/* Threat Intelligence Section */}
      <div>
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Threat Intelligence</h3>
        <div className="space-y-3">
          {integrationConfigs.filter(i => ['virustotal', 'abuseipdb', 'shodan', 'greynoise', 'misp'].includes(i.id)).map((integration) => {
            const status = integrations[integration.id];
            return (
              <div
                key={integration.id}
                className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">{integration.name}</h4>
                    <a
                      href={integration.docUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{integration.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  {status?.configured ? (
                    <>
                      <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                        <CheckCircle className="w-4 h-4" /> Configured
                      </span>
                      <button
                        onClick={() => handleTest(integration.id)}
                        disabled={testingId === integration.id}
                        className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 disabled:opacity-50"
                      >
                        {testingId === integration.id ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          'Test'
                        )}
                      </button>
                      <button
                        onClick={() => handleConfigure(integration)}
                        className="text-sm text-gray-600 hover:text-gray-700 dark:text-gray-400"
                      >
                        Edit
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => handleConfigure(integration)}
                      className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                    >
                      Configure
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Notifications Section */}
      <div>
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Notifications & Alerts</h3>
        <div className="space-y-3">
          {integrationConfigs.filter(i => ['slack', 'pagerduty'].includes(i.id)).map((integration) => {
            const status = integrations[integration.id];
            return (
              <div
                key={integration.id}
                className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">{integration.name}</h4>
                    <a
                      href={integration.docUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{integration.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  {status?.configured ? (
                    <>
                      <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                        <CheckCircle className="w-4 h-4" /> Configured
                      </span>
                      <button
                        onClick={() => handleTest(integration.id)}
                        disabled={testingId === integration.id}
                        className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 disabled:opacity-50"
                      >
                        {testingId === integration.id ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          'Test'
                        )}
                      </button>
                      <button
                        onClick={() => handleConfigure(integration)}
                        className="text-sm text-gray-600 hover:text-gray-700 dark:text-gray-400"
                      >
                        Edit
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => handleConfigure(integration)}
                      className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                    >
                      Configure
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* SIEM & Log Management Section */}
      <div>
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">SIEM & Log Management</h3>
        <div className="space-y-3">
          {integrationConfigs.filter(i => ['elasticsearch', 'splunk'].includes(i.id)).map((integration) => {
            const status = integrations[integration.id];
            return (
              <div
                key={integration.id}
                className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">{integration.name}</h4>
                    <a
                      href={integration.docUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{integration.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  {status?.configured ? (
                    <>
                      <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                        <CheckCircle className="w-4 h-4" /> Configured
                      </span>
                      <button
                        onClick={() => handleTest(integration.id)}
                        disabled={testingId === integration.id}
                        className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 disabled:opacity-50"
                      >
                        {testingId === integration.id ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          'Test'
                        )}
                      </button>
                      <button
                        onClick={() => handleConfigure(integration)}
                        className="text-sm text-gray-600 hover:text-gray-700 dark:text-gray-400"
                      >
                        Edit
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => handleConfigure(integration)}
                      className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                    >
                      Configure
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Analysis & Response Section */}
      <div>
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Analysis & Response</h3>
        <div className="space-y-3">
          {integrationConfigs.filter(i => ['cortex'].includes(i.id)).map((integration) => {
            const status = integrations[integration.id];
            return (
              <div
                key={integration.id}
                className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">{integration.name}</h4>
                    <a
                      href={integration.docUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{integration.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  {status?.configured ? (
                    <>
                      <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                        <CheckCircle className="w-4 h-4" /> Configured
                      </span>
                      <button
                        onClick={() => handleTest(integration.id)}
                        disabled={testingId === integration.id}
                        className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 disabled:opacity-50"
                      >
                        {testingId === integration.id ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          'Test'
                        )}
                      </button>
                      <button
                        onClick={() => handleConfigure(integration)}
                        className="text-sm text-gray-600 hover:text-gray-700 dark:text-gray-400"
                      >
                        Edit
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => handleConfigure(integration)}
                      className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                    >
                      Configure
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Configuration Modal */}
      {configModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div
              className="fixed inset-0 bg-gray-500/75 dark:bg-gray-900/80"
              onClick={() => setConfigModal(null)}
            />
            <div className="relative bg-white dark:bg-gray-800 rounded-xl shadow-xl max-w-lg w-full p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Configure {configModal.name}
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{configModal.description}</p>
                </div>
                <button
                  onClick={() => setConfigModal(null)}
                  className="text-gray-400 hover:text-gray-500"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4">
                {configModal.fields.map((field) => (
                  <div key={field.key}>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      {field.label}
                      {field.required && <span className="text-red-500 ml-1">*</span>}
                    </label>
                    <div className="relative">
                      <input
                        type={field.type === 'password' && !showPasswords[field.key] ? 'password' : 'text'}
                        value={formData[field.key] || ''}
                        onChange={(e) => setFormData({ ...formData, [field.key]: e.target.value })}
                        placeholder={field.placeholder}
                        className="block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                      />
                      {field.type === 'password' && (
                        <button
                          type="button"
                          onClick={() => togglePasswordVisibility(field.key)}
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                        >
                          {showPasswords[field.key] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <div className="flex items-center justify-between mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
                <a
                  href={configModal.docUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 flex items-center gap-1"
                >
                  <ExternalLink className="w-3 h-3" />
                  View Documentation
                </a>
                <div className="flex gap-3">
                  <button
                    onClick={() => setConfigModal(null)}
                    className="px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={saveMutation.isPending}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    {saveMutation.isPending ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Save className="w-4 h-4" />
                    )}
                    Save Configuration
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
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
