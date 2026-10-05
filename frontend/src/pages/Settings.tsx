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
  Bot,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import { settingsApi, healthApi } from '../api/endpoints';
import type { AIProviderName, AISettings, LLMHealth } from '../api/endpoints';
import { useAuth } from '../contexts/AuthContext';

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
  { id: 'general', name: 'General', icon: SettingsIcon, adminOnly: false },
  { id: 'notifications', name: 'Notifications', icon: Bell, adminOnly: false },
  { id: 'email', name: 'Email (SMTP)', icon: Mail, adminOnly: false },
  { id: 'integrations', name: 'Integrations', icon: Link, adminOnly: false },
  // Writing the org's LLM credential is an admin action; the tab is hidden
  // for everyone else rather than rendered and then rejected by the API.
  { id: 'ai', name: 'AI Provider', icon: Bot, adminOnly: true },
  { id: 'security', name: 'Security', icon: Shield, adminOnly: false },
];

export default function Settings() {
  const { user } = useAuth();
  const isAdmin = Boolean(user?.is_superuser) || user?.role === 'admin';
  const visibleTabs = tabs.filter((t) => !t.adminOnly || isAdmin);
  const [activeTab, setActiveTab] = useState('general');
  const [globalError, setGlobalError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: settings, isLoading } = useQuery<SettingsData>({
    queryKey: ['settings'],
    queryFn: async () => {
      try {
      const response = await api.get('/settings');
      return response.data;
      } catch { return null; }
    },
  });

  const testEmailMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/settings/test-email');
      return response.data;
    },
    onError: (err: any) => {
      console.error('Test email failed:', err);
      setGlobalError(
        err?.response?.data?.detail || err?.message || 'Failed to send test email'
      );
    },
    onSuccess: () => setGlobalError(null),
  });

  const testIntegrationMutation = useMutation({
    mutationFn: async (integration: string) => {
      const response = await api.post(`/settings/test-integration/${integration}`);
      return response.data;
    },
    onError: (err: any) => {
      console.error('Test integration failed:', err);
      setGlobalError(
        err?.response?.data?.detail || err?.message || 'Integration test failed'
      );
    },
    onSuccess: () => setGlobalError(null),
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

      {globalError && (
        <div className="flex items-start gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <XCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div className="flex-1">{globalError}</div>
          <button
            onClick={() => setGlobalError(null)}
            className="text-red-700 hover:text-red-900"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-48 flex-shrink-0">
          <nav className="space-y-1">
            {visibleTabs.map((tab) => (
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
          {activeTab === 'ai' &&
            (isAdmin ? (
              <AIProviderSettings />
            ) : (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Only an administrator can view or change the AI provider configuration.
              </p>
            ))}
          {activeTab === 'security' && settings && (
            <SecuritySettings settings={settings.alert_correlation} general={settings.general} />
          )}
        </div>
      </div>
    </div>
  );
}

function GeneralSettings({ settings }: { settings: SettingsData['general'] }) {
  const queryClient = useQueryClient();
  const [formData, setFormData] = useState(settings);
  const [saveError, setSaveError] = useState<string | null>(null);
  const saveMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const response = await api.patch('/settings/general', data);
      return response.data;
    },
    onSuccess: () => {
      setSaveError(null);
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (err: any) => {
      console.error('Save general settings failed:', err);
      setSaveError(
        err?.response?.data?.detail || err?.message || 'Failed to save settings'
      );
    },
  });

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
            value={formData.app_name}
            onChange={(e) => setFormData({ ...formData, app_name: e.target.value })}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Timezone</label>
          <select
            value={formData.timezone}
            onChange={(e) => setFormData({ ...formData, timezone: e.target.value })}
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
            value={formData.date_format}
            onChange={(e) => setFormData({ ...formData, date_format: e.target.value })}
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
            value={formData.time_format}
            onChange={(e) => setFormData({ ...formData, time_format: e.target.value })}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="HH:mm:ss">24-hour (HH:mm:ss)</option>
            <option value="hh:mm:ss A">12-hour (hh:mm:ss AM/PM)</option>
          </select>
        </div>
      </div>

      {saveError && (
        <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          <XCircle className="w-4 h-4" />
          {saveError}
        </div>
      )}

      <div className="flex justify-end pt-4 border-t border-gray-200">
        <button
          onClick={() => saveMutation.mutate(formData)}
          disabled={saveMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          Save Changes
        </button>
      </div>
    </div>
  );
}

function NotificationSettings({ settings }: { settings: SettingsData['notifications'] }) {
  const queryClient = useQueryClient();
  const [formData, setFormData] = useState(settings);
  const [saveError, setSaveError] = useState<string | null>(null);
  const saveMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const response = await api.patch('/settings/notifications', data);
      return response.data;
    },
    onSuccess: () => {
      setSaveError(null);
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (err: any) => {
      console.error('Save notification settings failed:', err);
      setSaveError(
        err?.response?.data?.detail || err?.message || 'Failed to save notification settings'
      );
    },
  });

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
              checked={formData.email_enabled}
              onChange={(e) => setFormData({ ...formData, email_enabled: e.target.checked })}
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
            {formData.slack_enabled ? (
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
            {formData.teams_enabled ? (
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

      {saveError && (
        <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          <XCircle className="w-4 h-4" />
          {saveError}
        </div>
      )}

      <div className="flex justify-end pt-4 border-t border-gray-200">
        <button
          onClick={() => saveMutation.mutate(formData)}
          disabled={saveMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
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

      <form id="smtp-form" onSubmit={async (e) => {
        e.preventDefault();
        const fd = new FormData(e.currentTarget);
        try {
          await api.patch('/settings/smtp', {
            host: fd.get('host'),
            port: Number(fd.get('port')),
            username: fd.get('username') || '',
            password: fd.get('password') || undefined,
            from_address: fd.get('from_address'),
            use_tls: fd.get('use_tls') === 'on',
          });
        } catch (err) {
          console.error('Failed to save SMTP settings:', err);
        }
      }}>
      <div className="grid grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-700">SMTP Host</label>
          <input
            name="host"
            type="text"
            defaultValue={settings.host}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">SMTP Port</label>
          <input
            name="port"
            type="number"
            defaultValue={settings.port}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Username</label>
          <input
            name="username"
            type="text"
            defaultValue={settings.username || ''}
            placeholder="Enter SMTP username"
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Password</label>
          <input
            name="password"
            type="password"
            placeholder="Enter SMTP password"
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">From Address</label>
          <input
            name="from_address"
            type="email"
            defaultValue={settings.from_address}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2">
            <input
              name="use_tls"
              type="checkbox"
              defaultChecked={settings.use_tls}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-700">Use TLS</span>
          </label>
        </div>
      </div>
      </form>

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
        <button
          type="submit"
          form="smtp-form"
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
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
  testStatus: { isPending: boolean; isSuccess: boolean; isError: boolean; variables?: string };
}) {
  const [configModal, setConfigModal] = useState<IntegrationConfig | null>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [saveError, setSaveError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // Drive "testing" state directly off mutation state (which integration is being tested)
  const testingId = testStatus.isPending ? (testStatus.variables ?? null) : null;

  const saveMutation = useMutation({
    mutationFn: async ({ integrationId, config }: { integrationId: string; config: Record<string, string> }) => {
      const response = await api.post(`/settings/integrations/${integrationId}`, config);
      return response.data;
    },
    onSuccess: () => {
      setSaveError(null);
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      setConfigModal(null);
      setFormData({});
    },
    onError: (err: any) => {
      console.error('Save integration failed:', err);
      setSaveError(
        err?.response?.data?.detail || err?.message || 'Failed to save integration'
      );
    },
  });

  const handleConfigure = (integration: IntegrationConfig) => {
    setConfigModal(integration);
    setFormData({});
    setShowPasswords({});
    // Clear any stale save error from a prior attempt — the modal
    // previously kept showing 'Unknown integration: slack' even
    // after the backend fix deployed because saveError survived
    // modal close+reopen.
    setSaveError(null);
  };

  const handleSave = () => {
    if (configModal) {
      saveMutation.mutate({ integrationId: configModal.id, config: formData });
    }
  };

  const handleTest = (integrationId: string) => {
    onTest(integrationId);
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

              {saveError && (
                <div className="mt-4 flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
                  <XCircle className="w-4 h-4" />
                  {saveError}
                </div>
              )}

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
  const queryClient = useQueryClient();
  const saveMutation = useMutation({
    mutationFn: async (data: { alert_correlation: any; general: any }) => {
      try {
      const response = await api.patch('/settings/security', data);
      return response.data;
      } catch { return null; }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
  });

  return (
    <form id="security-form" onSubmit={(e) => {
      e.preventDefault();
      const fd = new FormData(e.currentTarget);
      saveMutation.mutate({
        general: {
          session_timeout_minutes: Number(fd.get('session_timeout_minutes')),
          max_login_attempts: Number(fd.get('max_login_attempts')),
          lockout_duration_minutes: Number(fd.get('lockout_duration_minutes')),
        },
        alert_correlation: {
          enabled: fd.get('enabled') === 'on',
          time_window_minutes: Number(fd.get('time_window_minutes')),
          min_alerts_for_incident: Number(fd.get('min_alerts_for_incident')),
        },
      });
    }}>
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
                name="session_timeout_minutes"
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
                name="max_login_attempts"
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
                name="lockout_duration_minutes"
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
                  name="enabled"
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
                  name="time_window_minutes"
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
                  name="min_alerts_for_incident"
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
        <button
          type="submit"
          disabled={saveMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          Save Changes
        </button>
      </div>
    </div>
    </form>
  );
}

const AI_PROVIDERS: Array<{ id: AIProviderName; name: string }> = [
  { id: 'anthropic', name: 'Anthropic' },
  { id: 'gemini', name: 'Google Gemini' },
  { id: 'openai', name: 'OpenAI' },
  { id: 'ollama', name: 'Ollama' },
];

interface AiErrorInfo {
  code: string | null;
  detail: string | null;
  available: string[];
}

/**
 * PUT /settings/ai reports failures as a TOP-LEVEL body (`{error, detail,
 * available}`), not FastAPI's nested `{detail: {...}}`. Both are read here so
 * the panel can name the actual failure instead of "request failed".
 */
function readAiError(err: unknown): AiErrorInfo {
  const response = (err as { response?: { data?: unknown } })?.response;
  const data = response?.data;
  const body =
    data && typeof data === 'object' && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : null;
  if (!body) {
    const message = (err as { message?: string })?.message;
    return { code: null, detail: message || null, available: [] };
  }
  const nested =
    body.detail && typeof body.detail === 'object' && !Array.isArray(body.detail)
      ? (body.detail as Record<string, unknown>)
      : null;
  const code =
    (typeof body.error === 'string' && body.error) ||
    (nested && typeof nested.error === 'string' ? nested.error : null) ||
    null;
  const detail =
    (typeof body.detail === 'string' && body.detail) ||
    (nested && typeof nested.detail === 'string' ? nested.detail : null) ||
    null;
  const availableRaw = body.available ?? nested?.available;
  const available = Array.isArray(availableRaw)
    ? availableRaw.filter((m): m is string => typeof m === 'string')
    : [];
  return { code, detail, available };
}

const AI_ERROR_TEXT: Record<string, string> = {
  unknown_model: 'That model is not available for this provider.',
  invalid_credentials: 'The provider rejected this API key.',
  provider_timeout: 'The provider did not respond in time. Try again, or check the key.',
  llm_not_configured: 'No usable LLM configuration — set a provider, a model and a key.',
  secret_unreadable: 'The stored key could not be decrypted. Re-enter the API key to rotate it.',
  tenant_url_not_allowed: 'Provider URLs cannot be set per tenant.',
};

function formatTimestamp(value?: string | null): string {
  if (!value) return 'never';
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? value : new Date(parsed).toLocaleString();
}

function AIProviderSettings() {
  const { data: aiSettings, isLoading } = useQuery<AISettings | null>({
    queryKey: ['settings', 'ai'],
    queryFn: async () => settingsApi.getAi(),
  });

  const { data: health, isFetching: healthFetching } = useQuery<LLMHealth | null>({
    queryKey: ['health', 'llm'],
    queryFn: async () => healthApi.llm(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
      </div>
    );
  }

  // The form is seeded from the server state through `key` rather than an
  // effect: when the saved configuration changes the form remounts with the
  // new values, and no setState-in-effect cascade is needed.
  const formKey = [
    aiSettings?.provider ?? '',
    aiSettings?.model ?? '',
    String(aiSettings?.use_platform_default ?? false),
    aiSettings?.rotated_at ?? '',
  ].join('|');

  return (
    <AIProviderForm
      key={formKey}
      aiSettings={aiSettings ?? null}
      health={health ?? null}
      healthFetching={healthFetching}
    />
  );
}

function AIProviderForm({
  aiSettings,
  health,
  healthFetching,
}: {
  aiSettings: AISettings | null;
  health: LLMHealth | null;
  healthFetching: boolean;
}) {
  const queryClient = useQueryClient();
  // The API key is never echoed back by the server, so this always starts empty.
  const [provider, setProvider] = useState<AIProviderName>(aiSettings?.provider ?? 'anthropic');
  const [model, setModel] = useState(aiSettings?.model ?? '');
  const [usePlatformDefault, setUsePlatformDefault] = useState(
    Boolean(aiSettings?.use_platform_default),
  );
  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [modelsError, setModelsError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<AiErrorInfo | null>(null);
  const [saved, setSaved] = useState(false);

  const modelsMutation = useMutation({
    mutationFn: async (p: AIProviderName) => settingsApi.aiModels(p),
    onSuccess: (data) => {
      setModels(data.models || []);
      setModelsError(
        (data.models || []).length === 0
          ? 'The provider returned no models for this credential.'
          : null,
      );
    },
    onError: (err: unknown) => {
      const info = readAiError(err);
      setModels([]);
      setModelsError(
        AI_ERROR_TEXT[info.code || ''] || info.detail || 'Could not list models for this provider.',
      );
    },
  });

  const saveMutation = useMutation({
    mutationFn: async () =>
      settingsApi.putAi({
        provider,
        model: model.trim(),
        use_platform_default: usePlatformDefault,
        api_key: apiKey.trim() ? apiKey.trim() : undefined,
      }),
    onSuccess: () => {
      setSaveError(null);
      setSaved(true);
      setApiKey('');
      setShowKey(false);
      queryClient.invalidateQueries({ queryKey: ['settings', 'ai'] });
      queryClient.invalidateQueries({ queryKey: ['health', 'llm'] });
    },
    onError: (err: unknown) => {
      setSaved(false);
      setSaveError(readAiError(err));
    },
  });

  const configured = Boolean(aiSettings?.configured);
  const breakerOpen = health?.breaker_open === true;
  const canSave = model.trim().length > 0 && !saveMutation.isPending;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">AI Provider</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Which LLM this organization's agents call, and the credential they call it with. The
          provider endpoint is fixed by the platform — there is nothing to point at a different
          host.
        </p>
      </div>

      {/* Live status, straight from GET /health/llm */}
      <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 p-4">
        <div className="flex items-center gap-2 mb-2">
          {configured && !breakerOpen ? (
            <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          )}
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {configured ? 'Configured' : 'Not configured'}
          </span>
          {healthFetching ? (
            <Loader2 className="w-3 h-3 animate-spin text-gray-400" />
          ) : null}
          <button
            type="button"
            onClick={() => queryClient.invalidateQueries({ queryKey: ['health', 'llm'] })}
            className="ml-auto inline-flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200"
          >
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs">
          <div className="flex justify-between gap-2">
            <dt className="text-gray-500 dark:text-gray-400">Credential source</dt>
            <dd className="font-mono text-gray-900 dark:text-white">
              {health?.source || aiSettings?.source || 'none'}
            </dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-gray-500 dark:text-gray-400">Provider / model in use</dt>
            <dd className="font-mono text-gray-900 dark:text-white break-all">
              {health?.provider || aiSettings?.provider || '—'}
              {health?.model || aiSettings?.model ? ` / ${health?.model || aiSettings?.model}` : ''}
            </dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-gray-500 dark:text-gray-400">Last successful call</dt>
            <dd className="font-mono text-gray-900 dark:text-white">
              {formatTimestamp(health?.last_successful_call_at ?? aiSettings?.last_successful_call_at)}
            </dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-gray-500 dark:text-gray-400">Quota breaker</dt>
            <dd
              className={clsx(
                'font-mono',
                breakerOpen ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-white',
              )}
            >
              {health?.breaker_open === null || health?.breaker_open === undefined
                ? 'unknown'
                : breakerOpen
                  ? 'open — calls are being rejected'
                  : 'closed'}
            </dd>
          </div>
          {!configured && (aiSettings?.reason || health?.reason) ? (
            <div className="sm:col-span-2 flex justify-between gap-2">
              <dt className="text-gray-500 dark:text-gray-400">Reason</dt>
              <dd className="font-mono text-amber-700 dark:text-amber-300">
                {aiSettings?.reason || health?.reason}
              </dd>
            </div>
          ) : null}
        </dl>
      </div>

      {/* Provider */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Provider
        </label>
        <select
          value={provider}
          onChange={(e) => {
            setProvider(e.target.value as AIProviderName);
            setModels([]);
            setModelsError(null);
            setSaved(false);
          }}
          className="w-full max-w-sm px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white rounded-lg"
        >
          {AI_PROVIDERS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      {/* Model + live model list */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Model
        </label>
        <div className="flex flex-wrap gap-2 items-start">
          <input
            type="text"
            list="ai-model-options"
            value={model}
            onChange={(e) => {
              setModel(e.target.value);
              setSaved(false);
            }}
            placeholder="Model id, e.g. the provider's latest"
            className="flex-1 min-w-[16rem] px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white rounded-lg"
          />
          <datalist id="ai-model-options">
            {models.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
          <button
            type="button"
            onClick={() => {
              setModelsError(null);
              modelsMutation.mutate(provider);
            }}
            disabled={modelsMutation.isPending}
            className="inline-flex items-center gap-2 px-3 py-2 text-sm font-medium border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
          >
            {modelsMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
            Load models
          </button>
        </div>
        {models.length > 0 ? (
          <div className="mt-2">
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {models.length} model(s) reported by the provider — click to use:
            </p>
            <div className="flex flex-wrap gap-1">
              {models.map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => {
                    setModel(m);
                    setSaved(false);
                  }}
                  className={clsx(
                    'font-mono text-[11px] px-2 py-0.5 rounded border',
                    m === model
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                      : 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700',
                  )}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>
        ) : null}
        {modelsError ? (
          <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">{modelsError}</p>
        ) : null}
      </div>

      {/* API key — write only */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          API key
        </label>
        <div className="relative max-w-xl">
          <input
            type={showKey ? 'text' : 'password'}
            value={apiKey}
            autoComplete="off"
            onChange={(e) => {
              setApiKey(e.target.value);
              setSaved(false);
            }}
            placeholder={
              aiSettings?.key_fingerprint
                ? 'Leave blank to keep the stored key'
                : 'Paste the provider API key'
            }
            className="w-full px-3 py-2 pr-10 text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white rounded-lg"
          />
          <button
            type="button"
            onClick={() => setShowKey((s) => !s)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
            aria-label={showKey ? 'Hide API key' : 'Show API key'}
          >
            {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          The key is write-only: it is never returned by the API and is never pre-filled here.
          Stored key:{' '}
          <span className="font-mono text-gray-700 dark:text-gray-300">
            {aiSettings?.key_fingerprint || 'none'}
          </span>
          {aiSettings?.rotated_at ? ` · rotated ${formatTimestamp(aiSettings.rotated_at)}` : ''}
        </p>
      </div>

      {/* Platform default */}
      <div className="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={usePlatformDefault}
            onChange={(e) => {
              setUsePlatformDefault(e.target.checked);
              setSaved(false);
            }}
            className="mt-0.5 rounded"
          />
          <span className="text-sm">
            <span className="font-medium text-gray-900 dark:text-white">
              Fall back to the platform's provider
            </span>
            <span className="block text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              When enabled, agent runs that have no working organization credential are sent to
              the platform operator's provider account instead of failing. Your organization's
              alert, incident and asset data is included in those requests and therefore leaves
              your own provider contract. Leave this off if the tenant data must only reach your
              own provider.
            </span>
          </span>
        </label>
      </div>

      {saveError ? (
        <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-3 space-y-1">
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-red-600 dark:text-red-400" />
            <span className="text-sm font-medium text-red-800 dark:text-red-200">
              {AI_ERROR_TEXT[saveError.code || ''] || 'Could not save the AI configuration.'}
            </span>
            {saveError.code ? (
              <span className="ml-auto font-mono text-[10px] text-red-700 dark:text-red-300">
                {saveError.code}
              </span>
            ) : null}
          </div>
          {saveError.detail ? (
            <p className="text-xs font-mono text-red-900 dark:text-red-100 break-words">
              {saveError.detail}
            </p>
          ) : null}
          {saveError.available.length > 0 ? (
            <div>
              <p className="text-xs text-red-800 dark:text-red-200 mb-1">Available models:</p>
              <div className="flex flex-wrap gap-1">
                {saveError.available.map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => {
                      setModel(m);
                      setSaveError(null);
                    }}
                    className="font-mono text-[11px] px-2 py-0.5 rounded border border-red-300 dark:border-red-700 text-red-800 dark:text-red-200 hover:bg-red-100 dark:hover:bg-red-900/40"
                  >
                    {m}
                  </button>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {saved ? (
        <p className="flex items-center gap-2 text-sm text-green-700 dark:text-green-400">
          <CheckCircle className="w-4 h-4" /> Saved. The next agent run uses this configuration.
        </p>
      ) : null}

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => saveMutation.mutate()}
          disabled={!canSave}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white rounded-lg"
        >
          {saveMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          Save
        </button>
        {aiSettings?.capabilities?.models_seen_at ? (
          <span className="text-xs text-gray-500 dark:text-gray-400">
            Last model list: {aiSettings.capabilities.model_count ?? 0} models at{' '}
            {formatTimestamp(aiSettings.capabilities.models_seen_at)}
          </span>
        ) : null}
      </div>
    </div>
  );
}
