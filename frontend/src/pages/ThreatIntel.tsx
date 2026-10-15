import { useState, useMemo } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  Search,
  Globe,
  Shield,
  Activity,
  ExternalLink,
  RefreshCw,
  Loader2,
  XCircle,
  Server,
  Mail,
  Hash,
  FileText,
  TrendingUp,
  Download,
} from 'lucide-react';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import { describeLoadError } from '../lib/loadError';
import clsx from 'clsx';

interface ThreatFeed {
  id: string;
  name: string;
  provider: string;
  feed_type: string;
  is_enabled: boolean;
  last_poll_at: string | null;
  total_indicators: number;
  status: 'active' | 'error' | 'disabled';
}

// Local sources (intel.py lookup) carry name/verdict/last_seen/platform_intel;
// external enrichment sources (VirusTotal / AbuseIPDB / OTX, src/intel/providers.py)
// carry confidence, `details` (the provider's response excerpt) or `error`,
// plus `cached` and `key_source`.
interface LookupSource {
  name: string;
  verdict: string;
  last_seen?: string | null;
  confidence?: number;
  platform_intel?: boolean;
  details?: Record<string, unknown> | null;
  raw?: Record<string, unknown> | null;
  error?: string | null;
  cached?: boolean;
  key_source?: string | null;
}

// ProviderOutcome.summary(): one row per provider the platform knows.
interface ProviderOutcome {
  provider: string;
  status: 'ok' | 'not_configured' | 'credentials_unreadable' | 'unsupported_type' | 'error' | string;
  key_source: string | null;
  cached: boolean;
  error: string | null;
  detail: string | null;
}

type ExternalEnrichmentState =
  | 'ok'
  | 'not_configured'
  | 'enrichment_failed'
  | 'integration_credentials_unreadable'
  | 'unsupported_indicator_type';

interface IOCLookupResult {
  indicator: string;
  type: string;
  reputation: string;
  confidence: number;
  sources: LookupSource[];
  external_sources: LookupSource[];
  external_errors: string[];
  external_enrichment: ExternalEnrichmentState | string;
  providers: ProviderOutcome[];
  not_configured: string[];
  tags: string[];
  first_seen: string | null;
  last_seen: string | null;
}

// POST /threat-intel/indicators/{id}/enrich
interface EnrichResult {
  status: 'enriched' | ExternalEnrichmentState | string;
  indicator_id: string;
  checked_at: string;
  providers: ProviderOutcome[];
  external_sources: LookupSource[];
  external_errors: string[];
  not_configured: string[];
}

// GET /threat-intel/dashboard (IntelDashboardStats)
interface IntelDashboard {
  total_indicators: number;
  active_indicators: number;
  feeds_enabled: number;
  feeds_total: number;
  coverage_score: number;
  coverage_basis: string | null;
  feeds_polled_24h: number;
  top_tags: string[];
  top_tags_sample_size: number;
}

const ENRICHMENT_STATE_LABELS: Record<string, { label: string; cls: string }> = {
  ok: { label: 'Enriched by at least one provider', cls: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' },
  enriched: { label: 'Enriched by at least one provider', cls: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' },
  not_configured: { label: 'Not configured: no provider API key for this indicator type', cls: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300' },
  enrichment_failed: { label: 'Enrichment failed: every configured provider returned an error', cls: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' },
  integration_credentials_unreadable: { label: 'Installed integration credentials cannot be read', cls: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' },
  unsupported_indicator_type: { label: 'No external provider looks up this indicator type', cls: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300' },
};

function EnrichmentStateBadge({ state }: { state: string }) {
  const meta = ENRICHMENT_STATE_LABELS[state] ?? {
    label: state,
    cls: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
  };
  return (
    <span className={clsx('px-2 py-1 text-xs font-medium rounded', meta.cls)} title={state}>
      {meta.label}
    </span>
  );
}

const PROVIDER_STATUS_CLS: Record<string, string> = {
  ok: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  error: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  credentials_unreadable: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
};

/** One row per provider: status, where the key came from, cache, and the backend's reason. */
function ProviderTable({ providers }: { providers: ProviderOutcome[] }) {
  if (providers.length === 0) {
    return <p className="text-xs text-gray-500 dark:text-gray-400">The backend reported no providers.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-gray-50 dark:bg-gray-700/50">
          <tr>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Provider</th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Status</th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Key source</th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Cached</th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Detail</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
          {providers.map((p) => (
            <tr key={p.provider}>
              <td className="px-3 py-2 font-medium text-gray-900 dark:text-white">{p.provider}</td>
              <td className="px-3 py-2">
                <span
                  className={clsx(
                    'px-2 py-0.5 text-xs font-medium rounded',
                    PROVIDER_STATUS_CLS[p.status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                  )}
                >
                  {p.status}
                </span>
              </td>
              <td className="px-3 py-2 text-gray-600 dark:text-gray-300">{p.key_source ?? '—'}</td>
              <td className="px-3 py-2 text-gray-600 dark:text-gray-300">{p.status === 'ok' ? (p.cached ? 'yes' : 'no') : '—'}</td>
              <td className="px-3 py-2 text-xs text-gray-600 dark:text-gray-300 break-all">
                {p.error ?? p.detail ?? '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function verdictCls(verdict: string): string {
  return verdict === 'malicious'
    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
    : verdict === 'suspicious'
    ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
    : verdict === 'clean'
    ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
    : verdict === 'error'
    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
    : 'bg-gray-100 text-gray-700 dark:bg-gray-600 dark:text-gray-300';
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

interface ThreatStats {
  total_indicators: number;
  malicious_ips: number;
  malicious_domains: number;
  malicious_hashes: number;
  feeds_active: number;
  last_update: string | null;
}

const defaultIndicatorTypes = [
  { value: 'ip', label: 'IP Address', icon: Server },
  { value: 'domain', label: 'Domain', icon: Globe },
  { value: 'url', label: 'URL', icon: ExternalLink },
  { value: 'hash', label: 'File Hash', icon: Hash },
  { value: 'email', label: 'Email', icon: Mail },
];

const indicatorTypeIcons: Record<string, typeof Server> = {
  ip: Server,
  domain: Globe,
  url: ExternalLink,
  hash: Hash,
  email: Mail,
  file: FileText,
  process: Activity,
};

function IndicatorDetailContent({ indicatorId }: { indicatorId: string }) {
  const enrichMutation = useMutation<EnrichResult, unknown, void>({
    mutationFn: async () => {
      const response = await api.post(`/threat-intel/indicators/${indicatorId}/enrich`);
      return response.data;
    },
    onSuccess: () => {
      void refetch();
    },
  });

  const { data, isLoading, error, refetch } = useQuery<{
    id: string;
    indicator_type: string;
    value: string;
    severity: string | null;
    source: string | null;
    confidence: number | null;
    first_seen: string | null;
    last_seen: string | null;
    tags: string[];
    is_active: boolean;
    sighting_count: number;
    tlp: string | null;
    context: Record<string, unknown>;
  }>({
    queryKey: ['threat-intel', 'indicator-detail', indicatorId],
    queryFn: async () => {
      const response = await api.get(`/threat-intel/indicators/${indicatorId}`);
      return response.data;
    },
  });

  if (isLoading) return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-gray-400" /></div>;
  if (error || !data) return <p className="text-sm text-red-500">Failed to load indicator details. {describeLoadError(error)}</p>;

  return (
    <div className="space-y-3 text-sm">
      <div>
        <span className="text-gray-500 dark:text-gray-400">Value:</span>
        <code className="ml-2 text-gray-900 dark:text-white break-all">{data.value}</code>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Type:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.indicator_type}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Severity:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.severity || 'N/A'}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Confidence:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.confidence ?? 'N/A'}%</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Source:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.source || 'N/A'}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">TLP:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.tlp || 'N/A'}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Active:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.is_active ? 'Yes' : 'No'}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Sightings:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.sighting_count}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">First Seen:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.first_seen ? new Date(data.first_seen || "").toLocaleString() : 'N/A'}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Last Seen:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.last_seen ? new Date(data.last_seen || "").toLocaleString() : 'N/A'}</span>
      </div>
      {data?.tags?.length > 0 && (
        <div>
          <span className="text-gray-500 dark:text-gray-400">Tags:</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {data?.tags?.map((tag, idx) => (
              <span key={idx} className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 rounded">{tag}</span>
            ))}
          </div>
        </div>
      )}

      <div className="pt-3 border-t border-gray-200 dark:border-gray-700 space-y-2">
        <div className="flex items-center justify-between">
          <span className="font-medium text-gray-700 dark:text-gray-300">External enrichment</span>
          <button
            onClick={() => enrichMutation.mutate()}
            disabled={enrichMutation.isPending}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {enrichMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Enrich now
          </button>
        </div>
        <ActionErrorBanner what="enrich this indicator" error={enrichMutation.error} />
        {enrichMutation.data && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <EnrichmentStateBadge state={enrichMutation.data.status} />
              <span className="text-xs text-gray-500 dark:text-gray-400">
                Checked {new Date(enrichMutation.data.checked_at).toLocaleString()}
              </span>
            </div>
            {enrichMutation.data.not_configured.length > 0 && (
              <p className="text-xs text-gray-600 dark:text-gray-400">
                Not configured: {enrichMutation.data.not_configured.join(', ')}
              </p>
            )}
            <ProviderTable providers={enrichMutation.data.providers} />
            {enrichMutation.data.external_sources
              .filter((s) => s.verdict !== 'error')
              .map((s, idx) => (
                <div key={idx} className="flex items-center justify-between text-xs">
                  <span className="text-gray-900 dark:text-white">{s.name}</span>
                  <span className={clsx('px-2 py-0.5 rounded font-medium', verdictCls(s.verdict))}>
                    {s.verdict}{typeof s.confidence === 'number' ? ` (${s.confidence}%)` : ''}
                  </span>
                </div>
              ))}
            {enrichMutation.data.external_errors.map((err, idx) => (
              <p key={idx} className="text-xs text-red-600 dark:text-red-400 break-all">{err}</p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ThreatIntel() {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchType, setSearchType] = useState('auto');
  const [activeTab, setActiveTab] = useState<'lookup' | 'feeds' | 'iocs'>('lookup');
  const [iocTypeFilter, setIocTypeFilter] = useState('all');
  const [iocReputationFilter, setIocReputationFilter] = useState('all');
  const [iocPage, setIocPage] = useState(1);
  const [selectedIndicatorId, setSelectedIndicatorId] = useState<string | null>(null);
  const [iocTagsInput, setIocTagsInput] = useState('');
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  const iocTags = useMemo(
    () => iocTagsInput.split(',').map((t) => t.trim()).filter(Boolean),
    [iocTagsInput]
  );

  const { data: dashboard, error: dashboardError } = useQuery<IntelDashboard>({
    queryKey: ['threat-intel', 'dashboard'],
    refetchInterval: 60_000,
    queryFn: async () => {
      const response = await api.get('/threat-intel/dashboard');
      return response.data;
    },
  });

  const { data: stats, error: statsError } = useQuery<ThreatStats>({
    queryKey: ['threat-intel', 'stats'],
    // Auto-refresh stats every 60s so operators see feed ingestion results
    // without manually reloading the page.
    refetchInterval: 60_000,
    queryFn: async () => {
      const response = await api.get('/threat-intel/stats');
      return response.data;
    },
  });

  // Build type-dropdown chips from the /stats indicators_by_type dict
  // which is already aggregated server-side. Previously we fetched 1000
  // rows and grouped client-side — wasteful and referenced the wrong field
  // name (ioc_type vs indicator_type).
  const indicatorTypes = useMemo(() => {
    // Use the static list for now since /stats doesn't return
    // indicators_by_type in this shape. The feeds stats show the real
    // breakdown elsewhere.
    return defaultIndicatorTypes;
  }, []);

  const { data: feeds, refetch: refetchFeeds, error: feedsError } = useQuery<ThreatFeed[]>({
    queryKey: ['threat-intel', 'feeds'],
    // Auto-refresh feeds every 60s so sync progress shows up naturally.
    refetchInterval: 60_000,
    queryFn: async () => {
      const response = await api.get('/threat-intel/feeds');
      const d = response.data;
      const items = Array.isArray(d) ? d : (d?.items ?? []);
      // Backend doesn't populate a "status" field — derive it from
      // is_enabled + last_error + last_poll_at.
      return items.map((f: any) => ({
        ...f,
        status: !f.is_enabled
          ? 'disabled'
          : f.last_error
            ? 'error'
            : 'active',
      }));
    },
  });

  const iocQueryParams = useMemo(() => {
    const params: Record<string, string | number> = { page: iocPage, size: 50 };
    // Backend accepts CSV for indicator_type and severity so each UI
    // choice covers all matching DB values (ipv4+ipv6+ip, high+critical
    // for "malicious" etc.) — previously the filter excluded large
    // portions of rows because it did strict equality.
    if (iocTypeFilter !== 'all') {
      const typeMap: Record<string, string> = {
        ip: 'ip,ipv4,ipv6',
        domain: 'domain',
        url: 'url',
        hash: 'md5,sha1,sha256,hash',
        email: 'email',
      };
      params.indicator_type = typeMap[iocTypeFilter] ?? iocTypeFilter;
    }
    if (iocReputationFilter !== 'all') {
      params.severity =
        iocReputationFilter === 'malicious' ? 'critical,high'
        : iocReputationFilter === 'suspicious' ? 'medium'
        : 'low,informational';
    }
    return params;
  }, [iocPage, iocTypeFilter, iocReputationFilter]);

  // FastAPI reads repeated ?tags=a&tags=b; axios would send tags[]=, so
  // build the query string explicitly.
  const toSearchParams = (base: Record<string, string | number>, tags: string[]) => {
    const sp = new URLSearchParams();
    Object.entries(base).forEach(([k, v]) => sp.append(k, String(v)));
    tags.forEach((t) => sp.append('tags', t));
    return sp;
  };

  const exportMutation = useMutation<void, unknown, 'csv' | 'stix' | 'json'>({
    mutationFn: async (format) => {
      const sp = new URLSearchParams({ format });
      if (iocTypeFilter !== 'all') sp.append('indicator_types', iocTypeFilter);
      if (iocReputationFilter !== 'all') {
        const sev =
          iocReputationFilter === 'malicious' ? ['critical', 'high']
          : iocReputationFilter === 'suspicious' ? ['medium']
          : ['low', 'informational'];
        sev.forEach((s) => sp.append('severity', s));
      }
      iocTags.forEach((t) => sp.append('tags', t));
      if (format === 'csv') {
        const response = await api.get('/threat-intel/export', { params: sp, responseType: 'blob' });
        saveBlob(response.data as Blob, 'threat-indicators.csv');
        const truncated = String(response.headers?.['x-pysoar-truncated'] ?? '') === 'true';
        setExportNotice(
          truncated
            ? 'CSV downloaded. Truncated: the export cap was reached, so not every matching indicator is in the file.'
            : 'CSV downloaded (complete, not truncated).'
        );
        return;
      }
      const response = await api.get('/threat-intel/export', { params: sp });
      const body = response.data as Record<string, unknown>;
      saveBlob(
        new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' }),
        format === 'stix' ? 'threat-indicators.stix.json' : 'threat-indicators.json'
      );
      if (format === 'stix') {
        const objects = Array.isArray(body.objects) ? body.objects.length : 0;
        const skipped = Number(body.x_pysoar_skipped_untyped ?? 0);
        setExportNotice(
          `STIX 2.1 bundle downloaded: ${objects} indicator objects` +
            (skipped > 0 ? `, ${skipped} skipped (no STIX pattern for their type)` : '') +
            (body.x_pysoar_truncated === true ? '. Truncated: the export cap was reached.' : '.')
        );
      } else {
        setExportNotice(
          `JSON downloaded: ${Number(body.count ?? 0)} indicators` +
            (body.truncated === true ? '. Truncated: the export cap was reached.' : ' (not truncated).')
        );
      }
    },
    onMutate: () => setExportNotice(null),
  });

  const { data: iocData, isLoading: iocLoading, error: iocError } = useQuery<{
    items: Array<{
      id: string;
      indicator_type: string;
      value: string;
      severity: string | null;
      source: string | null;
      confidence: number | null;
      last_seen: string | null;
      first_seen: string | null;
      tags: string[];
    }>;
    total: number;
    page: number;
    pages: number;
  }>({
    queryKey: ['threat-intel', 'ioc-database', iocQueryParams, iocTags],
    queryFn: async () => {
      const response = await api.get('/threat-intel/indicators', {
        params: toSearchParams(iocQueryParams, iocTags),
      });
      return response.data;
    },
    enabled: activeTab === 'iocs',
  });

  const lookupMutation = useMutation<IOCLookupResult, unknown, { indicator: string; type: string }>({
    mutationFn: async ({ indicator, type }) => {
      const response = await api.post('/threat-intel/lookup', { indicator, type });
      return response.data;
    },
  });

  const syncFeedMutation = useMutation({
    mutationFn: async (feedId: string) => {
      const response = await api.post(`/threat-intel/feeds/${feedId}/sync`);
      return response.data;
    },
    onSuccess: () => {
      refetchFeeds();
    },
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      lookupMutation.mutate({ indicator: searchQuery.trim(), type: searchType });
    }
  };

  const getReputationColor = (reputation: string) => {
    switch (reputation) {
      case 'malicious':
        return 'text-red-600 bg-red-50 dark:bg-red-900/20 dark:text-red-400';
      case 'suspicious':
        return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'clean':
        return 'text-green-600 bg-green-50 dark:bg-green-900/20 dark:text-green-400';
      default:
        return 'text-gray-600 bg-gray-50 dark:bg-gray-700 dark:text-gray-400';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threat Intelligence</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Look up indicators and manage threat intelligence feeds
          </p>
        </div>
      </div>

      <LoadErrorBanner what="threat intel statistics" error={statsError} />

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <Activity className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Indicators</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.total_indicators?.toLocaleString() ?? 'not available'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <Server className="w-5 h-5 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Malicious IPs</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.malicious_ips?.toLocaleString() ?? 'not available'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              <Globe className="w-5 h-5 text-orange-600 dark:text-orange-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Malicious Domains</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.malicious_domains?.toLocaleString() ?? 'not available'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
              <Hash className="w-5 h-5 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Malicious Hashes</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.malicious_hashes?.toLocaleString() ?? 'not available'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <TrendingUp className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Active Feeds</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.feeds_active ?? 'not available'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Feed coverage (GET /threat-intel/dashboard) */}
      <LoadErrorBanner what="threat intel dashboard" error={dashboardError} />
      {dashboard && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Feed coverage</p>
            <p className="text-xl font-semibold text-gray-900 dark:text-white">
              {dashboard.feeds_enabled > 0 ? `${dashboard.coverage_score}%` : 'Not available'}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              {dashboard.feeds_enabled > 0
                ? `${dashboard.feeds_polled_24h} of ${dashboard.feeds_enabled} enabled feeds polled in the last 24h`
                : 'No enabled feeds, so there is nothing to measure'}
              {dashboard.coverage_basis ? ` — basis: ${dashboard.coverage_basis}` : ''}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Top tags</p>
            {dashboard.top_tags.length > 0 ? (
              <div className="flex flex-wrap gap-1 mt-1">
                {dashboard.top_tags.map((tag) => (
                  <button
                    key={tag}
                    onClick={() => { setIocTagsInput(tag); setIocPage(1); setActiveTab('iocs'); }}
                    title="Filter the IOC database by this tag"
                    className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-600"
                  >
                    {tag}
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">No tags on the sampled indicators</p>
            )}
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Counted over the newest {dashboard.top_tags_sample_size.toLocaleString()} indicators
            </p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('lookup')}
            className={clsx(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'lookup'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
            )}
          >
            <Search className="w-4 h-4 inline mr-2" />
            IOC Lookup
          </button>
          <button
            onClick={() => setActiveTab('feeds')}
            className={clsx(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'feeds'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
            )}
          >
            <Activity className="w-4 h-4 inline mr-2" />
            Threat Feeds
          </button>
          <button
            onClick={() => setActiveTab('iocs')}
            className={clsx(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'iocs'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
            )}
          >
            <Shield className="w-4 h-4 inline mr-2" />
            IOC Database
          </button>
        </nav>
      </div>

      {/* Lookup Tab */}
      {activeTab === 'lookup' && (
        <div className="space-y-6">
          {/* Search Form */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <form onSubmit={handleSearch} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Search for an indicator
                </label>
                <div className="flex gap-3">
                  <select
                    value={searchType}
                    onChange={(e) => setSearchType(e.target.value)}
                    className="rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  >
                    <option value="auto">Auto-detect</option>
                    {indicatorTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Enter IP, domain, URL, hash, or email..."
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={lookupMutation.isPending || !searchQuery.trim()}
                    className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    {lookupMutation.isPending ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Search className="w-4 h-4" />
                    )}
                    Lookup
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Lookup Result */}
          {lookupMutation.data && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        {lookupMutation.data.indicator}
                      </h3>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full',
                          getReputationColor(lookupMutation.data.reputation)
                        )}
                      >
                        {(lookupMutation.data?.reputation || 'unknown').charAt(0).toUpperCase() +
                          (lookupMutation.data?.reputation || 'unknown').slice(1)}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      Type: {lookupMutation.data.type} | Confidence:{' '}
                      {lookupMutation.data.confidence}%
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {/* The lookup response doesn't include a DB id — the detail
                        modal is only reachable from the IOC Database tab where
                        rows have real IDs. Remove the broken eye button here. */}
                    <button
                      onClick={() => {
                        if (!lookupMutation.data) return;
                        const blob = new Blob([JSON.stringify(lookupMutation.data, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `ioc-${lookupMutation.data.indicator}.json`;
                        a.click();
                        URL.revokeObjectURL(url);
                      }}
                      title="Download as JSON"
                      className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {lookupMutation.data?.tags?.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-3">
                    {lookupMutation.data?.tags?.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 rounded"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Local sources (own + platform intel) */}
              <div className="p-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-4">
                  Local Intelligence Matches ({lookupMutation.data.sources.length})
                </h4>
                {lookupMutation.data.sources.length === 0 && (
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    No indicator with this value in your intel or the platform intel.
                  </p>
                )}
                <div className="space-y-3">
                  {lookupMutation.data.sources.map((source, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                    >
                      <div className="flex items-center gap-3">
                        <Shield className="w-5 h-5 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white flex items-center gap-2">
                            {source.name}
                            <span className="px-1.5 py-0.5 text-[10px] uppercase rounded bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300">
                              {source.platform_intel ? 'Platform intel' : 'Your intel'}
                            </span>
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Last seen: {source.last_seen ? new Date(source.last_seen).toLocaleDateString() : 'Not recorded'}
                          </p>
                        </div>
                      </div>
                      <span className={clsx('px-2 py-1 text-xs font-medium rounded', verdictCls(source.verdict))}>
                        {source.verdict}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* External enrichment: state, per-provider outcomes, answers */}
              <div className="p-6 border-t border-gray-200 dark:border-gray-700 space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">External Enrichment</h4>
                  <EnrichmentStateBadge state={lookupMutation.data.external_enrichment} />
                </div>
                {lookupMutation.data.not_configured.length > 0 && (
                  <p className="text-xs text-gray-600 dark:text-gray-400">
                    Not configured: {lookupMutation.data.not_configured.join(', ')} (see the Detail column for the key each one needs)
                  </p>
                )}
                <ProviderTable providers={lookupMutation.data.providers} />
                <div className="space-y-3">
                  {lookupMutation.data.external_sources.map((source, idx) => {
                    const details = source.details ?? source.raw;
                    return (
                      <div
                        key={`ext-${idx}`}
                        className="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-100 dark:border-blue-900 rounded-lg"
                      >
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            {source.name}
                            <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">
                              key: {source.key_source ?? 'unknown'}
                              {source.verdict !== 'error' ? (source.cached ? ' · cached result' : ' · live result') : ''}
                            </span>
                          </p>
                          <span className={clsx('px-2 py-1 text-xs font-medium rounded', verdictCls(source.verdict))}>
                            {source.verdict}
                            {source.verdict !== 'error' && typeof source.confidence === 'number' ? ` (${source.confidence}%)` : ''}
                          </span>
                        </div>
                        {details && Object.keys(details).length > 0 && (
                          <pre className="mt-2 text-xs text-gray-600 dark:text-gray-400 whitespace-pre-wrap break-all">
                            {JSON.stringify(details, null, 2)}
                          </pre>
                        )}
                        {source.error && (
                          <p className="mt-2 text-xs text-red-600 dark:text-red-400 break-all">{source.error}</p>
                        )}
                      </div>
                    );
                  })}
                  {lookupMutation.data.external_errors.map((err, idx) => (
                    <div
                      key={`err-${idx}`}
                      className="p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-100 dark:border-yellow-900 rounded-lg text-xs text-yellow-800 dark:text-yellow-300"
                    >
                      {err}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Error State */}
          <ActionErrorBanner what="look up this indicator" error={lookupMutation.error} />
        </div>
      )}

      {/* Feeds Tab */}
      {activeTab === 'feeds' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <LoadErrorBanner what="threat feeds" error={feedsError} />
          {syncFeedMutation.error ? (
            <p role="alert" className="m-4 text-sm text-red-700 dark:text-red-300">Feed sync failed. {describeLoadError(syncFeedMutation.error)}</p>
          ) : null}
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h3 className="font-medium text-gray-900 dark:text-white">Threat Intelligence Feeds</h3>
            <button
              onClick={() => refetchFeeds()}
              className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {(feeds ?? []).map((feed) => (
              <div key={feed.id} className="p-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div
                    className={clsx(
                      'w-2 h-2 rounded-full',
                      feed.status === 'active'
                        ? 'bg-green-500'
                        : feed.status === 'error'
                        ? 'bg-red-500'
                        : 'bg-gray-400'
                    )}
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-gray-900 dark:text-white">{feed.name}</p>
                      <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                        {feed.feed_type}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {feed.provider} | {(feed.total_indicators || 0).toLocaleString()} indicators
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <p className="text-xs text-gray-500 dark:text-gray-400">Last Updated</p>
                    <p className="text-sm text-gray-900 dark:text-white">
                      {feed.last_poll_at
                        ? new Date(feed.last_poll_at || "").toLocaleString()
                        : 'Never'}
                    </p>
                  </div>
                  <button
                    onClick={() => syncFeedMutation.mutate(feed.id)}
                    disabled={syncFeedMutation.isPending}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/40 disabled:opacity-50"
                  >
                    {syncFeedMutation.isPending ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <RefreshCw className="w-4 h-4" />
                    )}
                    Sync
                  </button>
                </div>
              </div>
            ))}
            {feeds && feeds.length === 0 && (
              <div className="p-8 text-center text-gray-500 dark:text-gray-400">
                <Activity className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No threat feeds configured</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* IOCs Tab */}
      {activeTab === 'iocs' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <LoadErrorBanner what="IOC database" error={iocError} />
          <div className="px-4 pt-2 space-y-2">
            <ActionErrorBanner what="export indicators" error={exportMutation.error} />
            {exportNotice && (
              <p className="text-sm text-gray-700 dark:text-gray-300">{exportNotice}</p>
            )}
          </div>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h3 className="font-medium text-gray-900 dark:text-white">IOC Database</h3>
            <div className="flex items-center gap-2">
              <select
                value={iocTypeFilter}
                onChange={(e) => { setIocTypeFilter(e.target.value); setIocPage(1); }}
                className="text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 rounded-lg px-3 py-1.5 text-gray-700 dark:text-gray-300"
              >
                <option value="all">All Types</option>
                <option value="ipv4">IP Addresses</option>
                <option value="domain">Domains</option>
                <option value="md5">MD5 Hashes</option>
                <option value="sha256">SHA256 Hashes</option>
                <option value="url">URLs</option>
                <option value="email">Email</option>
              </select>
              <select
                value={iocReputationFilter}
                onChange={(e) => { setIocReputationFilter(e.target.value); setIocPage(1); }}
                className="text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 rounded-lg px-3 py-1.5 text-gray-700 dark:text-gray-300"
              >
                <option value="all">All Reputation</option>
                <option value="malicious">Malicious</option>
                <option value="suspicious">Suspicious</option>
                <option value="clean">Clean</option>
              </select>
              <input
                type="text"
                value={iocTagsInput}
                onChange={(e) => { setIocTagsInput(e.target.value); setIocPage(1); }}
                placeholder="Tags (comma-separated, all must match)"
                className="text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 rounded-lg px-3 py-1.5 text-gray-700 dark:text-gray-300 w-64"
              />
              {(['csv', 'stix', 'json'] as const).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => exportMutation.mutate(fmt)}
                  disabled={exportMutation.isPending}
                  title="Server export of active indicators matching the type, reputation and tag filters"
                  className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50"
                >
                  {exportMutation.isPending && exportMutation.variables === fmt ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Download className="w-4 h-4" />
                  )}
                  {fmt === 'stix' ? 'STIX 2.1' : fmt.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Indicator
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Reputation
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Last Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {iocLoading ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                      <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
                      Loading indicators...
                    </td>
                  </tr>
                ) : (iocData?.items || []).length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                      <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                      <p>No indicators found</p>
                    </td>
                  </tr>
                ) : (
                  (iocData?.items || []).map((ioc) => {
                    const severityMap: Record<string, { label: string; cls: string }> = {
                      critical: { label: 'Malicious', cls: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400' },
                      high: { label: 'Malicious', cls: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400' },
                      medium: { label: 'Suspicious', cls: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400' },
                      low: { label: 'Clean', cls: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' },
                      informational: { label: 'Clean', cls: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' },
                    };
                    const rep = severityMap[ioc.severity || ''] || { label: 'Unknown', cls: 'bg-gray-100 dark:bg-gray-600 text-gray-700 dark:text-gray-300' };
                    return (
                      <tr key={ioc.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                        <td className="px-4 py-3">
                          <code className="text-sm text-gray-900 dark:text-white truncate max-w-[200px] block">
                            {ioc.value}
                          </code>
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                            {ioc.indicator_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', rep.cls)}>
                            {rep.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                          {ioc.source || '-'}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                          {ioc.last_seen ? new Date(ioc.last_seen || "").toLocaleDateString() : '-'}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => setSelectedIndicatorId(ioc.id)}
                            className="text-blue-600 dark:text-blue-400 hover:text-blue-700 text-sm"
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <div className="p-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Showing page {iocData?.page || 1} of {iocData?.pages || 1} ({iocData?.total?.toLocaleString() || 0} total indicators)
            </p>
            <div className="flex gap-2">
              <button
                disabled={iocPage <= 1}
                onClick={() => setIocPage((p) => Math.max(1, p - 1))}
                className={clsx(
                  'px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg',
                  iocPage <= 1
                    ? 'text-gray-400 cursor-not-allowed'
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                )}
              >
                Previous
              </button>
              <button
                disabled={iocPage >= (iocData?.pages || 1)}
                onClick={() => setIocPage((p) => p + 1)}
                className={clsx(
                  'px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg',
                  iocPage >= (iocData?.pages || 1)
                    ? 'text-gray-400 cursor-not-allowed'
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                )}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Indicator Detail Modal */}
      {selectedIndicatorId && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedIndicatorId(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 w-full max-w-lg mx-4 p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Indicator Details</h3>
              <button onClick={() => setSelectedIndicatorId(null)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <IndicatorDetailContent indicatorId={selectedIndicatorId} />
          </div>
        </div>
      )}
    </div>
  );
}
