import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Database,
  Workflow,
  Search,
  HardDrive,
  Layers,
  Plus,
  X,
  CheckCircle,
  AlertCircle,
  TrendingUp,
  Play,
  Pause,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import clsx from 'clsx';
import { api } from '../api/client';
import { datalakeApi } from '../api/endpoints';
import LoadErrorBanner from '../components/LoadErrorBanner';
import type { Row } from '../lib/apiRow';
import { describeLoadError } from '../lib/loadError';

const NA = 'not available';

// Normalised DataSourceResponse (src/schemas/data_lake.py). Numbers the
// backend does not report are null and render "not available".
interface DataSource {
  id: string;
  name: string;
  type: string;
  health: string;
  ingestionRate: number | null; // events/sec (ingestion_rate_eps)
  events: number | null; // total_events_ingested
  lastSync: string | null; // last_event_received
  lastError: string | null;
  builtin: boolean;
  builtinTable: string | null;
  ingestionNote: string | null;
  // connection_config_encrypted: {configured, keys}; the secret never returns.
  configKeys: string[] | null;
}

// Pipeline row from GET /data-lake/pipelines (custom rows + Celery beat
// built-ins). Built-ins carry no run history, so their counters are null.
interface Pipeline {
  id: string;
  name: string;
  status: string;
  successRate: number | null;
  recordsProcessed: number | null;
  lastRun: string | null;
  duration: string | null;
  schedule: string | null;
  builtin: boolean;
  // Why there is no run history / executor (built-in: run_history
  // "not_recorded"; registered rows: no executor).
  note: string | null;
}

const fmtTs = (v: string | null | undefined): string => {
  if (!v) return NA;
  const d = new Date(v);
  return Number.isFinite(d.getTime()) ? d.toLocaleString() : v;
};

const fmtEps = (v: number | null): string => (v == null ? NA : `${v.toLocaleString()} events/sec`);
const fmtCount = (v: number | null): string => (v == null ? NA : v.toLocaleString());


export default function DataLakeDashboard() {
  const [activeTab, setActiveTab] = useState<'sources' | 'pipelines' | 'query' | 'catalog' | 'partitions' | 'storage'>('sources');
  const [selectedSource, setSelectedSource] = useState<DataSource | null>(null);
  const [selectedPipeline, setSelectedPipeline] = useState<Pipeline | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [queryLanguage, setQueryLanguage] = useState<'sql' | 'kql' | 'spl'>('sql');
  const [queryInput, setQueryInput] = useState('');
  const [queryResult, setQueryResult] = useState<string | null>(null);
  const [queryRunning, setQueryRunning] = useState(false);
  const [catalogSearch, setCatalogSearch] = useState('');

  // Backend DataSourceResponse emits snake_case + status values
  // ("active", "initializing") that don't match the UI's Healthy/Error
  // colors. Normalize once so all downstream consumers see the shape
  // they expect, and map backend status words into UI health labels.
  const backendStatusToHealth = (s: any): string => {
    const raw = String(s?.status ?? s?.health ?? s?.health_status ?? '').toLowerCase();
    if (raw === 'active' || raw === 'healthy' || raw === 'running') return 'Healthy';
    if (raw === 'error' || raw === 'failed' || raw === 'disabled') return 'Error';
    if (raw === 'paused') return 'Paused';
    if (raw === 'initializing' || raw === 'building') return 'Initializing';
    if (raw === 'registered') return 'Registered (no ingestion)';
    return raw || 'unknown';
  };
  const normalizeSource = (s: any): DataSource => ({
    id: s.id,
    name: s.name ?? 'Unnamed source',
    type: s.source_type ?? 'unknown',
    health: backendStatusToHealth(s),
    ingestionRate: typeof s.ingestion_rate_eps === 'number' ? s.ingestion_rate_eps : null,
    events: typeof s.total_events_ingested === 'number' ? s.total_events_ingested : null,
    lastSync: s.last_event_received ?? null,
    lastError: s.last_error ?? null,
    builtin: Boolean(s.builtin),
    builtinTable: s.builtin_table ?? null,
    ingestionNote: s.ingestion_note ?? null,
    configKeys: s.connection_config_encrypted && typeof s.connection_config_encrypted === 'object' && s.connection_config_encrypted.configured
      ? (Array.isArray(s.connection_config_encrypted.keys) ? s.connection_config_encrypted.keys : [])
      : null,
  });
  const backendStatusToPipelineStatus = (p: any): string => {
    const raw = String(p?.status ?? p?.pipeline_status ?? '').toLowerCase();
    if (raw === 'active' || raw === 'running') return 'Running';
    if (raw === 'paused') return 'Paused';
    if (raw === 'failed' || raw === 'error') return 'Failed';
    if (raw === 'completed') return 'Completed';
    if (raw === 'building' || raw === 'initializing') return 'Building';
    if (raw === 'scheduled') return 'Scheduled (built-in task)';
    if (raw === 'registered') return 'Registered (no executor)';
    return raw || 'unknown';
  };
  const normalizePipeline = (p: any): Pipeline => {
    const records = typeof p.records_processed_total === 'number' ? p.records_processed_total : null;
    const errors = typeof p.error_count === 'number' ? p.error_count : null;
    // Success rate only when something was actually processed; never
    // derived from "no errors recorded".
    const successRate = records != null && records > 0 && errors != null
      ? Math.round(((records - Math.min(errors, records)) / records) * 1000) / 10
      : null;
    return {
      id: p.id,
      name: p.name,
      status: backendStatusToPipelineStatus(p),
      successRate,
      recordsProcessed: records,
      lastRun: p.last_run ?? null,
      duration: typeof p.avg_processing_time_ms === 'number' ? `${p.avg_processing_time_ms}ms avg` : null,
      schedule: p.schedule_cron ?? null,
      builtin: Boolean(p.builtin),
      note: p.execution_note
        ?? (p.run_history === 'not_recorded' ? `Runs as ${p.task ?? 'a scheduled task'}; run history is not recorded` : null),
    };
  };

  const [sourceDetail, setSourceDetail] = useState<{ lineage?: Row; quality?: Row; lineageError?: unknown; qualityError?: unknown } | null>(null);
  const openSource = async (source: DataSource) => {
    setSelectedSource(source);
    setSourceDetail(null);
    const [lin, qual] = await Promise.allSettled([
      api.get(`/data-lake/catalog/lineage/${source.id}`).then((r) => r.data),
      api.get(`/data-lake/catalog/quality/${source.id}`).then((r) => r.data),
    ]);
    setSourceDetail({
      lineage: lin.status === 'fulfilled' ? lin.value : undefined,
      lineageError: lin.status === 'rejected' ? lin.reason : undefined,
      quality: qual.status === 'fulfilled' ? qual.value : undefined,
      qualityError: qual.status === 'rejected' ? qual.reason : undefined,
    });
  };

  const { data: sourcesRaw = [], error: sourcesError } = useQuery({ queryKey: ['dataSources'], queryFn: () => datalakeApi.getDataSources() });
  const { data: pipelinesRaw = [], error: pipelinesError } = useQuery({ queryKey: ['pipelines'], queryFn: () => datalakeApi.getPipelines() });
  const { data: catalog = [], error: catalogError } = useQuery({ queryKey: ['dataCatalog'], queryFn: datalakeApi.getCatalog });
  const sources: DataSource[] = useMemo(
    () => (Array.isArray(sourcesRaw) ? sourcesRaw : ((sourcesRaw as any)?.items ?? [])).map(normalizeSource),
    [sourcesRaw],
  );
  const pipelines: Pipeline[] = useMemo(
    () => (Array.isArray(pipelinesRaw) ? pipelinesRaw : ((pipelinesRaw as any)?.items ?? [])).map(normalizePipeline),
    [pipelinesRaw],
  );

  // Real storage-breakdown from the backend. Replaces the previous
  // fabrication (hot 0.7% / warm 2.5% / cold 12% split of an
  // events×0.0002 estimate) that produced a pie chart of invented
  // numbers even when the lake was empty.
  // Shared axios client: sends the bearer token (the old raw fetch sent
  // none and always 401'd) and surfaces failures instead of null.
  const { data: storageBreakdownRaw, error: storageError } = useQuery({
    queryKey: ['dl-storage-breakdown'],
    queryFn: async () => {
      const res = await api.get('/data-lake/dashboard/storage-breakdown');
      return res.data;
    },
  });

  const filteredCatalog = useMemo(() => {
    const q = catalogSearch.trim().toLowerCase();
    if (!q) return catalog;
    return (catalog as any[]).filter((item: any) => {
      const fields = [
        item?.name,
        item?.description,
        item?.source_type,
        item?.schema,
        item?.owner,
        item?.type,
        item?.entity_type,
      ];
      return fields.some(
        (f) => typeof f === 'string' && f.toLowerCase().includes(q),
      );
    });
  }, [catalog, catalogSearch]);

  const stats = useMemo(() => {
    const activeSources = sourcesError ? NA : `${sources.filter((s: DataSource) => s.health === 'Healthy').length}/${sources.length}`;
    const known = sources.filter((s: DataSource) => s.events != null);
    const totalEvents = sourcesError || known.length === 0
      ? NA
      : known.reduce((sum: number, s: DataSource) => sum + (s.events as number), 0).toLocaleString();
    const rawTotal = (storageBreakdownRaw as any)?.total_bytes;
    let totalStorage = NA;
    if (!storageError && typeof rawTotal === 'number') {
      const totalBytes = rawTotal;
      const tb = totalBytes / 1024 ** 4;
      totalStorage = tb >= 1
        ? `${tb.toFixed(2)} TB`
        : totalBytes >= 1024 ** 3
          ? `${(totalBytes / 1024 ** 3).toFixed(2)} GB`
          : totalBytes >= 1024 ** 2
            ? `${(totalBytes / 1024 ** 2).toFixed(1)} MB`
            : `${totalBytes} B`;
    }
    const activePipelines = pipelinesError ? NA : String(pipelines.filter((p: Pipeline) => p.status === 'Running').length);
    return { activeSources, totalEvents, totalStorage, activePipelines };
  }, [sources, pipelines, storageBreakdownRaw, sourcesError, pipelinesError, storageError]);

  const storageBreakdown = useMemo(() => {
    // Use the backend's real hot/warm/cold/archived split when
    // available. The previous fabrication applied hardcoded percentage
    // splits to an events×0.0002 estimate, producing a chart even when
    // no data existed.
    const fmtBytes = (b: number): { label: string; gb: number } => {
      if (!b || b <= 0) return { label: '0 B', gb: 0 };
      if (b >= 1024 ** 4) return { label: `${(b / 1024 ** 4).toFixed(2)} TB`, gb: b / 1024 ** 3 };
      if (b >= 1024 ** 3) return { label: `${(b / 1024 ** 3).toFixed(2)} GB`, gb: b / 1024 ** 3 };
      if (b >= 1024 ** 2) return { label: `${(b / 1024 ** 2).toFixed(1)} MB`, gb: b / 1024 ** 3 };
      if (b >= 1024) return { label: `${(b / 1024).toFixed(1)} KB`, gb: b / 1024 ** 3 };
      return { label: `${b} B`, gb: b / 1024 ** 3 };
    };
    if (storageBreakdownRaw && typeof storageBreakdownRaw === 'object') {
      // New backend shape: { total_bytes, by_tier: {hot, warm, cold, archived}, ... }
      const tiers = (storageBreakdownRaw as any).by_tier
        || (storageBreakdownRaw as any).tiers
        || storageBreakdownRaw;
      if (Array.isArray(tiers)) {
        return tiers.map((t: any) => {
          const b = t.bytes ?? t.size_bytes ?? t.value ?? null;
          if (b == null) return null;
          const f = fmtBytes(b);
          return {
            name: t.name ?? t.tier ?? 'tier',
            value: Number(f.gb.toFixed(3)),
            size: f.label,
          };
        }).filter((t): t is { name: string; value: number; size: string } => t !== null);
      }
      // A null tier value means the database cannot measure it (non-PostgreSQL).
      return ['hot', 'warm', 'cold', 'archived']
        .filter((k) => k in (tiers as any) && (tiers as any)[k] != null)
        .map((k) => {
          const b = (tiers as any)[k] ?? 0;
          const f = fmtBytes(b);
          return {
            name: k.charAt(0).toUpperCase() + k.slice(1),
            value: Number(f.gb.toFixed(3)),
            size: f.label,
          };
        });
    }
    return [];
  }, [storageBreakdownRaw]);

  const storageProbe: Row | null = (storageBreakdownRaw as Row | undefined)?.probe ?? null;

  // Real live partitions for the SIEM log table — one row per day,
  // bucketed hot/warm/cold/archived by age. Replaces the static
  // dashboard with genuine partitioned-data view.
  const { data: logPartitions, error: partitionsError } = useQuery({
    queryKey: ['dl-log-partitions'],
    queryFn: async () => {
      const res = await api.get('/data-lake/partitions/daily/log_entries?days=30');
      return res.data;
    },
  });

  const STORAGE_COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#8B5CF6'];

  // Real ingest trend from /data-lake/dashboard/ingestion-trend:
  // hourly ingested-record counts over the last 24h, summed across the
  // built-in ingest surfaces and org-scoped on the backend. Replaces
  // the fabricated 5-point line (base rate × [0.9, 0.95, 1.0] jitter).
  // No ingested rows → empty array → the chart's empty state.
  const { data: ingestTrendRaw, error: ingestTrendError } = useQuery({
    queryKey: ['dl-ingestion-trend'],
    queryFn: () => datalakeApi.getIngestionTrend(24),
  });
  const ingestTrendData: Array<{ time: string; rate: number }> = useMemo(() => {
    const points = (ingestTrendRaw as any)?.points;
    if (!Array.isArray(points)) return [];
    return points.map((p: any) => ({
      // "2026-07-01T13:00:00" -> "13:00"
      time: typeof p.time === 'string' ? p.time.slice(11, 16) : String(p.time ?? ''),
      rate: Number(p.count) || 0,
    }));
  }, [ingestTrendRaw]);

  // Only pipelines with a measured success rate are charted.
  const pipelineHealthData = useMemo(() => {
    return pipelines
      .filter((p: Pipeline) => p.successRate != null)
      .map((p: Pipeline) => ({
        pipeline: p.name,
        success: p.successRate as number,
        failure: Math.round((100 - (p.successRate as number)) * 10) / 10,
      }));
  }, [pipelines]);

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Database className="w-8 h-8 text-emerald-400" />
            Data Lake Dashboard
          </h1>
          <p className="text-gray-400">Data Ingestion, Pipeline Orchestration & Query Engine Management</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Data Sources Active</p>
                <p className="text-3xl font-bold">{stats.activeSources}</p>
              </div>
              <Database className="w-8 h-8 text-blue-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Total Events</p>
                <p className="text-3xl font-bold">{stats.totalEvents}</p>
              </div>
              <TrendingUp className="w-8 h-8 text-green-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Total Storage</p>
                <p className="text-3xl font-bold">{stats.totalStorage}</p>
              </div>
              <HardDrive className="w-8 h-8 text-purple-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active Pipelines</p>
                <p className="text-3xl font-bold">{stats.activePipelines}</p>
              </div>
              <Workflow className="w-8 h-8 text-orange-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-700">
          <div className="flex gap-8">
            {[
              { id: 'sources', label: 'Data Sources', icon: Database },
              { id: 'pipelines', label: 'Pipelines', icon: Workflow },
              { id: 'query', label: 'Query Engine', icon: Search },
              { id: 'catalog', label: 'Data Catalog', icon: Layers },
              { id: 'partitions', label: 'Partitions', icon: Layers },
              { id: 'storage', label: 'Storage Tiers', icon: HardDrive },
            ].map((tab) => {
              const TabIcon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={clsx(
                    'pb-4 px-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-emerald-400 text-emerald-400'
                      : 'border-transparent text-gray-400 hover:text-white'
                  )}
                >
                  <TabIcon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Sources Tab */}
        {activeTab === 'sources' && (
          <div>
            <div className="space-y-2 mb-4">
              <LoadErrorBanner what="data sources" error={sourcesError} />
              <LoadErrorBanner what="the ingestion trend" error={ingestTrendError} />
            </div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => setShowModal(true)}
                className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New Source
              </button>
            </div>

            <div className="mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Ingestion Rate Trend (events/hour, last 24h)</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={ingestTrendData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="time" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Line type="monotone" dataKey="rate" stroke="#10B981" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Source Name</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Ingestion Rate</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Total Events</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Health</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Last Sync</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map((source: DataSource) => (
                    <tr
                      key={source.id}
                      onClick={() => openSource(source)}
                      className="border-t border-gray-700 hover:bg-gray-700/50 cursor-pointer"
                    >
                      <td className="px-6 py-4 text-sm font-medium text-white">{source.name}</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{fmtEps(source.ingestionRate)}</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{fmtCount(source.events)}</td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-3 py-1 rounded text-xs font-medium flex items-center gap-2 w-fit',
                            source.health === 'Healthy'
                              ? 'bg-green-900/40 text-green-300'
                              : 'bg-yellow-900/40 text-yellow-300'
                          )}
                        >
                          {source.health === 'Healthy' ? <CheckCircle className="w-3 h-3" /> : <AlertCircle className="w-3 h-3" />}
                          {source.health}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">{fmtTs(source.lastSync)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Pipelines Tab */}
        {activeTab === 'pipelines' && (
          <div>
            <div className="mb-4">
              <LoadErrorBanner what="pipelines" error={pipelinesError} />
            </div>
            <div className="grid grid-cols-2 gap-8 mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Pipeline Success Rates</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={pipelineHealthData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="pipeline" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Legend />
                    <Bar dataKey="success" fill="#10B981" />
                    <Bar dataKey="failure" fill="#EF4444" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-4">
                {pipelines.slice(0, 3).map((pipeline: Pipeline) => (
                  <div key={pipeline.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4 dark:bg-gray-800 dark:border-gray-700">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-semibold text-white">{pipeline.name}</h4>
                      <span
                        className={clsx(
                          'px-2 py-1 rounded text-xs font-medium flex items-center gap-1',
                          pipeline.status === 'Running'
                            ? 'bg-green-900/40 text-green-300'
                            : pipeline.status === 'Completed'
                              ? 'bg-blue-900/40 text-blue-300'
                              : 'bg-gray-900/40 text-gray-300'
                        )}
                      >
                        {pipeline.status === 'Running' ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
                        {pipeline.status}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 mb-2">Success Rate: <span className="text-green-400 font-semibold">{pipeline.successRate != null ? `${pipeline.successRate}%` : NA}</span></p>
                    <div className="flex justify-between text-xs text-gray-500">
                      <span>{pipeline.builtin ? pipeline.schedule ?? NA : `Last run: ${fmtTs(pipeline.lastRun)}`}</span>
                      <span>{pipeline.duration ?? NA}</span>
                    </div>
                    {pipeline.note && <p className="text-xs text-gray-500 mt-1">{pipeline.note}</p>}
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Pipeline Name</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Success Rate</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Last Run</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {pipelines.map((pipeline: Pipeline) => (
                    <tr
                      key={pipeline.id}
                      onClick={() => setSelectedPipeline(pipeline)}
                      className="border-t border-gray-700 hover:bg-gray-700/50 cursor-pointer"
                    >
                      <td className="px-6 py-4 text-sm font-medium text-white">
                        {pipeline.name}
                        {pipeline.note && <div className="text-xs font-normal text-gray-500">{pipeline.note}</div>}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={clsx(
                            'px-3 py-1 rounded text-xs font-medium',
                            pipeline.status === 'Running' ? 'bg-green-900/40 text-green-300' : pipeline.status === 'Completed' ? 'bg-blue-900/40 text-blue-300' : 'bg-gray-900/40 text-gray-300'
                          )}
                        >
                          {pipeline.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        {pipeline.successRate != null ? (
                          <div className="flex items-center gap-2">
                            <div className="w-20 h-2 bg-gray-700 rounded-full dark:bg-gray-700">
                              <div className="h-full bg-green-500 rounded-full" style={{ width: `${pipeline.successRate}%` }} />
                            </div>
                            <span className="text-gray-400 text-xs">{pipeline.successRate}%</span>
                          </div>
                        ) : (
                          <span className="text-gray-500 text-xs">{NA}</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">{fmtTs(pipeline.lastRun)}</td>
                      <td className="px-6 py-4 text-sm text-gray-400">{pipeline.duration ?? NA}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Query Engine Tab */}
        {activeTab === 'query' && (
          <div className="space-y-6">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Query Interface</h3>

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-300 mb-2">Query Language</label>
                <div className="flex gap-4">
                  {[
                    { id: 'sql', label: 'SQL' },
                    { id: 'kql', label: 'KQL (Kusto)' },
                    { id: 'spl', label: 'SPL (Splunk)' },
                  ].map((lang) => (
                    <button
                      key={lang.id}
                      onClick={() => setQueryLanguage(lang.id as typeof queryLanguage)}
                      className={clsx(
                        'px-4 py-2 rounded font-medium text-sm transition-colors',
                        queryLanguage === lang.id
                          ? 'bg-emerald-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      )}
                    >
                      {lang.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Query</label>
                <textarea
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-4 py-3 text-white font-mono text-sm placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                  placeholder={queryLanguage === 'sql' ? 'SELECT * FROM user_events WHERE date > \'2026-03-20\'' : 'Type your query here...'}
                  rows={6}
                />
              </div>

              <div className="flex gap-4 mt-4">
                <button
                  onClick={() => setQueryInput('')}
                  className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors"
                >
                  Clear
                </button>
                <button
                  disabled={!queryInput.trim() || queryRunning}
                  onClick={async () => {
                    setQueryRunning(true);
                    setQueryResult(null);
                    try {
                      const res = await api.post('/data-lake/query', {
                        query: queryInput,
                        query_language: queryLanguage,
                      });
                      const d = res.data || {};
                      if (d.mode === 'sql' && Array.isArray(d.columns)) {
                        const header = d.columns.join(' | ');
                        const sep = d.columns.map(() => '---').join(' | ');
                        const body = (d.rows || [])
                          .map((r: any) => d.columns.map((c: string) => String(r[c] ?? '')).join(' | '))
                          .join('\n');
                        setQueryResult(
                          `${d.row_count} row(s) in ${d.execution_time_ms}ms\n\n${header}\n${sep}\n${body}`
                        );
                      } else {
                        setQueryResult(JSON.stringify(d, null, 2));
                      }
                    } catch (err: unknown) {
                      setQueryResult('Error: ' + describeLoadError(err));
                    } finally {
                      setQueryRunning(false);
                    }
                  }}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-2 rounded transition-colors font-medium disabled:opacity-50"
                >
                  {queryRunning ? 'Running...' : 'Execute Query'}
                </button>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
              <h4 className="font-semibold text-white mb-4">Query Results</h4>
              <div className="bg-gray-700/50 rounded p-4 text-gray-300 font-mono text-sm max-h-60 overflow-y-auto">
                <pre>{queryResult ?? 'Execute a query to see results here.'}</pre>
              </div>
            </div>
          </div>
        )}

        {/* Catalog Tab */}
        {activeTab === 'catalog' && (
          <div>
            <div className="mb-6">
              <div className="mb-4">
                <LoadErrorBanner what="the data catalog" error={catalogError} />
              </div>
              <input
                type="text"
                placeholder="Search data catalog..."
                value={catalogSearch}
                onChange={(e) => setCatalogSearch(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-4 py-3 text-white placeholder-gray-500 dark:bg-gray-800 dark:border-gray-700"
              />
              {catalogSearch && (
                <div className="mt-2 text-xs text-gray-400">
                  {filteredCatalog.length} of {(catalog as any[]).length} matching "{catalogSearch}"
                </div>
              )}
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Dataset</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Type</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Rows</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Size</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Columns</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Last event</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCatalog.map((item: any) => {
                    const rowCount = item.row_count ?? item.rows ?? null;
                    const bytes = item.size_bytes ?? 0;
                    const sizeLabel = bytes >= 1024 ** 3
                      ? `${(bytes / 1024 ** 3).toFixed(2)} GB`
                      : bytes >= 1024 ** 2
                        ? `${(bytes / 1024 ** 2).toFixed(1)} MB`
                        : bytes >= 1024
                          ? `${(bytes / 1024).toFixed(1)} KB`
                          : bytes > 0
                            ? `${bytes} B`
                            : '—';
                    const columnCount = Array.isArray(item.schema) ? item.schema.length : 0;
                    const last = item.last_event_at
                      ? new Date(item.last_event_at).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
                      : '—';
                    return (
                      <tr key={item.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                        <td className="px-6 py-4 text-sm font-medium text-white">
                          <div className="flex items-center gap-2">
                            <span>{item.name}</span>
                            {item.queryable && (
                              <span className="text-[10px] bg-emerald-900/40 text-emerald-300 px-2 py-0.5 rounded">queryable</span>
                            )}
                            {item.tenant_scoped && (
                              <span className="text-[10px] bg-blue-900/40 text-blue-300 px-2 py-0.5 rounded">tenant-scoped</span>
                            )}
                          </div>
                          {item.description && (
                            <div className="text-xs text-gray-500 mt-1">{item.description}</div>
                          )}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-300">{item.type ?? item.entity_type ?? '—'}</td>
                        <td className="px-6 py-4 text-sm text-gray-300">{rowCount != null ? Number(rowCount).toLocaleString() : NA}</td>
                        <td className="px-6 py-4 text-sm text-gray-300">{sizeLabel}</td>
                        <td className="px-6 py-4 text-sm text-gray-300">{columnCount || '—'}</td>
                        <td className="px-6 py-4 text-sm text-gray-400">{last}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Partitions Tab — real daily partitions of log_entries bucketed by age */}
        {activeTab === 'partitions' && (
          <div>
            <div className="mb-4">
              <LoadErrorBanner what="log partitions" error={partitionsError} />
            </div>
            <div className="mb-6 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold">SIEM Log Partitions (last 30 days)</h3>
                <p className="text-sm text-gray-400">
                  One partition per day · hot (&lt;7d) / warm (7–30d) / cold (30–365d) / archived (&gt;1y)
                </p>
              </div>
              {logPartitions && (
                <div className="text-sm text-gray-400">
                  {(logPartitions as any).partition_count} partitions ·{' '}
                  {(logPartitions as any).total_rows_scanned != null ? Number((logPartitions as any).total_rows_scanned).toLocaleString() : NA} rows
                </div>
              )}
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden dark:bg-gray-800 dark:border-gray-700">
              <table className="w-full">
                <thead className="bg-gray-700/50 border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Partition Key</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Day</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Tier</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Rows</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Size</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-300">Range</th>
                  </tr>
                </thead>
                <tbody>
                  {(logPartitions as any)?.partitions?.length ? (
                    (logPartitions as any).partitions.map((p: any) => {
                      const bytes = p.size_bytes || 0;
                      const sizeLabel =
                        bytes >= 1024 ** 3 ? `${(bytes / 1024 ** 3).toFixed(2)} GB`
                        : bytes >= 1024 ** 2 ? `${(bytes / 1024 ** 2).toFixed(1)} MB`
                        : bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB`
                        : bytes > 0 ? `${bytes} B` : '—';
                      const tierColor =
                        p.storage_tier === 'hot' ? 'bg-red-900/40 text-red-300'
                        : p.storage_tier === 'warm' ? 'bg-orange-900/40 text-orange-300'
                        : p.storage_tier === 'cold' ? 'bg-blue-900/40 text-blue-300'
                        : 'bg-gray-900/40 text-gray-300';
                      return (
                        <tr key={p.partition_key} className="border-t border-gray-700 hover:bg-gray-700/50">
                          <td className="px-6 py-4 text-sm font-mono text-white">{p.partition_key}</td>
                          <td className="px-6 py-4 text-sm text-gray-300">{p.day?.slice(0, 10)}</td>
                          <td className="px-6 py-4 text-sm">
                            <span className={clsx('px-3 py-1 rounded text-xs font-medium', tierColor)}>
                              {p.storage_tier}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm text-gray-300">{Number(p.record_count).toLocaleString()}</td>
                          <td className="px-6 py-4 text-sm text-gray-300">{sizeLabel}</td>
                          <td className="px-6 py-4 text-xs text-gray-500">
                            {p.first_at?.slice(11, 16)} → {p.last_at?.slice(11, 16)}
                          </td>
                        </tr>
                      );
                    })
                  ) : partitionsError ? null : (
                    <tr>
                      <td colSpan={6} className="px-6 py-6 text-center text-sm text-gray-500">
                        No log_entries in the last 30 days for this org.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Storage Tab */}
        {activeTab === 'storage' && storageError && (
          <LoadErrorBanner what="the storage breakdown" error={storageError} />
        )}
        {activeTab === 'storage' && !storageError && storageProbe && (
          <div className="mb-4 text-sm bg-gray-800 border border-gray-700 rounded-lg p-3 text-gray-300">
            Storage probe: {storageProbe.method ?? 'unknown method'}
            {storageProbe.available ? '' : ' · not available'}
            {storageProbe.reason ? ` · ${storageProbe.reason}` : ''}
            {storageProbe.attribution ? ` · ${storageProbe.attribution}` : ''}
            {Array.isArray(storageProbe.tables_measured) ? ` · tables measured: ${storageProbe.tables_measured.join(', ')}` : ''}
          </div>
        )}
        {activeTab === 'storage' && !storageError && storageBreakdown.length === 0 && (
          <p className="text-sm text-gray-400 text-center py-10 border border-dashed border-gray-700 rounded-lg">
            No storage figure is available from this database.
          </p>
        )}
        {activeTab === 'storage' && !storageError && storageBreakdown.length > 0 && (
          <div className="grid grid-cols-2 gap-8">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Storage Tier Breakdown</h3>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={storageBreakdown}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}GB`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {storageBreakdown.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={STORAGE_COLORS[index % STORAGE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="space-y-4">
              {(() => {
                const totalValue = storageBreakdown.reduce((sum, t) => sum + t.value, 0);
                // Same real total_bytes figure as the summary card.
                const totalLabel = stats.totalStorage;
                return (
                  <>
                    {storageBreakdown.map((tier, idx) => (
                      <div key={tier.name} className="bg-gray-800 border border-gray-700 rounded-lg p-4 dark:bg-gray-800 dark:border-gray-700">
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-semibold text-white">{tier.name} Storage</h4>
                          <span className="text-sm text-gray-400">{tier.size}</span>
                        </div>
                        <div className="flex justify-between text-xs text-gray-500 mb-2">
                          <span>Capacity Used</span>
                          <span>{Math.round((tier.value / (totalValue || 1)) * 100)}%</span>
                        </div>
                        <div className="w-full h-2 bg-gray-700 rounded-full dark:bg-gray-700">
                          <div
                            className="h-full rounded-full"
                            style={{
                              backgroundColor: STORAGE_COLORS[idx],
                              width: `${Math.round((tier.value / (totalValue || 1)) * 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                    ))}

                    <div className="bg-gray-700/50 rounded-lg p-4 mt-4">
                      <p className="text-sm text-gray-400 mb-2">Total Capacity</p>
                      <p className="text-3xl font-bold text-emerald-400">{totalLabel}</p>
                    </div>
                  </>
                );
              })()}
            </div>
          </div>
        )}

        {/* Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">Add Data Source</h2>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <form className="space-y-4" onSubmit={async (e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                try {
                  await api.post('/data-lake/sources', {
                    name: fd.get('name'),
                    source_type: fd.get('source_type'),
                    ingestion_type: fd.get('ingestion_type'),
                    format: fd.get('format'),
                    connection_config: { connection_string: fd.get('conn') || '' },
                  });
                  setShowModal(false);
                  window.location.reload();
                } catch (err) {
                  console.error('Failed to add source:', err);
                  alert(`Failed to add source: ${describeLoadError(err)}`);
                }
              }}>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Source Name</label>
                  <input name="name" required type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="e.g., Customer Events" />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Type</label>
                    <select name="source_type" required className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                      <option value="syslog">Syslog</option>
                      <option value="api">API</option>
                      <option value="database">Database</option>
                      <option value="file">File</option>
                      <option value="cloud">Cloud</option>
                      <option value="stream">Stream</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Ingestion</label>
                    <select name="ingestion_type" required className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                      <option value="batch">Batch</option>
                      <option value="streaming">Streaming</option>
                      <option value="polling">Polling</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Format</label>
                    <select name="format" required className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                      <option value="json">JSON</option>
                      <option value="csv">CSV</option>
                      <option value="syslog">Syslog</option>
                      <option value="cef">CEF</option>
                      <option value="parquet">Parquet</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Connection String</label>
                  <input name="conn" type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="e.g., postgresql://host/db or https://api.example.com" />
                </div>
                <div className="flex gap-4 mt-6">
                  <button type="button" onClick={() => setShowModal(false)} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors">Cancel</button>
                  <button type="submit" className="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded transition-colors">Add Source</button>
                </div>
              </form>
            </div>
          </div>
        )}

        {selectedSource && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">{selectedSource.name}</h2>
                <button
                  onClick={() => setSelectedSource(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <p className="text-sm text-gray-400">Ingestion Rate</p>
                  <p className="text-white font-medium">{fmtEps(selectedSource.ingestionRate)}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Total Events</p>
                  <p className="text-white font-medium">{fmtCount(selectedSource.events)}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Health</p>
                  <p className={clsx('font-medium', selectedSource.health === 'Healthy' ? 'text-green-400' : 'text-yellow-400')}>
                    {selectedSource.health}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Last Sync</p>
                  <p className="text-white font-medium">{fmtTs(selectedSource.lastSync)}</p>
                </div>
                {selectedSource.lastError && (
                  <div>
                    <p className="text-sm text-gray-400">Last Error</p>
                    <p className="text-red-300 font-medium break-words">{selectedSource.lastError}</p>
                  </div>
                )}
                {selectedSource.ingestionNote && <p className="text-sm text-gray-300">{selectedSource.ingestionNote}</p>}
                <p className="text-xs text-gray-400">
                  {selectedSource.builtin ? `Built-in source (table ${selectedSource.builtinTable ?? NA})` : 'Registered source'}
                  {selectedSource.configKeys ? ` · connection config stored encrypted (keys: ${selectedSource.configKeys.join(', ') || 'none'})` : ''}
                </p>
                <div className="border-t border-gray-700 pt-3 space-y-2 text-sm">
                  <p className="text-gray-400">Lineage</p>
                  {!sourceDetail && <p className="text-gray-500">Loading...</p>}
                  <LoadErrorBanner what="lineage" error={sourceDetail?.lineageError} />
                  {sourceDetail?.lineage && (
                    <ul className="text-xs text-gray-300 list-disc ml-4">
                      {(sourceDetail.lineage.downstream_consumers ?? []).length === 0 && <li>No downstream consumer recorded.</li>}
                      {(sourceDetail.lineage.downstream_consumers ?? []).map((c: Row, i: number) => (
                        <li key={i}>{c.name ?? c.task ?? c.id} ({c.type}{c.basis ? `, ${c.basis}` : ''})</li>
                      ))}
                      <li>{(sourceDetail.lineage.partitions ?? []).length} partition(s)</li>
                    </ul>
                  )}
                  <p className="text-gray-400">Quality</p>
                  <LoadErrorBanner what="quality" error={sourceDetail?.qualityError} />
                  {sourceDetail?.quality && (
                    <ul className="text-xs text-gray-300 grid grid-cols-2 gap-x-4">
                      {Object.entries(sourceDetail.quality as Record<string, unknown>)
                        .filter(([, v]) => v === null || ['string', 'number', 'boolean'].includes(typeof v))
                        .map(([k, v]) => (
                          <li key={k}>{k.replace(/_/g, ' ')}: {v === null ? NA : String(v)}</li>
                        ))}
                    </ul>
                  )}
                </div>
              </div>

              <button
                onClick={() => setSelectedSource(null)}
                className="w-full bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded mt-6 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
