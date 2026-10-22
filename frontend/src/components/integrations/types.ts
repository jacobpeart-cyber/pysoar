/**
 * Shapes of the integration routes (src/schemas/integrations.py), as the
 * marketplace page reads them. `rating`, `is_community`, `last_updated` and
 * `install_count` are deliberately absent: they are not marketplace
 * statistics (docs/integrations/connectors.md) and the page does not show them.
 */

export type ImplementationStatus = 'implemented' | 'log_ingest' | 'planned';
export type HealthStatus = 'healthy' | 'unhealthy' | 'unknown' | 'unavailable';

export interface ConnectorField {
  name: string;
  type: string;
  display_name: string;
  description?: string | null;
  required: boolean;
  default?: unknown;
  secret: boolean;
}

export interface JsonSchemaProperty {
  type?: string;
  description?: string;
  enum?: unknown[];
  items?: { type?: string };
  minimum?: number;
  maximum?: number;
  minLength?: number;
  minItems?: number;
  default?: unknown;
}

export interface JsonObjectSchema {
  type?: string;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface ConnectorAction {
  name: string;
  display_name: string;
  description: string;
  params_schema: JsonObjectSchema;
  output: string;
  idempotent: boolean;
  side_effect: boolean;
  action_type: string;
}

export interface Connector {
  id: string;
  name: string;
  display_name: string;
  description?: string | null;
  vendor?: string | null;
  category: string;
  integration_role?: string | null;
  implementation_status: ImplementationStatus | string;
  /** True when the SIEM cloud poller pulls this connector's events (computed by the server). */
  ingest?: boolean;
  installable: boolean;
  verification: string;
  test_call?: string | null;
  config_fields: ConnectorField[];
  credential_fields: ConnectorField[];
  actions: ConnectorAction[];
}

export interface InstalledIntegration {
  id: string;
  connector_id: string;
  display_name: string;
  config: Record<string, unknown>;
  status: string;
  health_status: HealthStatus | string;
  last_health_check?: string | null;
  last_successful_action?: string | null;
  error_message?: string | null;
}

export interface IntegrationTestResult {
  status: string;
  message?: string | null;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface InstalledAction {
  id: string;
  connector_id: string;
  action_name: string;
  display_name: string;
  description?: string | null;
  action_type: string;
  input_schema: JsonObjectSchema;
  requires_approval: boolean;
  is_idempotent: boolean;
}

/**
 * One execution. The execute route and the per-integration list return
 * `installation_id`; the flat list (`GET /integrations/executions`) returns
 * the stored row, which names the install `installed_id` and keeps
 * `input_data` / `output_data` as JSON text. All three carry the stored
 * `error_code` (the connector's code) and `http_status` (the vendor's).
 */
export interface IntegrationExecution {
  id: string;
  installation_id?: string;
  installed_id?: string;
  action_id: string;
  triggered_by?: string | null;
  playbook_run_id?: string | null;
  status: string;
  input_data?: unknown;
  output_data?: unknown;
  started_at?: string | null;
  completed_at?: string | null;
  created_at?: string | null;
  duration_ms?: number | null;
  error_message?: string | null;
  error_code?: string | null;
  http_status?: number | null;
  retry_count?: number | null;
}

/**
 * A registered webhook endpoint as the flat list (`GET /integrations/webhooks`)
 * returns the stored row: the install is `installed_id`, `event_types` is
 * JSON text, `last_received` / `received_count` are the inbound counters
 * (nothing increments them until an inbound receiver exists).
 */
export interface WebhookEndpointRow {
  id: string;
  installed_id: string;
  endpoint_path: string;
  http_method?: string | null;
  event_types?: unknown;
  transform_template?: string | null;
  is_active?: boolean | null;
  last_received?: string | null;
  received_count?: number | null;
  created_at?: string | null;
  updated_at?: string | null;
}

/** `event_types` of a stored webhook row: a JSON array as text, or already a list. */
export function webhookEventTypes(value: unknown): string[] {
  const v = parseJsonish(value);
  return Array.isArray(v) ? v.map((x) => String(x)) : [];
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page?: number;
  size?: number;
  pages?: number;
}

/** The error body of a refused request, whether the handler nests it under `detail` or not. */
export function errorBody(err: unknown): Record<string, unknown> | null {
  const data = (err as { response?: { data?: unknown } })?.response?.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const body = data as Record<string, unknown>;
  const nested = body.detail;
  if (nested && typeof nested === 'object' && !Array.isArray(nested) && 'error' in (nested as object)) {
    return nested as Record<string, unknown>;
  }
  return body;
}

export function httpStatusOf(err: unknown): number | null {
  const s = (err as { response?: { status?: number } })?.response?.status;
  return typeof s === 'number' ? s : null;
}

/** `detail` of a refused request as text (the 501 `not_implemented` reason, for example). */
export function errorDetailText(err: unknown): string | null {
  const body = errorBody(err);
  if (!body) return null;
  const d = body.detail;
  if (typeof d === 'string') return d;
  if (typeof body.message === 'string') return body.message;
  return null;
}

/** JSON text from the stored row, or the value itself. */
export function parseJsonish(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

export function formatJson(value: unknown): string {
  const v = parseJsonish(value);
  if (v === null || v === undefined || v === '') return '';
  if (typeof v === 'string') return v;
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function formatTime(value: string | null | undefined): string | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

/**
 * The server's private-address refusal (src/integrations/netguard.py
 * PRIVATE_TARGET_HINT) carries the allow-list instruction after a `; `:
 * "refused: target resolves to a private address; add its network to
 * OUTBOUND_PRIVATE_ALLOWLIST to allow it". Split it so the instruction can be
 * shown as its own line. Both parts are the server's text.
 */
export const PRIVATE_REFUSAL_PREFIX = 'refused: target resolves to a private address';

export function splitPrivateRefusal(message: string | null | undefined): { message: string; hint: string | null } {
  const text = message ?? '';
  const at = text.indexOf(PRIVATE_REFUSAL_PREFIX);
  if (at < 0) return { message: text, hint: null };
  const sep = text.indexOf('; ', at + PRIVATE_REFUSAL_PREFIX.length);
  if (sep < 0) return { message: text, hint: null };
  return { message: text.slice(0, sep), hint: text.slice(sep + 2) };
}
