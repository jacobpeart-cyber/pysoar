import type { JsonObjectSchema, JsonSchemaProperty } from './types';

/**
 * How a params_schema property is edited:
 * - `enum`: a select of the declared values
 * - `boolean`: a select (not set / true / false)
 * - `number`: integer or number input
 * - `list`: an array of strings or numbers as a comma-separated input
 * - `json`: an object or an array of objects as JSON text
 * - `text`: everything else
 */
export type InputKind = 'enum' | 'boolean' | 'number' | 'list' | 'json' | 'text';

export function inputKind(prop: JsonSchemaProperty): InputKind {
  if (Array.isArray(prop.enum) && prop.enum.length) return 'enum';
  switch (prop.type) {
    case 'boolean':
      return 'boolean';
    case 'integer':
    case 'number':
      return 'number';
    case 'array': {
      const it = prop.items?.type;
      return !it || it === 'string' || it === 'integer' || it === 'number' ? 'list' : 'json';
    }
    case 'object':
      return 'json';
    default:
      return 'text';
  }
}

export function schemaProperties(schema: JsonObjectSchema | null | undefined): [string, JsonSchemaProperty][] {
  return Object.entries(schema?.properties ?? {});
}

export function isRequired(schema: JsonObjectSchema | null | undefined, name: string): boolean {
  return (schema?.required ?? []).includes(name);
}

/**
 * Form strings -> `input_data`. Blank inputs are left out (the server
 * reports a missing required one). A value that does not parse is returned
 * as a problem naming the parameter, so the request is not sent.
 */
export function buildInputData(
  schema: JsonObjectSchema | null | undefined,
  values: Record<string, string>,
): { data: Record<string, unknown>; problems: string[] } {
  const data: Record<string, unknown> = {};
  const problems: string[] = [];
  for (const [name, prop] of schemaProperties(schema)) {
    const raw = (values[name] ?? '').trim();
    if (raw === '') {
      if (isRequired(schema, name)) problems.push(`missing required parameter '${name}'`);
      continue;
    }
    const kind = inputKind(prop);
    if (kind === 'boolean') {
      data[name] = raw === 'true';
    } else if (kind === 'number' || (kind === 'enum' && (prop.type === 'integer' || prop.type === 'number'))) {
      const n = Number(raw);
      if (!Number.isFinite(n) || (prop.type === 'integer' && !Number.isInteger(n))) {
        problems.push(`parameter '${name}' must be of type ${prop.type}`);
      } else {
        data[name] = n;
      }
    } else if (kind === 'list') {
      const parts = raw.split(',').map((p) => p.trim()).filter(Boolean);
      const itemType = prop.items?.type;
      if (itemType === 'integer' || itemType === 'number') {
        const nums = parts.map(Number);
        if (nums.some((n) => !Number.isFinite(n) || (itemType === 'integer' && !Number.isInteger(n)))) {
          problems.push(`parameter '${name}' must be a comma-separated list of ${itemType}s`);
        } else {
          data[name] = nums;
        }
      } else {
        data[name] = parts;
      }
    } else if (kind === 'json') {
      try {
        data[name] = JSON.parse(raw);
      } catch {
        problems.push(`parameter '${name}' must be valid JSON`);
      }
    } else {
      data[name] = raw;
    }
  }
  return { data, problems };
}
