/**
 * Typed Blob downloads shared by the pages: save a response body under the
 * server's Content-Disposition filename, and turn a blob-typed error body
 * back into JSON so LoadErrorBanner / ActionErrorBanner can read its key.
 */
interface BlobErrorLike {
  response?: { data?: unknown };
}

export async function parseBlobError(err: unknown): Promise<unknown> {
  const resp = (err as BlobErrorLike | null)?.response;
  if (resp && resp.data instanceof Blob) {
    try {
      resp.data = JSON.parse(await resp.data.text());
    } catch {
      /* body was not JSON; the status line speaks for itself */
    }
  }
  return err;
}

export function filenameFromDisposition(header: unknown, fallback: string): string {
  if (typeof header === 'string') {
    const m = header.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
    if (m) return decodeURIComponent(m[1]);
  }
  return fallback;
}

export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
