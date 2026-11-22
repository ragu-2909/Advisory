export class HttpError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly responseBody?: unknown
  ) {
    super(message);
  }
}

export async function fetchJson<T>(url: string | URL, init: RequestInit = {}, timeoutMs = 20_000): Promise<T> {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  const text = await response.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = text;
  }
  if (!response.ok) throw new HttpError(`HTTP ${response.status} from ${new URL(url).hostname}`, response.status, body);
  return body as T;
}
