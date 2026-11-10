export interface GetOptions {
  redirect?: RequestRedirect;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export async function get(url: string, { redirect = 'follow', headers = {}, timeoutMs = 15_000 }: GetOptions = {}): Promise<Response | null> {
  try {
    return await fetch(url, { redirect, signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': 'alil-launch', ...headers } });
  } catch {
    return null;
  }
}

/** Many hosts rate limit with 429 or 503, so those get one retry after the wait they ask for, up to 5 seconds. */
export async function politeGet(url: string, options: GetOptions = {}): Promise<Response | null> {
  const res = await get(url, options);
  if (!res || (res.status !== 429 && res.status !== 503)) return res;
  await res.body?.cancel().catch(() => undefined);
  const wait = Math.min(5, Math.max(1, Number(res.headers.get('retry-after')) || 2));
  await new Promise((resolve) => setTimeout(resolve, wait * 1000));
  return get(url, options);
}

/** Reads at most `max` bytes, so a huge or endless response cannot stall the scan. */
export async function readBytes(res: Response, max: number): Promise<Buffer> {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (size < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.length;
    }
  } catch {
    // A cut-off body still has useful content.
  } finally {
    reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks).subarray(0, max);
}

export async function readText(res: Response, max = 5_000_000): Promise<string> {
  return (await readBytes(res, max)).toString('utf8');
}

export const isHtml = (res: Response): boolean => /text\/html|application\/xhtml/.test(res.headers.get('content-type') ?? '');

export async function readHtml(res: Response, max = 2_000_000): Promise<string> {
  if (!isHtml(res)) {
    await res.body?.cancel().catch(() => undefined);
    return '';
  }
  return readText(res, max);
}
