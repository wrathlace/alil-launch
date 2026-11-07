import { createHash } from 'node:crypto';

export function sha(input: string, length = 16): string {
  return createHash('sha256').update(input).digest('hex').slice(0, length);
}

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Keeps a short prefix so a person can recognise the value. Never reveals the rest. */
export function redact(secret: string, keep = 4): string {
  const visible = secret.length <= keep * 2 ? 0 : keep;
  return `${secret.slice(0, visible)}${'*'.repeat(8)}`;
}

export function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

const TEST_PATH =
  /(^|\/)(tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|examples?|samples?|docs?|testdata|stories|cypress|e2e)(\/|$)|\.(test|spec|stories|e2e)\.[a-z]+$/i;

export function isTestPath(path: string): boolean {
  return TEST_PATH.test(path);
}

export function isCommentLine(line: string): boolean {
  return /^\s*(\/\/|#|\*|\/\*|<!--|--)/.test(line);
}

export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/** Fetches JSON, retrying server errors and rate limits, and throws once the retries run out. */
export async function fetchJson<T = any>(url: string, init: RequestInit = {}, { tries = 2, timeoutMs = 30_000, waitMs = 1000 } = {}): Promise<T> {
  let failure = 'no response';
  for (let attempt = 0; attempt < tries; attempt++) {
    if (attempt) await new Promise((done) => setTimeout(done, waitMs));
    try {
      const res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      if (res.ok) return (await res.json()) as T;
      failure = `HTTP ${res.status}`;
      if (res.status < 500 && res.status !== 403 && res.status !== 429) break;
    } catch (error) {
      failure = (error as Error).message;
    }
  }
  throw new Error(`${new URL(url).hostname}: ${failure}`);
}

export function compareVersions(a: string, b: string): number {
  const parts = (v: string): number[] => v.replace(/^v/, '').split(/[.+-]/).map((p) => Number.parseInt(p, 10) || 0);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const diff = (x[i] ?? 0) - (y[i] ?? 0);
    if (diff) return diff;
  }
  return 0;
}

export function parseJson<T = any>(text: string | null): T | null {
  if (!text) return null;
  try {
    return JSON.parse(text.replace(/^﻿/, '')) as T;
  } catch {
    return null;
  }
}
