import { readFileSync, writeFileSync } from 'node:fs';
import type { Finding } from '../types.js';

export const DEFAULT_BASELINE = '.alil-launch-baseline.json';

/** Stores hashes only, so a baseline file is safe to commit. */
export function readBaseline(path: string): Set<string> {
  try {
    const data = JSON.parse(readFileSync(path, 'utf8'));
    return new Set(Array.isArray(data.fingerprints) ? data.fingerprints : []);
  } catch {
    return new Set();
  }
}

export function writeBaseline(path: string, findings: Finding[]): void {
  const fingerprints = [...new Set(findings.map((f) => f.fingerprint))].sort();
  writeFileSync(path, `${JSON.stringify({ version: 1, fingerprints }, null, 2)}\n`);
}
