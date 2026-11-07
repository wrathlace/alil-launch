import type { Severity } from '../types.js';
import { compareVersions, fetchJson } from '../core/util.js';

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
/** NVD allows 5 requests per 30 seconds without a key and 50 with one. */
const delayMs = (): number => (process.env.NVD_API_KEY ? 700 : 6500);

export interface NvdQuery {
  /** The CPE to match, such as cpe:2.3:a:wordpress:wordpress:6.4.3 */
  cpe: string;
  version: string;
  /** Rejects CVEs that merely mention the product, such as a library bundled alongside it. */
  accepts(criteria: string): boolean;
}

export interface NvdMatch {
  id: string;
  severity: Severity;
  fixed: string;
  summary: string;
}

const SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

function severityOf(cve: any): Severity {
  const metrics = cve.metrics ?? {};
  const row = metrics.cvssMetricV40?.[0] ?? metrics.cvssMetricV31?.[0] ?? metrics.cvssMetricV30?.[0] ?? metrics.cvssMetricV2?.[0];
  return SEVERITY[String(row?.cvssData?.baseSeverity ?? row?.baseSeverity).toUpperCase()] ?? 'medium';
}

function covers(match: any, version: string): boolean {
  const exact = String(match.criteria).split(':')[5];
  if (exact && exact !== '*' && exact !== '-') return compareVersions(exact, version) === 0;
  if (match.versionStartIncluding && compareVersions(version, match.versionStartIncluding) < 0) return false;
  if (match.versionStartExcluding && compareVersions(version, match.versionStartExcluding) <= 0) return false;
  if (match.versionEndExcluding && compareVersions(version, match.versionEndExcluding) >= 0) return false;
  if (match.versionEndIncluding && compareVersions(version, match.versionEndIncluding) > 0) return false;
  return true;
}

function vulnerableMatches(cve: any, query: NvdQuery): any[] {
  const matches = (cve.configurations ?? []).flatMap((config: any) => config.nodes ?? []).flatMap((node: any) => node.cpeMatch ?? []);
  return matches.filter((match: any) => match.vulnerable && query.accepts(match.criteria) && covers(match, query.version));
}

let lastRequest = 0;

/** Runs one lookup, spaced out to stay inside NVD's public rate limit. */
export async function queryNvd(query: NvdQuery): Promise<NvdMatch[]> {
  const wait = lastRequest + delayMs() - Date.now();
  if (wait > 0) await new Promise((done) => setTimeout(done, wait));
  lastRequest = Date.now();
  const url = `${API}?virtualMatchString=${encodeURIComponent(query.cpe)}&resultsPerPage=2000`;
  const key = process.env.NVD_API_KEY;
  const data = await fetchJson<any>(url, key ? { headers: { apiKey: key } } : {}, { tries: 3, timeoutMs: 60_000, waitMs: 35_000 });
  const out: NvdMatch[] = [];
  for (const { cve } of data.vulnerabilities ?? []) {
    const matches = vulnerableMatches(cve, query);
    if (!matches.length) continue;
    const ends = matches.map((m) => m.versionEndExcluding).filter(Boolean).sort(compareVersions);
    out.push({
      id: cve.id,
      severity: severityOf(cve),
      fixed: ends.at(-1) ?? '',
      summary: String(cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? '').split(/(?<=\.)\s/)[0].slice(0, 140),
    });
  }
  return out;
}
