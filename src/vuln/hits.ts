import type { FindingInput, ScanContext, Severity } from '../types.js';
import { severityRank } from '../types.js';
import { fetchJson, mapLimit } from '../core/util.js';

/** One vulnerable package or platform component, before exploit data is added. */
export interface Hit {
  name: string;
  version: string;
  file: string;
  key: string;
  /** CVE ids where one exists, otherwise the advisory id. */
  ids: string[];
  severity: Severity;
  fixed: string;
  /** Per id, so a message can describe the advisory that matters most. */
  summaries: Record<string, string>;
  severities: Record<string, Severity>;
}

const KEV_FEEDS = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
];
const EPSS_BATCH = 100;
/** The chance of exploitation in the next 30 days at which a finding is treated as urgent. */
const EPSS_URGENT = 0.5;

async function exploitedCves(): Promise<Set<string>> {
  let failure: unknown;
  for (const url of KEV_FEEDS) {
    try {
      const feed = await fetchJson<any>(url);
      return new Set((feed.vulnerabilities ?? []).map((v: any) => v.cveID));
    } catch (error) {
      failure = error;
    }
  }
  throw failure;
}

async function exploitScores(cves: string[]): Promise<Map<string, number>> {
  const scores = new Map<string, number>();
  const batches: string[][] = [];
  for (let i = 0; i < cves.length; i += EPSS_BATCH) batches.push(cves.slice(i, i + EPSS_BATCH));
  await mapLimit(batches, 4, async (batch) => {
    const data = await fetchJson<any>(`https://api.first.org/data/v1/epss.json?cve=${batch.join(',')}&limit=${EPSS_BATCH}`);
    for (const row of data.data ?? []) scores.set(row.cve, Number(row.epss));
  });
  return scores;
}

function raise(severity: Severity, floor: Severity): Severity {
  return severityRank(floor) < severityRank(severity) ? floor : severity;
}

/** Adds CISA and EPSS exploit data, so what is being attacked now sorts above what merely exists. */
export async function reportHits(hits: Hit[], ctx: ScanContext, report: (input: FindingInput) => void): Promise<void> {
  const cves = [...new Set(hits.flatMap((hit) => hit.ids))].filter((id) => id.startsWith('CVE-'));
  let exploited = new Set<string>();
  let scores = new Map<string, number>();
  if (cves.length) {
    try {
      exploited = await exploitedCves();
    } catch (error) {
      ctx.gaps.push(`Could not check which CVEs are being actively exploited: ${(error as Error).message}`);
    }
    try {
      scores = await exploitScores(cves);
    } catch (error) {
      ctx.gaps.push(`Could not fetch exploit likelihood scores: ${(error as Error).message}`);
    }
  }

  for (const hit of hits) {
    const rank = (id: string): number => (exploited.has(id) ? 2 : 0) + (scores.get(id) ?? 0);
    const worse = (a: string, b: string): number => severityRank(hit.severities[a] ?? 'info') - severityRank(hit.severities[b] ?? 'info');
    const ids = [...hit.ids].sort((a, b) => rank(b) - rank(a) || worse(a, b) || b.localeCompare(a));
    const active = ids.filter((id) => exploited.has(id));
    const likelihood = Math.max(0, ...ids.map((id) => scores.get(id) ?? 0));
    let severity = hit.severity;
    if (likelihood >= EPSS_URGENT) severity = raise(severity, 'high');
    if (active.length) severity = 'critical';

    const summary = ids.map((id) => hit.summaries[id]).find(Boolean)?.replace(/[.]$/, '');
    const parts = [`${hit.name}@${hit.version}: ${ids.slice(0, 3).join(', ')}${ids.length > 3 ? ` and ${ids.length - 3} more` : ''}${summary ? ` (${summary})` : ''}.`];
    if (active.length) parts.push(`Actively exploited, per CISA: ${active.slice(0, 3).join(', ')}.`);
    else if (likelihood >= 0.1) parts.push(`${Math.min(99, Math.round(likelihood * 100))}% chance of exploitation in the next 30 days (EPSS).`);
    if (hit.fixed) parts.push(`Upgrade to ${hit.fixed} or later.`);
    report({ file: hit.file, severity, key: hit.key, advisories: ids, exploited: active.length > 0, message: parts.join(' ') });
  }
}
