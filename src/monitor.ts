import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { scan } from './core/scanner.js';
import { parseJson, sha } from './core/util.js';
import type { Category, Finding, ScanResult, Severity } from './types.js';
import { severityRank } from './types.js';

export const MONITOR_STATE = '.alil-launch-monitor.json';
const WATCHED: Category[] = ['secrets', 'config', 'dependencies', 'live'];

interface StateEntry {
  /** What the finding is about, such as a package and version. Never holds a secret. */
  label: string;
  title: string;
  severity: Severity;
  file?: string;
  advisories: string[];
  exploited: boolean;
  firstSeen: string;
}

interface MonitorState {
  version: 1;
  updatedAt: string;
  findings: Record<string, StateEntry>;
}

export interface MonitorOptions {
  /** Where to remember what was seen. Defaults to the project folder, or the home folder for a git URL. */
  state?: string;
  failOn?: Severity;
  url?: string;
  only?: Category[];
  baseline?: string;
  /** Slack, Discord or Teams style webhook, called only when something new needs attention. */
  webhook?: string;
}

export interface MonitorRun {
  target: string;
  firstRun: boolean;
  /** Findings not seen before. */
  fresh: Finding[];
  /** Findings seen before that gained a CVE or became actively exploited. */
  changed: Array<{ finding: Finding; advisories: string[]; nowExploited: boolean }>;
  /** Findings that are gone. Always empty when the scan was incomplete. */
  resolved: StateEntry[];
  /** Everything open now, at or above the alert level. */
  open: Finding[];
  result: ScanResult;
  failOn: Severity;
  /** 0 nothing new, 1 something new needs attention, 2 the check could not finish. */
  exitCode: number;
}

function readState(path: string): MonitorState | null {
  if (!existsSync(path)) return null;
  const state = parseJson<MonitorState>(readFileSync(path, 'utf8'));
  if (state?.version !== 1 || !state.findings) throw new Error(`Monitor state is damaged: ${path}. Delete it to start again.`);
  return state;
}

function compare(previous: MonitorState | null, result: ScanResult, failOn: Severity): Omit<MonitorRun, 'target' | 'result' | 'failOn' | 'exitCode'> {
  const known = previous?.findings ?? {};
  const atLevel = (f: { severity: Severity }): boolean => severityRank(f.severity) <= severityRank(failOn);
  const fresh = result.findings.filter((f) => !known[f.fingerprint]);
  const changed = result.findings.flatMap((finding) => {
    const before = known[finding.fingerprint];
    if (!before) return [];
    const advisories = (finding.advisories ?? []).filter((id) => !before.advisories.includes(id));
    const nowExploited = Boolean(finding.exploited) && !before.exploited;
    return advisories.length || nowExploited ? [{ finding, advisories, nowExploited }] : [];
  });
  const current = new Set(result.findings.map((f) => f.fingerprint));
  const resolved = result.incomplete.length ? [] : Object.entries(known).filter(([id]) => !current.has(id)).map(([, entry]) => entry);
  return { firstRun: !previous, fresh, changed, resolved, open: result.findings.filter(atLevel) };
}

function nextState(previous: MonitorState | null, result: ScanResult): MonitorState {
  const now = new Date().toISOString();
  // An incomplete scan can't show that something is gone, so it keeps what it couldn't see.
  const findings: Record<string, StateEntry> = result.incomplete.length ? { ...previous?.findings } : {};
  for (const f of result.findings) {
    findings[f.fingerprint] = {
      label: f.message.split(': ')[0].slice(0, 120),
      title: f.title,
      severity: f.severity,
      file: f.file,
      advisories: f.advisories ?? [],
      exploited: Boolean(f.exploited),
      firstSeen: previous?.findings[f.fingerprint]?.firstSeen ?? now,
    };
  }
  return { version: 1, updatedAt: now, findings };
}

const isGitUrl = (target: string): boolean => /^(https:\/\/|ssh:\/\/|git@)/.test(target);
export const withoutCredentials = (target: string): string => target.replace(/^(https:[/][/]|ssh:[/][/])[^@/]+@/, '$1');

function clone(url: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'alil-launch-'));
  try {
    execFileSync('git', ['clone', '--quiet', '--depth', '1', '--', url, dir], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    });
  } catch {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`Could not clone ${withoutCredentials(url)}`);
  }
  return dir;
}

/** The lines a person should read first, shared by the webhook and the reports. */
function alertLines(run: MonitorRun): string[] {
  const urgent = (f: Finding): boolean => severityRank(f.severity) <= severityRank(run.failOn);
  const lines = run.fresh.filter(urgent).map((f) => `[${f.severity}] ${f.message}${f.file ? ` (${f.file})` : ''}`);
  for (const { finding, advisories, nowExploited } of run.changed.filter((c) => urgent(c.finding))) {
    const detail = [nowExploited ? 'now actively exploited' : '', advisories.length ? `new: ${advisories.slice(0, 5).join(', ')}` : ''].filter(Boolean).join(', ');
    lines.push(`[${finding.severity}] ${finding.message.split(': ')[0]}: ${detail}${finding.file ? ` (${finding.file})` : ''}`);
  }
  return lines;
}

async function notify(webhook: string, run: MonitorRun, lines: string[]): Promise<void> {
  const text = [`Alil Launch found ${lines.length} new issue(s) in ${run.target}:`, ...lines.slice(0, 10).map((line) => `- ${line.slice(0, 300)}`), ...(lines.length > 10 ? [`and ${lines.length - 10} more`] : [])].join('\n');
  // Slack and Teams read `text`, and Discord reads `content`.
  const res = await fetch(webhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text, content: text.slice(0, 2000) }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`The webhook returned ${res.status}`);
}

/** Checks one project against what was seen last time. Saves state only once alerts have been delivered. */
export async function monitor(target: string, options: MonitorOptions = {}): Promise<MonitorRun> {
  const failOn = options.failOn ?? 'high';
  const remote = isGitUrl(target);
  const root = remote ? clone(target) : target;
  const statePath = resolve(options.state ?? (remote
    ? join(homedir(), '.alil-launch', 'monitor', `${sha(withoutCredentials(target))}.json`)
    : join(target, MONITOR_STATE)));
  try {
    const previous = readState(statePath);
    const result = await scan(root, { online: true, url: options.url, only: options.only ?? WATCHED, baseline: options.baseline });
    const run: MonitorRun = { ...compare(previous, result, failOn), target: withoutCredentials(target), result, failOn, exitCode: 0 };
    const alerts = alertLines(run);
    if (alerts.length && options.webhook) await notify(options.webhook, run, alerts);
    mkdirSync(dirname(statePath), { recursive: true });
    writeFileSync(statePath, `${JSON.stringify(nextState(previous, result), null, 2)}\n`);
    run.exitCode = alerts.length ? 1 : result.incomplete.length ? 2 : 0;
    return run;
  } finally {
    if (remote) rmSync(root, { recursive: true, force: true });
  }
}

export function renderMonitorJson(run: MonitorRun): string {
  const { target, firstRun, fresh, changed, resolved, open, exitCode, result } = run;
  return JSON.stringify({ target, firstRun, exitCode, incomplete: result.incomplete, packagesChecked: result.packagesChecked, fresh, changed, resolved, open }, null, 2);
}

export function renderMonitorText(run: MonitorRun): string {
  const out = [`Alil Launch monitor: ${run.target}`, `${run.result.packagesChecked ?? 0} packages checked at ${run.result.scannedAt}${run.firstRun ? '. First run, so everything open counts as new.' : ''}`, ''];
  for (const gap of run.result.incomplete) out.push(`NOT CHECKED  ${gap}`);
  const alerts = alertLines(run);
  if (alerts.length) out.push(`New since the last run (${alerts.length}):`, ...alerts.map((line) => `  ${line}`), '');
  else out.push('Nothing new since the last run.', '');
  if (run.resolved.length) out.push(`Resolved (${run.resolved.length}):`, ...run.resolved.map((entry) => `  ${entry.label}${entry.file ? ` (${entry.file})` : ''}`), '');
  out.push(run.open.length ? `Open at ${run.failOn} or above: ${run.open.length}` : `No open issues at ${run.failOn} or above.`);
  return `${out.join('\n')}\n`;
}

export function renderMonitorMarkdown(run: MonitorRun): string {
  const cell = (text: string): string => text.replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const out = [`## Alil Launch monitor: ${run.target}`, '', `${run.result.packagesChecked ?? 0} packages checked at ${run.result.scannedAt}.`, ''];
  for (const gap of run.result.incomplete) out.push(`> **Not checked:** ${gap}`, '');
  const alerts = alertLines(run);
  if (alerts.length) out.push(`### New since the last run (${alerts.length})`, '', ...alerts.map((line) => `- ${line}`), '');
  if (run.resolved.length) out.push(`### Resolved (${run.resolved.length})`, '', ...run.resolved.map((entry) => `- ${entry.label}${entry.file ? ` (\`${entry.file}\`)` : ''}`), '');
  if (run.open.length) {
    out.push(`### Open at ${run.failOn} or above (${run.open.length})`, '', '| Severity | Issue | Where |', '|---|---|---|');
    for (const f of run.open.slice(0, 100)) out.push(`| ${f.severity} | ${cell(f.message)} | ${f.file ? `\`${f.file}\`` : 'project'} |`);
  } else {
    out.push(`No open issues at ${run.failOn} or above.`);
  }
  return `${out.join('\n')}\n`;
}
