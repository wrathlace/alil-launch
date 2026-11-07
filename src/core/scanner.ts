import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import type { Category, Checker, Finding, FindingInput, RuleMeta, ScanContext, ScanOptions, ScanResult, Severity } from '../types.js';
import { SEVERITIES, severityRank } from '../types.js';
import { CHECKERS } from '../rules/index.js';
import { customChecker } from '../rules/custom.js';
import { readBaseline } from './baseline.js';
import { loadConfig } from './config.js';
import { gitInfo, listFiles, readText } from './files.js';
import { isIgnored, parseIgnore } from './ignore.js';
import { categoryScores, gradeOf, scoreOf, verdictOf } from './score.js';
import { detectStack } from './stack.js';
import { sha } from './util.js';

const require = createRequire(import.meta.url);
export const VERSION: string = require('../../package.json').version;

const CATEGORY_ORDER: Category[] = ['secrets', 'config', 'dependencies', 'backups', 'deployment', 'launch', 'checks', 'live'];
const SUPPRESS = /alil-launch-ignore\b/;

export function buildContext(rootInput: string, options: ScanOptions): ScanContext {
  const root = resolve(rootInput);
  if (!existsSync(root)) throw new Error(`Path not found: ${root}`);
  const config = options.config ?? loadConfig(root);
  const git = gitInfo(root);
  const listed = listFiles(root, git, options.staged);
  const rules = parseIgnore((config.ignore ?? []).join('\n'));
  const files = listed.files.filter((f) => !isIgnored(f, false, rules));
  const cache = new Map<string, string | null>();
  const read = (path: string): string | null => {
    if (!cache.has(path)) cache.set(path, readText(join(root, path)));
    return cache.get(path) ?? null;
  };
  const fileSet = new Set(listed.allPaths);
  return {
    root,
    files,
    allPaths: listed.allPaths,
    git,
    options: { ...options, config },
    gaps: [],
    packagesChecked: null,
    stack: detectStack({ files, read }),
    read,
    exists: (path) => fileSet.has(path) || existsSync(join(root, path)),
    matching(pattern, maxBytes) {
      const out: Array<{ path: string; text: string }> = [];
      for (const path of files) {
        if (!pattern.test(path)) continue;
        const text = maxBytes ? readText(join(root, path), maxBytes) : read(path);
        if (text) out.push({ path, text });
      }
      return out;
    },
  };
}

function isSuppressed(ctx: ScanContext, input: FindingInput): boolean {
  if (!input.file || !input.line) return false;
  const lines = ctx.read(input.file)?.split('\n');
  if (!lines) return false;
  return SUPPRESS.test(lines[input.line - 1] ?? '') || SUPPRESS.test(lines[input.line - 2] ?? '');
}

/** Runs every checker and returns scored findings. Never prints results. */
export async function scan(rootInput = '.', options: ScanOptions = {}): Promise<ScanResult> {
  const started = Date.now();
  const ctx = buildContext(rootInput, options);
  const config = ctx.options.config ?? {};
  const checkers: Checker[] = [...CHECKERS, customChecker(config)];
  const metas = new Map<string, RuleMeta>(checkers.flatMap((c) => c.rules).map((r) => [r.id, r]));
  const findings: Finding[] = [];
  let suppressed = 0;

  const report = (ruleId: string, input: FindingInput = {}): void => {
    const meta = metas.get(ruleId);
    if (!meta) throw new Error(`Unknown rule: ${ruleId}`);
    const override = config.rules?.[ruleId];
    if (override === 'off') return;
    if (options.only && !options.only.includes(meta.category)) return;
    if (isSuppressed(ctx, input)) {
      suppressed++;
      return;
    }
    findings.push({
      ruleId,
      title: meta.title,
      category: meta.category,
      severity: (override as Severity | undefined) ?? input.severity ?? meta.severity,
      message: input.message ?? meta.description,
      fix: meta.fix,
      file: input.file,
      line: input.line,
      evidence: input.evidence,
      advisories: input.advisories,
      exploited: input.exploited,
      fingerprint: sha(`${ruleId}|${input.file ?? ''}|${input.key ?? input.message ?? ''}`),
    });
  };

  for (const checker of checkers) {
    try {
      await checker.run(ctx, report);
    } catch (error) {
      if (checker.name !== 'dependencies' && checker.name !== 'live') throw error;
      ctx.gaps.push(`The ${checker.name} check stopped early: ${(error as Error).message}`);
    }
  }

  const baseline = options.baseline ? readBaseline(options.baseline) : new Set<string>();
  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    if (baseline.has(finding.fingerprint)) suppressed++;
    else unique.set(`${finding.fingerprint}:${finding.line ?? 0}`, finding);
  }
  const active = [...unique.values()].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || a.ruleId.localeCompare(b.ruleId) || (a.file ?? '').localeCompare(b.file ?? ''),
  );

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, active.filter((f) => f.severity === s).length])) as Record<Severity, number>;
  const categories = CATEGORY_ORDER.filter((c) => {
    if (options.only && !options.only.includes(c)) return false;
    if (c === 'live') return Boolean(options.url);
    if (c === 'checks') return Boolean(options.run);
    return true;
  });
  const score = ctx.gaps.length ? Math.min(scoreOf(active), 79) : scoreOf(active);
  return {
    tool: { name: 'alil-launch', version: VERSION },
    root: ctx.root,
    url: options.url,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    filesScanned: ctx.files.length,
    stack: ctx.stack,
    score,
    grade: gradeOf(score),
    verdict: verdictOf(active, ctx.gaps),
    categories: categoryScores(active, categories),
    counts,
    findings: active,
    suppressed,
    incomplete: ctx.gaps,
    packagesChecked: ctx.packagesChecked,
    rules: [...metas.values()].filter((r) => active.some((f) => f.ruleId === r.id)),
  };
}
