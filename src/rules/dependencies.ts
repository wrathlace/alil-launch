import type { Checker, RuleMeta, ScanContext, Severity } from '../types.js';
import { severityRank } from '../types.js';
import { compareVersions, fetchJson, mapLimit, parseJson } from '../core/util.js';
import { reportHits, type Hit } from '../vuln/hits.js';
import { readManifests, type Pkg } from './manifests.js';
import { checkPlatforms, detectPlatforms, PLATFORM_RULES } from './platforms.js';

const rule = (id: string, title: string, severity: RuleMeta['severity'], description: string, fix: string): RuleMeta => ({
  id, title, severity, description, fix, category: 'dependencies',
});

const RULES = {
  vuln: rule('deps/known-vulnerability', 'Dependency with a known vulnerability', 'high', 'An installed package or platform version has a published advisory in OSV or the NVD.', 'Upgrade to a fixed version.'),
  unchecked: rule('deps/unchecked-dependency', 'Dependency versions could not be checked', 'high', 'Without an exact version there is nothing to look up, so a clean result says nothing about these packages.', 'Commit a lockfile so every installed version is known.'),
  missing: rule('deps/package-does-not-exist', 'Dependency does not exist on the registry', 'high', 'AI tools sometimes invent package names. Attackers register those names and wait, a technique called slopsquatting.', 'Remove it or replace it with the real package. If it is private, ignore this rule for it.'),
  typo: rule('deps/possible-typosquat', 'Dependency name looks like a typo of a popular package', 'high', 'Typosquatted packages are a common way to run malware on install.', 'Check the name carefully and install the real package.'),
  wildcard: rule('deps/wildcard-version', 'Dependency has no version limit', 'medium', '`*` and `latest` can install anything at the next build.', 'Set a version range and commit your lockfile.'),
  git: rule('deps/git-dependency', 'Dependency installed from a git URL', 'low', 'Git dependencies skip registry checks and can change.', 'Use a published release, or pin a commit hash.'),
};

function fromPackageLock(text: string, file: string): Pkg[] {
  const lock = parseJson<any>(text);
  if (!lock) return [];
  const out: Pkg[] = [];
  for (const [path, value] of Object.entries<any>(lock.packages ?? {})) {
    if (!path || !value?.version) continue;
    out.push({ name: value.name ?? path.split('node_modules/').pop()!, version: value.version, ecosystem: 'npm', file });
  }
  const walk = (deps: any): void => {
    for (const [name, value] of Object.entries<any>(deps ?? {})) {
      if (value?.version) out.push({ name, version: value.version, ecosystem: 'npm', file });
      walk(value?.dependencies);
    }
  };
  if (!lock.packages) walk(lock.dependencies);
  return out;
}

/** Lockfiles in large projects are often well over the limit for a scanned source file. */
const MAX_LOCK_BYTES = 64 * 1024 * 1024;

function matchAll(text: string, re: RegExp, ecosystem: string, file: string): Pkg[] {
  return [...text.replace(/\r\n/g, '\n').matchAll(re)].map((m) => ({ name: m[1], version: m[2], ecosystem, file }));
}

export function parseLockfiles(ctx: Pick<ScanContext, 'matching'>): Pkg[] {
  const out: Pkg[] = [];
  for (const { path, text } of ctx.matching(/(^|\/)(package-lock\.json|npm-shrinkwrap\.json)$/, MAX_LOCK_BYTES)) out.push(...fromPackageLock(text, path));
  for (const { path, text } of ctx.matching(/(^|\/)yarn\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /^"?((?:@[^/\s"]+\/)?[^@\s"]+)@[^\n]*:\n\s+version:? "?([^"\n]+)"?/gm, 'npm', path));
  for (const { path, text } of ctx.matching(/(^|\/)pnpm-lock\.yaml$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /^\s+'?\/?((?:@[^/\s]+\/)?[^@\s/]+)[@/](\d+\.\d+\.\d+[^:'(\s]*)(?:\([^)]*\))*'?:/gm, 'npm', path));
  for (const { path, text } of ctx.matching(/(^|\/)bun\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /^\s+"[^"]+": \["((?:@[^/"]+\/)?[^@"]+)@(\d[^"]*)"/gm, 'npm', path));
  for (const { path, text } of ctx.matching(/(^|\/)composer\.lock$/, MAX_LOCK_BYTES)) {
    const lock = parseJson<any>(text);
    for (const p of [...(lock?.packages ?? []), ...(lock?.['packages-dev'] ?? [])]) {
      out.push({ name: p.name, version: String(p.version).replace(/^v/, ''), ecosystem: 'Packagist', file: path });
    }
  }
  for (const { path, text } of ctx.matching(/(^|\/)requirements[^/]*\.txt$/)) out.push(...matchAll(text, /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==([^\s;#]+)/gm, 'PyPI', path));
  for (const { path, text } of ctx.matching(/(^|\/)poetry\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/g, 'PyPI', path));
  for (const { path, text } of ctx.matching(/(^|\/)uv\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"\nsource = \{ registry/g, 'PyPI', path));
  for (const { path, text } of ctx.matching(/(^|\/)Pipfile\.lock$/, MAX_LOCK_BYTES)) {
    const lock = parseJson<any>(text);
    for (const section of ['default', 'develop']) {
      for (const [name, value] of Object.entries<any>(lock?.[section] ?? {})) {
        if (value?.version) out.push({ name, version: value.version.replace(/^==/, ''), ecosystem: 'PyPI', file: path });
      }
    }
  }
  for (const { path, text } of ctx.matching(/(^|\/)go\.mod$/)) out.push(...matchAll(text, /^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]+\/[^\s]+)\s+(v[^\s]+)/gm, 'Go', path));
  for (const { path, text } of ctx.matching(/(^|\/)Cargo\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/g, 'crates.io', path));
  for (const { path, text } of ctx.matching(/(^|\/)Gemfile\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)$/gm, 'RubyGems', path));
  for (const { path, text } of ctx.matching(/(^|\/)gradle\.lockfile$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /^([\w.-]+:[\w.-]+):([^=\s]+)=/gm, 'Maven', path));
  for (const { path, text } of ctx.matching(/(^|\/)packages\.lock\.json$/, MAX_LOCK_BYTES)) {
    for (const target of Object.values<any>(parseJson<any>(text)?.dependencies ?? {})) {
      for (const [name, value] of Object.entries<any>(target)) {
        if (value?.resolved && value.type !== 'Project') out.push({ name, version: value.resolved, ecosystem: 'NuGet', file: path });
      }
    }
  }
  for (const { path, text } of ctx.matching(/(^|\/)pubspec\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /^ {2}([a-z0-9_]+):\n(?: {4,}.*\n)*? {4}version: "([^"]+)"/gm, 'Pub', path));
  for (const { path, text } of ctx.matching(/(^|\/)mix\.lock$/, MAX_LOCK_BYTES)) out.push(...matchAll(text, /:hex, :([a-z0-9_]+), "([^"]+)"/g, 'Hex', path));
  return unique(out);
}

function unique(packages: Pkg[]): Pkg[] {
  const seen = new Set<string>();
  return packages.filter((p) => {
    const key = `${p.ecosystem}:${p.name}@${p.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** The first stable release above the installed version, so advice never jumps to a pre-release. */
export function nearestFix(current: string, fixes: string[]): string | undefined {
  return fixes
    .filter((v) => !/[a-z]/i.test(v.replace(/^v/, '')) && compareVersions(v, current) > 0)
    .sort(compareVersions)[0];
}

const OSV_SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

const MAX_ADVISORIES = 2000;

function severityOf(vuln: any): Severity | undefined {
  return OSV_SEVERITY[String(vuln?.database_specific?.severity).toUpperCase()];
}

async function advisory(id: string): Promise<any> {
  return fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {}, { timeoutMs: 15_000 }).catch(() => undefined);
}

/** Looks up every package, and records a gap rather than throwing, so a failure can never read as a clean result. */
export async function checkOsv(packages: Pkg[], ctx: ScanContext): Promise<Hit[]> {
  const found = new Map<Pkg, string[]>();
  let looked = 0;
  try {
    for (let i = 0; i < packages.length; i += 500) {
      const chunk = packages.slice(i, i + 500);
      const data = await fetchJson<any>('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
      });
      (data.results ?? []).forEach((r: any, index: number) => {
        if (r?.vulns?.length) found.set(chunk[index], r.vulns.map((v: any) => v.id));
        if (r?.next_page_token) ctx.gaps.push(`${chunk[index].name}@${chunk[index].version} has more advisories than OSV returned in one page.`);
      });
      looked += chunk.length;
    }
  } catch (error) {
    ctx.gaps.push(`${packages.length - looked} of ${packages.length} packages were not checked for known vulnerabilities: ${(error as Error).message}`);
  }
  ctx.packagesChecked = (ctx.packagesChecked ?? 0) + looked;

  const ids = [...new Set([...found.values()].flat())];
  if (ids.length > MAX_ADVISORIES) ctx.gaps.push(`Severity and fix details were fetched for only ${MAX_ADVISORIES} of ${ids.length} advisories.`);
  const details = new Map<string, any>();
  await mapLimit(ids.slice(0, MAX_ADVISORIES), 10, async (id) => {
    const vuln = await advisory(id);
    if (vuln) details.set(id, vuln);
  });
  // Drupal's own advisories carry no severity, but the GitHub copy of the same issue usually does.
  const alternates = new Map<string, any>();
  await mapLimit([...details].filter(([, vuln]) => !severityOf(vuln)), 10, async ([id, vuln]) => {
    const twin = (vuln.aliases ?? []).find((alias: string) => alias.startsWith('GHSA-'));
    if (twin) alternates.set(id, await advisory(twin));
  });

  const hits: Hit[] = [];
  for (const [pkg, vulnIds] of found) {
    let severity: Severity | undefined;
    let fixed = '';
    const summaries: Record<string, string> = {};
    const severities: Record<string, Severity> = {};
    const named = new Set<string>();
    for (const id of vulnIds) {
      const vuln = details.get(id);
      const label: string = (vuln?.aliases ?? []).find((alias: string) => alias.startsWith('CVE-')) ?? id;
      named.add(label);
      if (!vuln) continue;
      const mapped = severityOf(vuln) ?? severityOf(alternates.get(id));
      if (mapped && (!severity || severityRank(mapped) < severityRank(severity))) severity = mapped;
      if (mapped) severities[label] = mapped;
      summaries[label] ||= vuln.summary ?? '';
      const candidates: string[] = [];
      for (const affected of vuln.affected ?? []) {
        if (affected.package?.name !== pkg.name) continue;
        for (const range of affected.ranges ?? []) {
          for (const event of range.events ?? []) if (event.fixed) candidates.push(event.fixed);
        }
      }
      const nearest = nearestFix(pkg.version, candidates);
      if (nearest && (!fixed || compareVersions(nearest, fixed) > 0)) fixed = nearest;
    }
    hits.push({
      name: pkg.name,
      version: pkg.version,
      file: pkg.file,
      key: `${pkg.ecosystem}:${pkg.name}@${pkg.version}`,
      ids: [...named],
      severity: severity ?? 'medium',
      fixed,
      summaries,
      severities,
    });
  }
  return hits;
}

interface Direct {
  name: string;
  spec: string;
  ecosystem: 'npm' | 'PyPI';
  file: string;
}

function directDependencies(ctx: ScanContext): Direct[] {
  const out: Direct[] = [];
  for (const { path, text } of ctx.matching(/(^|\/)package\.json$/)) {
    const pkg = parseJson<any>(text);
    for (const [name, spec] of Object.entries<any>({ ...pkg?.dependencies, ...pkg?.devDependencies })) {
      out.push({ name, spec: String(spec), ecosystem: 'npm', file: path });
    }
  }
  for (const { path, text } of ctx.matching(/(^|\/)requirements[^/]*\.txt$/)) {
    for (const m of text.matchAll(/^(?!.*:\/\/)([A-Za-z][A-Za-z0-9._-]*)/gm)) out.push({ name: m[1], spec: '', ecosystem: 'PyPI', file: path });
  }
  return out;
}

const POPULAR: Record<string, string[]> = {
  npm: ['express', 'lodash', 'react', 'preact', 'axios', 'chalk', 'commander', 'webpack', 'typescript', 'eslint', 'prettier', 'moment', 'dotenv', 'mongoose', 'nodemon', 'request', 'jsonwebtoken', 'bcrypt', 'bcryptjs', 'cors', 'helmet', 'passport', 'prisma', 'sequelize', 'tailwindcss', 'vitest', 'playwright', 'puppeteer', 'stripe', 'openai', 'nodemailer', 'winston', 'redis', 'socket.io', 'fastify', 'graphql', 'zod', 'underscore', 'babel', 'rollup', 'esbuild', 'cross-env', 'colors', 'uuid', 'yargs', 'inquirer', 'multer', 'sharp', 'cheerio', 'mysql2'],
  PyPI: ['requests', 'numpy', 'pandas', 'django', 'flask', 'fastapi', 'pytest', 'boto3', 'urllib3', 'cryptography', 'pillow', 'scipy', 'sqlalchemy', 'pydantic', 'uvicorn', 'celery', 'redis', 'openai', 'anthropic', 'langchain', 'tensorflow', 'torch', 'matplotlib', 'beautifulsoup4', 'selenium', 'httpx', 'aiohttp', 'gunicorn'],
};

/** Optimal string alignment distance, stopping early once it exceeds 1. */
function withinOneEdit(a: string, b: string): boolean {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  while (i < a.length && a[i] === b[i]) i++;
  if (a.length === b.length) {
    if (a.slice(i + 1) === b.slice(i + 1)) return true;
    return a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
  }
  return a.length > b.length ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1);
}

async function existsOnRegistry(dep: Direct): Promise<boolean | null> {
  const url = dep.ecosystem === 'npm'
    ? `https://registry.npmjs.org/${encodeURIComponent(dep.name)}`
    : `https://pypi.org/pypi/${encodeURIComponent(dep.name)}/json`;
  try {
    const res = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(10_000) });
    if (res.status === 404) return false;
    return res.ok ? true : null;
  } catch {
    return null;
  }
}

export const dependenciesChecker: Checker = {
  name: 'dependencies',
  rules: [...Object.values(RULES), ...PLATFORM_RULES],
  async run(ctx, report) {
    const direct = directDependencies(ctx);
    for (const dep of direct) {
      if (dep.name.length >= 5 && !dep.name.startsWith('@')) {
        const popular = POPULAR[dep.ecosystem] ?? [];
        const lower = dep.name.toLowerCase();
        const target = popular.includes(lower) ? undefined : popular.find((p) => p.length >= 5 && withinOneEdit(lower, p));
        if (target) report(RULES.typo.id, { file: dep.file, key: dep.name, message: `\`${dep.name}\` is one character away from \`${target}\`.` });
      }
      if (/^(\*|latest|x)$/.test(dep.spec.trim())) report(RULES.wildcard.id, { file: dep.file, key: dep.name, message: `\`${dep.name}\` is set to \`${dep.spec}\`.` });
      if (/^(git\+|git:|github:|https?:.*\.git|[\w-]+\/[\w.-]+(#|$))/.test(dep.spec)) report(RULES.git.id, { file: dep.file, key: dep.name, message: `\`${dep.name}\` comes from ${dep.spec.split('#')[0]}.` });
    }
    const only = ctx.options.only;
    if (!ctx.options.online || (only && !only.includes('dependencies'))) return;

    ctx.packagesChecked = 0;
    const locked = parseLockfiles(ctx);
    const manifests = readManifests(ctx);
    const platforms = detectPlatforms(ctx, locked);
    for (const item of manifests.unchecked) report(RULES.unchecked.id, { file: item.file, severity: item.severity, key: item.file, message: item.message });
    for (const file of platforms.unversioned) report(RULES.unchecked.id, { file, severity: 'medium', key: file, message: `${file} does not state a version, so this component was not checked.` });

    const hits = await checkOsv(unique([...locked, ...manifests.packages, ...platforms.packages]), ctx);
    hits.push(...await checkPlatforms(platforms, ctx, report));
    await reportHits(hits, ctx, (input) => report(RULES.vuln.id, input));

    const names = [...new Map(direct.map((d) => [`${d.ecosystem}:${d.name}`, d])).values()]
      .filter((d) => !d.name.startsWith('@') && !/^(file:|link:|workspace:|portal:|git|https?:)/.test(d.spec));
    if (names.length > 300) ctx.gaps.push(`Only the first 300 of ${names.length} dependency names were confirmed to exist on their registry.`);
    let unconfirmed = 0;
    await mapLimit(names.slice(0, 300), 10, async (dep) => {
      const exists = await existsOnRegistry(dep);
      if (exists === null) unconfirmed++;
      if (exists === false) {
        report(RULES.missing.id, { file: dep.file, key: dep.name, message: `\`${dep.name}\` was not found on ${dep.ecosystem === 'npm' ? 'npm' : 'PyPI'}.` });
      }
    });
    if (unconfirmed) ctx.gaps.push(`${unconfirmed} dependency name(s) could not be confirmed to exist on their registry.`);
  },
};
