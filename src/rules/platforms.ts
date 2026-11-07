import type { Reporter, RuleMeta, ScanContext, Severity } from '../types.js';
import { severityRank } from '../types.js';
import { compareVersions, fetchJson, mapLimit } from '../core/util.js';
import type { Hit } from '../vuln/hits.js';
import { queryNvd, type NvdQuery } from '../vuln/nvd.js';
import type { Pkg } from './manifests.js';

export const PLATFORM_RULES: RuleMeta[] = [
  {
    id: 'deps/insecure-platform-version',
    title: 'Platform version is marked insecure',
    category: 'dependencies',
    severity: 'high',
    description: 'The platform maintainers no longer consider this release safe to run.',
    fix: 'Upgrade to a supported release.',
  },
  {
    id: 'deps/closed-plugin',
    title: 'WordPress plugin was closed',
    category: 'dependencies',
    severity: 'high',
    description: 'wordpress.org has removed this plugin, so it will get no more security fixes.',
    fix: 'Replace it with a maintained plugin.',
  },
];

/** A component that OSV does not cover, so it is looked up in the NVD by CPE. */
interface Component {
  label: string;
  version: string;
  file: string;
  queries: NvdQuery[];
  wordpressPlugin?: string;
}

export interface Platforms {
  /** Components OSV covers. */
  packages: Pkg[];
  components: Component[];
  wordpressCore?: { version: string; file: string };
  /** Component files with no version to look up. */
  unversioned: string[];
}

const SAFE_SLUG = /^[a-z0-9][a-z0-9_-]*$/;
const SAFE_VERSION = /^\d[\w.+-]*$/;
/** About ten minutes at NVD's public rate limit. */
const MAX_NVD_QUERIES = 90;

const header = (text: string, name: string): string | undefined =>
  new RegExp(`^[\\s*#]*${name}:[ \\t]*(.+?)[ \\t]*$`, 'mi').exec(text.slice(0, 8192))?.[1];

function product(vendor: string, name: string, version: string): NvdQuery {
  return {
    cpe: `cpe:2.3:a:${vendor}:${name}:${version}`,
    version,
    accepts(criteria) {
      const parts = criteria.split(':');
      return parts[3] === vendor && parts[4] === name;
    },
  };
}

/** Vendors for plugins and themes are not predictable, so these match on the name and target software. */
function wordpressAddon(slug: string, version: string): NvdQuery[] {
  return [...new Set([slug, slug.replace(/-/g, '_')])].map((name) => ({
    cpe: `cpe:2.3:a:*:${name}:${version}:*:*:*:*:wordpress:*:*`,
    version,
    accepts(criteria) {
      const parts = criteria.split(':');
      return parts[4] === name && parts[10] === 'wordpress';
    },
  }));
}

function addon(kind: string, slug: string, version: string | undefined, file: string, found: Platforms): void {
  if (!SAFE_SLUG.test(slug)) return;
  if (!version || !SAFE_VERSION.test(version)) {
    found.unversioned.push(file);
    return;
  }
  found.components.push({
    label: `WordPress ${kind} ${slug}`,
    version,
    file,
    queries: wordpressAddon(slug, version),
    wordpressPlugin: kind === 'plugin' ? slug : undefined,
  });
}

function drupalVersion(raw: string): string {
  const m = /^(?:\d+\.x-)?(\d+)\.(\d+)(?:\.(\d+))?(.*)$/.exec(raw);
  return m ? `${m[1]}.${m[2]}.${m[3] ?? 0}${m[4]}` : raw;
}

/** Finds CMS installs, whether committed as files or managed through Composer. */
export function detectPlatforms(ctx: Pick<ScanContext, 'matching'>, locked: Pkg[]): Platforms {
  const found: Platforms = { packages: [], components: [], unversioned: [] };

  const addWordPressCore = (version: string, file: string): void => {
    if (found.wordpressCore || !SAFE_VERSION.test(version)) return;
    found.wordpressCore = { version, file };
    found.components.push({ label: 'WordPress', version, file, queries: [product('wordpress', 'wordpress', version)] });
  };

  for (const { path, text } of ctx.matching(/(^|\/)wp-includes\/version\.php$/)) {
    const version = /\$wp_version\s*=\s*['"]([^'"]+)['"]/.exec(text)?.[1];
    if (version) addWordPressCore(version, path);
  }
  for (const { path, text } of ctx.matching(/(^|\/)plugins\/[^/]+\/[^/]+\.php$/)) {
    if (header(text, 'Plugin Name')) addon('plugin', path.split('/').at(-2)!, header(text, 'Version'), path, found);
  }
  for (const { path, text } of ctx.matching(/(^|\/)themes\/[^/]+\/style\.css$/)) {
    if (header(text, 'Theme Name')) addon('theme', path.split('/').at(-2)!, header(text, 'Version'), path, found);
  }
  for (const pkg of locked) {
    if (pkg.ecosystem !== 'Packagist') continue;
    const wpackagist = /^wpackagist-(plugin|theme)\/(.+)$/.exec(pkg.name);
    if (wpackagist) addon(wpackagist[1], wpackagist[2], pkg.version, pkg.file, found);
    else if (/^(johnpbloch\/wordpress(-core)?|roots\/wordpress(-no-content)?)$/.test(pkg.name)) addWordPressCore(pkg.version, pkg.file);
  }

  for (const { path, text } of ctx.matching(/(^|\/)core\/lib\/Drupal\.php$/)) {
    const version = /const VERSION = '([^']+)'/.exec(text)?.[1];
    if (version) found.packages.push({ name: 'drupal/core', version, ecosystem: 'Packagist', file: path });
  }
  for (const { path, text } of ctx.matching(/(^|\/)includes\/bootstrap\.inc$/)) {
    const version = /define\('VERSION', '([^']+)'\)/.exec(text)?.[1];
    if (!version) continue;
    for (const name of ['drupal/core', 'drupal/drupal']) found.packages.push({ name, version, ecosystem: 'Packagist', file: path });
  }
  for (const { path, text } of ctx.matching(/(^|\/)(modules|themes)\/contrib\/([^/]+)\/\3\.info\.yml$/)) {
    const name = path.split('/').at(-2)!;
    const version = /^version:\s*['"]?([^'"\s]+)/m.exec(text)?.[1];
    if (version) found.packages.push({ name: `drupal/${name}`, version: drupalVersion(version), ecosystem: 'Packagist', file: path });
    else found.unversioned.push(path);
  }

  for (const { path, text } of ctx.matching(/(^|\/)libraries\/src\/Version\.php$/)) {
    const part = (name: string): string | undefined => new RegExp(`const ${name}\\s*=\\s*(\\d+)`).exec(text)?.[1];
    const [major, minor, patch] = [part('MAJOR_VERSION'), part('MINOR_VERSION'), part('PATCH_VERSION')];
    if (!major || !minor || !patch) continue;
    const version = `${major}.${minor}.${patch}`;
    found.components.push({ label: 'Joomla', version, file: path, queries: [product('joomla', 'joomla\\!', version)] });
  }
  for (const { path, text } of ctx.matching(/(^|\/)version\.php$/)) {
    const version = /\$OC_VersionString\s*=\s*'([^']+)'/.exec(text)?.[1];
    if (version) found.components.push({ label: 'Nextcloud', version, file: path, queries: [product('nextcloud', 'nextcloud_server', version)] });
  }
  return found;
}

async function checkWordPressRelease(core: NonNullable<Platforms['wordpressCore']>, ctx: ScanContext, report: Reporter): Promise<void> {
  try {
    const status = await fetchJson<Record<string, string>>('https://api.wordpress.org/core/stable-check/1.0/');
    const state = status[core.version] ?? status[core.version.replace(/\.0$/, '')];
    if (state === 'insecure') report('deps/insecure-platform-version', { file: core.file, key: core.version, message: `wordpress.org marks WordPress ${core.version} as insecure.` });
  } catch (error) {
    ctx.gaps.push(`Could not check the WordPress release status: ${(error as Error).message}`);
  }
}

async function checkClosedPlugin(component: Component, report: Reporter): Promise<boolean> {
  const slug = component.wordpressPlugin!;
  const url = `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}&request[fields][sections]=0`;
  try {
    // A 404 is normal here: paid and private plugins are not on wordpress.org.
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok && res.status !== 404) return false;
    const info = (await res.json().catch(() => null)) as any;
    if (info?.closed) report('deps/closed-plugin', { file: component.file, key: slug, message: `\`${slug}\` was closed on wordpress.org${info.reason_text ? `. Reason: ${info.reason_text}` : ''}.` });
    return true;
  } catch {
    return false;
  }
}

/** Looks up what OSV cannot. A failed lookup becomes a gap, so it can't read as clean. */
export async function checkPlatforms(platforms: Platforms, ctx: ScanContext, report: Reporter): Promise<Hit[]> {
  if (platforms.wordpressCore) await checkWordPressRelease(platforms.wordpressCore, ctx, report);
  const plugins = platforms.components.filter((c) => c.wordpressPlugin);
  const statuses = await mapLimit(plugins, 5, (plugin) => checkClosedPlugin(plugin, report));
  const unknown = statuses.filter((ok) => !ok).length;
  if (unknown) ctx.gaps.push(`Could not check whether ${unknown} WordPress plugin(s) were closed on wordpress.org.`);

  const hits: Hit[] = [];
  let queries = 0;
  const failed: string[] = [];
  const skipped: string[] = [];
  for (const component of platforms.components) {
    if (queries + component.queries.length > MAX_NVD_QUERIES) {
      skipped.push(component.label);
      continue;
    }
    queries += component.queries.length;
    const matches = new Map<string, { severity: Severity; fixed: string; summary: string }>();
    try {
      for (const query of component.queries) {
        for (const { id, ...match } of await queryNvd(query)) matches.set(id, match);
      }
      ctx.packagesChecked = (ctx.packagesChecked ?? 0) + 1;
    } catch (error) {
      failed.push(`${component.label} (${(error as Error).message})`);
      continue;
    }
    if (!matches.size) continue;
    const rows = [...matches.values()];
    hits.push({
      name: component.label,
      version: component.version,
      file: component.file,
      key: `${component.label}@${component.version}`,
      ids: [...matches.keys()],
      severity: rows.map((m) => m.severity).sort((a, b) => severityRank(a) - severityRank(b))[0],
      fixed: rows.map((m) => m.fixed).filter(Boolean).sort(compareVersions).at(-1) ?? '',
      summaries: Object.fromEntries([...matches].map(([id, match]) => [id, match.summary])),
      severities: Object.fromEntries([...matches].map(([id, match]) => [id, match.severity])),
    });
  }
  if (failed.length) ctx.gaps.push(`These were not checked against the NVD: ${failed.join(', ')}.`);
  if (skipped.length) ctx.gaps.push(`${skipped.length} component(s) were skipped to stay inside NVD's rate limit. Set NVD_API_KEY or run again for: ${skipped.slice(0, 5).join(', ')}.`);
  return hits;
}
