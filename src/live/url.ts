import { connect } from 'node:tls';
import type { Checker, Reporter, ScanContext } from '../types.js';
import { mapLimit } from '../core/util.js';
import { checkOsv } from '../rules/dependencies.js';
import { addon, checkPlatforms, product, type Platforms } from '../rules/platforms.js';
import { reportHits, type Hit } from '../vuln/hits.js';
import { analyzeScripts, inspectText, reportEndpoints, reportSourceMaps } from './code.js';
import { get, politeGet, readHtml, readText } from './http.js';
import { resolveUrl, sameSite, STATIC_CDNS, tags, type Tag } from './html.js';
import { builtInDetector, loadRetire, type Detector } from './libraries.js';
import { collectForms, noteQueryLink, runActiveChecks } from './active.js';
import { checkLoginPages } from './passive.js';
import { checkCors, checkCsp, checkErrorPage, checkErrorPages, checkGraphql, checkHsts, checkSecurityTxt, checkTlsVersions, runProbes } from './probes.js';
import { LIVE_RULES, RULES } from './rules.js';
import { addTech, once, scanForSecrets, type LiveState, type WordPress } from './state.js';
import { fingerprintHeaders, fingerprintHtml, reportTech, SERVER_LABELS } from './tech.js';

/** How many internal pages are fetched after the home page, unless --pages says otherwise. */
export const DEFAULT_PAGES = 50;
const MAX_BROKEN = 10;

const HEADERS: Array<{ name: string; severity: 'high' | 'medium' | 'low' }> = [
  { name: 'strict-transport-security', severity: 'high' },
  { name: 'content-security-policy', severity: 'medium' },
  { name: 'x-content-type-options', severity: 'low' },
  { name: 'referrer-policy', severity: 'low' },
];

/** For npm CDNs: the package and the version it asks for, or '' when none is given. */
function npmSpec(url: URL): { name: string; version: string } | null {
  let path = url.pathname;
  if (url.hostname === 'cdn.jsdelivr.net') {
    if (!path.startsWith('/npm/')) return null;
    path = path.slice(4);
  } else if (url.hostname !== 'unpkg.com') return null;
  const segments = path.split('/').filter(Boolean);
  if (!segments.length) return null;
  const head = segments[0].startsWith('@') ? `${segments[0]}/${segments[1] ?? ''}` : segments[0];
  const at = head.lastIndexOf('@');
  return at > 0 ? { name: head.slice(0, at), version: head.slice(at + 1) } : { name: head, version: '' };
}

const VERSION = /^\d+\.\d+(\.\d+)?$/;
const CMS_GENERATOR = /^(WordPress|Drupal|Joomla!?|TYPO3|Ghost|Magento|PrestaShop|Craft CMS|concrete5|Concrete CMS|MediaWiki|DokuWiki|Moodle)\b[^;]*\d/i;
/** Links a crawler should never follow, even with GET. */
const SKIP_PATH = /(logout|log-out|signout|sign-out|delete|remove|unsubscribe|wp-login|wp-admin|\/cart|checkout|add-to-cart)/i;
const NOT_PAGE = /\.(pdf|jpe?g|png|gif|svg|webp|avif|ico|bmp|tiff?|zip|rar|7z|gz|tar|docx?|xlsx?|pptx?|odt|ods|csv|mp4|mp3|wav|avi|mov|webm|css|js|mjs|map|xml|json|txt|woff2?|ttf|eot|apk|exe|dmg)$/i;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Disallow prefixes for all crawlers, which the crawl respects. */
export function robotsDisallow(text: string): string[] {
  const rules: string[] = [];
  let applies = false;
  let inAgents = false;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const field = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (field === 'user-agent') {
      if (!inAgents) applies = false;
      inAgents = true;
      if (value === '*') applies = true;
    } else {
      inAgents = false;
      if (applies && field === 'disallow' && value) rules.push(value.replace(/\*.*$/, ''));
    }
  }
  return rules.filter(Boolean);
}

const newWordPress = (): WordPress => ({ plugins: new Map(), themes: new Set(), generators: new Map() });

function noteWordPressAsset(state: LiveState, url: URL): void {
  const wp = /\/wp-content\/(plugins|themes)\/([a-z0-9_-]+)\//i.exec(url.pathname);
  if (!wp && !/\/wp-includes\//.test(url.pathname)) return;
  state.wordpress ??= newWordPress();
  if (wp?.[1] === 'plugins') {
    const versions = state.wordpress.plugins.get(wp[2]) ?? new Set<string>();
    const ver = url.searchParams.get('ver');
    if (ver) versions.add(ver);
    state.wordpress.plugins.set(wp[2], versions);
  } else if (wp) state.wordpress.themes.add(wp[2]);
}

function checkScriptTag(state: LiveState, attrs: Record<string, string>, url: URL, where: string, scripts: Tag[], pageUrl: URL): void {
  if (!state.scripts.has(url.href)) state.scripts.set(url.href, where);
  if (sameSite(url, state.site)) return;
  const npm = npmSpec(url);
  if (npm && !/^\d+\.\d+\.\d+/.test(npm.version)) {
    if (once(state, `pin:${url.origin}${url.pathname}`)) {
      state.report(RULES.unpinned.id, { key: url.origin + url.pathname, message: `${where} loads ${url.href}, which serves ${npm.version ? `\`${npm.version}\`` : 'the newest version'} of \`${npm.name}\` instead of a fixed version.` });
    }
  } else if (STATIC_CDNS.test(url.hostname) && !attrs.integrity && once(state, `sri:${url.hostname}`)) {
    // One finding per CDN host, so a page with twenty CDN scripts is one issue, not twenty.
    const count = scripts.filter((s) => !s.attrs.integrity && resolveUrl(s.attrs.src ?? '', pageUrl.href)?.hostname === url.hostname).length;
    state.report(RULES.sri.id, { key: url.hostname, message: `${count} script(s) from ${url.hostname} on ${where} have no integrity hash, for example ${url.href}.` });
  }
}

function checkCookies(state: LiveState, headers: Headers, secure: boolean, where: string): void {
  for (const cookie of headers.getSetCookie?.() ?? []) {
    const name = cookie.split('=')[0].trim();
    const missing = [
      secure && !/;\s*secure/i.test(cookie) ? 'Secure' : '',
      !/;\s*httponly/i.test(cookie) ? 'HttpOnly' : '',
      !/;\s*samesite/i.test(cookie) ? 'SameSite' : '',
    ].filter(Boolean);
    if (missing.length && once(state, `cookie:${name}`)) state.report(RULES.cookie.id, { key: name, message: `Cookie \`${name}\` (set on ${where}) is missing ${missing.join(', ')}.` });
  }
}

/** Checks one page's markup and returns its internal links. Makes no requests. */
function checkPage(state: LiveState, html: string, pageUrl: URL): URL[] {
  const where = pageUrl.pathname + pageUrl.search;
  const secure = pageUrl.protocol === 'https:';
  const links: URL[] = [];
  const all = tags(html, 'script|link|iframe|img|source|video|audio|embed|object|form|a|meta');
  const scripts = all.filter((t) => t.tag === 'script');
  const generators = new Map<string, string>();

  for (const { tag, attrs } of all) {
    if (tag === 'meta') {
      const content = attrs.content ?? '';
      if (attrs.name?.toLowerCase() !== 'generator') continue;
      const named = /^([\w .!-]+?)\s+v?(\d+\.\d+(?:\.\d+)?)\b/.exec(content.split(';')[0].trim());
      if (named) {
        generators.set(named[1].toLowerCase().replace(/\s+/g, '-'), named[2]);
        addTech(state, named[1], named[2], 'generator tag');
      }
      if (!CMS_GENERATOR.test(content)) continue;
      const value = content.split(';')[0].trim();
      if (once(state, `gen:${value}`)) state.report(RULES.server.id, { key: `generator:${value}`, message: `The page names its platform and version: \`${value}\`.` });
      const wp = /^WordPress\s+([\d.]+)/i.exec(value);
      if (wp) {
        state.wordpress ??= newWordPress();
        state.wordpress.core = wp[1];
      }
      continue;
    }
    const raw = tag === 'form' ? attrs.action : tag === 'a' || tag === 'link' ? attrs.href : attrs.src ?? attrs.data;
    const url = resolveUrl(raw ?? '', pageUrl.href);
    if (!url || !/^https?:$/.test(url.protocol)) continue;

    if (IPV4.test(url.hostname) && url.hostname !== state.site.hostname && once(state, `internal:${url.host}`)) {
      state.report(RULES.internal.id, { key: url.host, message: `${where} links to a server by raw IP address${url.protocol === 'http:' ? ' over plain HTTP' : ''}: ${url.origin}/.` });
    }
    if (tag === 'a') {
      if (sameSite(url, state.site)) {
        links.push(url);
        noteQueryLink(state, url);
      }
      continue;
    }
    if (tag === 'link' && !/stylesheet|preload|modulepreload|icon/i.test(attrs.rel ?? '')) continue;

    if (sameSite(url, state.site)) {
      const dir = url.pathname.replace(/[^/]*$/, '');
      if (dir.length > 1 && tag !== 'form') state.assetDirs.add(dir);
      noteWordPressAsset(state, url);
    }
    if (secure && url.protocol === 'http:') {
      if (tag === 'form') {
        if (once(state, `form:${url.href}`)) state.report(RULES.form.id, { key: url.href, message: `A form on ${where} sends to ${url.href}.` });
      } else if (once(state, `mixed:${url.href}`)) {
        const active = /^(script|link|iframe|embed|object)$/.test(tag);
        state.report(RULES.mixed.id, { key: url.href, severity: active ? 'high' : 'low', message: `${where} loads \`<${tag}>\` from ${url.href}.` });
      }
    }
    if (tag === 'script') checkScriptTag(state, attrs, url, where, scripts, pageUrl);
  }
  if (state.wordpress) for (const [name, version] of generators) if (!state.wordpress.generators.has(name)) state.wordpress.generators.set(name, version);

  // Inline scripts and data blobs ship to every visitor too.
  scanForSecrets(state, html, where);
  inspectText(state, html, where);
  checkErrorPage(state, html, where);
  fingerprintHtml(state, html);
  if (state.active) collectForms(state, html, pageUrl);
  return links;
}

/** Fetches internal pages breadth first, so the most linked pages are checked before deep ones. */
async function crawl(state: LiveState, start: URL, homeHtml: string, disallow: string[], limit: number): Promise<void> {
  const key = (url: URL): string => `${url.pathname}${url.search}`;
  const visited = new Set<string>([key(start)]);
  const broken: Array<{ url: string; status: number; from: string }> = [];
  let queue = checkPage(state, homeHtml, start).map((url) => ({ url, from: key(start) }));
  let fetched = 0;

  while (queue.length && fetched < limit) {
    const batch: Array<{ url: URL; from: string }> = [];
    for (const item of queue) {
      if (fetched + batch.length >= limit) break;
      const url = new URL(item.url.href);
      url.hash = '';
      url.protocol = start.protocol;
      url.host = start.host;
      const k = key(url);
      if (visited.has(k) || NOT_PAGE.test(url.pathname) || SKIP_PATH.test(k) || disallow.some((d) => url.pathname.startsWith(d))) continue;
      visited.add(k);
      batch.push({ url, from: item.from });
    }
    fetched += batch.length;
    const next: Array<{ url: URL; from: string }> = [];
    await mapLimit(batch, 2, async ({ url, from }) => {
      const res = await politeGet(url.href);
      if (!res) return;
      // Still throttled after a retry: say nothing rather than call a working page broken.
      if (res.status === 429 || res.status === 503) return;
      if (res.status === 404 || res.status === 410 || res.status >= 500) {
        broken.push({ url: key(url), status: res.status, from });
        checkErrorPage(state, await readText(res, 300_000), key(url));
        return;
      }
      const landed = new URL(res.url || url.href);
      if (!res.ok || !sameSite(landed, state.site)) {
        await res.body?.cancel().catch(() => undefined);
        return;
      }
      checkCookies(state, res.headers, landed.protocol === 'https:', key(landed));
      fingerprintHeaders(state, res.headers);
      const html = await readHtml(res);
      if (html) next.push(...checkPage(state, html, landed).map((link) => ({ url: link, from: key(landed) })));
    });
    queue = next;
  }
  state.ctx.pagesChecked = 1 + fetched;

  for (const item of broken.slice(0, MAX_BROKEN)) {
    state.report(RULES.broken.id, { key: item.url, severity: item.status >= 500 ? 'medium' : 'low', message: `${item.url} returns ${item.status}. Linked from ${item.from}.` });
  }
}

async function checkDirectoryListings(state: LiveState): Promise<void> {
  const dirs = [...state.assetDirs];
  if (state.wordpress) dirs.push('/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/');
  // Shallow folders first: a listing there shows the most.
  const chosen = [...new Set(dirs)].sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b)).slice(0, 15);
  await mapLimit(chosen, 3, async (dir) => {
    const res = await get(new URL(dir, state.site.origin).href, { redirect: 'manual' });
    if (!res || res.status !== 200) {
      await res?.body?.cancel().catch(() => undefined);
      return;
    }
    const html = (await readHtml(res, 20_000)).slice(0, 4000);
    if (/<title>\s*Index of \/|<h1>\s*Index of \/|Directory listing for \//i.test(html)) {
      state.report(RULES.listing.id, { key: dir, message: `${dir} lists its files.` });
    }
  });
}

async function wordPressVersions(wp: WordPress, origin: string, platforms: Platforms): Promise<void> {
  // Asset ?ver= values are often cache busters, so readme.txt, generator tags and style.css are asked first.
  if (wp.core && !platforms.wordpressCore) {
    platforms.wordpressCore = { version: wp.core, file: 'WordPress' };
    platforms.components.push({ label: 'WordPress', version: wp.core, file: 'WordPress', queries: [product('wordpress', 'wordpress', wp.core)] });
  }
  await mapLimit([...wp.plugins].slice(0, 30), 4, async ([slug, versions]) => {
    const readme = await get(`${origin}/wp-content/plugins/${slug}/readme.txt`, { redirect: 'manual' });
    const stable = readme?.status === 200 ? /^\s*Stable tag:\s*([\d.]+)\s*$/im.exec(await readText(readme, 8000))?.[1] : undefined;
    const guessed = versions.size === 1 ? [...versions][0] : undefined;
    const version = stable ?? wp.generators.get(slug) ?? (guessed && VERSION.test(guessed) ? guessed : undefined);
    addon('plugin', slug, version, `/wp-content/plugins/${slug}/`, platforms);
  });
  await mapLimit([...wp.themes].slice(0, 5), 3, async (slug) => {
    const style = await get(`${origin}/wp-content/themes/${slug}/style.css`, { redirect: 'manual' });
    const version = style?.status === 200 ? /^[\s*#]*Version:\s*([\d.]+)/im.exec(await readText(style, 8000))?.[1] : undefined;
    addon('theme', slug, version, `/wp-content/themes/${slug}/`, platforms);
  });
}

async function checkWordPress(state: LiveState, platforms: Platforms): Promise<void> {
  const wp = state.wordpress!;
  const { origin } = state.site;
  let listed = false;
  const users = await get(`${origin}/wp-json/wp/v2/users`);
  if (users?.ok && /json/.test(users.headers.get('content-type') ?? '')) {
    const list = await users.json().catch(() => null);
    const names: string[] = Array.isArray(list) ? list.map((u: any) => u?.slug).filter((n: unknown) => typeof n === 'string') : [];
    if (names.length) {
      listed = true;
      state.report(RULES.users.id, { key: 'wp-json', message: `/wp-json/wp/v2/users lists ${names.length} account name(s): ${names.slice(0, 5).map((n) => `\`${n}\``).join(', ')}.` });
    }
  } else await users?.body?.cancel().catch(() => undefined);
  if (!listed) {
    const author = await get(`${origin}/?author=1`, { redirect: 'manual' });
    const name = /\/author\/([^/?#]+)/.exec(author?.headers.get('location') ?? '')?.[1];
    if (name) state.report(RULES.users.id, { key: 'author-archive', message: `/?author=1 redirects to the author page for \`${decodeURIComponent(name)}\`.` });
  }
  const xmlrpc = await get(`${origin}/xmlrpc.php`);
  if (xmlrpc && /XML-RPC server accepts POST requests only/i.test(await readText(xmlrpc, 2000))) state.report(RULES.xmlrpc.id, { message: '/xmlrpc.php is reachable.' });

  if (!wp.core) {
    const feed = await get(`${origin}/feed/`);
    const version = feed?.ok ? /<generator>https?:\/\/wordpress\.org\/\?v=([\d.]+)<\/generator>/.exec(await readText(feed, 50_000))?.[1] : undefined;
    if (version) {
      wp.core = version;
      state.report(RULES.server.id, { key: 'generator:feed', message: `The RSS feed at /feed/ names WordPress ${version}.` });
    }
  }
  if (wp.core) addTech(state, 'WordPress', wp.core, 'generator tag or feed');
  if (state.ctx.options.online) await wordPressVersions(wp, origin, platforms);
}

/** Offline, library advisories come from the built-in list and are reported without exploit data. */
function reportLibrariesOffline(state: LiveState, hits: Hit[]): void {
  for (const hit of hits) {
    const id = hit.ids[0];
    const summary = hit.summaries[id];
    state.report(RULES.library.id, {
      file: hit.file,
      key: hit.key,
      severity: hit.severity,
      advisories: hit.ids,
      message: `${hit.name}@${hit.version}: ${hit.ids.slice(0, 3).join(', ')}${summary ? ` (${summary})` : ''}.${hit.fixed ? ` Upgrade to ${hit.fixed} or later.` : ''}`,
    });
  }
}

const BACKPORT_NOTE = ' Linux distributions often backport fixes without changing this version number, so confirm with your host or package manager.';

async function lookUpVulnerabilities(state: LiveState, platforms: Platforms): Promise<void> {
  const { ctx } = state;
  const libraryHits = state.detector.hits(state.libraries);
  if (!ctx.options.online) {
    reportLibrariesOffline(state, libraryHits);
    return;
  }
  ctx.packagesChecked = (ctx.packagesChecked ?? 0) + state.libraries.size;
  await reportHits(libraryHits, ctx, (input) => state.report(RULES.library.id, input));

  platforms.components.push(...state.components);
  const asComponent: Reporter = (_id, input = {}) => {
    const server = [...SERVER_LABELS].some((label) => input.key?.startsWith(`${label}@`));
    state.report(RULES.component.id, { ...input, file: undefined, message: server && input.message ? input.message + BACKPORT_NOTE : input.message });
  };
  const hits = [...(state.packages.length ? await checkOsv(state.packages, ctx) : []), ...(await checkPlatforms(platforms, ctx, asComponent))];
  await reportHits(hits, ctx, (input) => asComponent(RULES.component.id, input));
  if (platforms.unversioned.length) {
    ctx.gaps.push(`${platforms.unversioned.length} WordPress plugin(s) or theme(s) did not reveal a version, so they were not checked for CVEs: ${platforms.unversioned.slice(0, 5).join(', ')}.`);
  }
}

function certificateDays(host: string, port: number): Promise<number | null> {
  return new Promise((resolve) => {
    const socket = connect({ host, port, servername: host, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve(cert?.valid_to ? Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000) : null);
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

async function loadDetector(ctx: ScanContext): Promise<Detector> {
  if (!ctx.options.online) return builtInDetector;
  try {
    return await loadRetire();
  } catch (error) {
    ctx.gaps.push(`Could not download the Retire.js library database, so only common libraries were checked: ${(error as Error).message}`);
    return builtInDetector;
  }
}

async function checkUrl(input: string, report: Reporter, ctx: ScanContext): Promise<void> {
  const target = new URL(/^https?:\/\//.test(input) ? input : `https://${input}`);
  const detector = loadDetector(ctx);
  const started = Date.now();
  const res = await get(target.href);
  const elapsed = Date.now() - started;
  if (!res || !res.ok) {
    report(RULES.unreachable.id, { message: res ? `${target.href} returned ${res.status}.` : `${target.href} did not respond.` });
    return;
  }
  const html = await readHtml(res);
  const final = new URL(res.url || target.href);
  const local = /^(localhost|127\.|0\.0\.0\.0|\[::1\])/.test(final.hostname);
  ctx.pagesChecked = 1;
  const state: LiveState = {
    site: final, ctx, report, active: Boolean(ctx.options.active), queryUrls: new Map(), forms: [], seen: new Set(), assetDirs: new Set(), scripts: new Map(), wordpress: null,
    detector: await detector, libraries: new Map(), endpoints: new Map(), tech: new Map(), packages: [], components: [], sourceMaps: [],
  };
  if (elapsed > 2000) report(RULES.slow.id, { message: `The first response took ${elapsed} ms.` });

  if (final.protocol !== 'https:') {
    if (!local) report(RULES.noHttps.id);
  } else {
    const days = await certificateDays(final.hostname, Number(final.port) || 443);
    if (days !== null && days < 21) report(RULES.cert.id, { severity: days < 7 ? 'critical' : 'high', message: `The certificate expires in ${days} day(s).` });
    const plain = await get(`http://${final.host}${final.pathname}`, { redirect: 'manual' });
    await plain?.body?.cancel().catch(() => undefined);
    const location = plain?.headers.get('location') ?? '';
    if (plain && !(plain.status >= 300 && plain.status < 400 && location.startsWith('https:'))) report(RULES.noRedirect.id);
    await checkTlsVersions(state);
  }

  for (const { name, severity } of HEADERS) {
    if (name === 'strict-transport-security' && final.protocol !== 'https:') continue;
    if (!res.headers.has(name)) report(RULES.header.id, { key: name, severity, message: `\`${name}\` is not set.` });
  }
  if (!res.headers.has('x-frame-options') && !/frame-ancestors/.test(res.headers.get('content-security-policy') ?? '')) {
    report(RULES.header.id, { key: 'framing', severity: 'low', message: 'No clickjacking protection (`x-frame-options` or `frame-ancestors`).' });
  }
  checkCsp(state, res.headers);
  if (final.protocol === 'https:') checkHsts(state, res.headers);
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version']) {
    const value = res.headers.get(name);
    if (value && (/\d/.test(value) || name === 'x-powered-by')) report(RULES.server.id, { key: name, message: `\`${name}: ${value}\`` });
  }
  checkCookies(state, res.headers, final.protocol === 'https:', 'the home page');
  fingerprintHeaders(state, res.headers);

  await runProbes(state);
  const missing = await get(new URL(`/alil-launch-check-${Date.now()}`, final.origin).href);
  if (missing?.status === 200) report(RULES.soft404.id);
  await missing?.body?.cancel().catch(() => undefined);
  await checkErrorPages(state);
  const robots = await get(new URL('/robots.txt', final.origin).href);
  const robotsText = robots?.ok ? await readText(robots, 500_000) : '';
  if (/user-agent:\s*\*\s*\n\s*disallow:\s*\/\s*$/im.test(robotsText)) report(RULES.robots.id);
  const disallow = robotsDisallow(robotsText);
  await checkSecurityTxt(state);

  if (html) {
    const absent = [
      /<title>[^<]+<\/title>/i.test(html) ? '' : 'title',
      /<meta[^>]+name=["']description["']/i.test(html) ? '' : 'meta description',
      /<meta[^>]+property=["']og:/i.test(html) ? '' : 'Open Graph tags',
    ].filter(Boolean);
    if (absent.length) report(RULES.meta.id, { message: `Missing: ${absent.join(', ')}.` });
    await crawl(state, final, html, disallow, ctx.options.maxPages ?? DEFAULT_PAGES);
    await checkDirectoryListings(state);
    await analyzeScripts(state);
  }

  const apiPaths = [...state.endpoints.keys()].filter((p) => !p.includes('{') && !disallow.some((d) => p.startsWith(d))).slice(0, 3);
  await checkCors(state, [final.pathname, ...apiPaths]);
  await checkGraphql(state);
  await checkLoginPages(state);
  if (state.active) await runActiveChecks(state);
  const platforms: Platforms = { packages: [], components: [], unversioned: [] };
  if (state.wordpress) await checkWordPress(state, platforms);

  reportSourceMaps(state);
  reportEndpoints(state);
  await lookUpVulnerabilities(state, platforms);
  reportTech(state);
}

export const liveChecker: Checker = {
  name: 'live',
  rules: LIVE_RULES,
  async run(ctx, report) {
    if (ctx.options.url) await checkUrl(ctx.options.url, report, ctx);
  },
};
