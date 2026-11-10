import { mapLimit } from '../core/util.js';
import { politeGet, readText } from './http.js';
import { sameSite, STATIC_CDNS, VENDOR_HOSTS } from './html.js';
import { inspectTokens } from './passive.js';
import { RULES } from './rules.js';
import { addLibraries, once, scanForSecrets, type LiveState } from './state.js';

const MAX_SCRIPTS = 80;
const MAX_SCRIPT_BYTES = 8_000_000;
const MAX_MAP_BYTES = 30_000_000;
/** Same-site scripts with no sourceMappingURL comment that are still tried at `<script>.map`. */
const MAX_GUESSED_MAPS = 15;
const MAX_MAP_SOURCES_SCANNED = 400;

const ENDPOINT = /["'`]((?:https?:\/\/[a-z0-9.-]+(?::\d+)?)?\/(?:api|graphql|gql|rest|rpc|v[1-9]\d?|oauth2?|wp-json|ajax|backend)(?:\/[\w\-.~%{}:$]*)*)(?:["'`?#])/gi;
const PRIVATE_IP = /\bhttps?:\/\/((?:10(?:\.\d{1,3}){3})|(?:192\.168(?:\.\d{1,3}){2})|(?:172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})|(?:127\.0\.0\.1)|localhost|0\.0\.0\.0)(:\d{2,5})?(\/[^\s"'`<>)]*)?/gi;
const STAGING_LABEL = /^(?:staging|stage|stg|dev|develop|uat|qa|test|preprod|pre-prod|sandbox|internal|intranet)(?:[-\d][a-z0-9-]*)?$|^[a-z0-9-]+-(?:staging|stage|dev|uat|qa|test|preprod|internal)$/i;
const HOST_URL = /\bhttps?:\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?/gi;

/** The part of a host name its owner controls, such as example.com or doib.gov.np. */
function baseDomain(host: string): string {
  const labels = host.replace(/^www\./, '').split('.');
  const secondLevel = labels.length >= 3 && labels.at(-1)!.length === 2 && labels.at(-2)!.length <= 3;
  return labels.slice(secondLevel ? -3 : -2).join('.');
}

/** Finds API paths, internal addresses and staging hosts in page or script text. */
export function inspectText(state: LiveState, text: string, where: string): void {
  for (const match of text.matchAll(ENDPOINT)) {
    let value = match[1];
    if (value.length > 150 || /\s/.test(value)) continue;
    try {
      if (/^https?:/.test(value)) {
        const url = new URL(value);
        if (!sameSite(url, state.site)) continue;
        value = url.pathname;
      }
    } catch {
      continue;
    }
    // /pages/15343 and /pages/15724 are one endpoint.
    value = value.replace(/\/\d+(?=\/|$)/g, '/{id}').replace(/\/[0-9a-f]{24,}(?=\/|$)/gi, '/{id}');
    if (!state.endpoints.has(value) && state.endpoints.size < 500) state.endpoints.set(value, where);
  }

  for (const match of text.matchAll(PRIVATE_IP)) {
    // Bare localhost with no port is usually a library default, not a leak.
    if (/localhost|0\.0\.0\.0/i.test(match[1]) && !match[2]) continue;
    const address = `${match[1]}${match[2] ?? ''}`;
    if (once(state, `internal:${address}`)) state.report(RULES.internal.id, { key: address, message: `${where} refers to ${match[0].slice(0, 120)}.` });
  }

  const base = baseDomain(state.site.hostname);
  for (const match of text.matchAll(HOST_URL)) {
    const host = match[1].toLowerCase();
    if (host === state.site.hostname || !host.endsWith(`.${base}`) && host !== base) continue;
    const own = host.slice(0, -(base.length + 1)).split('.');
    if (!own.some((label) => STAGING_LABEL.test(label))) continue;
    if (once(state, `internal:${host}`)) state.report(RULES.internal.id, { key: host, message: `${where} refers to a non-production host, ${host}.` });
  }

  inspectTokens(state, text, where);
}

interface SourceMap {
  sources?: string[];
  sourcesContent?: Array<string | null>;
  mappings?: string;
}

const packageOf = (source: string): string | undefined => /node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(source)?.[1];
const cleanSource = (source: string): string => source.replace(/^(webpack|vite|rollup|turbopack):\/\/\/?(\[[^\]]*\]\/)?|^\.?\.?\//g, '').replace(/^(\.\.\/)+|^\.\//, '');

function analyzeSourceMap(state: LiveState, map: SourceMap, mapUrl: URL): void {
  const sources = (map.sources ?? []).map(String);
  const contents = map.sourcesContent ?? [];
  const own: string[] = [];
  const packages = new Set<string>();
  let scanned = 0;
  sources.forEach((source, i) => {
    const pkg = packageOf(source);
    const name = cleanSource(source);
    if (pkg) packages.add(pkg);
    else if (!/^(webpack\/|\(webpack\)|\/?\(?bootstrap\)?$|external |ignored\|)/.test(name)) own.push(name);
    const content = contents[i];
    if (typeof content !== 'string' || scanned >= MAX_MAP_SOURCES_SCANNED || content.length > 1_000_000) return;
    scanned++;
    if (pkg) {
      addLibraries(state, state.detector.fromContent(content), `${pkg} in ${mapUrl.pathname}`);
    } else {
      const where = `${name} (from ${mapUrl.pathname})`;
      scanForSecrets(state, content, where, { generic: true });
      inspectText(state, content, where);
    }
  });
  state.sourceMaps.push({ url: mapUrl.pathname, files: sources.length, own, packages, content: contents.some((c) => typeof c === 'string') });
}

async function fetchSourceMap(state: LiveState, script: URL, text: string, header: string | null, guess: boolean): Promise<void> {
  const ref = header ?? /\/\/[#@]\s*sourceMappingURL=([^\s'"*]+)\s*(?:\*\/)?\s*$/.exec(text.slice(-4000))?.[1];
  if (ref?.startsWith('data:')) {
    const encoded = /^data:application\/json[^,]*;base64,(.+)$/.exec(ref)?.[1];
    if (!encoded) return;
    try {
      analyzeSourceMap(state, JSON.parse(Buffer.from(encoded, 'base64').toString('utf8')), script);
    } catch {
      // A broken inline map has nothing to show.
    }
    return;
  }
  if (!ref && !guess) return;
  let mapUrl: URL;
  try {
    mapUrl = new URL(ref ?? `${script.pathname}.map`, script);
  } catch {
    return;
  }
  if (!once(state, `map:${mapUrl.href}`)) return;
  const res = await politeGet(mapUrl.href);
  if (!res?.ok || /text\/html/.test(res.headers.get('content-type') ?? '')) {
    await res?.body?.cancel().catch(() => undefined);
    return;
  }
  try {
    const map = JSON.parse(await readText(res, MAX_MAP_BYTES)) as SourceMap;
    if (Array.isArray(map.sources) && typeof map.mappings === 'string') analyzeSourceMap(state, map, mapUrl);
  } catch {
    // Not a source map.
  }
}

/** Downloads the scripts the crawl found and reads what is inside them. */
export async function analyzeScripts(state: LiveState): Promise<void> {
  const own = [...state.scripts].filter(([href]) => sameSite(new URL(href), state.site));
  const others = [...state.scripts].filter(([href]) => !sameSite(new URL(href), state.site));
  const list = [...own, ...others].slice(0, MAX_SCRIPTS);
  let guessed = 0;

  await mapLimit(list, 3, async ([href, page]) => {
    const url = new URL(href);
    const isOwn = sameSite(url, state.site);
    const where = isOwn ? url.pathname : `${url.host}${url.pathname}`;
    const fromUrl = state.detector.fromUrl(href);
    addLibraries(state, fromUrl, where);
    // Big vendors' scripts are theirs, and a CDN file named by its version needs no download.
    if (!isOwn && (VENDOR_HOSTS.test(url.hostname) && !STATIC_CDNS.test(url.hostname))) return;
    if (STATIC_CDNS.test(url.hostname) && fromUrl.length) return;

    const res = await politeGet(href);
    if (!res?.ok) {
      await res?.body?.cancel().catch(() => undefined);
      return;
    }
    const text = await readText(res, MAX_SCRIPT_BYTES);
    if (/^\s*<(!doctype|html)/i.test(text.slice(0, 200))) return;
    addLibraries(state, state.detector.fromContent(text), where);
    if (STATIC_CDNS.test(url.hostname)) return;

    scanForSecrets(state, text, where);
    inspectText(state, text, where === url.pathname ? `${where} (loaded on ${page})` : where);
    const header = res.headers.get('sourcemap') ?? res.headers.get('x-sourcemap');
    const guess = isOwn && guessed < MAX_GUESSED_MAPS;
    if (guess) guessed++;
    await fetchSourceMap(state, url, text, header, guess);
  });
}

/** One finding for all source maps, so a site with forty chunks is one issue. */
export function reportSourceMaps(state: LiveState): void {
  if (!state.sourceMaps.length) return;
  const own = [...new Set(state.sourceMaps.flatMap((m) => m.own))];
  const packages = new Set(state.sourceMaps.flatMap((m) => [...m.packages]));
  const folders = [...new Set(own.map((f) => f.split('/').slice(0, 2).join('/')))].slice(0, 8);
  const withCode = state.sourceMaps.some((m) => m.content);
  const parts = [
    `${state.sourceMaps.length} source map(s), for example ${state.sourceMaps[0].url}, expose ${own.length} of your own source file(s)${withCode ? ' with their full original code' : ''}.`,
    folders.length ? `Folders: ${folders.join(', ')}.` : '',
    packages.size ? `They also list ${packages.size} npm package(s): ${[...packages].slice(0, 10).join(', ')}${packages.size > 10 ? ', ...' : ''}.` : '',
  ];
  state.report(RULES.sourceMap.id, { key: 'source-maps', severity: withCode && own.length ? 'medium' : 'low', message: parts.filter(Boolean).join(' ') });
}

export function reportEndpoints(state: LiveState): void {
  if (!state.endpoints.size) return;
  const paths = [...state.endpoints.keys()].sort();
  state.report(RULES.endpoints.id, { key: 'endpoints', message: `${paths.length} API path(s) found in public code: ${paths.slice(0, 25).join(', ')}${paths.length > 25 ? ', ...' : ''}.` });
}
