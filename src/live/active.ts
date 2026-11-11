import { mapLimit } from '../core/util.js';
import { sameSite } from './html.js';
import { get, isHtml, readText } from './http.js';
import { RULES } from './rules.js';
import { once, type LiveState } from './state.js';

/**
 * Active checks: these send a few extra, crafted-but-non-destructive requests, so they run only
 * when the user passes --active with authorization. Injection detection uses a unique, non-executing
 * marker (`<x>"'`) to observe missing output escaping and SQL errors — never a working script, a
 * data-modifying statement (no UNION/DROP/UPDATE), or a time-based payload. Nothing here modifies
 * data, floods the target, uses anything but GET/HEAD/OPTIONS, or touches state-changing paths.
 */

/** Parameter names that commonly carry a redirect destination. OAuth's redirect_uri is excluded: it is expected. */
const REDIRECT_PARAMS = /^(redirect|redir|redirecturl|redirect_url|return|returnurl|return_url|returnto|return_to|continue|next|dest|destination|goto|target|forward|out|url|u|link|checkout_url|success_url|cancel_url|callback)$/i;

/** Paths a probe must never touch, even with GET: they can change or destroy state. */
const UNSAFE = /(logout|log-out|signout|sign-out|delete|remove|destroy|drop|truncate|wipe|purge|reset|revoke|disable|deactivate|cancel|refund|pay|charge|checkout|subscribe|unsubscribe|create|update|edit|add|import|export|upload|download|backup|restore|migrate|seed|run|exec|shutdown|restart)/i;
/** Endpoints worth checking for missing auth: they read data that is usually private. */
const SENSITIVE = /(admin|users?|accounts?|members?|customers?|profiles?|orders?|invoices?|payments?|config|settings|internal|private|secret|debug|metrics|dashboard|reports?|audit|logs?|me\b|whoami|session|token)/i;

const MARKER_HOST = 'alil-launch-hostcheck.example';

const MAX_INJECT_URLS = 10;
const MAX_PARAMS = 4;
/** A unique, non-executing probe: `<x>` is a no-op tag and the quotes test attribute and SQL escaping. */
const randomMarker = (): string => `aliL${Math.random().toString(36).slice(2, 8)}`;
const payloadFor = (marker: string): string => `${marker}<x>"'`;
/** Database errors that appear when a stray quote breaks a query: the classic error-based SQLi signal. */
const DB_ERROR = /SQL syntax|SQLSTATE|mysqli?_|mysql_fetch|valid MySQL result|ORA-\d{5}|PLS-\d{5}|PostgreSQL.{0,40}ERROR|pg_query|pg_exec|SQLite3?::|System\.Data\.SQLite|System\.Data\.SqlClient|SqlException|ODBC.{0,30}SQL|JDBC|Unclosed quotation mark|quoted string not properly terminated|unterminated quoted string|syntax error at or near|near "[^"]*": syntax error|Warning: pg_/i;

/** Records a same-site link that carries query parameters, for later injection probes. Sends nothing. */
export function noteQueryLink(state: LiveState, url: URL): void {
  if (![...url.searchParams].length || UNSAFE.test(url.pathname + url.search)) return;
  const bare = `${url.origin}${url.pathname}?${url.searchParams.toString()}`;
  if (!state.queryUrls.has(bare) && state.queryUrls.size < 60) state.queryUrls.set(bare, state.site.pathname);
}

/** Collects GET forms and their input names, for later injection probes. Sends nothing. */
export function collectForms(state: LiveState, html: string, pageUrl: URL): void {
  for (const block of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = block[1];
    const method = (/\bmethod\s*=\s*["']?(\w+)/i.exec(attrs)?.[1] ?? 'get').toLowerCase();
    if (method !== 'get') continue;
    const action = /\baction\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? pageUrl.href;
    const url = resolveLink(action, pageUrl.href);
    if (!url || !sameSite(url, state.site) || UNSAFE.test(url.pathname)) continue;
    const params = [...new Set([...block[2].matchAll(/<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([\w.\[\]-]+)/gi)].map((m) => m[1]))]
      .filter((n) => !/csrf|token|_method/i.test(n))
      .slice(0, 6);
    if (params.length && state.forms.length < 30) state.forms.push({ action: `${url.origin}${url.pathname}`, params, where: pageUrl.pathname });
  }
}

function resolveLink(value: string, base: string): URL | null {
  try {
    const url = new URL(value, base);
    return /^https?:$/.test(url.protocol) ? url : null;
  } catch {
    return null;
  }
}

interface Target {
  base: string;
  params: string[];
  fixed: Record<string, string>;
  where: string;
}

/** Unifies query-string links and GET forms into one list of {url, parameters} to probe. */
function injectionTargets(state: LiveState): Target[] {
  const seen = new Set<string>();
  const targets: Target[] = [];
  const add = (base: string, params: string[], fixed: Record<string, string>, where: string): void => {
    const key = `${base}|${params.sort().join(',')}`;
    if (params.length && !seen.has(key)) {
      seen.add(key);
      targets.push({ base, params: params.slice(0, MAX_PARAMS), fixed, where });
    }
  };
  for (const [url, where] of state.queryUrls) {
    const parsed = new URL(url);
    const params = [...parsed.searchParams.keys()];
    add(`${parsed.origin}${parsed.pathname}`, params, Object.fromEntries(parsed.searchParams), where);
  }
  for (const form of state.forms) add(form.action, form.params, {}, form.where);
  return targets.slice(0, MAX_INJECT_URLS);
}

function buildProbe(target: Target, param: string, value: string): string {
  const search = new URLSearchParams(target.fixed);
  for (const p of target.params) if (!search.has(p)) search.set(p, target.fixed[p] ?? 'alil');
  search.set(param, value);
  return `${target.base}?${search.toString()}`;
}

/**
 * Error-based SQLi and reflected-XSS detection on GET parameters. Sends one probe per parameter with a
 * unique non-executing marker; never a working script, never a data-modifying or time-based payload.
 */
async function checkInjection(state: LiveState): Promise<void> {
  const targets = injectionTargets(state);
  await mapLimit(targets, 2, async (target) => {
    // Baseline, so a database error that is always present is not blamed on us.
    const baseRes = await get(buildProbe(target, target.params[0], target.fixed[target.params[0]] ?? 'alil'));
    const baseBody = baseRes ? await readText(baseRes, 200_000) : '';
    const baseError = DB_ERROR.test(baseBody);

    for (const param of target.params) {
      const marker = randomMarker();
      const res = await get(buildProbe(target, param, payloadFor(marker)));
      if (!res) continue;
      const type = res.headers.get('content-type') ?? '';
      const body = await readText(res, 300_000);
      const path = new URL(target.base).pathname;

      if (/html|xml|json|javascript|text\/plain/.test(type) || !type) {
        // Reflected unescaped: the marker comes back with its `<x>` tag intact, not HTML-encoded.
        if (body.includes(`${marker}<x>`) && once(state, `xss:${path}:${param}`)) {
          state.report(RULES.xss.id, { key: `${path}:${param}`, message: `The \`${param}\` parameter on ${path} is reflected into the page without escaping (seen from ${target.where}).` });
        }
      }
      if (!baseError && DB_ERROR.test(body) && once(state, `sqli:${path}:${param}`)) {
        const sample = DB_ERROR.exec(body)?.[0] ?? 'a database error';
        state.report(RULES.sqli.id, { key: `${path}:${param}`, message: `A quote in the \`${param}\` parameter on ${path} triggered a database error (\`${sample}\`), which indicates SQL injection (seen from ${target.where}).` });
      }
    }
  });
}

/** Reads redirect-style parameters out of text already fetched. Sends nothing. */
export function detectRedirectParams(state: LiveState, text: string, where: string): void {
  for (const match of text.matchAll(/[?&#]([a-z_][\w.-]{0,40})=(https?(?::|%3a)|\/\/|%2f%2f)/gi)) {
    const name = match[1];
    if (name.toLowerCase() === 'redirect_uri' || !REDIRECT_PARAMS.test(name)) continue;
    if (once(state, `redirect:${name.toLowerCase()}`)) {
      state.report(RULES.redirectParam.id, { key: name.toLowerCase(), message: `A \`${name}\` parameter taking a URL appears in ${where}. Validate the destination before redirecting.` });
    }
  }
}

/** Password-reset poisoning and cache poisoning: does the server echo an attacker-supplied Host? */
async function checkHostHeader(state: LiveState): Promise<void> {
  for (const header of ['host', 'x-forwarded-host']) {
    const res = await get(state.site.href, { headers: { [header]: MARKER_HOST } });
    if (!res) continue;
    const location = res.headers.get('location') ?? '';
    const body = isHtml(res) ? await readText(res, 200_000) : '';
    if (!isHtml(res)) await res.body?.cancel().catch(() => undefined);
    // A link or redirect built from our fake host means the header is trusted.
    const inLink = new RegExp(`(?:href|src|action)=["']https?://${MARKER_HOST}|<link[^>]+${MARKER_HOST}|["']https?://${MARKER_HOST}[/"']`, 'i').test(body);
    if (location.includes(MARKER_HOST) || inLink) {
      state.report(RULES.hostHeader.id, { key: header, severity: header === 'host' ? 'high' : 'medium', message: `The server reflected a \`${header}\` value of \`${MARKER_HOST}\` into ${location.includes(MARKER_HOST) ? 'a redirect' : 'page links'}, so the Host header is trusted.` });
      return;
    }
  }
}

/** Reports dangerous methods the server says it allows. Sends OPTIONS, and TRACE only to confirm. */
async function checkMethods(state: LiveState): Promise<void> {
  const res = await get(state.site.href, { method: 'OPTIONS', redirect: 'manual' });
  await res?.body?.cancel().catch(() => undefined);
  const allow = (res?.headers.get('allow') ?? res?.headers.get('access-control-allow-methods') ?? '').toUpperCase();
  const risky = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'].filter((m) => allow.includes(m));
  if (risky.length) {
    state.report(RULES.riskyMethod.id, { key: 'allow', severity: risky.includes('TRACE') ? 'high' : 'medium', message: `The server's \`Allow\` header lists ${risky.join(', ')} on the home page.` });
  }
}

/** One GET per sensitive-looking endpoint found in the site's own code. Never touches state-changing paths. */
async function checkOpenEndpoints(state: LiveState): Promise<void> {
  const paths = [...state.endpoints.keys()]
    .filter((p) => p.startsWith('/') && !p.includes('{') && SENSITIVE.test(p) && !UNSAFE.test(p))
    .slice(0, 12);
  await mapLimit(paths, 3, async (path) => {
    const res = await get(new URL(path, state.site.origin).href, { headers: { accept: 'application/json' } });
    if (!res) return;
    const type = res.headers.get('content-type') ?? '';
    const body = /json/.test(type) ? await readText(res, 100_000) : (await res.body?.cancel().catch(() => undefined), '');
    // A data response (JSON array/object) with no auth challenge is the signal; a login redirect or 401/403 is not.
    const data = /json/.test(type) && /^\s*[[{]/.test(body) && !/"(error|message)"\s*:\s*"[^"]*(unauth|forbidden|login|token|denied)/i.test(body);
    if (res.status === 200 && data && once(state, `open:${path}`)) {
      state.report(RULES.openEndpoint.id, { key: path, message: `${path} returned JSON data to an unauthenticated request. Confirm it is meant to be public.` });
    }
  });
}

/** Runs the gated active probes. Caller guarantees state.active is true. */
export async function runActiveChecks(state: LiveState): Promise<void> {
  await checkHostHeader(state);
  await checkMethods(state);
  await checkOpenEndpoints(state);
  await checkInjection(state);
}
