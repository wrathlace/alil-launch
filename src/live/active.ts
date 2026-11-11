import { mapLimit } from '../core/util.js';
import { get, isHtml, readText } from './http.js';
import { RULES } from './rules.js';
import { once, type LiveState } from './state.js';

/**
 * Active checks: these send a few extra, crafted-but-non-destructive requests, so they run only
 * when the user passes --active with authorization. Nothing here modifies data, sends attack
 * payloads (no SQLi/XSS strings), floods the target, or touches state-changing paths.
 */

/** Parameter names that commonly carry a redirect destination. OAuth's redirect_uri is excluded: it is expected. */
const REDIRECT_PARAMS = /^(redirect|redir|redirecturl|redirect_url|return|returnurl|return_url|returnto|return_to|continue|next|dest|destination|goto|target|forward|out|url|u|link|checkout_url|success_url|cancel_url|callback)$/i;

/** Paths a probe must never touch, even with GET: they can change or destroy state. */
const UNSAFE = /(logout|log-out|signout|sign-out|delete|remove|destroy|drop|truncate|wipe|purge|reset|revoke|disable|deactivate|cancel|refund|pay|charge|checkout|subscribe|unsubscribe|create|update|edit|add|import|export|upload|download|backup|restore|migrate|seed|run|exec|shutdown|restart)/i;
/** Endpoints worth checking for missing auth: they read data that is usually private. */
const SENSITIVE = /(admin|users?|accounts?|members?|customers?|profiles?|orders?|invoices?|payments?|config|settings|internal|private|secret|debug|metrics|dashboard|reports?|audit|logs?|me\b|whoami|session|token)/i;

const MARKER_HOST = 'alil-launch-hostcheck.example';

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
}
