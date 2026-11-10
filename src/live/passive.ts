import { mapLimit, parseJson, redact, sha } from '../core/util.js';
import { get, isHtml, readText } from './http.js';
import { RULES } from './rules.js';
import { once, type LiveState } from './state.js';

/**
 * Passive, non-destructive weakness checks: they read what the site already exposes and never send
 * credentials or attack payloads. JWT inspection decodes tokens the site hands to browsers; the login
 * check only observes that a sign-in page is reachable.
 */

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{0,}|)/g;
/** Claims whose presence in a browser-readable token means real privilege, not just a session. */
const PRIVILEGED = /^(service_role|admin|administrator|superuser|superadmin|root|owner)$/i;
const MAX_TOKENS = 40;

function decodePart(part: string): any {
  return parseJson(Buffer.from(part, 'base64url').toString('utf8'));
}

/** Finds JSON Web Tokens in page or script text and flags the ones that are genuinely weak. */
export function inspectTokens(state: LiveState, text: string, where: string): void {
  let count = 0;
  for (const match of text.matchAll(JWT)) {
    if (count++ > MAX_TOKENS) break;
    const token = match[0];
    const [rawHeader, rawPayload] = token.split('.');
    const header = decodePart(rawHeader);
    const payload = decodePart(rawPayload);
    if (!header || !payload || typeof payload !== 'object') continue;
    if (!once(state, `jwt:${sha(token)}`)) continue;

    const alg = String(header.alg ?? '').toLowerCase();
    const roles = [payload.role, payload.roles, payload.scope, payload.scopes, payload['https://hasura.io/jwt/claims'], payload.realm_access?.roles, payload.permissions]
      .flatMap((v) => (Array.isArray(v) ? v : typeof v === 'string' ? v.split(/[\s,]+/) : v ? [String(v)] : []));
    const privileged = roles.find((r) => PRIVILEGED.test(String(r)));

    if (alg === 'none' || alg === '') {
      state.report(RULES.jwt.id, { key: `jwt-none:${sha(token)}`, severity: 'high', evidence: redact(token), message: `A token in ${where} uses \`alg: ${header.alg ?? 'none'}\`, so it is unsigned and anyone can forge one.` });
    } else if (privileged) {
      state.report(RULES.jwt.id, { key: `jwt-priv:${sha(token)}`, severity: 'high', evidence: redact(token), message: `A token in ${where} grants the \`${privileged}\` role and is readable by any visitor, so it can be replayed to act as that role.` });
    }
  }
}

interface LoginProbe {
  path: string;
  marker: RegExp;
  label: string;
}

/** Common sign-in pages. A finding needs a real login marker, so an app's own 200 page is not mistaken for one. */
const LOGIN_PAGES: LoginProbe[] = [
  { path: '/wp-login.php', marker: /name=["']log["']|id=["']loginform["']|wp-submit/, label: 'WordPress login' },
  { path: '/administrator/', marker: /option=com_login|mod-login-username|Joomla/i, label: 'Joomla administrator' },
  { path: '/user/login', marker: /name=["']pass["'][^>]*>|user-login-form|drupal/i, label: 'Drupal login' },
  { path: '/admin/login/', marker: /id=["']login-form["']|csrfmiddlewaretoken|django/i, label: 'Django admin' },
  { path: '/login', marker: /type=["']password["']/i, label: 'login page' },
  { path: '/admin', marker: /type=["']password["']/i, label: 'admin login' },
  { path: '/rails/info', marker: /Rails version|Ruby version/i, label: 'Rails info page' },
];

/** Reports which admin or login pages are reachable. Sends only GET; never submits credentials. */
export async function checkLoginPages(state: LiveState): Promise<void> {
  const reported = new Set<string>();
  await mapLimit(LOGIN_PAGES, 3, async (probe) => {
    const res = await get(new URL(probe.path, state.site.origin).href, { redirect: 'manual' });
    if (!res || res.status !== 200 || !isHtml(res)) {
      await res?.body?.cancel().catch(() => undefined);
      return;
    }
    const html = (await readText(res, 200_000)).slice(0, 100_000);
    const hasPassword = /type=["']password["']/i.test(html) || probe.marker.test(html);
    // Generic /login and /admin must show a password field; named ones accept their own marker.
    if (!hasPassword || reported.has(probe.label)) return;
    if ((probe.path === '/login' || probe.path === '/admin') && !/type=["']password["']/i.test(html)) return;
    reported.add(probe.label);
    state.report(RULES.loginPage.id, { key: probe.path, message: `The ${probe.label} is reachable at ${probe.path}.` });
  });
}
