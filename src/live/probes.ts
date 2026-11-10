import { connect, type SecureVersion } from 'node:tls';
import type { Severity } from '../types.js';
import { mapLimit } from '../core/util.js';
import { parseLockfiles } from '../rules/dependencies.js';
import { get, isHtml, readBytes, readText } from './http.js';
import { RULES } from './rules.js';
import { once, type LiveState } from './state.js';

type RuleKey = keyof typeof RULES;

interface Probe {
  path: string;
  proof: RegExp;
  label: string;
  severity: Severity;
  rule?: RuleKey;
  /** The proof is specific enough to trust on an HTML response. */
  html?: boolean;
  /** A lockfile whose versions are worth looking up. */
  lock?: boolean;
}

const ENV = /^\s*[A-Z][A-Z0-9_]*\s*=/m;
const SQL = /INSERT INTO|CREATE TABLE/i;
const ARCHIVE = /^(PK\x03\x04|\x1f\x8b|Rar!|7z\xbc\xaf)/;
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/;
const PHP_LOG = /PHP (?:Warning|Fatal error|Notice|Parse error|Deprecated)|\[error\]/;

/** Every probe proves itself by content, so apps that answer every path with 200 are not flagged. */
export const PROBES: Probe[] = [
  ...['/.env', '/.env.local', '/.env.production', '/.env.prod', '/.env.dev', '/.env.backup', '/.env.old', '/.env.save'].map((path) => ({ path, proof: ENV, label: 'environment file', severity: 'critical' as Severity })),
  { path: '/.git/config', proof: /\[core\]/, label: 'git config, so the whole repository can be downloaded', severity: 'critical' },
  { path: '/.git/HEAD', proof: /^ref: refs\//, label: 'git metadata', severity: 'critical' },
  { path: '/.git-credentials', proof: /https?:\/\/[^\s:]+:[^\s@]+@/, label: 'git credentials', severity: 'critical' },
  { path: '/.svn/wc.db', proof: /^SQLite format 3/, label: 'Subversion metadata, so the source can be downloaded', severity: 'high' },
  { path: '/.svn/entries', proof: /^\d+\s*\n|^dir\s*$/m, label: 'Subversion metadata', severity: 'high' },
  { path: '/.hg/hgrc', proof: /^\[(paths|ui)\]/m, label: 'Mercurial metadata', severity: 'high' },
  { path: '/.aws/credentials', proof: /aws_access_key_id/i, label: 'AWS credentials', severity: 'critical' },
  { path: '/.npmrc', proof: /_auth(Token)?\s*=/, label: 'npm credentials', severity: 'critical' },
  { path: '/.ssh/id_rsa', proof: PRIVATE_KEY, label: 'SSH private key', severity: 'critical' },
  { path: '/id_rsa', proof: PRIVATE_KEY, label: 'SSH private key', severity: 'critical' },
  { path: '/.htpasswd', proof: /^[\w.-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}$)/m, label: 'password hashes', severity: 'high' },
  { path: '/.vscode/sftp.json', proof: /"(password|privateKeyPath|host)"\s*:/, label: 'editor deploy settings', severity: 'high' },
  ...['/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.save', '/wp-config.php.old', '/wp-config.php.orig', '/wp-config.txt', '/wp-config.php.swp'].map((path) => ({ path, proof: /DB_PASSWORD/, label: 'WordPress config backup', severity: 'critical' as Severity })),
  ...['/config.php.bak', '/configuration.php.bak', '/config.inc.php.bak', '/settings.php.bak'].map((path) => ({ path, proof: /pass(word)?['"]?\s*(=>|=|,)/i, label: 'config backup', severity: 'critical' as Severity })),
  ...['/backup.sql', '/dump.sql', '/db.sql', '/database.sql', '/site.sql', '/data.sql', '/mysql.sql'].map((path) => ({ path, proof: SQL, label: 'database dump', severity: 'critical' as Severity })),
  ...['/backup.zip', '/site.zip', '/www.zip', '/public_html.zip', '/backup.tar.gz', '/site.tar.gz', '/backup.rar'].map((path) => ({ path, proof: ARCHIVE, label: 'site backup archive', severity: 'critical' as Severity })),
  { path: '/web.config', proof: /<configuration[\s>]/, label: 'IIS configuration', severity: 'high' },
  { path: '/.htaccess', proof: /RewriteEngine|RewriteRule|Require all|Deny from|AuthUserFile/i, label: 'Apache configuration', severity: 'low' },
  { path: '/.DS_Store', proof: /Bud1/, label: 'macOS folder index, which lists file names', severity: 'low' },
  { path: '/phpinfo.php', proof: /phpinfo\(\)|PHP Version \d/, label: 'phpinfo page', severity: 'medium', html: true },
  { path: '/info.php', proof: /phpinfo\(\)|PHP Version \d/, label: 'phpinfo page', severity: 'medium', html: true },
  { path: '/server-status', proof: /Apache Server Status/, label: 'Apache server status', severity: 'medium', html: true },
  { path: '/server-info', proof: /Apache Server Information/, label: 'Apache server information', severity: 'medium', html: true },
  { path: '/nginx_status', proof: /Active connections:/, label: 'nginx status', severity: 'low' },
  { path: '/actuator/env', proof: /"(propertySources|activeProfiles)"/, label: 'Spring Boot environment, often with secrets', severity: 'critical' },
  { path: '/actuator', proof: /"_links"\s*:\s*\{[\s\S]*"(health|env|beans|heapdump)"/, label: 'Spring Boot actuator', severity: 'medium' },
  { path: '/elmah.axd', proof: /Error Log for/, label: 'ELMAH error log', severity: 'high', html: true },
  { path: '/trace.axd', proof: /Application Trace/, label: 'ASP.NET trace log', severity: 'high', html: true },
  { path: '/wp-content/debug.log', proof: PHP_LOG, label: 'WordPress debug log', severity: 'medium' },
  { path: '/storage/logs/laravel.log', proof: /\b(local|production|staging)\.(ERROR|INFO|DEBUG|WARNING)\b/, label: 'Laravel log', severity: 'high' },
  ...['/error_log', '/error.log', '/debug.log', '/logs/error.log', '/log/error.log'].map((path) => ({ path, proof: PHP_LOG, label: 'error log', severity: 'medium' as Severity })),
  { path: '/.idea/workspace.xml', proof: /<project version/, label: 'IDE workspace file', severity: 'low' },
  { path: '/docker-compose.yml', proof: /^services:/m, label: 'Docker Compose file', severity: 'medium' },
  { path: '/Dockerfile', proof: /^FROM\s+\S+/m, label: 'Dockerfile', severity: 'low' },
  { path: '/.gitlab-ci.yml', proof: /^(stages|variables|[\w-]+):\s*$[\s\S]*script:/m, label: 'CI pipeline file', severity: 'low' },
  { path: '/package.json', proof: /"(dependencies|devDependencies)"\s*:/, label: 'package.json', severity: 'low' },
  { path: '/composer.json', proof: /"require"\s*:/, label: 'composer.json', severity: 'low' },
  { path: '/package-lock.json', proof: /"lockfileVersion"/, label: 'npm lockfile with exact versions', severity: 'medium', lock: true },
  { path: '/yarn.lock', proof: /yarn lockfile|__metadata:/, label: 'Yarn lockfile with exact versions', severity: 'medium', lock: true },
  { path: '/pnpm-lock.yaml', proof: /^lockfileVersion:/m, label: 'pnpm lockfile with exact versions', severity: 'medium', lock: true },
  { path: '/composer.lock', proof: /"content-hash"/, label: 'Composer lockfile with exact versions', severity: 'medium', lock: true },
  { path: '/Gemfile.lock', proof: /^GEM$/m, label: 'Gemfile.lock with exact versions', severity: 'medium', lock: true },
  { path: '/Pipfile.lock', proof: /"_meta"/, label: 'Pipfile.lock with exact versions', severity: 'medium', lock: true },
  { path: '/poetry.lock', proof: /^\[\[package\]\]/m, label: 'poetry.lock with exact versions', severity: 'medium', lock: true },
  { path: '/requirements.txt', proof: /^[A-Za-z0-9_.-]+==\d/m, label: 'requirements.txt with exact versions', severity: 'low', lock: true },
  ...['/phpmyadmin/', '/phpMyAdmin/', '/pma/', '/myadmin/', '/dbadmin/'].map((path) => ({ path, proof: /phpMyAdmin|pma_username|pmahomme/, label: 'phpMyAdmin', severity: 'high' as Severity, rule: 'admin' as RuleKey, html: true })),
  { path: '/adminer.php', proof: /adminer\.org|<title>[^<]*Adminer/i, label: 'Adminer', severity: 'high', rule: 'admin', html: true },
  ...['/swagger.json', '/openapi.json', '/v2/api-docs', '/v3/api-docs', '/swagger/v1/swagger.json', '/api/swagger.json', '/api/openapi.json', '/api-docs'].map((path) => ({ path, proof: /"(swagger|openapi)"\s*:\s*"\d/, label: 'API specification', severity: 'low' as Severity, rule: 'apiDocs' as RuleKey })),
  ...['/swagger-ui.html', '/swagger-ui/', '/swagger/', '/api/docs', '/docs', '/redoc'].map((path) => ({ path, proof: /swagger-ui|<redoc|redoc\.standalone/i, label: 'API documentation page', severity: 'low' as Severity, rule: 'apiDocs' as RuleKey, html: true })),
  { path: '/crossdomain.xml', proof: /allow-access-from\s+domain=["']\*["']/, label: 'crossdomain.xml', severity: 'medium', rule: 'crossdomain', html: true },
  { path: '/clientaccesspolicy.xml', proof: /<domain\s+uri=["']\*["']/, label: 'clientaccesspolicy.xml', severity: 'medium', rule: 'crossdomain', html: true },
];

/** Requests every probe path. Exposed lockfiles are parsed so their exact versions can be looked up. */
export async function runProbes(state: LiveState): Promise<void> {
  const lockfiles: Array<{ path: string; text: string }> = [];
  const reportedRule = new Set<string>();
  await mapLimit(PROBES, 4, async (probe) => {
    const res = await get(new URL(probe.path, state.site.origin).href, { redirect: 'manual' });
    if (!res || res.status !== 200 || (!probe.html && isHtml(res))) {
      await res?.body?.cancel().catch(() => undefined);
      return;
    }
    const bytes = await readBytes(res, probe.lock ? 10_000_000 : 300_000);
    const text = ARCHIVE === probe.proof ? bytes.subarray(0, 8).toString('latin1') : bytes.toString('utf8');
    if (!probe.proof.test(text)) return;
    const rule = RULES[probe.rule ?? 'exposed'];
    // Several paths can prove the same thing, such as two API spec URLs; one finding each is enough.
    if (probe.rule && reportedRule.has(`${probe.rule}:${probe.label}`)) return;
    reportedRule.add(`${probe.rule}:${probe.label}`);
    let message = `${probe.label} is public at ${probe.path}.`;
    if (probe.rule === 'apiDocs' && !probe.html) {
      let paths = 0;
      try {
        paths = Object.keys((JSON.parse(text) as any)?.paths ?? {}).length;
      } catch {
        // A cut-off spec still proves the file is public.
      }
      if (paths) message = `${probe.label} is public at ${probe.path} and lists ${paths} endpoint path(s).`;
    }
    state.report(rule.id, { key: probe.path, severity: probe.severity, message });
    if (probe.lock) lockfiles.push({ path: probe.path.slice(1), text });
  });
  if (lockfiles.length) {
    const found = parseLockfiles({ matching: (re) => lockfiles.filter((f) => re.test(f.path)) });
    state.packages.push(...found.map((p) => ({ ...p, file: '' })));
  }
}

const ERROR_SIGNS: Array<[RegExp, string]> = [
  [/<b>(?:Warning|Fatal error|Notice|Parse error|Deprecated)<\/b>:[^\n]{0,300} in <b>[^<]+<\/b> on line <b>\d+/, 'PHP error with a server file path'],
  [/(?:Warning|Fatal error|Parse error): [^\n]{0,200} in \/[\w/.-]+\.php on line \d+/, 'PHP error with a server file path'],
  [/You're seeing this error because you have <code>DEBUG = True<\/code>/, 'Django debug page'],
  [/Traceback \(most recent call last\)/, 'Python stack trace'],
  // One backslash in HTML, two when the trace is JSON-escaped.
  [/Whoops! There was an error|vendor\/laravel\/framework|Illuminate\\{1,2}[A-Z]/, 'Laravel debug page'],
  [/Symfony\\{1,2}Component\\{1,2}|sf-toolbar|Symfony Exception/, 'Symfony debug page'],
  [/Server Error in '\/' Application|ASP\.NET is configured to show verbose error messages/, 'ASP.NET detailed error page'],
  [/\bat [\w.$]+\([\w]+\.java:\d+\)/, 'Java stack trace'],
  [/Action Controller: Exception caught/, 'Rails debug page'],
  [/SQLSTATE\[\w+\]|You have an error in your SQL syntax|ORA-\d{5}:|pg_query\(\):|Unclosed quotation mark after the character string/, 'database error message'],
  [/<title>Error: [^<]*<\/title>[\s\S]{0,400}<pre>[\s\S]{0,200}\bat \S+ \(\/[\w/.-]+\.js:\d+:\d+\)/, 'Node.js stack trace'],
];

/** Looks for debug pages and stack traces in a response body. */
export function checkErrorPage(state: LiveState, text: string, where: string): void {
  for (const [re, label] of ERROR_SIGNS) {
    if (re.test(text) && once(state, `errors:${label}`)) {
      state.report(RULES.errors.id, { key: label, message: `${where} shows a ${label}.` });
    }
  }
}

export async function checkErrorPages(state: LiveState): Promise<void> {
  const stamp = Date.now();
  for (const path of [`/alil-launch-check-${stamp}.php`, `/alil-launch-check-${stamp}.aspx`, `/alil-launch-check-${stamp}/`]) {
    const res = await get(new URL(path, state.site.origin).href);
    if (res) checkErrorPage(state, await readText(res, 300_000), 'An unknown URL');
  }
}

export function checkCsp(state: LiveState, headers: Headers): void {
  const csp = headers.get('content-security-policy');
  if (!csp) return;
  const directives = new Map(csp.split(';').map((d) => d.trim().split(/\s+/)).filter((d) => d[0]).map(([name, ...values]) => [name.toLowerCase(), values]));
  const scripts = directives.get('script-src') ?? directives.get('default-src');
  if (!scripts) {
    state.report(RULES.weakCsp.id, { key: 'script-src', message: 'The policy sets neither `script-src` nor `default-src`, so it does not limit scripts.' });
    return;
  }
  const strict = scripts.some((v) => /^'(nonce-|sha(256|384|512)-|strict-dynamic)/.test(v));
  const issues = [
    scripts.includes("'unsafe-inline'") && !strict ? "`'unsafe-inline'` lets any injected inline script run" : '',
    scripts.includes("'unsafe-eval'") ? "`'unsafe-eval'` allows eval()" : '',
    scripts.some((v) => ['*', 'http:', 'https:', 'data:'].includes(v)) ? `\`${scripts.find((v) => ['*', 'http:', 'https:', 'data:'].includes(v))}\` allows scripts from anywhere` : '',
  ].filter(Boolean);
  if (issues.length) state.report(RULES.weakCsp.id, { key: 'script-src', message: `script-src: ${issues.join('; ')}.` });
}

export function checkHsts(state: LiveState, headers: Headers): void {
  const hsts = headers.get('strict-transport-security');
  const age = Number(/max-age=["']?(\d+)/i.exec(hsts ?? '')?.[1] ?? NaN);
  if (hsts && Number.isFinite(age) && age < 15_552_000) {
    state.report(RULES.weakHsts.id, { message: `\`max-age\` is ${age} seconds (${Math.round(age / 86400)} days).` });
  }
}

/** Sends a foreign Origin and checks whether the server trusts it. */
export async function checkCors(state: LiveState, paths: string[]): Promise<void> {
  const evil = 'https://alil-launch-cors-check.example';
  const trusting: Array<{ path: string; origin: string; credentials: boolean }> = [];
  // WordPress reflects any Origin on its REST API by design, but cookie logins there also need a
  // nonce another site cannot get, so it is not a leak.
  for (const path of paths.filter((p) => !(state.wordpress && p.startsWith('/wp-json')))) {
    for (const origin of [evil, 'null']) {
      const res = await get(new URL(path, state.site.origin).href, { headers: { origin } });
      await res?.body?.cancel().catch(() => undefined);
      if (res?.headers.get('access-control-allow-origin') !== origin) continue;
      trusting.push({ path, origin, credentials: res.headers.get('access-control-allow-credentials') === 'true' });
      break;
    }
  }
  if (!trusting.length) return;
  const credentials = trusting.some((t) => t.credentials);
  const first = trusting.find((t) => t.credentials) ?? trusting[0];
  state.report(RULES.cors.id, {
    key: 'cors',
    severity: credentials ? 'high' : 'medium',
    message: `${trusting.map((t) => t.path).join(', ')} ${trusting.length === 1 ? 'answers' : 'answer'} any Origin, for example \`${first.origin}\`, with a matching \`access-control-allow-origin\`${credentials ? ' and allow credentials, so other sites can read logged-in responses' : ''}.`,
  });
}

function acceptsTls(host: string, port: number, version: SecureVersion): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      // Only the agreed protocol is read and nothing is sent, so an invalid certificate must not hide an old TLS version.
      // alil-launch-ignore
      const socket = connect({ host, port, servername: host, minVersion: version, maxVersion: version, ciphers: 'DEFAULT:@SECLEVEL=0', rejectUnauthorized: false, timeout: 8000 }, () => {
        const agreed = socket.getProtocol();
        socket.end();
        resolve(agreed === version);
      });
      socket.on('error', () => resolve(false));
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
    } catch {
      resolve(false);
    }
  });
}

export async function checkTlsVersions(state: LiveState): Promise<void> {
  const port = Number(state.site.port) || 443;
  const old = [];
  for (const version of ['TLSv1', 'TLSv1.1'] as SecureVersion[]) {
    if (await acceptsTls(state.site.hostname, port, version)) old.push(version.replace('TLSv', 'TLS '));
  }
  if (old.length) state.report(RULES.oldTls.id, { message: `The server still accepts ${old.join(' and ')}.` });
}

export async function checkGraphql(state: LiveState): Promise<void> {
  const candidates = new Set(['/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql', '/query']);
  for (const path of state.endpoints.keys()) if (/graphql|gql/i.test(path)) candidates.add(path.split('?')[0]);
  const query = encodeURIComponent('{__schema{queryType{name}types{name}}}');
  for (const path of [...candidates].slice(0, 8)) {
    const res = await get(`${new URL(path, state.site.origin).href}?query=${query}`, { headers: { accept: 'application/json' } });
    if (!res?.ok || !/json/.test(res.headers.get('content-type') ?? '')) {
      await res?.body?.cancel().catch(() => undefined);
      continue;
    }
    const body = await res.json().catch(() => null);
    const types = body?.data?.__schema?.types;
    if (Array.isArray(types)) {
      state.report(RULES.graphql.id, { key: path, message: `${path} returns its full schema (${types.length} types) to anyone.` });
      return;
    }
  }
}

export async function checkSecurityTxt(state: LiveState): Promise<void> {
  for (const path of ['/.well-known/security.txt', '/security.txt']) {
    const res = await get(new URL(path, state.site.origin).href);
    if (res?.ok && !isHtml(res) && /^Contact:/im.test(await readText(res, 50_000))) return;
    await res?.body?.cancel().catch(() => undefined);
  }
  state.report(RULES.securityTxt.id);
}
