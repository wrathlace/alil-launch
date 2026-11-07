import { connect } from 'node:tls';
import type { Checker, RuleMeta, Reporter } from '../types.js';
import { mapLimit } from '../core/util.js';

const rule = (id: string, title: string, severity: RuleMeta['severity'], description: string, fix: string): RuleMeta => ({
  id, title, severity, description, fix, category: 'live',
});

const RULES = {
  unreachable: rule('live/unreachable', 'Site could not be reached', 'critical', 'The URL did not return a successful response.', 'Check DNS, TLS and that the app is running.'),
  noHttps: rule('live/no-https', 'Site is not served over HTTPS', 'critical', 'Traffic can be read and changed in transit.', 'Serve the site over HTTPS.'),
  noRedirect: rule('live/http-not-redirected', 'HTTP does not redirect to HTTPS', 'high', 'Visitors can stay on an unencrypted connection.', 'Redirect all HTTP traffic to HTTPS.'),
  cert: rule('live/certificate-expiring', 'TLS certificate expires soon', 'high', 'When the certificate expires, browsers block the site.', 'Renew the certificate and automate renewal.'),
  exposed: rule('live/sensitive-file-exposed', 'Sensitive file publicly accessible', 'critical', 'A file that should be private can be downloaded by anyone.', 'Block the path at your web server and rotate anything it contained.'),
  header: rule('live/missing-security-header', 'Security header missing', 'medium', 'The response lacks a recommended browser protection.', 'Set the header in your app, web server or CDN.'),
  server: rule('live/version-disclosed', 'Server version disclosed', 'low', 'Exact versions help attackers choose an exploit.', 'Remove version details from response headers.'),
  cookie: rule('live/insecure-cookie', 'Cookie missing security flags', 'medium', 'Cookies without these flags are easier to steal.', 'Set Secure, HttpOnly and SameSite.'),
  soft404: rule('live/soft-404', 'Missing pages return 200', 'low', 'Search engines index error pages and monitors miss broken links.', 'Return status 404 for unknown URLs.'),
  robots: rule('live/robots-blocks-all', 'robots.txt blocks all crawlers', 'high', 'Often left over from staging, this removes the site from search results.', 'Allow crawling on your production site.'),
  meta: rule('live/missing-page-metadata', 'Missing page metadata', 'low', 'Search and link previews will look poor.', 'Add a title, description and Open Graph tags.'),
  slow: rule('live/slow-response', 'Slow first response', 'medium', 'The home page took over 2 seconds to respond.', 'Add caching or look into slow server work.'),
};

/** Each probe confirms content, so apps that answer every path with 200 are not flagged. */
const PROBES: Array<{ path: string; proof: RegExp; label: string }> = [
  { path: '/.env', proof: /^\s*[A-Z][A-Z0-9_]*\s*=/m, label: 'environment file' },
  { path: '/.git/config', proof: /\[core\]/, label: 'git config' },
  { path: '/.git/HEAD', proof: /^ref: refs\//, label: 'git metadata' },
  { path: '/backup.sql', proof: /INSERT INTO|CREATE TABLE/i, label: 'database backup' },
  { path: '/dump.sql', proof: /INSERT INTO|CREATE TABLE/i, label: 'database dump' },
  { path: '/.aws/credentials', proof: /aws_access_key_id/i, label: 'AWS credentials' },
  { path: '/wp-config.php.bak', proof: /DB_PASSWORD/, label: 'WordPress config backup' },
  { path: '/phpinfo.php', proof: /phpinfo\(\)|PHP Version/, label: 'phpinfo page' },
  { path: '/.DS_Store', proof: /Bud1/, label: 'directory listing' },
];

const HEADERS: Array<{ name: string; severity: RuleMeta['severity'] }> = [
  { name: 'strict-transport-security', severity: 'high' },
  { name: 'content-security-policy', severity: 'medium' },
  { name: 'x-content-type-options', severity: 'low' },
  { name: 'referrer-policy', severity: 'low' },
];

async function get(url: string, redirect: RequestRedirect = 'follow'): Promise<Response | null> {
  try {
    return await fetch(url, { redirect, signal: AbortSignal.timeout(15_000), headers: { 'user-agent': 'alil-launch' } });
  } catch {
    return null;
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

async function checkUrl(input: string, report: Reporter): Promise<void> {
  const target = new URL(/^https?:\/\//.test(input) ? input : `https://${input}`);
  const started = Date.now();
  const res = await get(target.href);
  const elapsed = Date.now() - started;
  if (!res || !res.ok) {
    report(RULES.unreachable.id, { message: res ? `${target.href} returned ${res.status}.` : `${target.href} did not respond.` });
    return;
  }
  const html = (res.headers.get('content-type') ?? '').includes('text/html') ? await res.text().catch(() => '') : '';
  const final = new URL(res.url || target.href);
  const local = /^(localhost|127\.|0\.0\.0\.0|\[::1\])/.test(final.hostname);
  if (elapsed > 2000) report(RULES.slow.id, { message: `The first response took ${elapsed} ms.` });

  if (final.protocol !== 'https:') {
    if (!local) report(RULES.noHttps.id);
  } else {
    const days = await certificateDays(final.hostname, Number(final.port) || 443);
    if (days !== null && days < 21) report(RULES.cert.id, { severity: days < 7 ? 'critical' : 'high', message: `The certificate expires in ${days} day(s).` });
    const plain = await get(`http://${final.host}${final.pathname}`, 'manual');
    const location = plain?.headers.get('location') ?? '';
    if (plain && !(plain.status >= 300 && plain.status < 400 && location.startsWith('https:'))) report(RULES.noRedirect.id);
  }

  for (const { name, severity } of HEADERS) {
    if (name === 'strict-transport-security' && final.protocol !== 'https:') continue;
    if (!res.headers.has(name)) report(RULES.header.id, { key: name, severity, message: `\`${name}\` is not set.` });
  }
  if (!res.headers.has('x-frame-options') && !/frame-ancestors/.test(res.headers.get('content-security-policy') ?? '')) {
    report(RULES.header.id, { key: 'framing', severity: 'low', message: 'No clickjacking protection (`x-frame-options` or `frame-ancestors`).' });
  }
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version']) {
    const value = res.headers.get(name);
    if (value && (/\d/.test(value) || name === 'x-powered-by')) report(RULES.server.id, { key: name, message: `\`${name}: ${value}\`` });
  }
  for (const cookie of res.headers.getSetCookie?.() ?? []) {
    const name = cookie.split('=')[0];
    const missing = [
      final.protocol === 'https:' && !/;\s*secure/i.test(cookie) ? 'Secure' : '',
      !/;\s*httponly/i.test(cookie) ? 'HttpOnly' : '',
      !/;\s*samesite/i.test(cookie) ? 'SameSite' : '',
    ].filter(Boolean);
    if (missing.length) report(RULES.cookie.id, { key: name, message: `Cookie \`${name}\` is missing ${missing.join(', ')}.` });
  }

  await mapLimit(PROBES, 3, async ({ path, proof, label }) => {
    const probe = await get(new URL(path, final.origin).href, 'manual');
    if (!probe || probe.status !== 200) return;
    const type = probe.headers.get('content-type') ?? '';
    const body = (await probe.text().catch(() => '')).slice(0, 2000);
    if ((!/text\/html/.test(type) || path === '/phpinfo.php') && proof.test(body)) {
      report(RULES.exposed.id, { key: path, message: `${label} is public at ${path}.` });
    }
  });

  const missing = await get(new URL(`/alil-launch-check-${Date.now()}`, final.origin).href);
  if (missing?.status === 200) report(RULES.soft404.id);
  const robots = await get(new URL('/robots.txt', final.origin).href);
  if (robots?.ok && /user-agent:\s*\*\s*\n\s*disallow:\s*\/\s*$/im.test(await robots.text())) report(RULES.robots.id);

  if (html) {
    const absent = [
      /<title>[^<]+<\/title>/i.test(html) ? '' : 'title',
      /<meta[^>]+name=["']description["']/i.test(html) ? '' : 'meta description',
      /<meta[^>]+property=["']og:/i.test(html) ? '' : 'Open Graph tags',
    ].filter(Boolean);
    if (absent.length) report(RULES.meta.id, { message: `Missing: ${absent.join(', ')}.` });
  }
}

export const liveChecker: Checker = {
  name: 'live',
  rules: Object.values(RULES),
  async run(ctx, report) {
    if (ctx.options.url) await checkUrl(ctx.options.url, report);
  },
};
