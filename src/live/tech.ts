import { product } from '../rules/platforms.js';
import { RULES } from './rules.js';
import { addTech, type LiveState } from './state.js';

/** Server software the NVD tracks by CPE. Some products moved vendor, so both names are asked. */
const SERVER_CPES: Record<string, { label: string; cpes: Array<[string, string]> }> = {
  nginx: { label: 'nginx', cpes: [['f5', 'nginx'], ['nginx', 'nginx']] },
  apache: { label: 'Apache HTTP Server', cpes: [['apache', 'http_server']] },
  php: { label: 'PHP', cpes: [['php', 'php']] },
  openssl: { label: 'OpenSSL', cpes: [['openssl', 'openssl']] },
  'microsoft-iis': { label: 'Microsoft IIS', cpes: [['microsoft', 'internet_information_services']] },
  openresty: { label: 'OpenResty', cpes: [['openresty', 'openresty']] },
  lighttpd: { label: 'lighttpd', cpes: [['lighttpd', 'lighttpd']] },
  'apache-coyote': { label: 'Apache Tomcat', cpes: [['apache', 'tomcat']] },
};

export const SERVER_LABELS = new Set(Object.values(SERVER_CPES).map((s) => s.label));

const COOKIE_TECH: Array<[RegExp, string]> = [
  [/^laravel_session$/i, 'Laravel'],
  [/^csrftoken$/i, 'Django'],
  [/^PHPSESSID$/i, 'PHP'],
  [/^JSESSIONID$/i, 'Java servlet container'],
  [/^(ASP\.NET_SessionId|\.AspNetCore\.)/i, 'ASP.NET'],
  [/^ci_session$/i, 'CodeIgniter'],
  [/^connect\.sid$/i, 'Express'],
  [/^_shopify/i, 'Shopify'],
  [/^wordpress_|^wp-settings/i, 'WordPress'],
  [/^(SESS|SSESS)[0-9a-f]{32}$/, 'Drupal'],
];

const HTML_TECH: Array<[RegExp, string]> = [
  [/id=["']__NEXT_DATA__["']|\/_next\/static\//, 'Next.js'],
  [/window\.__NUXT__|\/_nuxt\//, 'Nuxt'],
  [/\/sites\/(default|all)\/(files|themes|modules)\/|Drupal\.settings|data-drupal-/, 'Drupal'],
  [/\/media\/(system|jui)\/js\/|Joomla!/, 'Joomla'],
  [/\/wp-content\/|\/wp-includes\//, 'WordPress'],
  [/cdn\.shopify\.com/, 'Shopify'],
  [/static\.wixstatic\.com/, 'Wix'],
  [/static1\.squarespace\.com/, 'Squarespace'],
  [/\/typo3(conf|temp)\//, 'TYPO3'],
  [/wire:id=|livewire/i, 'Laravel Livewire'],
  [/data-turbo|turbolinks/i, 'Ruby on Rails (Turbo)'],
  [/__VIEWSTATE/, 'ASP.NET Web Forms'],
  [/<div[^>]+id=["']root["'][^>]*><\/div>|data-reactroot/, 'React'],
  [/<div[^>]+id=["']app["'][^>]*><\/div>|data-v-[0-9a-f]{8}/, 'Vue'],
  [/\/static\/js\/main\.[0-9a-f]{8}\.js/, 'Create React App'],
  [/\/@vite\/client|\/assets\/index-[\w-]{8}\.js/, 'Vite'],
];

function addServer(state: LiveState, product_: string, version: string, source: string): void {
  const known = SERVER_CPES[product_.toLowerCase()];
  addTech(state, known?.label ?? product_, version, source);
  if (!known || !/^\d+(\.\d+)+/.test(version)) return;
  const clean = /^\d+(\.\d+)+/.exec(version)![0];
  if (state.components.some((c) => c.label === known.label)) return;
  state.components.push({ label: known.label, version: clean, file: '', queries: known.cpes.map(([vendor, name]) => product(vendor, name, clean)) });
}

/** Reads the stack from a response's headers. */
export function fingerprintHeaders(state: LiveState, headers: Headers): void {
  for (const name of ['server', 'x-powered-by']) {
    const value = headers.get(name);
    if (!value) continue;
    const tokens = [...value.matchAll(/([A-Za-z][\w.-]*)\/(\d+(?:\.\d+)+[a-z]?)/g)];
    for (const [, prod, version] of tokens) addServer(state, prod, version, `\`${name}\` header`);
    if (!tokens.length) addTech(state, value.split(/[\s/;,(]/)[0], undefined, `\`${name}\` header`);
  }
  const aspnet = headers.get('x-aspnet-version') ?? headers.get('x-aspnetmvc-version');
  if (aspnet) addTech(state, 'ASP.NET', aspnet, '`x-aspnet-version` header');
  const generator = headers.get('x-generator');
  if (generator) addTech(state, generator.split('(')[0].trim(), undefined, '`x-generator` header');
  if (headers.has('x-drupal-cache') || headers.has('x-drupal-dynamic-cache')) addTech(state, 'Drupal', undefined, 'Drupal cache header');
  if (headers.has('cf-ray')) addTech(state, 'Cloudflare', undefined, '`cf-ray` header');
  if (headers.has('x-vercel-id')) addTech(state, 'Vercel', undefined, '`x-vercel-id` header');
  if (headers.has('x-amz-cf-id')) addTech(state, 'Amazon CloudFront', undefined, '`x-amz-cf-id` header');
  if (headers.has('x-varnish')) addTech(state, 'Varnish', undefined, '`x-varnish` header');
  for (const cookie of headers.getSetCookie?.() ?? []) {
    const name = cookie.split('=')[0].trim();
    const tech = COOKIE_TECH.find(([re]) => re.test(name));
    if (tech) addTech(state, tech[1], undefined, `\`${name}\` cookie`);
  }
}

/** Reads the stack from page markup. Exact versions found here are queued for CVE lookups. */
export function fingerprintHtml(state: LiveState, html: string): void {
  for (const [re, name] of HTML_TECH) if (re.test(html)) addTech(state, name, undefined, 'page markup');

  const angular = /\bng-version=["'](\d+\.\d+\.\d+)["']/.exec(html)?.[1];
  if (angular) {
    addTech(state, 'Angular', angular, '`ng-version` attribute');
    if (!state.packages.some((p) => p.name === '@angular/core')) state.packages.push({ name: '@angular/core', version: angular, ecosystem: 'npm', file: '' });
  }
  const drupal = /\/core\/misc\/drupal(?:\.init)?\.js\?v=(\d+\.\d+\.\d+)/.exec(html)?.[1];
  if (drupal) {
    addTech(state, 'Drupal', drupal, 'core script version');
    if (!state.packages.some((p) => p.name === 'drupal/core')) state.packages.push({ name: 'drupal/core', version: drupal, ecosystem: 'Packagist', file: '' });
  }
  const joomla = /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!? (\d+\.\d+(?:\.\d+)?)/i.exec(html)?.[1];
  if (joomla) {
    addTech(state, 'Joomla', joomla, 'generator tag');
    if (!state.components.some((c) => c.label === 'Joomla')) state.components.push({ label: 'Joomla', version: joomla, file: '', queries: [product('joomla', 'joomla\\!', joomla)] });
  }
}

export function reportTech(state: LiveState): void {
  for (const tech of state.tech.values()) {
    state.report(RULES.tech.id, { key: tech.name.toLowerCase(), message: `${tech.name}${tech.version ? ` ${tech.version}` : ''} (from the ${tech.source}).` });
  }
}
