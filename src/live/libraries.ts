import { createHash } from 'node:crypto';
import type { Severity } from '../types.js';
import { compareVersions, fetchJson } from '../core/util.js';
import type { Hit } from '../vuln/hits.js';

/**
 * Finds front-end libraries and their versions. With --online it uses the Retire.js repository
 * (https://github.com/RetireJS/retire.js, Apache-2.0), which knows ~75 libraries by URL, file name,
 * file content and hash, so versions inside minified bundles are found too. Offline, a short
 * built-in list covers the most common libraries.
 */

export const RETIRE_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json';
const VERSION_PATTERN = '[0-9][0-9.a-z_\\-]+';
const MAX_CONTENT = 3_000_000;

export interface Library {
  name: string;
  version: string;
}

interface Vulnerability {
  below?: string;
  atOrAbove?: string;
  severity?: string;
  identifiers?: { summary?: string; CVE?: string[]; githubID?: string; bug?: string; issue?: string };
}

interface Compiled {
  name: string;
  uri: RegExp[];
  filename: RegExp[];
  content: RegExp[];
  replace: Array<{ re: RegExp; with: string }>;
  hashes: Record<string, string>;
  vulnerabilities: Vulnerability[];
}

export interface Detector {
  source: 'retire' | 'built-in';
  fromUrl(url: string): Library[];
  fromContent(text: string): Library[];
  /** Turns detected libraries into hits for the vulnerability report. */
  hits(found: Map<string, Library & { where: string }>): Hit[];
}

function compile(pattern: string, flags = ''): RegExp | null {
  try {
    return new RegExp(pattern.replace(/§§version§§/g, VERSION_PATTERN), flags);
  } catch {
    return null;
  }
}

const SEVERITY: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

function affects(vuln: Vulnerability, version: string): boolean {
  if (vuln.below && compareVersions(version, vuln.below) >= 0) return false;
  if (vuln.atOrAbove && compareVersions(version, vuln.atOrAbove) < 0) return false;
  return Boolean(vuln.below || vuln.atOrAbove);
}

function toHits(found: Map<string, Library & { where: string }>, vulnsOf: (name: string) => Vulnerability[]): Hit[] {
  const hits: Hit[] = [];
  for (const lib of found.values()) {
    const matched = vulnsOf(lib.name).filter((v) => affects(v, lib.version));
    if (!matched.length) continue;
    const summaries: Record<string, string> = {};
    const severities: Record<string, Severity> = {};
    for (const v of matched) {
      const ids = v.identifiers?.CVE?.length ? v.identifiers.CVE : [v.identifiers?.githubID ?? v.identifiers?.summary ?? `${lib.name} advisory`];
      for (const id of ids) {
        summaries[id] ||= v.identifiers?.summary ?? '';
        severities[id] = SEVERITY[v.severity ?? ''] ?? 'medium';
      }
    }
    const ranked = Object.values(severities).sort((a, b) => ['critical', 'high', 'medium', 'low'].indexOf(a) - ['critical', 'high', 'medium', 'low'].indexOf(b));
    const fixed = matched.map((v) => v.below).filter((v): v is string => Boolean(v)).sort(compareVersions).at(-1) ?? '';
    hits.push({
      name: lib.name,
      version: lib.version,
      file: lib.where,
      key: `${lib.name}@${lib.version}`,
      ids: Object.keys(severities),
      severity: ranked[0] ?? 'medium',
      fixed,
      summaries,
      severities,
    });
  }
  return hits;
}

export async function loadRetire(): Promise<Detector> {
  const repo = await fetchJson<Record<string, any>>(RETIRE_URL, {}, { timeoutMs: 30_000 });
  const libs: Compiled[] = [];
  for (const [name, entry] of Object.entries(repo)) {
    if (name === 'retire-example' || name === 'dont check' || !entry?.extractors) continue;
    const x = entry.extractors;
    const list = (patterns: string[] | undefined, flags = ''): RegExp[] => (patterns ?? []).map((p) => compile(p, flags)).filter((r): r is RegExp => r !== null);
    libs.push({
      name,
      uri: list(x.uri),
      filename: list(x.filename),
      content: list(x.filecontent),
      replace: (x.filecontentreplace ?? []).flatMap((p: string) => {
        const parts = /^\/(.*[^\\])\/([^/]+)\/$/.exec(p);
        const re = parts && compile(parts[1]);
        return re ? [{ re, with: parts![2] }] : [];
      }),
      hashes: x.hashes ?? {},
      vulnerabilities: entry.vulnerabilities ?? [],
    });
  }
  const byName = new Map(libs.map((l) => [l.name, l]));

  return {
    source: 'retire',
    fromUrl(url) {
      const out: Library[] = [];
      const file = url.split(/[?#]/)[0].split('/').pop() ?? '';
      for (const lib of libs) {
        const hit = lib.uri.map((re) => re.exec(url)?.[1]).find(Boolean) ?? lib.filename.map((re) => re.exec(file)?.[1]).find(Boolean);
        if (hit) out.push({ name: lib.name, version: hit });
      }
      return out;
    },
    fromContent(text) {
      const content = text.slice(0, MAX_CONTENT);
      const sha1 = createHash('sha1').update(text).digest('hex');
      const out: Library[] = [];
      for (const lib of libs) {
        let version = lib.hashes[sha1] ?? lib.content.map((re) => re.exec(content)?.[1]).find(Boolean);
        if (!version) {
          for (const { re, with: replacement } of lib.replace) {
            const m = re.exec(content);
            if (m) {
              version = m[0].replace(re, replacement);
              break;
            }
          }
        }
        if (version) out.push({ name: lib.name, version });
      }
      return out;
    },
    hits: (found) => toHits(found, (name) => byName.get(name)?.vulnerabilities ?? []),
  };
}

/** Offline fallback: the libraries most often found outdated on live sites, with their best-known issues. */
const BUILT_IN: Record<string, { url: RegExp[]; content: RegExp[]; vulns: Vulnerability[] }> = {
  jquery: {
    url: [/\/ajax\/libs\/jquery\/(\d+\.\d+\.\d+)\//, /\/jquery[@-](\d+\.\d+\.\d+)(\.slim)?(\.min)?\.js/, /\/wp-includes\/js\/jquery\/jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)/],
    content: [/\/\*!? jQuery v(\d+\.\d+\.\d+)/, /\* jQuery JavaScript Library v(\d+\.\d+\.\d+)/],
    vulns: [{ below: '3.5.0', severity: 'medium', identifiers: { summary: 'XSS in HTML handling', CVE: ['CVE-2020-11022', 'CVE-2020-11023'] } }],
  },
  'jquery-ui': {
    url: [/\/ajax\/libs\/jqueryui\/(\d+\.\d+\.\d+)\//, /code\.jquery\.com\/ui\/(\d+\.\d+\.\d+)\//, /\/jquery-ui[@-](\d+\.\d+\.\d+)/],
    content: [/\/\*! jQuery UI - v(\d+\.\d+\.\d+)/],
    vulns: [{ below: '1.13.2', severity: 'medium', identifiers: { summary: 'XSS in several widgets', CVE: ['CVE-2021-41182', 'CVE-2021-41184', 'CVE-2022-31160'] } }],
  },
  bootstrap: {
    url: [/\/(?:twitter-)?bootstrap[/@](\d+\.\d+\.\d+)\//],
    content: [/\* Bootstrap v(\d+\.\d+\.\d+)/],
    vulns: [
      { below: '3.4.1', severity: 'medium', identifiers: { summary: 'XSS in tooltip and data attributes', CVE: ['CVE-2019-8331', 'CVE-2018-14042'] } },
      { atOrAbove: '4.0.0', below: '4.3.1', severity: 'medium', identifiers: { summary: 'XSS in tooltip and popover', CVE: ['CVE-2019-8331'] } },
    ],
  },
  angularjs: {
    url: [/\/angular\.js\/(\d+\.\d+\.\d+)\//, /\/angular@(1\.\d+\.\d+)\//],
    content: [/@license AngularJS v(\d+\.\d+\.\d+)/],
    vulns: [{ below: '2.0.0', severity: 'medium', identifiers: { summary: 'AngularJS reached end of life in 2021 and has unpatched XSS and ReDoS issues', CVE: ['CVE-2022-25869', 'CVE-2023-26116'] } }],
  },
  lodash: {
    url: [/\/lodash\.js\/(\d+\.\d+\.\d+)\//, /\/lodash@(\d+\.\d+\.\d+)\//],
    content: [],
    vulns: [{ below: '4.17.21', severity: 'high', identifiers: { summary: 'prototype pollution and command injection', CVE: ['CVE-2020-8203', 'CVE-2021-23337'] } }],
  },
  'moment.js': {
    url: [/\/moment\.js\/(\d+\.\d+\.\d+)\//, /\/moment@(\d+\.\d+\.\d+)\//],
    content: [/\/\/! version : (\d+\.\d+\.\d+)[\s\S]{0,80}momentjs\.com/],
    vulns: [{ below: '2.29.4', severity: 'high', identifiers: { summary: 'ReDoS in date parsing', CVE: ['CVE-2022-31129'] } }],
  },
  handlebars: {
    url: [/\/handlebars\.js\/(\d+\.\d+\.\d+)\//, /\/handlebars@(\d+\.\d+\.\d+)\//],
    content: [/handlebars v(\d+\.\d+\.\d+)/i],
    vulns: [{ below: '4.7.7', severity: 'high', identifiers: { summary: 'code execution through templates', CVE: ['CVE-2021-23369', 'CVE-2021-23383'] } }],
  },
  DOMPurify: {
    url: [/\/dompurify\/(\d+\.\d+\.\d+)\//, /\/dompurify@(\d+\.\d+\.\d+)\//],
    content: [/@license DOMPurify (\d+\.\d+\.\d+)/],
    vulns: [{ below: '2.5.4', severity: 'medium', identifiers: { summary: 'sanitizer bypasses', CVE: ['CVE-2024-45801'] } }],
  },
};

export const builtInDetector: Detector = {
  source: 'built-in',
  fromUrl(url) {
    return Object.entries(BUILT_IN).flatMap(([name, lib]) => {
      const version = lib.url.map((re) => re.exec(url)?.[1]).find(Boolean);
      return version ? [{ name, version }] : [];
    });
  },
  fromContent(text) {
    const head = text.slice(0, 20_000);
    return Object.entries(BUILT_IN).flatMap(([name, lib]) => {
      const version = lib.content.map((re) => re.exec(head)?.[1]).find(Boolean);
      return version ? [{ name, version }] : [];
    });
  },
  hits: (found) => toHits(found, (name) => BUILT_IN[name]?.vulns ?? []),
};
