import type { ScanContext } from '../types.js';

const USAGE = [
  /process\.env\.([A-Z][A-Z0-9_]+)/g,
  /process\.env\[["']([A-Z][A-Z0-9_]+)["']\]/g,
  /import\.meta\.env\.([A-Z][A-Z0-9_]+)/g,
  /os\.environ(?:\.get)?[[(]\s*["']([A-Z][A-Z0-9_]+)["']/g,
  /os\.(?:getenv|Getenv)\(\s*["']([A-Z][A-Z0-9_]+)["']/g,
  /\bgetenv\(\s*["']([A-Z][A-Z0-9_]+)["']/g,
  /\bENV\[\s*["']([A-Z][A-Z0-9_]+)["']/g,
  /std::env::var\(\s*"([A-Z][A-Z0-9_]+)"/g,
];

const BUILT_IN = new Set([
  'NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'HOME', 'PATH', 'PWD', 'USER', 'CI', 'TZ', 'LANG', 'SHELL', 'TEMP', 'TMP',
  'TMPDIR', 'DEBUG', 'BASE_URL', 'MODE', 'DEV', 'PROD', 'SSR', 'VERCEL', 'VERCEL_ENV', 'VERCEL_URL', 'NETLIFY',
  'GITHUB_ACTIONS', 'GITHUB_TOKEN', 'RENDER', 'RAILWAY_ENVIRONMENT', 'NO_COLOR', 'FORCE_COLOR',
]);

const CODE = /\.(m?[jt]sx?|cjs|vue|svelte|astro|py|rb|go|rs|php)$/;
export const ENV_TEMPLATE = /(^|\/)\.env\.(example|sample|template|dist|defaults)$/i;

/** Environment variables the code reads, with where each one was first seen. */
export function usedEnvVars(ctx: Pick<ScanContext, 'matching'>): Map<string, { file: string; line: number }> {
  const used = new Map<string, { file: string; line: number }>();
  for (const { path, text } of ctx.matching(CODE)) {
    for (const re of USAGE) {
      re.lastIndex = 0;
      for (const match of text.matchAll(re)) {
        const name = match[1];
        if (BUILT_IN.has(name) || used.has(name)) continue;
        used.set(name, { file: path, line: text.slice(0, match.index).split('\n').length });
      }
    }
  }
  return used;
}

export function documentedEnvVars(ctx: Pick<ScanContext, 'matching'>): Set<string> {
  const names = new Set<string>();
  for (const { text } of ctx.matching(/(^|\/)\.env\.(example|sample|template|dist|defaults)$|(^|\/)(docker-)?compose[^/]*\.ya?ml$/i)) {
    for (const match of text.matchAll(/^\s*(?:-\s*)?(?:export\s+)?([A-Z][A-Z0-9_]+)\s*[=:]/gm)) names.add(match[1]);
  }
  for (const { text } of ctx.matching(/^README[^/]*$/i)) {
    for (const match of text.matchAll(/`([A-Z][A-Z0-9_]{2,})`/g)) names.add(match[1]);
  }
  return names;
}
