import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { GitInfo } from '../types.js';
import { isIgnored, parseIgnore, type IgnoreRule } from './ignore.js';

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 100_000;

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'vendor', 'bower_components', 'dist', 'build', 'out', 'target',
  '.next', '.nuxt', '.svelte-kit', '.output', '.turbo', '.vercel', '.netlify', '.cache', '.parcel-cache',
  'coverage', '__pycache__', '.venv', 'venv', 'env', '.tox', '.mypy_cache', '.pytest_cache', '.gradle',
  '.idea', '.vscode', '.terraform', 'Pods', 'DerivedData', '.angular',
]);

const SKIP_EXT = /\.(png|jpe?g|gif|webp|avif|ico|bmp|tiff?|psd|eps|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|ear|class|exe|dll|so|dylib|a|o|bin|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|ogg|wav|flac|ibd|frm|myd|myi|wt|rdb|sqlite3?|db|pyc|map|bcmap)$/i;

export function runGit(root: string, args: string[]): string | null {
  try {
    return execFileSync('git', args, {
      cwd: root,
      encoding: 'utf8',
      maxBuffer: 512 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
}

export function gitInfo(root: string): GitInfo {
  const out = runGit(root, ['ls-files', '-z']);
  if (out === null) return { isRepo: false, tracked: new Set() };
  return { isRepo: true, tracked: new Set(out.split('\0').filter(Boolean)) };
}

function isSkippedPath(path: string): boolean {
  const parts = path.split('/');
  if (parts.slice(0, -1).some((part) => SKIP_DIRS.has(part))) return true;
  return SKIP_EXT.test(path) || /\.min\.(js|css)$/i.test(path);
}

function walk(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string, inherited: IgnoreRule[]): void => {
    if (out.length >= MAX_FILES) return;
    let rules = inherited;
    try {
      rules = [...inherited, ...parseIgnore(readFileSync(join(dir, '.gitignore'), 'utf8'))];
    } catch {
      /* no .gitignore here */
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const full = join(dir, entry.name);
      const rel = relative(root, full).split(sep).join('/');
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || isIgnored(rel, true, rules)) continue;
        visit(full, rules);
      } else if (entry.isFile() && !isIgnored(rel, false, rules)) {
        out.push(rel);
      }
    }
  };
  visit(root, []);
  return out;
}

export function listFiles(root: string, git: GitInfo, staged = false): { files: string[]; allPaths: string[] } {
  let allPaths: string[];
  if (staged && git.isRepo) {
    allPaths = (runGit(root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']) ?? '')
      .split('\0')
      .filter(Boolean);
  } else if (git.isRepo) {
    allPaths = (runGit(root, ['ls-files', '-co', '--exclude-standard', '-z']) ?? '').split('\0').filter(Boolean);
  } else {
    allPaths = walk(root);
  }
  return { files: allPaths.filter((p) => !isSkippedPath(p)).slice(0, MAX_FILES), allPaths };
}

export function readText(path: string, maxBytes = MAX_FILE_BYTES): string | null {
  try {
    if (statSync(path).size > maxBytes) return null;
    const buffer = readFileSync(path);
    if (buffer.subarray(0, 8000).includes(0)) return null;
    return buffer.toString('utf8');
  } catch {
    return null;
  }
}
