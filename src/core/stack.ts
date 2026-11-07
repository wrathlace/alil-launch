import type { Stack } from '../types.js';
import { parseJson } from './util.js';

interface StackInput {
  files: string[];
  read(path: string): string | null;
}

const WEB_SERVERS = ['express', 'fastify', 'koa', '@nestjs/core', 'hono', 'next', 'nuxt', '@remix-run/node', 'hapi', '@hapi/hapi', '@sveltejs/kit'];
const FRONTENDS = ['react', 'vue', 'svelte', 'next', 'nuxt', '@angular/core', 'solid-js', 'astro', 'vite'];
const NODE_DBS: Record<string, string> = {
  pg: 'postgres', postgres: 'postgres', mysql: 'mysql', mysql2: 'mysql', mongoose: 'mongodb', mongodb: 'mongodb',
  prisma: 'prisma', '@prisma/client': 'prisma', 'drizzle-orm': 'drizzle', typeorm: 'typeorm', sequelize: 'sequelize',
  knex: 'knex', 'better-sqlite3': 'sqlite', sqlite3: 'sqlite', '@supabase/supabase-js': 'supabase', firebase: 'firebase',
  'firebase-admin': 'firebase',
};

export function detectStack({ files, read }: StackInput): Stack {
  const stack: Stack = {
    languages: [], frameworks: [], databases: [], packageManagers: [],
    isWebServer: false, isFrontend: false, isLibrary: false,
  };
  const add = (list: string[], value: string): void => {
    if (!list.includes(value)) list.push(value);
  };
  const manifests = files.filter((f) => f.split('/').length <= 3);
  const has = (re: RegExp): string[] => manifests.filter((f) => re.test(f));
  const short = (name: string): string => name.replace(/^@[^/]+\//, '').replace(/^core$/, 'angular');

  let rootHasEntry = false;
  for (const path of has(/(^|\/)package\.json$/)) {
    add(stack.languages, 'javascript');
    add(stack.packageManagers, 'npm');
    const pkg = parseJson<any>(read(path));
    if (!pkg) continue;
    const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
    for (const name of Object.keys(deps)) {
      if (WEB_SERVERS.includes(name)) { stack.isWebServer = true; add(stack.frameworks, short(name)); }
      if (FRONTENDS.includes(name)) { stack.isFrontend = true; add(stack.frameworks, short(name)); }
      if (NODE_DBS[name]) add(stack.databases, NODE_DBS[name]);
    }
    if (path === 'package.json' && (pkg.main || pkg.exports || pkg.bin) && !pkg.scripts?.start) rootHasEntry = true;
  }
  stack.isLibrary = rootHasEntry && !stack.isWebServer && !stack.isFrontend;
  if (files.some((f) => /\.tsx?$/.test(f))) add(stack.languages, 'typescript');

  const py = has(/(^|\/)(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py)$/);
  if (py.length) {
    add(stack.languages, 'python');
    add(stack.packageManagers, 'pip');
    const text = py.map((f) => read(f) ?? '').join('\n').toLowerCase();
    for (const fw of ['django', 'flask', 'fastapi']) {
      if (new RegExp(`\\b${fw}\\b`).test(text)) { stack.isWebServer = true; add(stack.frameworks, fw); }
    }
    for (const [dep, db] of [['psycopg', 'postgres'], ['sqlalchemy', 'sqlalchemy'], ['pymongo', 'mongodb'], ['mysqlclient', 'mysql'], ['pymysql', 'mysql'], ['django', 'django-orm']] as const) {
      if (text.includes(dep)) add(stack.databases, db);
    }
  }
  if (has(/(^|\/)go\.mod$/).length) { add(stack.languages, 'go'); add(stack.packageManagers, 'go'); }
  if (has(/(^|\/)Cargo\.toml$/).length) { add(stack.languages, 'rust'); add(stack.packageManagers, 'cargo'); }
  const composer = has(/(^|\/)composer\.json$/);
  if (composer.length) {
    add(stack.languages, 'php');
    add(stack.packageManagers, 'composer');
    const text = composer.map((f) => read(f) ?? '').join('\n');
    for (const fw of ['laravel/framework', 'symfony/symfony', 'symfony/framework-bundle']) {
      if (text.includes(fw)) { stack.isWebServer = true; add(stack.frameworks, fw.split('/')[0]); add(stack.databases, 'orm'); }
    }
  }
  // A CMS is often installed under a web root, deeper than the manifests above.
  if (files.some((f) => /(^|\/)(wp-includes\/version\.php|wp-config(-sample)?\.php|wp-content\/)/.test(f))) {
    add(stack.languages, 'php'); add(stack.frameworks, 'wordpress'); stack.isWebServer = true;
  }
  if (files.some((f) => /(^|\/)(core\/lib\/Drupal\.php|modules\/contrib\/)/.test(f))) {
    add(stack.languages, 'php'); add(stack.frameworks, 'drupal'); stack.isWebServer = true;
  }
  const gemfile = has(/(^|\/)Gemfile$/);
  if (gemfile.length) {
    add(stack.languages, 'ruby');
    add(stack.packageManagers, 'bundler');
    if (/\brails\b/.test(gemfile.map((f) => read(f) ?? '').join('\n'))) {
      stack.isWebServer = true; add(stack.frameworks, 'rails'); add(stack.databases, 'activerecord');
    }
  }
  if (has(/(^|\/)(pom\.xml|build\.gradle(\.kts)?)$/).length) add(stack.languages, 'java');

  for (const path of files.filter((f) => /(^|\/)(docker-)?compose[^/]*\.ya?ml$/.test(f))) {
    const text = read(path) ?? '';
    for (const [re, db] of [[/image:\s*["']?(?:[\w./-]*\/)?postgres/, 'postgres'], [/image:\s*["']?(?:[\w./-]*\/)?(?:mysql|mariadb)/, 'mysql'], [/image:\s*["']?(?:[\w./-]*\/)?mongo/, 'mongodb']] as const) {
      if (re.test(text)) add(stack.databases, db);
    }
  }
  if (files.some((f) => /(^|\/)supabase\/(config\.toml|migrations\/)/.test(f))) add(stack.databases, 'supabase');
  if (files.some((f) => /(^|\/)schema\.prisma$/.test(f))) add(stack.databases, 'prisma');
  return stack;
}
