import type { Checker, RuleMeta } from '../types.js';
import { documentedEnvVars, usedEnvVars } from '../core/env.js';
import { isCommentLine, isTestPath, lineOf, parseJson } from '../core/util.js';

const rule = (id: string, title: string, severity: RuleMeta['severity'], description: string, fix: string): RuleMeta => ({
  id, title, severity, description, fix, category: 'deployment',
});

const RULES = {
  envIgnored: rule('deploy/env-not-ignored', '.env is not in .gitignore', 'high', 'The next `git add .` could publish your secrets.', 'Add `.env*` to .gitignore. `alil-launch fix` can do this.'),
  envExample: rule('deploy/no-env-example', 'No .env.example', 'medium', 'Nobody can tell which variables a deployment needs.', 'Create one. `alil-launch fix` can generate it from your code.'),
  envUndocumented: rule('deploy/env-var-undocumented', 'Environment variable not documented', 'low', 'A deploy without this variable may fail at runtime.', 'Add it to .env.example.'),
  lockfile: rule('deploy/no-lockfile', 'No dependency lockfile', 'high', 'Each deploy can install different code from the last.', 'Commit your lockfile.'),
  nodeModules: rule('deploy/dependencies-committed', 'Installed dependencies committed', 'medium', 'node_modules in git bloats the repo and can break builds across platforms.', 'Run `git rm -r --cached node_modules` and ignore it.'),
  noCi: rule('deploy/no-ci', 'No CI pipeline', 'medium', 'Nothing stops broken code from being deployed.', 'Add a pipeline that builds and tests every change.'),
  noTests: rule('deploy/no-tests', 'No tests found', 'medium', 'There is no automated way to catch regressions.', 'Add tests for your critical paths.'),
  noStart: rule('deploy/no-start-script', 'No start command', 'medium', 'Hosting platforms look for a start script to boot your app.', 'Add a `start` script to package.json.'),
  noEngines: rule('deploy/runtime-not-pinned', 'Runtime version not pinned', 'low', 'The host may run a different version from yours.', 'Set `engines.node` or add a .nvmrc.'),
  localhost: rule('deploy/hardcoded-localhost', 'Hardcoded localhost URL', 'medium', 'This will fail once the app is deployed.', 'Read the URL from an environment variable.'),
  port: rule('deploy/hardcoded-port', 'Hardcoded server port', 'medium', 'Hosts such as Render, Heroku and Cloud Run assign a port through $PORT.', 'Use `process.env.PORT`, with a fallback for local development.'),
  bindLocal: rule('deploy/binds-to-localhost', 'Server binds to localhost only', 'high', 'The app is unreachable inside a container or platform.', 'Bind to 0.0.0.0, or configure the host through the environment.'),
  dangerousMigrate: rule('deploy/dev-migration-in-production', 'Development migration command in deployment', 'critical', '`prisma db push --accept-data-loss` and `migrate reset` can delete production data.', 'Use `prisma migrate deploy` in production.'),
  autoSync: rule('deploy/schema-auto-sync', 'Schema auto-sync enabled', 'high', 'ORM auto-sync can drop columns and data on boot.', 'Turn it off and use migrations.'),
  shutdown: rule('deploy/no-graceful-shutdown', 'No graceful shutdown', 'low', 'Requests in progress fail on every deploy.', 'Handle SIGTERM and close the server before exiting.'),
  placeholder: rule('deploy/placeholder-content', 'Placeholder content left in the app', 'medium', 'Visitors will see unfinished text.', 'Replace it with real content.'),
};

const LOCK_FILES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock', 'npm-shrinkwrap.json'];
const SOURCE = /\.(m?[jt]sx?|cjs|vue|svelte|py)$/;
const TEST_FILE = /(^|\/)(tests?|__tests__|spec)\/|\.(test|spec)\.[a-z]+$|_test\.(go|py)$|(^|\/)test_[^/]+\.py$/;
const CONFIG_FILE = /(^|\/)(vite|vitest|jest|playwright|cypress|webpack|rollup|next|nuxt|tailwind|postcss|eslint|astro|svelte)\.config\.|(^|\/)scripts?\//;

export const deploymentChecker: Checker = {
  name: 'deployment',
  rules: Object.values(RULES),
  run(ctx, report) {
    const gitignore = ctx.read('.gitignore') ?? '';
    const envFiles = ctx.allPaths.filter((p) => /(^|\/)\.env(\.(local|production|prod|staging|development))?$/.test(p));
    const ignoresEnv = /^\s*\/?(\*\*\/)?\.env(\*|\.\*)?\s*$/m.test(gitignore);
    if (!ignoresEnv && (envFiles.length > 0 || ctx.stack.languages.length > 0)) {
      report(RULES.envIgnored.id, { file: ctx.exists('.gitignore') ? '.gitignore' : undefined, severity: envFiles.length ? 'high' : 'medium' });
    }

    const used = usedEnvVars(ctx);
    const hasExample = ctx.files.some((f) => /(^|\/)\.env\.(example|sample|template|dist|defaults)$/i.test(f));
    if (used.size > 0 && !hasExample && !ctx.stack.isLibrary) {
      report(RULES.envExample.id, { message: `The code reads ${used.size} environment variable(s), but there is no template listing them.` });
    } else if (hasExample) {
      const documented = documentedEnvVars(ctx);
      for (const [name, where] of used) {
        if (!documented.has(name)) report(RULES.envUndocumented.id, { file: where.file, line: where.line, key: name, message: `\`${name}\` is used but missing from .env.example.` });
      }
    }

    const pkg = parseJson<any>(ctx.read('package.json'));
    const app = !ctx.stack.isLibrary;
    if (pkg && !LOCK_FILES.some((f) => ctx.exists(f)) && !ctx.options.staged) {
      report(RULES.lockfile.id, { file: 'package.json' });
    }
    if (ctx.exists('requirements.txt')) {
      const loose = (ctx.read('requirements.txt') ?? '').split('\n').filter((l) => l.trim() && !l.startsWith('#') && !l.startsWith('-') && !/==/.test(l));
      if (loose.length && !ctx.exists('poetry.lock') && !ctx.exists('uv.lock') && !ctx.exists('Pipfile.lock')) {
        report(RULES.lockfile.id, { file: 'requirements.txt', message: `${loose.length} package(s) in requirements.txt have no exact version.` });
      }
    }
    if ([...ctx.git.tracked].some((p) => p.startsWith('node_modules/'))) report(RULES.nodeModules.id);

    const hasCi = ctx.allPaths.some((p) => /^\.github\/workflows\/|^\.gitlab-ci\.yml$|^\.circleci\/|^azure-pipelines\.yml$|^Jenkinsfile$|^bitbucket-pipelines\.yml$/.test(p));
    if (!hasCi && !ctx.options.staged) report(RULES.noCi.id);
    if (!ctx.files.some((f) => TEST_FILE.test(f)) && !ctx.options.staged) report(RULES.noTests.id);

    if (pkg && app && ctx.stack.isWebServer) {
      const script = pkg.scripts?.start;
      if (!script) report(RULES.noStart.id, { file: 'package.json' });
    }
    if (pkg && app && !pkg.engines?.node && !ctx.exists('.nvmrc') && !ctx.exists('.node-version') && !ctx.exists('.tool-versions')) {
      report(RULES.noEngines.id, { file: 'package.json' });
    }

    const scripts = [
      ...ctx.matching(/(^|\/)(Dockerfile[^/]*|Procfile|render\.ya?ml|fly\.toml|railway\.(json|toml)|vercel\.json|package\.json)$|\.github\/workflows\//),
    ];
    for (const { path, text } of scripts) {
      for (const match of text.matchAll(/prisma\s+db\s+push[^\n"']*--accept-data-loss|prisma\s+migrate\s+(reset|dev)\b|--force-reset/g)) {
        report(RULES.dangerousMigrate.id, { file: path, line: lineOf(text, match.index ?? 0), evidence: match[0] });
      }
    }

    let sawListen = false;
    let sawShutdown = false;
    for (const path of ctx.files) {
      if (!SOURCE.test(path) || isTestPath(path) || CONFIG_FILE.test(path)) continue;
      const text = ctx.read(path);
      if (!text) continue;
      if (/\bSIGTERM\b/.test(text)) sawShutdown = true;
      text.split('\n').forEach((line, i) => {
        if (isCommentLine(line) || line.length > 500) return;
        if (/["'`]https?:\/\/(localhost|127\.0\.0\.1):\d+/.test(line) && !/\|\||\?\?|NODE_ENV|DEV\b|development/.test(line) && !/\b(env|environ)\b/.test(line)) {
          report(RULES.localhost.id, { file: path, line: i + 1, evidence: line.trim().slice(0, 90) });
        }
        const listen = /\.listen\(\s*(\d{2,5})\b/.exec(line);
        if (/\.listen\(/.test(line)) sawListen = true;
        if (listen) report(RULES.port.id, { file: path, line: i + 1, evidence: line.trim().slice(0, 90) });
        if (/\.listen\([^)]*["'`](localhost|127\.0\.0\.1)["'`]/.test(line) || /\.run\([^)]*host\s*=\s*["']127\.0\.0\.1/.test(line)) {
          report(RULES.bindLocal.id, { file: path, line: i + 1 });
        }
        if (/synchronize\s*:\s*true/.test(line) || /\.sync\(\s*\{\s*(force|alter)\s*:\s*true/.test(line)) {
          report(RULES.autoSync.id, { file: path, line: i + 1, evidence: line.trim().slice(0, 90) });
        }
      });
    }
    if (sawListen && !sawShutdown) report(RULES.shutdown.id);

    for (const { path, text } of ctx.matching(/\.(html|jsx|tsx|vue|svelte|astro)$/)) {
      if (isTestPath(path)) continue;
      const hit = text.search(/lorem ipsum|your company name|acme (inc|corp)|coming soon|TODO: replace/i);
      if (hit >= 0) report(RULES.placeholder.id, { file: path, line: lineOf(text, hit) });
    }
  },
};
