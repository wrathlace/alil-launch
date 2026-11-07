import type { Checker, RuleMeta, Severity, ScanContext, Reporter } from '../types.js';
import { isCommentLine, isTestPath, lineOf } from '../core/util.js';

interface LineRule {
  id: string;
  title: string;
  severity: Severity;
  files: RegExp;
  re: RegExp;
  description: string;
  fix: string;
}

const JS = /\.(m?[jt]sx?|cjs|vue|svelte)$/;
const PY = /\.py$/;
const CODE = /\.(m?[jt]sx?|cjs|py|rb|go|php|java|cs|rs)$/;

const LINE_RULES: LineRule[] = [
  { id: 'config/tls-verification-off', title: 'TLS verification disabled', severity: 'high', files: CODE, re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFY(PEER|HOST)\s*(=>|,)\s*(false|0)\b/, description: 'Certificate checks are turned off, which allows man-in-the-middle attacks.', fix: 'Keep verification on. For private CAs, supply the CA certificate instead.' },
  { id: 'config/flask-debug', title: 'Flask debug mode enabled', severity: 'high', files: PY, re: /\.run\([^)]*debug\s*=\s*True/, description: 'The Flask debugger allows remote code execution if it is reachable.', fix: 'Read debug from an environment variable and default it to off.' },
  { id: 'config/django-debug', title: 'Django DEBUG enabled', severity: 'high', files: /(^|\/)settings[^/]*\.py$/, re: /^\s*DEBUG\s*=\s*True\b/, description: 'Django debug pages reveal settings and stack traces.', fix: 'Set DEBUG from an environment variable and default it to False.' },
  { id: 'config/django-allowed-hosts', title: 'Django ALLOWED_HOSTS allows everything', severity: 'medium', files: /(^|\/)settings[^/]*\.py$/, re: /ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']/, description: 'A wildcard host allows host-header attacks.', fix: 'List your real hostnames.' },
  { id: 'config/app-debug-env', title: 'Debug flag on in a production env file', severity: 'high', files: /(^|\/)\.env\.(production|prod)$/, re: /^\s*(APP_DEBUG|DEBUG)\s*=\s*(true|1)\b/i, description: 'Debug output leaks internals in production.', fix: 'Set the flag to false.' },
  { id: 'config/eval-user-input', title: 'eval on request data', severity: 'critical', files: JS, re: /\b(eval|new Function)\(\s*[^)]*\b(req|request|ctx)\.(body|query|params)/, description: 'Evaluating request data gives attackers code execution.', fix: 'Remove eval and parse the input explicitly.' },
  { id: 'config/command-injection', title: 'Shell command built from request data', severity: 'critical', files: JS, re: /\b(exec|execSync)\(\s*[`'"][^)]*(\$\{\s*(req|request|ctx)\.|["']\s*\+\s*(req|request|ctx)\.)/, description: 'Request data in a shell string allows command injection.', fix: 'Use execFile with an argument array and validate the input.' },
  { id: 'config/sql-injection', title: 'SQL built with string interpolation', severity: 'high', files: JS, re: /\.(query|execute|raw)\(\s*`\s*(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/i, description: 'Interpolated values in SQL allow injection.', fix: 'Use parameterised queries.' },
  { id: 'config/python-sql-injection', title: 'SQL built with an f-string', severity: 'high', files: PY, re: /\.execute\(\s*f["'](SELECT|INSERT|UPDATE|DELETE)\b/i, description: 'Interpolated values in SQL allow injection.', fix: 'Pass values as query parameters.' },
  { id: 'config/unsafe-deserialization', title: 'Unsafe deserialization', severity: 'high', files: PY, re: /\bpickle\.loads?\(|yaml\.load\((?![^)]*Loader)/, description: 'These loaders can execute code from untrusted data.', fix: 'Use yaml.safe_load, or JSON for untrusted input.' },
  { id: 'config/jwt-none', title: 'JWT accepts the "none" algorithm', severity: 'critical', files: CODE, re: /algorithms?\s*[:=]\s*\[?[^\]\n]*["']none["']/i, description: 'Unsigned tokens would be accepted as valid.', fix: 'Allow only the signing algorithm you use.' },
  { id: 'config/jwt-hardcoded-secret', title: 'JWT signed with a hardcoded secret', severity: 'critical', files: JS, re: /jwt\.(sign|verify)\([^,]+,\s*["'`][^"'`$]{3,}["'`]/, description: 'Anyone with the source can forge tokens.', fix: 'Load a long random secret from the environment.' },
  { id: 'config/insecure-cookie', title: 'Cookie security flag disabled', severity: 'medium', files: JS, re: /\b(httpOnly|secure)\s*:\s*false\b/, description: 'Cookies without these flags are easier to steal.', fix: 'Set httpOnly and secure to true in production.' },
  { id: 'config/browser-ai-key', title: 'AI SDK allowed in the browser', severity: 'high', files: JS, re: /dangerouslyAllowBrowser\s*:\s*true/, description: 'This ships your AI provider key to every visitor.', fix: 'Call the AI provider from your server.' },
  { id: 'config/firebase-open-rules', title: 'Firebase rules allow public access', severity: 'critical', files: /(^|\/)(firestore|storage)\.rules$|\.rules$/, re: /allow\s+[\w, ]+:\s*if\s+true\s*;/, description: 'Anyone on the internet can read or change this data.', fix: 'Require request.auth and scope access by user.' },
  { id: 'config/tf-open-ingress', title: 'Security group open to the internet', severity: 'high', files: /\.tf$/, re: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/, description: 'Check that only ports 80 and 443 are exposed this way.', fix: 'Restrict admin and database ports to known IP ranges.' },
  { id: 'config/tf-public-bucket', title: 'Public storage bucket', severity: 'high', files: /\.tf$/, re: /acl\s*=\s*"public-read(-write)?"/, description: 'Everything in this bucket is readable by anyone.', fix: 'Make the bucket private and serve files through a CDN or signed URLs.' },
  { id: 'config/k8s-privileged', title: 'Privileged Kubernetes container', severity: 'high', files: /\.ya?ml$/, re: /^\s*privileged:\s*true\b/, description: 'A privileged container can take over its node.', fix: 'Remove privileged and grant only the capabilities you need.' },
];

const CORS_RULE: RuleMeta = {
  id: 'config/cors-credentials-wildcard',
  title: 'CORS allows any origin with credentials',
  category: 'config',
  severity: 'high',
  description: 'Any website could make logged-in requests on behalf of your users.',
  fix: 'List your allowed origins explicitly.',
};
const RLS_RULE: RuleMeta = {
  id: 'config/supabase-rls-missing',
  title: 'Supabase table without row level security',
  category: 'config',
  severity: 'critical',
  description: 'Without RLS, the public anon key can read and write the whole table.',
  fix: 'Run `alter table <name> enable row level security;` and add policies.',
};
const NEXT_RULE: RuleMeta = {
  id: 'config/next-build-checks-off',
  title: 'Next.js build checks disabled',
  category: 'config',
  severity: 'medium',
  description: 'Type or lint errors can reach production unnoticed.',
  fix: 'Remove ignoreBuildErrors and ignoreDuringBuilds, then fix the errors.',
};
const SOURCEMAP_RULE: RuleMeta = {
  id: 'config/production-source-maps',
  title: 'Source maps published in production',
  category: 'config',
  severity: 'medium',
  description: 'Anyone can read your original front-end source.',
  fix: 'Disable public source maps, or upload them privately to your error tracker.',
};

function checkCors(path: string, text: string, report: Reporter): void {
  const lines = text.split('\n');
  const origin = /(origin|allow_origins?)["']?\s*[:=]\s*\[?\s*["'`]\*["'`]|Access-Control-Allow-Origin["']?\s*[,:]\s*["'`]?\*/i;
  const credentials = /(allow_)?credentials["']?\s*[:=]\s*(true|True)\b|Access-Control-Allow-Credentials["']?\s*[,:]\s*["'`]?true/i;
  lines.forEach((line, i) => {
    if (!origin.test(line)) return;
    const window = lines.slice(Math.max(0, i - 12), i + 13).join('\n');
    if (credentials.test(window)) report(CORS_RULE.id, { file: path, line: i + 1 });
  });
}

function checkRls(ctx: ScanContext, report: Reporter): void {
  const migrations = ctx.matching(/(^|\/)supabase\/migrations\/.*\.sql$/);
  const all = migrations.map((m) => m.text).join('\n');
  for (const { path, text } of migrations) {
    for (const match of text.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?["']?(\w+)/gi)) {
      const table = match[1];
      const enabled = new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(?:public\\.)?["']?${table}["']?\\s+enable\\s+row\\s+level\\s+security`, 'i');
      if (!enabled.test(all)) {
        report(RLS_RULE.id, { file: path, line: lineOf(text, match.index ?? 0), key: table, message: `Table \`${table}\` has no row level security.` });
      }
    }
  }
}

export const configChecker: Checker = {
  name: 'config',
  rules: [
    ...LINE_RULES.map((r): RuleMeta => ({ id: r.id, title: r.title, category: 'config', severity: r.severity, description: r.description, fix: r.fix })),
    CORS_RULE, RLS_RULE, NEXT_RULE, SOURCEMAP_RULE,
  ],
  run(ctx, report) {
    for (const path of ctx.files) {
      if (isTestPath(path)) continue;
      const rules = LINE_RULES.filter((r) => r.files.test(path));
      const text = ctx.read(path);
      if (!text) continue;
      if (rules.length) {
        text.split('\n').forEach((line, i) => {
          if (isCommentLine(line) || line.length > 2000) return;
          for (const rule of rules) {
            if (rule.re.test(line)) report(rule.id, { file: path, line: i + 1, evidence: line.trim().slice(0, 100) });
          }
        });
      }
      if (/\.(m?[jt]s|py|php|ya?ml)$/.test(path)) checkCors(path, text, report);
    }
    checkRls(ctx, report);
    for (const { path, text } of ctx.matching(/(^|\/)next\.config\.(m?js|ts)$/)) {
      const build = text.search(/ignoreBuildErrors\s*:\s*true|ignoreDuringBuilds\s*:\s*true/);
      if (build >= 0) report(NEXT_RULE.id, { file: path, line: lineOf(text, build) });
      const maps = text.search(/productionBrowserSourceMaps\s*:\s*true/);
      if (maps >= 0) report(SOURCEMAP_RULE.id, { file: path, line: lineOf(text, maps) });
    }
  },
};
