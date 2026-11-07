import type { Checker, RuleMeta } from '../types.js';
import { parseJson } from '../core/util.js';

const rule = (id: string, title: string, severity: RuleMeta['severity'], description: string, fix: string): RuleMeta => ({
  id, title, severity, description, fix, category: 'launch',
});

const RULES = {
  readme: rule('launch/no-readme', 'No README', 'low', 'Nobody can tell how to run or deploy this project.', 'Add a README with setup and deploy steps.'),
  license: rule('launch/no-license', 'No license', 'low', 'Without a license, others have no right to use public code.', 'Add a LICENSE file, or mark the project as private.'),
  health: rule('launch/no-health-endpoint', 'No health endpoint', 'medium', 'Load balancers and uptime monitors have nothing to check.', 'Add a `/health` route that checks the app and its database.'),
  monitoring: rule('launch/no-error-monitoring', 'No error monitoring', 'medium', 'You will hear about production errors from users.', 'Add Sentry, Rollbar, Bugsnag or similar.'),
  rateLimit: rule('launch/no-rate-limiting', 'No rate limiting', 'medium', 'Login and API routes can be brute-forced or abused.', 'Add rate limiting at your app or edge layer.'),
  headers: rule('launch/no-security-headers', 'No security header middleware', 'medium', 'Browsers get no CSP, HSTS or clickjacking protection from the app.', 'Add helmet, or set the headers in your framework or CDN.'),
  logging: rule('launch/no-structured-logging', 'No structured logging', 'low', 'Plain console output is hard to search during an incident.', 'Use pino, winston, structlog or similar.'),
  privacy: rule('launch/no-privacy-policy', 'No privacy policy page', 'medium', 'Apps that collect accounts or emails usually need one by law.', 'Publish a privacy policy and link it in the footer.'),
  robots: rule('launch/no-robots-txt', 'No robots.txt', 'low', 'Search engines get no crawl instructions.', 'Add a robots.txt to your public folder.'),
  favicon: rule('launch/no-favicon', 'No favicon', 'low', 'Browser tabs show a generic icon.', 'Add a favicon.'),
  notFound: rule('launch/no-404-page', 'No custom 404 page', 'low', 'Lost visitors get a bare error page.', 'Add a 404 page that links home.'),
  meta: rule('launch/no-social-metadata', 'No social sharing metadata', 'low', 'Shared links will have no title or preview image.', 'Add Open Graph tags.'),
  securityPolicy: rule('launch/no-security-policy', 'No security contact', 'info', 'Researchers have no way to report a problem privately.', 'Add a SECURITY.md or /.well-known/security.txt.'),
};

const has = (text: string, re: RegExp): boolean => re.test(text);

export const launchChecker: Checker = {
  name: 'launch',
  rules: Object.values(RULES),
  run(ctx, report) {
    if (ctx.options.staged) return;
    const names = ctx.files.map((f) => f.toLowerCase());
    if (!names.some((f) => /^readme(\.|$)/.test(f))) report(RULES.readme.id);
    if (!names.some((f) => /^(licen[sc]e|copying)(\.|$)/.test(f))) {
      const pkg = parseJson<any>(ctx.read('package.json'));
      if (!pkg?.private) report(RULES.license.id);
    }
    if (!names.some((f) => /^(\.github\/)?security\.md$|security\.txt$/.test(f))) report(RULES.securityPolicy.id);
    const { isWebServer, isFrontend, isLibrary } = ctx.stack;
    if ((!isWebServer && !isFrontend) || isLibrary) return;

    const manifests = ctx.matching(/(^|\/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Gemfile|composer\.json|go\.mod)$/).map((m) => m.text).join('\n');
    const source = ctx.matching(/\.(m?[jt]sx?|cjs|py|rb|go|php|ya?ml|conf|toml)$/).filter((m) => !/lock/.test(m.path)).map((m) => m.text).join('\n');
    const everything = `${manifests}\n${source}`;

    if (isWebServer) {
      if (!has(everything, /["'`/](api\/)?(health|healthz|healthcheck|ready|readyz|livez|ping|up|status)["'`/]/i) && !names.some((f) => /(^|\/)(health|healthz|ready)(\/route\.[jt]sx?|\.[jt]s)$/.test(f))) {
        report(RULES.health.id);
      }
      if (!has(everything, /rate[-_ ]?limit|ratelimit|throttl|slowapi|@upstash\/ratelimit|limiter/i)) report(RULES.rateLimit.id);
      if (!has(everything, /\bhelmet\b|secure_headers|django\.middleware\.security|Content-Security-Policy|Strict-Transport-Security|flask[-_]talisman|secure-headers/i)) report(RULES.headers.id);
      if (!has(manifests, /\b(pino|winston|bunyan|structlog|loguru|log4js|zap|zerolog|monolog|lograge)\b/i)) report(RULES.logging.id);
    }
    if (!has(manifests, /sentry|rollbar|bugsnag|honeybadger|datadog|dd-trace|newrelic|airbrake|appsignal|posthog/i)) report(RULES.monitoring.id);

    if (isFrontend) {
      const pages = names.filter((f) => /\.(html|[jt]sx|vue|svelte|astro|mdx?)$/.test(f));
      const collectsUsers = has(everything, /\b(signup|sign-up|register|login|signIn|createUser|newsletter|next-auth|clerk|supabase\.auth)\b/i);
      if (collectsUsers && !pages.some((f) => /privacy/.test(f)) && !has(source, /privacy[- ]?policy/i)) report(RULES.privacy.id);
      if (!names.some((f) => /(^|\/)robots\.(txt|[jt]s)$/.test(f))) report(RULES.robots.id);
      if (!names.some((f) => /favicon|(^|\/)icon\.(png|svg|ico)$/.test(f))) report(RULES.favicon.id);
      if (!names.some((f) => /(^|\/)(not-found|404|\[\.\.\.404\]|\+error)\.?[a-z]*$/.test(f))) report(RULES.notFound.id);
      const markup = ctx.matching(/\.(html|[jt]sx|vue|svelte|astro)$/).map((m) => m.text).join('\n');
      if (!/og:title|openGraph|og:image/i.test(markup)) report(RULES.meta.id);
    }
  },
};
