import type { Checker, RuleMeta, ScanContext, Reporter, Severity } from '../types.js';
import { runGit } from '../core/files.js';
import { ENV_TEMPLATE } from '../core/env.js';
import { entropy, isTestPath, lineOf, parseJson, redact, sha } from '../core/util.js';

interface Provider {
  id: string;
  title: string;
  re: RegExp;
  severity?: Severity;
  group?: number;
  validate?: (value: string, line: string) => boolean;
  severityFor?: (value: string) => Severity;
}

function decodeJwtPayload(token: string): any {
  const part = token.split('.')[1];
  if (!part) return null;
  return parseJson(Buffer.from(part, 'base64url').toString('utf8'));
}

const isPlaceholderKey = (value: string): boolean => /EXAMPLE|XXXX|0000000000|abcdef|123456789/i.test(value);

const PROVIDERS: Provider[] = [
  { id: 'aws-access-key', title: 'AWS access key ID', re: /\b((?:AKIA|ASIA)[A-Z2-7]{16})\b/g, group: 1, validate: (v) => !isPlaceholderKey(v) },
  { id: 'aws-secret-key', title: 'AWS secret access key', re: /aws[_-]?secret[_-]?(?:access[_-]?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})\b/gi, group: 1, validate: (v) => !isPlaceholderKey(v) },
  { id: 'github-token', title: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g, group: 1 },
  { id: 'github-fine-grained', title: 'GitHub fine-grained token', re: /\b(github_pat_[A-Za-z0-9_]{50,255})\b/g, group: 1 },
  { id: 'gitlab-token', title: 'GitLab token', re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g, group: 1 },
  { id: 'slack-token', title: 'Slack token', re: /\b(xox[abeoprs]-[A-Za-z0-9-]{20,})\b/g, group: 1 },
  { id: 'slack-webhook', title: 'Slack webhook URL', re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]{20,})/g, group: 1, severity: 'high' },
  { id: 'discord-webhook', title: 'Discord webhook URL', re: /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{50,})/g, group: 1, severity: 'high' },
  { id: 'telegram-bot-token', title: 'Telegram bot token', re: /\b(\d{8,12}:AA[A-Za-z0-9_-]{32,})\b/g, group: 1 },
  { id: 'stripe-live-key', title: 'Stripe live secret key', re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g, group: 1 },
  { id: 'stripe-test-key', title: 'Stripe test secret key', re: /\b(sk_test_[A-Za-z0-9]{20,})\b/g, group: 1, severity: 'medium' },
  { id: 'stripe-webhook-secret', title: 'Stripe webhook secret', re: /\b(whsec_[A-Za-z0-9]{24,})\b/g, group: 1, severity: 'high' },
  { id: 'google-api-key', title: 'Google API key', re: /\b(AIza[A-Za-z0-9_-]{35})\b/g, group: 1, severity: 'high' },
  { id: 'google-oauth-secret', title: 'Google OAuth client secret', re: /\b(GOCSPX-[A-Za-z0-9_-]{28})\b/g, group: 1 },
  { id: 'openai-key', title: 'OpenAI API key', re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,})\b/g, group: 1, validate: (v) => !v.startsWith('sk-ant-') },
  { id: 'anthropic-key', title: 'Anthropic API key', re: /\b(sk-ant-[A-Za-z0-9_-]{32,})\b/g, group: 1 },
  { id: 'huggingface-token', title: 'Hugging Face token', re: /\b(hf_[A-Za-z0-9]{32,})\b/g, group: 1 },
  { id: 'replicate-token', title: 'Replicate API token', re: /\b(r8_[A-Za-z0-9]{37,})\b/g, group: 1 },
  { id: 'groq-key', title: 'Groq API key', re: /\b(gsk_[A-Za-z0-9]{50,})\b/g, group: 1 },
  { id: 'xai-key', title: 'xAI API key', re: /\b(xai-[A-Za-z0-9]{60,})\b/g, group: 1 },
  { id: 'npm-token', title: 'npm access token', re: /\b(npm_[A-Za-z0-9]{36})\b/g, group: 1 },
  { id: 'pypi-token', title: 'PyPI upload token', re: /\b(pypi-AgE[A-Za-z0-9_-]{50,})\b/g, group: 1 },
  { id: 'sendgrid-key', title: 'SendGrid API key', re: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b/g, group: 1 },
  { id: 'resend-key', title: 'Resend API key', re: /\b(re_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,})\b/g, group: 1 },
  { id: 'twilio-key', title: 'Twilio API key', re: /\b(SK[0-9a-f]{32})\b/g, group: 1, severity: 'high' },
  { id: 'shopify-token', title: 'Shopify access token', re: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g, group: 1 },
  { id: 'digitalocean-token', title: 'DigitalOcean token', re: /\b(do[op]_v1_[a-f0-9]{64})\b/g, group: 1 },
  { id: 'azure-storage-key', title: 'Azure storage account key', re: /AccountKey=([A-Za-z0-9/+]{80,}={0,2})/g, group: 1 },
  { id: 'databricks-token', title: 'Databricks token', re: /\b(dapi[a-f0-9]{32})\b/g, group: 1 },
  { id: 'linear-key', title: 'Linear API key', re: /\b(lin_api_[A-Za-z0-9]{40})\b/g, group: 1 },
  { id: 'notion-token', title: 'Notion integration token', re: /\b((?:ntn_|secret_)[A-Za-z0-9]{43,50})\b/g, group: 1, severity: 'high' },
  { id: 'sentry-auth-token', title: 'Sentry auth token', re: /\b(sntry[us]_[A-Za-z0-9_+=/-]{40,})\b/g, group: 1 },
  { id: 'postman-key', title: 'Postman API key', re: /\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b/g, group: 1 },
  { id: 'atlassian-token', title: 'Atlassian API token', re: /\b(ATATT3[A-Za-z0-9_=-]{100,})\b/g, group: 1 },
  { id: 'planetscale-token', title: 'PlanetScale token', re: /\b(pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,})\b/g, group: 1 },
  { id: 'private-key', title: 'Private key', re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g, group: 1 },
  {
    id: 'database-url-password',
    title: 'Database URL with password',
    re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@/"'`]+:([^\s:@/"'`]{3,})@[^\s"'`]+)/g,
    group: 1,
    validate: (v) => !/\$\{|\{\{|<|%\(|:(password|pass|pwd|secret|changeme|example)@/i.test(v),
    severity: 'high',
    severityFor: (v) => (/@(localhost|127\.0\.0\.1|0\.0\.0\.0|db|database|mysql|postgres|mongo|redis|host\.docker\.internal)(:|\/|$)/i.test(v) ? 'low' : 'high'),
  },
  {
    id: 'supabase-service-key',
    title: 'Supabase service_role key',
    re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    group: 1,
    validate: (v) => decodeJwtPayload(v)?.role === 'service_role',
  },
];

const GENERIC_RULE: RuleMeta = {
  id: 'secret/generic',
  title: 'Hardcoded credential',
  category: 'secrets',
  severity: 'high',
  description: 'A variable named like a password, token or key is assigned a literal value.',
  fix: 'Move the value into an environment variable or secret manager, and rotate it if it was ever committed.',
};
const PUBLIC_RULE: RuleMeta = {
  id: 'secret/public-env-var',
  title: 'Secret exposed through a public env prefix',
  category: 'secrets',
  severity: 'critical',
  description: 'NEXT_PUBLIC_, VITE_, REACT_APP_ and similar variables are compiled into browser code, so anything sensitive in them is public.',
  fix: 'Remove the public prefix, read the value only on the server, and rotate the key.',
};
const ENV_TRACKED_RULE: RuleMeta = {
  id: 'secret/env-file-committed',
  title: '.env file committed to git',
  category: 'secrets',
  severity: 'critical',
  description: 'A real environment file is tracked by git, so everyone with repository access can read it.',
  fix: 'Run `git rm --cached <file>`, add it to .gitignore, rotate its values, and purge it from history.',
};
const HISTORY_RULE: RuleMeta = {
  id: 'secret/in-git-history',
  title: 'Secret in git history',
  category: 'secrets',
  severity: 'critical',
  description: 'A secret was committed at some point. Deleting it from the latest commit does not remove it from history.',
  fix: 'Rotate the secret first, then purge history with git-filter-repo if you need to.',
};
const KEY_FILE_RULE: RuleMeta = {
  id: 'secret/key-file-committed',
  title: 'Key or credential file committed',
  category: 'secrets',
  severity: 'high',
  description: 'A file that normally holds credentials is tracked in the repository.',
  fix: 'Remove it from git, add it to .gitignore and rotate the credential.',
};

const PROVIDER_RULES: RuleMeta[] = PROVIDERS.map((p) => ({
  id: `secret/${p.id}`,
  title: p.title,
  category: 'secrets',
  severity: p.severity ?? 'critical',
  description: `Detects a ${p.title} in a project file.`,
  fix: 'Revoke and rotate this credential now, then load it from an environment variable or secret manager.',
}));

const SKIP_FILES = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|poetry\.lock|Pipfile\.lock|Cargo\.lock|Gemfile\.lock|go\.sum)$|\.(svg|lock)$/;
const CONFIG_STYLE = /(^|\/)\.env(\.[^/]*)?$|\.(ya?ml|ini|toml|properties|conf|cfg)$/i;
const LOCALE_PATH = /(^|\/)(locales?|i18n|l10n|lang|languages|translations?|snippets?)\/|(^|\/)messages\.[a-z-]+\.json$/i;
const CI_FILE = /(^|\/)(\.drone|\.gitlab-ci|\.travis|bitbucket-pipelines)\.ya?ml$|\.dist$|(^|\/)\.github\//;
const MAX_GENERIC_LINE = 500;
const BUNDLED_LINE = 2000;
const SECRET_NAME = '[A-Za-z0-9_.-]{0,48}(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?key|private[_-]?key|credential)[A-Za-z0-9_-]{0,48}';
const QUOTED = new RegExp(`(?:^|[\\s"'{,(])(${SECRET_NAME})["']?\\s*(?:=|:|=>)\\s*["']([^"'\\s]{8,200})["']`, 'gim');
const BARE = new RegExp(`^\\s*(?:-\\s*)?(?:export\\s+)?(${SECRET_NAME})\\s*[:=]\\s*([^\\s#"'\`]{6,200})\\s*$`, 'gim');
const PLACEHOLDER =
  /example|sample|placeholder|change[-_]?me|your[-_a-z]*|xxx+|dummy|fake|mock|test|todo|replace|redacted|\*{3,}|<[^>]*>|\$\{|\$\(|\{\{|%\(|%env|^%.*%$|^@|^\$|process\.env|os\.environ|getenv|^(true|false|null|none|undefined|required|optional|string|bearer|basic|password|secret|token)$|^[a-z]+(\.[a-z_]+)+$/i;
const PUBLIC_PREFIX = /^\s*(?:export\s+)?((?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC|PUBLIC|GATSBY)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|OPENAI|ANTHROPIC|STRIPE_SECRET|ADMIN_KEY|API_SECRET|TOKEN)[A-Z0-9_]*)\s*=\s*(\S+)/g;

const compact = (value: string): string => value.toLowerCase().replace(/[^a-z0-9]/g, '');

/** Constants such as MODE_RESET = 'reset_password' name a thing rather than hold a credential. */
function isIdentifier(name: string, value: string): boolean {
  if (/^[A-Za-z]+([_-][A-Za-z]+)+$/.test(value) || /^[A-Z]+$/.test(value)) return true;
  const a = compact(name);
  const b = compact(value);
  return a.includes(b) || b.includes(a);
}

function looksLikeSecret(name: string, value: string): boolean {
  if (PLACEHOLDER.test(value) || isIdentifier(name, value)) return false;
  if (value.includes('\\')) return false;
  if (/^(https?:|\/|\.\/|[a-z]+:\/\/)/i.test(value)) return false;
  if (/password|passwd|pwd/i.test(name)) return value.length >= 6 && entropy(value) >= 2;
  if (/[\\[\]()|^]/.test(value) || /^[\w.-]+(\/[\w.-]+)+$/.test(value)) return false;
  return entropy(value) >= 3 && /[0-9]/.test(value) && /[A-Za-z]/.test(value);
}

function scanText(path: string, text: string, report: Reporter): void {
  const downgrade = isTestPath(path) || ENV_TEMPLATE.test(path) || CI_FILE.test(path);
  const seen = new Set<string>();
  const emit = (ruleId: string, value: string, line: number, base: Severity, message: string): void => {
    const key = `${ruleId}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    report(ruleId, {
      file: path,
      line,
      evidence: redact(value),
      key: sha(value),
      severity: downgrade ? 'low' : base,
      message: downgrade ? `${message} This is in a test or example file, so confirm the value is fake.` : message,
    });
  };

  for (const provider of PROVIDERS) {
    provider.re.lastIndex = 0;
    for (const match of text.matchAll(provider.re)) {
      const value = match[provider.group ?? 0];
      if (provider.validate && !provider.validate(value, match[0])) continue;
      const severity = provider.severityFor?.(value) ?? provider.severity ?? 'critical';
      emit(`secret/${provider.id}`, value, lineOf(text, match.index ?? 0), severity, `${provider.title} found in source.`);
    }
  }

  if (ENV_TEMPLATE.test(path) || LOCALE_PATH.test(path)) return;
  const lines = text.split('\n');
  if (lines.some((line) => line.length > BUNDLED_LINE)) return;
  const patterns = CONFIG_STYLE.test(path) ? [QUOTED, BARE] : [QUOTED];
  lines.forEach((line, i) => {
    if (line.length > MAX_GENERIC_LINE) return;
    for (const re of patterns) {
      re.lastIndex = 0;
      for (const match of line.matchAll(re)) {
        const [, name, value] = match;
        if (looksLikeSecret(name, value)) emit('secret/generic', value, i + 1, 'high', `\`${name}\` is assigned a literal value.`);
      }
    }
    if (/(^|\/)\.env/.test(path)) {
      PUBLIC_PREFIX.lastIndex = 0;
      for (const match of line.matchAll(PUBLIC_PREFIX)) {
        if (!PLACEHOLDER.test(match[2])) {
          emit('secret/public-env-var', match[2], i + 1, 'critical', `\`${match[1]}\` is compiled into browser code and readable by anyone.`);
        }
      }
    }
  });
}

function scanHistory(ctx: ScanContext, report: Reporter): void {
  const log = runGit(ctx.root, ['log', '--all', '-p', '-U0', '--no-color', '--no-ext-diff', '--format=commit %h', '--max-count=2000']);
  if (!log) return;
  let commit = '';
  let file = '';
  const seen = new Set<string>();
  for (const line of log.split('\n')) {
    if (line.startsWith('commit ')) commit = line.slice(7);
    else if (line.startsWith('+++ b/')) file = line.slice(6);
    else if (line.startsWith('+') && !line.startsWith('+++') && !SKIP_FILES.test(file)) {
      for (const provider of PROVIDERS) {
        provider.re.lastIndex = 0;
        for (const match of line.matchAll(provider.re)) {
          const value = match[provider.group ?? 0];
          if (provider.validate && !provider.validate(value, match[0])) continue;
          const hash = sha(value);
          if (seen.has(hash)) continue;
          seen.add(hash);
          report(HISTORY_RULE.id, {
            file,
            evidence: redact(value),
            key: hash,
            severity: isTestPath(file) ? 'low' : 'critical',
            message: `${provider.title} was committed in ${commit}.`,
          });
        }
      }
    }
  }
}

export const secretsChecker: Checker = {
  name: 'secrets',
  rules: [...PROVIDER_RULES, GENERIC_RULE, PUBLIC_RULE, ENV_TRACKED_RULE, KEY_FILE_RULE, HISTORY_RULE],
  run(ctx, report) {
    for (const path of ctx.files) {
      if (SKIP_FILES.test(path)) continue;
      const text = ctx.read(path);
      if (text) scanText(path, text, report);
    }
    for (const path of ctx.git.tracked) {
      const name = path.split('/').pop() ?? '';
      if (/^\.env(\.(local|production|prod|staging|development|dev|test))?$/.test(name)) {
        report(ENV_TRACKED_RULE.id, { file: path, message: `${path} is tracked by git.` });
      } else if (/^(id_rsa|id_ed25519|id_ecdsa|.*\.pem|.*\.p12|.*\.pfx|.*\.keystore|credentials\.json|service[-_]?account.*\.json|\.npmrc|\.pypirc|\.netrc)$/.test(name) && !isTestPath(path)) {
        const text = ctx.read(path) ?? '';
        const harmless = /\.(pem)$/.test(name) && !/PRIVATE KEY/.test(text);
        const npmrc = name === '.npmrc' && !/_authToken|_password/.test(text);
        if (!harmless && !npmrc) report(KEY_FILE_RULE.id, { file: path, message: `${path} usually contains credentials.` });
      }
    }
    if (ctx.options.history && ctx.git.isRepo) scanHistory(ctx, report);
  },
};
