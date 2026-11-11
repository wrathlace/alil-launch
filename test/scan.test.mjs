import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { allRules, applyFixes, assertLaunchReady, renderHtml, renderJson, renderMarkdown, renderPrompt, renderSarif, scan } from '../dist/index.js';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
const created = [];

function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'lr-test-'));
  created.push(root);
  for (const [file, content] of Object.entries(files)) {
    const path = join(root, file);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return root;
}

function git(root, ...args) {
  execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t.dev', ...args], { cwd: root, stdio: 'ignore' });
}

after(() => created.forEach((root) => rmSync(root, { recursive: true, force: true })));

const ids = (result) => result.findings.map((f) => f.ruleId);
const secrets = {
  stripe: ['sk', 'live', 'q7Xk2Lm9Pz4Rt8Vn1Bc6Wd3Y'].join('_'),
  github: ['ghp', 'q7Xk2Lm9Pz4Rt8Vn1Bc6Wd3Yh5Jf0Sa2Gu4e'].join('_'),
  aws: ['AKIA', 'QYLPMN5HHHFPZAM2'].join(''),
  anthropic: ['sk-ant', 'api03', 'q7Xk2Lm9Pz4Rt8Vn1Bc6Wd3Yh5Jf0Sa2Gu4e'].join('-'),
};

test('finds provider secrets and never reveals them in any output format', async () => {
  const value = secrets.stripe;
  const root = project({ 'app.js': `const key = "${value}";\nconst gh = "${secrets.github}";\nconst a = "${secrets.anthropic}";\nconst k = "${secrets.aws}";\n` });
  const result = await scan(root);
  for (const id of ['secret/stripe-live-key', 'secret/github-token', 'secret/anthropic-key', 'secret/aws-access-key']) {
    assert.ok(ids(result).includes(id), id);
  }
  for (const output of [renderJson(result), renderSarif(result), renderMarkdown(result), renderPrompt(result), renderHtml(result)]) {
    assert.ok(!output.includes(value), 'secret leaked into a report');
    assert.ok(!output.includes(secrets.github), 'secret leaked into a report');
  }
});

test('secrets in command output and matched lines are masked in every report', async () => {
  const { maskSecrets } = await import('../dist/rules/secrets.js');
  const values = {
    stripe: secrets.stripe,
    github: secrets.github,
    password: ['Hunter2', 'Secret99'].join(''),
    url: ['s3cretPw', '42'].join(''),
    bearer: ['eyJhbGciOiJIUzI1NiJ9', 'Zm9vYmFyYmF6'].join(''),
    unknown: ['Qm9vT2ZTZWNyZXRz', 'X9aB7cD2eF4gH6jK'].join(''),
  };
  const output = [
    `> build`,
    `STRIPE_KEY=${values.stripe}`,
    `token: ${values.github}`,
    `db_password = "${values.password}"`,
    `connecting to https://admin:${values.url}@api.example.dev/v1`,
    `Authorization: Bearer ${values.bearer}`,
    `custom key ${values.unknown}`,
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');
  const masked = maskSecrets(output);
  for (const [name, value] of Object.entries(values)) assert.ok(!masked.includes(value), `${name} leaked: ${masked}`);
  assert.ok(!masked.includes('MIIEowIBAAKCAQEA'), 'private key body leaked');
  assert.match(masked, /STRIPE_KEY=sk_l\*{8}/, 'the prefix stays so a person can tell what it was');

  // Through a real scan: a failing build that prints secrets, and a non-secret rule that quotes its line.
  const script = `node -e "console.log(process.env.LEAK_A); console.log('password=' + process.env.LEAK_B); process.exit(1)"`;
  const root = project({
    'package.json': JSON.stringify({ scripts: { build: script } }),
    'client.js': `fetch("http://localhost:3000/api?token=${values.github}");\n`,
  });
  const before = { ...process.env };
  process.env.LEAK_A = values.stripe;
  process.env.LEAK_B = values.password;
  try {
    const result = await scan(root, { run: true });
    assert.ok(result.findings.some((f) => f.ruleId === 'run/command-failed'), 'the failing build is still reported');
    assert.ok(result.findings.some((f) => f.ruleId === 'deploy/hardcoded-localhost'), 'the localhost rule still fires');
    for (const report of [renderJson(result), renderSarif(result), renderMarkdown(result), renderPrompt(result), renderHtml(result)]) {
      for (const value of [values.stripe, values.password, values.github]) assert.ok(!report.includes(value), 'secret leaked into a report');
    }
  } finally {
    process.env = before;
  }
});

test('masking leaves ordinary report text alone', async () => {
  const { maskSecrets } = await import('../dist/rules/secrets.js');
  const plain = [
    'org.apache.logging.log4j:log4j-core@2.14.0: CVE-2021-44228, CVE-2021-45046 (Remote code injection in Log4j). Upgrade to 2.17.1 or later.',
    'Cookie `session_token` is missing Secure, HttpOnly.',
    'commit 15dd70e6a2b4c8d9e0f1a2b3c4d5e6f7a8b9c0d1 changed package.json',
    '`npm run test` exited with code 3.',
    'There is no lockfile, so the installed versions of 1 of 2 direct dependencies are unknown and were not checked: axios.',
  ];
  for (const line of plain) assert.equal(maskSecrets(line), line);
});

test('placeholders and environment lookups are not reported as secrets', async () => {
  const root = project({
    'app.js': 'const password = process.env.DB_PASSWORD;\nconst apiKey = "your_api_key_here";\nconst token = "<token>";\nconst secret = "changeme";\nconst tokenKey = "auth.token.name";\n',
    'config.yml': 'password: ${DB_PASSWORD}\napi_key: {{ vault_key }}\n',
    '.env.example': 'API_KEY=your_key\nDB_PASSWORD=\n',
  });
  const result = await scan(root);
  assert.deepEqual(ids(result).filter((id) => id.startsWith('secret/')), []);
});

test('code that only names a credential is not reported', async () => {
  const root = project({
    'Constants.php': "const MODE_CHANGE_PASSWORD = 'change_password';\nconst USER_2FA_TOKEN = 'user_2fa_token';\nconst TOKEN_RESOURCE = 'v1/oauth2/token';\n",
    'app/config.yml': "password: '%database_password%'\nclient_token: '@service.token'\n",
    'lang/de/messages.json': '{ "Password": "Passwort1234" }\n',
    'bundle.js': `${'x'.repeat(3000)}\nconst password = "abc123def456";\n`,
    'configs/urls.ts': 'export const urls = {\n  forgetPasswordOtpVerfication: "Login/OtpVerification",\n  resetPassword: "Login/ChangePassword",\n  changePassword: "Login/ChangeUserPassword",\n  forgotPasswordApi: "api/v1/auth/forgot-password/",\n};\n',
  });
  assert.deepEqual(ids(await scan(root)).filter((id) => id.startsWith('secret/')), []);

  // A real password value is still found, even next to route constants.
  const real = project({ 'configs/db.ts': 'export const dbPassword = "Kq7!vR2pLm9x";\n' });
  assert.ok(ids(await scan(real)).includes('secret/generic'));
});

test('real credentials in config files are still found', async () => {
  const root = project({
    'deploy/app.yml': 'DB_PASSWORD: s3rv1ce-acc0unt\nGITHUB_CLIENT_SECRET: 403ae4a2cb18cd54a043\nJIRA_PASSWORD: demo2018\n',
    'app.py': 'password = "correct-horse-7-battery"\nauth_token = "a8f5f167f44f4964e6c998dee827110c"\n',
  });
  const found = (await scan(root)).findings.filter((f) => f.ruleId === 'secret/generic');
  assert.equal(found.length, 5);
});

test('long minified lines do not slow the scan down', async () => {
  const root = project({ 'bundle.js': `var a="${'password_token_'.repeat(70000)}";\n` });
  const started = Date.now();
  await scan(root);
  assert.ok(Date.now() - started < 5000);
});

test('secrets in test folders are downgraded', async () => {
  const root = project({ 'test/fixture.js': `const key = "${secrets.stripe}";\n` });
  const found = (await scan(root)).findings.find((f) => f.ruleId === 'secret/stripe-live-key');
  assert.equal(found.severity, 'low');
});

test('public env prefix exposure is critical', async () => {
  const root = project({ '.env.production': `NEXT_PUBLIC_STRIPE_SECRET_KEY=${secrets.stripe}\n` });
  assert.ok(ids(await scan(root)).includes('secret/public-env-var'));
});

test('Supabase service_role keys are recognised but anon keys are not', async () => {
  const jwt = (role) => ['eyJhbGciOiJIUzI1NiJ9', Buffer.from(JSON.stringify({ role, iss: 'supabase' })).toString('base64url'), 'c2lnbmF0dXJlMTIzNDU2'].join('.');
  const root = project({ 'a.js': `const s = "${jwt('service_role')}";\n`, 'b.js': `const a = "${jwt('anon')}";\n` });
  const found = (await scan(root)).findings.filter((f) => f.ruleId === 'secret/supabase-service-key');
  assert.equal(found.length, 1);
  assert.equal(found[0].file, 'a.js');
});

test('committed .env file and secrets in git history', async () => {
  const root = project({ '.env': `KEY=${secrets.github}\n`, 'README.md': '# x\n' });
  git(root, 'init', '-q');
  git(root, 'add', '.');
  git(root, 'commit', '-qm', 'first');
  assert.ok(ids(await scan(root)).includes('secret/env-file-committed'));
  git(root, 'rm', '-q', '.env');
  git(root, 'commit', '-qm', 'remove');
  assert.ok(!ids(await scan(root)).includes('secret/github-token'));
  assert.ok(ids(await scan(root, { history: true })).includes('secret/in-git-history'));
});

test('gitignored files are skipped in repos and in plain folders', async () => {
  const files = { '.gitignore': '.env\nsecret-stuff/\n', '.env': `KEY=${secrets.stripe}\n`, 'secret-stuff/a.js': `const k = "${secrets.stripe}";\n`, 'a.js': 'const x = 1;\n' };
  const plain = project(files);
  assert.ok(!ids(await scan(plain)).includes('secret/stripe-live-key'));
  const repo = project(files);
  git(repo, 'init', '-q');
  assert.ok(!ids(await scan(repo)).includes('secret/stripe-live-key'));
});

test('--staged scans only staged files', async () => {
  const root = project({ 'clean.js': 'const a = 1;\n' });
  git(root, 'init', '-q');
  writeFileSync(join(root, 'unstaged.js'), `const k = "${secrets.stripe}";\n`);
  writeFileSync(join(root, 'staged.js'), `const k = "${secrets.github}";\n`);
  git(root, 'add', 'staged.js');
  const found = ids(await scan(root, { staged: true }));
  assert.ok(found.includes('secret/github-token'));
  assert.ok(!found.includes('secret/stripe-live-key'));
});

test('Dockerfile and compose mistakes', async () => {
  const root = project({
    Dockerfile: 'FROM node:latest\nCOPY . .\nENV API_TOKEN=abc123\nRUN curl https://x.io/i.sh | sh\n',
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n    environment:\n      POSTGRES_PASSWORD: postgres\n  app:\n    image: app:1\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n',
  });
  const found = ids(await scan(root));
  for (const id of ['docker/runs-as-root', 'docker/unpinned-base-image', 'docker/secret-in-image', 'docker/curl-pipe-shell', 'docker/no-dockerignore', 'compose/docker-socket-mounted', 'compose/privileged', 'compose/database-port-exposed', 'compose/weak-default-password', 'compose/database-without-volume']) {
    assert.ok(found.includes(id), id);
  }
});

test('a well configured compose file stays clean', async () => {
  const root = project({ 'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "127.0.0.1:5432:5432"\n    environment:\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n    volumes:\n      - pgdata:/var/lib/postgresql/data\nvolumes:\n  pgdata:\n' });
  assert.deepEqual(ids(await scan(root, { only: ['config'] })).filter((id) => id.startsWith('compose/')), []);
});

test('unsafe code settings', async () => {
  const root = project({
    'app.js': 'app.use(cors({ origin: "*", credentials: true }));\nhttps.request({ rejectUnauthorized: false });\neval(req.body.code);\n',
    'settings.py': 'DEBUG = True\n',
    'supabase/migrations/1.sql': 'create table a (id int);\ncreate table b (id int);\nalter table b enable row level security;\n',
    'firestore.rules': 'match /{d=**} { allow read, write: if true; }\n',
  });
  const result = await scan(root);
  for (const id of ['config/cors-credentials-wildcard', 'config/tls-verification-off', 'config/eval-user-input', 'config/django-debug', 'config/firebase-open-rules']) {
    assert.ok(ids(result).includes(id), id);
  }
  const rls = result.findings.filter((f) => f.ruleId === 'config/supabase-rls-missing');
  assert.equal(rls.length, 1);
  assert.match(rls[0].message, /`a`/);
});

test('GitHub workflow risks', async () => {
  const root = project({ '.github/workflows/x.yml': 'on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: someone/thing@v1\n      - run: echo "${{ github.event.pull_request.title }}"\n' });
  const found = ids(await scan(root));
  for (const id of ['ci/pull-request-target-checkout', 'ci/unpinned-third-party-action', 'ci/script-injection', 'ci/no-token-permissions']) assert.ok(found.includes(id), id);
});

test('backups: missing, present without restore plan, and committed dumps', async () => {
  const pkg = JSON.stringify({ dependencies: { pg: '8.0.0' } });
  assert.ok(ids(await scan(project({ 'package.json': pkg }))).includes('backup/none-found'));
  const partial = ids(await scan(project({ 'package.json': pkg, 'ops/cron.sh': 'pg_dump mydb > x.sql\n' })));
  assert.ok(!partial.includes('backup/none-found'));
  assert.ok(partial.includes('backup/no-restore-plan'));
  const done = ids(await scan(project({ 'package.json': pkg, 'ops/cron.sh': 'pg_dump mydb > x.sql\n', 'RUNBOOK.md': 'Run pg_restore x.sql\n' })));
  assert.ok(!done.includes('backup/no-restore-plan'));
  assert.ok(ids(await scan(project({ 'data.sql': "INSERT INTO users VALUES (1);\n" }))).includes('backup/dump-committed'));
  assert.ok(!ids(await scan(project({ 'migrations/1.sql': 'CREATE TABLE a (id int);\n' }))).includes('backup/dump-committed'));
});

test('deployment mistakes', async () => {
  const root = project({
    'package.json': JSON.stringify({ dependencies: { express: '4.0.0' }, scripts: { deploy: 'prisma migrate reset --force' } }),
    'server.js': 'const u = process.env.STRIPE_KEY;\nfetch("http://localhost:3000/a");\napp.listen(3000);\nconst o = { synchronize: true };\n',
  });
  const found = ids(await scan(root));
  for (const id of ['deploy/no-env-example', 'deploy/no-lockfile', 'deploy/no-ci', 'deploy/no-tests', 'deploy/no-start-script', 'deploy/hardcoded-localhost', 'deploy/hardcoded-port', 'deploy/dev-migration-in-production', 'deploy/schema-auto-sync']) {
    assert.ok(found.includes(id), id);
  }
});

test('a localhost fallback is not reported', async () => {
  const root = project({ 'server.js': 'const u = process.env.API || "http://localhost:3000";\napp.listen(process.env.PORT || 3000);\n' });
  const found = ids(await scan(root));
  assert.ok(!found.includes('deploy/hardcoded-localhost'));
  assert.ok(!found.includes('deploy/hardcoded-port'));
});

test('upgrade advice picks the nearest stable fix', async () => {
  const { nearestFix } = await import('../dist/rules/dependencies.js');
  assert.equal(nearestFix('4.19.0', ['5.0.0-beta.3', '4.20.0', '4.19.2', '3.0.0']), '4.19.2');
  assert.equal(nearestFix('4.19.0', ['5.0.0-beta.3']), undefined);
});

test('typosquats are flagged, real packages are not', async () => {
  const root = project({ 'package.json': JSON.stringify({ dependencies: { expresss: '1.0.0', preact: '10.0.0', lodash: '4.0.0', axois: '1.0.0' } }) });
  const found = (await scan(root)).findings.filter((f) => f.ruleId === 'deps/possible-typosquat').map((f) => f.message);
  assert.equal(found.length, 2);
});

test('inline suppression, config and custom rules', async () => {
  const root = project({
    '.alil-launch.json': JSON.stringify({ rules: { 'config/tls-verification-off': 'off' }, ignore: ['generated/'], customRules: [{ id: 'no-todo', pattern: 'FIXME', severity: 'low', files: '\\.js$' }] }),
    'a.js': `// alil-launch-ignore\nconst k = "${secrets.stripe}";\nhttps.request({ rejectUnauthorized: false });\n// FIXME later\n`,
    'generated/b.js': `const k = "${secrets.github}";\n`,
  });
  const result = await scan(root);
  assert.ok(!ids(result).includes('secret/stripe-live-key'));
  assert.ok(!ids(result).includes('secret/github-token'));
  assert.ok(!ids(result).includes('config/tls-verification-off'));
  assert.ok(ids(result).includes('custom/no-todo'));
  assert.equal(result.suppressed, 1);
});

test('fingerprints stay the same when a line moves', async () => {
  const a = await scan(project({ 'a.js': `const k = "${secrets.stripe}";\n` }));
  const b = await scan(project({ 'a.js': `\n\n\nconst k = "${secrets.stripe}";\n` }));
  const pick = (r) => r.findings.find((f) => f.ruleId === 'secret/stripe-live-key').fingerprint;
  assert.equal(pick(a), pick(b));
});

test('baseline hides known findings and holds no secrets', () => {
  const root = project({ 'a.js': `const k = "${secrets.stripe}";\n` });
  const run = (...args) => {
    try {
      return { code: 0, out: execFileSync('node', [CLI, root, ...args], { encoding: 'utf8' }) };
    } catch (error) {
      return { code: error.status, out: error.stdout };
    }
  };
  assert.equal(run('--only', 'secrets').code, 1);
  run('--only', 'secrets', '--update-baseline');
  const baseline = readFileSync(join(root, '.alil-launch-baseline.json'), 'utf8');
  assert.ok(!baseline.includes(secrets.stripe));
  assert.equal(run('--only', 'secrets').code, 0);
});

test('score, verdict and SARIF structure', async () => {
  const bad = await scan(project({ 'a.js': `const k = "${secrets.stripe}";\n` }));
  assert.equal(bad.verdict, 'NOT READY');
  assert.ok(bad.score <= 49);
  const sarif = JSON.parse(renderSarif(bad));
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.length > 0);
  for (const r of sarif.runs[0].results) assert.ok(sarif.runs[0].tool.driver.rules.some((x) => x.id === r.ruleId));
});

test('HTML report escapes project content', async () => {
  const result = await scan(project({ 'a.js': 'const a = 1;\n' }));
  result.findings.push({ ...result.findings[0], title: '<script>alert(1)</script>' });
  assert.ok(!renderHtml(result).includes('<script>alert'));
});

test('fix adds safe files, keeps existing content, and is repeatable', async () => {
  const root = project({ '.gitignore': 'dist\n', 'a.js': 'process.env.API_TOKEN;\n', Dockerfile: 'FROM node:22\n' });
  assert.equal(applyFixes(root, true).length, 3);
  assert.ok(!existsSync(join(root, '.env.example')), 'dry run must not write');
  applyFixes(root);
  assert.match(readFileSync(join(root, '.gitignore'), 'utf8'), /^dist\n\.env\n/);
  assert.equal(readFileSync(join(root, '.env.example'), 'utf8'), 'API_TOKEN=\n');
  assert.ok(existsSync(join(root, '.dockerignore')));
  assert.equal(applyFixes(root).length, 0);
});

test('--run reports failing project commands', async () => {
  const root = project({ 'package.json': JSON.stringify({ scripts: { test: 'node -e "process.exit(3)"', build: 'node -e "process.exit(0)"' } }) });
  const found = (await scan(root, { run: true })).findings.filter((f) => f.ruleId === 'run/command-failed');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /npm run test/);
});

test('live checks use content proof, so a catch-all app is not flagged', async () => {
  const exposed = createServer((req, res) => {
    if (req.url === '/.env') { res.setHeader('content-type', 'text/plain'); res.end('DB_PASSWORD=x\n'); return; }
    res.setHeader('content-type', 'text/html');
    res.setHeader('set-cookie', 'sid=1');
    res.end('<html><title>x</title></html>');
  });
  const spa = createServer((req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end('<html><title>x</title><meta name="description" content="x"><meta property="og:title" content="x"></html>');
  });
  await Promise.all([new Promise((r) => exposed.listen(0, r)), new Promise((r) => spa.listen(0, r))]);
  try {
    const live = async (server) => (await scan(project({ 'a.js': '' }), { url: `http://localhost:${server.address().port}`, only: ['live'] })).findings;
    const bad = await live(exposed);
    assert.ok(bad.some((f) => f.ruleId === 'live/sensitive-file-exposed' && f.message.includes('.env')));
    assert.ok(bad.some((f) => f.ruleId === 'live/insecure-cookie'));
    const good = await live(spa);
    assert.ok(!good.some((f) => f.ruleId === 'live/sensitive-file-exposed'));
    assert.ok(good.some((f) => f.ruleId === 'live/soft-404'));
  } finally {
    exposed.close();
    spa.close();
  }
});

test('live checks crawl internal pages and read what they load', async () => {
  const requested = [];
  const html = (body) => `<html><head><title>x</title><meta name="description" content="x"><meta property="og:title" content="x"></head><body>${body}</body></html>`;
  const pages = {
    '/': html(`
      <a href="/about">About</a> <a href="/gone">Old</a> <a href="/private/report">Private</a> <a href="/logout">Out</a> <a href="/busy">Busy</a>
      <a href="https://elsewhere.example/">External</a> <a href="mailto:a@b.dev">Mail</a>
      <script src="https://unpkg.com/some-widget@latest/widget.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js" integrity="sha384-x" crossorigin="anonymous"></script>
      <script src="/static/js/app.js"></script>
      <script src="/wp-content/plugins/contact-form/js/form.js?ver=1.2.3"></script>`),
    '/about': html('<a href="/about/team">Team</a><script src="https://unpkg.com/@scope/icons"></script>'),
    '/about/team': html('Team'),
    '/static/js/': '<html><head><title>Index of /static/js/</title></head><body><a href="app.js">app.js</a></body></html>',
  };
  const server = createServer((req, res) => {
    const path = req.url.split('?')[0];
    requested.push(path);
    if (path === '/robots.txt') { res.setHeader('content-type', 'text/plain'); res.end('User-agent: *\nDisallow: /private\n'); return; }
    if (path === '/busy') { res.statusCode = 503; res.setHeader('retry-after', '1'); res.end(); return; }
    if (path === '/wp-json/wp/v2/users') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify([{ slug: 'admin' }, { slug: 'editor' }])); return; }
    if (path === '/xmlrpc.php') { res.setHeader('content-type', 'text/plain'); res.end('XML-RPC server accepts POST requests only.'); return; }
    if (!pages[path]) { res.statusCode = 404; res.end('nope'); return; }
    res.setHeader('content-type', 'text/html');
    res.end(pages[path]);
  });
  await new Promise((r) => server.listen(0, r));
  try {
    const result = await scan(project({ 'a.js': '' }), { url: `http://localhost:${server.address().port}`, only: ['live'] });
    const found = (id) => result.findings.filter((f) => f.ruleId === id);

    assert.equal(result.pagesChecked, 5, 'home, /about, /gone, /busy and /about/team');
    assert.ok(requested.includes('/about/team'), 'follows links found on internal pages');
    assert.ok(!requested.includes('/private/report'), 'respects robots.txt');
    assert.ok(!requested.includes('/logout'), 'never follows logout links');

    assert.deepEqual(found('live/broken-link').map((f) => f.message), ['/gone returns 404. Linked from /.']);
    assert.equal(found('live/unpinned-script').length, 2);
    assert.ok(found('live/unpinned-script').some((f) => f.message.includes('/about') && f.message.includes('@scope/icons')));
    assert.match(found('live/vulnerable-js-library')[0]?.message ?? '', /jquery@1\.12\.4/);
    const sri = found('live/script-without-integrity');
    assert.equal(sri.length, 1, 'one finding per CDN host');
    assert.match(sri[0].message, /^1 script\(s\) from cdnjs\.cloudflare\.com/, 'the script with an integrity hash is not counted');
    assert.deepEqual(found('live/directory-listing').map((f) => f.message), ['/static/js/ lists its files.']);
    assert.match(found('live/user-enumeration')[0]?.message ?? '', /2 account name\(s\): `admin`, `editor`/);
    assert.equal(found('live/xmlrpc-enabled').length, 1);
  } finally {
    server.close();
  }
});

test('active probes are gated behind authorization and run only non-destructive checks', async () => {
  const methods = [];
  const hostHeaders = [];
  const server = createServer((req, res) => {
    methods.push(req.method);
    if (req.headers['x-forwarded-host']) hostHeaders.push(req.headers['x-forwarded-host']);
    const send = (type, body, status = 200, extra = {}) => { res.writeHead(status, { 'content-type': type, ...extra }); res.end(body); };
    if (req.method === 'OPTIONS') return send('text/plain', '', 204, { allow: 'GET, HEAD, OPTIONS, PUT, DELETE, TRACE' });
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    if (req.url === '/') return send('text/html', `<html><title>x</title><a href="/go?next=https://evil.example/path">next</a><link rel="canonical" href="https://${host}/"><script>fetch("/api/users");fetch("/api/orders/5")</script></html>`);
    if (req.url === '/api/users') return send('application/json', JSON.stringify([{ id: 1, email: 'a@b.dev' }]));
    if (req.url === '/api/orders/5') return send('application/json', JSON.stringify({ error: 'Unauthorized: login required' }), 401);
    send('text/html', 'nope', 404);
  });
  await new Promise((r) => server.listen(0, r));
  const url = `http://localhost:${server.address().port}`;
  try {
    // Without --active: the redirect parameter is still flagged (zero-request analysis), but no probes run.
    const passive = await scan(project({ 'a.js': '' }), { url, only: ['live'] });
    assert.ok(passive.findings.some((f) => f.ruleId === 'live/open-redirect-parameter' && f.message.includes('next')), 'redirect param found passively');
    assert.ok(!passive.findings.some((f) => ['live/host-header-reflected', 'live/risky-http-method', 'live/unauthenticated-endpoint'].includes(f.ruleId)), 'no active findings without --active');
    assert.ok(!methods.includes('OPTIONS') && hostHeaders.length === 0, 'no probes sent without --active');

    const result = await scan(project({ 'a.js': '' }), { url, only: ['live'], active: true });
    const found = (id) => result.findings.filter((f) => f.ruleId === id);
    assert.match(found('live/host-header-reflected')[0]?.message ?? '', /x-forwarded-host|host/i);
    assert.match(found('live/risky-http-method')[0]?.message ?? '', /TRACE/);
    assert.ok(found('live/unauthenticated-endpoint').some((f) => f.message.includes('/api/users')), 'open endpoint flagged');
    assert.ok(!found('live/unauthenticated-endpoint').some((f) => f.message.includes('/api/orders')), '401 endpoint is not flagged');
    assert.ok(methods.every((m) => ['GET', 'HEAD', 'OPTIONS'].includes(m)), 'only safe HTTP methods are used');
  } finally {
    server.close();
  }
});

test('active injection probes detect reflected XSS and error-based SQLi, safely', async () => {
  const probes = [];
  const server = createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    probes.push({ method: req.method, path: u.pathname, q: u.searchParams.get('q'), id: u.searchParams.get('id'), term: u.searchParams.get('term') });
    const send = (type, body, status = 200) => { res.writeHead(status, { 'content-type': type }); res.end(body); };
    if (u.pathname === '/') return send('text/html', '<html><title>x</title><a href="/search?q=hello">s</a><a href="/item?id=1">i</a><form method="get" action="/find"><input name="term"></form></html>');
    if (u.pathname === '/search') return send('text/html', `<html><body>Results for ${u.searchParams.get('q') ?? ''}</body></html>`); // reflects raw -> XSS
    if (u.pathname === '/find') return send('text/html', `<html><body>No match: ${u.searchParams.get('term') ?? ''}</body></html>`); // reflects raw -> XSS
    if (u.pathname === '/item') {
      const id = u.searchParams.get('id') ?? '';
      if (id.includes("'")) return send('text/html', '<html><body>Error: You have an error in your SQL syntax near "\'"</body></html>', 500); // SQLi
      return send('text/html', `<html><body>Item ${id.replace(/[<>]/g, '')}</body></html>`); // escapes, so no XSS
    }
    send('text/html', 'nope', 404);
  });
  await new Promise((r) => server.listen(0, r));
  const url = `http://localhost:${server.address().port}`;
  try {
    const off = await scan(project({ 'a.js': '' }), { url, only: ['live'] });
    assert.ok(!off.findings.some((f) => ['live/reflected-xss', 'live/sql-injection'].includes(f.ruleId)), 'no injection probes without --active');
    assert.ok(probes.every((p) => !String(p.q).includes('<x>') && !String(p.id).includes("'")), 'no payloads sent without --active');

    const result = await scan(project({ 'a.js': '' }), { url, only: ['live'], active: true });
    const found = (id) => result.findings.filter((f) => f.ruleId === id);
    assert.ok(found('live/reflected-xss').some((f) => f.message.includes('`q`')), 'reflected XSS in q');
    assert.ok(found('live/reflected-xss').some((f) => f.message.includes('`term`')), 'reflected XSS in a GET form field');
    assert.ok(found('live/sql-injection').some((f) => f.message.includes('`id`')), 'SQLi in id');
    assert.ok(!found('live/reflected-xss').some((f) => f.message.includes('`id`')), 'escaped param is not flagged as XSS');
    // Safety: only safe methods overall, any payload-carrying request is GET, and no executable markers.
    assert.ok(probes.every((p) => ['GET', 'HEAD', 'OPTIONS'].includes(p.method)), 'only safe HTTP methods are used');
    const payloadReqs = probes.filter((p) => /<x>|'/.test(`${p.q} ${p.id} ${p.term}`));
    assert.ok(payloadReqs.length > 0 && payloadReqs.every((p) => p.method === 'GET'), 'payloads are sent only via GET');
    assert.ok(probes.every((p) => !/<script|onerror=|onload=|javascript:|union select|drop table|sleep\(/i.test(`${p.q} ${p.id} ${p.term}`)), 'no executable or destructive payloads are sent');
  } finally {
    server.close();
  }
});

test('the CLI refuses --active without authorization', () => {
  const run = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  const noAuth = run(['--url', 'https://example.com', '--active']);
  assert.equal(noAuth.status, 2);
  assert.match(noAuth.stderr, /--i-am-authorized/);
  const noUrl = run(['.', '--active', '--i-am-authorized']);
  assert.equal(noUrl.status, 2);
  assert.match(noUrl.stderr, /--active works with --url/);
});

test('passive checks flag weak tokens and reachable login pages, without sending credentials', async () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  // A deliberately unsigned token and a privileged one, as a site might embed in page bootstrap state.
  const noneToken = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: '1', name: 'x' })}.`;
  const adminToken = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: '1', role: 'admin' })}.c2ln`;
  const normalToken = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ sub: '1', scope: 'read:profile' })}.c2ln`;
  const requests = [];
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    const send = (type, body, status = 200) => { res.statusCode = status; res.setHeader('content-type', type); res.end(body); };
    if (req.url === '/') return send('text/html', `<html><title>x</title><script>window.__T={a:"${noneToken}",b:"${adminToken}",c:"${normalToken}"}</script></html>`);
    if (req.url === '/wp-login.php') return send('text/html', '<html><form name="loginform"><input name="log"><input type="password" name="pwd"><input id="wp-submit"></form></html>');
    if (req.url === '/login') return send('text/html', '<html><form><input type="password"></form></html>');
    if (req.url === '/admin') return send('text/html', '<html><body>Welcome to the admin blog section</body></html>'); // no password field: must not be flagged
    send('text/html', 'nope', 404);
  });
  await new Promise((r) => server.listen(0, r));
  try {
    const result = await scan(project({ 'a.js': '' }), { url: `http://localhost:${server.address().port}`, only: ['live'] });
    const found = (id) => result.findings.filter((f) => f.ruleId === id);
    const jwt = found('live/weak-jwt');
    assert.ok(jwt.some((f) => /alg: none/i.test(f.message)), 'unsigned token flagged');
    assert.ok(jwt.some((f) => /`admin` role/.test(f.message)), 'privileged token flagged');
    assert.ok(!jwt.some((f) => f.message.includes('read:profile')), 'a normal scoped token is not flagged');
    assert.ok(!JSON.stringify(result).includes(adminToken), 'tokens are not printed in full');

    const logins = found('live/login-page-exposed');
    assert.ok(logins.some((f) => f.message.includes('/wp-login.php')), 'wp-login detected');
    assert.ok(logins.some((f) => f.message.includes('/login')), 'generic login detected');
    assert.ok(!logins.some((f) => f.message === 'The admin login is reachable at /admin.'), '/admin without a password field is not flagged');
    assert.ok(requests.every((r) => r.startsWith('GET ')), 'only GET; no credential submission');
  } finally {
    server.close();
  }
});

test('live checks read inside scripts, source maps and exposed files', async () => {
  const requested = [];
  const key = secrets.stripe;
  const bundle = `!function(){var a="${key}";fetch("/api/v2/orders/123");fetch("/api/v2/orders/456");var b="http://10.0.4.12:8080/internal";}();\n//# sourceMappingURL=app.js.map`;
  const map = JSON.stringify({
    version: 3,
    mappings: 'AAAA',
    sources: ['webpack:///src/config/db.ts', 'webpack:///src/pages/Home.tsx', 'webpack:///node_modules/jquery/dist/jquery.js'],
    sourcesContent: [`export const db = "postgres://app:${['Sup3r', 'Secret9x'].join('')}@db.prod.example.com:5432/app";\n`, 'export default () => null;\n', '/*! jQuery v1.11.0 | (c) jQuery Foundation */\n'],
  });
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.15' } } });
  const server = createServer((req, res) => {
    const path = req.url.split('?')[0];
    requested.push(`${req.method} ${req.url}`);
    if (req.headers.origin) {
      res.setHeader('access-control-allow-origin', req.headers.origin);
      res.setHeader('access-control-allow-credentials', 'true');
    }
    const send = (type, body, status = 200) => { res.statusCode = status; res.setHeader('content-type', type); res.end(body); };
    if (path === '/') return send('text/html', '<html><title>x</title><script src="/static/app.js"></script></html>');
    if (path === '/static/app.js') return send('application/javascript', bundle);
    if (path === '/static/app.js.map') return send('application/json', map);
    if (path === '/package-lock.json') return send('application/json', lock);
    if (path === '/graphql') return send('application/json', JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'Query' }, { name: 'User' }] } } }));
    if (path.endsWith('.php')) return send('text/html', '<b>Fatal error</b>: Uncaught Error in <b>/var/www/html/index.php</b> on line <b>12</b>', 500);
    send('text/html', 'not found', 404);
  });
  await new Promise((r) => server.listen(0, r));
  try {
    const result = await scan(project({ 'a.js': '' }), { url: `http://localhost:${server.address().port}`, only: ['live'] });
    const found = (id) => result.findings.filter((f) => f.ruleId === id);
    const text = JSON.stringify(result);

    const leaked = found('live/secret-in-javascript');
    assert.ok(leaked.some((f) => f.severity === 'critical' && /Stripe live secret key found in \/static\/app\.js/.test(f.message)), 'secret in a bundle');
    assert.ok(leaked.some((f) => /src\/config\/db\.ts \(from \/static\/app\.js\.map\)/.test(f.message)), 'secret in original source from the map');
    assert.ok(!text.includes(key) && !text.includes('Sup3rSecret9x'), 'secrets stay masked');

    assert.match(found('live/source-map-exposed')[0]?.message ?? '', /expose 2 of your own source file\(s\) with their full original code[\s\S]*src\/config[\s\S]*jquery/);
    assert.match(found('live/vulnerable-js-library')[0]?.message ?? '', /jquery@1\.11\.0/, 'library version read from inside the map');
    assert.ok(found('live/internal-address-leaked').some((f) => f.message.includes('10.0.4.12:8080')));
    assert.match(found('live/api-endpoints-found')[0]?.message ?? '', /1 API path\(s\)[^]*\/api\/v2\/orders\/\{id\}/);
    assert.ok(found('live/sensitive-file-exposed').some((f) => f.message.includes('/package-lock.json')));
    assert.equal(found('live/cors-misconfigured')[0]?.severity, 'high');
    assert.match(found('live/error-details-exposed')[0]?.message ?? '', /PHP error with a server file path/);
    assert.match(found('live/graphql-introspection')[0]?.message ?? '', /2 types/);
    assert.ok(requested.every((r) => r.startsWith('GET ')), 'only GET requests are sent');
    assert.ok(!requested.some((r) => /osv|nvd|retire/i.test(r)) && result.packagesChecked === null, 'no advisory lookups without --online');
  } finally {
    server.close();
  }
});

test('--url with no path checks only the site, not the current folder', async () => {
  const root = project({ 'app.js': `const key = "${secrets.stripe}";\n` });
  const server = createServer((req, res) => { res.setHeader('content-type', 'text/html'); res.end('<html><title>x</title></html>'); });
  await new Promise((r) => server.listen(0, r));
  try {
    const run = (args) => new Promise((resolve) => {
      const child = spawn(process.execPath, [CLI, ...args, '--format', 'json'], { cwd: root });
      let out = '';
      child.stdout.on('data', (d) => (out += d));
      child.on('close', () => resolve(JSON.parse(out)));
    });
    const url = `http://localhost:${server.address().port}`;
    const siteOnly = await run(['--url', url]);
    assert.equal(siteOnly.filesScanned, 0);
    assert.ok(!siteOnly.findings.some((f) => f.ruleId.startsWith('secret/')), 'the folder was scanned');
    const both = await run(['.', '--url', url]);
    assert.ok(both.findings.some((f) => f.ruleId === 'secret/stripe-live-key'), 'a path still scans the folder');
  } finally {
    server.close();
  }
});

test('MCP server lists tools and runs a scan', async () => {
  const root = project({ 'a.js': `const k = "${secrets.stripe}";\n` });
  const child = spawn('node', [CLI, 'mcp'], { stdio: ['pipe', 'pipe', 'inherit'] });
  const replies = [];
  let buffer = '';
  const waitFor = (id) => new Promise((resolve) => {
    const check = () => {
      const hit = replies.find((r) => r.id === id);
      if (hit) resolve(hit); else setTimeout(check, 10);
    };
    check();
  });
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    const lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) replies.push(JSON.parse(line));
  });
  const send = (message) => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
  send({ id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } });
  assert.equal((await waitFor(1)).result.serverInfo.name, 'alil-launch');
  send({ id: 2, method: 'tools/list' });
  assert.ok((await waitFor(2)).result.tools.some((t) => t.name === 'scan_project'));
  send({ id: 3, method: 'tools/call', params: { name: 'scan_project', arguments: { path: root } } });
  const text = (await waitFor(3)).result.content[0].text;
  assert.match(text, /secret\/stripe-live-key/);
  assert.ok(!text.includes(secrets.stripe));
  child.kill();
});

test('assertLaunchReady throws on blocking issues', async () => {
  await assert.rejects(assertLaunchReady(project({ 'a.js': `const k = "${secrets.stripe}";\n` })), /blocking/);
});

test('every rule is complete and has a unique id', () => {
  const rules = allRules();
  assert.equal(new Set(rules.map((r) => r.id)).size, rules.length);
  for (const rule of rules) assert.ok(rule.title && rule.description && rule.fix, rule.id);
});
