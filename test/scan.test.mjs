import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
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
  });
  assert.deepEqual(ids(await scan(root)).filter((id) => id.startsWith('secret/')), []);
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
