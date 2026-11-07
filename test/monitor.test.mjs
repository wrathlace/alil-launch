import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, afterEach, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertLaunchReady, monitor, renderHtml, renderMarkdown, renderPrompt, scan } from '../dist/index.js';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
const created = [];
const realFetch = globalThis.fetch;

function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'lr-monitor-'));
  created.push(root);
  for (const [file, content] of Object.entries(files)) {
    const path = join(root, file);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return root;
}

after(() => created.forEach((root) => rmSync(root, { recursive: true, force: true })));
afterEach(() => { globalThis.fetch = realFetch; });
process.env.NVD_API_KEY = 'test-key';

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const VULN = { id: 'GHSA-aaaa', aliases: ['CVE-2024-0001'], summary: 'Remote code execution', database_specific: { severity: 'HIGH' }, affected: [] };

/**
 * A stand-in for every online source. `packages` maps `ecosystem:name@version` to advisory ids,
 * and anything in `routes` overrides a hostname.
 */
function network({ packages = {}, advisories = { 'GHSA-aaaa': VULN }, kev = [], epss = {}, routes = {} } = {}) {
  const log = { queried: [], urls: [] };
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    log.urls.push(url.href);
    if (routes[url.hostname]) return routes[url.hostname](url, init);
    if (url.hostname === 'api.osv.dev' && url.pathname === '/v1/querybatch') {
      const { queries } = JSON.parse(init.body);
      const keys = queries.map((q) => `${q.package.ecosystem}:${q.package.name}@${q.version}`);
      log.queried.push(...keys);
      return json({ results: keys.map((key) => (packages[key] ? { vulns: packages[key].map((id) => ({ id })) } : {})) });
    }
    if (url.hostname === 'api.osv.dev') {
      const id = decodeURIComponent(url.pathname.split('/').pop());
      return advisories[id] ? json(advisories[id]) : json({}, 404);
    }
    if (url.hostname === 'www.cisa.gov') return json({ vulnerabilities: kev.map((cveID) => ({ cveID })) });
    if (url.hostname === 'api.first.org') return json({ data: Object.entries(epss).map(([cve, score]) => ({ cve, epss: String(score) })) });
    if (url.hostname === 'services.nvd.nist.gov') return json({ vulnerabilities: [] });
    if (url.hostname === 'api.wordpress.org') return json(url.pathname.includes('stable-check') ? {} : { name: 'x' });
    return new Response(null, { status: 200 });
  };
  return log;
}

const down = () => { globalThis.fetch = async () => { throw new TypeError('fetch failed'); }; };
const of = (result, rule) => result.findings.filter((f) => f.ruleId === rule);
const online = { online: true, only: ['dependencies'] };

test('a default scan makes no network requests', async () => {
  globalThis.fetch = async () => { throw new Error('network used'); };
  const result = await scan(project({ 'package.json': '{"dependencies":{"lodash":"4.17.15"}}' }));
  assert.equal(result.packagesChecked, null);
  assert.deepEqual(result.incomplete, []);
});

test('a failed vulnerability check is never reported as ready', async () => {
  down();
  const root = project({ 'requirements.txt': 'django==2.2.0\n' });
  const result = await scan(root, online);
  assert.equal(result.verdict, 'INCOMPLETE');
  assert.equal(result.packagesChecked, 0);
  assert.ok(result.score <= 79);
  assert.match(result.incomplete[0], /1 of 1 packages were not checked/);
  for (const output of [renderMarkdown(result), renderPrompt(result), renderHtml(result)]) assert.match(output, /not checked/i);
  await assert.rejects(assertLaunchReady(root, online), /could not finish/);
});

test('the command exits 2 when a requested check could not finish', () => {
  const root = project({ 'requirements.txt': 'django==2.2.0\n' });
  const hook = join(root, 'down.cjs');
  writeFileSync(hook, "globalThis.fetch = async () => { throw new TypeError('fetch failed'); };\n");
  const run = spawnSync(process.execPath, [CLI, root, '--online', '--only', 'dependencies'], { encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: `--require ${hook}` } });
  assert.equal(run.status, 2);
  assert.match(run.stdout, /INCOMPLETE/);
});

test('a server error is retried before it counts as a failure', async () => {
  let calls = 0;
  const log = network({ routes: {} });
  const fallback = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    if (String(input).endsWith('querybatch') && calls++ === 0) return json({}, 503);
    return fallback(input, init);
  };
  const result = await scan(project({ 'requirements.txt': 'django==2.2.0\n' }), online);
  assert.equal(result.verdict, 'READY');
  assert.equal(log.queried.length, 1);
});

test('every supported lockfile and build file reaches the vulnerability lookup', async () => {
  const log = network();
  await scan(project({
    'uv/uv.lock': '[[package]]\r\nname = "app"\r\nversion = "0.1.0"\r\nsource = { virtual = "." }\r\n\r\n[[package]]\r\nname = "django"\r\nversion = "2.2.0"\r\nsource = { registry = "https://pypi.org/simple" }\r\n',
    'bun/bun.lock': '{\n  "packages": {\n    "lodash": ["lodash@4.17.15", "", {}, "sha512-x"],\n  }\n}\n',
    'dart/pubspec.lock': 'packages:\n  http:\n    dependency: "direct main"\n    description:\n      name: http\n    source: hosted\n    version: "0.13.0"\n',
    'ex/mix.lock': '%{\n  "plug": {:hex, :plug, "1.0.0", "abc", [:mix], [], "hexpm", "def"},\n}\n',
    'gr/gradle.lockfile': 'org.yaml:snakeyaml:1.26=compileClasspath\nempty=\n',
    'net/packages.lock.json': JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' }, Local: { type: 'Project' } } } }),
    'net2/packages.config': '<packages><package id="jQuery" version="1.7.0" /></packages>',
    'net3/a.csproj': '<Project><PackageReference Include="Serilog"><Version>2.0.0</Version></PackageReference></Project>',
  }), online);
  for (const key of ['PyPI:django@2.2.0', 'npm:lodash@4.17.15', 'Pub:http@0.13.0', 'Hex:plug@1.0.0', 'Maven:org.yaml:snakeyaml@1.26', 'NuGet:Newtonsoft.Json@12.0.1', 'NuGet:jQuery@1.7.0', 'NuGet:Serilog@2.0.0']) {
    assert.ok(log.queried.includes(key), `${key} was not looked up: ${log.queried}`);
  }
  assert.ok(!log.queried.includes('PyPI:app@0.1.0'), 'the project itself is not a dependency');
});

test('Maven versions resolve from properties and dependencyManagement', async () => {
  const log = network();
  const result = await scan(project({
    'pom.xml': `<project>
      <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.5.0</version></parent>
      <properties><jackson.version>2.9.0</jackson.version></properties>
      <!-- <dependency><groupId>x</groupId><artifactId>commented</artifactId><version>1.0</version></dependency> -->
      <dependencyManagement><dependencies>
        <dependency><groupId>a</groupId><artifactId>managed</artifactId><version>1.2.3</version></dependency>
      </dependencies></dependencyManagement>
      <dependencies>
        <dependency><groupId>a</groupId><artifactId>managed</artifactId></dependency>
        <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>\${jackson.version}</version></dependency>
        <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
      </dependencies>
    </project>`,
  }), online);
  assert.deepEqual(log.queried.sort(), ['Maven:a:managed@1.2.3', 'Maven:com.fasterxml.jackson.core:jackson-databind@2.9.0', 'Maven:org.springframework.boot:spring-boot-starter-parent@2.5.0']);
  const [unchecked] = of(result, 'deps/unchecked-dependency');
  assert.equal(unchecked.severity, 'medium');
  assert.match(unchecked.message, /spring-boot-starter-web/);
});

test('Gradle build files and version catalogs are read', async () => {
  const log = network();
  await scan(project({
    'build.gradle': "dependencies {\n  implementation 'org.apache.commons:commons-text:1.9'\n  implementation \"org.foo:bar:$ver\"\n}\n",
    'app/build.gradle.kts': 'dependencies { testImplementation("junit:junit:4.12") }\n',
    'gradle/libs.versions.toml': '[versions]\nguava = "30.0-jre"\n\n[libraries]\nguava = { module = "com.google.guava:guava", version.ref = "guava" }\nnetty = "io.netty:netty-all:4.1.0.Final"\nsplit = { group = "a.b", name = "c", version = "1.0" }\n',
  }), online);
  for (const key of ['Maven:org.apache.commons:commons-text@1.9', 'Maven:junit:junit@4.12', 'Maven:com.google.guava:guava@30.0-jre', 'Maven:io.netty:netty-all@4.1.0.Final', 'Maven:a.b:c@1.0']) {
    assert.ok(log.queried.includes(key), key);
  }
});

test('dependencies with no known version are reported, and pinned ones are still checked', async () => {
  const log = network({ packages: { 'npm:lodash@4.17.15': ['GHSA-aaaa'] } });
  const result = await scan(project({ 'package.json': '{"dependencies":{"lodash":"4.17.15","axios":"^1.0.0","local":"file:../x"}}' }), online);
  assert.deepEqual(log.queried, ['npm:lodash@4.17.15']);
  assert.equal(of(result, 'deps/known-vulnerability').length, 1);
  const [unchecked] = of(result, 'deps/unchecked-dependency');
  assert.equal(unchecked.severity, 'high');
  assert.match(unchecked.message, /1 of 2 direct dependencies .*axios/);
});

test('version ranges and other manifests without a lockfile are reported', async () => {
  network();
  const result = await scan(project({
    'py/requirements.txt': 'Django>=2.2,<3\nrequests==2.19.0  # pinned\ngit+https://example.dev/a.git\n-r base.txt\n',
    'pep/pyproject.toml': '[project]\nname = "x"\ndependencies = [\n  "flask>=2",\n]\n',
    'poetry/pyproject.toml': '[tool.poetry.dependencies]\npython = "^3.11"\nfastapi = "^0.100"\n',
    'php/composer.json': '{"require":{"php":">=8.1","laravel/framework":"^10.0"}}',
    'rb/Gemfile': "gem 'rails', '~> 7.0'\n",
    'rs/Cargo.toml': '[package]\nname = "x"\n\n[dependencies]\nserde = "1"\n',
  }), online);
  const messages = of(result, 'deps/unchecked-dependency').map((f) => `${f.file} ${f.message}`).join('\n');
  for (const name of ['py/requirements.txt.*Django', 'pep/pyproject.toml.*flask', 'poetry/pyproject.toml.*fastapi', 'php/composer.json.*laravel/framework', 'rb/Gemfile.*rails', 'rs/Cargo.toml.*serde']) {
    assert.match(messages, new RegExp(name));
  }
  assert.doesNotMatch(messages, /\bgit\b|python|php,/);
});

test('a URL in requirements.txt is not mistaken for a package name', async () => {
  network({ routes: { 'pypi.org': () => new Response(null, { status: 404 }) } });
  const result = await scan(project({ 'requirements.txt': 'git+https://example.dev/a.git\nhttps://example.dev/b.whl\n' }), online);
  assert.deepEqual(of(result, 'deps/package-does-not-exist'), []);
});

test('a lockfile silences the missing version report', async () => {
  network();
  const result = await scan(project({
    'package.json': '{"dependencies":{"axios":"^1.0.0"}}',
    'package-lock.json': JSON.stringify({ packages: { 'node_modules/axios': { version: '1.0.0' } } }),
    'apps/web/package.json': '{"dependencies":{"react":"^18.0.0"}}',
  }), online);
  assert.deepEqual(of(result, 'deps/unchecked-dependency'), []);
});

test('lockfiles over the scan size limit are still read', async () => {
  const log = network();
  const filler = Object.fromEntries(Array.from({ length: 40_000 }, (_, i) => [`node_modules/p${i}`, { version: '1.0.0', integrity: 'sha512-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }]));
  await scan(project({ 'package-lock.json': JSON.stringify({ packages: filler }) }), online);
  assert.equal(log.queried.length, 40_000);
});

test('CVE ids replace duplicate advisory ids, and exploited CVEs become critical', async () => {
  const twin = { ...VULN, id: 'PYSEC-1' };
  network({
    packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa', 'PYSEC-1', 'GHSA-low'] },
    advisories: { 'GHSA-aaaa': VULN, 'PYSEC-1': twin, 'GHSA-low': { id: 'GHSA-low', aliases: ['CVE-2024-0002'], summary: 'Harmless thing', database_specific: { severity: 'LOW' } } },
    kev: ['CVE-2024-0001'],
  });
  const result = await scan(project({ 'requirements.txt': 'django==2.2.0\n' }), online);
  const [finding] = of(result, 'deps/known-vulnerability');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.exploited, true);
  assert.deepEqual(finding.advisories, ['CVE-2024-0001', 'CVE-2024-0002']);
  assert.match(finding.message, /Actively exploited, per CISA: CVE-2024-0001/);
  assert.match(finding.message, /Remote code execution/, 'the summary describes the worst advisory');
});

test('a high EPSS score raises the severity, and a low one does not', async () => {
  const medium = (id, cve) => ({ id, aliases: [cve], database_specific: { severity: 'MODERATE' } });
  network({
    packages: { 'PyPI:a@1.0.0': ['GHSA-a'], 'PyPI:b@1.0.0': ['GHSA-b'] },
    advisories: { 'GHSA-a': medium('GHSA-a', 'CVE-2024-1000'), 'GHSA-b': medium('GHSA-b', 'CVE-2024-2000') },
    epss: { 'CVE-2024-1000': 0.8, 'CVE-2024-2000': 0.01 },
  });
  const result = await scan(project({ 'requirements.txt': 'aaaaa==1.0.0\n'.replace('aaaaa', 'a') + 'b==1.0.0\n' }), online);
  const [a, b] = of(result, 'deps/known-vulnerability');
  assert.equal(a.severity, 'high');
  assert.match(a.message, /80% chance of exploitation/);
  assert.equal(b.severity, 'medium');
});

test('losing exploit data is reported, but the vulnerability still is too', async () => {
  const unavailable = () => json({}, 503);
  network({
    packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa'] },
    routes: { 'www.cisa.gov': unavailable, 'raw.githubusercontent.com': unavailable, 'api.first.org': unavailable },
  });
  const result = await scan(project({ 'requirements.txt': 'django==2.2.0\n' }), online);
  assert.equal(of(result, 'deps/known-vulnerability').length, 1);
  assert.match(result.incomplete.join(' '), /actively exploited/);
  assert.match(result.incomplete.join(' '), /likelihood/);
});

test('the KEV catalog falls back to its mirror', async () => {
  network({
    packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa'] },
    routes: {
      'www.cisa.gov': () => json({}, 403),
      'raw.githubusercontent.com': () => json({ vulnerabilities: [{ cveID: 'CVE-2024-0001' }] }),
    },
  });
  const result = await scan(project({ 'requirements.txt': 'django==2.2.0\n' }), online);
  assert.equal(of(result, 'deps/known-vulnerability')[0].severity, 'critical');
  assert.deepEqual(result.incomplete, []);
});

test('Drupal core and contrib modules are found, and severity comes from the GitHub twin', async () => {
  const drupal = { id: 'DRUPAL-CORE-2024-001', aliases: ['CVE-2024-0003', 'GHSA-twin'], summary: 'Access bypass' };
  const log = network({
    packages: { 'Packagist:drupal/core@10.1.0': ['DRUPAL-CORE-2024-001'] },
    advisories: { 'DRUPAL-CORE-2024-001': drupal, 'GHSA-twin': { id: 'GHSA-twin', database_specific: { severity: 'CRITICAL' } } },
  });
  const result = await scan(project({
    'web/core/lib/Drupal.php': "<?php\nclass Drupal {\n  const VERSION = '10.1.0';\n}\n",
    'web/modules/contrib/webform/webform.info.yml': "name: Webform\nversion: '8.x-5.2'\n",
    'web/modules/contrib/token/token.info.yml': "name: Token\nversion: 1.13.0\n",
    'web/modules/contrib/dev/dev.info.yml': 'name: Dev\n',
    'web/modules/custom/mine/mine.info.yml': "name: Mine\nversion: '1.0'\n",
  }), online);
  assert.ok(log.queried.includes('Packagist:drupal/webform@5.2.0'));
  assert.ok(log.queried.includes('Packagist:drupal/token@1.13.0'));
  assert.ok(!log.queried.some((key) => key.includes('mine')));
  assert.equal(of(result, 'deps/known-vulnerability')[0].severity, 'critical');
  assert.match(of(result, 'deps/unchecked-dependency')[0].file, /dev\.info\.yml/);
  assert.ok(result.stack.frameworks.includes('drupal'));
});

test('Drupal 7 is looked up under both of its package names', async () => {
  const log = network();
  await scan(project({ 'includes/bootstrap.inc': "<?php\ndefine('VERSION', '7.98');\n" }), online);
  assert.ok(log.queried.includes('Packagist:drupal/core@7.98') && log.queried.includes('Packagist:drupal/drupal@7.98'));
});

const nvdRow = (id, criteria, extra = {}) => ({
  cve: {
    id,
    descriptions: [{ lang: 'en', value: `${id} is a flaw. More detail.` }],
    metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'HIGH' } }] },
    configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria, ...extra }] }] }],
  },
});

const WORDPRESS = {
  'wp-includes/version.php': "<?php\n$wp_version = '6.1.1';\n",
  'wp-content/plugins/woo-commerce/woocommerce.php': '<?php\n/**\n * Plugin Name: WooCommerce\n * Version: 5.0.0\n */\n',
  'wp-content/plugins/old-thing/old-thing.php': '<?php\n/*\nPlugin Name: Old Thing\nVersion: 1.0\n*/\n',
  'wp-content/plugins/woo-commerce/includes/helper.php': '<?php // no header here\n',
  'wp-content/themes/shiny/style.css': '/*\nTheme Name: Shiny\nVersion: 2.0\n*/\n',
};

function wordpressRoutes(rows, seen = []) {
  return {
    'services.nvd.nist.gov': (url) => {
      const cpe = url.searchParams.get('virtualMatchString');
      seen.push(cpe);
      return json({ vulnerabilities: rows.filter((row) => row.cve.configurations[0].nodes[0].cpeMatch[0].criteria.split(':')[4] === cpe.split(':')[4]) });
    },
    'api.wordpress.org': (url) => {
      if (url.pathname.includes('stable-check')) return json({ '6.1.1': 'insecure' });
      if (url.search.includes('old-thing')) return json({ error: 'closed', closed: true, reason_text: 'Security Issue' }, 404);
      return json({ error: 'not found' }, 404);
    },
  };
}

test('WordPress core, plugins and themes are looked up by CPE', async () => {
  const seen = [];
  network({
    routes: wordpressRoutes([
      nvdRow('CVE-2023-0001', 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*', { versionEndExcluding: '6.2' }),
      nvdRow('CVE-2023-0002', 'cpe:2.3:a:woocommerce:woo_commerce:*:*:*:*:*:wordpress:*:*', { versionEndExcluding: '5.2.0' }),
    ], seen),
  });
  const result = await scan(project(WORDPRESS), online);
  for (const cpe of ['cpe:2.3:a:wordpress:wordpress:6.1.1', 'cpe:2.3:a:*:woo-commerce:5.0.0:*:*:*:*:wordpress:*:*', 'cpe:2.3:a:*:woo_commerce:5.0.0:*:*:*:*:wordpress:*:*', 'cpe:2.3:a:*:shiny:2.0:*:*:*:*:wordpress:*:*']) {
    assert.ok(seen.includes(cpe), cpe);
  }
  const messages = of(result, 'deps/known-vulnerability').map((f) => f.message).join('\n');
  assert.match(messages, /WordPress@6\.1\.1: CVE-2023-0001.*Upgrade to 6\.2/);
  assert.match(messages, /woo-commerce@5\.0\.0: CVE-2023-0002/);
  assert.match(of(result, 'deps/insecure-platform-version')[0].message, /6\.1\.1/);
  assert.match(of(result, 'deps/closed-plugin')[0].message, /old-thing.*Security Issue/);
  assert.equal(result.packagesChecked, 4);
  assert.deepEqual(result.incomplete, []);
  assert.ok(result.stack.frameworks.includes('wordpress'));
});

test('NVD results for another product or a fixed version are dropped', async () => {
  network({
    routes: wordpressRoutes([
      nvdRow('CVE-2023-0003', 'cpe:2.3:a:phpmailer_project:wordpress:*:*:*:*:*:*:*:*'),
      nvdRow('CVE-2023-0004', 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*', { versionEndExcluding: '6.0' }),
      nvdRow('CVE-2023-0005', 'cpe:2.3:a:wordpress:wordpress:6.0:*:*:*:*:*:*:*'),
    ]),
  });
  const result = await scan(project({ 'wp-includes/version.php': "<?php\n$wp_version = '6.1.1';\n" }), online);
  assert.deepEqual(of(result, 'deps/known-vulnerability'), []);
});

test('WordPress packages installed through Composer are found', async () => {
  const seen = [];
  network({ routes: wordpressRoutes([], seen) });
  await scan(project({
    'composer.lock': JSON.stringify({ packages: [
      { name: 'roots/wordpress', version: '6.1.1' },
      { name: 'wpackagist-plugin/akismet', version: '5.0' },
      { name: 'wpackagist-theme/twentytwenty', version: '1.0' },
    ] }),
  }), online);
  assert.ok(seen.includes('cpe:2.3:a:wordpress:wordpress:6.1.1'));
  assert.ok(seen.includes('cpe:2.3:a:*:akismet:5.0:*:*:*:*:wordpress:*:*'));
  assert.ok(seen.includes('cpe:2.3:a:*:twentytwenty:1.0:*:*:*:*:wordpress:*:*'));
});

test('Joomla and Nextcloud versions are read from their source files', async () => {
  const seen = [];
  network({ routes: wordpressRoutes([], seen) });
  await scan(project({
    'libraries/src/Version.php': '<?php\nfinal class Version {\n  public const MAJOR_VERSION = 4;\n  public const MINOR_VERSION = 2;\n  public const PATCH_VERSION = 8;\n}\n',
    'nextcloud/version.php': "<?php\n$OC_VersionString = '27.1.3';\n",
  }), online);
  assert.ok(seen.includes('cpe:2.3:a:joomla:joomla\\!:4.2.8'));
  assert.ok(seen.includes('cpe:2.3:a:nextcloud:nextcloud_server:27.1.3'));
});

test('a plugin with no version, or an unsafe name, never reaches a query', async () => {
  const seen = [];
  network({ routes: wordpressRoutes([], seen) });
  const result = await scan(project({
    'wp-content/plugins/noversion/noversion.php': '<?php\n/*\nPlugin Name: No Version\n*/\n',
    'wp-content/plugins/BAD NAME/bad.php': '<?php\n/*\nPlugin Name: Bad\nVersion: 1.0\n*/\n',
  }), online);
  assert.deepEqual(seen, []);
  assert.match(of(result, 'deps/unchecked-dependency')[0].file, /noversion/);
});

test('NVD failures leave the scan incomplete', async () => {
  network({ routes: { ...wordpressRoutes([]), 'services.nvd.nist.gov': () => json({}, 404) } });
  const result = await scan(project({ 'wp-includes/version.php': "<?php\n$wp_version = '6.2';\n" }), online);
  assert.equal(result.verdict, 'INCOMPLETE');
  assert.match(result.incomplete.join(' '), /not checked against the NVD: WordPress/);
});

test('monitoring reports only what changed', async () => {
  const root = project({ 'requirements.txt': 'django==2.2.0\n', 'poetry.lock': '' });
  const state = join(root, '.alil-launch-monitor.json');
  const packages = { 'PyPI:django@2.2.0': ['GHSA-aaaa'] };
  network({ packages });

  const first = await monitor(root);
  assert.equal(first.firstRun, true);
  assert.equal(first.fresh.length, 1);
  assert.equal(first.exitCode, 1);

  const second = await monitor(root);
  assert.equal(second.fresh.length, 0);
  assert.equal(second.open.length, 1, 'still open, but not new');
  assert.equal(second.exitCode, 0);

  // The same version gets a brand new CVE.
  const later = { ...VULN, id: 'GHSA-bbbb', aliases: ['CVE-2024-9999'] };
  network({ packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa', 'GHSA-bbbb'] }, advisories: { 'GHSA-aaaa': VULN, 'GHSA-bbbb': later } });
  const third = await monitor(root);
  assert.equal(third.fresh.length, 0);
  assert.deepEqual(third.changed[0].advisories, ['CVE-2024-9999']);
  assert.equal(third.exitCode, 1);

  // An existing CVE is now being exploited.
  network({ packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa', 'GHSA-bbbb'] }, advisories: { 'GHSA-aaaa': VULN, 'GHSA-bbbb': later }, kev: ['CVE-2024-0001'] });
  const fourth = await monitor(root);
  assert.equal(fourth.changed[0].nowExploited, true);
  assert.equal(fourth.exitCode, 1);

  writeFileSync(join(root, 'requirements.txt'), 'django==5.2.17\n');
  network();
  const fifth = await monitor(root);
  assert.equal(fifth.resolved[0].label, 'django@2.2.0');
  assert.equal(fifth.exitCode, 0);
  assert.deepEqual(JSON.parse(readFileSync(state, 'utf8')).findings, {});
});

test('an upgrade to a version that is still vulnerable alerts again', async () => {
  const root = project({ 'requirements.txt': 'django==2.2.0\n' });
  network({ packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa'], 'PyPI:django@3.0.0': ['GHSA-aaaa'] } });
  await monitor(root);
  writeFileSync(join(root, 'requirements.txt'), 'django==3.0.0\n');
  const run = await monitor(root);
  assert.equal(run.fresh.length, 1);
  assert.equal(run.resolved.length, 1);
});

test('an outage does not mark anything as resolved', async () => {
  const root = project({ 'requirements.txt': 'django==2.2.0\n' });
  network({ packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa'] } });
  await monitor(root);

  down();
  const outage = await monitor(root);
  assert.equal(outage.exitCode, 2);
  assert.deepEqual(outage.resolved, []);

  network({ packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa'] } });
  const back = await monitor(root);
  assert.deepEqual(back.fresh, [], 'nothing should look new after an outage');
  assert.equal(back.exitCode, 0);
});

test('alerts below the threshold stay quiet, but are still remembered', async () => {
  const low = { ...VULN, database_specific: { severity: 'LOW' } };
  const root = project({ 'requirements.txt': 'django==2.2.0\n' });
  network({ packages: { 'PyPI:django@2.2.0': ['GHSA-aaaa'] }, advisories: { 'GHSA-aaaa': low } });
  const run = await monitor(root, { failOn: 'high' });
  assert.equal(run.fresh.length >= 1, true);
  assert.equal(run.exitCode, 0);
});

test('secrets are watched, and their values never reach state or alerts', async () => {
  const value = ['sk', 'live', 'q7Xk2Lm9Pz4Rt8Vn1Bc6Wd3Y'].join('_');
  const root = project({ 'app.js': `const key = "${value}";\n` });
  let posted = '';
  network({ routes: { 'hooks.example.dev': async (_url, init) => { posted = init.body; return new Response('ok'); } } });
  const run = await monitor(root, { webhook: 'https://hooks.example.dev/x' });
  assert.ok(run.fresh.some((f) => f.ruleId.startsWith('secret/')));
  assert.ok(posted.length > 0);
  assert.ok(!posted.includes(value));
  assert.ok(!readFileSync(join(root, '.alil-launch-monitor.json'), 'utf8').includes(value));
});

test('webhooks fire only for new issues, and a failed one alerts again next time', async () => {
  const root = project({ 'requirements.txt': 'django==2.2.0\n' });
  const packages = { 'PyPI:django@2.2.0': ['GHSA-aaaa'] };
  const bodies = [];
  let healthy = false;
  const routes = {
    'hooks.example.dev': async (_url, init) => {
      if (!healthy) return new Response('nope', { status: 500 });
      bodies.push(JSON.parse(init.body));
      return new Response('ok');
    },
  };
  network({ packages, routes });
  await assert.rejects(monitor(root, { webhook: 'https://hooks.example.dev/x' }), /webhook returned 500/);

  healthy = true;
  await monitor(root, { webhook: 'https://hooks.example.dev/x' });
  assert.equal(bodies.length, 1, 'the alert was not lost');
  assert.match(bodies[0].text, /CVE-2024-0001/);
  assert.equal(bodies[0].content, bodies[0].text);

  await monitor(root, { webhook: 'https://hooks.example.dev/x' });
  assert.equal(bodies.length, 1, 'no repeat alert');
});

test('a damaged state file stops the run instead of alerting on everything', async () => {
  const root = project({ '.alil-launch-monitor.json': '{ broken' });
  network();
  await assert.rejects(monitor(root), /state is damaged/);
});

test('a git URL that cannot be cloned fails cleanly and hides its credentials', () => {
  const url = 'https://user:hunter2@example.invalid/x.git';
  const run = spawnSync(process.execPath, [CLI, 'monitor', url], { encoding: 'utf8', env: { ...process.env, GIT_ALLOW_PROTOCOL: 'none' } });
  assert.equal(run.status, 2);
  assert.ok(run.stderr.includes('Could not clone https://example.invalid/x.git'), run.stderr);
  assert.ok(!run.stderr.includes('hunter2'));
});

test('monitor renders pretty, markdown and json, and rejects other formats', () => {
  const root = project({ 'readme.txt': 'hello\n' });
  const hook = join(root, 'stub.cjs');
  writeFileSync(hook, 'globalThis.fetch = async () => new Response(JSON.stringify({ results: [], vulnerabilities: [], data: [] }));\n');
  const env = { ...process.env, NODE_OPTIONS: `--require ${hook}` };
  const cli = (...args) => spawnSync(process.execPath, [CLI, 'monitor', root, ...args], { encoding: 'utf8', env });
  assert.match(cli().stdout, /No open issues at high or above/);
  assert.match(cli('--format', 'markdown').stdout, /## Alil Launch monitor/);
  assert.equal(JSON.parse(cli('--format', 'json').stdout).exitCode, 0);
  assert.equal(cli('--format', 'sarif').status, 2);
  assert.equal(spawnSync(process.execPath, [CLI, 'monitor', root, root, '--state', 'x'], { encoding: 'utf8', env }).status, 2);
  assert.equal(cli('--every', '0.1').status, 2);
});

test('bad command line input fails with a clear message', () => {
  const root = project({ 'a.txt': 'hello\n' });
  const hook = join(root, 'stub.cjs');
  writeFileSync(hook, 'globalThis.fetch = async () => { throw new Error("network used"); };\n');
  const cli = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: `--require ${hook}` } });

  const typo = cli(root, '--only', 'secrts');
  assert.equal(typo.status, 2);
  assert.match(typo.stderr, /Unknown --only category: secrts/);
  assert.equal(cli(root, '--only', 'secrets,config').status, 0);
  assert.equal(cli('monitor', root, '--only', 'secrts').status, 2);

  const explain = cli('explain');
  assert.equal(explain.status, 2);
  assert.match(explain.stderr, /Usage: alil-launch explain/);
  assert.doesNotMatch(explain.stderr, /undefined/);

  assert.equal(cli('monitor', root, '--every', '1000').status, 2);
});

test('a bad monitor format stops before state is saved, so no alert is lost', () => {
  const root = project({ 'a.txt': 'hello\n' });
  const run = spawnSync(process.execPath, [CLI, 'monitor', root, '--format', 'sarif'], { encoding: 'utf8' });
  assert.equal(run.status, 2);
  assert.throws(() => readFileSync(join(root, '.alil-launch-monitor.json')));
});

test('init adds the monitor workflow with expressions left for GitHub to fill in', () => {
  const root = project({});
  execFileSync(process.execPath, [CLI, 'init', root]);
  const workflow = readFileSync(join(root, '.github/workflows/alil-launch-monitor.yml'), 'utf8');
  assert.match(workflow, /cron:/);
  assert.match(workflow, /issues: write/);
  assert.match(workflow, /\$\{\{ secrets\.ALIL_LAUNCH_WEBHOOK \}\}/);
  assert.match(workflow, /\$\{\{ github\.run_id \}\}/);
  assert.match(workflow, /monitor --format markdown/);
  assert.match(readFileSync(join(root, '.github/workflows/alil-launch.yml'), 'utf8'), /--online/);
});
