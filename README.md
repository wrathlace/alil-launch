# Alil Launch

**A lil check before you launch.**

```bash
npx alil-launch
```

No install, no account, no config. It works in any project, whatever language it's written in, and your code never leaves your machine.

Alil Launch checks the things that actually go wrong on launch day: API keys in your code, a database with no backups, a `.env` file in git, a Docker socket exposed to a container, a Supabase table anyone can read. You get a score, a clear verdict, and the fix for each problem.

```
  Alil Launch v0.1.0
  8 files scanned in 0.2s · javascript, express, next, react, postgres, supabase

  NOT READY   0/100  grade F

  secrets       ██░░░░░░░░░░░░░░░░░░   8  7 found
  config        ░░░░░░░░░░░░░░░░░░░░   2  14 found
  dependencies  ███████████████░░░░░  75  2 found
  backups       ███████████████░░░░░  75  2 found
  deployment    ████████░░░░░░░░░░░░  39  10 found
  launch        ████████████░░░░░░░░  60  12 found

  CRITICAL Supabase table without row level security config/supabase-rls-missing
           supabase/migrations/001_init.sql:1
           Table `profiles` has no row level security.
           Fix: Run `alter table <name> enable row level security;` and add policies.
```

Try it now on a deliberately broken sample project. It's safe and leaves nothing behind:

```bash
npx alil-launch demo
```

## What it checks

| Area | Examples |
|---|---|
| **Secrets** | 38 credential types (AWS, Stripe, OpenAI, Anthropic, GitHub and more), hardcoded passwords, `.env` files in git, secrets in git history |
| **Unsafe settings** | Debug mode, CORS mistakes, disabled TLS checks, SQL and command injection, weak JWT setups, open Firebase rules, public buckets |
| **Containers and CI** | Root containers, secrets in images, exposed Docker sockets, open database ports, risky GitHub Actions |
| **Backups** | No backup setup, no restore plan, database dumps in the repo, databases with no persistent volume, SQLite on serverless hosts |
| **Deployment** | Missing lockfiles, undocumented env vars, hardcoded localhost and ports, destructive migrations in production, no CI or tests |
| **Launch readiness** | Health checks, error monitoring, rate limiting, privacy policy, robots.txt, 404 page, social previews |
| **Your live site** | HTTPS, old TLS versions, certificate expiry, security headers, weak CSP and HSTS, CORS, cookies. About 100 sensitive paths, such as `.env`, `.git`, backups, logs, lockfiles, phpMyAdmin, Spring actuator, API docs and GraphQL introspection. Up to 50 internal pages (`--pages` to change) and every script they load: credentials shipped to browsers, public source maps and the original code inside them, internal addresses, API endpoints, debug pages, mixed content, unpinned or unhashed CDN scripts, vulnerable libraries, directory listings and broken links. Weak JSON Web Tokens and reachable admin or login pages. WordPress account names and XML-RPC. With `--online`, CVEs for the server software, CMS, plugins, themes, front-end libraries (using the [Retire.js](https://github.com/RetireJS/retire.js) database, so versions inside bundles are found too) and any exposed lockfile |
| **Known vulnerabilities** | CVEs in your dependencies and CMS, with active exploitation flagged. Needs `--online` |

Run `npx alil-launch rules` to see all of them.

## Built for AI-assisted coding

AI tools write working code fast, and they repeat certain mistakes. Alil Launch looks for those specifically:

- **Supabase tables without row level security**, where the public key can read the whole table
- **Secrets in `NEXT_PUBLIC_` and `VITE_` variables**, which are compiled into browser code
- **AI keys in the browser**, such as `dangerouslyAllowBrowser: true`
- **Packages that don't exist.** AI tools sometimes invent package names, and attackers register them. `--online` checks that each one is real
- **Destructive migration commands** such as `prisma migrate reset` in deployment scripts

### Let your AI agent fix it

Print a task list to paste into any AI coding tool:

```bash
npx alil-launch --format prompt
```

Or connect Alil Launch as an MCP server, so tools like Claude Code and Cursor can run scans themselves:

```json
{
  "mcpServers": {
    "alil-launch": { "command": "npx", "args": ["-y", "alil-launch", "mcp"] }
  }
}
```

Findings never include secret values, so it's safe to hand results to an AI tool.

## Deeper checks

These are off by default, so a plain scan stays fast and fully offline.

```bash
npx alil-launch --url https://myapp.com   # Check your live site
npx alil-launch --online                  # Known CVEs and non-existent packages
npx alil-launch --history                 # Secrets anywhere in git history
npx alil-launch --run                     # Run your own build, lint and test commands
```

On its own, `--url` checks only the website and reads no files, so it works from any folder. To check a project and its site together, add the path: `npx alil-launch . --url https://myapp.com`.

Only use `--url` on sites you own or have permission to test. It sends only GET requests, the way a browser or search engine would: it requests about 100 common sensitive paths, follows up to 50 internal links two at a time, downloads the scripts and source maps those pages load, and sends one request with a foreign `Origin` header to test CORS. It respects `robots.txt`, never follows logout, delete or checkout links, and never sends attack payloads. With `--online` it also sends the names and versions of what it found to OSV, the NVD and wordpress.org, and downloads the Retire.js database from GitHub.

`--online` sends package and plugin names and versions to [OSV](https://osv.dev), the [NVD](https://nvd.nist.gov), npm, PyPI and wordpress.org, and CVE ids to [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST](https://www.first.org/epss/). It never sends your code. Private package names are included, so don't use it if a name itself is confidential.

`--run` executes the commands in your project, so use it only on code you trust.

## Known vulnerabilities

`--online` looks up every package it can find a version for:

| Platform | Read from | Checked against |
|---|---|---|
| **JavaScript** | npm, yarn, pnpm and bun lockfiles | OSV |
| **Python** | `poetry.lock`, `uv.lock`, `Pipfile.lock`, pinned requirements | OSV |
| **Java and Kotlin** | `pom.xml`, Gradle build files, version catalogs, `gradle.lockfile` | OSV |
| **PHP** | `composer.lock` | OSV |
| **.NET** | `packages.lock.json`, project files, `packages.config` | OSV |
| **Go, Rust, Ruby, Dart, Elixir** | `go.mod`, `Cargo.lock`, `Gemfile.lock`, `pubspec.lock`, `mix.lock` | OSV |
| **Drupal** | Core, contrib modules and themes, as files or through Composer | OSV |
| **Shopware, Magento, Laravel, TYPO3** | `composer.lock` | OSV |
| **WordPress** | Core, plugins and themes, as files or through Composer | NVD and wordpress.org |
| **Joomla, Nextcloud** | The version in their source files | NVD |

Findings show the CVE ids and the version to upgrade to. Anything in CISA's list of actively exploited vulnerabilities becomes critical, and a high [EPSS](https://www.first.org/epss/) score raises a finding to at least high.

Two limits are worth knowing:

- **Without a lockfile, only direct dependencies can be checked**, and only if they have an exact version. Alil Launch reports what it couldn't check, so a missing lockfile never looks like a clean result. Maven has no lockfile, so its transitive dependencies aren't covered.
- **WordPress plugin coverage depends on the NVD**, which is slower to list new plugin issues than specialist databases, and misses some plugins. Paid and private plugins may not appear at all. wordpress.org also tells us if a plugin was closed.

The NVD limits anonymous lookups, so a site with many plugins can take a few minutes. A free [API key](https://nvd.nist.gov/developers/request-an-api-key) in `NVD_API_KEY` makes this about ten times faster.

## Keep watching after launch

New CVEs appear for code you haven't touched. `monitor` remembers what it saw last time and tells you only what's new:

```bash
npx alil-launch monitor
```

It reports a new issue, a new CVE in a package you already had, an old CVE that's now being actively exploited, and anything you've fixed. It watches for secrets, unsafe settings and vulnerabilities, plus your live site if you add `--url`.

**On GitHub:** `npx alil-launch init` adds a workflow that runs every day. It opens an issue when something needs attention, updates it as things change, and closes it when everything is fixed. Add `ALIL_LAUNCH_WEBHOOK` and `NVD_API_KEY` as repository secrets if you want them.

**On your own server or another CI:**

```bash
npx alil-launch monitor --every 24                 # Keep running, checking once a day
npx alil-launch monitor --webhook https://hooks.slack.com/services/...
npx alil-launch monitor . ../api https://github.com/me/site.git
```

Git URLs are cloned with your own git credentials, scanned and deleted. `--webhook` works with Slack, Discord and Teams.

What it remembers is stored in `.alil-launch-monitor.json`, or in `~/.alil-launch` for a git URL. It holds no secret values, so it's safe to commit.

| Exit code | Meaning |
|---|---|
| **0** | Nothing new at `--fail-on` or above |
| **1** | Something new needs attention |
| **2** | The check couldn't finish |

If a vulnerability database is down, nothing is marked as fixed, and nothing is reported as new when it comes back.

Alil Launch reports problems but doesn't change your code. To get update pull requests as well, use it alongside [Dependabot](https://docs.github.com/en/code-security/dependabot) or [Renovate](https://docs.renovatebot.com).

## Use it anywhere

**Any project, using Node.js:** `npx alil-launch`

**As a dev dependency:**

```bash
npm install --save-dev alil-launch
```

**Python projects:**

```bash
pipx run alil-launch
```

The Python package is a small launcher, so it needs Node.js 20 or later.

**Docker, no Node.js needed:** build the image from this repo, then mount your project:

```bash
docker build -t alil-launch .
docker run --rm -v "$PWD:/project" alil-launch
```

**GitHub Actions:** `npx alil-launch init` adds a workflow, or add the action yourself:

```yaml
- uses: actions/checkout@v4
- uses: wrathlace/alil-launch@v0
  with:
    fail-on: high
```

The action looks up known vulnerabilities by default. Set `online: false` to turn that off.

**pre-commit**, to stop secrets before they're committed:

```yaml
repos:
  - repo: https://github.com/wrathlace/alil-launch
    rev: v0.1.0
    hooks:
      - id: alil-launch
```

**Inside your tests:**

```js
import { test } from 'node:test';
import { assertLaunchReady } from 'alil-launch';

test('safe to launch', () => assertLaunchReady('.'));
```

**From your own code:**

```js
import { scan } from 'alil-launch';

const result = await scan('.');
console.log(result.verdict, result.score);
```

## Reports

```bash
npx alil-launch --html report.html     # A shareable report in one file
npx alil-launch --format sarif -o r.sarif   # GitHub code scanning
npx alil-launch --format markdown      # PR comments
npx alil-launch --format json          # Scripts
npx alil-launch --badge badge.svg      # A score badge for your README
```

## Safe automatic fixes

```bash
npx alil-launch fix --dry-run   # Preview
npx alil-launch fix
```

This only adds `.env` to `.gitignore`, generates `.env.example` with empty values, and creates `.dockerignore`. It never edits your source code.

## Configuration

Add a `.alil-launch.json` file. Everything is optional.

```json
{
  "ignore": ["legacy/", "*.generated.js"],
  "rules": {
    "launch/no-favicon": "off",
    "deploy/no-tests": "high"
  },
  "customRules": [
    {
      "id": "no-internal-urls",
      "pattern": "internal\\.mycompany\\.com",
      "files": "\\.(js|ts)$",
      "severity": "high",
      "message": "Internal hostnames must not ship to production."
    }
  ]
}
```

To silence one line, add a comment on it or on the line above: `alil-launch-ignore`.

To adopt it on an existing project, record what's there today so only new problems fail your build:

```bash
npx alil-launch --update-baseline
```

The baseline stores hashes only, so it's safe to commit.

## How scoring works

| Verdict | Meaning |
|---|---|
| **NOT READY** | At least one critical issue. The score can't go above 49 |
| **RISKY** | At least one high issue. The score can't go above 79 |
| **INCOMPLETE** | No critical or high issues, but a check you asked for couldn't finish. The score can't go above 79 |
| **READY** | No critical or high issues, and every check finished |

The command exits with code 1 if it finds anything at `high` or above, which fails a CI build. Change the level with `--fail-on`. Exit code 2 means the scan failed or couldn't finish, for example because a vulnerability database was unreachable.

A READY verdict means Alil Launch found no serious problems. It doesn't prove your app is secure, and it's not a replacement for a professional security review.

## Privacy and trust

- A default scan makes no network requests. Only `--url`, `--online` and `monitor` do
- There's no telemetry and no account
- Secret values are masked in every report, and baselines store only hashes. See below
- It has **zero runtime dependencies**, so installing it pulls in nothing else

### What reports contain

A finding names the rule, the file and the line. It never prints a usable credential, so a report is safe to paste into a CI log, a pull request or a support ticket.

- **Secret findings** show the first 4 characters followed by a mask, such as `sk_l********`, so you can tell which key it was. Values of 8 characters or fewer are fully masked.
- **Everything else a report quotes is masked too.** This covers lines matched by other rules and the output of failed `--run` commands. Masking catches known key formats, values assigned to names like `password` or `token`, passwords in URLs, `Authorization` headers, private keys and long random-looking strings.
- **Baselines and monitor state** store hashes and advisory ids, never values. Webhook alerts are built from the masked findings.

Masking can't recognise every possible format. If your build prints secrets in an unusual format, keep `--run` out of public CI logs, and fix the build so it stops printing them.

## Contributing

New rules are the easiest way to start, and each rule is only a few lines. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
