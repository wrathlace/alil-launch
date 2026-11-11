# alil-launch — Usage Guide

**A lil check before you launch.** alil-launch finds exposed secrets, unsafe settings, missing
backups, known CVEs and deployment mistakes in your project, scans your live site for the ways it
leaks or can be attacked, and keeps watching for new problems after you ship.

This guide covers every command, every flag, the configuration file, output formats, exit codes,
CI integration, the live scanner (passive and active), and the rule catalog.

- Version: 0.1.4
- Node: 20 or newer
- License: MIT

---

## Table of contents

1. [Install](#install)
2. [Quick start](#quick-start)
3. [Commands](#commands)
4. [Options reference](#options-reference)
5. [The live site scanner (`--url`)](#the-live-site-scanner---url)
6. [Active scanning (`--active`)](#active-scanning---active)
7. [Scores, grades, verdicts and exit codes](#scores-grades-verdicts-and-exit-codes)
8. [Output formats](#output-formats)
9. [Configuration file (`.alil-launch.json`)](#configuration-file-alil-launchjson)
10. [Baselines](#baselines)
11. [Continuous integration and pre-commit](#continuous-integration-and-pre-commit)
12. [Monitoring](#monitoring)
13. [MCP server (for AI coding agents)](#mcp-server-for-ai-coding-agents)
14. [The rule catalog](#the-rule-catalog)
15. [Environment variables](#environment-variables)
16. [Privacy: what leaves your machine](#privacy-what-leaves-your-machine)
17. [Recipes](#recipes)

---

## Install

No install is needed — run it with `npx`:

```bash
npx alil-launch
```

Or install it globally / as a dev dependency:

```bash
npm install -g alil-launch     # global, gives you the `alil-launch` command
npm install -D alil-launch     # per-project dev dependency
```

All examples below use `alil-launch`; prefix with `npx` if you did not install it.

---

## Quick start

```bash
# Scan the current folder
alil-launch

# Scan a specific folder
alil-launch ./my-app

# Scan and also look up known vulnerabilities (CVEs) for your dependencies
alil-launch --online

# Check your live website
alil-launch --url https://example.com

# See the tool work on a deliberately broken sample project
alil-launch demo

# Apply the safe automatic fixes
alil-launch fix
```

A scan prints a score out of 100, a letter grade, a per-category breakdown, and a list of findings
sorted by severity.

---

## Commands

| Command | What it does |
|---|---|
| `alil-launch [path]` | Scan a project folder (default: current folder). |
| `alil-launch demo` | Create and scan a deliberately broken sample project. All its secrets are fake. Good for seeing what findings look like. |
| `alil-launch fix [path]` | Apply safe automatic fixes (add `.env*` to `.gitignore`, create a `.env.example`, add a `.dockerignore`). Use `--dry-run` to preview. |
| `alil-launch init [path]` | Create a config file (`.alil-launch.json`) and two GitHub Actions workflows. Existing files are left untouched. |
| `alil-launch monitor [targets]` | Report only what is **new** since the last check. Targets are folders or git URLs (default: current folder). |
| `alil-launch rules` | List every rule (id, severity, title). |
| `alil-launch explain <rule-id>` | Explain one rule: what it means, why it matters, and how to fix it. |
| `alil-launch mcp` | Start the MCP server so AI coding agents can run scans as a tool. |

### `fix`

Applies only changes that are always safe and reversible — adding `.env*` to `.gitignore` (keeping
`.env.example`), creating a `.env.example` listing the environment variables your code uses, and
adding a `.dockerignore`. Preview first:

```bash
alil-launch fix --dry-run      # show what would change
alil-launch fix                # apply
```

### `init`

```bash
alil-launch init
```

Creates (if absent):
- `.alil-launch.json` — the config file (see [Configuration](#configuration-file-alil-launchjson))
- `.github/workflows/alil-launch.yml` — run a scan on every push / pull request
- `.github/workflows/alil-launch-monitor.yml` — a scheduled job that opens an issue when something new appears

### `explain`

```bash
alil-launch explain secret/aws-access-key
alil-launch explain live/sql-injection
```

---

## Options reference

### Deeper checks (all off by default)

| Flag | Meaning |
|---|---|
| `--url <url>` | Scan your live site: TLS, headers, CORS, exposed files, internal pages and their JavaScript. With **no path** argument, only the site is checked; add a path to scan the folder and the site together. See [the live scanner](#the-live-site-scanner---url). |
| `--pages <n>` | How many internal pages `--url` may crawl after the home page (default 50, range 0–2000). `0` checks only the home page. |
| `--active` | Send extra **non-destructive** active probes with `--url` (host-header reflection, risky HTTP methods, unauthenticated endpoints, reflected-XSS and error-based SQL injection on GET parameters). Requires `--i-am-authorized`. See [Active scanning](#active-scanning---active). |
| `--i-am-authorized` | Confirm you own the `--url` target or have written permission to test it. Required by `--active`. |
| `--online` | Look up known vulnerabilities (CVEs/advisories) for your dependencies and platforms, and find packages that do not exist (typosquats / "slopsquats"). Sends only package names and versions. With `--url`, also checks the server software, CMS, plugins and front-end libraries found on the site. |
| `--history` | Search git history for secrets, not just the current files. |
| `--run` | Run the project's own build, lint and test commands and report failures. |

### Output

| Flag | Meaning |
|---|---|
| `--format <name>` | `pretty` (default), `json`, `sarif`, `markdown` or `prompt`. See [Output formats](#output-formats). |
| `--output <file>` | Write the report to a file instead of the terminal. |
| `--html <file>` | Write a shareable HTML report. |
| `--badge <file>` | Write an SVG score badge (e.g. for your README). |
| `--verbose`, `-v` | Show every finding, including `info` level and anything normally truncated. |

### Control

| Flag | Meaning |
|---|---|
| `--fail-on <level>` | Exit with code 1 at this severity or above (default `high`). One of `critical`, `high`, `medium`, `low`, `info`. |
| `--only <list>` | Comma-separated categories to run: `secrets,config,dependencies,backups,deployment,launch`. (`live` runs when `--url` is given; `checks` runs when `--run` is given.) |
| `--staged` | Scan only git-staged files. For pre-commit hooks. |
| `--baseline [file]` | Ignore findings recorded in a baseline file (default `.alil-launch-baseline.json`). See [Baselines](#baselines). |
| `--update-baseline` | Record the current findings in the baseline file. |
| `--version`, `--help`, `-h` | Print version / help. |

### Monitoring (see [Monitoring](#monitoring))

| Flag | Meaning |
|---|---|
| `--every <hours>` | Keep running and check again at this interval. |
| `--webhook <url>` | Post new issues to Slack, Discord or Teams. Also read from `ALIL_LAUNCH_WEBHOOK`. |
| `--state <file>` | Where to remember what was seen (one target only). |

---

## The live site scanner (`--url`)

`--url` points the scanner at a running website and reports what it exposes. It behaves like a
browser or search engine: **GET requests only, no attack payloads**, it respects `robots.txt`, and
it never follows logout, delete or checkout links.

```bash
# Only the site (no folder scan)
alil-launch --url https://example.com

# Site + folder together
alil-launch . --url https://example.com

# Crawl more pages, and look up CVEs for what it finds
alil-launch --url https://example.com --pages 100 --online
```

What it checks, passively:

- **Transport:** HTTPS, HTTP→HTTPS redirect, certificate expiry, TLS 1.0/1.1 still accepted.
- **Headers:** HSTS (and weak `max-age`), CSP (and weak CSP), `x-content-type-options`,
  `referrer-policy`, clickjacking protection, server/version disclosure, cookie flags, CORS.
- **Exposed files:** ~100 sensitive paths — `.env`, `.git`, backups, SQL dumps, logs, lockfiles,
  `phpMyAdmin`/`Adminer`, Spring actuator, API docs, GraphQL introspection, `crossdomain.xml`,
  and more. Each is proven by content, so a catch-all 200 page is not falsely flagged.
- **Pages and their JavaScript** (up to `--pages`, default 50): credentials shipped to the browser,
  public **source maps** (and the original source code inside them), internal IPs and staging
  hosts, API endpoints referenced in code, debug pages and stack traces, mixed content, forms that
  submit over HTTP, unpinned or unhashed CDN scripts, vulnerable front-end libraries, directory
  listings, broken internal links, weak JSON Web Tokens, reachable admin/login pages, and
  open-redirect parameters.
- **WordPress:** public account names, XML-RPC, and (with `--online`) CVEs for core, plugins and themes.

With `--online`, the server software, CMS, plugins, themes, front-end libraries (using the
[Retire.js](https://github.com/RetireJS/retire.js) database, so versions inside minified bundles
are found) and any exposed lockfile are checked for known CVEs.

> **Single-page apps (React/Vue/etc.):** the crawler follows `<a href>` links in the HTML. An SPA
> renders its links in JavaScript, so often only the home page is reachable. You will still get
> TLS, headers, exposed files and source-map findings, but deep page coverage needs server-rendered
> links or specific URLs passed directly.

---

## Active scanning (`--active`)

`--active` adds a small number of **non-destructive** probes that send a few extra requests to the
target. Because it actively probes the site, it is strictly opt-in and gated:

```bash
alil-launch --url https://your-site.com --active --i-am-authorized
```

Without `--i-am-authorized`, it refuses to run.

What it does:

| Check | How it detects the problem |
|---|---|
| **Host-header reflection** | Sends a benign marker host; flags it if the server echoes it into links or redirects (password-reset / cache poisoning). |
| **Risky HTTP methods** | Sends `OPTIONS`; flags TRACE/PUT/DELETE/PATCH/CONNECT if the server says they are allowed. |
| **Unauthenticated endpoints** | Sends one `GET` to sensitive-looking endpoints found in the site's own code; flags any that return data with no login. |
| **Reflected XSS** | Injects a unique **non-executing** marker (`<x>"'`) into a GET parameter; flags it if it comes back unescaped. |
| **Error-based SQL injection** | Injects a single quote; flags it if a database error appears that the normal request did not produce. |

**Safety guarantees — by design, enforced in code:**

- Only `GET`, `HEAD` and `OPTIONS` are ever sent.
- No working exploit is ever sent: the XSS marker is a no-op `<x>` tag (no `<script>`, no event
  handlers), and SQLi uses a lone quote — **never** `UNION`/`DROP`/`UPDATE` or time-based payloads.
- State-changing paths (delete, pay, reset, export, logout, …) are never touched.
- Probes are capped (≤10 URLs × ≤4 parameters) and rate-limited.

> ⚠️ **Legal note.** Active scanning a site you do not own, without written permission, is illegal
> in most jurisdictions. `--active` is for **your own sites** and **client engagements with a
> signed scope**. The `--i-am-authorized` flag is your explicit confirmation that you have that
> permission. You are responsible for how you use it.

---

## Scores, grades, verdicts and exit codes

**Score** is 0–100. A critical finding caps the score at 49; a high finding caps it at 79. Repeats
of the same rule count for progressively less, so one noisy issue can't sink the score alone.

**Grade** follows the score:

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 65–79 | C |
| 50–64 | D |
| 0–49 | F |

**Verdict:**

| Verdict | Meaning |
|---|---|
| `READY` | No critical or high findings, and every requested check finished. |
| `RISKY` | At least one high finding. |
| `NOT READY` | At least one critical finding. |
| `INCOMPLETE` | A requested check (e.g. a CVE lookup) could not finish, so a clean result proves nothing. |

**Exit codes** (for scripts and CI):

| Code | Meaning |
|---|---|
| `0` | Passed: no findings at or above `--fail-on`, and nothing incomplete. |
| `1` | Findings at or above `--fail-on` (default `high`). |
| `2` | A requested check could not finish (incomplete), or the tool errored. |

---

## Output formats

```bash
alil-launch --format json  --output report.json
alil-launch --format sarif --output results.sarif     # GitHub code scanning
alil-launch --format markdown --output report.md       # PR comments / tickets
alil-launch --format prompt                             # compact text for an AI agent
alil-launch --html report.html                          # shareable HTML
alil-launch --badge badge.svg                           # score badge for a README
```

- **pretty** — the default colored terminal report.
- **json** — the full result object, for tooling.
- **sarif** — SARIF 2.1.0, for GitHub/GitLab code-scanning dashboards.
- **markdown** — a table you can paste into a PR or ticket.
- **prompt** — a compact plain-text summary designed to hand to an AI coding assistant.

Every report masks secrets: a detected credential is shown only as a short prefix plus `********`,
so a report is safe to paste into a log, ticket or PR.

---

## Configuration file (`.alil-launch.json`)

Create one with `alil-launch init`, or by hand in the project root:

```json
{
  "ignore": [
    "vendor/**",
    "**/*.min.js"
  ],
  "rules": {
    "launch/no-favicon": "off",
    "secret/generic": "medium"
  },
  "failOn": "high",
  "customRules": [
    {
      "id": "custom/internal-host",
      "title": "Internal hostname committed",
      "pattern": "intranet\\.corp\\.example\\.com",
      "flags": "i",
      "files": "\\.(ts|js|env)$",
      "severity": "medium",
      "category": "config",
      "message": "An internal hostname is referenced in committed code.",
      "fix": "Move it to configuration that is not committed."
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `ignore` | Glob patterns to skip (in addition to `.gitignore`). |
| `rules` | Per-rule overrides. Set a rule to `"off"` to disable it, or to a severity (`critical`/`high`/`medium`/`low`/`info`) to re-rank it. |
| `failOn` | Default severity for exit code 1 (overridden by `--fail-on`). |
| `customRules` | Your own regex-based rules. |

**Custom rule fields:** `id` (required), `pattern` (required regex), `title`, `flags` (regex flags),
`files` (regex matched against the file path), `severity`, `category`, `message`, `fix`.

**Inline suppression:** add a comment containing `alil-launch-ignore` on or just above a line to
suppress findings for it.

---

## Baselines

A baseline records the findings you already know about so that future scans show only what's new —
useful when adopting the tool on an existing project.

```bash
# Record current findings as the accepted baseline
alil-launch --update-baseline

# Later scans ignore everything in the baseline
alil-launch --baseline
```

The default baseline file is `.alil-launch-baseline.json`. Pass a path to use a different file:
`--baseline path/to/file.json`. Baselines store fingerprints, not secret values.

---

## Continuous integration and pre-commit

### GitHub Actions

`alil-launch init` writes `.github/workflows/alil-launch.yml` (scan on push / PR) and
`.github/workflows/alil-launch-monitor.yml` (scheduled, opens an issue on new findings). Upload
SARIF to GitHub code scanning with `--format sarif --output results.sarif`.

### Pre-commit

This repo ships a [pre-commit](https://pre-commit.com) hook. In your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/wrathlace/alil-launch
    rev: v0.1.4
    hooks:
      - id: alil-launch
```

The hook runs `alil-launch --staged --only secrets,config --fail-on high`, so a commit that adds a
secret or an unsafe setting is blocked. Run the same thing manually:

```bash
alil-launch --staged --only secrets,config --fail-on high
```

---

## Monitoring

`monitor` reports only what changed since the last run, so you can watch projects over time without
re-reading the same findings.

```bash
# Watch the current folder; remember state between runs
alil-launch monitor

# Watch several targets (folders or git URLs)
alil-launch monitor ./app https://github.com/me/other-repo.git

# Keep running and re-check every 6 hours, posting new issues to a webhook
alil-launch monitor --every 6 --webhook "$ALIL_LAUNCH_WEBHOOK"
```

- `--every <hours>` keeps the process running and re-checks on an interval.
- `--webhook <url>` posts new issues to Slack, Discord or Teams (or set `ALIL_LAUNCH_WEBHOOK`).
- `--state <file>` chooses where the "what was seen last time" state is stored (single target).

A monitor run reports a new issue, a newly published CVE in a package you already had, an old CVE
that is now being actively exploited, and anything you've fixed. Add `--url` to monitor a live site too.

---

## MCP server (for AI coding agents)

```bash
alil-launch mcp
```

Starts a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, exposing two
tools to an AI coding assistant:

- `scan_project` — run a scan and return the findings.
- `explain_rule` — explain a rule by id.

Point your MCP-capable client (e.g. an AI IDE) at the command `alil-launch mcp`.

---

## The rule catalog

alil-launch ships **174 rules** across these categories. List them all with `alil-launch rules`,
and explain any one with `alil-launch explain <rule-id>`.

| Category | Rules | Covers |
|---|---|---|
| `secret/*` | 43 | Hardcoded API keys, tokens, private keys, DB URLs with passwords, committed `.env` files, secrets in git history. Providers include AWS, GitHub, Stripe, OpenAI, Anthropic, Google, Slack, Supabase and many more. |
| `live/*` | 45 | Everything the `--url` live scanner reports (passive and active). |
| `config/*` | 22 | Unsafe framework/app settings: debug mode on, SQL built by string concatenation, open Firebase rules, missing Supabase RLS, hardcoded JWT secrets, disabled TLS verification, open Terraform ingress, and more. |
| `deploy/*` | 16 | Deployment mistakes: `.env` not ignored, no lockfile, dev migration commands in production, binding to localhost, no start script, no tests, no CI. |
| `launch/*` | 13 | Launch readiness: no README/license, no 404 page, no favicon, no error monitoring, no rate limiting, no security headers, no health endpoint. |
| `deps/*` | 8 | Dependencies: known CVEs, packages that don't exist (slopsquatting), typosquats, wildcard versions, insecure/closed platform versions. |
| `compose/*` | 8 | Docker Compose: exposed DB ports, privileged containers, mounted Docker socket, weak default passwords, databases without volumes. |
| `docker/*` | 6 | Dockerfiles: secrets baked into images, `curl | sh`, running as root, unpinned base images, no healthcheck. |
| `backup/*` | 5 | Backups: none found, committed dumps, SQLite in the repo or on serverless, no restore plan. |
| `ci/*` | 5 | CI pipelines: script/secret injection, `pull_request_target` checkout, unpinned third-party actions, default token permissions. |
| `run/*` | 3 | `--run` results: a build/lint/test command failed, timed out, or was unavailable. |

Severities range from `info` (e.g. detected technology) to `critical` (e.g. an exposed secret or a
confirmed SQL injection).

---

## Environment variables

| Variable | Meaning |
|---|---|
| `NVD_API_KEY` | Optional. A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) makes WordPress/Joomla/Nextcloud CVE lookups about ten times faster. |
| `ALIL_LAUNCH_WEBHOOK` | Default webhook URL for `monitor` (same as `--webhook`). |

---

## Privacy: what leaves your machine

- A **default scan makes no network requests.** Everything is read locally.
- `--online` sends only **package names and versions** to OSV, the NVD and (for CMS platforms)
  wordpress.org, and downloads the Retire.js database from GitHub.
- `--url` sends HTTP requests to the site you name (and fetches the scripts/source maps it loads).
- `--active` sends the extra probes described above, to the site you name, only with `--i-am-authorized`.
- `monitor --webhook` posts new findings to the webhook URL you provide. All reports mask secrets.

---

## Recipes

```bash
# Pre-launch gate: fail the build on anything high or worse, check CVEs too
alil-launch --online --fail-on high

# Full pre-launch sweep of code + live site, with CVE lookups
alil-launch . --url https://staging.example.com --online --pages 100

# Authorized penetration-style pass on your own staging site
alil-launch --url https://staging.example.com --online --active --i-am-authorized --verbose

# Secrets-only gate for a fast pre-commit hook
alil-launch --staged --only secrets,config --fail-on high

# Produce artifacts for a PR: SARIF for code scanning + an HTML report
alil-launch --online --format sarif --output results.sarif --html report.html

# Adopt on a legacy project: accept current findings, then only see new ones
alil-launch --update-baseline
alil-launch --baseline --fail-on high

# Search git history for leaked secrets
alil-launch --history

# Run the project's own build/lint/test and fold failures into the report
alil-launch --run
```

---

For a one-screen overview see the [README](../README.md). To see findings in action without a real
project, run `alil-launch demo`.
