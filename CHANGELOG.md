# Changelog

## Unreleased

- Reports now mask credentials everywhere they quote text, including failed `--run` output and lines matched by non-secret rules. Before this, a secret printed by a project's build could appear in full
- A "What reports contain" section in the README
- `--url` on its own now really checks only the site. Before this, it also scanned the current folder, so every site's report was filled with the same findings from wherever it was run
- `--url` now crawls up to 50 internal pages (`--pages <n>` to change) and checks what they load: mixed content, forms that submit over HTTP, unpinned CDN scripts, CDN scripts without integrity hashes, front-end libraries with known vulnerabilities, directory listings and broken internal links
- `--url` reads inside every script the site loads: credentials shipped to the browser, public source maps (and secrets in the original code they contain), internal IPs and staging hosts, and the API endpoints the code calls
- `--url` checks about 100 sensitive paths, including backups, logs, lockfiles, VCS folders, phpMyAdmin, Adminer, Spring actuator, API docs and GraphQL introspection, plus CORS, TLS 1.0 and 1.1, weak CSP and HSTS, debug pages and stack traces, and security.txt
- `--url` reports the stack it can see (server, CMS, frameworks) as info findings, shown with `--verbose`
- `--url` decodes JSON Web Tokens the site hands to browsers and flags unsigned (`alg: none`) or privileged ones, and reports which admin or login pages are publicly reachable. Both are observe-only: no credentials or payloads are ever sent
- On WordPress sites, `--url` checks for public account names and XML-RPC
- `--url --online` looks up CVEs for the server software, CMS, WordPress plugins and themes, front-end libraries (with the Retire.js database, which finds versions inside bundles) and the packages in any exposed lockfile
- `--url --online` with no path checks only the site

## 0.1.0

First release.

- Scanning for secrets, unsafe settings, containers, CI, dependencies, backups, deployment and launch readiness
- Live site checks with `--url`
- Vulnerability and non-existent package checks with `--online`, across JavaScript, Python, Java, PHP, .NET, Go, Rust, Ruby, Dart and Elixir
- CVE checks for WordPress, Drupal, Joomla, Nextcloud, Shopware and other Composer-based platforms
- Exploit data from CISA KEV and EPSS
- Ongoing monitoring with `monitor`: new issue alerts, webhooks, git URLs and a daily GitHub workflow
- An INCOMPLETE verdict and exit code 2 when a requested check can't finish, and a report of dependencies that can't be checked
- Git history scanning with `--history`
- Project build and test runs with `--run`
- Pretty, JSON, SARIF, Markdown, HTML, AI prompt and badge output
- MCP server, GitHub Action, pre-commit hook, Docker image and Python launcher
