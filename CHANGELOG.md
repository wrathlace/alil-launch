# Changelog

## Unreleased

- Reports now mask credentials everywhere they quote text, including failed `--run` output and lines matched by non-secret rules. Before this, a secret printed by a project's build could appear in full
- A "What reports contain" section in the README

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
