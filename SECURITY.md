# Security policy

## Reporting a vulnerability

Please report security problems in Alil Launch privately, through GitHub's **Report a vulnerability** button on the repository's Security tab. Don't open a public issue.

Please include the affected version, steps to reproduce, and the impact you expect. We aim to reply within a week.

## Supported versions

Security fixes go into the latest release.

## In scope

Examples of what we want to hear about:

- A secret value appearing in any report or log
- Code running from a scanned project without `--run`
- Data leaving the machine without `--url`, `--online` or `monitor`
- Credentials from a git URL appearing in a report, log or state file
- A scanned file causing a crash or a very long hang

A scan that misses a problem is a normal bug, so please open a regular issue for those.
