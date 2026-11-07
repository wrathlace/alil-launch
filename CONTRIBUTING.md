# Contributing

Thanks for helping. New rules, false-positive reports and fixes are all welcome.

## Setup

```bash
npm install
npm test
node dist/cli.js demo
```

Alil Launch needs Node.js 20 or later.

## Project layout

| Path | Purpose |
|---|---|
| `src/rules/` | The checks, grouped by area |
| `src/live/url.ts` | Live site checks |
| `src/vuln/` | CVE lookups and exploit data |
| `src/monitor.ts` | Ongoing monitoring |
| `src/run/commands.ts` | Runs a project's own build and test commands |
| `src/core/` | File discovery, scoring, baselines and config |
| `src/report/` | Output formats |
| `src/mcp.ts` | MCP server for AI agents |
| `test/` | Tests |

## Adding a rule

Most rules are one entry in a table. To add a code pattern, add it to `LINE_RULES` in `src/rules/config.ts`:

```ts
{
  id: 'config/my-rule',
  title: 'Short name of the problem',
  severity: 'high',
  files: /\.py$/,
  re: /dangerous_call\(/,
  description: 'Why this matters, in one sentence.',
  fix: 'What to do about it.',
},
```

To add a credential type, add an entry to `PROVIDERS` in `src/rules/secrets.ts`.

## What makes a good rule

False alarms are the fastest way to lose people's trust, so accuracy comes first.

- **Test both sides.** Add a test that it fires on bad code and one that it stays quiet on good code.
- **Try it on real code.** Scan a few large open-source projects and read the results before you open a PR.
- **Prefer a specific prefix or format** over a broad pattern.
- **Say how to fix it.** Every rule needs a clear, practical fix.

## Project rules

- **No runtime dependencies.** This is a core promise of the project, so use Node's standard library.
- **Never output a full secret.** Pass values through `redact()`, and test that they don't appear in reports.
- **A default scan makes no network requests.** Anything online stays behind a flag.
- **A failed check must never look clean.** If a lookup can't finish, add it to `ctx.gaps`.
- **Test fixtures must not look like real keys in source.** Build them at runtime, as `src/demo.ts` does, so push protection doesn't block them.

## False positives

If Alil Launch flags something it shouldn't, please open an issue with the rule ID and a small example, with any real secret removed.

## Reporting security issues

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
